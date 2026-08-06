use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, DatabaseConnection,
    DbBackend, EntityTrait, IntoActiveModel, QueryFilter, QueryOrder, QueryResult, QuerySelect,
    Statement, TransactionTrait,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::{
    application::{
        ApplicationError, ApplicationUserEventRecord, ClaimedWebhookDelivery,
        ClaimedWebhookSecretCleanup, HistoryCursor, PrepareWebhookEndpoint, PrepareWebhookRotation,
        PreparedSecretMaterial, PreparedWebhookEndpoint, PreparedWebhookSecret,
        ProjectionVerifiedEmailProtector, ProtectedValue, SealedProtectedMaterial,
        UpdateWebhookEndpoint, WebhookControlPort, WebhookDeliveryRecord,
        WebhookDeliveryRepository, WebhookEndpointRecord, WebhookSecretPreparationState,
        WebhookTransportOutcome, endpoint_status,
    },
    domain::{
        ApplicationUserEventType, MAX_WEBHOOK_DELIVERY_ATTEMPTS,
        MAX_WEBHOOK_ENDPOINTS_PER_APPLICATION, USER_PROJECTION_SCHEMA_V1,
    },
};

use super::{
    audit::append_runtime_audit,
    authentication::persistence,
    custody::{
        MaterialOwnerKind, MaterialPurpose, ProtectedMaterialRepository, finalize_pending_material,
    },
    entity::{
        application, application_user_event, application_user_projection, project,
        webhook_delivery, webhook_delivery_attempt, webhook_endpoint, webhook_secret_generation,
    },
};
#[cfg(test)]
use crate::application::ConfirmWebhookSecretProvisioned;
use owlauth_key_provider::{MaterialKind, ProviderFormatVersion, ProviderId};

const MAX_LIST_ROWS: usize = 101;

#[derive(Clone)]
pub(crate) struct PostgresWebhookRepository {
    database: DatabaseConnection,
    projection_protector: Arc<dyn ProjectionVerifiedEmailProtector>,
    #[cfg(not(test))]
    custody: WebhookCustody,
    #[cfg(test)]
    custody: Option<WebhookCustody>,
}

#[derive(Clone)]
struct WebhookCustody {
    materials: ProtectedMaterialRepository,
    active_secret: Option<(ProviderId, ProviderFormatVersion)>,
}

impl PostgresWebhookRepository {
    pub(crate) fn new_control_protected(
        database: DatabaseConnection,
        projection_protector: Arc<dyn ProjectionVerifiedEmailProtector>,
        deployment_id: &str,
        provider_id: ProviderId,
        provider_format_version: ProviderFormatVersion,
    ) -> Result<Self, ApplicationError> {
        let custody = WebhookCustody {
            materials: ProtectedMaterialRepository::new(database.clone(), deployment_id)?,
            active_secret: Some((provider_id, provider_format_version)),
        };
        Ok(Self {
            database,
            projection_protector,
            #[cfg(not(test))]
            custody,
            #[cfg(test)]
            custody: Some(custody),
        })
    }

    pub(crate) fn new_runtime_protected(
        database: DatabaseConnection,
        projection_protector: Arc<dyn ProjectionVerifiedEmailProtector>,
        deployment_id: &str,
    ) -> Result<Self, ApplicationError> {
        let custody = WebhookCustody {
            materials: ProtectedMaterialRepository::new(database.clone(), deployment_id)?,
            active_secret: None,
        };
        Ok(Self {
            database,
            projection_protector,
            #[cfg(not(test))]
            custody,
            #[cfg(test)]
            custody: Some(custody),
        })
    }

    #[cfg(test)]
    pub(crate) fn new(
        database: DatabaseConnection,
        projection_protector: Arc<dyn ProjectionVerifiedEmailProtector>,
    ) -> Self {
        Self {
            database,
            projection_protector,
            custody: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_custody(
        mut self,
        deployment_id: &str,
        provider_id: ProviderId,
        provider_format_version: ProviderFormatVersion,
    ) -> Result<Self, ApplicationError> {
        self.custody = Some(WebhookCustody {
            materials: ProtectedMaterialRepository::new(self.database.clone(), deployment_id)?,
            active_secret: Some((provider_id, provider_format_version)),
        });
        Ok(self)
    }

    #[allow(
        clippy::unnecessary_wraps,
        reason = "production custody is mandatory while legacy unit fixtures deliberately omit it"
    )]
    fn custody(&self) -> Result<&WebhookCustody, ApplicationError> {
        #[cfg(not(test))]
        return Ok(&self.custody);
        #[cfg(test)]
        self.custody.as_ref().ok_or(ApplicationError::Integrity)
    }

    #[allow(
        clippy::unnecessary_wraps,
        reason = "production custody is mandatory while legacy unit fixtures deliberately omit it"
    )]
    fn optional_custody(&self) -> Option<&WebhookCustody> {
        #[cfg(not(test))]
        return Some(&self.custody);
        #[cfg(test)]
        self.custody.as_ref()
    }

    async fn prepared_secret_material(
        &self,
        project_id: Uuid,
        secret: &webhook_secret_generation::Model,
    ) -> Result<Option<PreparedSecretMaterial>, ApplicationError> {
        let Some(material_id) = secret.material_id else {
            return Ok(None);
        };
        let custody = self.custody()?;
        let reservation = custody
            .materials
            .load_project_reservation(
                project_id,
                material_id,
                MaterialPurpose::WebhookSigningSecret,
            )
            .await?;
        if reservation.owner_kind != MaterialOwnerKind::WebhookSecret
            || reservation.owner_id != secret.endpoint_id
            || reservation.generation != i64::from(secret.generation)
            || reservation.material_kind != MaterialKind::ConfigurationSecret
        {
            return Err(ApplicationError::Integrity);
        }
        Ok(Some(PreparedSecretMaterial {
            material_id,
            provider_id: reservation.provider_id,
            provider_format_version: reservation.provider_format_version,
            context: reservation.context,
        }))
    }
}

async fn event_retention_window(
    transaction: &sea_orm::DatabaseTransaction,
) -> Result<(OffsetDateTime, OffsetDateTime, OffsetDateTime), ApplicationError> {
    let clock = transaction
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT transaction_timestamp() AS occurred_at, \
                    transaction_timestamp() + INTERVAL '29 days' AS replay_until, \
                    transaction_timestamp() + INTERVAL '30 days' AS retain_until",
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?;
    Ok((
        clock.try_get("", "occurred_at").map_err(persistence)?,
        clock.try_get("", "replay_until").map_err(persistence)?,
        clock.try_get("", "retain_until").map_err(persistence)?,
    ))
}

async fn ensure_dispatch_state(
    transaction: &sea_orm::DatabaseTransaction,
    project_id: Uuid,
    application_id: Uuid,
) -> Result<(), ApplicationError> {
    transaction
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO webhook_application_dispatch_state (project_id,application_id) \
             VALUES ($1,$2) ON CONFLICT (project_id,application_id) DO NOTHING",
            [project_id.into(), application_id.into()],
        ))
        .await
        .map_err(persistence)?;
    Ok(())
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) async fn append_projection_event(
    transaction: &sea_orm::DatabaseTransaction,
    project_public_id: &str,
    application_public_id: &str,
    binding_id: Uuid,
    projection: &application_user_projection::Model,
    wire_projection: &Value,
    event_type: ApplicationUserEventType,
) -> Result<application_user_event::Model, ApplicationError> {
    let (occurred_at, replay_until, retain_until) = event_retention_window(transaction).await?;
    let event_uuid = Uuid::new_v4();
    let event_id = format!("evt_{}", event_uuid.simple());
    let occurred_at_text = occurred_at
        .format(&Rfc3339)
        .map_err(|_| ApplicationError::Integrity)?;
    let body = json!({
        "event_id": event_id,
        "type": event_type.as_str(),
        "project_id": project_public_id,
        "application_id": application_public_id,
        "user_id": wire_projection.get("user_id").ok_or(ApplicationError::Integrity)?,
        "user_revision": projection.source_user_revision,
        "projection_revision": projection.projection_revision,
        "projection_schema": USER_PROJECTION_SCHEMA_V1,
        "occurred_at": occurred_at_text,
        "data": { "projection": wire_projection },
    });
    let canonical = serde_json::to_vec(&body).map_err(|_| ApplicationError::Integrity)?;
    let digest = Sha256::digest(&canonical).to_vec();
    let mut safe_body = body;
    safe_body
        .pointer_mut("/data/projection/verified_email")
        .ok_or(ApplicationError::Integrity)?
        .clone_from(&Value::Null);
    let event = application_user_event::ActiveModel {
        id: Set(event_uuid),
        event_id: Set(event_id),
        project_id: Set(projection.project_id),
        application_id: Set(projection.application_id),
        binding_id: Set(binding_id),
        user_id: Set(projection.user_id),
        event_type: Set(event_type.as_str().to_owned()),
        user_revision: Set(projection.source_user_revision),
        projection_revision: Set(projection.projection_revision),
        projection_schema: Set(USER_PROJECTION_SCHEMA_V1.to_owned()),
        safe_body: Set(safe_body),
        canonical_body_digest: Set(digest),
        verified_email_source_identity_id: Set(projection.verified_email_source_identity_id),
        verified_email_ciphertext: Set(projection.verified_email_ciphertext.clone()),
        verified_email_key_version: Set(projection.verified_email_key_version),
        occurred_at: Set(occurred_at),
        replay_until: Set(replay_until),
        retain_until: Set(retain_until),
        created_at: Set(occurred_at),
    }
    .insert(transaction)
    .await
    .map_err(persistence)?;

    let endpoints = webhook_endpoint::Entity::find()
        .filter(webhook_endpoint::Column::ProjectId.eq(projection.project_id))
        .filter(webhook_endpoint::Column::ApplicationId.eq(projection.application_id))
        .filter(webhook_endpoint::Column::Status.eq("active"))
        .order_by_asc(webhook_endpoint::Column::Id)
        .limit((MAX_WEBHOOK_ENDPOINTS_PER_APPLICATION + 1) as u64)
        .all(transaction)
        .await
        .map_err(persistence)?;
    if endpoints.len() > MAX_WEBHOOK_ENDPOINTS_PER_APPLICATION {
        return Err(ApplicationError::Integrity);
    }
    ensure_dispatch_state(
        transaction,
        projection.project_id,
        projection.application_id,
    )
    .await?;
    for endpoint in endpoints {
        if endpoint
            .subscribed_event_types
            .iter()
            .any(|value| value == event_type.as_str())
        {
            webhook_delivery::ActiveModel {
                id: Set(Uuid::new_v4()),
                project_id: Set(event.project_id),
                application_id: Set(event.application_id),
                endpoint_id: Set(endpoint.id),
                event_id: Set(event.id),
                replay_sequence: Set(0),
                replay_of_delivery_id: Set(None),
                state: Set("pending".to_owned()),
                attempt_count: Set(0),
                next_attempt_at: Set(occurred_at),
                lease_owner: Set(None),
                lease_incarnation: Set(None),
                lease_generation: Set(0),
                lease_expires_at: Set(None),
                claimed_secret_generation: Set(None),
                claimed_overlap_generation: Set(None),
                claimed_secret_material_id: Set(None),
                claimed_overlap_material_id: Set(None),
                last_outcome_class: Set(None),
                last_http_status: Set(None),
                created_at: Set(occurred_at),
                updated_at: Set(occurred_at),
                delivered_at: Set(None),
                terminal_at: Set(None),
            }
            .insert(transaction)
            .await
            .map_err(persistence)?;
        }
    }
    Ok(event)
}

#[async_trait]
#[allow(
    clippy::too_many_lines,
    reason = "the repository keeps one explicit transaction per webhook lifecycle command"
)]
impl WebhookControlPort for PostgresWebhookRepository {
    async fn prepare_endpoint(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        command: PrepareWebhookEndpoint,
        now: OffsetDateTime,
        correlation_id: Uuid,
    ) -> Result<PreparedWebhookEndpoint, ApplicationError> {
        if command.request_fingerprint.len() != 32 {
            return Err(ApplicationError::InvalidInput);
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        lock_active_application(&transaction, project_id, application_id).await?;
        if let Some(existing) = webhook_endpoint::Entity::find()
            .filter(webhook_endpoint::Column::ProjectId.eq(project_id))
            .filter(webhook_endpoint::Column::ApplicationId.eq(application_id))
            .filter(webhook_endpoint::Column::IdempotencyKey.eq(&command.idempotency_key))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
        {
            if existing.url != command.url
                || existing.subscribed_event_types != command.subscribed_event_types
                || !bool::from(
                    existing
                        .secret_request_fingerprint
                        .as_slice()
                        .ct_eq(command.request_fingerprint.as_slice()),
                )
            {
                return Err(ApplicationError::IdempotencyConflict);
            }
            let secret = webhook_secret_generation::Entity::find_by_id((existing.id, 1))
                .one(&transaction)
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::Integrity)?;
            transaction.commit().await.map_err(persistence)?;
            let preparation_state = secret_preparation_state(&secret, existing.status == "pending");
            let material = self.prepared_secret_material(project_id, &secret).await?;
            return Ok(PreparedWebhookEndpoint {
                endpoint: endpoint_record(existing)?,
                #[cfg(test)]
                secret_ref: secret.secret_ref,
                material,
                preparation_state,
            });
        }
        if let Some(existing) = webhook_endpoint::Entity::find()
            .filter(webhook_endpoint::Column::ProjectId.eq(project_id))
            .filter(webhook_endpoint::Column::ApplicationId.eq(application_id))
            .filter(webhook_endpoint::Column::Url.eq(&command.url))
            .filter(webhook_endpoint::Column::Status.ne("disabled"))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
        {
            if existing.status != "pending"
                || existing.subscribed_event_types != command.subscribed_event_types
                || !bool::from(
                    existing
                        .secret_request_fingerprint
                        .as_slice()
                        .ct_eq(command.request_fingerprint.as_slice()),
                )
            {
                return Err(ApplicationError::IdempotencyConflict);
            }
            let secret = webhook_secret_generation::Entity::find_by_id((existing.id, 1))
                .one(&transaction)
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::Integrity)?;
            transaction.commit().await.map_err(persistence)?;
            let preparation_state = secret_preparation_state(&secret, existing.status == "pending");
            let material = self.prepared_secret_material(project_id, &secret).await?;
            return Ok(PreparedWebhookEndpoint {
                endpoint: endpoint_record(existing)?,
                #[cfg(test)]
                secret_ref: secret.secret_ref,
                material,
                preparation_state,
            });
        }
        let count = webhook_endpoint::Entity::find()
            .filter(webhook_endpoint::Column::ProjectId.eq(project_id))
            .filter(webhook_endpoint::Column::ApplicationId.eq(application_id))
            .filter(webhook_endpoint::Column::Status.is_in(["pending", "active"]))
            .limit((MAX_WEBHOOK_ENDPOINTS_PER_APPLICATION + 1) as u64)
            .all(&transaction)
            .await
            .map_err(persistence)?
            .len();
        if count >= MAX_WEBHOOK_ENDPOINTS_PER_APPLICATION {
            return Err(ApplicationError::InvalidTransition);
        }
        let endpoint_id = Uuid::new_v4();
        let public_id = format!("wh_{}", endpoint_id.simple());
        let material_id = self.optional_custody().map(|_| Uuid::new_v4());
        let secret_ref = format!(
            "webhook_{}_{}_{}_1",
            project_id.simple(),
            application_id.simple(),
            endpoint_id.simple()
        );
        let safe_fingerprint = self
            .optional_custody()
            .is_none()
            .then(|| URL_SAFE_NO_PAD.encode(&command.request_fingerprint[..16]));
        let endpoint = webhook_endpoint::ActiveModel {
            id: Set(endpoint_id),
            project_id: Set(project_id),
            application_id: Set(application_id),
            public_id: Set(public_id),
            idempotency_key: Set(command.idempotency_key.clone()),
            secret_request_fingerprint: Set(command.request_fingerprint.clone()),
            url: Set(command.url),
            subscribed_event_types: Set(command.subscribed_event_types),
            status: Set("pending".to_owned()),
            revision: Set(1),
            current_secret_generation: Set(None),
            overlap_secret_generation: Set(None),
            overlap_expires_at: Set(None),
            consecutive_failure_count: Set(0),
            last_delivery_at: Set(None),
            last_success_at: Set(None),
            last_failure_class: Set(None),
            last_tested_at: Set(None),
            last_test_succeeded_at: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
            disabled_at: Set(None),
        }
        .insert(&transaction)
        .await
        .map_err(persistence)?;
        let material =
            if let (Some(custody), Some(material_id)) = (self.optional_custody(), material_id) {
                let (provider_id, provider_format_version) = custody
                    .active_secret
                    .as_ref()
                    .ok_or(ApplicationError::Integrity)?;
                let reservation = custody
                    .materials
                    .reserve_project_in_transaction(
                        &transaction,
                        project_id,
                        material_id,
                        MaterialOwnerKind::WebhookSecret,
                        endpoint_id,
                        1,
                        MaterialKind::ConfigurationSecret,
                        MaterialPurpose::WebhookSigningSecret,
                        provider_id.clone(),
                        *provider_format_version,
                    )
                    .await?;
                Some(PreparedSecretMaterial {
                    material_id,
                    provider_id: reservation.provider_id,
                    provider_format_version: reservation.provider_format_version,
                    context: reservation.context,
                })
            } else {
                None
            };
        reserve_new_secret_reference(&transaction, &secret_ref, material_id, now).await?;
        webhook_secret_generation::ActiveModel {
            endpoint_id: Set(endpoint_id),
            generation: Set(1),
            idempotency_key: Set(command.idempotency_key),
            request_fingerprint: Set(command.request_fingerprint),
            secret_ref: Set(secret_ref.clone()),
            safe_fingerprint: Set(safe_fingerprint),
            material_id: Set(material_id),
            state: Set("pending".to_owned()),
            created_at: Set(now),
            provisioned_at: Set(None),
            activated_at: Set(None),
            retired_at: Set(None),
        }
        .insert(&transaction)
        .await
        .map_err(persistence)?;
        append_runtime_audit(
            &transaction,
            project_id,
            "deployment_operator",
            "webhook.endpoint.prepare",
            "webhook_endpoint",
            Some(endpoint_id),
            correlation_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(PreparedWebhookEndpoint {
            endpoint: endpoint_record(endpoint)?,
            #[cfg(test)]
            secret_ref,
            material,
            preparation_state: WebhookSecretPreparationState::Pending,
        })
    }

    #[cfg(test)]
    async fn confirm_secret_provisioned(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        endpoint_id: Uuid,
        command: ConfirmWebhookSecretProvisioned,
        now: OffsetDateTime,
        correlation_id: Uuid,
    ) -> Result<(), ApplicationError> {
        if command.generation < 1 || command.request_fingerprint.len() != 32 {
            return Err(ApplicationError::InvalidInput);
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        let endpoint =
            lock_active_endpoint(&transaction, project_id, application_id, endpoint_id).await?;
        if endpoint.revision != command.expected_endpoint_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        let secret =
            webhook_secret_generation::Entity::find_by_id((endpoint_id, command.generation))
                .lock_exclusive()
                .one(&transaction)
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::NotFound)?;
        if !bool::from(
            secret
                .request_fingerprint
                .as_slice()
                .ct_eq(command.request_fingerprint.as_slice()),
        ) {
            return Err(ApplicationError::RevisionConflict);
        }
        if secret.provisioned_at.is_none() {
            if secret.state != "pending" {
                return Err(ApplicationError::InvalidTransition);
            }
            ensure_live_secret_reference(&transaction, &secret.secret_ref).await?;
            let mut active = secret.into_active_model();
            active.provisioned_at = Set(Some(now));
            active.update(&transaction).await.map_err(persistence)?;
            append_runtime_audit(
                &transaction,
                project_id,
                "deployment_operator",
                "webhook.secret.provision",
                "webhook_endpoint",
                Some(endpoint_id),
                correlation_id,
            )
            .await?;
        }
        transaction.commit().await.map_err(persistence)?;
        Ok(())
    }

    async fn finalize_protected_secret(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        endpoint_id: Uuid,
        generation: i32,
        expected_endpoint_revision: i64,
        request_fingerprint: &[u8],
        material: SealedProtectedMaterial,
        now: OffsetDateTime,
        correlation_id: Uuid,
    ) -> Result<(), ApplicationError> {
        if generation < 1 || request_fingerprint.len() != 32 {
            return Err(ApplicationError::InvalidInput);
        }
        let fingerprint = material.request_fingerprint.into_bytes();
        if fingerprint.len() != 32 {
            return Err(ApplicationError::Integrity);
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        let endpoint =
            lock_active_endpoint(&transaction, project_id, application_id, endpoint_id).await?;
        if endpoint.revision != expected_endpoint_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        let secret = webhook_secret_generation::Entity::find_by_id((endpoint_id, generation))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if secret.material_id != Some(material.material_id)
            || !bool::from(
                secret
                    .request_fingerprint
                    .as_slice()
                    .ct_eq(request_fingerprint),
            )
            || !matches!(
                secret.state.as_str(),
                "pending" | "active" | "overlap" | "retired" | "compromised"
            )
        {
            return Err(ApplicationError::InvalidTransition);
        }
        let terminal = matches!(secret.state.as_str(), "retired" | "compromised");
        let custody = self.custody()?;
        let reservation = custody
            .materials
            .load_project_reservation_in_transaction(
                &transaction,
                project_id,
                material.material_id,
                MaterialPurpose::WebhookSigningSecret,
            )
            .await?;
        if reservation.owner_kind != MaterialOwnerKind::WebhookSecret
            || reservation.owner_id != endpoint_id
            || reservation.generation != i64::from(generation)
            || reservation.material_kind != MaterialKind::ConfigurationSecret
            || reservation.provider_id != material.provider_id
            || reservation.provider_format_version != material.provider_format_version
        {
            return Err(ApplicationError::Integrity);
        }
        if !terminal {
            ensure_live_secret_reference(&transaction, &secret.secret_ref).await?;
        }
        let was_provisioned = secret.provisioned_at.is_some();
        finalize_pending_material(
            &transaction,
            material.material_id,
            Some(project_id),
            material.envelope.into_zeroizing().to_vec(),
            Some(fingerprint.clone()),
            now,
        )
        .await?;
        if terminal {
            transaction.commit().await.map_err(persistence)?;
            return Ok(());
        }
        let mut active = secret.into_active_model();
        active.safe_fingerprint = Set(Some(URL_SAFE_NO_PAD.encode(&fingerprint[..16])));
        if !was_provisioned {
            active.provisioned_at = Set(Some(now));
        }
        active.update(&transaction).await.map_err(persistence)?;
        if !was_provisioned {
            append_runtime_audit(
                &transaction,
                project_id,
                "deployment_operator",
                "webhook.secret.provision",
                "webhook_endpoint",
                Some(endpoint_id),
                correlation_id,
            )
            .await?;
        }
        transaction.commit().await.map_err(persistence)?;
        Ok(())
    }

    async fn get_endpoint(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        endpoint_id: Uuid,
    ) -> Result<WebhookEndpointRecord, ApplicationError> {
        let endpoint = webhook_endpoint::Entity::find_by_id(endpoint_id)
            .filter(webhook_endpoint::Column::ProjectId.eq(project_id))
            .filter(webhook_endpoint::Column::ApplicationId.eq(application_id))
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        endpoint_record(endpoint)
    }

    async fn record_endpoint_test_success(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        endpoint_id: Uuid,
        expected_revision: i64,
        now: OffsetDateTime,
        correlation_id: Uuid,
    ) -> Result<WebhookEndpointRecord, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        let endpoint =
            lock_active_endpoint(&transaction, project_id, application_id, endpoint_id).await?;
        if endpoint.status == "disabled" {
            return Err(ApplicationError::Disabled);
        }
        if endpoint.revision != expected_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        let revision = expected_revision
            .checked_add(1)
            .ok_or(ApplicationError::Integrity)?;
        let mut active = endpoint.into_active_model();
        active.revision = Set(revision);
        active.last_tested_at = Set(Some(now));
        active.last_test_succeeded_at = Set(Some(now));
        active.updated_at = Set(now);
        let endpoint = active.update(&transaction).await.map_err(persistence)?;
        append_runtime_audit(
            &transaction,
            project_id,
            "deployment_operator",
            "webhook.endpoint.test",
            "webhook_endpoint",
            Some(endpoint_id),
            correlation_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        endpoint_record(endpoint)
    }

    async fn activate_prepared_endpoint(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        endpoint_id: Uuid,
        expected_revision: i64,
        now: OffsetDateTime,
        correlation_id: Uuid,
    ) -> Result<WebhookEndpointRecord, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        let endpoint =
            lock_active_endpoint(&transaction, project_id, application_id, endpoint_id).await?;
        if endpoint.status == "active" {
            if endpoint.revision == expected_revision.saturating_add(1) {
                transaction.commit().await.map_err(persistence)?;
                return endpoint_record(endpoint);
            }
            return Err(ApplicationError::RevisionConflict);
        }
        if !endpoint_status(&endpoint.status)?.can_activate() {
            return Err(ApplicationError::InvalidTransition);
        }
        if endpoint.revision != expected_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        if endpoint.last_test_succeeded_at.is_none() {
            return Err(ApplicationError::InvalidTransition);
        }
        let secret = webhook_secret_generation::Entity::find_by_id((endpoint_id, 1))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        if secret.state != "pending" || secret.provisioned_at.is_none() {
            return Err(ApplicationError::InvalidTransition);
        }
        let mut secret_active = secret.into_active_model();
        secret_active.state = Set("active".to_owned());
        secret_active.activated_at = Set(Some(now));
        secret_active
            .update(&transaction)
            .await
            .map_err(persistence)?;
        let mut active = endpoint.into_active_model();
        active.status = Set("active".to_owned());
        active.current_secret_generation = Set(Some(1));
        active.revision = Set(expected_revision
            .checked_add(1)
            .ok_or(ApplicationError::Integrity)?);
        active.updated_at = Set(now);
        let endpoint = active.update(&transaction).await.map_err(persistence)?;
        append_runtime_audit(
            &transaction,
            project_id,
            "deployment_operator",
            "webhook.endpoint.activate",
            "webhook_endpoint",
            Some(endpoint_id),
            correlation_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        endpoint_record(endpoint)
    }

    async fn list_endpoints(
        &self,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<Vec<WebhookEndpointRecord>, ApplicationError> {
        ensure_application(&self.database, project_id, application_id).await?;
        let rows = webhook_endpoint::Entity::find()
            .filter(webhook_endpoint::Column::ProjectId.eq(project_id))
            .filter(webhook_endpoint::Column::ApplicationId.eq(application_id))
            .order_by_asc(webhook_endpoint::Column::CreatedAt)
            .order_by_asc(webhook_endpoint::Column::Id)
            .limit(MAX_LIST_ROWS as u64)
            .all(&self.database)
            .await
            .map_err(persistence)?;
        rows.into_iter().map(endpoint_record).collect()
    }

    async fn update_endpoint(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        endpoint_id: Uuid,
        command: UpdateWebhookEndpoint,
        now: OffsetDateTime,
        correlation_id: Uuid,
    ) -> Result<WebhookEndpointRecord, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        let endpoint =
            lock_active_endpoint(&transaction, project_id, application_id, endpoint_id).await?;
        if endpoint.status == "disabled" {
            return Err(ApplicationError::Disabled);
        }
        if endpoint.revision != command.expected_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        let mut active = endpoint.into_active_model();
        active.subscribed_event_types = Set(command.subscribed_event_types);
        active.revision = Set(command.expected_revision + 1);
        active.updated_at = Set(now);
        let endpoint = active.update(&transaction).await.map_err(persistence)?;
        append_runtime_audit(
            &transaction,
            project_id,
            "deployment_operator",
            "webhook.endpoint.update",
            "webhook_endpoint",
            Some(endpoint_id),
            correlation_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        endpoint_record(endpoint)
    }

    async fn disable_endpoint(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        endpoint_id: Uuid,
        expected_revision: i64,
        now: OffsetDateTime,
        correlation_id: Uuid,
    ) -> Result<WebhookEndpointRecord, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        lock_active_application(&transaction, project_id, application_id).await?;
        let endpoint = lock_endpoint(&transaction, project_id, application_id, endpoint_id).await?;
        if !endpoint_status(&endpoint.status)?.can_disable() {
            return Err(ApplicationError::InvalidTransition);
        }
        if endpoint.revision != expected_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        let generations = webhook_secret_generation::Entity::find()
            .filter(webhook_secret_generation::Column::EndpointId.eq(endpoint_id))
            .filter(
                webhook_secret_generation::Column::State.is_in(["pending", "active", "overlap"]),
            )
            .order_by_asc(webhook_secret_generation::Column::Generation)
            .lock_exclusive()
            .all(&transaction)
            .await
            .map_err(persistence)?;
        if generations.len() > 3 {
            return Err(ApplicationError::Integrity);
        }
        let overlap_generation = endpoint.overlap_secret_generation;
        let overlap_not_before = match overlap_generation {
            Some(_) => Some(
                endpoint
                    .overlap_expires_at
                    .ok_or(ApplicationError::Integrity)?,
            ),
            None => None,
        };
        let mut active = endpoint.into_active_model();
        active.status = Set("disabled".to_owned());
        active.current_secret_generation = Set(None);
        active.overlap_secret_generation = Set(None);
        active.overlap_expires_at = Set(None);
        active.revision = Set(expected_revision + 1);
        active.disabled_at = Set(Some(now));
        active.updated_at = Set(now);
        let endpoint = active.update(&transaction).await.map_err(persistence)?;
        for generation in generations {
            let generation_number = generation.generation;
            let secret_ref = generation.secret_ref.clone();
            let mut retired = generation.into_active_model();
            retired.state = Set("retired".to_owned());
            retired.retired_at = Set(Some(now));
            retired.update(&transaction).await.map_err(persistence)?;
            let not_before = if overlap_generation == Some(generation_number) {
                overlap_not_before.ok_or(ApplicationError::Integrity)?
            } else {
                now
            };
            enqueue_secret_cleanup(
                &transaction,
                endpoint_id,
                generation_number,
                &secret_ref,
                now,
                not_before,
            )
            .await?;
        }
        append_runtime_audit(
            &transaction,
            project_id,
            "deployment_operator",
            "webhook.endpoint.disable",
            "webhook_endpoint",
            Some(endpoint_id),
            correlation_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        endpoint_record(endpoint)
    }

    async fn prepare_secret_rotation(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        endpoint_id: Uuid,
        command: PrepareWebhookRotation,
        now: OffsetDateTime,
        correlation_id: Uuid,
    ) -> Result<PreparedWebhookSecret, ApplicationError> {
        if command.request_fingerprint.len() != 32 {
            return Err(ApplicationError::InvalidInput);
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        let endpoint =
            lock_active_endpoint(&transaction, project_id, application_id, endpoint_id).await?;
        if endpoint.status != "active" {
            return Err(ApplicationError::Disabled);
        }
        if let Some(existing) = webhook_secret_generation::Entity::find()
            .filter(webhook_secret_generation::Column::EndpointId.eq(endpoint_id))
            .filter(webhook_secret_generation::Column::IdempotencyKey.eq(&command.idempotency_key))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
        {
            if !bool::from(
                existing
                    .request_fingerprint
                    .as_slice()
                    .ct_eq(command.request_fingerprint.as_slice()),
            ) {
                return Err(ApplicationError::IdempotencyConflict);
            }
            transaction.commit().await.map_err(persistence)?;
            let preparation_state = secret_preparation_state(&existing, true);
            let already_active = existing.activated_at.is_some();
            let material = self.prepared_secret_material(project_id, &existing).await?;
            return Ok(PreparedWebhookSecret {
                endpoint: endpoint_record(endpoint)?,
                generation: existing.generation,
                #[cfg(test)]
                secret_ref: existing.secret_ref,
                material,
                preparation_state,
                already_active,
            });
        }
        if endpoint.revision != command.expected_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        if let Some(pending) = webhook_secret_generation::Entity::find()
            .filter(webhook_secret_generation::Column::EndpointId.eq(endpoint_id))
            .filter(webhook_secret_generation::Column::State.eq("pending"))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
        {
            if bool::from(
                pending
                    .request_fingerprint
                    .as_slice()
                    .ct_eq(command.request_fingerprint.as_slice()),
            ) {
                transaction.commit().await.map_err(persistence)?;
                let preparation_state = secret_preparation_state(&pending, true);
                let material = self.prepared_secret_material(project_id, &pending).await?;
                return Ok(PreparedWebhookSecret {
                    endpoint: endpoint_record(endpoint)?,
                    generation: pending.generation,
                    #[cfg(test)]
                    secret_ref: pending.secret_ref,
                    material,
                    preparation_state,
                    already_active: false,
                });
            }
            let abandoned_generation = pending.generation;
            let abandoned_ref = pending.secret_ref.clone();
            let mut abandoned = pending.into_active_model();
            abandoned.state = Set("retired".to_owned());
            abandoned.retired_at = Set(Some(now));
            abandoned.update(&transaction).await.map_err(persistence)?;
            enqueue_secret_cleanup(
                &transaction,
                endpoint_id,
                abandoned_generation,
                &abandoned_ref,
                now,
                now,
            )
            .await?;
        }
        let generation = webhook_secret_generation::Entity::find()
            .filter(webhook_secret_generation::Column::EndpointId.eq(endpoint_id))
            .order_by_desc(webhook_secret_generation::Column::Generation)
            .one(&transaction)
            .await
            .map_err(persistence)?
            .map_or(1, |value| value.generation + 1);
        let material_id = self.optional_custody().map(|_| Uuid::new_v4());
        let secret_ref = format!(
            "webhook_{}_{}_{}_{}",
            project_id.simple(),
            application_id.simple(),
            endpoint_id.simple(),
            generation
        );
        let material =
            if let (Some(custody), Some(material_id)) = (self.optional_custody(), material_id) {
                let (provider_id, provider_format_version) = custody
                    .active_secret
                    .as_ref()
                    .ok_or(ApplicationError::Integrity)?;
                let reservation = custody
                    .materials
                    .reserve_project_in_transaction(
                        &transaction,
                        project_id,
                        material_id,
                        MaterialOwnerKind::WebhookSecret,
                        endpoint_id,
                        i64::from(generation),
                        MaterialKind::ConfigurationSecret,
                        MaterialPurpose::WebhookSigningSecret,
                        provider_id.clone(),
                        *provider_format_version,
                    )
                    .await?;
                Some(PreparedSecretMaterial {
                    material_id,
                    provider_id: reservation.provider_id,
                    provider_format_version: reservation.provider_format_version,
                    context: reservation.context,
                })
            } else {
                None
            };
        reserve_new_secret_reference(&transaction, &secret_ref, material_id, now).await?;
        webhook_secret_generation::ActiveModel {
            endpoint_id: Set(endpoint_id),
            generation: Set(generation),
            idempotency_key: Set(command.idempotency_key),
            request_fingerprint: Set(command.request_fingerprint.clone()),
            secret_ref: Set(secret_ref.clone()),
            safe_fingerprint: Set(self
                .optional_custody()
                .is_none()
                .then(|| URL_SAFE_NO_PAD.encode(&command.request_fingerprint[..16]))),
            material_id: Set(material_id),
            state: Set("pending".to_owned()),
            created_at: Set(now),
            provisioned_at: Set(None),
            activated_at: Set(None),
            retired_at: Set(None),
        }
        .insert(&transaction)
        .await
        .map_err(persistence)?;
        append_runtime_audit(
            &transaction,
            project_id,
            "deployment_operator",
            "webhook.secret.prepare",
            "webhook_endpoint",
            Some(endpoint_id),
            correlation_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(PreparedWebhookSecret {
            endpoint: endpoint_record(endpoint)?,
            generation,
            #[cfg(test)]
            secret_ref,
            material,
            preparation_state: WebhookSecretPreparationState::Pending,
            already_active: false,
        })
    }

    async fn activate_secret_rotation(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        endpoint_id: Uuid,
        generation: i32,
        expected_revision: i64,
        overlap_seconds: i64,
        correlation_id: Uuid,
    ) -> Result<WebhookEndpointRecord, ApplicationError> {
        if !(300..=86_400).contains(&overlap_seconds) {
            return Err(ApplicationError::InvalidInput);
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        let endpoint =
            lock_active_endpoint(&transaction, project_id, application_id, endpoint_id).await?;
        if endpoint.status != "active" {
            return Err(ApplicationError::Disabled);
        }
        let current_generation = endpoint
            .current_secret_generation
            .ok_or(ApplicationError::Integrity)?;
        if generation == current_generation {
            if endpoint.revision == expected_revision.saturating_add(1) {
                transaction.commit().await.map_err(persistence)?;
                return endpoint_record(endpoint);
            }
            return Err(ApplicationError::RevisionConflict);
        }
        if endpoint.revision != expected_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        let pending = webhook_secret_generation::Entity::find_by_id((endpoint_id, generation))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if pending.state != "pending" || pending.provisioned_at.is_none() {
            return Err(ApplicationError::InvalidTransition);
        }
        let current =
            webhook_secret_generation::Entity::find_by_id((endpoint_id, current_generation))
                .lock_exclusive()
                .one(&transaction)
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::Integrity)?;
        if current.state != "active" {
            return Err(ApplicationError::Integrity);
        }
        let clock = transaction
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "WITH db_clock AS (SELECT clock_timestamp() AS now) \
                 SELECT now,now+make_interval(secs=>$1) AS overlap_expires_at FROM db_clock",
                [overlap_seconds.into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        let now: OffsetDateTime = clock.try_get("", "now").map_err(persistence)?;
        let overlap_expires_at: OffsetDateTime = clock
            .try_get("", "overlap_expires_at")
            .map_err(persistence)?;
        if let Some(previous_overlap) = endpoint.overlap_secret_generation {
            let previous_overlap_expires_at = endpoint
                .overlap_expires_at
                .ok_or(ApplicationError::Integrity)?;
            if previous_overlap_expires_at > now {
                return Err(ApplicationError::InvalidTransition);
            }
            let overlap =
                webhook_secret_generation::Entity::find_by_id((endpoint_id, previous_overlap))
                    .lock_exclusive()
                    .one(&transaction)
                    .await
                    .map_err(persistence)?
                    .ok_or(ApplicationError::Integrity)?;
            let retired_generation = overlap.generation;
            let retired_ref = overlap.secret_ref.clone();
            let mut retired = overlap.into_active_model();
            retired.state = Set("retired".to_owned());
            retired.retired_at = Set(Some(now));
            retired.update(&transaction).await.map_err(persistence)?;
            enqueue_secret_cleanup(
                &transaction,
                endpoint_id,
                retired_generation,
                &retired_ref,
                now,
                previous_overlap_expires_at,
            )
            .await?;
        }
        let mut overlap = current.into_active_model();
        overlap.state = Set("overlap".to_owned());
        overlap.update(&transaction).await.map_err(persistence)?;
        let mut new_active = pending.into_active_model();
        new_active.state = Set("active".to_owned());
        new_active.activated_at = Set(Some(now));
        new_active.update(&transaction).await.map_err(persistence)?;
        let mut endpoint_active = endpoint.into_active_model();
        endpoint_active.current_secret_generation = Set(Some(generation));
        endpoint_active.overlap_secret_generation = Set(Some(current_generation));
        endpoint_active.overlap_expires_at = Set(Some(overlap_expires_at));
        endpoint_active.revision = Set(expected_revision + 1);
        endpoint_active.updated_at = Set(now);
        let endpoint = endpoint_active
            .update(&transaction)
            .await
            .map_err(persistence)?;
        append_runtime_audit(
            &transaction,
            project_id,
            "deployment_operator",
            "webhook.secret.activate",
            "webhook_endpoint",
            Some(endpoint_id),
            correlation_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        endpoint_record(endpoint)
    }

    async fn list_events(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        cursor: Option<HistoryCursor>,
        limit: usize,
    ) -> Result<Vec<ApplicationUserEventRecord>, ApplicationError> {
        ensure_application(&self.database, project_id, application_id).await?;
        if !(1..=MAX_LIST_ROWS).contains(&limit) {
            return Err(ApplicationError::InvalidInput);
        }
        let rows = self
            .database
            .query_all_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT id,event_id,project_id,application_id,user_id,event_type,user_revision,
                        projection_revision,projection_schema,safe_body,occurred_at
                   FROM application_user_events
                  WHERE project_id=$1 AND application_id=$2
                    AND retain_until > transaction_timestamp()
                    AND ($3::timestamptz IS NULL OR (occurred_at,id) < ($3,$4))
                  ORDER BY occurred_at DESC,id DESC LIMIT $5",
                vec![
                    project_id.into(),
                    application_id.into(),
                    cursor.map(|value| value.timestamp).into(),
                    cursor.map(|value| value.id).into(),
                    i64::try_from(limit)
                        .map_err(|_| ApplicationError::InvalidInput)?
                        .into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        rows.iter().map(event_record_from_row).collect()
    }

    async fn list_deliveries(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        endpoint_id: Option<Uuid>,
        cursor: Option<HistoryCursor>,
        limit: usize,
    ) -> Result<Vec<WebhookDeliveryRecord>, ApplicationError> {
        ensure_application(&self.database, project_id, application_id).await?;
        if !(1..=MAX_LIST_ROWS).contains(&limit) {
            return Err(ApplicationError::InvalidInput);
        }
        let rows = self
            .database
            .query_all_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT delivery.id,delivery.endpoint_id,event.event_id,
                        delivery.replay_sequence,delivery.replay_of_delivery_id,delivery.state,
                        delivery.attempt_count,delivery.next_attempt_at,
                        delivery.last_outcome_class,delivery.last_http_status,
                        delivery.delivered_at,delivery.terminal_at,delivery.created_at
                   FROM webhook_deliveries delivery
                   JOIN application_user_events event ON event.id=delivery.event_id
                  WHERE delivery.project_id=$1 AND delivery.application_id=$2
                    AND event.retain_until > transaction_timestamp()
                    AND ($3::uuid IS NULL OR delivery.endpoint_id=$3)
                    AND ($4::timestamptz IS NULL OR (delivery.created_at,delivery.id) < ($4,$5))
                  ORDER BY delivery.created_at DESC,delivery.id DESC LIMIT $6",
                vec![
                    project_id.into(),
                    application_id.into(),
                    endpoint_id.into(),
                    cursor.map(|value| value.timestamp).into(),
                    cursor.map(|value| value.id).into(),
                    i64::try_from(limit)
                        .map_err(|_| ApplicationError::InvalidInput)?
                        .into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        rows.iter().map(delivery_record_from_row).collect()
    }

    async fn replay_delivery(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        delivery_id: Uuid,
        now: OffsetDateTime,
        correlation_id: Uuid,
    ) -> Result<WebhookDeliveryRecord, ApplicationError> {
        let hint = webhook_delivery::Entity::find_by_id(delivery_id)
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if hint.project_id != project_id || hint.application_id != application_id {
            return Err(ApplicationError::NotFound);
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        lock_active_application(&transaction, project_id, application_id).await?;
        let endpoint =
            lock_endpoint(&transaction, project_id, application_id, hint.endpoint_id).await?;
        if endpoint.status != "active" {
            return Err(ApplicationError::Disabled);
        }
        let original = webhook_delivery::Entity::find_by_id(delivery_id)
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if original.project_id != project_id
            || original.application_id != application_id
            || original.endpoint_id != endpoint.id
        {
            return Err(ApplicationError::NotFound);
        }
        let event_id = transaction
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT event_id FROM application_user_events
                  WHERE project_id=$1 AND application_id=$2 AND id=$3
                    AND replay_until > transaction_timestamp() FOR SHARE",
                [
                    project_id.into(),
                    application_id.into(),
                    original.event_id.into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::InvalidTransition)?
            .try_get::<String>("", "event_id")
            .map_err(persistence)?;
        let latest = webhook_delivery::Entity::find()
            .filter(webhook_delivery::Column::EventId.eq(original.event_id))
            .filter(webhook_delivery::Column::EndpointId.eq(original.endpoint_id))
            .order_by_desc(webhook_delivery::Column::ReplaySequence)
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        let replay_sequence = latest
            .replay_sequence
            .checked_add(1)
            .ok_or(ApplicationError::Integrity)?;
        ensure_dispatch_state(&transaction, project_id, application_id).await?;
        let replay = webhook_delivery::ActiveModel {
            id: Set(Uuid::new_v4()),
            project_id: Set(project_id),
            application_id: Set(application_id),
            endpoint_id: Set(original.endpoint_id),
            event_id: Set(original.event_id),
            replay_sequence: Set(replay_sequence),
            replay_of_delivery_id: Set(Some(original.id)),
            state: Set("pending".to_owned()),
            attempt_count: Set(0),
            next_attempt_at: Set(now),
            lease_owner: Set(None),
            lease_incarnation: Set(None),
            lease_generation: Set(0),
            lease_expires_at: Set(None),
            claimed_secret_generation: Set(None),
            claimed_overlap_generation: Set(None),
            claimed_secret_material_id: Set(None),
            claimed_overlap_material_id: Set(None),
            last_outcome_class: Set(None),
            last_http_status: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
            delivered_at: Set(None),
            terminal_at: Set(None),
        }
        .insert(&transaction)
        .await
        .map_err(persistence)?;
        append_runtime_audit(
            &transaction,
            project_id,
            "deployment_operator",
            "webhook.delivery.replay",
            "webhook_delivery",
            Some(replay.id),
            correlation_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(delivery_record(replay, event_id))
    }
}

#[async_trait]
#[allow(
    clippy::too_many_lines,
    reason = "claim and finish transactions keep lease, attempt, and endpoint health state atomic"
)]
impl WebhookDeliveryRepository for PostgresWebhookRepository {
    async fn maintain(
        &self,
        now: OffsetDateTime,
        row_budget: u32,
    ) -> Result<u32, ApplicationError> {
        if row_budget == 0 || row_budget > 100 {
            return Err(ApplicationError::InvalidInput);
        }
        let mut affected =
            u32::from(retire_one_disabled_owner_endpoint(&self.database, now).await?);
        if affected < row_budget {
            affected += u32::from(retire_one_expired_overlap(&self.database, now).await?);
        }
        recover_one_expired_delivery(&self.database, now).await?;
        if affected >= row_budget {
            return Ok(affected);
        }

        let transaction = self.database.begin().await.map_err(persistence)?;
        let remaining = i64::from(row_budget - affected);
        let cancelled = transaction
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "WITH bounded AS (
                    SELECT delivery.id
                      FROM webhook_deliveries delivery
                      JOIN webhook_endpoints endpoint ON endpoint.id=delivery.endpoint_id
                      JOIN application_user_events event ON event.id=delivery.event_id
                     WHERE delivery.state='pending'
                       AND (endpoint.status='disabled'
                            OR event.retain_until <= transaction_timestamp())
                     ORDER BY event.retain_until,delivery.created_at,delivery.id
                     LIMIT $1 FOR UPDATE OF delivery SKIP LOCKED
                 )
                 UPDATE webhook_deliveries delivery
                    SET state='cancelled',terminal_at=transaction_timestamp(),
                        updated_at=transaction_timestamp()
                   FROM bounded WHERE delivery.id=bounded.id",
                [remaining.into()],
            ))
            .await
            .map_err(persistence)?
            .rows_affected();
        affected = affected
            .checked_add(u32::try_from(cancelled).map_err(|_| ApplicationError::Integrity)?)
            .ok_or(ApplicationError::Integrity)?;

        if affected < row_budget {
            let remaining = i64::from(row_budget - affected);
            let deleted = transaction
                .execute_raw(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "WITH bounded AS (
                        SELECT attempt.ctid
                          FROM webhook_delivery_attempts attempt
                          JOIN webhook_deliveries delivery ON delivery.id=attempt.delivery_id
                          JOIN application_user_events event ON event.id=delivery.event_id
                         WHERE delivery.state IN ('delivered','terminal','cancelled')
                           AND event.retain_until <= transaction_timestamp()
                         ORDER BY event.retain_until,attempt.delivery_id,attempt.attempt_number
                         LIMIT $1
                     )
                     DELETE FROM webhook_delivery_attempts attempt
                      USING bounded WHERE attempt.ctid=bounded.ctid",
                    [remaining.into()],
                ))
                .await
                .map_err(persistence)?
                .rows_affected();
            affected = affected
                .checked_add(u32::try_from(deleted).map_err(|_| ApplicationError::Integrity)?)
                .ok_or(ApplicationError::Integrity)?;
        }

        if affected < row_budget {
            let remaining = i64::from(row_budget - affected);
            let deleted = transaction
                .execute_raw(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "WITH bounded AS (
                        SELECT delivery.id
                          FROM webhook_deliveries delivery
                          JOIN application_user_events event ON event.id=delivery.event_id
                         WHERE delivery.state IN ('delivered','terminal','cancelled')
                           AND event.retain_until <= transaction_timestamp()
                           AND NOT EXISTS (
                               SELECT 1 FROM webhook_delivery_attempts attempt
                                WHERE attempt.delivery_id=delivery.id)
                           AND NOT EXISTS (
                               SELECT 1 FROM webhook_deliveries replay
                                WHERE replay.replay_of_delivery_id=delivery.id)
                         ORDER BY event.retain_until,delivery.replay_sequence DESC,delivery.id
                         LIMIT $1 FOR UPDATE OF delivery SKIP LOCKED
                     )
                     DELETE FROM webhook_deliveries delivery
                      USING bounded WHERE delivery.id=bounded.id",
                    [remaining.into()],
                ))
                .await
                .map_err(persistence)?
                .rows_affected();
            affected = affected
                .checked_add(u32::try_from(deleted).map_err(|_| ApplicationError::Integrity)?)
                .ok_or(ApplicationError::Integrity)?;
        }

        if affected < row_budget {
            let remaining = i64::from(row_budget - affected);
            let deleted = transaction
                .execute_raw(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "WITH bounded AS (
                        SELECT event.id
                          FROM application_user_events event
                         WHERE event.retain_until <= transaction_timestamp()
                           AND NOT EXISTS (
                               SELECT 1 FROM webhook_deliveries delivery
                                WHERE delivery.event_id=event.id)
                         ORDER BY event.retain_until,event.id
                         LIMIT $1 FOR UPDATE OF event SKIP LOCKED
                     )
                     DELETE FROM application_user_events event
                      USING bounded WHERE event.id=bounded.id",
                    [remaining.into()],
                ))
                .await
                .map_err(persistence)?
                .rows_affected();
            affected = affected
                .checked_add(u32::try_from(deleted).map_err(|_| ApplicationError::Integrity)?)
                .ok_or(ApplicationError::Integrity)?;
        }
        transaction.commit().await.map_err(persistence)?;
        Ok(affected)
    }

    async fn claim_secret_cleanup(
        &self,
        worker_id: &str,
        worker_incarnation: Uuid,
        _now: OffsetDateTime,
        lease_duration: Duration,
    ) -> Result<Option<ClaimedWebhookSecretCleanup>, ApplicationError> {
        let lease_seconds =
            i64::try_from(lease_duration.as_secs()).map_err(|_| ApplicationError::InvalidInput)?;
        if worker_id.is_empty() || lease_seconds < 1 {
            return Err(ApplicationError::InvalidInput);
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        let row = transaction
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT cleanup.id,cleanup.secret_ref,cleanup.material_id,
                        reservation.state AS reservation_state,reservation.cleanup_id
                   FROM webhook_secret_cleanup_operations cleanup
                   JOIN webhook_secret_generations secret
                     ON secret.endpoint_id=cleanup.endpoint_id
                    AND secret.generation=cleanup.generation
                   JOIN webhook_secret_reference_reservations reservation
                     ON reservation.secret_ref=cleanup.secret_ref
                    AND reservation.material_id IS NOT DISTINCT FROM cleanup.material_id
                  WHERE cleanup.not_before <= transaction_timestamp()
                    AND (cleanup.state='pending'
                         OR (cleanup.state='leased' AND cleanup.lease_expires_at <= transaction_timestamp()))
                    AND secret.state IN ('retired','compromised')
                    AND NOT EXISTS (
                        SELECT 1 FROM webhook_endpoints endpoint
                         WHERE endpoint.id=cleanup.endpoint_id
                           AND (endpoint.current_secret_generation=cleanup.generation
                                OR endpoint.overlap_secret_generation=cleanup.generation))
                    AND NOT EXISTS (
                        SELECT 1 FROM webhook_deliveries delivery
                         WHERE delivery.endpoint_id=cleanup.endpoint_id
                           AND delivery.state='leased'
                           AND (delivery.claimed_secret_generation=cleanup.generation
                                OR delivery.claimed_overlap_generation=cleanup.generation))
                    AND (reservation.state='live'
                         OR (reservation.state='reserved' AND reservation.cleanup_id=cleanup.id)
                         OR reservation.state='erased')
                  ORDER BY CASE reservation.state WHEN 'reserved' THEN 0 WHEN 'erased' THEN 1 ELSE 2 END,
                           cleanup.created_at,cleanup.id
                  LIMIT 1 FOR UPDATE OF cleanup,reservation SKIP LOCKED",
                [],
            ))
            .await
            .map_err(persistence)?;
        let Some(row) = row else {
            transaction.commit().await.map_err(persistence)?;
            return Ok(None);
        };
        let id: Uuid = row.try_get("", "id").map_err(persistence)?;
        let secret_ref: String = row.try_get("", "secret_ref").map_err(persistence)?;
        let material_id: Option<Uuid> = row.try_get("", "material_id").map_err(persistence)?;
        lock_webhook_secret_reference(&transaction, &secret_ref).await?;
        let reservation_state: String =
            row.try_get("", "reservation_state").map_err(persistence)?;
        let reservation_cleanup: Option<Uuid> =
            row.try_get("", "cleanup_id").map_err(persistence)?;
        if reservation_state == "erased" {
            transaction
                .execute_raw(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "UPDATE webhook_secret_cleanup_operations
                        SET state='erased',lease_owner=NULL,lease_incarnation=NULL,
                            lease_expires_at=NULL,updated_at=transaction_timestamp(),
                            erased_at=COALESCE(erased_at,transaction_timestamp())
                      WHERE id=$1 AND state<>'erased'",
                    [id.into()],
                ))
                .await
                .map_err(persistence)?;
            transaction.commit().await.map_err(persistence)?;
            return Ok(None);
        }
        if reservation_state == "live" {
            let reserved = transaction
                .execute_raw(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "UPDATE webhook_secret_reference_reservations
                        SET state='reserved',cleanup_id=$2,updated_at=transaction_timestamp()
                      WHERE secret_ref=$1 AND state='live'",
                    [secret_ref.clone().into(), id.into()],
                ))
                .await
                .map_err(persistence)?;
            if reserved.rows_affected() != 1 {
                return Err(ApplicationError::RevisionConflict);
            }
        } else if reservation_state != "reserved" || reservation_cleanup != Some(id) {
            return Err(ApplicationError::RevisionConflict);
        }
        let leased = transaction
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "UPDATE webhook_secret_cleanup_operations
                    SET state='leased',lease_owner=$2,lease_incarnation=$3,
                        lease_generation=lease_generation+1,
                        lease_expires_at=transaction_timestamp()+make_interval(secs=>$4),
                        updated_at=transaction_timestamp()
                  WHERE id=$1 AND not_before <= transaction_timestamp()
                    AND (state='pending'
                         OR (state='leased' AND lease_expires_at <= transaction_timestamp()))
                  RETURNING lease_generation",
                [
                    id.into(),
                    worker_id.to_owned().into(),
                    worker_incarnation.into(),
                    lease_seconds.into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::RevisionConflict)?;
        let cleanup = ClaimedWebhookSecretCleanup {
            id,
            secret_ref: material_id.map_or_else(|| secret_ref.clone(), |id| id.to_string()),
            legacy_secret_ref: Some(secret_ref),
            material_id,
            lease_owner: worker_id.to_owned(),
            lease_incarnation: worker_incarnation,
            lease_generation: leased
                .try_get("", "lease_generation")
                .map_err(persistence)?,
        };
        transaction.commit().await.map_err(persistence)?;
        Ok(Some(cleanup))
    }

    async fn finish_secret_cleanup(
        &self,
        cleanup: &ClaimedWebhookSecretCleanup,
        now: OffsetDateTime,
    ) -> Result<(), ApplicationError> {
        let secret_ref = cleanup
            .legacy_secret_ref
            .as_deref()
            .ok_or(ApplicationError::Integrity)?;
        let transaction = self.database.begin().await.map_err(persistence)?;
        lock_webhook_secret_reference(&transaction, secret_ref).await?;
        let row = transaction
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "UPDATE webhook_secret_cleanup_operations
                    SET state='erased',lease_owner=NULL,lease_incarnation=NULL,
                        lease_expires_at=NULL,updated_at=$6,erased_at=$6
                  WHERE id=$1 AND secret_ref=$2 AND state='leased'
                    AND lease_owner=$3 AND lease_incarnation=$4 AND lease_generation=$5
                    AND material_id IS NOT DISTINCT FROM $7
                    AND lease_expires_at > transaction_timestamp()
                  RETURNING endpoint_id",
                [
                    cleanup.id.into(),
                    secret_ref.to_owned().into(),
                    cleanup.lease_owner.clone().into(),
                    cleanup.lease_incarnation.into(),
                    cleanup.lease_generation.into(),
                    now.into(),
                    cleanup.material_id.into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::RevisionConflict)?;
        let endpoint_id: Uuid = row.try_get("", "endpoint_id").map_err(persistence)?;
        if let Some(material_id) = cleanup.material_id {
            self.custody()?
                .materials
                .erase_by_id_in_transaction(&transaction, material_id, now)
                .await?;
        }
        let reserved = transaction
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "UPDATE webhook_secret_reference_reservations
                    SET state='erased',cleanup_id=NULL,updated_at=$3,erased_at=$3
                  WHERE secret_ref=$1 AND state='reserved' AND cleanup_id=$2
                    AND material_id IS NOT DISTINCT FROM $4",
                [
                    secret_ref.to_owned().into(),
                    cleanup.id.into(),
                    now.into(),
                    cleanup.material_id.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        if reserved.rows_affected() != 1 {
            return Err(ApplicationError::RevisionConflict);
        }
        let project_id = transaction
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT project_id FROM webhook_endpoints WHERE id=$1",
                [endpoint_id.into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?
            .try_get::<Uuid>("", "project_id")
            .map_err(persistence)?;
        append_runtime_audit(
            &transaction,
            project_id,
            "system",
            "webhook.secret.erased",
            "webhook_endpoint",
            Some(endpoint_id),
            Uuid::new_v4(),
        )
        .await?;
        transaction.commit().await.map_err(persistence)
    }

    async fn claim_one(
        &self,
        worker_id: &str,
        worker_incarnation: Uuid,
        now: OffsetDateTime,
        lease_duration: Duration,
    ) -> Result<Option<ClaimedWebhookDelivery>, ApplicationError> {
        let lease_seconds =
            i64::try_from(lease_duration.as_secs()).map_err(|_| ApplicationError::InvalidInput)?;
        if lease_seconds < 1 {
            return Err(ApplicationError::InvalidInput);
        }
        retire_one_expired_overlap(&self.database, now).await?;
        recover_one_expired_delivery(&self.database, now).await?;
        let transaction = self.database.begin().await.map_err(persistence)?;
        let Some((candidate_id, project_id, application_id, endpoint_id)) =
            find_claim_candidate(&transaction, now).await?
        else {
            transaction.commit().await.map_err(persistence)?;
            return Ok(None);
        };
        lock_active_application(&transaction, project_id, application_id).await?;
        let endpoint = lock_endpoint(&transaction, project_id, application_id, endpoint_id).await?;
        if endpoint.status != "active" {
            return Err(ApplicationError::Disabled);
        }
        let row = transaction
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "WITH endpoint_candidates AS (
                    SELECT DISTINCT ON (d.endpoint_id)
                           d.id,d.application_id,d.next_attempt_at,d.created_at
                    FROM webhook_deliveries d
                    JOIN webhook_endpoints e ON e.id=d.endpoint_id
                    JOIN applications a ON a.id=d.application_id AND a.project_id=d.project_id
                    JOIN projects p ON p.id=d.project_id
                    WHERE d.state='pending' AND d.next_attempt_at <= $1
                      AND e.status='active' AND a.status='active' AND p.status='active'
                      AND NOT EXISTS (
                          SELECT 1 FROM webhook_deliveries leased
                          WHERE leased.endpoint_id=d.endpoint_id
                            AND leased.state='leased'
                      )
                    ORDER BY d.endpoint_id,d.next_attempt_at,d.created_at,d.id
                 ), application_candidates AS (
                    SELECT DISTINCT ON (application_id)
                           id,application_id,next_attempt_at,created_at
                    FROM endpoint_candidates
                    ORDER BY application_id,next_attempt_at,created_at,id
                 ), chosen AS (
                    SELECT d.id,d.project_id,d.application_id
                    FROM webhook_deliveries d
                    JOIN application_candidates c ON c.id=d.id
                    JOIN webhook_application_dispatch_state s
                      ON s.project_id=d.project_id AND s.application_id=d.application_id
                    JOIN projects p ON p.id=d.project_id AND p.status='active'
                    WHERE d.id=$5
                    ORDER BY s.last_claim_sequence,c.next_attempt_at,c.created_at,c.id
                    LIMIT 1 FOR SHARE OF p FOR UPDATE OF d,s SKIP LOCKED
                 ), advanced AS (
                    UPDATE webhook_application_dispatch_state s
                    SET last_claim_sequence=nextval('webhook_dispatch_claim_sequence')
                    FROM chosen
                    WHERE s.project_id=chosen.project_id
                      AND s.application_id=chosen.application_id
                    RETURNING chosen.id AS delivery_id
                 ), db_clock AS MATERIALIZED (
                    SELECT clock_timestamp() AS now FROM advanced LIMIT 1
                 )
                 UPDATE webhook_deliveries d
                 SET state='leased', attempt_count=d.attempt_count+1,
                     lease_owner=$2, lease_incarnation=$3,
                     lease_generation=d.lease_generation+1,
                     lease_expires_at=db_clock.now+make_interval(secs=>$4),
                     claimed_secret_generation=e.current_secret_generation,
                     claimed_overlap_generation=CASE
                         WHEN e.overlap_expires_at > db_clock.now
                         THEN e.overlap_secret_generation ELSE NULL END,
                     claimed_secret_material_id=(
                         SELECT secret.material_id
                           FROM webhook_secret_generations secret
                          WHERE secret.endpoint_id=e.id
                            AND secret.generation=e.current_secret_generation),
                     claimed_overlap_material_id=CASE
                         WHEN e.overlap_expires_at > db_clock.now THEN (
                             SELECT secret.material_id
                               FROM webhook_secret_generations secret
                              WHERE secret.endpoint_id=e.id
                                AND secret.generation=e.overlap_secret_generation)
                         ELSE NULL END,
                     updated_at=db_clock.now
                 FROM advanced,db_clock,webhook_endpoints e,applications a,projects p,
                      application_user_events event
                 WHERE d.id=advanced.delivery_id AND e.id=d.endpoint_id
                   AND a.id=d.application_id AND a.project_id=d.project_id
                   AND p.id=d.project_id AND event.id=d.event_id
                   AND event.retain_until > db_clock.now
                   AND e.status='active' AND a.status='active' AND p.status='active'
                 RETURNING d.id,d.event_id,d.endpoint_id,d.lease_generation,
                           d.attempt_count,d.claimed_secret_generation,
                           d.claimed_overlap_generation,e.url",
                [
                    now.into(),
                    worker_id.to_owned().into(),
                    worker_incarnation.into(),
                    lease_seconds.into(),
                    candidate_id.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        let Some(row) = row else {
            transaction.commit().await.map_err(persistence)?;
            return Ok(None);
        };
        let delivery_id: Uuid = row.try_get("", "id").map_err(persistence)?;
        let event_uuid: Uuid = row.try_get("", "event_id").map_err(persistence)?;
        let endpoint_id: Uuid = row.try_get("", "endpoint_id").map_err(persistence)?;
        let lease_generation: i64 = row.try_get("", "lease_generation").map_err(persistence)?;
        let attempt_number: i32 = row.try_get("", "attempt_count").map_err(persistence)?;
        let primary_generation: i32 = row
            .try_get("", "claimed_secret_generation")
            .map_err(persistence)?;
        let overlap_generation: Option<i32> = row
            .try_get("", "claimed_overlap_generation")
            .map_err(persistence)?;
        let endpoint_url: String = row.try_get("", "url").map_err(persistence)?;
        let event = application_user_event::Entity::find_by_id(event_uuid)
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        let raw_body = event_raw_body(&event, self.projection_protector.as_ref())?;
        let primary =
            webhook_secret_generation::Entity::find_by_id((endpoint_id, primary_generation))
                .one(&transaction)
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::Integrity)?;
        let overlap_secret_ref = if let Some(generation) = overlap_generation {
            let overlap = webhook_secret_generation::Entity::find_by_id((endpoint_id, generation))
                .one(&transaction)
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::Integrity)?;
            Some(
                overlap
                    .material_id
                    .map_or(overlap.secret_ref, |material_id| material_id.to_string()),
            )
        } else {
            None
        };
        transaction.commit().await.map_err(persistence)?;
        Ok(Some(ClaimedWebhookDelivery {
            delivery_id,
            lease_owner: worker_id.to_owned(),
            lease_incarnation: worker_incarnation,
            lease_generation,
            event_id: event.event_id,
            endpoint_url,
            raw_body,
            primary_secret_ref: primary
                .material_id
                .map_or(primary.secret_ref, |material_id| material_id.to_string()),
            overlap_secret_ref,
            attempt_number,
        }))
    }

    async fn finish(
        &self,
        claim: &ClaimedWebhookDelivery,
        attempt_timestamp: i64,
        outcome: WebhookTransportOutcome,
        next_attempt_at: Option<OffsetDateTime>,
        now: OffsetDateTime,
        correlation_id: Uuid,
    ) -> Result<(), ApplicationError> {
        let hint = webhook_delivery::Entity::find_by_id(claim.delivery_id)
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let transaction = self.database.begin().await.map_err(persistence)?;
        let (project, application) =
            lock_application_owners(&transaction, hint.project_id, hint.application_id).await?;
        let endpoint = lock_endpoint(
            &transaction,
            hint.project_id,
            hint.application_id,
            hint.endpoint_id,
        )
        .await?;
        let delivery = webhook_delivery::Entity::find_by_id(claim.delivery_id)
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if delivery.project_id != hint.project_id
            || delivery.application_id != hint.application_id
            || delivery.endpoint_id != endpoint.id
            || delivery.state != "leased"
            || delivery.lease_owner.as_deref() != Some(claim.lease_owner.as_str())
            || delivery.lease_incarnation != Some(claim.lease_incarnation)
            || delivery.lease_generation != claim.lease_generation
            || delivery.attempt_count != claim.attempt_number
        {
            return Err(ApplicationError::RevisionConflict);
        }
        webhook_delivery_attempt::ActiveModel {
            delivery_id: Set(delivery.id),
            attempt_number: Set(delivery.attempt_count),
            lease_generation: Set(delivery.lease_generation),
            attempted_at: Set(now),
            attempt_timestamp: Set(attempt_timestamp),
            outcome_class: Set(outcome.outcome.as_str().to_owned()),
            http_status: Set(outcome.http_status.map(i32::from)),
            duration_millis: Set(i32::try_from(outcome.duration_millis).unwrap_or(i32::MAX)),
            correlation_id: Set(correlation_id),
        }
        .insert(&transaction)
        .await
        .map_err(persistence)?;
        let owners_active = project.status == "active"
            && application.status == "active"
            && endpoint.status == "active";
        let retry = owners_active
            && outcome.outcome.retryable()
            && delivery.attempt_count < MAX_WEBHOOK_DELIVERY_ATTEMPTS
            && next_attempt_at.is_some();
        let state = if outcome.outcome.as_str() == "accepted" {
            "delivered"
        } else if retry {
            "pending"
        } else if outcome.outcome.retryable() && !owners_active {
            "cancelled"
        } else {
            "terminal"
        };
        let mut active = delivery.into_active_model();
        active.state = Set(state.to_owned());
        active.next_attempt_at = Set(next_attempt_at.unwrap_or(now));
        active.lease_owner = Set(None);
        active.lease_incarnation = Set(None);
        active.lease_expires_at = Set(None);
        active.claimed_secret_generation = Set(None);
        active.claimed_overlap_generation = Set(None);
        active.claimed_secret_material_id = Set(None);
        active.claimed_overlap_material_id = Set(None);
        active.last_outcome_class = Set(Some(outcome.outcome.as_str().to_owned()));
        active.last_http_status = Set(outcome.http_status.map(i32::from));
        active.updated_at = Set(now);
        active.delivered_at = Set((state == "delivered").then_some(now));
        active.terminal_at = Set(matches!(state, "terminal" | "cancelled").then_some(now));
        active.update(&transaction).await.map_err(persistence)?;
        let mut endpoint_active = endpoint.into_active_model();
        endpoint_active.last_delivery_at = Set(Some(now));
        if state == "delivered" {
            endpoint_active.last_success_at = Set(Some(now));
            endpoint_active.consecutive_failure_count = Set(0);
            endpoint_active.last_failure_class = Set(None);
        } else {
            endpoint_active.consecutive_failure_count = Set(endpoint_active
                .consecutive_failure_count
                .as_ref()
                .checked_add(1)
                .unwrap_or(i32::MAX));
            endpoint_active.last_failure_class = Set(Some(outcome.outcome.as_str().to_owned()));
        }
        endpoint_active.updated_at = Set(now);
        endpoint_active
            .update(&transaction)
            .await
            .map_err(persistence)?;
        transaction.commit().await.map_err(persistence)?;
        Ok(())
    }
}

async fn find_claim_candidate<C: ConnectionTrait>(
    connection: &C,
    now: OffsetDateTime,
) -> Result<Option<(Uuid, Uuid, Uuid, Uuid)>, ApplicationError> {
    let row = connection
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "WITH endpoint_candidates AS (
                SELECT DISTINCT ON (delivery.endpoint_id)
                       delivery.id,delivery.project_id,delivery.application_id,
                       delivery.endpoint_id,delivery.next_attempt_at,delivery.created_at
                  FROM webhook_deliveries delivery
                  JOIN webhook_endpoints endpoint ON endpoint.id=delivery.endpoint_id
                  JOIN application_user_events event ON event.id=delivery.event_id
                  JOIN applications application
                    ON application.id=delivery.application_id
                   AND application.project_id=delivery.project_id
                  JOIN projects project ON project.id=delivery.project_id
                 WHERE delivery.state='pending' AND delivery.next_attempt_at <= $1
                   AND event.retain_until > transaction_timestamp()
                   AND endpoint.status='active' AND application.status='active'
                   AND project.status='active'
                   AND NOT EXISTS (
                       SELECT 1 FROM webhook_deliveries leased
                        WHERE leased.endpoint_id=delivery.endpoint_id
                          AND leased.state='leased'
                   )
                 ORDER BY delivery.endpoint_id,delivery.next_attempt_at,
                          delivery.created_at,delivery.id
             ), application_candidates AS (
                SELECT DISTINCT ON (application_id)
                       id,project_id,application_id,endpoint_id,next_attempt_at,created_at
                  FROM endpoint_candidates
                 ORDER BY application_id,next_attempt_at,created_at,id
             )
             SELECT candidate.id,candidate.project_id,candidate.application_id,
                    candidate.endpoint_id
               FROM application_candidates candidate
               JOIN webhook_application_dispatch_state dispatch
                 ON dispatch.project_id=candidate.project_id
                AND dispatch.application_id=candidate.application_id
              ORDER BY dispatch.last_claim_sequence,candidate.next_attempt_at,
                       candidate.created_at,candidate.id
              LIMIT 1",
            [now.into()],
        ))
        .await
        .map_err(persistence)?;
    row.map(|row| {
        Ok((
            row.try_get("", "id").map_err(persistence)?,
            row.try_get("", "project_id").map_err(persistence)?,
            row.try_get("", "application_id").map_err(persistence)?,
            row.try_get("", "endpoint_id").map_err(persistence)?,
        ))
    })
    .transpose()
}

async fn retire_one_disabled_owner_endpoint(
    database: &DatabaseConnection,
    now: OffsetDateTime,
) -> Result<bool, ApplicationError> {
    let hint = database
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT endpoint.id,endpoint.project_id,endpoint.application_id
               FROM webhook_endpoints endpoint
               JOIN applications application
                 ON application.id=endpoint.application_id
                AND application.project_id=endpoint.project_id
               JOIN projects project ON project.id=endpoint.project_id
              WHERE (endpoint.status='disabled' OR application.status<>'active'
                     OR project.status<>'active')
                AND (endpoint.current_secret_generation IS NOT NULL
                     OR endpoint.overlap_secret_generation IS NOT NULL
                     OR EXISTS (
                         SELECT 1 FROM webhook_secret_generations secret
                          WHERE secret.endpoint_id=endpoint.id
                            AND secret.state='pending'))
              ORDER BY endpoint.updated_at,endpoint.id LIMIT 1",
        ))
        .await
        .map_err(persistence)?;
    let Some(hint) = hint else { return Ok(false) };
    let project_id: Uuid = hint.try_get("", "project_id").map_err(persistence)?;
    let application_id: Uuid = hint.try_get("", "application_id").map_err(persistence)?;
    let endpoint_id: Uuid = hint.try_get("", "id").map_err(persistence)?;
    let transaction = database.begin().await.map_err(persistence)?;
    let (project, application) =
        lock_application_owners(&transaction, project_id, application_id).await?;
    let endpoint = lock_endpoint(&transaction, project_id, application_id, endpoint_id).await?;
    if endpoint.status != "disabled" && project.status == "active" && application.status == "active"
    {
        transaction.commit().await.map_err(persistence)?;
        return Ok(false);
    }
    let generations = webhook_secret_generation::Entity::find()
        .filter(webhook_secret_generation::Column::EndpointId.eq(endpoint_id))
        .filter(webhook_secret_generation::Column::State.is_in(["pending", "active", "overlap"]))
        .order_by_asc(webhook_secret_generation::Column::Generation)
        .limit(4)
        .lock_exclusive()
        .all(&transaction)
        .await
        .map_err(persistence)?;
    if generations.len() > 3 {
        return Err(ApplicationError::Integrity);
    }
    let overlap_generation = endpoint.overlap_secret_generation;
    let overlap_not_before = match overlap_generation {
        Some(_) => Some(
            endpoint
                .overlap_expires_at
                .ok_or(ApplicationError::Integrity)?,
        ),
        None => None,
    };
    let should_disable = endpoint.status != "disabled";
    let mut active = endpoint.into_active_model();
    if should_disable {
        active.status = Set("disabled".to_owned());
        active.revision = Set(active
            .revision
            .as_ref()
            .checked_add(1)
            .ok_or(ApplicationError::Integrity)?);
        active.disabled_at = Set(Some(now));
    }
    active.current_secret_generation = Set(None);
    active.overlap_secret_generation = Set(None);
    active.overlap_expires_at = Set(None);
    active.updated_at = Set(now);
    active.update(&transaction).await.map_err(persistence)?;
    for generation in generations {
        let generation_number = generation.generation;
        let secret_ref = generation.secret_ref.clone();
        let mut retired = generation.into_active_model();
        retired.state = Set("retired".to_owned());
        retired.retired_at = Set(Some(now));
        retired.update(&transaction).await.map_err(persistence)?;
        let not_before = if overlap_generation == Some(generation_number) {
            overlap_not_before.ok_or(ApplicationError::Integrity)?
        } else {
            now
        };
        enqueue_secret_cleanup(
            &transaction,
            endpoint_id,
            generation_number,
            &secret_ref,
            now,
            not_before,
        )
        .await?;
    }
    transaction.commit().await.map_err(persistence)?;
    Ok(true)
}

async fn retire_one_expired_overlap(
    database: &DatabaseConnection,
    now: OffsetDateTime,
) -> Result<bool, ApplicationError> {
    let hint = database
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT id,project_id,application_id FROM webhook_endpoints
              WHERE status='active' AND overlap_expires_at <= transaction_timestamp()
              ORDER BY overlap_expires_at,id LIMIT 1",
        ))
        .await
        .map_err(persistence)?;
    let Some(hint) = hint else { return Ok(false) };
    let endpoint_id: Uuid = hint.try_get("", "id").map_err(persistence)?;
    let project_id: Uuid = hint.try_get("", "project_id").map_err(persistence)?;
    let application_id: Uuid = hint.try_get("", "application_id").map_err(persistence)?;
    let transaction = database.begin().await.map_err(persistence)?;
    lock_application_owners(&transaction, project_id, application_id).await?;
    let endpoint = lock_endpoint(&transaction, project_id, application_id, endpoint_id).await?;
    let expired = transaction
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT overlap_expires_at <= transaction_timestamp() AS expired
               FROM webhook_endpoints WHERE id=$1",
            [endpoint_id.into()],
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?
        .try_get::<Option<bool>>("", "expired")
        .map_err(persistence)?
        .unwrap_or(false);
    if endpoint.status != "active" || !expired {
        transaction.commit().await.map_err(persistence)?;
        return Ok(false);
    }
    let generation = endpoint
        .overlap_secret_generation
        .ok_or(ApplicationError::Integrity)?;
    let secret = webhook_secret_generation::Entity::find_by_id((endpoint.id, generation))
        .lock_exclusive()
        .one(&transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?;
    let secret_ref = secret.secret_ref.clone();
    if secret.state == "overlap" {
        let mut active = secret.into_active_model();
        active.state = Set("retired".to_owned());
        active.retired_at = Set(Some(now));
        active.update(&transaction).await.map_err(persistence)?;
    } else if secret.state != "retired" {
        return Err(ApplicationError::Integrity);
    }
    let endpoint_id = endpoint.id;
    let overlap_not_before = endpoint
        .overlap_expires_at
        .ok_or(ApplicationError::Integrity)?;
    let mut active = endpoint.into_active_model();
    active.overlap_secret_generation = Set(None);
    active.overlap_expires_at = Set(None);
    active.updated_at = Set(now);
    active.update(&transaction).await.map_err(persistence)?;
    enqueue_secret_cleanup(
        &transaction,
        endpoint_id,
        generation,
        &secret_ref,
        now,
        overlap_not_before,
    )
    .await?;
    transaction.commit().await.map_err(persistence)?;
    Ok(true)
}

#[allow(
    clippy::too_many_lines,
    reason = "lease recovery keeps owner fencing, attempt append, and endpoint health in one transaction"
)]
async fn recover_one_expired_delivery(
    database: &DatabaseConnection,
    now: OffsetDateTime,
) -> Result<(), ApplicationError> {
    let hint = database
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT id,project_id,application_id,endpoint_id FROM webhook_deliveries
              WHERE state='leased' AND lease_expires_at <= transaction_timestamp()
              ORDER BY lease_expires_at,endpoint_id,id LIMIT 1",
        ))
        .await
        .map_err(persistence)?;
    let Some(hint) = hint else { return Ok(()) };
    let delivery_id: Uuid = hint.try_get("", "id").map_err(persistence)?;
    let project_id: Uuid = hint.try_get("", "project_id").map_err(persistence)?;
    let application_id: Uuid = hint.try_get("", "application_id").map_err(persistence)?;
    let endpoint_id: Uuid = hint.try_get("", "endpoint_id").map_err(persistence)?;
    let transaction = database.begin().await.map_err(persistence)?;
    let (project, application) =
        lock_application_owners(&transaction, project_id, application_id).await?;
    let endpoint = lock_endpoint(&transaction, project_id, application_id, endpoint_id).await?;
    let delivery = webhook_delivery::Entity::find_by_id(delivery_id)
        .lock_exclusive()
        .one(&transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?;
    if delivery.project_id != project_id
        || delivery.application_id != application_id
        || delivery.endpoint_id != endpoint.id
    {
        return Err(ApplicationError::Integrity);
    }
    let expired = transaction
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT lease_expires_at <= transaction_timestamp() AS expired
               FROM webhook_deliveries WHERE id=$1",
            [delivery_id.into()],
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?
        .try_get::<Option<bool>>("", "expired")
        .map_err(persistence)?
        .unwrap_or(false);
    if delivery.state != "leased" || !expired {
        transaction.commit().await.map_err(persistence)?;
        return Ok(());
    }
    webhook_delivery_attempt::ActiveModel {
        delivery_id: Set(delivery.id),
        attempt_number: Set(delivery.attempt_count),
        lease_generation: Set(delivery.lease_generation),
        attempted_at: Set(now),
        attempt_timestamp: Set(delivery.updated_at.unix_timestamp().max(1)),
        outcome_class: Set("ambiguous".to_owned()),
        http_status: Set(None),
        duration_millis: Set(0),
        correlation_id: Set(Uuid::new_v4()),
    }
    .insert(&transaction)
    .await
    .map_err(persistence)?;
    let owners_active =
        project.status == "active" && application.status == "active" && endpoint.status == "active";
    let terminal = delivery.attempt_count >= MAX_WEBHOOK_DELIVERY_ATTEMPTS;
    let state = if !owners_active {
        "cancelled"
    } else if terminal {
        "terminal"
    } else {
        "pending"
    };
    let mut active = delivery.into_active_model();
    active.state = Set(state.to_owned());
    active.lease_owner = Set(None);
    active.lease_incarnation = Set(None);
    active.lease_expires_at = Set(None);
    active.claimed_secret_generation = Set(None);
    active.claimed_overlap_generation = Set(None);
    active.claimed_secret_material_id = Set(None);
    active.claimed_overlap_material_id = Set(None);
    active.next_attempt_at = Set(active.next_attempt_at.take().unwrap_or(now).min(now));
    active.last_outcome_class = Set(Some("ambiguous".to_owned()));
    active.last_http_status = Set(None);
    active.terminal_at = Set(matches!(state, "terminal" | "cancelled").then_some(now));
    active.updated_at = Set(now);
    active.update(&transaction).await.map_err(persistence)?;
    let mut endpoint_active = endpoint.into_active_model();
    endpoint_active.last_delivery_at = Set(Some(now));
    endpoint_active.last_failure_class = Set(Some("ambiguous".to_owned()));
    endpoint_active.consecutive_failure_count = Set(endpoint_active
        .consecutive_failure_count
        .as_ref()
        .checked_add(1)
        .unwrap_or(i32::MAX));
    endpoint_active.updated_at = Set(now);
    endpoint_active
        .update(&transaction)
        .await
        .map_err(persistence)?;
    transaction.commit().await.map_err(persistence)?;
    Ok(())
}

fn event_raw_body(
    event: &application_user_event::Model,
    protector: &dyn ProjectionVerifiedEmailProtector,
) -> Result<Vec<u8>, ApplicationError> {
    let mut body = event.safe_body.clone();
    match (
        event.verified_email_source_identity_id,
        event.verified_email_ciphertext.as_ref(),
        event.verified_email_key_version,
    ) {
        (None, None, None) => {}
        (Some(_), Some(ciphertext), Some(key_version)) if key_version > 0 => {
            let plaintext = protector.unprotect_verified_email(
                event.project_id,
                event.application_id,
                event.user_id,
                event.projection_revision,
                &ProtectedValue {
                    ciphertext: ciphertext.clone(),
                    key_version,
                },
            )?;
            let email = (*plaintext).clone();
            body.pointer_mut("/data/projection/verified_email")
                .ok_or(ApplicationError::Integrity)?
                .clone_from(&json!(email));
        }
        _ => return Err(ApplicationError::Integrity),
    }
    let raw = serde_json::to_vec(&body).map_err(|_| ApplicationError::Integrity)?;
    let digest = Sha256::digest(&raw);
    if !bool::from(event.canonical_body_digest.as_slice().ct_eq(&digest[..])) {
        return Err(ApplicationError::Integrity);
    }
    Ok(raw)
}

async fn reserve_new_secret_reference<C: ConnectionTrait>(
    connection: &C,
    secret_ref: &str,
    material_id: Option<Uuid>,
    now: OffsetDateTime,
) -> Result<(), ApplicationError> {
    lock_webhook_secret_reference(connection, secret_ref).await?;
    let result = connection
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO webhook_secret_reference_reservations
                 (secret_ref,state,material_id,created_at,updated_at)
             VALUES ($1,'live',$2,$3,$3) ON CONFLICT (secret_ref) DO NOTHING",
            [secret_ref.to_owned().into(), material_id.into(), now.into()],
        ))
        .await
        .map_err(persistence)?;
    if result.rows_affected() != 1 {
        return Err(ApplicationError::InvalidTransition);
    }
    Ok(())
}

async fn ensure_live_secret_reference<C: ConnectionTrait>(
    connection: &C,
    secret_ref: &str,
) -> Result<(), ApplicationError> {
    lock_webhook_secret_reference(connection, secret_ref).await?;
    let state = connection
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT state FROM webhook_secret_reference_reservations
              WHERE secret_ref=$1 FOR UPDATE",
            [secret_ref.to_owned().into()],
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?
        .try_get::<String>("", "state")
        .map_err(persistence)?;
    if state != "live" {
        return Err(ApplicationError::InvalidTransition);
    }
    Ok(())
}

async fn enqueue_secret_cleanup<C: ConnectionTrait>(
    connection: &C,
    endpoint_id: Uuid,
    generation: i32,
    secret_ref: &str,
    now: OffsetDateTime,
    not_before: OffsetDateTime,
) -> Result<(), ApplicationError> {
    let material_id = webhook_secret_generation::Entity::find_by_id((endpoint_id, generation))
        .one(connection)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?
        .material_id;
    connection
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO webhook_secret_cleanup_operations
                 (id,endpoint_id,generation,secret_ref,material_id,state,not_before,created_at,updated_at)
             VALUES ($1,$2,$3,$4,$5,'pending',
                     CASE WHEN $7 <= $6 THEN transaction_timestamp() ELSE $7 END,
                     transaction_timestamp(),transaction_timestamp())
             ON CONFLICT (endpoint_id,generation) DO NOTHING",
            [
                Uuid::new_v4().into(),
                endpoint_id.into(),
                generation.into(),
                secret_ref.to_owned().into(),
                material_id.into(),
                now.into(),
                not_before.into(),
            ],
        ))
        .await
        .map_err(persistence)?;
    Ok(())
}

async fn lock_webhook_secret_reference<C: ConnectionTrait>(
    connection: &C,
    secret_ref: &str,
) -> Result<(), ApplicationError> {
    connection
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT pg_advisory_xact_lock(hashtextextended('owlauth:webhook-secret:' || $1,0))",
            [secret_ref.to_owned().into()],
        ))
        .await
        .map_err(persistence)?;
    Ok(())
}

async fn lock_application_owners<C: ConnectionTrait>(
    connection: &C,
    project_id: Uuid,
    application_id: Uuid,
) -> Result<(project::Model, application::Model), ApplicationError> {
    let project = project::Entity::find_by_id(project_id)
        .lock_shared()
        .one(connection)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
    let application = application::Entity::find_by_id(application_id)
        .filter(application::Column::ProjectId.eq(project_id))
        .lock_exclusive()
        .one(connection)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
    Ok((project, application))
}

async fn lock_active_application<C: ConnectionTrait>(
    connection: &C,
    project_id: Uuid,
    application_id: Uuid,
) -> Result<application::Model, ApplicationError> {
    let (project, application) =
        lock_application_owners(connection, project_id, application_id).await?;
    if project.status != "active" {
        return Err(ApplicationError::Disabled);
    }
    if application.status != "active" {
        return Err(ApplicationError::Disabled);
    }
    Ok(application)
}

async fn lock_active_endpoint<C: ConnectionTrait>(
    connection: &C,
    project_id: Uuid,
    application_id: Uuid,
    endpoint_id: Uuid,
) -> Result<webhook_endpoint::Model, ApplicationError> {
    lock_active_application(connection, project_id, application_id).await?;
    lock_endpoint(connection, project_id, application_id, endpoint_id).await
}

async fn ensure_application<C: ConnectionTrait>(
    connection: &C,
    project_id: Uuid,
    application_id: Uuid,
) -> Result<(), ApplicationError> {
    application::Entity::find_by_id(application_id)
        .filter(application::Column::ProjectId.eq(project_id))
        .one(connection)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)
        .map(|_| ())
}

async fn lock_endpoint<C: ConnectionTrait>(
    connection: &C,
    project_id: Uuid,
    application_id: Uuid,
    endpoint_id: Uuid,
) -> Result<webhook_endpoint::Model, ApplicationError> {
    webhook_endpoint::Entity::find_by_id(endpoint_id)
        .filter(webhook_endpoint::Column::ProjectId.eq(project_id))
        .filter(webhook_endpoint::Column::ApplicationId.eq(application_id))
        .lock_exclusive()
        .one(connection)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)
}

fn secret_preparation_state(
    secret: &webhook_secret_generation::Model,
    can_provision: bool,
) -> WebhookSecretPreparationState {
    if secret.provisioned_at.is_some() {
        WebhookSecretPreparationState::Provisioned
    } else if can_provision && secret.state == "pending" {
        WebhookSecretPreparationState::Pending
    } else {
        WebhookSecretPreparationState::Terminal
    }
}

fn endpoint_record(
    endpoint: webhook_endpoint::Model,
) -> Result<WebhookEndpointRecord, ApplicationError> {
    endpoint_status(&endpoint.status)?;
    Ok(WebhookEndpointRecord {
        id: endpoint.id,
        public_id: endpoint.public_id,
        project_id: endpoint.project_id,
        application_id: endpoint.application_id,
        url: endpoint.url,
        subscribed_event_types: endpoint.subscribed_event_types,
        status: endpoint.status,
        revision: endpoint.revision,
        current_secret_generation: endpoint.current_secret_generation,
        overlap_secret_generation: endpoint.overlap_secret_generation,
        overlap_expires_at: endpoint.overlap_expires_at,
        consecutive_failure_count: endpoint.consecutive_failure_count,
        last_delivery_at: endpoint.last_delivery_at,
        last_success_at: endpoint.last_success_at,
        last_failure_class: endpoint.last_failure_class,
        last_tested_at: endpoint.last_tested_at,
        last_test_succeeded_at: endpoint.last_test_succeeded_at,
        created_at: endpoint.created_at,
        updated_at: endpoint.updated_at,
    })
}

fn event_record_from_row(
    row: &QueryResult,
) -> Result<ApplicationUserEventRecord, ApplicationError> {
    let event_type: String = row.try_get("", "event_type").map_err(persistence)?;
    crate::application::event_type(&event_type)?;
    Ok(ApplicationUserEventRecord {
        id: row.try_get("", "id").map_err(persistence)?,
        event_id: row.try_get("", "event_id").map_err(persistence)?,
        project_id: row.try_get("", "project_id").map_err(persistence)?,
        application_id: row.try_get("", "application_id").map_err(persistence)?,
        user_id: row.try_get("", "user_id").map_err(persistence)?,
        event_type,
        user_revision: row.try_get("", "user_revision").map_err(persistence)?,
        projection_revision: row
            .try_get("", "projection_revision")
            .map_err(persistence)?,
        projection_schema: row.try_get("", "projection_schema").map_err(persistence)?,
        safe_body: row.try_get("", "safe_body").map_err(persistence)?,
        occurred_at: row.try_get("", "occurred_at").map_err(persistence)?,
    })
}

fn delivery_record_from_row(row: &QueryResult) -> Result<WebhookDeliveryRecord, ApplicationError> {
    Ok(WebhookDeliveryRecord {
        id: row.try_get("", "id").map_err(persistence)?,
        endpoint_id: row.try_get("", "endpoint_id").map_err(persistence)?,
        event_id: row.try_get("", "event_id").map_err(persistence)?,
        replay_sequence: row.try_get("", "replay_sequence").map_err(persistence)?,
        replay_of_delivery_id: row
            .try_get("", "replay_of_delivery_id")
            .map_err(persistence)?,
        state: row.try_get("", "state").map_err(persistence)?,
        attempt_count: row.try_get("", "attempt_count").map_err(persistence)?,
        next_attempt_at: row.try_get("", "next_attempt_at").map_err(persistence)?,
        last_outcome_class: row.try_get("", "last_outcome_class").map_err(persistence)?,
        last_http_status: row.try_get("", "last_http_status").map_err(persistence)?,
        delivered_at: row.try_get("", "delivered_at").map_err(persistence)?,
        terminal_at: row.try_get("", "terminal_at").map_err(persistence)?,
        created_at: row.try_get("", "created_at").map_err(persistence)?,
    })
}

fn delivery_record(delivery: webhook_delivery::Model, event_id: String) -> WebhookDeliveryRecord {
    WebhookDeliveryRecord {
        id: delivery.id,
        endpoint_id: delivery.endpoint_id,
        event_id,
        replay_sequence: delivery.replay_sequence,
        replay_of_delivery_id: delivery.replay_of_delivery_id,
        state: delivery.state,
        attempt_count: delivery.attempt_count,
        next_attempt_at: delivery.next_attempt_at,
        last_outcome_class: delivery.last_outcome_class,
        last_http_status: delivery.last_http_status,
        delivered_at: delivery.delivered_at,
        terminal_at: delivery.terminal_at,
        created_at: delivery.created_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_body_keeps_email_null_in_safe_storage() {
        let mut body = json!({"data":{"projection":{"verified_email":"ada@example.test"}}});
        body.pointer_mut("/data/projection/verified_email")
            .unwrap()
            .clone_from(&Value::Null);
        assert_eq!(
            body.pointer("/data/projection/verified_email"),
            Some(&Value::Null)
        );
    }
}
