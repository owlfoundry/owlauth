use std::{collections::BTreeSet, sync::Arc, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, DatabaseConnection,
    DatabaseTransaction, DbErr, EntityTrait, IntoActiveModel, PaginatorTrait, QueryFilter,
    QueryOrder, QuerySelect, RuntimeErr, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use async_trait::async_trait;

use crate::{
    adapters::{
        postgres::entity::{
            application, application_origin, application_provider_assignment,
            application_publishable_key, application_redirect, audit_event,
            control_idempotency_record, key_provisioning_operation, key_state_event, project,
            project_key_ring, project_policy, project_signing_key, provider_configuration,
            provider_secret_operation, runtime_publication_lease,
        },
        software_store::{EncryptedFileStore, StoreError},
    },
    application::{
        ApplicationConfiguration, ApplicationError, ApplicationRecord, CreateApplication,
        CreateProject, CreateProvider, ProjectPolicyRecord, ProjectRecord, ProviderRecord,
        ProvisioningPort, ReplaceApplicationConfiguration, SigningKeyRecord, UpdateApplication,
        UpdateProject, UpdateProjectPolicy,
    },
    domain::{
        ApplicationStatus, ApplicationType, BrowserOrigin, DisplayName, OpaqueOwner, ProjectStatus,
        ProviderKey, ProviderStatus, PublicId, RedirectUri, SigningKeyState,
    },
};

const LIST_LIMIT: u64 = 100;
const CONFIGURATION_VALUE_LIMIT: usize = 50;
const SIGNING_PURPOSE: &str = "application_tokens";
const SIGNING_ALGORITHM: &str = "EdDSA";

#[derive(Clone)]
pub(crate) struct PostgresProvisioningAdapter {
    database: DatabaseConnection,
    signer_store: EncryptedFileStore,
    secret_store: EncryptedFileStore,
    runtime_base: Arc<Url>,
    required_runtime_process_ids: Arc<BTreeSet<String>>,
    propagation_delay: Duration,
    verification_retention: Duration,
}

impl PostgresProvisioningAdapter {
    pub(crate) fn new(
        database: DatabaseConnection,
        signer_store: EncryptedFileStore,
        secret_store: EncryptedFileStore,
        runtime_base: Url,
        required_runtime_process_ids: Vec<String>,
        propagation_delay: Duration,
        verification_retention: Duration,
    ) -> Self {
        Self {
            database,
            signer_store,
            secret_store,
            runtime_base: Arc::new(runtime_base),
            required_runtime_process_ids: Arc::new(
                required_runtime_process_ids.into_iter().collect(),
            ),
            propagation_delay,
            verification_retention,
        }
    }

    pub(crate) async fn create_project(
        &self,
        command: CreateProject,
        correlation_id: Uuid,
    ) -> Result<ProjectRecord, ApplicationError> {
        validate_idempotency_key(&command.idempotency_key)?;
        let display_name = DisplayName::parse(command.display_name)?.into_inner();
        let belongs_to = command
            .belongs_to
            .map(OpaqueOwner::parse)
            .transpose()?
            .map(OpaqueOwner::into_inner);
        let digest = request_digest(&json!({
            "display_name": display_name,
            "belongs_to": belongs_to,
        }))?;
        let transaction = self.database.begin().await.map_err(persistence)?;
        if let Some(replayed) = replay::<ProjectRecord>(
            &transaction,
            &command.idempotency_key,
            "project.create",
            "deployment",
            &digest,
        )
        .await?
        {
            transaction.commit().await.map_err(persistence)?;
            return Ok(replayed);
        }
        let id = Uuid::new_v4();
        let public_id = generated_id("prj");
        project::ActiveModel {
            id: Set(id),
            public_id: Set(public_id.clone()),
            belongs_to: Set(belongs_to.clone()),
            display_name: Set(display_name.clone()),
            status: Set("active".to_owned()),
            metadata_revision: Set(1),
            security_revision: Set(1),
            ..Default::default()
        }
        .insert(&transaction)
        .await
        .map_err(persistence)?;
        project_policy::ActiveModel {
            project_id: Set(id),
            claims_revision: Set(1),
            session_revision: Set(1),
            claims_policy: Set(json!({ "access_token_lifetime_seconds": 900 })),
            session_policy: Set(json!({ "browser_session_reuse": false })),
        }
        .insert(&transaction)
        .await
        .map_err(persistence)?;
        let record = ProjectRecord {
            id,
            public_id,
            display_name,
            belongs_to,
            status: "active".to_owned(),
            metadata_revision: 1,
            security_revision: 1,
        };
        insert_audit(
            &transaction,
            Some(id),
            "project.created",
            "project",
            Some(id),
            correlation_id,
        )
        .await?;
        complete_idempotency(
            &transaction,
            command.idempotency_key,
            Some(id),
            Some(id),
            "project.create",
            "deployment",
            digest,
            &record,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(record)
    }

    pub(crate) async fn list_projects(
        &self,
        belongs_to: Option<String>,
    ) -> Result<Vec<ProjectRecord>, ApplicationError> {
        let belongs_to = belongs_to
            .map(OpaqueOwner::parse)
            .transpose()?
            .map(OpaqueOwner::into_inner);
        let mut query = project::Entity::find();
        if let Some(owner) = belongs_to {
            query = query.filter(project::Column::BelongsTo.eq(owner));
        }
        query
            .order_by_asc(project::Column::CreatedAt)
            .order_by_asc(project::Column::Id)
            .limit(LIST_LIMIT + 1)
            .all(&self.database)
            .await
            .map_err(persistence)
            .and_then(bounded_list)
            .map(|models| models.into_iter().map(project_record).collect())
    }

    pub(crate) async fn get_project(
        &self,
        project_id: Uuid,
    ) -> Result<ProjectRecord, ApplicationError> {
        let model = project::Entity::find_by_id(project_id)
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        Ok(project_record(model))
    }

    pub(crate) async fn get_project_policy(
        &self,
        project_id: Uuid,
    ) -> Result<ProjectPolicyRecord, ApplicationError> {
        ensure_project(&self.database, project_id).await?;
        let policy = project_policy::Entity::find_by_id(project_id)
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        project_policy_record(&policy)
    }

    pub(crate) async fn update_project_policy(
        &self,
        project_id: Uuid,
        command: UpdateProjectPolicy,
        correlation_id: Uuid,
    ) -> Result<ProjectPolicyRecord, ApplicationError> {
        if !(60..=3600).contains(&command.access_token_lifetime_seconds) {
            return Err(ApplicationError::InvalidInput);
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        active_project(&transaction, project_id).await?;
        let policy = project_policy::Entity::find_by_id(project_id)
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if policy.claims_revision != command.expected_claims_revision
            || policy.session_revision != command.expected_session_revision
        {
            return Err(ApplicationError::RevisionConflict);
        }
        let mut active = policy.into_active_model();
        active.claims_policy = Set(json!({
            "access_token_lifetime_seconds": command.access_token_lifetime_seconds,
        }));
        active.session_policy = Set(json!({
            "browser_session_reuse": command.browser_session_reuse,
        }));
        active.claims_revision = Set(command.expected_claims_revision + 1);
        active.session_revision = Set(command.expected_session_revision + 1);
        let updated = active.update(&transaction).await.map_err(persistence)?;
        insert_audit(
            &transaction,
            Some(project_id),
            "project.policy_updated",
            "project_policy",
            Some(project_id),
            correlation_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        project_policy_record(&updated)
    }

    pub(crate) async fn update_project(
        &self,
        project_id: Uuid,
        command: UpdateProject,
        correlation_id: Uuid,
    ) -> Result<ProjectRecord, ApplicationError> {
        let display_name = DisplayName::parse(command.display_name)?.into_inner();
        let belongs_to = command
            .belongs_to
            .map(OpaqueOwner::parse)
            .transpose()?
            .map(OpaqueOwner::into_inner);
        let transaction = self.database.begin().await.map_err(persistence)?;
        let model = active_project(&transaction, project_id).await?;
        if model.metadata_revision != command.expected_metadata_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        let mut active = model.into_active_model();
        active.display_name = Set(display_name);
        active.belongs_to = Set(belongs_to);
        active.metadata_revision = Set(command.expected_metadata_revision + 1);
        active.updated_at = Set(OffsetDateTime::now_utc());
        let updated = active.update(&transaction).await.map_err(persistence)?;
        insert_audit(
            &transaction,
            Some(project_id),
            "project.metadata_updated",
            "project",
            Some(project_id),
            correlation_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(project_record(updated))
    }

    pub(crate) async fn disable_project(
        &self,
        project_id: Uuid,
        expected_security_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ProjectRecord, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        let model = active_project(&transaction, project_id).await?;
        if model.security_revision != expected_security_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        let mut status = ProjectStatus::Active;
        status
            .disable()
            .map_err(|_| ApplicationError::InvalidTransition)?;
        let mut active = model.into_active_model();
        active.status = Set(status.as_str().to_owned());
        active.security_revision = Set(expected_security_revision + 1);
        active.updated_at = Set(OffsetDateTime::now_utc());
        let updated = active.update(&transaction).await.map_err(persistence)?;
        insert_audit(
            &transaction,
            Some(project_id),
            "project.disabled",
            "project",
            Some(project_id),
            correlation_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(project_record(updated))
    }

    pub(crate) async fn create_application(
        &self,
        project_id: Uuid,
        command: CreateApplication,
        correlation_id: Uuid,
    ) -> Result<ApplicationRecord, ApplicationError> {
        validate_idempotency_key(&command.idempotency_key)?;
        let display_name = DisplayName::parse(command.display_name)?.into_inner();
        let digest = request_digest(&json!({
            "project_id": project_id,
            "display_name": display_name,
            "application_type": command.application_type.as_str(),
        }))?;
        let scope = project_id.to_string();
        let transaction = self.database.begin().await.map_err(persistence)?;
        active_project(&transaction, project_id).await?;
        if let Some(replayed) = replay::<ApplicationRecord>(
            &transaction,
            &command.idempotency_key,
            "application.create",
            &scope,
            &digest,
        )
        .await?
        {
            transaction.commit().await.map_err(persistence)?;
            return Ok(replayed);
        }
        let id = Uuid::new_v4();
        let public_id = generated_id("app");
        application::ActiveModel {
            id: Set(id),
            project_id: Set(project_id),
            public_id: Set(public_id.clone()),
            display_name: Set(display_name.clone()),
            application_type: Set(command.application_type.as_str().to_owned()),
            status: Set("active".to_owned()),
            revision: Set(1),
            metadata_revision: Set(1),
            security_revision: Set(1),
            ..Default::default()
        }
        .insert(&transaction)
        .await
        .map_err(persistence)?;
        let publishable_id = generated_id("owl_app");
        application_publishable_key::ActiveModel {
            id: Set(Uuid::new_v4()),
            project_id: Set(project_id),
            application_id: Set(id),
            public_id: Set(publishable_id.clone()),
            status: Set("active".to_owned()),
            revision: Set(1),
        }
        .insert(&transaction)
        .await
        .map_err(persistence)?;
        let record = ApplicationRecord {
            id,
            project_id,
            public_id,
            display_name,
            application_type: command.application_type.as_str().to_owned(),
            status: "active".to_owned(),
            metadata_revision: 1,
            security_revision: 1,
            configuration: ApplicationConfiguration {
                redirect_uris: Vec::new(),
                allowed_origins: Vec::new(),
                publishable_keys: vec![publishable_id],
            },
        };
        insert_audit(
            &transaction,
            Some(project_id),
            "application.created",
            "application",
            Some(id),
            correlation_id,
        )
        .await?;
        complete_idempotency(
            &transaction,
            command.idempotency_key,
            Some(project_id),
            Some(id),
            "application.create",
            &scope,
            digest,
            &record,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(record)
    }

    pub(crate) async fn list_applications(
        &self,
        project_id: Uuid,
    ) -> Result<Vec<ApplicationRecord>, ApplicationError> {
        ensure_project(&self.database, project_id).await?;
        let models = application::Entity::find()
            .filter(application::Column::ProjectId.eq(project_id))
            .order_by_asc(application::Column::CreatedAt)
            .order_by_asc(application::Column::Id)
            .limit(LIST_LIMIT + 1)
            .all(&self.database)
            .await
            .map_err(persistence)?;
        let models = bounded_list(models)?;
        let mut records = Vec::with_capacity(models.len());
        for model in models {
            records.push(self.application_record(model).await?);
        }
        Ok(records)
    }

    pub(crate) async fn get_application(
        &self,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<ApplicationRecord, ApplicationError> {
        let model = find_application(&self.database, project_id, application_id).await?;
        self.application_record(model).await
    }

    pub(crate) async fn update_application(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        command: UpdateApplication,
        correlation_id: Uuid,
    ) -> Result<ApplicationRecord, ApplicationError> {
        let display_name = DisplayName::parse(command.display_name)?.into_inner();
        let transaction = self.database.begin().await.map_err(persistence)?;
        active_project(&transaction, project_id).await?;
        let model = active_application(&transaction, project_id, application_id).await?;
        if model.metadata_revision != command.expected_metadata_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        let aggregate_revision = model.revision + 1;
        let mut active = model.into_active_model();
        active.display_name = Set(display_name);
        active.metadata_revision = Set(command.expected_metadata_revision + 1);
        active.revision = Set(aggregate_revision);
        active.updated_at = Set(OffsetDateTime::now_utc());
        let updated = active.update(&transaction).await.map_err(persistence)?;
        insert_audit(
            &transaction,
            Some(project_id),
            "application.metadata_updated",
            "application",
            Some(application_id),
            correlation_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        self.application_record(updated).await
    }

    pub(crate) async fn replace_application_configuration(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        command: ReplaceApplicationConfiguration,
        correlation_id: Uuid,
    ) -> Result<ApplicationRecord, ApplicationError> {
        if command.redirect_uris.len() > CONFIGURATION_VALUE_LIMIT
            || command.allowed_origins.len() > CONFIGURATION_VALUE_LIMIT
        {
            return Err(ApplicationError::InvalidInput);
        }
        let model = find_application(&self.database, project_id, application_id).await?;
        if model.status != "active" {
            return Err(ApplicationError::Disabled);
        }
        let application_type = parse_application_type(&model.application_type)?;
        let redirects = command
            .redirect_uris
            .into_iter()
            .map(|value| RedirectUri::parse(value, application_type))
            .collect::<Result<Vec<_>, _>>()?;
        let origins = command
            .allowed_origins
            .into_iter()
            .map(BrowserOrigin::parse)
            .collect::<Result<Vec<_>, _>>()?;
        reject_duplicates(redirects.iter().map(|value| value.clone().into_parts().0))?;
        reject_duplicates(origins.iter().map(|value| value.clone().into_inner()))?;

        let transaction = self.database.begin().await.map_err(persistence)?;
        active_project(&transaction, project_id).await?;
        let current = active_application(&transaction, project_id, application_id).await?;
        if current.security_revision != command.expected_security_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        application_redirect::Entity::delete_many()
            .filter(application_redirect::Column::ProjectId.eq(project_id))
            .filter(application_redirect::Column::ApplicationId.eq(application_id))
            .exec(&transaction)
            .await
            .map_err(persistence)?;
        application_origin::Entity::delete_many()
            .filter(application_origin::Column::ProjectId.eq(project_id))
            .filter(application_origin::Column::ApplicationId.eq(application_id))
            .exec(&transaction)
            .await
            .map_err(persistence)?;
        for redirect in redirects {
            let (uri, kind) = redirect.into_parts();
            application_redirect::ActiveModel {
                project_id: Set(project_id),
                application_id: Set(application_id),
                redirect_uri: Set(uri),
                redirect_type: Set(kind.as_str().to_owned()),
            }
            .insert(&transaction)
            .await
            .map_err(persistence)?;
        }
        for origin in origins {
            application_origin::ActiveModel {
                project_id: Set(project_id),
                application_id: Set(application_id),
                origin: Set(origin.into_inner()),
            }
            .insert(&transaction)
            .await
            .map_err(persistence)?;
        }
        let aggregate_revision = current.revision + 1;
        let mut active = current.into_active_model();
        active.security_revision = Set(command.expected_security_revision + 1);
        active.revision = Set(aggregate_revision);
        active.updated_at = Set(OffsetDateTime::now_utc());
        active.update(&transaction).await.map_err(persistence)?;
        insert_audit(
            &transaction,
            Some(project_id),
            "application.configuration_replaced",
            "application",
            Some(application_id),
            correlation_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        self.get_application(project_id, application_id).await
    }

    pub(crate) async fn disable_application(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        expected_security_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ApplicationRecord, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        active_project(&transaction, project_id).await?;
        let model = active_application(&transaction, project_id, application_id).await?;
        if model.security_revision != expected_security_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        let mut status = ApplicationStatus::Active;
        status
            .disable()
            .map_err(|_| ApplicationError::InvalidTransition)?;
        let aggregate_revision = model.revision + 1;
        let next_security_revision = expected_security_revision + 1;
        let assignments = application_provider_assignment::Entity::find()
            .filter(application_provider_assignment::Column::ProjectId.eq(project_id))
            .filter(application_provider_assignment::Column::ApplicationId.eq(application_id))
            .filter(application_provider_assignment::Column::Status.eq("active"))
            .all(&transaction)
            .await
            .map_err(persistence)?;
        for assignment in assignments {
            let mut active = assignment.into_active_model();
            active.status = Set("disabled".to_owned());
            active.security_revision = Set(next_security_revision);
            active.update(&transaction).await.map_err(persistence)?;
        }
        let publishable_keys = application_publishable_key::Entity::find()
            .filter(application_publishable_key::Column::ProjectId.eq(project_id))
            .filter(application_publishable_key::Column::ApplicationId.eq(application_id))
            .filter(application_publishable_key::Column::Status.eq("active"))
            .all(&transaction)
            .await
            .map_err(persistence)?;
        for publishable_key in publishable_keys {
            let mut active = publishable_key.into_active_model();
            active.status = Set("disabled".to_owned());
            active.revision = Set(next_security_revision);
            active.update(&transaction).await.map_err(persistence)?;
        }
        let mut active = model.into_active_model();
        active.status = Set(status.as_str().to_owned());
        active.security_revision = Set(next_security_revision);
        active.revision = Set(aggregate_revision);
        active.updated_at = Set(OffsetDateTime::now_utc());
        active.update(&transaction).await.map_err(persistence)?;
        insert_audit(
            &transaction,
            Some(project_id),
            "application.disabled",
            "application",
            Some(application_id),
            correlation_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        self.get_application(project_id, application_id).await
    }

    async fn application_record(
        &self,
        model: application::Model,
    ) -> Result<ApplicationRecord, ApplicationError> {
        let redirects = application_redirect::Entity::find()
            .filter(application_redirect::Column::ProjectId.eq(model.project_id))
            .filter(application_redirect::Column::ApplicationId.eq(model.id))
            .order_by_asc(application_redirect::Column::RedirectUri)
            .all(&self.database)
            .await
            .map_err(persistence)?
            .into_iter()
            .map(|value| value.redirect_uri)
            .collect();
        let origins = application_origin::Entity::find()
            .filter(application_origin::Column::ProjectId.eq(model.project_id))
            .filter(application_origin::Column::ApplicationId.eq(model.id))
            .order_by_asc(application_origin::Column::Origin)
            .all(&self.database)
            .await
            .map_err(persistence)?
            .into_iter()
            .map(|value| value.origin)
            .collect();
        let publishable_keys = application_publishable_key::Entity::find()
            .filter(application_publishable_key::Column::ProjectId.eq(model.project_id))
            .filter(application_publishable_key::Column::ApplicationId.eq(model.id))
            .filter(application_publishable_key::Column::Status.eq("active"))
            .order_by_asc(application_publishable_key::Column::PublicId)
            .all(&self.database)
            .await
            .map_err(persistence)?
            .into_iter()
            .map(|value| value.public_id)
            .collect();
        Ok(ApplicationRecord {
            id: model.id,
            project_id: model.project_id,
            public_id: model.public_id,
            display_name: model.display_name,
            application_type: model.application_type,
            status: model.status,
            metadata_revision: model.metadata_revision,
            security_revision: model.security_revision,
            configuration: ApplicationConfiguration {
                redirect_uris: redirects,
                allowed_origins: origins,
                publishable_keys,
            },
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the durable prepare, external store, and finalize protocol is reviewed as one operation"
    )]
    pub(crate) async fn provision_signing_key(
        &self,
        project_id: Uuid,
        operation_alias: String,
        expected_project_revision: i64,
        correlation_id: Uuid,
    ) -> Result<SigningKeyRecord, ApplicationError> {
        validate_idempotency_key(&operation_alias)?;
        let digest = request_digest(&json!({
            "project_id": project_id,
            "algorithm": SIGNING_ALGORITHM,
            "purpose": SIGNING_PURPOSE,
            "expected_project_revision": expected_project_revision,
        }))?;
        let (ring, key, operation) = self
            .prepare_signing_key(
                project_id,
                operation_alias.clone(),
                expected_project_revision,
                digest.clone(),
            )
            .await?;
        if operation.request_digest != digest {
            return Err(ApplicationError::IdempotencyConflict);
        }
        if operation.state == "completed" {
            return signing_key_record(&self.database, key).await;
        }

        let mut generated = Zeroizing::new(vec![0_u8; 32]);
        getrandom::fill(&mut generated).map_err(|_| ApplicationError::ExternalStore)?;
        self.signer_store
            .put_if_absent(key.signer_ref.clone(), generated)
            .await
            .map_err(external_store)?;
        let stored = self
            .signer_store
            .read(key.signer_ref.clone())
            .await
            .map_err(external_store)?;
        let signing_bytes: [u8; 32] = stored
            .as_slice()
            .try_into()
            .map_err(|_| ApplicationError::ExternalStore)?;
        let signing = SigningKey::from_bytes(&signing_bytes);
        let public_jwk = json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": SIGNING_ALGORITHM,
            "use": "sig",
            "kid": key.kid,
            "x": URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes()),
        });

        let now = OffsetDateTime::now_utc();
        let stored_transaction = self.database.begin().await.map_err(persistence)?;
        active_project(&stored_transaction, project_id).await?;
        let stored_operation = key_provisioning_operation::Entity::find_by_id(operation.id)
            .filter(key_provisioning_operation::Column::ProjectId.eq(project_id))
            .lock_exclusive()
            .one(&stored_transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if stored_operation.state == "completed" {
            stored_transaction.commit().await.map_err(persistence)?;
            return signing_key_record(&self.database, key).await;
        }
        if !matches!(stored_operation.state.as_str(), "prepared" | "stored") {
            return Err(ApplicationError::InvalidTransition);
        }
        let stored_key = project_signing_key::Entity::find_by_id(key.id)
            .filter(project_signing_key::Column::ProjectId.eq(project_id))
            .lock_exclusive()
            .one(&stored_transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if stored_key.state != SigningKeyState::Provisioning.as_str() {
            return Err(ApplicationError::InvalidTransition);
        }
        let mut key_active = stored_key.into_active_model();
        key_active.public_jwk = Set(public_jwk);
        key_active.provisioned_at = Set(Some(now));
        key_active.updated_at = Set(now);
        key_active
            .update(&stored_transaction)
            .await
            .map_err(persistence)?;
        let mut operation_active = stored_operation.into_active_model();
        operation_active.state = Set("stored".to_owned());
        operation_active.attempt_count =
            Set(operation_active.attempt_count.take().unwrap_or(0) + 1);
        operation_active.last_attempt_at = Set(Some(now));
        operation_active
            .update(&stored_transaction)
            .await
            .map_err(persistence)?;
        stored_transaction.commit().await.map_err(persistence)?;

        let transaction = self.database.begin().await.map_err(persistence)?;
        active_project(&transaction, project_id).await?;
        let current_ring = project_key_ring::Entity::find_by_id(ring.id)
            .filter(project_key_ring::Column::ProjectId.eq(project_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let current_key = project_signing_key::Entity::find_by_id(key.id)
            .filter(project_signing_key::Column::ProjectId.eq(project_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let current_operation = key_provisioning_operation::Entity::find_by_id(operation.id)
            .filter(key_provisioning_operation::Column::ProjectId.eq(project_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if current_operation.state == "completed" {
            transaction.commit().await.map_err(persistence)?;
            return signing_key_record(&self.database, current_key).await;
        }
        if current_operation.state != "stored"
            || current_key.state != SigningKeyState::Provisioning.as_str()
        {
            return Err(ApplicationError::InvalidTransition);
        }
        let next_revision = current_ring.revision + 1;
        let mut key_active = current_key.into_active_model();
        key_active.state = Set(SigningKeyState::Published.as_str().to_owned());
        key_active.ring_revision = Set(next_revision);
        key_active.published_at = Set(Some(now));
        key_active.updated_at = Set(now);
        let finalized_key = key_active.update(&transaction).await.map_err(persistence)?;
        let mut ring_active = current_ring.into_active_model();
        ring_active.revision = Set(next_revision);
        ring_active
            .update(&transaction)
            .await
            .map_err(persistence)?;
        let mut operation_active = current_operation.into_active_model();
        operation_active.state = Set("completed".to_owned());
        operation_active.completed_at = Set(Some(now));
        operation_active
            .update(&transaction)
            .await
            .map_err(persistence)?;
        insert_key_state_event(
            &transaction,
            project_id,
            ring.id,
            finalized_key.id,
            next_revision,
            SigningKeyState::Provisioning,
            SigningKeyState::Published,
            now,
        )
        .await?;
        insert_audit(
            &transaction,
            Some(project_id),
            "signing_key.published",
            "signing_key",
            Some(finalized_key.id),
            correlation_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        signing_key_record(&self.database, finalized_key).await
    }

    async fn prepare_signing_key(
        &self,
        project_id: Uuid,
        operation_alias: String,
        expected_project_revision: i64,
        digest: Vec<u8>,
    ) -> Result<
        (
            project_key_ring::Model,
            project_signing_key::Model,
            key_provisioning_operation::Model,
        ),
        ApplicationError,
    > {
        if let Some(operation) = key_provisioning_operation::Entity::find()
            .filter(key_provisioning_operation::Column::ProjectId.eq(project_id))
            .filter(key_provisioning_operation::Column::OperationAlias.eq(&operation_alias))
            .one(&self.database)
            .await
            .map_err(persistence)?
        {
            let ring = project_key_ring::Entity::find_by_id(operation.ring_id)
                .one(&self.database)
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::NotFound)?;
            let key = project_signing_key::Entity::find_by_id(operation.key_id)
                .filter(project_signing_key::Column::ProjectId.eq(project_id))
                .one(&self.database)
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::NotFound)?;
            return Ok((ring, key, operation));
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        let project = active_project(&transaction, project_id).await?;
        if project.metadata_revision != expected_project_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        let issuer = self
            .runtime_base
            .join(&format!("projects/{}/", project.public_id))
            .map_err(|_| ApplicationError::InvalidInput)?
            .to_string();
        let ring = match project_key_ring::Entity::find()
            .filter(project_key_ring::Column::ProjectId.eq(project_id))
            .filter(project_key_ring::Column::Issuer.eq(&issuer))
            .filter(project_key_ring::Column::Purpose.eq(SIGNING_PURPOSE))
            .filter(project_key_ring::Column::Algorithm.eq(SIGNING_ALGORITHM))
            .one(&transaction)
            .await
            .map_err(persistence)?
        {
            Some(ring) => ring,
            None => project_key_ring::ActiveModel {
                id: Set(Uuid::new_v4()),
                project_id: Set(project_id),
                issuer: Set(issuer),
                purpose: Set(SIGNING_PURPOSE.to_owned()),
                algorithm: Set(SIGNING_ALGORITHM.to_owned()),
                revision: Set(1),
                signing_epoch: Set(1),
            }
            .insert(&transaction)
            .await
            .map_err(persistence)?,
        };
        let key = project_signing_key::ActiveModel {
            id: Set(Uuid::new_v4()),
            project_id: Set(project_id),
            ring_id: Set(ring.id),
            kid: Set(generated_id("kid")),
            public_jwk: Set(json!({})),
            signer_ref: Set(store_alias("signer", project_id, &operation_alias)),
            state: Set(SigningKeyState::Provisioning.as_str().to_owned()),
            ring_revision: Set(ring.revision),
            ..Default::default()
        }
        .insert(&transaction)
        .await
        .map_err(persistence)?;
        let operation = key_provisioning_operation::ActiveModel {
            id: Set(Uuid::new_v4()),
            project_id: Set(project_id),
            ring_id: Set(ring.id),
            key_id: Set(key.id),
            operation_alias: Set(operation_alias),
            request_digest: Set(digest),
            state: Set("prepared".to_owned()),
            attempt_count: Set(0),
            expected_project_revision: Set(expected_project_revision),
            expected_ring_revision: Set(ring.revision),
            last_attempt_at: Set(None),
            completed_at: Set(None),
        }
        .insert(&transaction)
        .await
        .map_err(persistence)?;
        transaction.commit().await.map_err(persistence)?;
        Ok((ring, key, operation))
    }

    pub(crate) async fn list_signing_keys(
        &self,
        project_id: Uuid,
    ) -> Result<Vec<SigningKeyRecord>, ApplicationError> {
        ensure_project(&self.database, project_id).await?;
        let keys = project_signing_key::Entity::find()
            .filter(project_signing_key::Column::ProjectId.eq(project_id))
            .order_by_asc(project_signing_key::Column::CreatedAt)
            .limit(LIST_LIMIT + 1)
            .all(&self.database)
            .await
            .map_err(persistence)?;
        let keys = bounded_list(keys)?;
        let mut records = Vec::with_capacity(keys.len());
        for key in keys {
            records.push(signing_key_record(&self.database, key).await?);
        }
        Ok(records)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "activation validates signer material, publication leases, and rotation atomically"
    )]
    pub(crate) async fn activate_signing_key(
        &self,
        project_id: Uuid,
        key_id: Uuid,
        expected_ring_revision: i64,
        correlation_id: Uuid,
    ) -> Result<SigningKeyRecord, ApplicationError> {
        let candidate = find_signing_key(&self.database, project_id, key_id).await?;
        if candidate.state != SigningKeyState::Published.as_str() {
            return Err(ApplicationError::InvalidTransition);
        }
        self.verify_signer_capability(&candidate).await?;

        let transaction = self.database.begin().await.map_err(persistence)?;
        active_project(&transaction, project_id).await?;
        let ring = project_key_ring::Entity::find_by_id(candidate.ring_id)
            .filter(project_key_ring::Column::ProjectId.eq(project_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if ring.revision != expected_ring_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        let candidate = project_signing_key::Entity::find_by_id(key_id)
            .filter(project_signing_key::Column::ProjectId.eq(project_id))
            .filter(project_signing_key::Column::RingId.eq(ring.id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if candidate.state != SigningKeyState::Published.as_str()
            || candidate.published_at.is_none()
        {
            return Err(ApplicationError::InvalidTransition);
        }
        let now = OffsetDateTime::now_utc();
        let minimum_observation = now - self.propagation_delay;
        for process_id in self.required_runtime_process_ids.iter() {
            let qualifying = runtime_publication_lease::Entity::find()
                .filter(runtime_publication_lease::Column::ProjectId.eq(project_id))
                .filter(runtime_publication_lease::Column::RingId.eq(ring.id))
                .filter(runtime_publication_lease::Column::ProcessId.eq(process_id))
                .filter(
                    runtime_publication_lease::Column::LoadedRevision.gte(candidate.ring_revision),
                )
                .filter(runtime_publication_lease::Column::ExpiresAt.gt(now))
                .filter(runtime_publication_lease::Column::FirstObservedAt.lte(minimum_observation))
                .count(&transaction)
                .await
                .map_err(persistence)?;
            if qualifying != 1 {
                return Err(ApplicationError::PublicationPending);
            }
        }
        if self.required_runtime_process_ids.is_empty() {
            return Err(ApplicationError::PublicationPending);
        }

        let next_revision = ring.revision + 1;
        if let Some(old) = project_signing_key::Entity::find()
            .filter(project_signing_key::Column::ProjectId.eq(project_id))
            .filter(project_signing_key::Column::RingId.eq(ring.id))
            .filter(project_signing_key::Column::State.eq(SigningKeyState::Active.as_str()))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
        {
            let retention = time::Duration::try_from(self.verification_retention)
                .map_err(|_| ApplicationError::InvalidInput)?;
            let old_id = old.id;
            let mut old_active = old.into_active_model();
            old_active.state = Set(SigningKeyState::Retiring.as_str().to_owned());
            old_active.ring_revision = Set(next_revision);
            old_active.retiring_at = Set(Some(now));
            old_active.verify_not_after = Set(Some(now + retention));
            old_active.updated_at = Set(now);
            old_active.update(&transaction).await.map_err(persistence)?;
            insert_key_state_event(
                &transaction,
                project_id,
                ring.id,
                old_id,
                next_revision,
                SigningKeyState::Active,
                SigningKeyState::Retiring,
                now,
            )
            .await?;
        }

        let mut candidate_active = candidate.into_active_model();
        candidate_active.state = Set(SigningKeyState::Active.as_str().to_owned());
        candidate_active.ring_revision = Set(next_revision);
        candidate_active.activated_at = Set(Some(now));
        candidate_active.sign_not_before = Set(Some(now));
        candidate_active.updated_at = Set(now);
        let updated = candidate_active
            .update(&transaction)
            .await
            .map_err(persistence)?;
        insert_key_state_event(
            &transaction,
            project_id,
            ring.id,
            key_id,
            next_revision,
            SigningKeyState::Published,
            SigningKeyState::Active,
            now,
        )
        .await?;
        let mut ring_active = ring.into_active_model();
        ring_active.revision = Set(next_revision);
        ring_active.signing_epoch = Set(ring_active.signing_epoch.take().unwrap_or(1) + 1);
        ring_active
            .update(&transaction)
            .await
            .map_err(persistence)?;
        insert_audit(
            &transaction,
            Some(project_id),
            "signing_key.activated",
            "signing_key",
            Some(key_id),
            correlation_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        signing_key_record(&self.database, updated).await
    }

    pub(crate) async fn retire_signing_key(
        &self,
        project_id: Uuid,
        key_id: Uuid,
        expected_ring_revision: i64,
        correlation_id: Uuid,
    ) -> Result<SigningKeyRecord, ApplicationError> {
        let current = find_signing_key(&self.database, project_id, key_id).await?;
        if parse_signing_state(&current.state)? != SigningKeyState::Retiring {
            return Err(ApplicationError::InvalidTransition);
        }
        self.transition_signing_key(
            project_id,
            key_id,
            expected_ring_revision,
            SigningKeyState::Retired,
            "signing_key.retired",
            correlation_id,
        )
        .await
    }

    pub(crate) async fn revoke_signing_key(
        &self,
        project_id: Uuid,
        key_id: Uuid,
        expected_ring_revision: i64,
        correlation_id: Uuid,
    ) -> Result<SigningKeyRecord, ApplicationError> {
        self.transition_signing_key(
            project_id,
            key_id,
            expected_ring_revision,
            SigningKeyState::Revoked,
            "signing_key.revoked",
            correlation_id,
        )
        .await
    }

    async fn transition_signing_key(
        &self,
        project_id: Uuid,
        key_id: Uuid,
        expected_ring_revision: i64,
        target: SigningKeyState,
        audit_action: &str,
        correlation_id: Uuid,
    ) -> Result<SigningKeyRecord, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        active_project(&transaction, project_id).await?;
        let key = find_signing_key(&transaction, project_id, key_id).await?;
        let ring = project_key_ring::Entity::find_by_id(key.ring_id)
            .filter(project_key_ring::Column::ProjectId.eq(project_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if ring.revision != expected_ring_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        let key = project_signing_key::Entity::find_by_id(key_id)
            .filter(project_signing_key::Column::ProjectId.eq(project_id))
            .filter(project_signing_key::Column::RingId.eq(ring.id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let current = parse_signing_state(&key.state)?;
        let now = OffsetDateTime::now_utc();
        if target == SigningKeyState::Retired {
            if current != SigningKeyState::Retiring
                || key.verify_not_after.is_none_or(|cutoff| cutoff > now)
            {
                return Err(ApplicationError::InvalidTransition);
            }
        } else {
            let mut state = current;
            state
                .transition(target)
                .map_err(|_| ApplicationError::InvalidTransition)?;
        }
        let next_revision = ring.revision + 1;
        let mut key_active = key.into_active_model();
        key_active.state = Set(target.as_str().to_owned());
        key_active.ring_revision = Set(next_revision);
        key_active.updated_at = Set(now);
        match target {
            SigningKeyState::Active => key_active.activated_at = Set(Some(now)),
            SigningKeyState::Retiring => key_active.retiring_at = Set(Some(now)),
            SigningKeyState::Retired => key_active.retired_at = Set(Some(now)),
            SigningKeyState::Revoked => key_active.revoked_at = Set(Some(now)),
            _ => {}
        }
        let updated = key_active.update(&transaction).await.map_err(persistence)?;
        insert_key_state_event(
            &transaction,
            project_id,
            ring.id,
            key_id,
            next_revision,
            current,
            target,
            now,
        )
        .await?;
        let mut ring_active = ring.into_active_model();
        ring_active.revision = Set(next_revision);
        ring_active.signing_epoch = Set(ring_active.signing_epoch.take().unwrap_or(1) + 1);
        ring_active
            .update(&transaction)
            .await
            .map_err(persistence)?;
        insert_audit(
            &transaction,
            Some(project_id),
            audit_action,
            "signing_key",
            Some(key_id),
            correlation_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        signing_key_record(&self.database, updated).await
    }

    async fn verify_signer_capability(
        &self,
        key: &project_signing_key::Model,
    ) -> Result<(), ApplicationError> {
        let stored = self
            .signer_store
            .read(key.signer_ref.clone())
            .await
            .map_err(external_store)?;
        let signing_bytes: [u8; 32] = stored
            .as_slice()
            .try_into()
            .map_err(|_| ApplicationError::ExternalStore)?;
        let verifying_bytes = SigningKey::from_bytes(&signing_bytes)
            .verifying_key()
            .to_bytes();
        let expected = key
            .public_jwk
            .as_object()
            .filter(|jwk| {
                jwk.get("kty").and_then(Value::as_str) == Some("OKP")
                    && jwk.get("crv").and_then(Value::as_str) == Some("Ed25519")
                    && jwk.get("alg").and_then(Value::as_str) == Some(SIGNING_ALGORITHM)
                    && jwk.get("use").and_then(Value::as_str) == Some("sig")
                    && jwk.get("kid").and_then(Value::as_str) == Some(key.kid.as_str())
            })
            .and_then(|jwk| jwk.get("x"))
            .and_then(Value::as_str)
            .and_then(|value| URL_SAFE_NO_PAD.decode(value).ok())
            .ok_or(ApplicationError::InvalidTransition)?;
        if expected.len() != verifying_bytes.len()
            || !bool::from(expected.as_slice().ct_eq(verifying_bytes.as_slice()))
        {
            return Err(ApplicationError::InvalidTransition);
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the durable prepare, external store, and finalize protocol is reviewed as one operation"
    )]
    pub(crate) async fn create_provider(
        &self,
        project_id: Uuid,
        command: CreateProvider,
        correlation_id: Uuid,
    ) -> Result<ProviderRecord, ApplicationError> {
        validate_idempotency_key(&command.idempotency_key)?;
        let provider_key = ProviderKey::parse(command.provider_key.clone())?.into_inner();
        let display_name = DisplayName::parse(command.display_name.clone())?.into_inner();
        validate_https_url(&command.issuer)?;
        if command.client_id.is_empty() || command.client_id.len() > 512 {
            return Err(ApplicationError::InvalidInput);
        }
        if command.client_secret.is_empty() || command.client_secret.len() > 4096 {
            return Err(ApplicationError::InvalidInput);
        }
        let secret_digest = self
            .secret_store
            .request_fingerprint(command.client_secret.as_bytes());
        let digest = request_digest(&json!({
            "project_id": project_id,
            "provider_key": provider_key,
            "display_name": display_name,
            "issuer": command.issuer,
            "client_id": command.client_id,
            "secret_digest": URL_SAFE_NO_PAD.encode(secret_digest),
            "expected_project_revision": command.expected_project_revision,
        }))?;
        let (provider, operation) = self
            .prepare_provider(
                project_id,
                &command,
                provider_key,
                display_name,
                digest.clone(),
            )
            .await?;
        if operation.request_digest != digest {
            return Err(ApplicationError::IdempotencyConflict);
        }
        if operation.state == "completed" {
            return self.provider_record(provider).await;
        }
        let secret_ref = store_alias("secret", project_id, &command.idempotency_key);
        self.secret_store
            .put_if_absent(
                secret_ref.clone(),
                Zeroizing::new(command.client_secret.as_bytes().to_vec()),
            )
            .await
            .map_err(external_store)?;
        self.secret_store
            .read(secret_ref.clone())
            .await
            .map_err(external_store)?;

        let now = OffsetDateTime::now_utc();
        let stored_transaction = self.database.begin().await.map_err(persistence)?;
        active_project(&stored_transaction, project_id).await?;
        let stored_operation = provider_secret_operation::Entity::find_by_id(operation.id)
            .filter(provider_secret_operation::Column::ProjectId.eq(project_id))
            .lock_exclusive()
            .one(&stored_transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if stored_operation.state == "completed" {
            stored_transaction.commit().await.map_err(persistence)?;
            return self.provider_record(provider).await;
        }
        if !matches!(stored_operation.state.as_str(), "prepared" | "stored") {
            return Err(ApplicationError::InvalidTransition);
        }
        let mut operation_active = stored_operation.into_active_model();
        operation_active.state = Set("stored".to_owned());
        operation_active.attempt_count =
            Set(operation_active.attempt_count.take().unwrap_or(0) + 1);
        operation_active.last_attempt_at = Set(Some(now));
        operation_active
            .update(&stored_transaction)
            .await
            .map_err(persistence)?;
        stored_transaction.commit().await.map_err(persistence)?;

        let transaction = self.database.begin().await.map_err(persistence)?;
        active_project(&transaction, project_id).await?;
        let current = provider_configuration::Entity::find_by_id(provider.id)
            .filter(provider_configuration::Column::ProjectId.eq(project_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let current_operation = provider_secret_operation::Entity::find_by_id(operation.id)
            .filter(provider_secret_operation::Column::ProjectId.eq(project_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if current_operation.state == "completed" {
            transaction.commit().await.map_err(persistence)?;
            return self.provider_record(current).await;
        }
        if current_operation.state != "stored" || current.status != "provisioning" {
            return Err(ApplicationError::InvalidTransition);
        }
        let mut status = ProviderStatus::Provisioning;
        status
            .provision()
            .map_err(|_| ApplicationError::InvalidTransition)?;
        let next_revision = current.revision + 1;
        let mut active = current.into_active_model();
        active.secret_ref = Set(Some(secret_ref));
        active.status = Set(status.as_str().to_owned());
        active.revision = Set(next_revision);
        let updated = active.update(&transaction).await.map_err(persistence)?;
        let mut operation_active = current_operation.into_active_model();
        operation_active.state = Set("completed".to_owned());
        operation_active.completed_at = Set(Some(now));
        operation_active
            .update(&transaction)
            .await
            .map_err(persistence)?;
        insert_audit(
            &transaction,
            Some(project_id),
            "provider.configured",
            "provider",
            Some(updated.id),
            correlation_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        self.provider_record(updated).await
    }

    async fn prepare_provider(
        &self,
        project_id: Uuid,
        command: &CreateProvider,
        provider_key: String,
        display_name: String,
        digest: Vec<u8>,
    ) -> Result<
        (
            provider_configuration::Model,
            provider_secret_operation::Model,
        ),
        ApplicationError,
    > {
        if let Some(operation) = provider_secret_operation::Entity::find()
            .filter(provider_secret_operation::Column::ProjectId.eq(project_id))
            .filter(provider_secret_operation::Column::OperationAlias.eq(&command.idempotency_key))
            .one(&self.database)
            .await
            .map_err(persistence)?
        {
            let provider = provider_configuration::Entity::find_by_id(operation.provider_id)
                .filter(provider_configuration::Column::ProjectId.eq(project_id))
                .one(&self.database)
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::NotFound)?;
            return Ok((provider, operation));
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        let project = active_project(&transaction, project_id).await?;
        if project.metadata_revision != command.expected_project_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        let callback_url = self
            .runtime_base
            .join(&format!(
                "projects/{}/auth/callback/{provider_key}",
                project.public_id
            ))
            .map_err(|_| ApplicationError::InvalidInput)?
            .to_string();
        let provider = provider_configuration::ActiveModel {
            id: Set(Uuid::new_v4()),
            project_id: Set(project_id),
            provider_key: Set(provider_key),
            kind: Set("oidc".to_owned()),
            display_name: Set(display_name),
            issuer: Set(command.issuer.clone()),
            client_id: Set(command.client_id.clone()),
            callback_url: Set(callback_url),
            secret_ref: Set(None),
            status: Set("provisioning".to_owned()),
            revision: Set(1),
        }
        .insert(&transaction)
        .await
        .map_err(persistence)?;
        let operation = provider_secret_operation::ActiveModel {
            id: Set(Uuid::new_v4()),
            project_id: Set(project_id),
            provider_id: Set(provider.id),
            operation_alias: Set(command.idempotency_key.clone()),
            request_digest: Set(digest),
            state: Set("prepared".to_owned()),
            attempt_count: Set(0),
            expected_project_revision: Set(command.expected_project_revision),
            expected_provider_revision: Set(1),
            last_attempt_at: Set(None),
            completed_at: Set(None),
        }
        .insert(&transaction)
        .await
        .map_err(persistence)?;
        transaction.commit().await.map_err(persistence)?;
        Ok((provider, operation))
    }

    pub(crate) async fn list_providers(
        &self,
        project_id: Uuid,
    ) -> Result<Vec<ProviderRecord>, ApplicationError> {
        ensure_project(&self.database, project_id).await?;
        let providers = provider_configuration::Entity::find()
            .filter(provider_configuration::Column::ProjectId.eq(project_id))
            .order_by_asc(provider_configuration::Column::ProviderKey)
            .limit(LIST_LIMIT + 1)
            .all(&self.database)
            .await
            .map_err(persistence)?;
        let providers = bounded_list(providers)?;
        let mut records = Vec::with_capacity(providers.len());
        for provider in providers {
            records.push(self.provider_record(provider).await?);
        }
        Ok(records)
    }

    pub(crate) async fn assign_provider(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
        application_id: Uuid,
        expected_application_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ProviderRecord, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        active_project(&transaction, project_id).await?;
        let provider = active_provider(&transaction, project_id, provider_id).await?;
        let application = active_application(&transaction, project_id, application_id).await?;
        if application.security_revision != expected_application_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        let next_revision = expected_application_revision + 1;
        let existing = application_provider_assignment::Entity::find_by_id((
            project_id,
            application_id,
            provider_id,
        ))
        .one(&transaction)
        .await
        .map_err(persistence)?;
        match existing {
            Some(existing) => {
                let mut active = existing.into_active_model();
                active.status = Set("active".to_owned());
                active.security_revision = Set(next_revision);
                active.update(&transaction).await.map_err(persistence)?;
            }
            None => {
                application_provider_assignment::ActiveModel {
                    project_id: Set(project_id),
                    application_id: Set(application_id),
                    provider_id: Set(provider_id),
                    status: Set("active".to_owned()),
                    security_revision: Set(next_revision),
                }
                .insert(&transaction)
                .await
                .map_err(persistence)?;
            }
        }
        bump_application_security(&transaction, application, next_revision).await?;
        insert_audit(
            &transaction,
            Some(project_id),
            "provider.assigned",
            "provider",
            Some(provider_id),
            correlation_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        self.provider_record(provider).await
    }

    pub(crate) async fn unassign_provider(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
        application_id: Uuid,
        expected_application_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ProviderRecord, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        active_project(&transaction, project_id).await?;
        let provider = find_provider(&transaction, project_id, provider_id).await?;
        let application = find_application(&transaction, project_id, application_id).await?;
        if application.security_revision != expected_application_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        let assignment = application_provider_assignment::Entity::find_by_id((
            project_id,
            application_id,
            provider_id,
        ))
        .one(&transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
        let next_revision = expected_application_revision + 1;
        let mut active = assignment.into_active_model();
        active.status = Set("disabled".to_owned());
        active.security_revision = Set(next_revision);
        active.update(&transaction).await.map_err(persistence)?;
        bump_application_security(&transaction, application, next_revision).await?;
        insert_audit(
            &transaction,
            Some(project_id),
            "provider.unassigned",
            "provider",
            Some(provider_id),
            correlation_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        self.provider_record(provider).await
    }

    pub(crate) async fn disable_provider(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
        expected_provider_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ProviderRecord, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        active_project(&transaction, project_id).await?;
        let provider = active_provider(&transaction, project_id, provider_id).await?;
        if provider.revision != expected_provider_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        let assignments = application_provider_assignment::Entity::find()
            .filter(application_provider_assignment::Column::ProjectId.eq(project_id))
            .filter(application_provider_assignment::Column::ProviderId.eq(provider_id))
            .filter(application_provider_assignment::Column::Status.eq("active"))
            .all(&transaction)
            .await
            .map_err(persistence)?;
        for assignment in assignments {
            let application =
                find_application(&transaction, project_id, assignment.application_id).await?;
            let next_revision = application.security_revision + 1;
            let mut assignment_active = assignment.into_active_model();
            assignment_active.status = Set("disabled".to_owned());
            assignment_active.security_revision = Set(next_revision);
            assignment_active
                .update(&transaction)
                .await
                .map_err(persistence)?;
            bump_application_security(&transaction, application, next_revision).await?;
        }
        let mut status = ProviderStatus::Active;
        status
            .disable()
            .map_err(|_| ApplicationError::InvalidTransition)?;
        let mut active = provider.into_active_model();
        active.status = Set(status.as_str().to_owned());
        active.revision = Set(expected_provider_revision + 1);
        let updated = active.update(&transaction).await.map_err(persistence)?;
        insert_audit(
            &transaction,
            Some(project_id),
            "provider.disabled",
            "provider",
            Some(provider_id),
            correlation_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        self.provider_record(updated).await
    }

    async fn provider_record(
        &self,
        provider: provider_configuration::Model,
    ) -> Result<ProviderRecord, ApplicationError> {
        let assignments = application_provider_assignment::Entity::find()
            .filter(application_provider_assignment::Column::ProjectId.eq(provider.project_id))
            .filter(application_provider_assignment::Column::ProviderId.eq(provider.id))
            .filter(application_provider_assignment::Column::Status.eq("active"))
            .order_by_asc(application_provider_assignment::Column::ApplicationId)
            .all(&self.database)
            .await
            .map_err(persistence)?
            .into_iter()
            .map(|assignment| assignment.application_id)
            .collect();
        Ok(ProviderRecord {
            id: provider.id,
            project_id: provider.project_id,
            provider_key: provider.provider_key,
            kind: provider.kind,
            display_name: provider.display_name,
            issuer: provider.issuer,
            client_id: provider.client_id,
            callback_url: provider.callback_url,
            status: provider.status,
            revision: provider.revision,
            assigned_application_ids: assignments,
        })
    }
}

fn project_policy_record(
    model: &project_policy::Model,
) -> Result<ProjectPolicyRecord, ApplicationError> {
    let access_token_lifetime_seconds = model
        .claims_policy
        .get("access_token_lifetime_seconds")
        .and_then(Value::as_i64)
        .and_then(|value| i32::try_from(value).ok())
        .filter(|value| (60..=3600).contains(value))
        .ok_or(ApplicationError::InvalidTransition)?;
    let browser_session_reuse = model
        .session_policy
        .get("browser_session_reuse")
        .and_then(Value::as_bool)
        .ok_or(ApplicationError::InvalidTransition)?;
    Ok(ProjectPolicyRecord {
        project_id: model.project_id,
        access_token_lifetime_seconds,
        browser_session_reuse,
        claims_revision: model.claims_revision,
        session_revision: model.session_revision,
    })
}

fn project_record(model: project::Model) -> ProjectRecord {
    ProjectRecord {
        id: model.id,
        public_id: model.public_id,
        display_name: model.display_name,
        belongs_to: model.belongs_to,
        status: model.status,
        metadata_revision: model.metadata_revision,
        security_revision: model.security_revision,
    }
}

async fn active_project<C>(
    connection: &C,
    project_id: Uuid,
) -> Result<project::Model, ApplicationError>
where
    C: ConnectionTrait,
{
    let project = project::Entity::find_by_id(project_id)
        .lock_exclusive()
        .one(connection)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
    if project.status != "active" {
        return Err(ApplicationError::Disabled);
    }
    Ok(project)
}

async fn ensure_project<C>(connection: &C, project_id: Uuid) -> Result<(), ApplicationError>
where
    C: ConnectionTrait,
{
    project::Entity::find_by_id(project_id)
        .one(connection)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
    Ok(())
}

async fn find_application<C>(
    connection: &C,
    project_id: Uuid,
    application_id: Uuid,
) -> Result<application::Model, ApplicationError>
where
    C: ConnectionTrait,
{
    application::Entity::find_by_id(application_id)
        .filter(application::Column::ProjectId.eq(project_id))
        .one(connection)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)
}

async fn active_application<C>(
    connection: &C,
    project_id: Uuid,
    application_id: Uuid,
) -> Result<application::Model, ApplicationError>
where
    C: ConnectionTrait,
{
    let application = find_application(connection, project_id, application_id).await?;
    if application.status != "active" {
        return Err(ApplicationError::Disabled);
    }
    Ok(application)
}

async fn find_signing_key<C>(
    connection: &C,
    project_id: Uuid,
    key_id: Uuid,
) -> Result<project_signing_key::Model, ApplicationError>
where
    C: ConnectionTrait,
{
    project_signing_key::Entity::find_by_id(key_id)
        .filter(project_signing_key::Column::ProjectId.eq(project_id))
        .one(connection)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)
}

async fn signing_key_record<C>(
    connection: &C,
    key: project_signing_key::Model,
) -> Result<SigningKeyRecord, ApplicationError>
where
    C: ConnectionTrait,
{
    let ring = project_key_ring::Entity::find_by_id(key.ring_id)
        .filter(project_key_ring::Column::ProjectId.eq(key.project_id))
        .one(connection)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
    Ok(SigningKeyRecord {
        id: key.id,
        project_id: key.project_id,
        kid: key.kid,
        algorithm: ring.algorithm,
        state: key.state,
        ring_revision: ring.revision,
        signing_epoch: ring.signing_epoch,
        sign_not_before: key.sign_not_before,
        verify_not_after: key.verify_not_after,
        public_jwk: key.public_jwk,
    })
}

async fn find_provider<C>(
    connection: &C,
    project_id: Uuid,
    provider_id: Uuid,
) -> Result<provider_configuration::Model, ApplicationError>
where
    C: ConnectionTrait,
{
    provider_configuration::Entity::find_by_id(provider_id)
        .filter(provider_configuration::Column::ProjectId.eq(project_id))
        .one(connection)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)
}

async fn active_provider<C>(
    connection: &C,
    project_id: Uuid,
    provider_id: Uuid,
) -> Result<provider_configuration::Model, ApplicationError>
where
    C: ConnectionTrait,
{
    let provider = find_provider(connection, project_id, provider_id).await?;
    if provider.status != "active" {
        return Err(ApplicationError::Disabled);
    }
    Ok(provider)
}

async fn bump_application_security(
    transaction: &DatabaseTransaction,
    application: application::Model,
    next_revision: i64,
) -> Result<(), ApplicationError> {
    let aggregate_revision = application.revision + 1;
    let mut active = application.into_active_model();
    active.security_revision = Set(next_revision);
    active.revision = Set(aggregate_revision);
    active.updated_at = Set(OffsetDateTime::now_utc());
    active.update(transaction).await.map_err(persistence)?;
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "the arguments are the complete immutable key transition event"
)]
async fn insert_key_state_event(
    transaction: &DatabaseTransaction,
    project_id: Uuid,
    ring_id: Uuid,
    signing_key_id: Uuid,
    ring_revision: i64,
    from_state: SigningKeyState,
    to_state: SigningKeyState,
    occurred_at: OffsetDateTime,
) -> Result<(), ApplicationError> {
    key_state_event::ActiveModel {
        id: Set(Uuid::new_v4()),
        project_id: Set(project_id),
        ring_id: Set(ring_id),
        signing_key_id: Set(signing_key_id),
        ring_revision: Set(ring_revision),
        from_state: Set(from_state.as_str().to_owned()),
        to_state: Set(to_state.as_str().to_owned()),
        actor_kind: Set("deployment_operator".to_owned()),
        occurred_at: Set(occurred_at),
    }
    .insert(transaction)
    .await
    .map_err(persistence)?;
    Ok(())
}

async fn insert_audit(
    transaction: &DatabaseTransaction,
    project_id: Option<Uuid>,
    action: &str,
    target_kind: &str,
    target_id: Option<Uuid>,
    correlation_id: Uuid,
) -> Result<(), ApplicationError> {
    audit_event::ActiveModel {
        id: Set(Uuid::new_v4()),
        project_id: Set(project_id),
        actor_kind: Set("deployment_operator".to_owned()),
        action: Set(action.to_owned()),
        target_kind: Set(target_kind.to_owned()),
        target_id: Set(target_id),
        outcome: Set("succeeded".to_owned()),
        correlation_id: Set(correlation_id),
        safe_context: Set(Value::Object(Map::new())),
    }
    .insert(transaction)
    .await
    .map_err(persistence)?;
    Ok(())
}

async fn replay<T>(
    transaction: &DatabaseTransaction,
    idempotency_key: &str,
    operation_kind: &str,
    scope: &str,
    digest: &[u8],
) -> Result<Option<T>, ApplicationError>
where
    T: for<'de> Deserialize<'de>,
{
    let Some(existing) = control_idempotency_record::Entity::find_by_id(idempotency_key)
        .one(transaction)
        .await
        .map_err(persistence)?
    else {
        return Ok(None);
    };
    if existing.operation_kind != operation_kind
        || existing.request_scope != scope
        || existing.request_digest != digest
    {
        return Err(ApplicationError::IdempotencyConflict);
    }
    if existing.state != "completed" {
        return Err(ApplicationError::OperationInProgress);
    }
    let response = existing.response.ok_or(ApplicationError::Persistence)?;
    serde_json::from_value(response)
        .map(Some)
        .map_err(|_| ApplicationError::Persistence)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the arguments are the durable idempotency record and its response"
)]
async fn complete_idempotency<T>(
    transaction: &DatabaseTransaction,
    idempotency_key: String,
    owner_project_id: Option<Uuid>,
    result_resource_id: Option<Uuid>,
    operation_kind: &str,
    scope: &str,
    digest: Vec<u8>,
    result: &T,
) -> Result<(), ApplicationError>
where
    T: Serialize,
{
    control_idempotency_record::ActiveModel {
        idempotency_key: Set(idempotency_key),
        project_id: Set(owner_project_id),
        request_digest: Set(digest),
        state: Set("completed".to_owned()),
        result_resource_id: Set(result_resource_id),
        response: Set(Some(
            serde_json::to_value(result).map_err(|_| ApplicationError::Persistence)?,
        )),
        operation_kind: Set(operation_kind.to_owned()),
        request_scope: Set(scope.to_owned()),
        expires_at: Set(None),
        completed_at: Set(Some(OffsetDateTime::now_utc())),
    }
    .insert(transaction)
    .await
    .map_err(persistence)?;
    Ok(())
}

fn request_digest(value: &Value) -> Result<Vec<u8>, ApplicationError> {
    let encoded = serde_json::to_vec(value).map_err(|_| ApplicationError::InvalidInput)?;
    Ok(Sha256::digest(encoded).to_vec())
}

fn generated_id(prefix: &str) -> String {
    format!("{prefix}_{}", Uuid::new_v4().simple())
}

fn store_alias(purpose: &str, project_id: Uuid, operation_alias: &str) -> String {
    let digest = Sha256::digest(operation_alias.as_bytes());
    format!(
        "{purpose}_{}_{}",
        project_id.simple(),
        URL_SAFE_NO_PAD.encode(&digest[..16])
    )
}

fn bounded_list<T>(items: Vec<T>) -> Result<Vec<T>, ApplicationError> {
    if u64::try_from(items.len()).map_err(|_| ApplicationError::Integrity)? > LIST_LIMIT {
        return Err(ApplicationError::Integrity);
    }
    Ok(items)
}

fn validate_idempotency_key(value: &str) -> Result<(), ApplicationError> {
    PublicId::parse(value.to_owned())?;
    if value.len() > 128 {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(())
}

fn reject_duplicates(values: impl Iterator<Item = String>) -> Result<(), ApplicationError> {
    let mut unique = BTreeSet::new();
    for value in values {
        if !unique.insert(value) {
            return Err(ApplicationError::InvalidInput);
        }
    }
    Ok(())
}

fn parse_application_type(value: &str) -> Result<ApplicationType, ApplicationError> {
    match value {
        "web" => Ok(ApplicationType::Web),
        "native" => Ok(ApplicationType::Native),
        _ => Err(ApplicationError::Persistence),
    }
}

fn parse_signing_state(value: &str) -> Result<SigningKeyState, ApplicationError> {
    match value {
        "provisioning" => Ok(SigningKeyState::Provisioning),
        "published" => Ok(SigningKeyState::Published),
        "active" => Ok(SigningKeyState::Active),
        "retiring" => Ok(SigningKeyState::Retiring),
        "retired" => Ok(SigningKeyState::Retired),
        "revoked" => Ok(SigningKeyState::Revoked),
        "abandoned" => Ok(SigningKeyState::Abandoned),
        _ => Err(ApplicationError::Persistence),
    }
}

fn validate_https_url(value: &str) -> Result<(), ApplicationError> {
    let url = Url::parse(value).map_err(|_| ApplicationError::InvalidInput)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.as_str() != value
    {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(())
}

fn external_store(error: StoreError) -> ApplicationError {
    match error {
        StoreError::InvalidAlias => ApplicationError::InvalidInput,
        StoreError::NotFound | StoreError::InvalidValue => ApplicationError::Integrity,
        StoreError::Unavailable => ApplicationError::ExternalStore,
    }
}

fn persistence(error: DbErr) -> ApplicationError {
    match error {
        DbErr::Exec(RuntimeErr::SqlxError(error)) | DbErr::Query(RuntimeErr::SqlxError(error)) => {
            match error.as_ref() {
                sqlx::Error::Database(error) => match error.code().as_deref() {
                    Some("23505" | "40001" | "40P01") => ApplicationError::RevisionConflict,
                    Some("23503" | "23514" | "23P01") => ApplicationError::InvalidInput,
                    _ => ApplicationError::Integrity,
                },
                _ => ApplicationError::Integrity,
            }
        }
        DbErr::Conn(_) | DbErr::ConnectionAcquire(_) => ApplicationError::Persistence,
        _ => ApplicationError::Integrity,
    }
}

#[async_trait]
impl ProvisioningPort for PostgresProvisioningAdapter {
    async fn create_project(
        &self,
        command: CreateProject,
        correlation_id: Uuid,
    ) -> Result<ProjectRecord, ApplicationError> {
        PostgresProvisioningAdapter::create_project(self, command, correlation_id).await
    }

    async fn list_projects(
        &self,
        belongs_to: Option<String>,
    ) -> Result<Vec<ProjectRecord>, ApplicationError> {
        PostgresProvisioningAdapter::list_projects(self, belongs_to).await
    }

    async fn get_project(&self, project_id: Uuid) -> Result<ProjectRecord, ApplicationError> {
        PostgresProvisioningAdapter::get_project(self, project_id).await
    }

    async fn get_project_policy(
        &self,
        project_id: Uuid,
    ) -> Result<ProjectPolicyRecord, ApplicationError> {
        PostgresProvisioningAdapter::get_project_policy(self, project_id).await
    }

    async fn update_project_policy(
        &self,
        project_id: Uuid,
        command: UpdateProjectPolicy,
        correlation_id: Uuid,
    ) -> Result<ProjectPolicyRecord, ApplicationError> {
        PostgresProvisioningAdapter::update_project_policy(
            self,
            project_id,
            command,
            correlation_id,
        )
        .await
    }

    async fn update_project(
        &self,
        project_id: Uuid,
        command: UpdateProject,
        correlation_id: Uuid,
    ) -> Result<ProjectRecord, ApplicationError> {
        PostgresProvisioningAdapter::update_project(self, project_id, command, correlation_id).await
    }

    async fn disable_project(
        &self,
        project_id: Uuid,
        expected_security_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ProjectRecord, ApplicationError> {
        PostgresProvisioningAdapter::disable_project(
            self,
            project_id,
            expected_security_revision,
            correlation_id,
        )
        .await
    }

    async fn create_application(
        &self,
        project_id: Uuid,
        command: CreateApplication,
        correlation_id: Uuid,
    ) -> Result<ApplicationRecord, ApplicationError> {
        PostgresProvisioningAdapter::create_application(self, project_id, command, correlation_id)
            .await
    }

    async fn list_applications(
        &self,
        project_id: Uuid,
    ) -> Result<Vec<ApplicationRecord>, ApplicationError> {
        PostgresProvisioningAdapter::list_applications(self, project_id).await
    }

    async fn get_application(
        &self,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<ApplicationRecord, ApplicationError> {
        PostgresProvisioningAdapter::get_application(self, project_id, application_id).await
    }

    async fn update_application(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        command: UpdateApplication,
        correlation_id: Uuid,
    ) -> Result<ApplicationRecord, ApplicationError> {
        PostgresProvisioningAdapter::update_application(
            self,
            project_id,
            application_id,
            command,
            correlation_id,
        )
        .await
    }

    async fn replace_application_configuration(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        command: ReplaceApplicationConfiguration,
        correlation_id: Uuid,
    ) -> Result<ApplicationRecord, ApplicationError> {
        PostgresProvisioningAdapter::replace_application_configuration(
            self,
            project_id,
            application_id,
            command,
            correlation_id,
        )
        .await
    }

    async fn disable_application(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        expected_security_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ApplicationRecord, ApplicationError> {
        PostgresProvisioningAdapter::disable_application(
            self,
            project_id,
            application_id,
            expected_security_revision,
            correlation_id,
        )
        .await
    }

    async fn provision_signing_key(
        &self,
        project_id: Uuid,
        operation_alias: String,
        expected_project_revision: i64,
        correlation_id: Uuid,
    ) -> Result<SigningKeyRecord, ApplicationError> {
        PostgresProvisioningAdapter::provision_signing_key(
            self,
            project_id,
            operation_alias,
            expected_project_revision,
            correlation_id,
        )
        .await
    }

    async fn list_signing_keys(
        &self,
        project_id: Uuid,
    ) -> Result<Vec<SigningKeyRecord>, ApplicationError> {
        PostgresProvisioningAdapter::list_signing_keys(self, project_id).await
    }

    async fn activate_signing_key(
        &self,
        project_id: Uuid,
        key_id: Uuid,
        expected_ring_revision: i64,
        correlation_id: Uuid,
    ) -> Result<SigningKeyRecord, ApplicationError> {
        PostgresProvisioningAdapter::activate_signing_key(
            self,
            project_id,
            key_id,
            expected_ring_revision,
            correlation_id,
        )
        .await
    }

    async fn retire_signing_key(
        &self,
        project_id: Uuid,
        key_id: Uuid,
        expected_ring_revision: i64,
        correlation_id: Uuid,
    ) -> Result<SigningKeyRecord, ApplicationError> {
        PostgresProvisioningAdapter::retire_signing_key(
            self,
            project_id,
            key_id,
            expected_ring_revision,
            correlation_id,
        )
        .await
    }

    async fn revoke_signing_key(
        &self,
        project_id: Uuid,
        key_id: Uuid,
        expected_ring_revision: i64,
        correlation_id: Uuid,
    ) -> Result<SigningKeyRecord, ApplicationError> {
        PostgresProvisioningAdapter::revoke_signing_key(
            self,
            project_id,
            key_id,
            expected_ring_revision,
            correlation_id,
        )
        .await
    }

    async fn create_provider(
        &self,
        project_id: Uuid,
        command: CreateProvider,
        correlation_id: Uuid,
    ) -> Result<ProviderRecord, ApplicationError> {
        PostgresProvisioningAdapter::create_provider(self, project_id, command, correlation_id)
            .await
    }

    async fn list_providers(
        &self,
        project_id: Uuid,
    ) -> Result<Vec<ProviderRecord>, ApplicationError> {
        PostgresProvisioningAdapter::list_providers(self, project_id).await
    }

    async fn assign_provider(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
        application_id: Uuid,
        expected_application_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ProviderRecord, ApplicationError> {
        PostgresProvisioningAdapter::assign_provider(
            self,
            project_id,
            provider_id,
            application_id,
            expected_application_revision,
            correlation_id,
        )
        .await
    }

    async fn unassign_provider(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
        application_id: Uuid,
        expected_application_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ProviderRecord, ApplicationError> {
        PostgresProvisioningAdapter::unassign_provider(
            self,
            project_id,
            provider_id,
            application_id,
            expected_application_revision,
            correlation_id,
        )
        .await
    }

    async fn disable_provider(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
        expected_provider_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ProviderRecord, ApplicationError> {
        PostgresProvisioningAdapter::disable_provider(
            self,
            project_id,
            provider_id,
            expected_provider_revision,
            correlation_id,
        )
        .await
    }
}
