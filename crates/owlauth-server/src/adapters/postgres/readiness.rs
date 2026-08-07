use std::{sync::Arc, time::Duration};

use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, DatabaseConnection,
    EntityTrait, FromQueryResult, IntoActiveModel, QueryFilter, QueryOrder, QuerySelect, Statement,
    TransactionTrait,
};
use time::OffsetDateTime;
use uuid::Uuid;

use async_trait::async_trait;

use crate::{
    adapters::postgres::entity::{
        application, application_provider_assignment, application_publishable_key, project,
        project_key_ring, project_signing_key, provider_configuration, runtime_publication_lease,
    },
    application::{
        ApplicationError, JwksDocument, PublicApplicationConfig, PublicProvider, ReadinessPort,
    },
};

#[derive(Clone)]
pub(crate) struct PostgresReadinessAdapter {
    database: DatabaseConnection,
    process_id: Arc<str>,
    process_incarnation: Uuid,
    required_auth_process_ids: Arc<[String]>,
    lease_ttl: Duration,
}

impl PostgresReadinessAdapter {
    pub(crate) fn new(
        database: DatabaseConnection,
        process_id: String,
        process_incarnation: Uuid,
        required_auth_process_ids: Vec<String>,
        lease_ttl: Duration,
    ) -> Self {
        Self {
            database,
            process_id: Arc::from(process_id),
            process_incarnation,
            required_auth_process_ids: required_auth_process_ids.into(),
            lease_ttl,
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one linear transaction makes the complete public configuration snapshot auditable"
    )]
    pub(crate) async fn public_application_config(
        &self,
        project_public_id: &str,
        application_public_id: &str,
    ) -> Result<PublicApplicationConfig, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        self.lock_local_auth_incarnation(&transaction).await?;
        // Every Control mutation takes the same Project row exclusively before touching
        // child aggregates. This shared guard therefore linearizes the complete public
        // snapshot and prevents a child disable/unassignment from committing mid-read.
        let project = project::Entity::find()
            .filter(project::Column::PublicId.eq(project_public_id))
            .filter(project::Column::Status.eq("active"))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let application = application::Entity::find()
            .filter(application::Column::ProjectId.eq(project.id))
            .filter(application::Column::PublicId.eq(application_public_id))
            .filter(application::Column::Status.eq("active"))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let publishable_keys = application_publishable_key::Entity::find()
            .filter(application_publishable_key::Column::ProjectId.eq(project.id))
            .filter(application_publishable_key::Column::ApplicationId.eq(application.id))
            .filter(application_publishable_key::Column::Status.eq("active"))
            .order_by_asc(application_publishable_key::Column::PublicId)
            .limit(51)
            .lock_shared()
            .all(&transaction)
            .await
            .map_err(persistence)?;
        if publishable_keys.len() > 50 {
            return Err(ApplicationError::Integrity);
        }
        let assignments = application_provider_assignment::Entity::find()
            .filter(application_provider_assignment::Column::ProjectId.eq(project.id))
            .filter(application_provider_assignment::Column::ApplicationId.eq(application.id))
            .filter(application_provider_assignment::Column::Status.eq("active"))
            .order_by_asc(application_provider_assignment::Column::ProviderId)
            .limit(51)
            .lock_shared()
            .all(&transaction)
            .await
            .map_err(persistence)?;
        if assignments.len() > 50 {
            return Err(ApplicationError::Integrity);
        }
        let provider_ids: Vec<_> = assignments
            .iter()
            .map(|assignment| assignment.provider_id)
            .collect();
        let providers = if provider_ids.is_empty() {
            Vec::new()
        } else {
            let providers = provider_configuration::Entity::find()
                .filter(provider_configuration::Column::ProjectId.eq(project.id))
                .filter(provider_configuration::Column::Id.is_in(provider_ids.clone()))
                .filter(provider_configuration::Column::Status.eq("active"))
                .order_by_asc(provider_configuration::Column::ProviderKey)
                .limit(51)
                .lock_shared()
                .all(&transaction)
                .await
                .map_err(persistence)?;
            if providers.len() != assignments.len() {
                return Err(ApplicationError::Integrity);
            }
            providers
        };
        let active_signing_keys = project_signing_key::Entity::find()
            .filter(project_signing_key::Column::ProjectId.eq(project.id))
            .filter(project_signing_key::Column::State.eq("active"))
            .order_by_asc(project_signing_key::Column::Kid)
            .limit(2)
            .lock_shared()
            .all(&transaction)
            .await
            .map_err(persistence)?;
        if active_signing_keys.len() > 1 {
            return Err(ApplicationError::Integrity);
        }

        let final_publishable_keys = application_publishable_key::Entity::find()
            .filter(application_publishable_key::Column::ProjectId.eq(project.id))
            .filter(application_publishable_key::Column::ApplicationId.eq(application.id))
            .filter(application_publishable_key::Column::Status.eq("active"))
            .order_by_asc(application_publishable_key::Column::PublicId)
            .limit(51)
            .all(&transaction)
            .await
            .map_err(persistence)?;
        let final_assignments = application_provider_assignment::Entity::find()
            .filter(application_provider_assignment::Column::ProjectId.eq(project.id))
            .filter(application_provider_assignment::Column::ApplicationId.eq(application.id))
            .filter(application_provider_assignment::Column::Status.eq("active"))
            .order_by_asc(application_provider_assignment::Column::ProviderId)
            .limit(51)
            .all(&transaction)
            .await
            .map_err(persistence)?;
        let final_providers = if provider_ids.is_empty() {
            Vec::new()
        } else {
            provider_configuration::Entity::find()
                .filter(provider_configuration::Column::ProjectId.eq(project.id))
                .filter(provider_configuration::Column::Id.is_in(provider_ids))
                .filter(provider_configuration::Column::Status.eq("active"))
                .order_by_asc(provider_configuration::Column::ProviderKey)
                .limit(51)
                .all(&transaction)
                .await
                .map_err(persistence)?
        };
        let final_active_signing_keys = project_signing_key::Entity::find()
            .filter(project_signing_key::Column::ProjectId.eq(project.id))
            .filter(project_signing_key::Column::State.eq("active"))
            .order_by_asc(project_signing_key::Column::Kid)
            .limit(2)
            .all(&transaction)
            .await
            .map_err(persistence)?;
        let final_project = project::Entity::find_by_id(project.id)
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::RevisionConflict)?;
        let final_application = application::Entity::find_by_id(application.id)
            .filter(application::Column::ProjectId.eq(project.id))
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::RevisionConflict)?;
        if final_project.status != "active"
            || final_project.metadata_revision != project.metadata_revision
            || final_project.security_revision != project.security_revision
            || final_application.status != "active"
            || final_application.revision != application.revision
            || final_application.metadata_revision != application.metadata_revision
            || final_application.security_revision != application.security_revision
            || final_publishable_keys != publishable_keys
            || final_assignments != assignments
            || final_providers != providers
            || final_active_signing_keys != active_signing_keys
        {
            return Err(ApplicationError::RevisionConflict);
        }

        // Email readiness follows the same canonical owner order as admission: policy and
        // assignment first, then the selected SMTP generation/readiness, then scoped protection.
        // Nullable outer-join sides are never row-locked.
        let email_policy = transaction
            .query_one_raw(Statement::from_sql_and_values(
                sea_orm::DbBackend::Postgres,
                "SELECT policy.otp_enabled,policy.magic_link_enabled,policy.allow_deployment_default
                 FROM project_email_policies policy
                 JOIN application_email_assignments assignment
                   ON assignment.project_id=policy.project_id AND assignment.application_id=$2
                 WHERE policy.project_id=$1 AND policy.status='enabled'
                   AND assignment.status='active'
                 FOR SHARE OF policy,assignment",
                vec![project.id.into(), application.id.into()],
            ))
            .await
            .map_err(persistence)?;
        let mut smtp_ready = false;
        if let Some(policy) = &email_policy {
            let project_smtp = transaction
                .query_one_raw(Statement::from_sql_and_values(
                    sea_orm::DbBackend::Postgres,
                    "SELECT id,generation FROM project_smtp_configurations
                     WHERE project_id=$1 AND status='active' FOR SHARE",
                    vec![project.id.into()],
                ))
                .await
                .map_err(persistence)?;
            if let Some(smtp) = project_smtp {
                let configuration_id: Uuid = smtp.try_get("", "id").map_err(persistence)?;
                let generation: i32 = smtp.try_get("", "generation").map_err(persistence)?;
                let roster_ready: bool = transaction
                    .query_one_raw(Statement::from_sql_and_values(
                        sea_orm::DbBackend::Postgres,
                        "SELECT NOT EXISTS (
                           SELECT required.process_id
                           FROM jsonb_array_elements_text($4::jsonb) AS required(process_id)
                           WHERE NOT EXISTS (
                             SELECT 1 FROM project_smtp_runtime_readiness readiness
                             WHERE readiness.project_id=$1
                               AND readiness.configuration_id=$2
                               AND readiness.generation=$3
                               AND readiness.process_id=required.process_id
                               AND readiness.state='ready'
                               AND readiness.lease_expires_at>transaction_timestamp()
                               AND EXISTS (
                                 SELECT 1 FROM auth_process_incarnations current
                                 WHERE current.process_id=readiness.process_id
                                   AND current.process_incarnation=readiness.process_incarnation)))
                         AS roster_ready",
                        vec![
                            project.id.into(),
                            configuration_id.into(),
                            generation.into(),
                            serde_json::json!(&*self.required_auth_process_ids).into(),
                        ],
                    ))
                    .await
                    .map_err(persistence)?
                    .ok_or(ApplicationError::Persistence)?
                    .try_get("", "roster_ready")
                    .map_err(persistence)?;
                smtp_ready = !self.required_auth_process_ids.is_empty() && roster_ready;
            } else if policy
                .try_get::<bool>("", "allow_deployment_default")
                .map_err(persistence)?
            {
                smtp_ready = transaction
                    .query_one_raw(Statement::from_string(
                        sea_orm::DbBackend::Postgres,
                        "SELECT generation FROM deployment_smtp_generations
                         WHERE status='active' FOR SHARE"
                            .to_owned(),
                    ))
                    .await
                    .map_err(persistence)?
                    .is_some();
            }
        }
        let protection_ready = transaction
            .query_one_raw(Statement::from_sql_and_values(
                sea_orm::DbBackend::Postgres,
                "SELECT 1 FROM email_protection_runtime_readiness protection
                 JOIN auth_process_incarnations current
                   ON current.process_id=protection.process_id
                  AND current.process_incarnation=protection.process_incarnation
                 WHERE protection.process_id=$1 AND protection.process_incarnation=$2
                   AND protection.state='ready'
                   AND protection.lease_expires_at>transaction_timestamp()
                 FOR SHARE OF protection,current",
                vec![
                    self.process_id.to_string().into(),
                    self.process_incarnation.into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .is_some();
        let email_available = email_policy.is_some()
            && smtp_ready
            && protection_ready
            && active_signing_keys.len() == 1;
        let email_otp_enabled = email_available
            && email_policy
                .as_ref()
                .map(|row| row.try_get("", "otp_enabled").map_err(persistence))
                .transpose()?
                .unwrap_or(false);
        let email_magic_link_enabled = email_available
            && email_policy
                .as_ref()
                .map(|row| row.try_get("", "magic_link_enabled").map_err(persistence))
                .transpose()?
                .unwrap_or(false);
        let login_available = !publishable_keys.is_empty()
            && active_signing_keys.len() == 1
            && (!providers.is_empty() || email_available);
        let result = PublicApplicationConfig {
            project_public_id: project.public_id,
            project_display_name: project.display_name,
            application_public_id: application.public_id,
            application_display_name: application.display_name,
            publishable_keys: publishable_keys
                .into_iter()
                .map(|key| key.public_id)
                .collect(),
            providers: providers
                .into_iter()
                .map(|provider| {
                    let kind = super::provider_row::effective_provider_kind(
                        &provider.kind,
                        &provider.issuer,
                    )?;
                    Ok(PublicProvider {
                        key: provider.provider_key,
                        display_name: provider.display_name,
                        kind: kind.as_str().to_owned(),
                        issuer: provider.issuer,
                    })
                })
                .collect::<Result<Vec<_>, ApplicationError>>()?,
            email_available,
            email_otp_enabled,
            email_magic_link_enabled,
            login_available,
        };
        transaction.commit().await.map_err(persistence)?;
        Ok(result)
    }

    pub(crate) async fn project_jwks(
        &self,
        project_public_id: &str,
    ) -> Result<JwksDocument, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        self.lock_local_auth_incarnation(&transaction).await?;
        // Control mutations serialize on the Project row exclusively. Keep the
        // corresponding shared guard through lease observation so disablement and
        // publication have one database ordering point, with no post-disable lease.
        let project = project::Entity::find()
            .filter(project::Column::PublicId.eq(project_public_id))
            .filter(project::Column::Status.eq("active"))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let ring = project_key_ring::Entity::find()
            .filter(project_key_ring::Column::ProjectId.eq(project.id))
            .filter(project_key_ring::Column::Purpose.eq("application_tokens"))
            .filter(project_key_ring::Column::Algorithm.eq("EdDSA"))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let now = database_now(&transaction).await?;
        let loaded = project_signing_key::Entity::find()
            .filter(project_signing_key::Column::ProjectId.eq(project.id))
            .filter(project_signing_key::Column::RingId.eq(ring.id))
            .filter(project_signing_key::Column::State.is_in(["published", "active", "retiring"]))
            .order_by_asc(project_signing_key::Column::Kid)
            .limit(101)
            .all(&transaction)
            .await
            .map_err(persistence)?;
        if loaded.len() > 100 {
            return Err(ApplicationError::InvalidTransition);
        }
        let keys = loaded
            .into_iter()
            .filter(|key| {
                key.state != "retiring" || key.verify_not_after.is_some_and(|cutoff| cutoff > now)
            })
            .map(|key| key.public_jwk)
            .collect();
        self.observe_revision(&transaction, project.id, ring.id, ring.revision)
            .await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(JwksDocument {
            keys,
            revision: ring.revision,
            signing_epoch: ring.signing_epoch,
        })
    }

    async fn observe_revision(
        &self,
        transaction: &sea_orm::DatabaseTransaction,
        project_id: uuid::Uuid,
        ring_id: uuid::Uuid,
        loaded_revision: i64,
    ) -> Result<(), ApplicationError> {
        let now = database_now(transaction).await?;
        let expires_at = now + self.lease_ttl;
        let existing = runtime_publication_lease::Entity::find_by_id((
            project_id,
            ring_id,
            self.process_id.to_string(),
        ))
        .lock_exclusive()
        .one(transaction)
        .await
        .map_err(persistence)?;
        match existing {
            Some(existing) => {
                if existing.loaded_revision > loaded_revision {
                    return Err(ApplicationError::RevisionConflict);
                }
                let observation_restarted = existing.process_incarnation
                    != self.process_incarnation
                    || existing.loaded_revision < loaded_revision
                    || existing.expires_at <= now;
                let mut active = existing.into_active_model();
                active.process_incarnation = Set(self.process_incarnation);
                active.loaded_revision = Set(loaded_revision);
                if observation_restarted {
                    active.first_observed_at = Set(now);
                }
                active.last_observed_at = Set(now);
                active.expires_at = Set(expires_at);
                active.update(transaction).await.map_err(persistence)?;
            }
            None => {
                runtime_publication_lease::ActiveModel {
                    project_id: Set(project_id),
                    ring_id: Set(ring_id),
                    process_id: Set(self.process_id.to_string()),
                    process_incarnation: Set(self.process_incarnation),
                    loaded_revision: Set(loaded_revision),
                    first_observed_at: Set(now),
                    last_observed_at: Set(now),
                    expires_at: Set(expires_at),
                }
                .insert(transaction)
                .await
                .map_err(persistence)?;
            }
        }
        Ok(())
    }

    async fn observe_signing_revisions(&self, limit: usize) -> Result<usize, ApplicationError> {
        let limit = u64::try_from(limit).map_err(|_| ApplicationError::InvalidInput)?;
        if !(1..=100).contains(&limit) {
            return Err(ApplicationError::InvalidInput);
        }
        let rings = project_key_ring::Entity::find()
            .filter(project_key_ring::Column::Purpose.eq("application_tokens"))
            .filter(project_key_ring::Column::Algorithm.eq("EdDSA"))
            .order_by_asc(project_key_ring::Column::ProjectId)
            .order_by_asc(project_key_ring::Column::Id)
            .limit(limit)
            .all(&self.database)
            .await
            .map_err(persistence)?;
        let mut observed = 0;
        for ring in rings {
            let Some(project) = project::Entity::find_by_id(ring.project_id)
                .filter(project::Column::Status.eq("active"))
                .one(&self.database)
                .await
                .map_err(persistence)?
            else {
                continue;
            };
            match self.project_jwks(&project.public_id).await {
                Ok(_) => observed += 1,
                Err(ApplicationError::NotFound | ApplicationError::RevisionConflict) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(observed)
    }

    async fn lock_local_auth_incarnation<C: ConnectionTrait>(
        &self,
        connection: &C,
    ) -> Result<(), ApplicationError> {
        let current = connection
            .query_one_raw(Statement::from_sql_and_values(
                sea_orm::DbBackend::Postgres,
                "SELECT 1 FROM auth_process_incarnations
                 WHERE process_id=$1 AND process_incarnation=$2 FOR SHARE",
                vec![
                    self.process_id.to_string().into(),
                    self.process_incarnation.into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .is_some();
        current.then_some(()).ok_or(ApplicationError::Disabled)
    }
}

#[derive(FromQueryResult)]
struct DatabaseTime {
    database_now: OffsetDateTime,
}

async fn database_now<C>(connection: &C) -> Result<OffsetDateTime, ApplicationError>
where
    C: ConnectionTrait,
{
    DatabaseTime::find_by_statement(Statement::from_string(
        connection.get_database_backend(),
        "SELECT transaction_timestamp() AS database_now",
    ))
    .one(connection)
    .await
    .map_err(persistence)?
    .map(|row| row.database_now)
    .ok_or(ApplicationError::Persistence)
}

fn persistence(_: impl std::fmt::Debug) -> ApplicationError {
    ApplicationError::Persistence
}

#[async_trait]
impl ReadinessPort for PostgresReadinessAdapter {
    async fn readiness(&self) -> Result<(), ApplicationError> {
        self.lock_local_auth_incarnation(&self.database).await
    }

    async fn public_application_config(
        &self,
        project_public_id: &str,
        application_public_id: &str,
    ) -> Result<PublicApplicationConfig, ApplicationError> {
        PostgresReadinessAdapter::public_application_config(
            self,
            project_public_id,
            application_public_id,
        )
        .await
    }

    async fn project_jwks(
        &self,
        project_public_id: &str,
    ) -> Result<JwksDocument, ApplicationError> {
        PostgresReadinessAdapter::project_jwks(self, project_public_id).await
    }

    async fn observe_signing_revisions(&self, limit: usize) -> Result<usize, ApplicationError> {
        PostgresReadinessAdapter::observe_signing_revisions(self, limit).await
    }
}
