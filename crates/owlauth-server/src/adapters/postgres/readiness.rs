use std::{sync::Arc, time::Duration};

use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, DatabaseConnection, EntityTrait,
    IntoActiveModel, QueryFilter, QueryOrder, QuerySelect, TransactionTrait,
};
use time::OffsetDateTime;

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
    lease_ttl: Duration,
}

impl PostgresReadinessAdapter {
    pub(crate) fn new(
        database: DatabaseConnection,
        process_id: String,
        lease_ttl: Duration,
    ) -> Self {
        Self {
            database,
            process_id: Arc::from(process_id),
            lease_ttl,
        }
    }

    pub(crate) async fn public_application_config(
        &self,
        project_public_id: &str,
        application_public_id: &str,
    ) -> Result<PublicApplicationConfig, ApplicationError> {
        let project = project::Entity::find()
            .filter(project::Column::PublicId.eq(project_public_id))
            .filter(project::Column::Status.eq("active"))
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let application = application::Entity::find()
            .filter(application::Column::ProjectId.eq(project.id))
            .filter(application::Column::PublicId.eq(application_public_id))
            .filter(application::Column::Status.eq("active"))
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let publishable_keys = application_publishable_key::Entity::find()
            .filter(application_publishable_key::Column::ProjectId.eq(project.id))
            .filter(application_publishable_key::Column::ApplicationId.eq(application.id))
            .filter(application_publishable_key::Column::Status.eq("active"))
            .order_by_asc(application_publishable_key::Column::PublicId)
            .limit(51)
            .all(&self.database)
            .await
            .map_err(persistence)?;
        if publishable_keys.len() > 50 {
            return Err(ApplicationError::Integrity);
        }
        let publishable_keys = publishable_keys
            .into_iter()
            .map(|key| key.public_id)
            .collect();
        let assignments = application_provider_assignment::Entity::find()
            .filter(application_provider_assignment::Column::ProjectId.eq(project.id))
            .filter(application_provider_assignment::Column::ApplicationId.eq(application.id))
            .filter(application_provider_assignment::Column::Status.eq("active"))
            .limit(51)
            .all(&self.database)
            .await
            .map_err(persistence)?;
        if assignments.len() > 50 {
            return Err(ApplicationError::Integrity);
        }
        let provider_ids: Vec<_> = assignments
            .into_iter()
            .map(|assignment| assignment.provider_id)
            .collect();
        let providers = if provider_ids.is_empty() {
            Vec::new()
        } else {
            let providers = provider_configuration::Entity::find()
                .filter(provider_configuration::Column::ProjectId.eq(project.id))
                .filter(provider_configuration::Column::Id.is_in(provider_ids))
                .filter(provider_configuration::Column::Status.eq("active"))
                .order_by_asc(provider_configuration::Column::ProviderKey)
                .limit(51)
                .all(&self.database)
                .await
                .map_err(persistence)?;
            if providers.len() > 50 {
                return Err(ApplicationError::Integrity);
            }
            providers
                .into_iter()
                .map(|provider| PublicProvider {
                    key: provider.provider_key,
                    display_name: provider.display_name,
                    kind: provider.kind,
                })
                .collect()
        };
        Ok(PublicApplicationConfig {
            project_public_id: project.public_id,
            project_display_name: project.display_name,
            application_public_id: application.public_id,
            application_display_name: application.display_name,
            publishable_keys,
            providers,
            login_available: false,
        })
    }

    pub(crate) async fn project_jwks(
        &self,
        project_public_id: &str,
    ) -> Result<JwksDocument, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        let project = project::Entity::find()
            .filter(project::Column::PublicId.eq(project_public_id))
            .filter(project::Column::Status.eq("active"))
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
        let now = OffsetDateTime::now_utc();
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
        let now = OffsetDateTime::now_utc();
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
                let revision_advanced = existing.loaded_revision < loaded_revision;
                let mut active = existing.into_active_model();
                active.loaded_revision = Set(loaded_revision);
                if revision_advanced {
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
}

fn persistence(_: impl std::fmt::Debug) -> ApplicationError {
    ApplicationError::Persistence
}

#[async_trait]
impl ReadinessPort for PostgresReadinessAdapter {
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
}
