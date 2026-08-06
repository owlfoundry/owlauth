use async_trait::async_trait;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, DatabaseConnection, EntityTrait, IntoActiveModel,
    QuerySelect, TransactionTrait,
};
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use super::entity::{audit_event, project, project_provider_egress_policy};
use crate::{
    application::{ApplicationError, ProviderEgressPolicyPort, ProviderEgressPolicyRecord},
    domain::ProviderEgressPolicy,
};

#[derive(Clone)]
pub(crate) struct PostgresProviderEgressPolicyRepository {
    database: DatabaseConnection,
}

impl PostgresProviderEgressPolicyRepository {
    pub(crate) fn new(database: DatabaseConnection) -> Self {
        Self { database }
    }
}

#[async_trait]
impl ProviderEgressPolicyPort for PostgresProviderEgressPolicyRepository {
    async fn get_provider_egress_policy(
        &self,
        project_id: Uuid,
    ) -> Result<ProviderEgressPolicyRecord, ApplicationError> {
        let model = project_provider_egress_policy::Entity::find_by_id(project_id)
            .one(&self.database)
            .await
            .map_err(persistence)?;
        match model {
            Some(model) => map_policy(model),
            None => {
                if project::Entity::find_by_id(project_id)
                    .one(&self.database)
                    .await
                    .map_err(persistence)?
                    .is_some()
                {
                    Err(ApplicationError::Integrity)
                } else {
                    Err(ApplicationError::NotFound)
                }
            }
        }
    }

    async fn get_active_provider_egress_policy(
        &self,
        project_id: Uuid,
    ) -> Result<ProviderEgressPolicyRecord, ApplicationError> {
        let project = project::Entity::find_by_id(project_id)
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if project.status != "active" {
            return Err(ApplicationError::Disabled);
        }
        project_provider_egress_policy::Entity::find_by_id(project_id)
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)
            .and_then(map_policy)
    }

    async fn get_active_project_public_id(
        &self,
        project_id: Uuid,
    ) -> Result<String, ApplicationError> {
        let project = project::Entity::find_by_id(project_id)
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if project.status != "active" {
            return Err(ApplicationError::Disabled);
        }
        Ok(project.public_id)
    }

    async fn update_provider_egress_policy(
        &self,
        project_id: Uuid,
        policy: ProviderEgressPolicy,
        expected_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ProviderEgressPolicyRecord, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        let project = project::Entity::find_by_id(project_id)
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if project.status != "active" {
            return Err(ApplicationError::Disabled);
        }
        let current = project_provider_egress_policy::Entity::find_by_id(project_id)
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        if current.revision != expected_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        let mode = policy.mode();
        let exact_origins = policy
            .exact_origins()
            .map(|origin| origin.as_str().to_owned())
            .collect::<Vec<_>>();
        let now = OffsetDateTime::now_utc();
        let mut active = current.into_active_model();
        active.mode = Set(mode.as_str().to_owned());
        active.exact_origins = Set(json!(exact_origins));
        active.revision = Set(expected_revision + 1);
        active.updated_at = Set(now);
        let updated = active.update(&transaction).await.map_err(persistence)?;
        audit_event::ActiveModel {
            id: Set(Uuid::new_v4()),
            project_id: Set(Some(project_id)),
            actor_kind: Set("operator".to_owned()),
            action: Set("provider.egress_policy.updated".to_owned()),
            target_kind: Set("provider_egress_policy".to_owned()),
            target_id: Set(None),
            outcome: Set("success".to_owned()),
            correlation_id: Set(correlation_id),
            safe_context: Set(json!({
                "mode": mode.as_str(),
                "origin_count": exact_origins.len(),
            })),
        }
        .insert(&transaction)
        .await
        .map_err(persistence)?;
        transaction.commit().await.map_err(persistence)?;
        map_policy(updated)
    }

    async fn record_oidc_preflight_outcome(
        &self,
        project_id: Uuid,
        outcome: &'static str,
        correlation_id: Uuid,
    ) -> Result<(), ApplicationError> {
        if !matches!(
            outcome,
            "success" | "metadata_rejected" | "provider_unavailable"
        ) {
            return Err(ApplicationError::InvalidInput);
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        let project = project::Entity::find_by_id(project_id)
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if project.status != "active" {
            return Err(ApplicationError::Disabled);
        }
        audit_event::ActiveModel {
            id: Set(Uuid::new_v4()),
            project_id: Set(Some(project_id)),
            actor_kind: Set("operator".to_owned()),
            action: Set("provider.oidc_preflight".to_owned()),
            target_kind: Set("provider_egress_policy".to_owned()),
            target_id: Set(None),
            outcome: Set(outcome.to_owned()),
            correlation_id: Set(correlation_id),
            safe_context: Set(json!({})),
        }
        .insert(&transaction)
        .await
        .map_err(persistence)?;
        transaction.commit().await.map_err(persistence)
    }
}

fn map_policy(
    model: project_provider_egress_policy::Model,
) -> Result<ProviderEgressPolicyRecord, ApplicationError> {
    let policy =
        super::provider_row::decode_provider_egress_policy(&model.mode, model.exact_origins)?;
    Ok(ProviderEgressPolicyRecord {
        project_id: model.project_id,
        mode: policy.mode(),
        exact_origins: policy
            .exact_origins()
            .map(|origin| origin.as_str().to_owned())
            .collect(),
        revision: model.revision,
    })
}

fn persistence(_: sea_orm::DbErr) -> ApplicationError {
    ApplicationError::Persistence
}
