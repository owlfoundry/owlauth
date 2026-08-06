use async_trait::async_trait;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, DatabaseConnection,
    DbBackend, EntityTrait, IntoActiveModel, QueryFilter, QueryOrder, QuerySelect, QueryTrait,
    Statement, TransactionTrait,
};
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use super::entity::{
    audit_event, project, project_provider_egress_policy, provider_egress_policy_bridge_authority,
};
use crate::{
    application::{ApplicationError, ProviderEgressPolicyPort, ProviderEgressPolicyRecord},
    domain::{ProviderEgressMode, ProviderEgressPolicy},
};

const BRIDGE_BATCH_SIZE: u64 = 128;

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

    async fn legacy_provider_policy_bridge_pending(&self) -> Result<bool, ApplicationError> {
        let authority = provider_egress_policy_bridge_authority::Entity::find_by_id(true)
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        match authority.state.as_str() {
            "pending" => Ok(true),
            "completed" => Ok(false),
            _ => Err(ApplicationError::Integrity),
        }
    }

    async fn bridge_legacy_provider_policy(
        &self,
        policy: ProviderEgressPolicy,
    ) -> Result<(), ApplicationError> {
        let mode = policy.mode();
        if mode != ProviderEgressMode::ExactOrigins {
            return Err(ApplicationError::InvalidInput);
        }
        let exact_origins = policy
            .exact_origins()
            .map(|origin| origin.as_str().to_owned())
            .collect::<Vec<_>>();
        loop {
            let transaction = self.database.begin().await.map_err(persistence)?;
            let authority = provider_egress_policy_bridge_authority::Entity::find_by_id(true)
                .lock_exclusive()
                .one(&transaction)
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::Integrity)?;
            if authority.state == "completed" {
                transaction.commit().await.map_err(persistence)?;
                return Ok(());
            }
            if authority.state != "pending" {
                return Err(ApplicationError::Integrity);
            }
            let projects = project::Entity::find()
                .filter(
                    project::Column::Id.not_in_subquery(
                        project_provider_egress_policy::Entity::find()
                            .select_only()
                            .column(project_provider_egress_policy::Column::ProjectId)
                            .into_query(),
                    ),
                )
                .order_by_asc(project::Column::Id)
                .limit(BRIDGE_BATCH_SIZE)
                .lock_exclusive()
                .all(&transaction)
                .await
                .map_err(persistence)?;
            if projects.is_empty() {
                let now = OffsetDateTime::now_utc();
                let next_revision = authority.revision + 1;
                let mut active = authority.into_active_model();
                active.state = Set("completed".to_owned());
                active.revision = Set(next_revision);
                active.completed_at = Set(Some(now));
                active.updated_at = Set(now);
                active.update(&transaction).await.map_err(persistence)?;
                transaction.commit().await.map_err(persistence)?;
                return Ok(());
            }
            for project in projects {
                project_provider_egress_policy::ActiveModel {
                    project_id: Set(project.id),
                    mode: Set(mode.as_str().to_owned()),
                    exact_origins: Set(json!(exact_origins)),
                    revision: Set(1),
                    ..Default::default()
                }
                .insert(&transaction)
                .await
                .map_err(persistence)?;
                transaction
                    .execute_raw(Statement::from_sql_and_values(
                        DbBackend::Postgres,
                        "UPDATE provider_configurations
                            SET adapter_kind='oidc',onboarding_policy_revision=1
                          WHERE project_id=$1
                            AND (
                                adapter_kind='oidc'
                                OR (
                                    adapter_kind IS NULL
                                    AND issuer NOT IN (
                                        'https://accounts.google.com',
                                        'https://github.com'
                                    )
                                )
                            )",
                        [project.id.into()],
                    ))
                    .await
                    .map_err(persistence)?;
                bridge_project_operation_snapshots(&transaction, project.id).await?;
            }
            transaction.commit().await.map_err(persistence)?;
        }
    }
}

async fn bridge_project_operation_snapshots<C: ConnectionTrait>(
    connection: &C,
    project_id: Uuid,
) -> Result<(), ApplicationError> {
    let provider_kind = "provider.adapter_kind";
    connection
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!(
                "UPDATE login_transaction_methods AS method
                    SET provider_kind={provider_kind},
                        provider_egress_policy_revision=CASE
                            WHEN {provider_kind}='oidc' THEN 1 ELSE NULL END
                   FROM provider_configurations AS provider,
                        login_transactions AS login
                  WHERE method.project_id=$1
                    AND method.method_kind='provider'
                    AND provider.project_id=method.project_id
                    AND provider.id=method.provider_configuration_id
                    AND login.project_id=method.project_id
                    AND login.id=method.transaction_id
                    AND provider.adapter_kind IS NOT NULL
                    AND login.status NOT IN (
                        'completed','provider_exchange_failed','expired','cancelled'
                    )"
            ),
            [project_id.into()],
        ))
        .await
        .map_err(persistence)?;
    connection
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!(
                "UPDATE identity_mutation_proof_slots AS slot
                    SET provider_egress_policy_revision=CASE
                            WHEN {provider_kind}='oidc' THEN 1 ELSE NULL END
                   FROM provider_configurations AS provider,
                        identity_mutation_intents AS intent
                  WHERE slot.project_id=$1
                    AND slot.method_kind='provider'
                    AND provider.project_id=slot.project_id
                    AND provider.id=slot.provider_configuration_id
                    AND intent.project_id=slot.project_id
                    AND intent.id=slot.intent_id
                    AND provider.adapter_kind IS NOT NULL
                    AND intent.status NOT IN ('completed','failed','expired','cancelled')"
            ),
            [project_id.into()],
        ))
        .await
        .map_err(persistence)?;
    connection
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!(
                "UPDATE managed_provider_reauthorization_interactions AS interaction
                    SET provider_egress_policy_revision=CASE
                            WHEN {provider_kind}='oidc' THEN 1 ELSE NULL END
                   FROM provider_configurations AS provider
                  WHERE interaction.project_id=$1
                    AND provider.project_id=interaction.project_id
                    AND provider.id=interaction.provider_configuration_id
                    AND provider.adapter_kind IS NOT NULL
                    AND interaction.status NOT IN (
                        'completed','provider_exchange_failed','expired','cancelled'
                    )"
            ),
            [project_id.into()],
        ))
        .await
        .map_err(persistence)?;
    connection
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!(
                "UPDATE managed_provider_renewal_operations AS operation
                    SET provider_egress_policy_revision=CASE
                            WHEN {provider_kind}='oidc' THEN 1 ELSE NULL END
                   FROM managed_provider_connections AS managed_connection,
                        provider_configurations AS provider
                  WHERE operation.project_id=$1
                    AND managed_connection.project_id=operation.project_id
                    AND managed_connection.id=operation.connection_id
                    AND provider.project_id=managed_connection.project_id
                    AND provider.id=managed_connection.provider_configuration_id
                    AND provider.adapter_kind IS NOT NULL
                    AND operation.state IN ('prepared','submitted')"
            ),
            [project_id.into()],
        ))
        .await
        .map_err(persistence)?;
    bridge_project_provider_secret_operations(connection, project_id).await
}

async fn bridge_project_provider_secret_operations<C: ConnectionTrait>(
    connection: &C,
    project_id: Uuid,
) -> Result<(), ApplicationError> {
    connection
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "UPDATE provider_secret_operations AS operation
                SET egress_policy_revision=1
               FROM provider_configurations AS provider
              WHERE operation.project_id=$1
                AND provider.project_id=operation.project_id
                AND provider.id=operation.provider_id
                AND provider.adapter_kind='oidc'
                AND operation.state IN ('prepared','stored')",
            [project_id.into()],
        ))
        .await
        .map_err(persistence)?;
    Ok(())
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
