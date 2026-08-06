use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use sea_orm::sea_query::{LockBehavior, LockType};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, DatabaseConnection,
    DbBackend, EntityTrait, IntoActiveModel, QueryFilter, QueryOrder, QueryResult, QuerySelect,
    Statement, TransactionTrait,
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::application::{
    ApplicationError, ConfirmedProjectionPolicyUpdate, McpConfirmationContext, McpConfirmationPort,
    PROJECTION_POLICY_COMMIT_TOOL, PreparedProjectionPolicyConfirmation,
    ProjectionExpansionRepository, ProjectionPolicyPort, ProjectionPolicyRecord,
    UpdateProjectionPolicy,
};

const MAX_MCP_CONFIRMATION_ROWS: i64 = 4096;
const MCP_CONFIRMATION_CLEANUP_BATCH_SIZE: i64 = 256;
const MCP_CONFIRMATION_ADVISORY_LOCK: i64 = 5_778_354_003_992_237_833;

use super::{
    audit::append_runtime_audit,
    authentication::persistence,
    entity::{
        application, application_user_binding, project, project_policy,
        projection_expansion_operation,
    },
    projection::PostgresIdentityProjectionMaterializer,
};

#[derive(Clone)]
pub(crate) struct PostgresProjectionExpansionRepository {
    database: DatabaseConnection,
    materializer: Arc<PostgresIdentityProjectionMaterializer>,
}

impl PostgresProjectionExpansionRepository {
    pub(crate) fn new(
        database: DatabaseConnection,
        materializer: Arc<PostgresIdentityProjectionMaterializer>,
    ) -> Self {
        Self {
            database,
            materializer,
        }
    }

    async fn claim_operation(
        &self,
        worker_id: &str,
        worker_incarnation: Uuid,
        now: OffsetDateTime,
        lease_duration: Duration,
    ) -> Result<Option<(Uuid, Uuid, i64)>, ApplicationError> {
        if worker_id.is_empty() || worker_id.len() > 128 || lease_duration.is_zero() {
            return Err(ApplicationError::InvalidInput);
        }
        let lease_expires_at = now
            .checked_add(
                time::Duration::try_from(lease_duration)
                    .map_err(|_| ApplicationError::InvalidInput)?,
            )
            .ok_or(ApplicationError::InvalidInput)?;
        let retry_before = now
            .checked_sub(time::Duration::seconds(30))
            .ok_or(ApplicationError::InvalidInput)?;
        let hint = self
            .database
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT operation.id,operation.project_id
                   FROM projection_expansion_operations operation
                   JOIN projects project ON project.id=operation.project_id
                  WHERE project.status='active'
                    AND (operation.status='pending'
                      OR (operation.status='running' AND operation.lease_expires_at <= $1)
                      OR (operation.status='failed' AND operation.updated_at <= $2))
                  ORDER BY operation.created_at,operation.id LIMIT 1",
                [now.into(), retry_before.into()],
            ))
            .await
            .map_err(persistence)?;
        let Some(hint) = hint else {
            return Ok(None);
        };
        let operation_id: Uuid = hint.try_get("", "id").map_err(persistence)?;
        let project_id: Uuid = hint.try_get("", "project_id").map_err(persistence)?;
        let transaction = self.database.begin().await.map_err(persistence)?;
        lock_active_project(&transaction, project_id).await?;
        let operation = projection_expansion_operation::Entity::find_by_id(operation_id)
            .filter(projection_expansion_operation::Column::ProjectId.eq(project_id))
            .lock_with_behavior(LockType::Update, LockBehavior::SkipLocked)
            .one(&transaction)
            .await
            .map_err(persistence)?;
        let Some(operation) = operation.filter(|operation| {
            operation.status == "pending"
                || (operation.status == "running"
                    && operation
                        .lease_expires_at
                        .is_some_and(|expiry| expiry <= now))
                || (operation.status == "failed" && operation.updated_at <= retry_before)
        }) else {
            transaction.commit().await.map_err(persistence)?;
            return Ok(None);
        };
        let generation = operation
            .lease_generation
            .checked_add(1)
            .ok_or(ApplicationError::Integrity)?;
        let operation_id = operation.id;
        let mut active = operation.into_active_model();
        active.status = Set("running".to_owned());
        active.lease_owner = Set(Some(worker_id.to_owned()));
        active.lease_incarnation = Set(Some(worker_incarnation));
        active.lease_generation = Set(generation);
        active.lease_expires_at = Set(Some(lease_expires_at));
        active.updated_at = Set(now);
        active.update(&transaction).await.map_err(persistence)?;
        transaction.commit().await.map_err(persistence)?;
        Ok(Some((operation_id, project_id, generation)))
    }
}

#[async_trait]
impl ProjectionPolicyPort for PostgresProjectionExpansionRepository {
    async fn get_project_projection_policy(
        &self,
        project_id: Uuid,
    ) -> Result<ProjectionPolicyRecord, ApplicationError> {
        let owner = project::Entity::find_by_id(project_id)
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if owner.status != "active" {
            return Err(ApplicationError::Disabled);
        }
        let policy = project_policy::Entity::find_by_id(project_id)
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        Ok(project_policy_record(&policy, None))
    }

    async fn update_project_projection_policy(
        &self,
        project_id: Uuid,
        command: UpdateProjectionPolicy,
        now: OffsetDateTime,
        correlation_id: Uuid,
    ) -> Result<ProjectionPolicyRecord, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        let owner = project::Entity::find_by_id(project_id)
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if owner.status != "active" {
            return Err(ApplicationError::Disabled);
        }
        let policy = project_policy::Entity::find_by_id(project_id)
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        if policy.projection_revision != command.expected_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        reject_narrowing(
            policy.projection_verified_email_enabled,
            command.verified_email_enabled,
        )?;
        if policy.projection_verified_email_enabled == command.verified_email_enabled {
            transaction.commit().await.map_err(persistence)?;
            return Ok(project_policy_record(&policy, None));
        }
        let revision = policy
            .projection_revision
            .checked_add(1)
            .ok_or(ApplicationError::Integrity)?;
        let mut active = policy.into_active_model();
        active.projection_verified_email_enabled = Set(command.verified_email_enabled);
        active.projection_revision = Set(revision);
        let policy = active.update(&transaction).await.map_err(persistence)?;
        let operation_id = Uuid::new_v4();
        insert_operation(
            &transaction,
            operation_id,
            project_id,
            None,
            "project",
            revision,
            now,
        )
        .await?;
        append_runtime_audit(
            &transaction,
            project_id,
            "deployment_operator",
            "projection.policy.expand.project",
            "project_policy",
            Some(project_id),
            correlation_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(project_policy_record(&policy, Some(operation_id)))
    }

    async fn get_application_projection_policy(
        &self,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<ProjectionPolicyRecord, ApplicationError> {
        let application = application::Entity::find_by_id(application_id)
            .filter(application::Column::ProjectId.eq(project_id))
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if application.status != "active" {
            return Err(ApplicationError::Disabled);
        }
        Ok(application_policy_record(&application, None))
    }

    async fn update_application_projection_policy(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        command: UpdateProjectionPolicy,
        now: OffsetDateTime,
        correlation_id: Uuid,
    ) -> Result<ProjectionPolicyRecord, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        let owner = project::Entity::find_by_id(project_id)
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if owner.status != "active" {
            return Err(ApplicationError::Disabled);
        }
        let application = application::Entity::find_by_id(application_id)
            .filter(application::Column::ProjectId.eq(project_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if application.status != "active" {
            return Err(ApplicationError::Disabled);
        }
        if application.projection_revision != command.expected_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        reject_narrowing(
            application.projection_verified_email_enabled,
            command.verified_email_enabled,
        )?;
        if application.projection_verified_email_enabled == command.verified_email_enabled {
            transaction.commit().await.map_err(persistence)?;
            return Ok(application_policy_record(&application, None));
        }
        let revision = application
            .projection_revision
            .checked_add(1)
            .ok_or(ApplicationError::Integrity)?;
        let aggregate_revision = application
            .revision
            .checked_add(1)
            .ok_or(ApplicationError::Integrity)?;
        let mut active = application.into_active_model();
        active.projection_verified_email_enabled = Set(command.verified_email_enabled);
        active.projection_revision = Set(revision);
        active.revision = Set(aggregate_revision);
        active.updated_at = Set(now);
        let application = active.update(&transaction).await.map_err(persistence)?;
        let operation_id = Uuid::new_v4();
        insert_operation(
            &transaction,
            operation_id,
            project_id,
            Some(application_id),
            "application",
            revision,
            now,
        )
        .await?;
        append_runtime_audit(
            &transaction,
            project_id,
            "deployment_operator",
            "projection.policy.expand.application",
            "application",
            Some(application_id),
            correlation_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(application_policy_record(&application, Some(operation_id)))
    }
}

#[async_trait]
impl McpConfirmationPort for PostgresProjectionExpansionRepository {
    async fn prepare_projection_policy_update(
        &self,
        context: &McpConfirmationContext,
        command: ConfirmedProjectionPolicyUpdate,
        capability_digest: Vec<u8>,
        command_digest: Vec<u8>,
    ) -> Result<PreparedProjectionPolicyConfirmation, ApplicationError> {
        if capability_digest.len() != 32 || command_digest.len() != 32 {
            return Err(ApplicationError::InvalidInput);
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        let owner = lock_active_project(&transaction, command.project_id).await?;
        let policy = preview_policy_snapshot(&transaction, &command).await?;
        if policy.verified_email_enabled == command.verified_email_enabled {
            return Err(ApplicationError::InvalidTransition);
        }
        admit_confirmation_capacity(&transaction).await?;
        let capability_id = Uuid::new_v4();
        let row = transaction
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "WITH authority_clock AS (SELECT clock_timestamp() AS now)
                 INSERT INTO mcp_confirmation_capabilities
                    (id,capability_digest,actor_kind,audience,instance_id,control_endpoint,
                     tool_name,command_digest,project_id,project_metadata_revision,
                     application_id,target_revision,created_at,expires_at,consumed_at)
                 SELECT $1,$2,'deployment_operator','control_mcp',$3,$4,$5,$6,$7,$8,$9,$10,
                        authority_clock.now,authority_clock.now + INTERVAL '5 minutes',NULL
                   FROM authority_clock
                 RETURNING expires_at",
                [
                    capability_id.into(),
                    capability_digest.into(),
                    context.instance_id.clone().into(),
                    context.control_endpoint.clone().into(),
                    PROJECTION_POLICY_COMMIT_TOOL.into(),
                    command_digest.into(),
                    command.project_id.into(),
                    owner.metadata_revision.into(),
                    command.application_id.into(),
                    command.expected_revision.into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Persistence)?;
        let expires_at = row.try_get("", "expires_at").map_err(persistence)?;
        transaction.commit().await.map_err(persistence)?;
        Ok(PreparedProjectionPolicyConfirmation { policy, expires_at })
    }

    async fn commit_projection_policy_update(
        &self,
        context: &McpConfirmationContext,
        command: ConfirmedProjectionPolicyUpdate,
        capability_digest: Vec<u8>,
        command_digest: Vec<u8>,
        correlation_id: Uuid,
    ) -> Result<ProjectionPolicyRecord, ApplicationError> {
        if capability_digest.len() != 32 || command_digest.len() != 32 {
            return Err(ApplicationError::InvalidInput);
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        let capability = transaction
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT id,actor_kind,audience,instance_id,control_endpoint,tool_name,
                        command_digest,project_id,project_metadata_revision,application_id,
                        target_revision,expires_at,consumed_at
                   FROM mcp_confirmation_capabilities
                  WHERE capability_digest=$1
                  FOR UPDATE",
                [capability_digest.into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::InvalidTransition)?;
        validate_confirmation_binding(&capability, context, &command, &command_digest)?;

        let owner = lock_active_project(&transaction, command.project_id).await?;
        let expected_project_revision: i64 = capability
            .try_get("", "project_metadata_revision")
            .map_err(persistence)?;
        if owner.metadata_revision != expected_project_revision {
            return Err(ApplicationError::RevisionConflict);
        }

        let CommittedProjectionPolicy {
            policy,
            target_kind,
            target_id,
            authority_now,
        } = commit_confirmed_policy_update(&transaction, &capability, &command, correlation_id)
            .await?;

        let capability_id: Uuid = capability.try_get("", "id").map_err(persistence)?;
        let consumed = transaction
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "UPDATE mcp_confirmation_capabilities
                    SET consumed_at=$2
                  WHERE id=$1 AND consumed_at IS NULL",
                [capability_id.into(), authority_now.into()],
            ))
            .await
            .map_err(persistence)?;
        if consumed.rows_affected() != 1 {
            return Err(ApplicationError::InvalidTransition);
        }
        transaction
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "INSERT INTO audit_events
                    (id,project_id,actor_kind,action,target_kind,target_id,outcome,
                     correlation_id,safe_context,occurred_at)
                 VALUES ($1,$2,'deployment_operator','mcp.projection_policy.update.commit',
                         $3,$4,'succeeded',$5,$6,$7)",
                [
                    Uuid::new_v4().into(),
                    command.project_id.into(),
                    target_kind.into(),
                    target_id.into(),
                    correlation_id.into(),
                    serde_json::json!({
                        "capability_id": capability_id,
                        "tool": PROJECTION_POLICY_COMMIT_TOOL,
                    })
                    .into(),
                    authority_now.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        transaction.commit().await.map_err(persistence)?;
        Ok(policy)
    }
}

struct CommittedProjectionPolicy {
    policy: ProjectionPolicyRecord,
    target_kind: &'static str,
    target_id: Uuid,
    authority_now: OffsetDateTime,
}

async fn preview_policy_snapshot(
    transaction: &sea_orm::DatabaseTransaction,
    command: &ConfirmedProjectionPolicyUpdate,
) -> Result<ProjectionPolicyRecord, ApplicationError> {
    if let Some(application_id) = command.application_id {
        let application = application::Entity::find_by_id(application_id)
            .filter(application::Column::ProjectId.eq(command.project_id))
            .lock_shared()
            .one(transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if application.status != "active" {
            return Err(ApplicationError::Disabled);
        }
        if application.projection_revision != command.expected_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        reject_narrowing(
            application.projection_verified_email_enabled,
            command.verified_email_enabled,
        )?;
        Ok(application_policy_record(&application, None))
    } else {
        let policy = project_policy::Entity::find_by_id(command.project_id)
            .lock_shared()
            .one(transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        if policy.projection_revision != command.expected_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        reject_narrowing(
            policy.projection_verified_email_enabled,
            command.verified_email_enabled,
        )?;
        Ok(project_policy_record(&policy, None))
    }
}

async fn commit_confirmed_policy_update(
    transaction: &sea_orm::DatabaseTransaction,
    capability: &QueryResult,
    command: &ConfirmedProjectionPolicyUpdate,
    correlation_id: Uuid,
) -> Result<CommittedProjectionPolicy, ApplicationError> {
    if let Some(application_id) = command.application_id {
        commit_confirmed_application_policy(
            transaction,
            capability,
            command,
            application_id,
            correlation_id,
        )
        .await
    } else {
        commit_confirmed_project_policy(transaction, capability, command, correlation_id).await
    }
}

async fn commit_confirmed_application_policy(
    transaction: &sea_orm::DatabaseTransaction,
    capability: &QueryResult,
    command: &ConfirmedProjectionPolicyUpdate,
    application_id: Uuid,
    correlation_id: Uuid,
) -> Result<CommittedProjectionPolicy, ApplicationError> {
    let application = application::Entity::find_by_id(application_id)
        .filter(application::Column::ProjectId.eq(command.project_id))
        .lock_exclusive()
        .one(transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
    if application.status != "active" {
        return Err(ApplicationError::Disabled);
    }
    let authority_now = confirmation_authority_now(transaction, capability).await?;
    if application.projection_revision != command.expected_revision {
        return Err(ApplicationError::RevisionConflict);
    }
    reject_narrowing(
        application.projection_verified_email_enabled,
        command.verified_email_enabled,
    )?;
    if application.projection_verified_email_enabled == command.verified_email_enabled {
        return Err(ApplicationError::InvalidTransition);
    }
    let revision = application
        .projection_revision
        .checked_add(1)
        .ok_or(ApplicationError::Integrity)?;
    let aggregate_revision = application
        .revision
        .checked_add(1)
        .ok_or(ApplicationError::Integrity)?;
    let mut active = application.into_active_model();
    active.projection_verified_email_enabled = Set(command.verified_email_enabled);
    active.projection_revision = Set(revision);
    active.revision = Set(aggregate_revision);
    active.updated_at = Set(authority_now);
    let application = active.update(transaction).await.map_err(persistence)?;
    let operation_id = Uuid::new_v4();
    insert_operation(
        transaction,
        operation_id,
        command.project_id,
        Some(application_id),
        "application",
        revision,
        authority_now,
    )
    .await?;
    append_runtime_audit(
        transaction,
        command.project_id,
        "deployment_operator",
        "projection.policy.expand.application",
        "application",
        Some(application_id),
        correlation_id,
    )
    .await?;
    let policy = application_policy_record(&application, Some(operation_id));
    Ok(CommittedProjectionPolicy {
        policy,
        target_kind: "application",
        target_id: application_id,
        authority_now,
    })
}

async fn commit_confirmed_project_policy(
    transaction: &sea_orm::DatabaseTransaction,
    capability: &QueryResult,
    command: &ConfirmedProjectionPolicyUpdate,
    correlation_id: Uuid,
) -> Result<CommittedProjectionPolicy, ApplicationError> {
    let policy = project_policy::Entity::find_by_id(command.project_id)
        .lock_exclusive()
        .one(transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?;
    let authority_now = confirmation_authority_now(transaction, capability).await?;
    if policy.projection_revision != command.expected_revision {
        return Err(ApplicationError::RevisionConflict);
    }
    reject_narrowing(
        policy.projection_verified_email_enabled,
        command.verified_email_enabled,
    )?;
    if policy.projection_verified_email_enabled == command.verified_email_enabled {
        return Err(ApplicationError::InvalidTransition);
    }
    let revision = policy
        .projection_revision
        .checked_add(1)
        .ok_or(ApplicationError::Integrity)?;
    let mut active = policy.into_active_model();
    active.projection_verified_email_enabled = Set(command.verified_email_enabled);
    active.projection_revision = Set(revision);
    let policy = active.update(transaction).await.map_err(persistence)?;
    let operation_id = Uuid::new_v4();
    insert_operation(
        transaction,
        operation_id,
        command.project_id,
        None,
        "project",
        revision,
        authority_now,
    )
    .await?;
    append_runtime_audit(
        transaction,
        command.project_id,
        "deployment_operator",
        "projection.policy.expand.project",
        "project_policy",
        Some(command.project_id),
        correlation_id,
    )
    .await?;
    let policy = project_policy_record(&policy, Some(operation_id));
    Ok(CommittedProjectionPolicy {
        policy,
        target_kind: "project_policy",
        target_id: command.project_id,
        authority_now,
    })
}

async fn confirmation_authority_now(
    transaction: &sea_orm::DatabaseTransaction,
    capability: &QueryResult,
) -> Result<OffsetDateTime, ApplicationError> {
    let authority_now = transaction
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT clock_timestamp() AS authority_now".to_owned(),
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Persistence)?
        .try_get("", "authority_now")
        .map_err(persistence)?;
    let expires_at: OffsetDateTime = capability.try_get("", "expires_at").map_err(persistence)?;
    let consumed_at: Option<OffsetDateTime> =
        capability.try_get("", "consumed_at").map_err(persistence)?;
    if consumed_at.is_some() || authority_now >= expires_at {
        return Err(ApplicationError::InvalidTransition);
    }
    Ok(authority_now)
}

async fn admit_confirmation_capacity(
    transaction: &sea_orm::DatabaseTransaction,
) -> Result<(), ApplicationError> {
    transaction
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT pg_advisory_xact_lock($1)",
            [MCP_CONFIRMATION_ADVISORY_LOCK.into()],
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Persistence)?;
    transaction
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "DELETE FROM mcp_confirmation_capabilities
              WHERE id IN (
                    SELECT id
                      FROM mcp_confirmation_capabilities
                     WHERE expires_at <= clock_timestamp()
                     ORDER BY expires_at,id
                     FOR UPDATE SKIP LOCKED
                     LIMIT $1
              )",
            [MCP_CONFIRMATION_CLEANUP_BATCH_SIZE.into()],
        ))
        .await
        .map_err(persistence)?;
    let retained: i64 = transaction
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT count(*)::bigint AS retained FROM mcp_confirmation_capabilities".to_owned(),
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Persistence)?
        .try_get("", "retained")
        .map_err(persistence)?;
    if retained >= MAX_MCP_CONFIRMATION_ROWS {
        return Err(ApplicationError::OperationInProgress);
    }
    Ok(())
}

fn validate_confirmation_binding(
    capability: &QueryResult,
    context: &McpConfirmationContext,
    command: &ConfirmedProjectionPolicyUpdate,
    command_digest: &[u8],
) -> Result<(), ApplicationError> {
    let actor_kind: String = capability.try_get("", "actor_kind").map_err(persistence)?;
    let audience: String = capability.try_get("", "audience").map_err(persistence)?;
    let instance_id: String = capability.try_get("", "instance_id").map_err(persistence)?;
    let control_endpoint: String = capability
        .try_get("", "control_endpoint")
        .map_err(persistence)?;
    let tool_name: String = capability.try_get("", "tool_name").map_err(persistence)?;
    let stored_command_digest: Vec<u8> = capability
        .try_get("", "command_digest")
        .map_err(persistence)?;
    let project_id: Uuid = capability.try_get("", "project_id").map_err(persistence)?;
    let application_id: Option<Uuid> = capability
        .try_get("", "application_id")
        .map_err(persistence)?;
    let target_revision: i64 = capability
        .try_get("", "target_revision")
        .map_err(persistence)?;
    if actor_kind != "deployment_operator"
        || audience != "control_mcp"
        || instance_id != context.instance_id
        || control_endpoint != context.control_endpoint
        || tool_name != PROJECTION_POLICY_COMMIT_TOOL
        || stored_command_digest != command_digest
        || project_id != command.project_id
        || application_id != command.application_id
        || target_revision != command.expected_revision
    {
        return Err(ApplicationError::InvalidTransition);
    }
    Ok(())
}

#[async_trait]
impl ProjectionExpansionRepository for PostgresProjectionExpansionRepository {
    async fn process_one_batch(
        &self,
        worker_id: &str,
        worker_incarnation: Uuid,
        now: OffsetDateTime,
        lease_duration: Duration,
        batch_size: usize,
    ) -> Result<bool, ApplicationError> {
        if batch_size == 0 || batch_size > 64 {
            return Err(ApplicationError::InvalidInput);
        }
        let Some((operation_id, project_id, lease_generation)) = self
            .claim_operation(worker_id, worker_incarnation, now, lease_duration)
            .await?
        else {
            return Ok(false);
        };
        let transaction = self.database.begin().await.map_err(persistence)?;
        lock_active_project(&transaction, project_id).await?;
        let operation = projection_expansion_operation::Entity::find_by_id(operation_id)
            .filter(projection_expansion_operation::Column::ProjectId.eq(project_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        if operation.status != "running"
            || operation.lease_owner.as_deref() != Some(worker_id)
            || operation.lease_incarnation != Some(worker_incarnation)
            || operation.lease_generation != lease_generation
        {
            return Err(ApplicationError::RevisionConflict);
        }
        let mut query = application_user_binding::Entity::find()
            .filter(application_user_binding::Column::ProjectId.eq(operation.project_id))
            .filter(application_user_binding::Column::Status.eq("active"));
        if let Some(application_id) = operation.application_id {
            query =
                query.filter(application_user_binding::Column::ApplicationId.eq(application_id));
        }
        if let Some(cursor) = operation.cursor_binding_id {
            query = query.filter(application_user_binding::Column::Id.gt(cursor));
        }
        let bindings = query
            .order_by_asc(application_user_binding::Column::Id)
            .limit(batch_size as u64)
            .all(&transaction)
            .await
            .map_err(persistence)?;
        let convergence = async {
            for binding in &bindings {
                let application = application::Entity::find_by_id(binding.application_id)
                    .filter(application::Column::ProjectId.eq(operation.project_id))
                    .one(&transaction)
                    .await
                    .map_err(persistence)?
                    .ok_or(ApplicationError::Integrity)?;
                if application.status == "active" {
                    self.materializer
                        .converge_binding(&transaction, binding.id, now)
                        .await?;
                }
            }
            Ok::<(), ApplicationError>(())
        }
        .await;
        if let Err(error) = convergence {
            let mut active = operation.into_active_model();
            active.status = Set("failed".to_owned());
            active.lease_owner = Set(None);
            active.lease_incarnation = Set(None);
            active.lease_expires_at = Set(None);
            active.last_error_class = Set(Some(application_error_class(error).to_owned()));
            active.updated_at = Set(now);
            active.update(&transaction).await.map_err(persistence)?;
            transaction.commit().await.map_err(persistence)?;
            return Err(error);
        }
        let completed = bindings.len() < batch_size;
        let processed = i64::try_from(bindings.len()).map_err(|_| ApplicationError::Integrity)?;
        let cursor_binding_id = bindings
            .last()
            .map(|binding| binding.id)
            .or(operation.cursor_binding_id);
        let processed_count = operation
            .processed_count
            .checked_add(processed)
            .ok_or(ApplicationError::Integrity)?;
        let mut active = operation.into_active_model();
        active.cursor_binding_id = Set(cursor_binding_id);
        active.processed_count = Set(processed_count);
        active.status = Set(if completed { "completed" } else { "pending" }.to_owned());
        active.lease_owner = Set(None);
        active.lease_incarnation = Set(None);
        active.lease_expires_at = Set(None);
        active.updated_at = Set(now);
        active.completed_at = Set(completed.then_some(now));
        active.last_error_class = Set(None);
        active.update(&transaction).await.map_err(persistence)?;
        transaction.commit().await.map_err(persistence)?;
        Ok(true)
    }
}

async fn lock_active_project<C: ConnectionTrait>(
    connection: &C,
    project_id: Uuid,
) -> Result<project::Model, ApplicationError> {
    let project = project::Entity::find_by_id(project_id)
        .lock_shared()
        .one(connection)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
    if project.status != "active" {
        return Err(ApplicationError::Disabled);
    }
    Ok(project)
}

async fn insert_operation(
    transaction: &sea_orm::DatabaseTransaction,
    operation_id: Uuid,
    project_id: Uuid,
    application_id: Option<Uuid>,
    scope_kind: &str,
    target_policy_revision: i64,
    now: OffsetDateTime,
) -> Result<(), ApplicationError> {
    projection_expansion_operation::ActiveModel {
        id: Set(operation_id),
        project_id: Set(project_id),
        application_id: Set(application_id),
        scope_kind: Set(scope_kind.to_owned()),
        target_policy_revision: Set(target_policy_revision),
        status: Set("pending".to_owned()),
        cursor_binding_id: Set(None),
        processed_count: Set(0),
        lease_owner: Set(None),
        lease_incarnation: Set(None),
        lease_generation: Set(0),
        lease_expires_at: Set(None),
        last_error_class: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
        completed_at: Set(None),
    }
    .insert(transaction)
    .await
    .map_err(persistence)?;
    Ok(())
}

fn application_error_class(error: ApplicationError) -> &'static str {
    match error {
        ApplicationError::Persistence => "persistence",
        ApplicationError::Integrity => "integrity",
        ApplicationError::RevisionConflict => "revision_conflict",
        ApplicationError::Disabled => "disabled",
        ApplicationError::NotFound => "not_found",
        ApplicationError::InvalidInput
        | ApplicationError::InvalidTransition
        | ApplicationError::IdempotencyConflict
        | ApplicationError::OperationInProgress => "invalid_state",
        ApplicationError::PublicationPending => "publication_pending",
        ApplicationError::ClientVerifierUnavailable => "client_verifier_unavailable",
        ApplicationError::ProviderPreflightRejected => "provider_preflight_rejected",
        ApplicationError::ProviderPreflightUnavailable => "provider_preflight_unavailable",
        ApplicationError::ExternalStore => "external_store",
    }
}

fn reject_narrowing(current: bool, requested: bool) -> Result<(), ApplicationError> {
    if current && !requested {
        return Err(ApplicationError::InvalidTransition);
    }
    Ok(())
}

fn project_policy_record(
    policy: &project_policy::Model,
    expansion_operation_id: Option<Uuid>,
) -> ProjectionPolicyRecord {
    ProjectionPolicyRecord {
        project_id: policy.project_id,
        application_id: None,
        verified_email_enabled: policy.projection_verified_email_enabled,
        revision: policy.projection_revision,
        expansion_operation_id,
    }
}

fn application_policy_record(
    application: &application::Model,
    expansion_operation_id: Option<Uuid>,
) -> ProjectionPolicyRecord {
    ProjectionPolicyRecord {
        project_id: application.project_id,
        application_id: Some(application.id),
        verified_email_enabled: application.projection_verified_email_enabled,
        revision: application.projection_revision,
        expansion_operation_id,
    }
}
