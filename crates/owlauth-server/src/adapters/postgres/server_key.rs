use std::fmt::Write as _;

use async_trait::async_trait;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, ConnectionTrait, DatabaseConnection,
    DatabaseTransaction, EntityTrait, IntoActiveModel, PaginatorTrait, QueryFilter, QueryOrder,
    QuerySelect, Set, Statement, TransactionTrait,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::application::{
    AcknowledgeProjectServerKeyDelivery, ApplicationError, MAX_ACTIVE_SERVER_KEYS_PER_PROJECT,
    PreparedProjectServerKey, ProjectServerKeyCursor, ProjectServerKeyRecord,
    ProjectServerKeyStatus, RevokeProjectServerKey, ServerKeyCreateAttemptError,
    ServerKeyLifecyclePort, StoredProjectServerKeyCreate,
};

use super::entity::{audit_event, control_idempotency_record, project, project_server_key};

const CREATE_OPERATION_KIND: &str = "project_server_key.create";
const ACKNOWLEDGE_OPERATION_KIND: &str = "project_server_key.acknowledge_delivery";
const REVOKE_OPERATION_KIND: &str = "project_server_key.revoke";

#[derive(Clone)]
pub(crate) struct PostgresServerKeyRepository {
    database: DatabaseConnection,
}

impl PostgresServerKeyRepository {
    pub(crate) fn new(database: DatabaseConnection) -> Self {
        Self { database }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the lifecycle port keeps each transaction boundary and secret-free replay visible"
)]
#[async_trait]
impl ServerKeyLifecyclePort for PostgresServerKeyRepository {
    async fn list_project_server_keys(
        &self,
        project_id: Uuid,
        after: Option<ProjectServerKeyCursor>,
        limit_plus_one: usize,
    ) -> Result<Vec<ProjectServerKeyRecord>, ApplicationError> {
        if !(2..=101).contains(&limit_plus_one) {
            return Err(ApplicationError::InvalidInput);
        }
        ensure_project(&self.database, project_id).await?;
        let mut query = project_server_key::Entity::find()
            .filter(project_server_key::Column::ProjectId.eq(project_id));
        if let Some(after) = after {
            query = query.filter(
                Condition::any()
                    .add(project_server_key::Column::CreatedAt.gt(after.created_at))
                    .add(
                        Condition::all()
                            .add(project_server_key::Column::CreatedAt.eq(after.created_at))
                            .add(project_server_key::Column::Id.gt(after.key_id)),
                    ),
            );
        }
        query
            .order_by_asc(project_server_key::Column::CreatedAt)
            .order_by_asc(project_server_key::Column::Id)
            .limit(u64::try_from(limit_plus_one).map_err(|_| ApplicationError::InvalidInput)?)
            .all(&self.database)
            .await
            .map_err(persistence)?
            .into_iter()
            .map(server_key_record)
            .collect()
    }

    async fn active_unacknowledged_project_server_key(
        &self,
        project_id: Uuid,
    ) -> Result<Option<ProjectServerKeyRecord>, ApplicationError> {
        ensure_project(&self.database, project_id).await?;
        project_server_key::Entity::find()
            .filter(project_server_key::Column::ProjectId.eq(project_id))
            .filter(project_server_key::Column::Status.eq("active"))
            .filter(project_server_key::Column::CredentialAcknowledgedAt.is_null())
            .one(&self.database)
            .await
            .map_err(persistence)?
            .map(server_key_record)
            .transpose()
    }

    async fn get_project_server_key(
        &self,
        project_id: Uuid,
        key_id: Uuid,
    ) -> Result<ProjectServerKeyRecord, ApplicationError> {
        project_server_key::Entity::find_by_id(key_id)
            .filter(project_server_key::Column::ProjectId.eq(project_id))
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)
            .and_then(server_key_record)
    }

    async fn replay_project_server_key_create(
        &self,
        project_id: Uuid,
        idempotency_key: &str,
        request_digest: &[u8],
    ) -> Result<Option<ProjectServerKeyRecord>, ApplicationError> {
        if request_digest.len() != 32 {
            return Err(ApplicationError::InvalidInput);
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        lock_advisory(&transaction, idempotency_key).await?;
        let result = replay::<ProjectServerKeyRecord>(
            &transaction,
            idempotency_key,
            project_id,
            CREATE_OPERATION_KIND,
            &project_id.to_string(),
            request_digest,
        )
        .await?;
        if result
            .as_ref()
            .is_some_and(|record| record.project_id != project_id)
        {
            return Err(ApplicationError::Integrity);
        }
        transaction.commit().await.map_err(persistence)?;
        Ok(result)
    }

    async fn create_project_server_key_attempt(
        &self,
        prepared: PreparedProjectServerKey,
    ) -> Result<StoredProjectServerKeyCreate, ServerKeyCreateAttemptError> {
        if prepared.request_digest.len() != 32 || prepared.digest_key_version <= 0 {
            return Err(ApplicationError::InvalidInput.into());
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        lock_advisory(&transaction, &prepared.idempotency_key).await?;
        if let Some(replayed) = replay::<ProjectServerKeyRecord>(
            &transaction,
            &prepared.idempotency_key,
            prepared.project_id,
            CREATE_OPERATION_KIND,
            &prepared.project_id.to_string(),
            &prepared.request_digest,
        )
        .await?
        {
            if replayed.project_id != prepared.project_id {
                return Err(ApplicationError::Integrity.into());
            }
            transaction.commit().await.map_err(persistence)?;
            return Ok(StoredProjectServerKeyCreate::ReplayWithoutSecret(replayed));
        }

        let owner = project::Entity::find_by_id(prepared.project_id)
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if owner.status != "active" {
            return Err(ApplicationError::Disabled.into());
        }
        if project_server_key::Entity::find()
            .filter(project_server_key::Column::ProjectId.eq(prepared.project_id))
            .filter(project_server_key::Column::Status.eq("active"))
            .filter(project_server_key::Column::CredentialAcknowledgedAt.is_null())
            .one(&transaction)
            .await
            .map_err(persistence)?
            .is_some()
        {
            return Err(ApplicationError::InvalidTransition.into());
        }
        let active_count = project_server_key::Entity::find()
            .filter(project_server_key::Column::ProjectId.eq(prepared.project_id))
            .filter(project_server_key::Column::Status.eq("active"))
            .count(&transaction)
            .await
            .map_err(persistence)?;
        if active_count
            >= u64::try_from(MAX_ACTIVE_SERVER_KEYS_PER_PROJECT)
                .map_err(|_| ApplicationError::Integrity)?
        {
            return Err(ApplicationError::CapacityExceeded.into());
        }

        lock_advisory(
            &transaction,
            &format!("project-server-key-public-id:{}", prepared.public_key_id),
        )
        .await?;
        if project_server_key::Entity::find()
            .filter(project_server_key::Column::PublicKeyId.eq(prepared.public_key_id.clone()))
            .one(&transaction)
            .await
            .map_err(persistence)?
            .is_some()
        {
            transaction.rollback().await.map_err(persistence)?;
            return Err(ServerKeyCreateAttemptError::PublicIdCollision);
        }

        let model = project_server_key::ActiveModel {
            id: Set(prepared.id),
            project_id: Set(prepared.project_id),
            public_key_id: Set(prepared.public_key_id),
            label: Set(prepared.label),
            status: Set("active".to_owned()),
            digest_key_version: Set(prepared.digest_key_version),
            credential_digest: Set(prepared.credential_digest.to_vec()),
            display_prefix: Set(prepared.display_prefix),
            revision: Set(1),
            created_at: Set(prepared.created_at),
            credential_acknowledged_at: Set(None),
            last_used_at: Set(None),
            revoked_at: Set(None),
        }
        .insert(&transaction)
        .await
        .map_err(persistence)?;
        let record = server_key_record(model)?;
        insert_server_key_audit(
            &transaction,
            &record,
            "project_server_key.created",
            prepared.correlation_id,
            &prepared.idempotency_key,
        )
        .await?;
        complete_idempotency(
            &transaction,
            prepared.idempotency_key,
            prepared.project_id,
            prepared.id,
            CREATE_OPERATION_KIND,
            &prepared.project_id.to_string(),
            prepared.request_digest,
            &record,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(StoredProjectServerKeyCreate::Created(record))
    }

    async fn acknowledge_project_server_key_delivery(
        &self,
        command: AcknowledgeProjectServerKeyDelivery,
        request_digest: Vec<u8>,
        acknowledged_at: OffsetDateTime,
    ) -> Result<ProjectServerKeyRecord, ApplicationError> {
        if request_digest.len() != 32 {
            return Err(ApplicationError::InvalidInput);
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        lock_advisory(&transaction, &command.idempotency_key).await?;
        if let Some(replayed) = replay::<ProjectServerKeyRecord>(
            &transaction,
            &command.idempotency_key,
            command.project_id,
            ACKNOWLEDGE_OPERATION_KIND,
            &command.project_id.to_string(),
            &request_digest,
        )
        .await?
        {
            if replayed.project_id != command.project_id
                || replayed.id != command.key_id
                || replayed.status != ProjectServerKeyStatus::Active
                || replayed.credential_acknowledged_at.is_none()
            {
                return Err(ApplicationError::Integrity);
            }
            transaction.commit().await.map_err(persistence)?;
            return Ok(replayed);
        }
        project::Entity::find_by_id(command.project_id)
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let model = project_server_key::Entity::find_by_id(command.key_id)
            .filter(project_server_key::Column::ProjectId.eq(command.project_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if model.revision != command.expected_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        if model.status != "active"
            || model.revoked_at.is_some()
            || model.credential_acknowledged_at.is_some()
        {
            return Err(ApplicationError::InvalidTransition);
        }
        let next_revision = command
            .expected_revision
            .checked_add(1)
            .ok_or(ApplicationError::InvalidInput)?;
        let mut active = model.into_active_model();
        active.revision = Set(next_revision);
        active.credential_acknowledged_at = Set(Some(acknowledged_at));
        let record = server_key_record(active.update(&transaction).await.map_err(persistence)?)?;
        insert_server_key_audit(
            &transaction,
            &record,
            "project_server_key.delivery_acknowledged",
            command.correlation_id,
            &command.idempotency_key,
        )
        .await?;
        complete_idempotency(
            &transaction,
            command.idempotency_key,
            command.project_id,
            command.key_id,
            ACKNOWLEDGE_OPERATION_KIND,
            &command.project_id.to_string(),
            request_digest,
            &record,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(record)
    }

    async fn revoke_project_server_key(
        &self,
        command: RevokeProjectServerKey,
        request_digest: Vec<u8>,
        revoked_at: OffsetDateTime,
    ) -> Result<ProjectServerKeyRecord, ApplicationError> {
        if request_digest.len() != 32 {
            return Err(ApplicationError::InvalidInput);
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        lock_advisory(&transaction, &command.idempotency_key).await?;
        if let Some(replayed) = replay::<ProjectServerKeyRecord>(
            &transaction,
            &command.idempotency_key,
            command.project_id,
            REVOKE_OPERATION_KIND,
            &command.project_id.to_string(),
            &request_digest,
        )
        .await?
        {
            if replayed.project_id != command.project_id
                || replayed.id != command.key_id
                || replayed.status != ProjectServerKeyStatus::Revoked
            {
                return Err(ApplicationError::Integrity);
            }
            transaction.commit().await.map_err(persistence)?;
            return Ok(replayed);
        }
        project::Entity::find_by_id(command.project_id)
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let model = project_server_key::Entity::find_by_id(command.key_id)
            .filter(project_server_key::Column::ProjectId.eq(command.project_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if model.revision != command.expected_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        if model.status != "active" || model.revoked_at.is_some() {
            return Err(ApplicationError::InvalidTransition);
        }
        let next_revision = command
            .expected_revision
            .checked_add(1)
            .ok_or(ApplicationError::InvalidInput)?;
        let mut active = model.into_active_model();
        active.status = Set("revoked".to_owned());
        active.revision = Set(next_revision);
        active.revoked_at = Set(Some(revoked_at));
        let record = server_key_record(active.update(&transaction).await.map_err(persistence)?)?;
        insert_server_key_audit(
            &transaction,
            &record,
            "project_server_key.revoked",
            command.correlation_id,
            &command.idempotency_key,
        )
        .await?;
        complete_idempotency(
            &transaction,
            command.idempotency_key,
            command.project_id,
            command.key_id,
            REVOKE_OPERATION_KIND,
            &command.project_id.to_string(),
            request_digest,
            &record,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(record)
    }
}

async fn ensure_project<C>(database: &C, project_id: Uuid) -> Result<(), ApplicationError>
where
    C: ConnectionTrait,
{
    project::Entity::find_by_id(project_id)
        .one(database)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
    Ok(())
}

fn server_key_record(
    model: project_server_key::Model,
) -> Result<ProjectServerKeyRecord, ApplicationError> {
    let status = match model.status.as_str() {
        "active" if model.revoked_at.is_none() => ProjectServerKeyStatus::Active,
        "revoked" if model.revoked_at.is_some() => ProjectServerKeyStatus::Revoked,
        _ => return Err(ApplicationError::Integrity),
    };
    if model.revision <= 0
        || model.digest_key_version <= 0
        || model.credential_digest.len() != 32
        || model
            .credential_acknowledged_at
            .is_some_and(|acknowledged_at| acknowledged_at < model.created_at)
    {
        return Err(ApplicationError::Integrity);
    }
    Ok(ProjectServerKeyRecord {
        id: model.id,
        project_id: model.project_id,
        public_key_id: model.public_key_id,
        label: model.label,
        status,
        digest_key_version: model.digest_key_version,
        display_prefix: model.display_prefix,
        revision: model.revision,
        created_at: model.created_at,
        credential_acknowledged_at: model.credential_acknowledged_at,
        last_used_at: model.last_used_at,
        revoked_at: model.revoked_at,
    })
}

async fn lock_advisory(
    transaction: &DatabaseTransaction,
    namespace: &str,
) -> Result<(), ApplicationError> {
    transaction
        .execute_raw(Statement::from_sql_and_values(
            transaction.get_database_backend(),
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            [namespace.to_owned().into()],
        ))
        .await
        .map_err(persistence)?;
    Ok(())
}

async fn replay<T>(
    transaction: &DatabaseTransaction,
    idempotency_key: &str,
    project_id: Uuid,
    operation_kind: &str,
    scope: &str,
    request_digest: &[u8],
) -> Result<Option<T>, ApplicationError>
where
    T: DeserializeOwned,
{
    let Some(existing) = control_idempotency_record::Entity::find_by_id(idempotency_key)
        .one(transaction)
        .await
        .map_err(persistence)?
    else {
        return Ok(None);
    };
    if existing.project_id != Some(project_id)
        || existing.operation_kind != operation_kind
        || existing.request_scope != scope
        || existing.request_digest != request_digest
    {
        return Err(ApplicationError::IdempotencyConflict);
    }
    if existing.state != "completed" {
        return Err(ApplicationError::OperationInProgress);
    }
    serde_json::from_value(existing.response.ok_or(ApplicationError::Persistence)?)
        .map(Some)
        .map_err(|_| ApplicationError::Persistence)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the arguments are the complete metadata-only Control idempotency authority"
)]
async fn complete_idempotency<T>(
    transaction: &DatabaseTransaction,
    idempotency_key: String,
    project_id: Uuid,
    result_resource_id: Uuid,
    operation_kind: &str,
    scope: &str,
    request_digest: Vec<u8>,
    response: &T,
) -> Result<(), ApplicationError>
where
    T: Serialize,
{
    control_idempotency_record::ActiveModel {
        idempotency_key: Set(idempotency_key),
        project_id: Set(Some(project_id)),
        request_digest: Set(request_digest),
        state: Set("completed".to_owned()),
        result_resource_id: Set(Some(result_resource_id)),
        response: Set(Some(
            serde_json::to_value(response).map_err(|_| ApplicationError::Persistence)?,
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

async fn insert_server_key_audit(
    transaction: &DatabaseTransaction,
    record: &ProjectServerKeyRecord,
    action: &str,
    correlation_id: Uuid,
    idempotency_key: &str,
) -> Result<(), ApplicationError> {
    audit_event::ActiveModel {
        id: Set(Uuid::new_v4()),
        project_id: Set(Some(record.project_id)),
        actor_kind: Set("deployment_operator".to_owned()),
        action: Set(action.to_owned()),
        target_kind: Set("project_server_key".to_owned()),
        target_id: Set(Some(record.id)),
        outcome: Set("succeeded".to_owned()),
        correlation_id: Set(correlation_id),
        safe_context: Set(json!({
            "public_key_id": record.public_key_id,
            "display_prefix": record.display_prefix,
            "label": record.label,
            "revision": record.revision,
            "idempotency_fingerprint": hex_digest(idempotency_key.as_bytes()),
        })),
    }
    .insert(transaction)
    .await
    .map_err(persistence)?;
    Ok(())
}

fn hex_digest(value: &[u8]) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in Sha256::digest(value) {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

fn persistence(_: sea_orm::DbErr) -> ApplicationError {
    ApplicationError::Persistence
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model() -> project_server_key::Model {
        let public_key_id = "AAAAAAAAAAAAAAAAAAAAAA".to_owned();
        project_server_key::Model {
            id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            public_key_id: public_key_id.clone(),
            label: "backend".to_owned(),
            status: "active".to_owned(),
            digest_key_version: 1,
            credential_digest: vec![7_u8; 32],
            display_prefix: format!("owl_server_v1.{public_key_id}"),
            revision: 1,
            created_at: OffsetDateTime::UNIX_EPOCH,
            credential_acknowledged_at: None,
            last_used_at: None,
            revoked_at: None,
        }
    }

    #[test]
    fn row_mapping_rejects_incoherent_or_secret_length_state() {
        let record = server_key_record(model()).expect("valid active record");
        assert_eq!(record.status, ProjectServerKeyStatus::Active);

        let mut invalid = model();
        invalid.credential_digest.pop();
        assert_eq!(server_key_record(invalid), Err(ApplicationError::Integrity));

        let mut invalid = model();
        invalid.status = "revoked".to_owned();
        assert_eq!(server_key_record(invalid), Err(ApplicationError::Integrity));

        let mut invalid = model();
        invalid.credential_acknowledged_at =
            Some(OffsetDateTime::UNIX_EPOCH - time::Duration::SECOND);
        assert_eq!(server_key_record(invalid), Err(ApplicationError::Integrity));
    }

    #[test]
    fn audit_idempotency_fingerprint_is_bounded_and_not_plaintext() {
        let plaintext = b"server-key-create-sensitive-label";
        let fingerprint = hex_digest(plaintext);
        assert_eq!(fingerprint.len(), 64);
        assert!(!fingerprint.contains("sensitive"));
        assert_eq!(fingerprint, hex_digest(plaintext));
    }
}
