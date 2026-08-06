use std::{collections::BTreeSet, fmt::Write as _};

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
    AcknowledgeProjectClientKeyDelivery, ApplicationError, ClientKeyCreateAttemptError,
    ClientKeyLifecyclePort, MAX_ACTIVE_CLIENT_KEYS_PER_PROJECT, PreparedProjectClientKey,
    ProjectClientKeyCursor, ProjectClientKeyRecord, ProjectClientKeyStatus, RevokeProjectClientKey,
    StoredProjectClientKeyCreate,
};

use super::entity::{audit_event, control_idempotency_record, project, project_client_key};

const CREATE_OPERATION_KIND: &str = "project_client_key.create";
const ACKNOWLEDGE_OPERATION_KIND: &str = "project_client_key.acknowledge_delivery";
const REVOKE_OPERATION_KIND: &str = "project_client_key.revoke";

#[derive(Clone)]
pub(crate) struct PostgresClientKeyRepository {
    database: DatabaseConnection,
    required_client_process_ids: Vec<String>,
}

impl PostgresClientKeyRepository {
    pub(crate) fn new(
        database: DatabaseConnection,
        required_client_process_ids: Vec<String>,
    ) -> Result<Self, ApplicationError> {
        let unique = required_client_process_ids.iter().collect::<BTreeSet<_>>();
        if required_client_process_ids.is_empty()
            || required_client_process_ids.len() > 64
            || unique.len() != required_client_process_ids.len()
            || required_client_process_ids
                .iter()
                .any(|process_id| !valid_process_id(process_id))
        {
            return Err(ApplicationError::InvalidInput);
        }
        let mut required_client_process_ids = required_client_process_ids;
        required_client_process_ids.sort_unstable();
        Ok(Self {
            database,
            required_client_process_ids,
        })
    }

    async fn digest_version_ready(
        &self,
        transaction: &DatabaseTransaction,
        digest_key_version: i32,
    ) -> Result<bool, ApplicationError> {
        if digest_key_version <= 0 {
            return Err(ApplicationError::InvalidInput);
        }
        // Lock both the authoritative incarnation and its exact readiness observation until the
        // key transaction commits. A concurrent process claim or renewal therefore cannot replace
        // the evidence after this verifier-first check but before the new key becomes visible.
        let roster = transaction
            .query_all_raw(Statement::from_sql_and_values(
                transaction.get_database_backend(),
                "SELECT current.process_id
                   FROM client_process_incarnations current
                   JOIN client_key_digest_readiness readiness
                     ON readiness.process_id=current.process_id
                    AND readiness.process_incarnation=current.process_incarnation
                  WHERE current.process_id IN (
                        SELECT jsonb_array_elements_text($1::jsonb))
                  ORDER BY current.process_id
                  FOR SHARE OF current,readiness",
                [json!(&self.required_client_process_ids).into()],
            ))
            .await
            .map_err(persistence)?;
        if roster.len() != self.required_client_process_ids.len() {
            return Ok(false);
        }
        for (row, expected_process_id) in roster.iter().zip(&self.required_client_process_ids) {
            let process_id = row
                .try_get::<String>("", "process_id")
                .map_err(persistence)?;
            if process_id != *expected_process_id {
                return Ok(false);
            }
        }

        // PostgreSQL may evaluate SELECT expressions before waiting for a trailing FOR SHARE lock.
        // Evaluate lease wall time only after the first statement has acquired every parent/child
        // lock, otherwise a lease that expires during the lock wait can be accepted from a stale
        // pre-wait clock_timestamp() result.
        let rows = transaction
            .query_all_raw(Statement::from_sql_and_values(
                transaction.get_database_backend(),
                "SELECT current.process_id,
                        readiness.state='ready'
                          AND readiness.failure_class IS NULL
                          AND readiness.lease_expires_at > clock_timestamp()
                          AND $2 = ANY(readiness.supported_digest_versions) AS ready
                   FROM client_process_incarnations current
                   JOIN client_key_digest_readiness readiness
                     ON readiness.process_id=current.process_id
                    AND readiness.process_incarnation=current.process_incarnation
                  WHERE current.process_id IN (
                        SELECT jsonb_array_elements_text($1::jsonb))
                  ORDER BY current.process_id",
                [
                    json!(&self.required_client_process_ids).into(),
                    digest_key_version.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        if rows.len() != self.required_client_process_ids.len() {
            return Err(ApplicationError::Integrity);
        }
        for (row, expected_process_id) in rows.iter().zip(&self.required_client_process_ids) {
            let process_id = row
                .try_get::<String>("", "process_id")
                .map_err(persistence)?;
            let ready = row.try_get::<bool>("", "ready").map_err(persistence)?;
            if process_id != *expected_process_id {
                return Err(ApplicationError::Integrity);
            }
            if !ready {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the lifecycle port keeps each transaction boundary and secret-free replay visible"
)]
#[async_trait]
impl ClientKeyLifecyclePort for PostgresClientKeyRepository {
    async fn list_project_client_keys(
        &self,
        project_id: Uuid,
        after: Option<ProjectClientKeyCursor>,
        limit_plus_one: usize,
    ) -> Result<Vec<ProjectClientKeyRecord>, ApplicationError> {
        if !(2..=101).contains(&limit_plus_one) {
            return Err(ApplicationError::InvalidInput);
        }
        ensure_project(&self.database, project_id).await?;
        let mut query = project_client_key::Entity::find()
            .filter(project_client_key::Column::ProjectId.eq(project_id));
        if let Some(after) = after {
            query = query.filter(
                Condition::any()
                    .add(project_client_key::Column::CreatedAt.gt(after.created_at))
                    .add(
                        Condition::all()
                            .add(project_client_key::Column::CreatedAt.eq(after.created_at))
                            .add(project_client_key::Column::Id.gt(after.key_id)),
                    ),
            );
        }
        query
            .order_by_asc(project_client_key::Column::CreatedAt)
            .order_by_asc(project_client_key::Column::Id)
            .limit(u64::try_from(limit_plus_one).map_err(|_| ApplicationError::InvalidInput)?)
            .all(&self.database)
            .await
            .map_err(persistence)?
            .into_iter()
            .map(client_key_record)
            .collect()
    }

    async fn active_unacknowledged_project_client_key(
        &self,
        project_id: Uuid,
    ) -> Result<Option<ProjectClientKeyRecord>, ApplicationError> {
        ensure_project(&self.database, project_id).await?;
        project_client_key::Entity::find()
            .filter(project_client_key::Column::ProjectId.eq(project_id))
            .filter(project_client_key::Column::Status.eq("active"))
            .filter(project_client_key::Column::CredentialAcknowledgedAt.is_null())
            .one(&self.database)
            .await
            .map_err(persistence)?
            .map(client_key_record)
            .transpose()
    }

    async fn get_project_client_key(
        &self,
        project_id: Uuid,
        key_id: Uuid,
    ) -> Result<ProjectClientKeyRecord, ApplicationError> {
        project_client_key::Entity::find_by_id(key_id)
            .filter(project_client_key::Column::ProjectId.eq(project_id))
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)
            .and_then(client_key_record)
    }

    async fn replay_project_client_key_create(
        &self,
        project_id: Uuid,
        idempotency_key: &str,
        request_digest: &[u8],
    ) -> Result<Option<ProjectClientKeyRecord>, ApplicationError> {
        if request_digest.len() != 32 {
            return Err(ApplicationError::InvalidInput);
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        lock_advisory(&transaction, idempotency_key).await?;
        let result = replay::<ProjectClientKeyRecord>(
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

    async fn create_project_client_key_attempt(
        &self,
        prepared: PreparedProjectClientKey,
    ) -> Result<StoredProjectClientKeyCreate, ClientKeyCreateAttemptError> {
        if prepared.request_digest.len() != 32 || prepared.digest_key_version <= 0 {
            return Err(ApplicationError::InvalidInput.into());
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        lock_advisory(&transaction, &prepared.idempotency_key).await?;
        if let Some(replayed) = replay::<ProjectClientKeyRecord>(
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
            return Ok(StoredProjectClientKeyCreate::ReplayWithoutSecret(replayed));
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
        if project_client_key::Entity::find()
            .filter(project_client_key::Column::ProjectId.eq(prepared.project_id))
            .filter(project_client_key::Column::Status.eq("active"))
            .filter(project_client_key::Column::CredentialAcknowledgedAt.is_null())
            .one(&transaction)
            .await
            .map_err(persistence)?
            .is_some()
        {
            return Err(ApplicationError::InvalidTransition.into());
        }
        if !self
            .digest_version_ready(&transaction, prepared.digest_key_version)
            .await?
        {
            return Err(ApplicationError::ClientVerifierUnavailable.into());
        }
        let active_count = project_client_key::Entity::find()
            .filter(project_client_key::Column::ProjectId.eq(prepared.project_id))
            .filter(project_client_key::Column::Status.eq("active"))
            .count(&transaction)
            .await
            .map_err(persistence)?;
        if active_count
            >= u64::try_from(MAX_ACTIVE_CLIENT_KEYS_PER_PROJECT)
                .map_err(|_| ApplicationError::Integrity)?
        {
            return Err(ApplicationError::InvalidTransition.into());
        }

        lock_advisory(
            &transaction,
            &format!("project-client-key-public-id:{}", prepared.public_key_id),
        )
        .await?;
        if project_client_key::Entity::find()
            .filter(project_client_key::Column::PublicKeyId.eq(prepared.public_key_id.clone()))
            .one(&transaction)
            .await
            .map_err(persistence)?
            .is_some()
        {
            transaction.rollback().await.map_err(persistence)?;
            return Err(ClientKeyCreateAttemptError::PublicIdCollision);
        }

        let model = project_client_key::ActiveModel {
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
        let record = client_key_record(model)?;
        insert_client_key_audit(
            &transaction,
            &record,
            "project_client_key.created",
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
        Ok(StoredProjectClientKeyCreate::Created(record))
    }

    async fn acknowledge_project_client_key_delivery(
        &self,
        command: AcknowledgeProjectClientKeyDelivery,
        request_digest: Vec<u8>,
        acknowledged_at: OffsetDateTime,
    ) -> Result<ProjectClientKeyRecord, ApplicationError> {
        if request_digest.len() != 32 {
            return Err(ApplicationError::InvalidInput);
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        lock_advisory(&transaction, &command.idempotency_key).await?;
        if let Some(replayed) = replay::<ProjectClientKeyRecord>(
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
                || replayed.status != ProjectClientKeyStatus::Active
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
        let model = project_client_key::Entity::find_by_id(command.key_id)
            .filter(project_client_key::Column::ProjectId.eq(command.project_id))
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
        let record = client_key_record(active.update(&transaction).await.map_err(persistence)?)?;
        insert_client_key_audit(
            &transaction,
            &record,
            "project_client_key.delivery_acknowledged",
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

    async fn revoke_project_client_key(
        &self,
        command: RevokeProjectClientKey,
        request_digest: Vec<u8>,
        revoked_at: OffsetDateTime,
    ) -> Result<ProjectClientKeyRecord, ApplicationError> {
        if request_digest.len() != 32 {
            return Err(ApplicationError::InvalidInput);
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        lock_advisory(&transaction, &command.idempotency_key).await?;
        if let Some(replayed) = replay::<ProjectClientKeyRecord>(
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
                || replayed.status != ProjectClientKeyStatus::Revoked
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
        let model = project_client_key::Entity::find_by_id(command.key_id)
            .filter(project_client_key::Column::ProjectId.eq(command.project_id))
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
        let record = client_key_record(active.update(&transaction).await.map_err(persistence)?)?;
        insert_client_key_audit(
            &transaction,
            &record,
            "project_client_key.revoked",
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

fn client_key_record(
    model: project_client_key::Model,
) -> Result<ProjectClientKeyRecord, ApplicationError> {
    let status = match model.status.as_str() {
        "active" if model.revoked_at.is_none() => ProjectClientKeyStatus::Active,
        "revoked" if model.revoked_at.is_some() => ProjectClientKeyStatus::Revoked,
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
    Ok(ProjectClientKeyRecord {
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

async fn insert_client_key_audit(
    transaction: &DatabaseTransaction,
    record: &ProjectClientKeyRecord,
    action: &str,
    correlation_id: Uuid,
    idempotency_key: &str,
) -> Result<(), ApplicationError> {
    audit_event::ActiveModel {
        id: Set(Uuid::new_v4()),
        project_id: Set(Some(record.project_id)),
        actor_kind: Set("deployment_operator".to_owned()),
        action: Set(action.to_owned()),
        target_kind: Set("project_client_key".to_owned()),
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

fn valid_process_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn persistence(_: sea_orm::DbErr) -> ApplicationError {
    ApplicationError::Persistence
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model() -> project_client_key::Model {
        let public_key_id = "AAAAAAAAAAAAAAAAAAAAAA".to_owned();
        project_client_key::Model {
            id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            public_key_id: public_key_id.clone(),
            label: "backend".to_owned(),
            status: "active".to_owned(),
            digest_key_version: 1,
            credential_digest: vec![7_u8; 32],
            display_prefix: format!("owl_client_v1.{public_key_id}"),
            revision: 1,
            created_at: OffsetDateTime::UNIX_EPOCH,
            credential_acknowledged_at: None,
            last_used_at: None,
            revoked_at: None,
        }
    }

    #[test]
    fn required_client_roster_is_non_empty_unique_and_canonical() {
        assert!(
            PostgresClientKeyRepository::new(
                DatabaseConnection::default(),
                vec!["client-1".to_owned(), "region.example:2".to_owned()],
            )
            .is_ok()
        );
        for invalid in [
            Vec::new(),
            vec!["client-1".to_owned(), "client-1".to_owned()],
            vec!["contains space".to_owned()],
            vec!["x".repeat(129)],
        ] {
            assert_eq!(
                PostgresClientKeyRepository::new(DatabaseConnection::default(), invalid).err(),
                Some(ApplicationError::InvalidInput)
            );
        }
    }

    #[test]
    fn row_mapping_rejects_incoherent_or_secret_length_state() {
        let record = client_key_record(model()).expect("valid active record");
        assert_eq!(record.status, ProjectClientKeyStatus::Active);

        let mut invalid = model();
        invalid.credential_digest.pop();
        assert_eq!(client_key_record(invalid), Err(ApplicationError::Integrity));

        let mut invalid = model();
        invalid.status = "revoked".to_owned();
        assert_eq!(client_key_record(invalid), Err(ApplicationError::Integrity));

        let mut invalid = model();
        invalid.credential_acknowledged_at =
            Some(OffsetDateTime::UNIX_EPOCH - time::Duration::SECOND);
        assert_eq!(client_key_record(invalid), Err(ApplicationError::Integrity));
    }

    #[test]
    fn audit_idempotency_fingerprint_is_bounded_and_not_plaintext() {
        let plaintext = b"client-key-create-sensitive-label";
        let fingerprint = hex_digest(plaintext);
        assert_eq!(fingerprint.len(), 64);
        assert!(!fingerprint.contains("sensitive"));
        assert_eq!(fingerprint, hex_digest(plaintext));
    }
}
