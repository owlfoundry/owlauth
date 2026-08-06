use std::sync::Arc;

use async_trait::async_trait;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, DbBackend, EntityTrait,
    IntoActiveModel, QueryFilter, QuerySelect, Set, Statement, TransactionTrait,
};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::application::{
    ApplicationError, BoundedManagedProfile, ClaimedManagedCredential, ConnectionGuard,
    ManagedConnectionMetadata, ManagedConnectionRepository, PreparedRenewal, ProtectedValue,
    RenewalOperationState, SuccessorProfileClaim,
};
use crate::domain::{
    ProfileDisplayName, ProfileLocale, ProfilePictureUrl, ProviderEgressPolicy, ProviderKind,
};

use super::{
    audit::append_runtime_audit, authentication::persistence, entity::project_user,
    projection::IdentityProjectionMaterializer, session_authority::base_profile_digest,
};

#[cfg(test)]
use super::session_authority::fan_out_user_projections;

#[derive(Clone)]
pub(crate) struct PostgresManagedConnectionRepository {
    database: DatabaseConnection,
    projection_materializer: Option<Arc<dyn IdentityProjectionMaterializer>>,
}

impl PostgresManagedConnectionRepository {
    #[cfg(test)]
    pub(crate) fn new(database: DatabaseConnection) -> Self {
        Self {
            database,
            projection_materializer: None,
        }
    }

    pub(crate) fn new_with_projection_materializer(
        database: DatabaseConnection,
        projection_materializer: Arc<dyn IdentityProjectionMaterializer>,
    ) -> Self {
        Self {
            database,
            projection_materializer: Some(projection_materializer),
        }
    }
}

#[async_trait]
#[allow(
    clippy::too_many_lines,
    reason = "generation-fenced PostgreSQL transitions remain explicit in the repository"
)]
impl ManagedConnectionRepository for PostgresManagedConnectionRepository {
    async fn list_metadata(
        &self,
        project_id: Uuid,
        user_id: Uuid,
        limit: u64,
    ) -> Result<Vec<ManagedConnectionMetadata>, ApplicationError> {
        if limit == 0 || limit > 100 {
            return Err(ApplicationError::InvalidInput);
        }
        let rows = self
            .database
            .query_all_raw(statement(
                r"SELECT connection.id, connection.project_id,
                      connection.provider_configuration_id, connection.linked_identity_id,
                      connection.user_id, connection.state, connection.revision,
                      connection.generation, connection.credential_generation,
                      connection.adapter_key AS capability_key,
                      to_json(connection.required_scopes) AS required_scopes,
                      identity.source_schema, connection.supports_revocation,
                      to_json(ARRAY(SELECT assignment.application_id
                          FROM application_provider_assignments AS assignment
                          JOIN applications AS application ON application.project_id=assignment.project_id
                           AND application.id=assignment.application_id
                         WHERE assignment.project_id=connection.project_id
                           AND assignment.provider_id=connection.provider_configuration_id
                           AND assignment.status='active' AND application.status='active'
                         ORDER BY assignment.application_id)) AS reauthorization_application_ids,
                      connection.last_safe_outcome,
                      connection.last_synchronized_at, connection.next_synchronize_at,
                      connection.next_renewal_at, connection.consecutive_failures
               FROM managed_provider_connections AS connection
               JOIN provider_configurations AS provider
                 ON provider.project_id = connection.project_id
                AND provider.id = connection.provider_configuration_id
               JOIN linked_identities AS identity
                 ON identity.project_id = connection.project_id
                AND identity.id = connection.linked_identity_id
               WHERE connection.project_id = $1 AND connection.user_id = $2
               ORDER BY connection.id LIMIT $3",
                vec![project_id.into(), user_id.into(), limit.into()],
            ))
            .await
            .map_err(persistence)?;
        rows.into_iter()
            .map(|row| {
                let scopes: Value = row
                    .try_get("", "required_scopes")
                    .map_err(|_| ApplicationError::Integrity)?;
                Ok(ManagedConnectionMetadata {
                    id: get(&row, "id")?,
                    project_id: get(&row, "project_id")?,
                    provider_configuration_id: get(&row, "provider_configuration_id")?,
                    linked_identity_id: get(&row, "linked_identity_id")?,
                    user_id: get(&row, "user_id")?,
                    state: get(&row, "state")?,
                    revision: get(&row, "revision")?,
                    generation: get(&row, "generation")?,
                    credential_generation: get(&row, "credential_generation")?,
                    capability_key: get(&row, "capability_key")?,
                    required_scopes: json_strings(&scopes)?,
                    source_schema: get(&row, "source_schema")?,
                    supports_revocation: get(&row, "supports_revocation")?,
                    reauthorization_application_ids: json_uuids(&get(
                        &row,
                        "reauthorization_application_ids",
                    )?)?,
                    last_safe_outcome: get(&row, "last_safe_outcome")?,
                    last_synchronized_at: get(&row, "last_synchronized_at")?,
                    next_synchronize_at: get(&row, "next_synchronize_at")?,
                    next_renewal_at: get(&row, "next_renewal_at")?,
                    consecutive_failures: get(&row, "consecutive_failures")?,
                })
            })
            .collect()
    }

    async fn metadata_for_owner(
        &self,
        project_id: Uuid,
        user_id: Uuid,
        connection_id: Uuid,
    ) -> Result<ManagedConnectionMetadata, ApplicationError> {
        metadata_for_owner(&self.database, project_id, user_id, connection_id).await
    }

    async fn claim_next_read(
        &self,
        worker_id: Uuid,
        now: OffsetDateTime,
        lease_until: OffsetDateTime,
    ) -> Result<Option<ClaimedManagedCredential>, ApplicationError> {
        claim_connection(&self.database, worker_id, now, lease_until, "read", None).await
    }

    async fn commit_read_profile(
        &self,
        claim: &ClaimedManagedCredential,
        profile: BoundedManagedProfile,
        next_sync: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<bool, ApplicationError> {
        validate_profile(&profile)?;
        let display_name = profile
            .profile
            .display_name
            .map(ProfileDisplayName::into_inner);
        let picture_url = profile
            .profile
            .picture_url
            .map(ProfilePictureUrl::into_inner);
        let locale = profile.profile.locale.map(ProfileLocale::into_inner);
        let transaction = self.database.begin().await.map_err(persistence)?;
        if !lock_guard_authority(&transaction, &claim.guard).await? {
            transaction.rollback().await.map_err(persistence)?;
            return Ok(false);
        }
        let result = transaction.execute_raw(statement(
            r"WITH current_connection AS (
                   SELECT connection.id
                   FROM managed_provider_connections AS connection
                   JOIN projects AS project ON project.id = connection.project_id
                   JOIN provider_configurations AS provider
                     ON provider.project_id = connection.project_id
                    AND provider.id = connection.provider_configuration_id
                   JOIN project_users AS project_user
                     ON project_user.project_id = connection.project_id
                    AND project_user.id = connection.user_id
                   JOIN linked_identities AS identity
                     ON identity.project_id = connection.project_id
                    AND identity.id = connection.linked_identity_id
                   WHERE connection.project_id = $1 AND connection.id = $2
                     AND connection.state = 'active'
                     AND connection.revision = $3 AND connection.generation = $4
                     AND connection.credential_generation = $5
                     AND connection.provider_revision = $6
                     AND connection.managed_profile_revision = $7
                     AND connection.user_security_revision = $8
                     AND connection.identity_revision = $9
                     AND connection.lease_owner = $10 AND connection.lease_kind = 'read'
                     AND connection.lease_expires_at > $11
                     AND project.status = 'active'
                     AND project.security_revision = connection.project_security_revision
                     AND provider.status = 'active'
                     AND provider.revision = connection.provider_revision
                     AND provider.managed_profile_enabled
                     AND provider.managed_profile_revision = connection.managed_profile_revision
                     AND project_user.status = 'active'
                     AND project_user.security_revision = connection.user_security_revision
                     AND identity.status = 'active'
                     AND identity.identity_revision = connection.identity_revision
                   FOR UPDATE OF connection, identity
               ), updated_identity AS (
                   UPDATE linked_identities AS identity
                      SET display_name = $12, picture_url = $13, locale = $14,
                          observed_at = $15,
                          identity_revision = identity.identity_revision
                            + CASE WHEN (identity.display_name, identity.picture_url, identity.locale)
                                IS DISTINCT FROM ($12, $13, $14) THEN 1 ELSE 0 END,
                          updated_at = CASE WHEN (identity.display_name, identity.picture_url, identity.locale)
                                IS DISTINCT FROM ($12, $13, $14) THEN $11 ELSE identity.updated_at END
                     FROM current_connection
                    WHERE identity.project_id = $1 AND identity.id = $16
                    RETURNING identity.id
               )
               UPDATE managed_provider_connections AS connection
                  SET last_safe_outcome = 'read_succeeded', last_synchronized_at = $11,
                      next_synchronize_at = $17, consecutive_failures = 0,
                      identity_revision = identity.identity_revision,
                      lease_owner = NULL, lease_kind = NULL, lease_expires_at = NULL,
                      updated_at = $11
                 FROM linked_identities AS identity, updated_identity
                WHERE connection.project_id = $1 AND connection.id = $2
                  AND identity.project_id = $1 AND identity.id = $16",
            vec![
                claim.guard.project_id.into(), claim.guard.connection_id.into(),
                claim.guard.connection_revision.into(), claim.guard.connection_generation.into(),
                claim.guard.credential_generation.into(), claim.guard.provider_revision.into(),
                claim.guard.managed_profile_revision.into(), claim.guard.user_security_revision.into(),
                claim.guard.identity_revision.into(), claim.lease_owner.into(), now.into(),
                display_name.clone().into(), picture_url.clone().into(), locale.clone().into(), profile.observed_at.into(),
                claim.guard.linked_identity_id.into(), next_sync.into(),
            ],
        )).await.map_err(persistence)?;
        if result.rows_affected() == 1 {
            let user = project_user::Entity::find_by_id(claim.guard.user_id)
                .filter(project_user::Column::ProjectId.eq(claim.guard.project_id))
                .lock_exclusive()
                .one(&transaction)
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::Integrity)?;
            if user.status == "active"
                && user.primary_source_kind == "provider"
                && user.primary_profile_identity_id == Some(claim.guard.linked_identity_id)
            {
                let effective_display_name = if user.local_display_name_set {
                    user.local_display_name.clone()
                } else {
                    display_name
                };
                let effective_picture_url = if user.local_picture_url_set {
                    user.local_picture_url.clone()
                } else {
                    picture_url
                };
                let effective_locale = if user.local_locale_set {
                    user.local_locale.clone()
                } else {
                    locale
                };
                if (
                    user.display_name.as_ref(),
                    user.picture_url.as_ref(),
                    user.locale.as_ref(),
                ) != (
                    effective_display_name.as_ref(),
                    effective_picture_url.as_ref(),
                    effective_locale.as_ref(),
                ) {
                    let digest = base_profile_digest(
                        effective_display_name.as_deref(),
                        effective_picture_url.as_deref(),
                        effective_locale.as_deref(),
                        None,
                    )?;
                    let mut active = user.into_active_model();
                    active.display_name = Set(effective_display_name);
                    active.picture_url = Set(effective_picture_url);
                    active.locale = Set(effective_locale);
                    active.base_profile_digest = Set(digest);
                    active.user_revision = Set(active.user_revision.take().unwrap_or(1) + 1);
                    active.updated_at = Set(now);
                    let updated = active.update(&transaction).await.map_err(persistence)?;
                    materialize_user_projections(
                        self.projection_materializer.as_deref(),
                        &transaction,
                        &updated,
                        now,
                    )
                    .await?;
                }
            }
        }
        transaction.commit().await.map_err(persistence)?;
        Ok(result.rows_affected() == 1)
    }

    async fn finish_read_failure(
        &self,
        claim: &ClaimedManagedCredential,
        safe_outcome: &'static str,
        retry_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<bool, ApplicationError> {
        if safe_outcome.is_empty() || safe_outcome.len() > 64 {
            return Err(ApplicationError::InvalidInput);
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        if !lock_guard_authority(&transaction, &claim.guard).await? {
            transaction.rollback().await.map_err(persistence)?;
            return Ok(false);
        }
        let result = transaction
            .execute_raw(statement(
                r"UPDATE managed_provider_connections
                  SET last_safe_outcome = $1, next_synchronize_at = $2,
                      consecutive_failures = LEAST(consecutive_failures + 1, 32),
                      lease_owner = NULL, lease_kind = NULL, lease_expires_at = NULL,
                      updated_at = $3
                WHERE project_id = $4 AND id = $5 AND state = 'active'
                  AND revision = $6 AND generation = $7 AND credential_generation = $8
                  AND provider_revision = $9 AND managed_profile_revision = $10
                  AND user_security_revision = $11 AND identity_revision = $12
                  AND lease_owner = $13 AND lease_kind = 'read' AND lease_expires_at > $3",
                vec![
                    safe_outcome.into(),
                    retry_at.into(),
                    now.into(),
                    claim.guard.project_id.into(),
                    claim.guard.connection_id.into(),
                    claim.guard.connection_revision.into(),
                    claim.guard.connection_generation.into(),
                    claim.guard.credential_generation.into(),
                    claim.guard.provider_revision.into(),
                    claim.guard.managed_profile_revision.into(),
                    claim.guard.user_security_revision.into(),
                    claim.guard.identity_revision.into(),
                    claim.lease_owner.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        transaction.commit().await.map_err(persistence)?;
        Ok(result.rows_affected() == 1)
    }

    async fn prepare_next_renewal(
        &self,
        worker_id: Uuid,
        now: OffsetDateTime,
        lease_until: OffsetDateTime,
        adapter_idempotent_replay: bool,
    ) -> Result<Option<PreparedRenewal>, ApplicationError> {
        if lease_until <= now {
            return Err(ApplicationError::InvalidInput);
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        // Submitted operations win recovery. Non-replayable ones are returned only so the
        // service can destructively terminalize without another provider dispatch.
        let existing = transaction.query_one_raw(statement(
            r"SELECT operation.id AS operation_id, operation.attempt_id,
                      operation.adapter_idempotent_replay, operation.state AS operation_state,
                      (project.status='active'
                       AND project.security_revision=connection.project_security_revision
                       AND provider.status='active' AND provider.managed_profile_enabled
                       AND provider.revision=connection.provider_revision
                       AND provider.managed_profile_revision=connection.managed_profile_revision
                       AND ((provider.adapter_kind='oidc'
                             AND operation.provider_egress_policy_revision=egress.revision)
                            OR (provider.adapter_kind<>'oidc'
                                AND operation.provider_egress_policy_revision IS NULL))
                       AND project_user.status='active'
                       AND project_user.security_revision=connection.user_security_revision
                       AND identity.status='active'
                       AND identity.identity_revision=connection.identity_revision) AS authority_valid,
                      connection.id, connection.project_id, connection.provider_configuration_id,
                      connection.linked_identity_id, connection.user_id,
                      connection.revision, connection.generation, connection.credential_generation,
                      project.security_revision AS project_security_revision,
                      connection.provider_revision, connection.managed_profile_revision,
                      connection.adapter_key,connection.adapter_capability_revision,
                      to_json(connection.required_scopes) AS required_scopes,
                      connection.user_security_revision, connection.identity_revision,
                      connection.consecutive_failures,provider.kind AS provider_legacy_kind,provider.adapter_kind AS provider_adapter_kind,provider.issuer, identity.subject, provider.client_id, COALESCE(provider.secret_material_id::TEXT, provider.secret_ref) AS secret_ref,
                      operation.provider_egress_policy_revision,
                      egress.mode AS current_egress_mode,
                      egress.exact_origins AS current_egress_exact_origins,
                      egress.revision AS current_egress_policy_revision,
                      credential.key_version, credential.ciphertext
               FROM managed_provider_renewal_operations AS operation
               JOIN managed_provider_connections AS connection
                 ON connection.project_id = operation.project_id AND connection.id = operation.connection_id
               JOIN projects AS project ON project.id = connection.project_id
               LEFT JOIN project_provider_egress_policies AS egress
                 ON egress.project_id=connection.project_id
               JOIN provider_configurations AS provider
                 ON provider.project_id = connection.project_id AND provider.id = connection.provider_configuration_id
               JOIN project_users AS project_user
                 ON project_user.project_id = connection.project_id AND project_user.id = connection.user_id
               JOIN linked_identities AS identity
                 ON identity.project_id = connection.project_id AND identity.id = connection.linked_identity_id
               JOIN managed_provider_credentials AS credential
                 ON credential.project_id = connection.project_id AND credential.connection_id = connection.id
                AND credential.credential_generation = operation.expected_credential_generation
               JOIN managed_provider_claim_fairness AS fairness
                 ON fairness.project_id=connection.project_id
                AND fairness.provider_configuration_id=connection.provider_configuration_id
                AND fairness.queue_kind='outbound'
               WHERE operation.state IN ('submitted', 'prepared')
                 AND (operation.lease_expires_at IS NULL OR operation.lease_expires_at <= $1)
                 AND (connection.lease_expires_at IS NULL OR connection.lease_expires_at <= $1)
                 AND (fairness.lease_expires_at IS NULL OR fairness.lease_expires_at <= $1
                      OR NOT EXISTS (
                        SELECT 1 FROM managed_provider_connections AS budget_holder
                         WHERE budget_holder.project_id=connection.project_id
                           AND budget_holder.provider_configuration_id=connection.provider_configuration_id
                           AND budget_holder.lease_owner=fairness.lease_owner
                           AND budget_holder.lease_expires_at>$1))
                 AND connection.state = 'active'
                 AND connection.generation = operation.expected_connection_generation
                 AND connection.credential_generation = operation.expected_credential_generation
                 AND credential.ciphertext IS NOT NULL
                 AND (operation.state='submitted' OR (
                      project.status='active'
                      AND project.security_revision=connection.project_security_revision
                      AND provider.status='active' AND provider.managed_profile_enabled
                      AND provider.revision=connection.provider_revision
                      AND provider.managed_profile_revision=connection.managed_profile_revision
                      AND ((provider.adapter_kind='oidc'
                            AND operation.provider_egress_policy_revision=egress.revision)
                           OR (provider.adapter_kind<>'oidc'
                               AND operation.provider_egress_policy_revision IS NULL))
                      AND project_user.status='active'
                      AND project_user.security_revision=connection.user_security_revision
                      AND identity.status='active'
                      AND identity.identity_revision=connection.identity_revision))
               ORDER BY CASE WHEN operation.state = 'submitted' THEN 0 ELSE 1 END,
                        fairness.last_claimed_at ASC NULLS FIRST,
                        operation.prepared_at, operation.project_id,
                        connection.provider_configuration_id
               FOR UPDATE OF operation, connection, fairness SKIP LOCKED LIMIT 1",
            vec![now.into()],
        )).await.map_err(persistence)?;
        if let Some(row) = existing {
            transaction.execute_raw(statement(
                "UPDATE managed_provider_renewal_operations SET lease_owner = $1, lease_expires_at = $2, updated_at = $3 WHERE id = $4",
                vec![worker_id.into(), lease_until.into(), now.into(), get::<Uuid>(&row, "operation_id")?.into()],
            )).await.map_err(persistence)?;
            transaction.execute_raw(statement(
                "UPDATE managed_provider_connections SET lease_owner = $1, lease_kind = 'renewal', lease_expires_at = $2, updated_at = $3 WHERE project_id = $4 AND id = $5",
                vec![worker_id.into(), lease_until.into(), now.into(), get::<Uuid>(&row, "project_id")?.into(), get::<Uuid>(&row, "id")?.into()],
            )).await.map_err(persistence)?;
            record_claim_fairness(&transaction, &row, "renewal", worker_id, now, lease_until)
                .await?;
            transaction.commit().await.map_err(persistence)?;
            return Ok(Some(prepared_from_row(&row, worker_id, lease_until)?));
        }
        let Some(claim) =
            claim_connection_on(&transaction, worker_id, now, lease_until, "renewal", None).await?
        else {
            transaction.commit().await.map_err(persistence)?;
            return Ok(None);
        };
        let operation_id = Uuid::new_v4();
        let attempt_id = Uuid::new_v4();
        let inserted = transaction
            .execute_raw(statement(
                r"INSERT INTO managed_provider_renewal_operations
                 (id, project_id, connection_id, expected_connection_generation,
                  expected_credential_generation, successor_connection_generation,
                  successor_credential_generation, attempt_id, state, adapter_idempotent_replay,
                  lease_owner, lease_expires_at, safe_outcome, prepared_at, updated_at,
                  provider_egress_policy_revision)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'prepared',$9,$10,$11,'prepared',$12,$12,$13)
               ON CONFLICT (project_id, connection_id, expected_connection_generation) DO NOTHING",
                vec![
                    operation_id.into(),
                    claim.guard.project_id.into(),
                    claim.guard.connection_id.into(),
                    claim.guard.connection_generation.into(),
                    claim.guard.credential_generation.into(),
                    (claim.guard.connection_generation + 1).into(),
                    (claim.guard.credential_generation + 1).into(),
                    attempt_id.into(),
                    adapter_idempotent_replay.into(),
                    worker_id.into(),
                    lease_until.into(),
                    now.into(),
                    claim.guard.provider_egress_policy_revision.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        if inserted.rows_affected() != 1 {
            transaction
                .execute_raw(statement(
                    r"UPDATE managed_provider_connections
                      SET next_renewal_at = NULL,
                          last_safe_outcome = 'renewal_generation_terminal',
                          lease_owner = NULL, lease_kind = NULL, lease_expires_at = NULL,
                          updated_at = $1
                    WHERE project_id = $2 AND id = $3 AND lease_owner = $4",
                    vec![
                        now.into(),
                        claim.guard.project_id.into(),
                        claim.guard.connection_id.into(),
                        worker_id.into(),
                    ],
                ))
                .await
                .map_err(persistence)?;
            transaction.commit().await.map_err(persistence)?;
            return Ok(None);
        }
        transaction.commit().await.map_err(persistence)?;
        Ok(Some(PreparedRenewal {
            operation_id,
            attempt_id,
            claim,
            adapter_idempotent_replay,
            authority_valid: true,
            operation_state: RenewalOperationState::Prepared,
        }))
    }

    async fn mark_renewal_submitted(
        &self,
        renewal: &PreparedRenewal,
        now: OffsetDateTime,
    ) -> Result<bool, ApplicationError> {
        let guard = &renewal.claim.guard;
        let transaction = self.database.begin().await.map_err(persistence)?;
        // Canonical order: Project/policy/provider authority -> user -> identity ->
        // connection/credential/operation. This is the final authorization point before dispatch.
        let project_ok = lock_boolean(
            &transaction,
            "SELECT EXISTS (SELECT 1 FROM projects WHERE id=$1 AND status='active' AND security_revision=$2 FOR SHARE)",
            vec![guard.project_id.into(), guard.project_security_revision.into()],
        )
        .await?;
        let policy_ok = lock_guard_egress_policy(&transaction, guard).await?;
        let provider_ok = lock_boolean(
            &transaction,
            "SELECT EXISTS (SELECT 1 FROM provider_configurations WHERE project_id=$1 AND id=$2 AND status='active' AND revision=$3 AND managed_profile_enabled AND managed_profile_revision=$4 FOR SHARE)",
            vec![guard.project_id.into(), guard.provider_configuration_id.into(), guard.provider_revision.into(), guard.managed_profile_revision.into()],
        )
        .await?;
        let user_ok = lock_boolean(
            &transaction,
            "SELECT EXISTS (SELECT 1 FROM project_users WHERE project_id=$1 AND id=$2 AND status='active' AND security_revision=$3 FOR UPDATE)",
            vec![guard.project_id.into(), guard.user_id.into(), guard.user_security_revision.into()],
        )
        .await?;
        let identity_ok = lock_boolean(
            &transaction,
            "SELECT EXISTS (SELECT 1 FROM linked_identities WHERE project_id=$1 AND id=$2 AND user_id=$3 AND status='active' AND identity_revision=$4 FOR UPDATE)",
            vec![guard.project_id.into(), guard.linked_identity_id.into(), guard.user_id.into(), guard.identity_revision.into()],
        )
        .await?;
        if !(project_ok && policy_ok && provider_ok && user_ok && identity_ok) {
            transaction.rollback().await.map_err(persistence)?;
            return Ok(false);
        }
        let authority = transaction.query_one_raw(statement(
            r"SELECT connection.id
                 FROM managed_provider_connections AS connection
                 JOIN managed_provider_credentials AS credential
                   ON credential.project_id=connection.project_id AND credential.connection_id=connection.id
                  AND credential.credential_generation=connection.credential_generation
                 JOIN managed_provider_renewal_operations AS operation
                   ON operation.project_id=connection.project_id AND operation.connection_id=connection.id
                WHERE connection.project_id=$1 AND connection.id=$2 AND connection.state='active'
                  AND connection.revision=$3 AND connection.generation=$4
                  AND connection.credential_generation=$5 AND connection.provider_revision=$6
                  AND connection.managed_profile_revision=$7 AND connection.user_security_revision=$8
                  AND connection.identity_revision=$9 AND connection.lease_owner=$10
                  AND connection.lease_kind='renewal' AND connection.lease_expires_at>$11
                  AND credential.ciphertext IS NOT NULL
                  AND operation.id=$12 AND operation.attempt_id=$13 AND operation.state='prepared'
                  AND operation.expected_connection_generation=$4
                  AND operation.expected_credential_generation=$5
                  AND operation.lease_owner=$10 AND operation.lease_expires_at>$11
                  AND operation.provider_egress_policy_revision IS NOT DISTINCT FROM $14
                FOR UPDATE OF connection, credential, operation",
            vec![guard.project_id.into(), guard.connection_id.into(), guard.connection_revision.into(),
                 guard.connection_generation.into(), guard.credential_generation.into(), guard.provider_revision.into(),
                 guard.managed_profile_revision.into(), guard.user_security_revision.into(), guard.identity_revision.into(),
                 renewal.claim.lease_owner.into(), now.into(), renewal.operation_id.into(), renewal.attempt_id.into(),
                 guard.provider_egress_policy_revision.into()],
        )).await.map_err(persistence)?;
        if authority.is_none() {
            transaction.rollback().await.map_err(persistence)?;
            return Ok(false);
        }
        let result = transaction
            .execute_raw(statement(
                r"UPDATE managed_provider_renewal_operations
                  SET state='submitted', submitted_at=$1, safe_outcome='submitted', updated_at=$1
                WHERE project_id=$2 AND id=$3 AND state='prepared'",
                vec![
                    now.into(),
                    guard.project_id.into(),
                    renewal.operation_id.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        transaction.commit().await.map_err(persistence)?;
        Ok(result.rows_affected() == 1)
    }

    async fn commit_renewal_successor(
        &self,
        renewal: &PreparedRenewal,
        protected: ProtectedValue,
        now: OffsetDateTime,
    ) -> Result<Option<SuccessorProfileClaim>, ApplicationError> {
        if protected.ciphertext.len() < 40 || protected.key_version <= 0 {
            return Err(ApplicationError::InvalidInput);
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        if !lock_guard_egress_policy(&transaction, &renewal.claim.guard).await? {
            transaction.rollback().await.map_err(persistence)?;
            return Ok(None);
        }
        let inserted = transaction.execute_raw(statement(
            r"WITH guarded AS (
                 SELECT connection.id
                   FROM projects AS project
                   LEFT JOIN project_provider_egress_policies AS egress ON egress.project_id=project.id
                   JOIN provider_configurations AS provider ON provider.project_id=project.id
                   JOIN project_users AS project_user ON project_user.project_id=project.id
                   JOIN linked_identities AS identity
                     ON identity.project_id=project.id AND identity.user_id=project_user.id
                   JOIN managed_provider_connections AS connection
                     ON connection.project_id=project.id
                    AND connection.provider_configuration_id=provider.id
                    AND connection.user_id=project_user.id
                    AND connection.linked_identity_id=identity.id
                   JOIN managed_provider_renewal_operations AS operation
                     ON operation.project_id = connection.project_id AND operation.connection_id = connection.id
                  WHERE connection.project_id = $1 AND connection.id = $2 AND connection.state = 'active'
                    AND connection.revision = $3 AND connection.generation = $4
                    AND connection.credential_generation = $5
                    AND project.status='active' AND project.security_revision=$14
                    AND provider.status='active' AND provider.managed_profile_enabled
                    AND provider.revision=connection.provider_revision
                    AND provider.managed_profile_revision=connection.managed_profile_revision
                    AND operation.provider_egress_policy_revision IS NOT DISTINCT FROM $15
                    AND ((provider.adapter_kind='oidc'
                          AND operation.provider_egress_policy_revision=egress.revision)
                         OR (provider.adapter_kind<>'oidc'
                             AND operation.provider_egress_policy_revision IS NULL))
                    AND project_user.status='active'
                    AND project_user.security_revision=connection.user_security_revision
                    AND identity.status='active' AND identity.identity_revision=connection.identity_revision
                    AND operation.id = $6 AND operation.attempt_id = $7 AND operation.state = 'submitted'
                    AND operation.lease_owner = $8 AND operation.lease_expires_at > $9
                  FOR UPDATE OF project, provider, project_user, identity, connection, operation
               ), destroyed AS (
                 UPDATE managed_provider_credentials AS credential
                    SET ciphertext = NULL, superseded_at = $9, destroyed_at = $9
                   FROM guarded WHERE credential.project_id = $1 AND credential.connection_id = $2
                     AND credential.credential_generation = $5 AND credential.ciphertext IS NOT NULL
                 RETURNING credential.connection_id
               )
               INSERT INTO managed_provider_credentials
                 (project_id, connection_id, connection_generation, credential_generation,
                  key_version, ciphertext, created_at)
               SELECT $1,$2,$10,$11,$12,$13,$9 FROM destroyed",
            vec![renewal.claim.guard.project_id.into(), renewal.claim.guard.connection_id.into(),
                 renewal.claim.guard.connection_revision.into(), renewal.claim.guard.connection_generation.into(),
                 renewal.claim.guard.credential_generation.into(), renewal.operation_id.into(),
                 renewal.attempt_id.into(), renewal.claim.lease_owner.into(), now.into(),
                 (renewal.claim.guard.connection_generation + 1).into(),
                 (renewal.claim.guard.credential_generation + 1).into(), protected.key_version.into(),
                 protected.ciphertext.into(), renewal.claim.guard.project_security_revision.into(),
                 renewal.claim.guard.provider_egress_policy_revision.into()],
        )).await.map_err(persistence)?;
        if inserted.rows_affected() != 1 {
            transaction.rollback().await.map_err(persistence)?;
            return Ok(None);
        }
        let connection_updated = transaction.execute_raw(statement(
            r"UPDATE managed_provider_connections SET revision = revision + 1,
                     generation = generation + 1, credential_generation = credential_generation + 1,
                     state = 'active', last_safe_outcome = 'successor_profile_pending', consecutive_failures = 0,
                     next_renewal_at = $1 + INTERVAL '30 days',
                     next_synchronize_at = GREATEST($1 + INTERVAL '1 minute',
                                                   lease_expires_at + INTERVAL '1 minute'),
                     lease_kind = 'renewal', updated_at = $1
                WHERE project_id = $2 AND id = $3",
            vec![now.into(), renewal.claim.guard.project_id.into(),
                 renewal.claim.guard.connection_id.into()],
        )).await.map_err(persistence)?;
        let operation_updated = transaction
            .execute_raw(statement(
                r"UPDATE managed_provider_renewal_operations SET state = 'successor_committed',
                     safe_outcome = 'successor_committed', terminal_at = $1, lease_owner = NULL,
                     lease_expires_at = NULL, updated_at = $1 WHERE project_id = $2 AND id = $3",
                vec![
                    now.into(),
                    renewal.claim.guard.project_id.into(),
                    renewal.operation_id.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        if connection_updated.rows_affected() != 1 || operation_updated.rows_affected() != 1 {
            transaction.rollback().await.map_err(persistence)?;
            return Err(ApplicationError::Integrity);
        }
        append_runtime_audit(
            &transaction,
            renewal.claim.guard.project_id,
            "runtime_worker",
            "managed_connection.renewal_succeeded",
            "managed_provider_connection",
            Some(renewal.claim.guard.connection_id),
            renewal.attempt_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        let mut guard = renewal.claim.guard.clone();
        guard.connection_revision += 1;
        guard.connection_generation += 1;
        guard.credential_generation += 1;
        Ok(Some(SuccessorProfileClaim {
            guard,
            lease_owner: renewal.claim.lease_owner,
            lease_expires_at: renewal.claim.lease_expires_at,
        }))
    }

    async fn commit_successor_profile(
        &self,
        claim: &SuccessorProfileClaim,
        profile: BoundedManagedProfile,
        next_sync: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<bool, ApplicationError> {
        commit_profile_for_guard(
            &self.database,
            self.projection_materializer.as_deref(),
            &claim.guard,
            Some(claim),
            profile,
            next_sync,
            now,
        )
        .await
    }

    async fn commit_reauthorization_profile(
        &self,
        guard: &ConnectionGuard,
        profile: BoundedManagedProfile,
        next_sync: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<bool, ApplicationError> {
        commit_profile_for_guard(
            &self.database,
            self.projection_materializer.as_deref(),
            guard,
            None,
            profile,
            next_sync,
            now,
        )
        .await
    }

    async fn finish_successor_profile_failure(
        &self,
        claim: &SuccessorProfileClaim,
        safe_outcome: &'static str,
        retry_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<bool, ApplicationError> {
        if safe_outcome.is_empty() || safe_outcome.len() > 64 {
            return Err(ApplicationError::InvalidInput);
        }
        let guard = &claim.guard;
        let transaction = self.database.begin().await.map_err(persistence)?;
        if !lock_guard_authority(&transaction, guard).await? {
            transaction.rollback().await.map_err(persistence)?;
            return Ok(false);
        }
        let result = transaction
            .execute_raw(statement(
                r"UPDATE managed_provider_connections SET last_safe_outcome=$1,
                    next_synchronize_at=$2, consecutive_failures=LEAST(consecutive_failures+1,32),
                    lease_owner=NULL, lease_kind=NULL, lease_expires_at=NULL, updated_at=$3
               WHERE project_id=$4 AND id=$5 AND state='active' AND revision=$6
                 AND generation=$7 AND credential_generation=$8 AND provider_revision=$9
                 AND managed_profile_revision=$10 AND user_security_revision=$11
                 AND identity_revision=$12 AND lease_owner=$13 AND lease_kind='renewal'
                 AND lease_expires_at=$14 AND lease_expires_at>$3",
                vec![
                    safe_outcome.into(),
                    retry_at.into(),
                    now.into(),
                    guard.project_id.into(),
                    guard.connection_id.into(),
                    guard.connection_revision.into(),
                    guard.connection_generation.into(),
                    guard.credential_generation.into(),
                    guard.provider_revision.into(),
                    guard.managed_profile_revision.into(),
                    guard.user_security_revision.into(),
                    guard.identity_revision.into(),
                    claim.lease_owner.into(),
                    claim.lease_expires_at.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        transaction.commit().await.map_err(persistence)?;
        Ok(result.rows_affected() == 1)
    }

    async fn finish_successor_without_profile(
        &self,
        claim: &SuccessorProfileClaim,
        now: OffsetDateTime,
    ) -> Result<bool, ApplicationError> {
        let guard = &claim.guard;
        let transaction = self.database.begin().await.map_err(persistence)?;
        if !lock_guard_authority(&transaction, guard).await? {
            transaction.rollback().await.map_err(persistence)?;
            return Ok(false);
        }
        let released = transaction
            .execute_raw(statement(
                r"UPDATE managed_provider_connections
                 SET next_synchronize_at=NULL, lease_owner=NULL, lease_kind=NULL,
                     lease_expires_at=NULL, updated_at=$1
               WHERE project_id=$2 AND id=$3 AND state='active' AND revision=$4
                 AND generation=$5 AND credential_generation=$6
                 AND provider_revision=$7 AND managed_profile_revision=$8
                 AND user_security_revision=$9 AND identity_revision=$10
                 AND lease_owner=$11 AND lease_kind='renewal'
                 AND lease_expires_at=$12 AND lease_expires_at>$1",
                vec![
                    now.into(),
                    guard.project_id.into(),
                    guard.connection_id.into(),
                    guard.connection_revision.into(),
                    guard.connection_generation.into(),
                    guard.credential_generation.into(),
                    guard.provider_revision.into(),
                    guard.managed_profile_revision.into(),
                    guard.user_security_revision.into(),
                    guard.identity_revision.into(),
                    claim.lease_owner.into(),
                    claim.lease_expires_at.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        transaction.commit().await.map_err(persistence)?;
        Ok(released.rows_affected() == 1)
    }

    async fn release_prepared_failure(
        &self,
        renewal: &PreparedRenewal,
        safe_outcome: &'static str,
        retry_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<bool, ApplicationError> {
        if renewal.operation_state != RenewalOperationState::Prepared || safe_outcome.is_empty() {
            return Err(ApplicationError::InvalidInput);
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        let operation = transaction
            .execute_raw(statement(
                r"UPDATE managed_provider_renewal_operations SET safe_outcome=$1,
                    lease_owner=NULL, lease_expires_at=$2, updated_at=$3
               WHERE project_id=$4 AND id=$5 AND state='prepared' AND attempt_id=$6
                 AND lease_owner=$7",
                vec![
                    safe_outcome.into(),
                    retry_at.into(),
                    now.into(),
                    renewal.claim.guard.project_id.into(),
                    renewal.operation_id.into(),
                    renewal.attempt_id.into(),
                    renewal.claim.lease_owner.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        if operation.rows_affected() == 1 {
            transaction.execute_raw(statement(
                r"UPDATE managed_provider_connections SET lease_owner=NULL, lease_kind=NULL,
                        lease_expires_at=NULL, last_safe_outcome=$1, next_renewal_at=$2, updated_at=$3
                   WHERE project_id=$4 AND id=$5 AND lease_owner=$6 AND lease_kind='renewal'",
                vec![safe_outcome.into(), retry_at.into(), now.into(), renewal.claim.guard.project_id.into(),
                     renewal.claim.guard.connection_id.into(), renewal.claim.lease_owner.into()],
            )).await.map_err(persistence)?;
        }
        transaction.commit().await.map_err(persistence)?;
        Ok(operation.rows_affected() == 1)
    }

    async fn terminalize_renewal(
        &self,
        renewal: &PreparedRenewal,
        state: RenewalOperationState,
        safe_outcome: &'static str,
        now: OffsetDateTime,
    ) -> Result<bool, ApplicationError> {
        if !matches!(
            state,
            RenewalOperationState::ReauthRequired | RenewalOperationState::Abandoned
        ) || safe_outcome.is_empty()
            || safe_outcome.len() > 64
        {
            return Err(ApplicationError::InvalidInput);
        }
        let connection_state = if safe_outcome == "provider_confirmed_revocation" {
            "revoked"
        } else if state == RenewalOperationState::ReauthRequired {
            "reauth_required"
        } else {
            "active"
        };
        let destroy = state == RenewalOperationState::ReauthRequired;
        let transaction = self.database.begin().await.map_err(persistence)?;
        // Match successor/reauthorization ordering: connection, credential, then operation.
        if transaction
            .query_one_raw(statement(
                r"SELECT id FROM managed_provider_connections
                    WHERE project_id=$1 AND id=$2 AND revision=$3 AND generation=$4 FOR UPDATE",
                vec![
                    renewal.claim.guard.project_id.into(),
                    renewal.claim.guard.connection_id.into(),
                    renewal.claim.guard.connection_revision.into(),
                    renewal.claim.guard.connection_generation.into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .is_none()
        {
            transaction.rollback().await.map_err(persistence)?;
            return Ok(false);
        }
        transaction
            .query_one_raw(statement(
                r"SELECT credential_generation FROM managed_provider_credentials
                    WHERE project_id=$1 AND connection_id=$2 AND credential_generation=$3 FOR UPDATE",
                vec![
                    renewal.claim.guard.project_id.into(),
                    renewal.claim.guard.connection_id.into(),
                    renewal.claim.guard.credential_generation.into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        let result = transaction.execute_raw(statement(
            r"UPDATE managed_provider_renewal_operations AS operation
                  SET state = $1, safe_outcome = $2, terminal_at = $3,
                      lease_owner = NULL, lease_expires_at = NULL, updated_at = $3
                WHERE operation.project_id = $4 AND operation.id = $5 AND operation.connection_id = $6
                  AND operation.attempt_id = $7 AND operation.state IN ('prepared','submitted')
                  AND operation.expected_connection_generation = $8
                  AND operation.expected_credential_generation = $9
                  AND operation.lease_owner = $10 AND operation.lease_expires_at = $11
                  AND operation.lease_expires_at > $3",
            vec![state.as_str().into(), safe_outcome.into(), now.into(),
                 renewal.claim.guard.project_id.into(), renewal.operation_id.into(),
                 renewal.claim.guard.connection_id.into(), renewal.attempt_id.into(),
                 renewal.claim.guard.connection_generation.into(), renewal.claim.guard.credential_generation.into(),
                 renewal.claim.lease_owner.into(), renewal.claim.lease_expires_at.into()],
        )).await.map_err(persistence)?;
        if result.rows_affected() != 1 {
            transaction.rollback().await.map_err(persistence)?;
            return Ok(false);
        }
        if destroy {
            transaction
                .execute_raw(statement(
                    r"UPDATE managed_provider_credentials SET ciphertext = NULL, destroyed_at = $1
                    WHERE project_id = $2 AND connection_id = $3 AND credential_generation = $4
                      AND ciphertext IS NOT NULL",
                    vec![
                        now.into(),
                        renewal.claim.guard.project_id.into(),
                        renewal.claim.guard.connection_id.into(),
                        renewal.claim.guard.credential_generation.into(),
                    ],
                ))
                .await
                .map_err(persistence)?;
        }
        let connection = transaction
            .execute_raw(statement(
                r"UPDATE managed_provider_connections SET state = $1, revision = revision + 1,
                     generation = generation + CASE WHEN $2 THEN 1 ELSE 0 END,
                     credential_generation = credential_generation,
                     last_safe_outcome = $3,
                     next_synchronize_at = CASE WHEN $2 THEN NULL ELSE next_synchronize_at END,
                     next_renewal_at = CASE WHEN $2 THEN NULL ELSE next_renewal_at END,
                     lease_owner = NULL, lease_kind = NULL, lease_expires_at = NULL, updated_at = $4
                WHERE project_id = $5 AND id = $6 AND revision = $7 AND generation = $8",
                vec![
                    connection_state.into(),
                    destroy.into(),
                    safe_outcome.into(),
                    now.into(),
                    renewal.claim.guard.project_id.into(),
                    renewal.claim.guard.connection_id.into(),
                    renewal.claim.guard.connection_revision.into(),
                    renewal.claim.guard.connection_generation.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        if connection.rows_affected() != 1 {
            transaction.rollback().await.map_err(persistence)?;
            return Ok(false);
        }
        append_runtime_audit(
            &transaction,
            renewal.claim.guard.project_id,
            "runtime_worker",
            if connection_state == "revoked" {
                "managed_connection.provider_revoked"
            } else if destroy {
                "managed_connection.reauthorization_required"
            } else {
                "managed_connection.renewal_abandoned"
            },
            "managed_provider_connection",
            Some(renewal.claim.guard.connection_id),
            renewal.attempt_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(true)
    }

    async fn request_synchronize(
        &self,
        project_id: Uuid,
        user_id: Uuid,
        connection_id: Uuid,
        expected_revision: i64,
        expected_generation: i64,
        now: OffsetDateTime,
    ) -> Result<ManagedConnectionMetadata, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        let result = transaction
            .execute_raw(statement(
                r"UPDATE managed_provider_connections SET next_renewal_at = $1,
                     last_safe_outcome = 'synchronize_requested', updated_at = $1
                WHERE project_id = $2 AND user_id = $3 AND id = $4 AND state = 'active'
                  AND revision = $5 AND generation = $6 AND revocation_requested_at IS NULL
                  AND (lease_expires_at IS NULL OR lease_expires_at <= $1)",
                vec![
                    now.into(),
                    project_id.into(),
                    user_id.into(),
                    connection_id.into(),
                    expected_revision.into(),
                    expected_generation.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        if result.rows_affected() != 1 {
            transaction.rollback().await.map_err(persistence)?;
            return Err(ApplicationError::RevisionConflict);
        }
        let metadata = metadata_for_owner(&transaction, project_id, user_id, connection_id).await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(metadata)
    }

    async fn disconnect(
        &self,
        project_id: Uuid,
        user_id: Uuid,
        connection_id: Uuid,
        expected_revision: i64,
        expected_generation: i64,
        now: OffsetDateTime,
    ) -> Result<ManagedConnectionMetadata, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        // Classify under the connection lock; zero-row queue updates must never turn transient
        // lease contention into a local-only destructive fallback.
        let row = transaction
            .query_one_raw(statement(
                r"SELECT state,supports_revocation,credential_generation,revocation_requested_at,
                         lease_expires_at
                    FROM managed_provider_connections
                   WHERE project_id=$1 AND user_id=$2 AND id=$3 AND revision=$4 AND generation=$5
                     AND state IN ('active','reauth_required','revoked') FOR UPDATE",
                vec![
                    project_id.into(),
                    user_id.into(),
                    connection_id.into(),
                    expected_revision.into(),
                    expected_generation.into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::RevisionConflict)?;
        let state: String = get(&row, "state")?;
        let supports_revocation: bool = get(&row, "supports_revocation")?;
        let credential_generation: i64 = get(&row, "credential_generation")?;
        let revocation_requested_at: Option<OffsetDateTime> = get(&row, "revocation_requested_at")?;
        let lease_expires_at: Option<OffsetDateTime> = get(&row, "lease_expires_at")?;
        let credential = transaction
            .query_one_raw(statement(
                r"SELECT ciphertext IS NOT NULL AS accessible
                    FROM managed_provider_credentials
                   WHERE project_id=$1 AND connection_id=$2 AND credential_generation=$3
                   FOR UPDATE",
                vec![
                    project_id.into(),
                    connection_id.into(),
                    credential_generation.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        let accessible = credential
            .as_ref()
            .map(|row| get::<bool>(row, "accessible"))
            .transpose()?
            .unwrap_or(false);
        if revocation_requested_at.is_some() || lease_expires_at.is_some_and(|until| until > now) {
            // Neither unsupported capability nor locally destroyed material authorizes Control
            // to race an in-flight Runtime read/renewal/rewrap or an existing durable intent.
            transaction.rollback().await.map_err(persistence)?;
            return Err(ApplicationError::RevisionConflict);
        }
        if state == "active" && supports_revocation && accessible {
            transaction
                .execute_raw(statement(
                    r"UPDATE managed_provider_connections
                          SET revision=revision+1,last_safe_outcome='disconnect_revocation_requested',
                              revocation_requested_at=$1,revocation_disposition='disconnect',updated_at=$1
                        WHERE project_id=$2 AND user_id=$3 AND id=$4 AND revision=$5 AND generation=$6",
                    vec![
                        now.into(),
                        project_id.into(),
                        user_id.into(),
                        connection_id.into(),
                        expected_revision.into(),
                        expected_generation.into(),
                    ],
                ))
                .await
                .map_err(persistence)?;
            append_runtime_audit(
                &transaction,
                project_id,
                "deployment_operator",
                "managed_connection.disconnect_revocation_requested",
                "managed_provider_connection",
                Some(connection_id),
                Uuid::new_v4(),
            )
            .await?;
            let metadata =
                metadata_for_owner(&transaction, project_id, user_id, connection_id).await?;
            transaction.commit().await.map_err(persistence)?;
            return Ok(metadata);
        }
        transaction
            .execute_raw(statement(
                r"UPDATE managed_provider_credentials SET ciphertext=NULL,destroyed_at=$1
                    WHERE project_id=$2 AND connection_id=$3 AND credential_generation=$4
                      AND ciphertext IS NOT NULL",
                vec![
                    now.into(),
                    project_id.into(),
                    connection_id.into(),
                    credential_generation.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        let updated = transaction
            .execute_raw(statement(
                r"UPDATE managed_provider_connections
                      SET state='disconnected',revision=revision+1,generation=generation+1,
                          last_safe_outcome='locally_disconnected',next_synchronize_at=NULL,
                          next_renewal_at=NULL,revocation_requested_at=NULL,
                          revocation_disposition=NULL,lease_owner=NULL,lease_kind=NULL,
                          lease_expires_at=NULL,disconnected_at=$1,updated_at=$1
                    WHERE project_id=$2 AND user_id=$3 AND id=$4 AND revision=$5 AND generation=$6",
                vec![
                    now.into(),
                    project_id.into(),
                    user_id.into(),
                    connection_id.into(),
                    expected_revision.into(),
                    expected_generation.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        if updated.rows_affected() != 1 {
            transaction.rollback().await.map_err(persistence)?;
            return Err(ApplicationError::RevisionConflict);
        }
        append_runtime_audit(
            &transaction,
            project_id,
            "deployment_operator",
            "managed_connection.disconnect",
            "managed_provider_connection",
            Some(connection_id),
            Uuid::new_v4(),
        )
        .await?;
        let metadata = metadata_for_owner(&transaction, project_id, user_id, connection_id).await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(metadata)
    }

    async fn request_revocation(
        &self,
        project_id: Uuid,
        user_id: Uuid,
        connection_id: Uuid,
        expected_revision: i64,
        expected_generation: i64,
        correlation_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<ManagedConnectionMetadata, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        let result = transaction
            .execute_raw(statement(
                r"UPDATE managed_provider_connections
                  SET revision=revision+1, last_safe_outcome='revocation_requested',
                      revocation_requested_at=$1, revocation_disposition='revoke', updated_at=$1
                WHERE project_id=$2 AND user_id=$3 AND id=$4 AND state='active'
                  AND revision=$5 AND generation=$6 AND supports_revocation
                  AND revocation_requested_at IS NULL
                  AND (lease_expires_at IS NULL OR lease_expires_at<=$1)",
                vec![
                    now.into(),
                    project_id.into(),
                    user_id.into(),
                    connection_id.into(),
                    expected_revision.into(),
                    expected_generation.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        if result.rows_affected() != 1 {
            transaction.rollback().await.map_err(persistence)?;
            return Err(ApplicationError::RevisionConflict);
        }
        append_runtime_audit(
            &transaction,
            project_id,
            "deployment_operator",
            "managed_connection.revocation_requested",
            "managed_provider_connection",
            Some(connection_id),
            correlation_id,
        )
        .await?;
        let metadata = metadata_for_owner(&transaction, project_id, user_id, connection_id).await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(metadata)
    }

    async fn claim_next_revocation(
        &self,
        worker_id: Uuid,
        now: OffsetDateTime,
        lease_until: OffsetDateTime,
    ) -> Result<Option<ClaimedManagedCredential>, ApplicationError> {
        // A prior process may have crossed the destructive boundary and vanished. Recovery is
        // terminal-only: it must run before ordinary claiming and can never return ciphertext.
        terminalize_one_ambiguous_revocation(&self.database, now).await?;
        terminalize_one_stale_revocation(&self.database, now).await?;
        claim_connection(
            &self.database,
            worker_id,
            now,
            lease_until,
            "revocation",
            None,
        )
        .await
    }

    async fn claim_for_revocation(
        &self,
        project_id: Uuid,
        user_id: Uuid,
        connection_id: Uuid,
        expected_revision: i64,
        expected_generation: i64,
        worker_id: Uuid,
        now: OffsetDateTime,
        lease_until: OffsetDateTime,
    ) -> Result<ClaimedManagedCredential, ApplicationError> {
        if lease_until <= now {
            return Err(ApplicationError::InvalidInput);
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        let row = transaction.query_one_raw(statement(
            r"WITH locked AS (
                 SELECT connection.id
                   FROM projects AS project
                   LEFT JOIN project_provider_egress_policies AS egress ON egress.project_id=project.id
                   JOIN provider_configurations AS provider ON provider.project_id=project.id
                   JOIN project_users AS project_user ON project_user.project_id=project.id
                   JOIN linked_identities AS identity ON identity.project_id=project.id AND identity.user_id=project_user.id
                   JOIN managed_provider_connections AS connection
                     ON connection.project_id=project.id AND connection.provider_configuration_id=provider.id
                    AND connection.user_id=project_user.id AND connection.linked_identity_id=identity.id
                  WHERE project.id=$1 AND project.status='active' AND connection.id=$2
                    AND connection.user_id=$3 AND connection.state='active' AND connection.revision=$4
                    AND connection.generation=$5 AND provider.status='active'
                    AND connection.revocation_dispatch_started_at IS NULL
                    AND provider.revision=connection.provider_revision AND provider.managed_profile_enabled
                    AND provider.managed_profile_revision=connection.managed_profile_revision
                    AND project_user.status='active' AND project_user.security_revision=connection.user_security_revision
                    AND identity.status='active' AND identity.identity_revision=connection.identity_revision
                    AND (connection.lease_expires_at IS NULL OR connection.lease_expires_at<=$6)
                  FOR UPDATE OF project_user, identity, connection
               ), claimed AS (
                 UPDATE managed_provider_connections AS connection SET lease_owner=$7,
                        lease_kind='revocation', lease_expires_at=$8, updated_at=$6
                   FROM locked WHERE connection.project_id=$1 AND connection.id=locked.id
                 RETURNING connection.*
               )
               SELECT claimed.id, claimed.project_id, claimed.provider_configuration_id,
                      claimed.linked_identity_id, claimed.user_id, claimed.revision, claimed.generation,
                      claimed.credential_generation, project.security_revision AS project_security_revision,
                      claimed.provider_revision, claimed.managed_profile_revision,
                      claimed.adapter_key,claimed.adapter_capability_revision,
                      to_json(claimed.required_scopes) AS required_scopes,
                      claimed.user_security_revision, claimed.identity_revision,
                      claimed.consecutive_failures,provider.kind AS provider_legacy_kind,provider.adapter_kind AS provider_adapter_kind,provider.issuer, identity.subject, provider.client_id, COALESCE(provider.secret_material_id::TEXT, provider.secret_ref) AS secret_ref,
                      CASE WHEN provider.adapter_kind='oidc' THEN egress.revision ELSE NULL END
                        AS provider_egress_policy_revision,
                      egress.mode AS current_egress_mode,
                      egress.exact_origins AS current_egress_exact_origins,
                      egress.revision AS current_egress_policy_revision,
                      credential.key_version, credential.ciphertext
                 FROM claimed JOIN projects AS project ON project.id=claimed.project_id
                 LEFT JOIN project_provider_egress_policies AS egress ON egress.project_id=claimed.project_id
                 JOIN provider_configurations AS provider ON provider.project_id=claimed.project_id AND provider.id=claimed.provider_configuration_id
                 JOIN linked_identities AS identity ON identity.project_id=claimed.project_id AND identity.id=claimed.linked_identity_id
                 JOIN managed_provider_credentials AS credential ON credential.project_id=claimed.project_id
                  AND credential.connection_id=claimed.id AND credential.credential_generation=claimed.credential_generation
                  AND credential.ciphertext IS NOT NULL",
            vec![project_id.into(), connection_id.into(), user_id.into(), expected_revision.into(),
                 expected_generation.into(), now.into(), worker_id.into(), lease_until.into()],
        )).await.map_err(persistence)?.ok_or(ApplicationError::RevisionConflict)?;
        let claim = claim_from_row(&row, worker_id, lease_until, false)?;
        transaction.commit().await.map_err(persistence)?;
        Ok(claim)
    }

    async fn mark_revocation_dispatched(
        &self,
        claim: &ClaimedManagedCredential,
        now: OffsetDateTime,
    ) -> Result<bool, ApplicationError> {
        let guard = &claim.guard;
        let transaction = self.database.begin().await.map_err(persistence)?;
        if !lock_guard_authority(&transaction, guard).await? {
            transaction.rollback().await.map_err(persistence)?;
            return Ok(false);
        }
        let connection = transaction
            .query_one_raw(statement(
                r"SELECT id FROM managed_provider_connections
                    WHERE project_id=$1 AND id=$2 AND state='active' AND revision=$3
                      AND generation=$4 AND credential_generation=$5
                      AND revocation_requested_at IS NOT NULL
                      AND revocation_dispatch_started_at IS NULL
                      AND lease_owner=$6 AND lease_kind='revocation'
                      AND lease_expires_at=$7 AND lease_expires_at>$8 FOR UPDATE",
                vec![
                    guard.project_id.into(),
                    guard.connection_id.into(),
                    guard.connection_revision.into(),
                    guard.connection_generation.into(),
                    guard.credential_generation.into(),
                    claim.lease_owner.into(),
                    claim.lease_expires_at.into(),
                    now.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        if connection.is_none() {
            transaction.rollback().await.map_err(persistence)?;
            return Ok(false);
        }
        let destroyed = transaction
            .execute_raw(statement(
                r"UPDATE managed_provider_credentials SET ciphertext=NULL,destroyed_at=$1
                    WHERE project_id=$2 AND connection_id=$3 AND credential_generation=$4
                      AND ciphertext IS NOT NULL",
                vec![
                    now.into(),
                    guard.project_id.into(),
                    guard.connection_id.into(),
                    guard.credential_generation.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        if destroyed.rows_affected() != 1 {
            transaction.rollback().await.map_err(persistence)?;
            return Ok(false);
        }
        let marked = transaction
            .execute_raw(statement(
                r"UPDATE managed_provider_connections
                      SET revocation_dispatch_started_at=$1,revocation_attempt_id=$2,
                          last_safe_outcome='revocation_dispatch_started',updated_at=$1
                    WHERE project_id=$3 AND id=$4 AND revision=$5 AND generation=$6
                      AND lease_owner=$2 AND lease_kind='revocation'",
                vec![
                    now.into(),
                    claim.lease_owner.into(),
                    guard.project_id.into(),
                    guard.connection_id.into(),
                    guard.connection_revision.into(),
                    guard.connection_generation.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        if marked.rows_affected() != 1 {
            transaction.rollback().await.map_err(persistence)?;
            return Ok(false);
        }
        append_runtime_audit(
            &transaction,
            guard.project_id,
            "runtime_worker",
            "managed_connection.revocation_dispatch_started",
            "managed_provider_connection",
            Some(guard.connection_id),
            claim.lease_owner,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(true)
    }

    async fn finish_revocation(
        &self,
        claim: &ClaimedManagedCredential,
        result: crate::application::ProviderRevocationResult,
        now: OffsetDateTime,
    ) -> Result<ManagedConnectionMetadata, ApplicationError> {
        use crate::application::ProviderRevocationResult;
        let transaction = self.database.begin().await.map_err(persistence)?;
        let guard = &claim.guard;
        let row = transaction
            .query_one_raw(statement(
                r"SELECT revocation_disposition FROM managed_provider_connections
                    WHERE project_id=$1 AND id=$2 AND state='active' AND revision=$3
                      AND generation=$4 AND credential_generation=$5 AND lease_owner=$6
                      AND lease_kind='revocation' AND lease_expires_at>$7
                      AND revocation_dispatch_started_at IS NOT NULL
                      AND revocation_attempt_id=$6 FOR UPDATE",
                vec![
                    guard.project_id.into(),
                    guard.connection_id.into(),
                    guard.connection_revision.into(),
                    guard.connection_generation.into(),
                    guard.credential_generation.into(),
                    claim.lease_owner.into(),
                    now.into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::RevisionConflict)?;
        let disposition: String = get(&row, "revocation_disposition")?;
        let disconnect = disposition == "disconnect";
        if !disconnect && disposition != "revoke" {
            transaction.rollback().await.map_err(persistence)?;
            return Err(ApplicationError::Integrity);
        }
        let (state, outcome) = if disconnect {
            (
                "disconnected",
                match result {
                    ProviderRevocationResult::Confirmed => {
                        "disconnect_provider_revocation_confirmed"
                    }
                    ProviderRevocationResult::Unsupported => {
                        "disconnect_provider_revocation_unsupported"
                    }
                    ProviderRevocationResult::Ambiguous => {
                        "disconnect_provider_revocation_ambiguous"
                    }
                },
            )
        } else {
            match result {
                ProviderRevocationResult::Confirmed => ("revoked", "provider_revocation_confirmed"),
                ProviderRevocationResult::Ambiguous => {
                    ("reauth_required", "provider_revocation_ambiguous")
                }
                ProviderRevocationResult::Unsupported => (
                    "reauth_required",
                    "provider_revocation_unsupported_after_dispatch",
                ),
            }
        };
        // The pre-dispatch commit already destroyed this generation. Finishing is allowed only
        // while it remains inaccessible; no result path can restore or redispatch it.
        let inaccessible = lock_boolean(
            &transaction,
            "SELECT EXISTS (SELECT 1 FROM managed_provider_credentials WHERE project_id=$1 AND connection_id=$2 AND credential_generation=$3 AND ciphertext IS NULL AND destroyed_at IS NOT NULL FOR UPDATE)",
            vec![guard.project_id.into(), guard.connection_id.into(), guard.credential_generation.into()],
        )
        .await?;
        if !inaccessible {
            transaction.rollback().await.map_err(persistence)?;
            return Err(ApplicationError::Integrity);
        }
        let updated = transaction.execute_raw(statement(
            r"UPDATE managed_provider_connections SET state=$1,revision=revision+1,generation=generation+1,
                    last_safe_outcome=$2,next_synchronize_at=NULL,next_renewal_at=NULL,
                    revocation_requested_at=NULL,revocation_disposition=NULL,
                    revocation_dispatch_started_at=NULL,revocation_attempt_id=NULL,
                    supports_revocation=CASE WHEN $3 THEN FALSE ELSE supports_revocation END,
                    disconnected_at=CASE WHEN $4 THEN $5 ELSE disconnected_at END,
                    lease_owner=NULL,lease_kind=NULL,lease_expires_at=NULL,updated_at=$5
               WHERE project_id=$6 AND id=$7 AND revision=$8 AND generation=$9",
            vec![state.into(),outcome.into(),(result==ProviderRevocationResult::Unsupported).into(),
                 disconnect.into(),now.into(),guard.project_id.into(),guard.connection_id.into(),
                 guard.connection_revision.into(),guard.connection_generation.into()],
        )).await.map_err(persistence)?;
        if updated.rows_affected() != 1 {
            transaction.rollback().await.map_err(persistence)?;
            return Err(ApplicationError::RevisionConflict);
        }
        append_runtime_audit(
            &transaction,
            guard.project_id,
            "runtime_worker",
            "managed_connection.revoke",
            "managed_provider_connection",
            Some(guard.connection_id),
            claim.lease_owner,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        metadata_by_id(&self.database, guard.project_id, guard.connection_id).await
    }

    async fn release_revocation_claim(
        &self,
        claim: &ClaimedManagedCredential,
        now: OffsetDateTime,
    ) -> Result<bool, ApplicationError> {
        let guard = &claim.guard;
        let released = self
            .database
            .execute_raw(statement(
                r"UPDATE managed_provider_connections
                  SET lease_owner=NULL, lease_kind=NULL, lease_expires_at=NULL, updated_at=$1
                WHERE project_id=$2 AND id=$3 AND state='active' AND revision=$4 AND generation=$5
                  AND credential_generation=$6 AND lease_owner=$7 AND lease_kind='revocation'
                  AND revocation_dispatch_started_at IS NULL",
                vec![
                    now.into(),
                    guard.project_id.into(),
                    guard.connection_id.into(),
                    guard.connection_revision.into(),
                    guard.connection_generation.into(),
                    guard.credential_generation.into(),
                    claim.lease_owner.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        Ok(released.rows_affected() == 1)
    }

    async fn fence_successor_read_evidence(
        &self,
        claim: &SuccessorProfileClaim,
        revoked: bool,
        safe_outcome: &'static str,
        now: OffsetDateTime,
    ) -> Result<bool, ApplicationError> {
        let guard = &claim.guard;
        let transaction = self.database.begin().await.map_err(persistence)?;
        // UserInfo is external I/O. Re-lock every material authority class in canonical order
        // before consuming destructive evidence; a stale observation is simply discarded.
        if !lock_guard_authority(&transaction, guard).await? {
            transaction.rollback().await.map_err(persistence)?;
            return Ok(false);
        }
        // Lock the exact lifecycle row before touching ciphertext. Control-side destructive
        // requests take this same row lock, so either they win and this observation is discarded,
        // or this transaction atomically destroys and terminalizes before Control can proceed.
        let locked = transaction
            .query_one_raw(statement(
                r"SELECT id FROM managed_provider_connections
                WHERE project_id=$1 AND id=$2 AND state='active'
                  AND revision=$3 AND generation=$4 AND credential_generation=$5
                  AND project_security_revision=$6 AND provider_revision=$7
                  AND managed_profile_revision=$8 AND user_security_revision=$9
                  AND identity_revision=$10 AND revocation_requested_at IS NULL
                  AND revocation_dispatch_started_at IS NULL
                  AND lease_owner=$11 AND lease_kind='renewal'
                  AND lease_expires_at=$12 AND lease_expires_at>$13
                FOR UPDATE",
                vec![
                    guard.project_id.into(),
                    guard.connection_id.into(),
                    guard.connection_revision.into(),
                    guard.connection_generation.into(),
                    guard.credential_generation.into(),
                    guard.project_security_revision.into(),
                    guard.provider_revision.into(),
                    guard.managed_profile_revision.into(),
                    guard.user_security_revision.into(),
                    guard.identity_revision.into(),
                    claim.lease_owner.into(),
                    claim.lease_expires_at.into(),
                    now.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        if locked.is_none() {
            transaction.rollback().await.map_err(persistence)?;
            return Ok(false);
        }
        let destroyed = transaction
            .execute_raw(statement(
                r"UPDATE managed_provider_credentials SET ciphertext=NULL, destroyed_at=$1
                WHERE project_id=$2 AND connection_id=$3 AND connection_generation=$4
                  AND credential_generation=$5 AND ciphertext IS NOT NULL",
                vec![
                    now.into(),
                    guard.project_id.into(),
                    guard.connection_id.into(),
                    guard.connection_generation.into(),
                    guard.credential_generation.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        if destroyed.rows_affected() != 1 {
            transaction.rollback().await.map_err(persistence)?;
            return Ok(false);
        }
        let updated = transaction.execute_raw(statement(
            r"UPDATE managed_provider_connections SET state=$1, revision=revision+1, generation=generation+1,
                    last_safe_outcome=$2, next_synchronize_at=NULL, next_renewal_at=NULL,
                    lease_owner=NULL,lease_kind=NULL,lease_expires_at=NULL,updated_at=$3
               WHERE project_id=$4 AND id=$5 AND state='active' AND revision=$6 AND generation=$7
                 AND credential_generation=$8 AND project_security_revision=$9
                 AND provider_revision=$10 AND managed_profile_revision=$11
                 AND user_security_revision=$12 AND identity_revision=$13
                 AND revocation_requested_at IS NULL AND revocation_dispatch_started_at IS NULL
                 AND lease_owner=$14 AND lease_kind='renewal'
                 AND lease_expires_at=$15 AND lease_expires_at>$3",
            vec![if revoked { "revoked" } else { "reauth_required" }.into(), safe_outcome.into(), now.into(),
                 guard.project_id.into(), guard.connection_id.into(), guard.connection_revision.into(),
                 guard.connection_generation.into(), guard.credential_generation.into(),
                 guard.project_security_revision.into(), guard.provider_revision.into(),
                 guard.managed_profile_revision.into(), guard.user_security_revision.into(),
                 guard.identity_revision.into(), claim.lease_owner.into(),
                 claim.lease_expires_at.into()],
        )).await.map_err(persistence)?;
        if updated.rows_affected() != 1 {
            transaction.rollback().await.map_err(persistence)?;
            return Ok(false);
        }
        append_runtime_audit(
            &transaction,
            guard.project_id,
            "runtime_worker",
            "managed_connection.read_evidence",
            "managed_provider_connection",
            Some(guard.connection_id),
            Uuid::new_v4(),
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(updated.rows_affected() == 1)
    }

    async fn fence_read_evidence(
        &self,
        guard: &ConnectionGuard,
        revoked: bool,
        safe_outcome: &'static str,
        now: OffsetDateTime,
    ) -> Result<bool, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        // UserInfo is external I/O. Re-lock every material authority class in canonical order
        // before consuming destructive evidence; a stale observation is simply discarded.
        if !lock_guard_authority(&transaction, guard).await? {
            transaction.rollback().await.map_err(persistence)?;
            return Ok(false);
        }
        // Lock the exact lifecycle row before touching ciphertext. Control-side destructive
        // requests take this same row lock, so either they win and this observation is discarded,
        // or this transaction atomically destroys and terminalizes before Control can proceed.
        let locked = transaction
            .query_one_raw(statement(
                r"SELECT id FROM managed_provider_connections
                WHERE project_id=$1 AND id=$2 AND state='active'
                  AND revision=$3 AND generation=$4 AND credential_generation=$5
                  AND project_security_revision=$6 AND provider_revision=$7
                  AND managed_profile_revision=$8 AND user_security_revision=$9
                  AND identity_revision=$10 AND revocation_requested_at IS NULL
                  AND revocation_dispatch_started_at IS NULL
                FOR UPDATE",
                vec![
                    guard.project_id.into(),
                    guard.connection_id.into(),
                    guard.connection_revision.into(),
                    guard.connection_generation.into(),
                    guard.credential_generation.into(),
                    guard.project_security_revision.into(),
                    guard.provider_revision.into(),
                    guard.managed_profile_revision.into(),
                    guard.user_security_revision.into(),
                    guard.identity_revision.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        if locked.is_none() {
            transaction.rollback().await.map_err(persistence)?;
            return Ok(false);
        }
        let destroyed = transaction
            .execute_raw(statement(
                r"UPDATE managed_provider_credentials SET ciphertext=NULL, destroyed_at=$1
                WHERE project_id=$2 AND connection_id=$3 AND connection_generation=$4
                  AND credential_generation=$5 AND ciphertext IS NOT NULL",
                vec![
                    now.into(),
                    guard.project_id.into(),
                    guard.connection_id.into(),
                    guard.connection_generation.into(),
                    guard.credential_generation.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        if destroyed.rows_affected() != 1 {
            transaction.rollback().await.map_err(persistence)?;
            return Ok(false);
        }
        let updated = transaction.execute_raw(statement(
            r"UPDATE managed_provider_connections SET state=$1, revision=revision+1, generation=generation+1,
                    last_safe_outcome=$2, next_synchronize_at=NULL, next_renewal_at=NULL,
                    lease_owner=NULL,lease_kind=NULL,lease_expires_at=NULL,updated_at=$3
               WHERE project_id=$4 AND id=$5 AND state='active' AND revision=$6 AND generation=$7
                 AND credential_generation=$8 AND project_security_revision=$9
                 AND provider_revision=$10 AND managed_profile_revision=$11
                 AND user_security_revision=$12 AND identity_revision=$13
                 AND revocation_requested_at IS NULL AND revocation_dispatch_started_at IS NULL",
            vec![if revoked { "revoked" } else { "reauth_required" }.into(), safe_outcome.into(), now.into(),
                 guard.project_id.into(), guard.connection_id.into(), guard.connection_revision.into(),
                 guard.connection_generation.into(), guard.credential_generation.into(),
                 guard.project_security_revision.into(), guard.provider_revision.into(),
                 guard.managed_profile_revision.into(), guard.user_security_revision.into(),
                 guard.identity_revision.into()],
        )).await.map_err(persistence)?;
        if updated.rows_affected() != 1 {
            transaction.rollback().await.map_err(persistence)?;
            return Ok(false);
        }
        append_runtime_audit(
            &transaction,
            guard.project_id,
            "runtime_worker",
            "managed_connection.read_evidence",
            "managed_provider_connection",
            Some(guard.connection_id),
            Uuid::new_v4(),
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(updated.rows_affected() == 1)
    }

    async fn terminalize_unreadable_interactions(
        &self,
        readable_runtime_key_versions: &std::collections::BTreeSet<i32>,
        readable_target_key_versions: &std::collections::BTreeSet<i32>,
        limit: u64,
        now: OffsetDateTime,
    ) -> Result<u64, ApplicationError> {
        if readable_runtime_key_versions.is_empty()
            || readable_target_key_versions.is_empty()
            || limit == 0
            || limit > 1_024
        {
            return Err(ApplicationError::InvalidInput);
        }
        // Versions are validated positive integers owned by the local protector; rendering this
        // bounded set avoids relying on backend-specific array Value conversion.
        let runtime_versions = readable_runtime_key_versions
            .iter()
            .map(i32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let target_versions = readable_target_key_versions
            .iter()
            .map(i32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            r"WITH candidates AS (
                 SELECT interaction.id
                   FROM managed_provider_reauthorization_interactions AS interaction
                   LEFT JOIN managed_reauthorization_create_results AS result
                     ON result.interaction_id=interaction.id AND result.erased_at IS NULL
                  WHERE interaction.status IN ('awaiting_browser_binding','awaiting_provider_start',
                                               'provider_authorization_started','provider_exchange_in_progress')
                    AND interaction.expires_at>$1 AND (
                         interaction.interaction_digest_key_version NOT IN ({target_versions})
                      OR (interaction.browser_binding_key_version IS NOT NULL
                          AND interaction.browser_binding_key_version NOT IN ({runtime_versions}))
                      OR (interaction.csrf_key_version IS NOT NULL
                          AND interaction.csrf_key_version NOT IN ({runtime_versions}))
                      OR (interaction.upstream_state_key_version IS NOT NULL
                          AND interaction.upstream_state_key_version NOT IN ({runtime_versions}))
                      OR (interaction.oidc_nonce_key_version IS NOT NULL
                          AND interaction.oidc_nonce_key_version NOT IN ({runtime_versions}))
                      OR (interaction.provider_pkce_key_version IS NOT NULL
                          AND interaction.provider_pkce_key_version NOT IN ({runtime_versions}))
                      OR (result.create_result_key_version IS NOT NULL
                          AND result.create_result_key_version NOT IN ({target_versions})))
                  ORDER BY interaction.expires_at,interaction.id
                  FOR UPDATE OF interaction SKIP LOCKED LIMIT $2
               ), terminalized AS (
                 UPDATE managed_provider_reauthorization_interactions AS interaction
                    SET status='cancelled',revision=revision+1,terminal_at=$1,
                        interaction_digest=NULL,interaction_digest_key_version=NULL,
                        browser_binding_digest=NULL,browser_binding_key_version=NULL,
                        csrf_digest=NULL,csrf_key_version=NULL,
                        upstream_state_digest=NULL,upstream_state_key_version=NULL,
                        oidc_nonce_digest=NULL,oidc_nonce_key_version=NULL,
                        provider_pkce_ciphertext=NULL,provider_pkce_key_version=NULL
                   FROM candidates
                  WHERE interaction.id=candidates.id
              RETURNING interaction.id,interaction.project_id
               ) SELECT id,project_id FROM terminalized"
        );
        let limit = i64::try_from(limit).map_err(|_| ApplicationError::InvalidInput)?;
        let transaction = self.database.begin().await.map_err(persistence)?;
        let rows = transaction
            .query_all_raw(statement(&sql, vec![now.into(), limit.into()]))
            .await
            .map_err(persistence)?;
        for row in &rows {
            let interaction_id: Uuid = get(row, "id")?;
            let project_id: Uuid = get(row, "project_id")?;
            // The encrypted Control create result is not callback material. Retain it through the
            // interaction deadline even when Runtime can no longer read its key version; the
            // deadline sweep owns deterministic tombstoning.
            append_runtime_audit(
                &transaction,
                project_id,
                "runtime_restore",
                "managed_reauthorization.unreadable_key_terminalized",
                "managed_reauthorization",
                Some(interaction_id),
                Uuid::new_v4(),
            )
            .await?;
        }
        transaction.commit().await.map_err(persistence)?;
        Ok(rows.len() as u64)
    }

    async fn terminalize_expired_interactions(
        &self,
        limit: u64,
        now: OffsetDateTime,
    ) -> Result<u64, ApplicationError> {
        if limit == 0 || limit > 1_024 {
            return Err(ApplicationError::InvalidInput);
        }
        let limit = i64::try_from(limit).map_err(|_| ApplicationError::InvalidInput)?;
        let transaction = self.database.begin().await.map_err(persistence)?;
        let rows = transaction
            .query_all_raw(statement(
                r"WITH candidates AS (
                     SELECT interaction.id
                       FROM managed_provider_reauthorization_interactions AS interaction
                      WHERE interaction.expires_at<=$1 AND (
                            interaction.status NOT IN
                              ('completed','provider_exchange_failed','expired','cancelled')
                         OR (interaction.status IN ('completed','provider_exchange_failed') AND
                             (interaction.upstream_state_digest IS NOT NULL OR
                              interaction.browser_binding_digest IS NOT NULL))
                         OR (interaction.status='cancelled' AND EXISTS (
                               SELECT 1
                                 FROM managed_reauthorization_create_results AS result
                                WHERE result.interaction_id=interaction.id
                                  AND result.expires_at<=$1
                                  AND result.request_digest IS NOT NULL
                                  AND result.create_result_ciphertext IS NOT NULL
                                  AND result.erased_at IS NULL)))
                      ORDER BY interaction.expires_at,interaction.id
                      FOR UPDATE OF interaction SKIP LOCKED LIMIT $2
                   ), terminalized AS (
                     UPDATE managed_provider_reauthorization_interactions AS interaction
                        SET status=CASE
                              WHEN interaction.status IN
                                ('completed','provider_exchange_failed','cancelled')
                              THEN interaction.status ELSE 'expired' END,
                            revision=revision+CASE
                              WHEN interaction.status='cancelled' THEN 0 ELSE 1 END,
                            terminal_at=COALESCE(terminal_at,$1),
                            interaction_digest=NULL,interaction_digest_key_version=NULL,
                            browser_binding_digest=NULL,browser_binding_key_version=NULL,
                            csrf_digest=NULL,csrf_key_version=NULL,
                            upstream_state_digest=NULL,upstream_state_key_version=NULL,
                            oidc_nonce_digest=NULL,oidc_nonce_key_version=NULL,
                            provider_pkce_ciphertext=NULL,provider_pkce_key_version=NULL
                       FROM candidates WHERE interaction.id=candidates.id
                  RETURNING interaction.id,interaction.project_id,interaction.status
                   ) SELECT id,project_id,status FROM terminalized",
                vec![now.into(), limit.into()],
            ))
            .await
            .map_err(persistence)?;
        for row in &rows {
            let interaction_id: Uuid = get(row, "id")?;
            let project_id: Uuid = get(row, "project_id")?;
            let status: String = get(row, "status")?;
            let erased = transaction
                .execute_raw(statement(
                    r"UPDATE managed_reauthorization_create_results
                         SET request_digest=NULL,create_result_ciphertext=NULL,erased_at=$1
                       WHERE interaction_id=$2 AND expires_at<=$1 AND erased_at IS NULL",
                    vec![now.into(), interaction_id.into()],
                ))
                .await
                .map_err(persistence)?;
            if status == "cancelled" && erased.rows_affected() != 1 {
                transaction.rollback().await.map_err(persistence)?;
                return Err(ApplicationError::Integrity);
            }
            append_runtime_audit(
                &transaction,
                project_id,
                "runtime_worker",
                "managed_reauthorization.expired_swept",
                "managed_reauthorization",
                Some(interaction_id),
                Uuid::new_v4(),
            )
            .await?;
        }
        transaction.commit().await.map_err(persistence)?;
        Ok(rows.len() as u64)
    }

    async fn required_key_versions(
        &self,
    ) -> Result<std::collections::BTreeSet<i32>, ApplicationError> {
        let rows = self.database.query_all_raw(statement(
            r"SELECT DISTINCT credential.key_version
                 FROM managed_provider_credentials AS credential
                 JOIN managed_provider_connections AS connection
                   ON connection.project_id=credential.project_id AND connection.id=credential.connection_id
                 LEFT JOIN managed_provider_renewal_operations AS operation
                   ON operation.project_id=credential.project_id AND operation.connection_id=credential.connection_id
                  AND operation.expected_credential_generation=credential.credential_generation
                WHERE credential.ciphertext IS NOT NULL AND (
                      (connection.state='active' AND connection.credential_generation=credential.credential_generation)
                      OR operation.state IN ('prepared','submitted'))",
            vec![],
        )).await.map_err(persistence)?;
        rows.into_iter()
            .map(|row| get(&row, "key_version"))
            .collect()
    }

    async fn claim_next_rewrap(
        &self,
        worker_id: Uuid,
        target_key_version: i32,
        now: OffsetDateTime,
        lease_until: OffsetDateTime,
    ) -> Result<Option<ClaimedManagedCredential>, ApplicationError> {
        claim_connection(
            &self.database,
            worker_id,
            now,
            lease_until,
            "rewrap",
            Some(target_key_version),
        )
        .await
    }

    async fn finish_rewrap(
        &self,
        claim: &ClaimedManagedCredential,
        expected_key_version: i32,
        protected: ProtectedValue,
        now: OffsetDateTime,
    ) -> Result<bool, ApplicationError> {
        if expected_key_version <= 0
            || protected.key_version <= 0
            || protected.ciphertext.len() < 40
        {
            return Err(ApplicationError::InvalidInput);
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        let guard = &claim.guard;
        let updated = transaction
            .execute_raw(statement(
                r"UPDATE managed_provider_credentials AS credential
                  SET key_version=$1, ciphertext=$2
                 FROM managed_provider_connections AS connection
                WHERE connection.project_id=$3 AND connection.id=$4 AND connection.state='active'
                  AND connection.revision=$5 AND connection.generation=$6
                  AND connection.credential_generation=$7 AND connection.lease_owner=$8
                  AND connection.lease_kind='rewrap' AND connection.lease_expires_at>$9
                  AND credential.project_id=connection.project_id
                  AND credential.connection_id=connection.id
                  AND credential.credential_generation=connection.credential_generation
                  AND credential.key_version=$10 AND credential.ciphertext IS NOT NULL",
                vec![
                    protected.key_version.into(),
                    protected.ciphertext.into(),
                    guard.project_id.into(),
                    guard.connection_id.into(),
                    guard.connection_revision.into(),
                    guard.connection_generation.into(),
                    guard.credential_generation.into(),
                    claim.lease_owner.into(),
                    now.into(),
                    expected_key_version.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        if updated.rows_affected() != 1 {
            transaction.rollback().await.map_err(persistence)?;
            return Ok(false);
        }
        transaction
            .execute_raw(statement(
                r"UPDATE managed_provider_connections SET lease_owner=NULL, lease_kind=NULL,
                    lease_expires_at=NULL, updated_at=$1
                WHERE project_id=$2 AND id=$3 AND lease_owner=$4 AND lease_kind='rewrap'",
                vec![
                    now.into(),
                    guard.project_id.into(),
                    guard.connection_id.into(),
                    claim.lease_owner.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        append_runtime_audit(
            &transaction,
            guard.project_id,
            "runtime_worker",
            "managed_connection.credential_rewrapped",
            "managed_provider_connection",
            Some(guard.connection_id),
            claim.lease_owner,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(true)
    }

    async fn rewrap_credential(
        &self,
        guard: &ConnectionGuard,
        expected_key_version: i32,
        protected: ProtectedValue,
        now: OffsetDateTime,
    ) -> Result<bool, ApplicationError> {
        if expected_key_version <= 0
            || protected.key_version <= 0
            || protected.ciphertext.len() < 40
        {
            return Err(ApplicationError::InvalidInput);
        }
        let result = self.database.execute_raw(statement(
            r"UPDATE managed_provider_credentials AS credential SET key_version=$1, ciphertext=$2
                 FROM managed_provider_connections AS connection
                WHERE connection.project_id=$3 AND connection.id=$4 AND connection.state='active'
                  AND connection.revision=$5 AND connection.generation=$6
                  AND connection.credential_generation=$7 AND credential.project_id=connection.project_id
                  AND credential.connection_id=connection.id
                  AND credential.credential_generation=connection.credential_generation
                  AND credential.key_version=$8 AND credential.ciphertext IS NOT NULL
                  AND $9 >= credential.created_at",
            vec![protected.key_version.into(), protected.ciphertext.into(), guard.project_id.into(), guard.connection_id.into(),
                 guard.connection_revision.into(), guard.connection_generation.into(), guard.credential_generation.into(),
                 expected_key_version.into(), now.into()],
        )).await.map_err(persistence)?;
        Ok(result.rows_affected() == 1)
    }
}

async fn terminalize_one_ambiguous_revocation(
    database: &DatabaseConnection,
    now: OffsetDateTime,
) -> Result<bool, ApplicationError> {
    let transaction = database.begin().await.map_err(persistence)?;
    let row = transaction
        .query_one_raw(statement(
            r"SELECT connection.id,connection.project_id,connection.revocation_disposition,
                     connection.revision,connection.generation,connection.credential_generation,
                     connection.revocation_attempt_id
                FROM managed_provider_connections AS connection
               WHERE connection.state='active'
                 AND connection.revocation_dispatch_started_at IS NOT NULL
                 AND connection.revocation_attempt_id IS NOT NULL
                 AND connection.revocation_requested_at IS NOT NULL
                 AND (connection.lease_expires_at IS NULL OR connection.lease_expires_at<=$1)
               ORDER BY connection.revocation_dispatch_started_at,connection.id
               FOR UPDATE OF connection SKIP LOCKED LIMIT 1",
            vec![now.into()],
        ))
        .await
        .map_err(persistence)?;
    let Some(row) = row else {
        transaction.commit().await.map_err(persistence)?;
        return Ok(false);
    };
    let connection_id: Uuid = get(&row, "id")?;
    let project_id: Uuid = get(&row, "project_id")?;
    let revision: i64 = get(&row, "revision")?;
    let generation: i64 = get(&row, "generation")?;
    let credential_generation: i64 = get(&row, "credential_generation")?;
    let attempt_id: Uuid = get(&row, "revocation_attempt_id")?;
    let disconnect = get::<String>(&row, "revocation_disposition")? == "disconnect";
    let inaccessible = lock_boolean(
        &transaction,
        "SELECT EXISTS (SELECT 1 FROM managed_provider_credentials WHERE project_id=$1 AND connection_id=$2 AND credential_generation=$3 AND ciphertext IS NULL AND destroyed_at IS NOT NULL FOR UPDATE)",
        vec![project_id.into(), connection_id.into(), credential_generation.into()],
    )
    .await?;
    if !inaccessible {
        transaction.rollback().await.map_err(persistence)?;
        return Err(ApplicationError::Integrity);
    }
    let updated = transaction
        .execute_raw(statement(
            r"UPDATE managed_provider_connections
                  SET state=CASE WHEN $1 THEN 'disconnected' ELSE 'reauth_required' END,
                      revision=revision+1,generation=generation+1,
                      last_safe_outcome=CASE WHEN $1
                         THEN 'disconnect_provider_result_unknown'
                         ELSE 'provider_revocation_result_unknown' END,
                      next_synchronize_at=NULL,next_renewal_at=NULL,
                      revocation_requested_at=NULL,revocation_disposition=NULL,
                      revocation_dispatch_started_at=NULL,revocation_attempt_id=NULL,
                      disconnected_at=CASE WHEN $1 THEN $2 ELSE disconnected_at END,
                      lease_owner=NULL,lease_kind=NULL,lease_expires_at=NULL,updated_at=$2
                WHERE project_id=$3 AND id=$4 AND revision=$5 AND generation=$6
                  AND revocation_attempt_id=$7",
            vec![
                disconnect.into(),
                now.into(),
                project_id.into(),
                connection_id.into(),
                revision.into(),
                generation.into(),
                attempt_id.into(),
            ],
        ))
        .await
        .map_err(persistence)?;
    if updated.rows_affected() != 1 {
        transaction.rollback().await.map_err(persistence)?;
        return Ok(false);
    }
    append_runtime_audit(
        &transaction,
        project_id,
        "runtime_worker",
        "managed_connection.revocation_result_unknown",
        "managed_provider_connection",
        Some(connection_id),
        attempt_id,
    )
    .await?;
    transaction.commit().await.map_err(persistence)?;
    Ok(true)
}

async fn terminalize_one_stale_revocation(
    database: &DatabaseConnection,
    now: OffsetDateTime,
) -> Result<bool, ApplicationError> {
    let transaction = database.begin().await.map_err(persistence)?;
    let row = transaction
        .query_one_raw(statement(
            r"SELECT connection.id,connection.project_id,connection.revocation_disposition,
                     connection.revision,connection.generation,connection.credential_generation
                FROM managed_provider_connections AS connection
               WHERE connection.state='active' AND connection.revocation_requested_at IS NOT NULL
                 AND NOT EXISTS (
                     SELECT 1 FROM projects AS project
                     JOIN provider_configurations AS provider
                       ON provider.project_id=project.id
                     JOIN project_users AS project_user
                       ON project_user.project_id=project.id
                     JOIN linked_identities AS identity
                       ON identity.project_id=project.id AND identity.user_id=project_user.id
                    WHERE project.id=connection.project_id AND project.status='active'
                      AND project.security_revision=connection.project_security_revision
                      AND provider.id=connection.provider_configuration_id
                      AND provider.status='active' AND provider.managed_profile_enabled
                      AND provider.revision=connection.provider_revision
                      AND provider.managed_profile_revision=connection.managed_profile_revision
                      AND project_user.id=connection.user_id AND project_user.status='active'
                      AND project_user.security_revision=connection.user_security_revision
                      AND identity.id=connection.linked_identity_id AND identity.status='active'
                      AND identity.identity_revision=connection.identity_revision)
               ORDER BY connection.revocation_requested_at,connection.id
               FOR UPDATE OF connection SKIP LOCKED LIMIT 1",
            vec![],
        ))
        .await
        .map_err(persistence)?;
    let Some(row) = row else {
        transaction.commit().await.map_err(persistence)?;
        return Ok(false);
    };
    let connection_id: Uuid = get(&row, "id")?;
    let project_id: Uuid = get(&row, "project_id")?;
    let revision: i64 = get(&row, "revision")?;
    let generation: i64 = get(&row, "generation")?;
    let credential_generation: i64 = get(&row, "credential_generation")?;
    let disconnect = get::<String>(&row, "revocation_disposition")? == "disconnect";
    transaction
        .execute_raw(statement(
            r"UPDATE managed_provider_credentials SET ciphertext=NULL,destroyed_at=$1
                WHERE project_id=$2 AND connection_id=$3 AND credential_generation=$4
                  AND ciphertext IS NOT NULL",
            vec![
                now.into(),
                project_id.into(),
                connection_id.into(),
                credential_generation.into(),
            ],
        ))
        .await
        .map_err(persistence)?;
    let updated = transaction
        .execute_raw(statement(
            r"UPDATE managed_provider_connections
                  SET state=CASE WHEN $1 THEN 'disconnected' ELSE 'reauth_required' END,
                      revision=revision+1,generation=generation+1,
                      last_safe_outcome='revocation_authority_stale',
                      next_synchronize_at=NULL,next_renewal_at=NULL,
                      revocation_requested_at=NULL,revocation_disposition=NULL,
                      revocation_dispatch_started_at=NULL,revocation_attempt_id=NULL,
                      disconnected_at=CASE WHEN $1 THEN $2 ELSE disconnected_at END,
                      lease_owner=NULL,lease_kind=NULL,lease_expires_at=NULL,updated_at=$2
                WHERE project_id=$3 AND id=$4 AND revision=$5 AND generation=$6",
            vec![
                disconnect.into(),
                now.into(),
                project_id.into(),
                connection_id.into(),
                revision.into(),
                generation.into(),
            ],
        ))
        .await
        .map_err(persistence)?;
    if updated.rows_affected() != 1 {
        transaction.rollback().await.map_err(persistence)?;
        return Ok(false);
    }
    append_runtime_audit(
        &transaction,
        project_id,
        "runtime_worker",
        "managed_connection.revocation_authority_stale",
        "managed_provider_connection",
        Some(connection_id),
        Uuid::new_v4(),
    )
    .await?;
    transaction.commit().await.map_err(persistence)?;
    Ok(true)
}

async fn claim_connection(
    database: &DatabaseConnection,
    worker_id: Uuid,
    now: OffsetDateTime,
    lease_until: OffsetDateTime,
    kind: &'static str,
    target_key_version: Option<i32>,
) -> Result<Option<ClaimedManagedCredential>, ApplicationError> {
    let transaction = database.begin().await.map_err(persistence)?;
    let claim = claim_connection_on(
        &transaction,
        worker_id,
        now,
        lease_until,
        kind,
        target_key_version,
    )
    .await?;
    transaction.commit().await.map_err(persistence)?;
    Ok(claim)
}

#[allow(
    clippy::too_many_lines,
    reason = "the single SQL claim preserves one atomic provider-budget and generation fence"
)]
async fn claim_connection_on<C: ConnectionTrait>(
    connection: &C,
    worker_id: Uuid,
    now: OffsetDateTime,
    lease_until: OffsetDateTime,
    kind: &'static str,
    target_key_version: Option<i32>,
) -> Result<Option<ClaimedManagedCredential>, ApplicationError> {
    if lease_until <= now || !matches!(kind, "read" | "renewal" | "revocation" | "rewrap") {
        return Err(ApplicationError::InvalidInput);
    }
    if (kind == "rewrap") != target_key_version.is_some() {
        return Err(ApplicationError::InvalidInput);
    }
    if target_key_version.is_some_and(|version| version <= 0) {
        return Err(ApplicationError::InvalidInput);
    }
    let row = connection.query_one_raw(statement(
        r"WITH candidate AS (
             SELECT connection.id
               FROM managed_provider_connections AS connection
               JOIN projects AS project ON project.id = connection.project_id
               LEFT JOIN project_provider_egress_policies AS egress
                 ON egress.project_id = connection.project_id
               JOIN provider_configurations AS provider
                 ON provider.project_id = connection.project_id AND provider.id = connection.provider_configuration_id
               JOIN project_users AS project_user
                 ON project_user.project_id = connection.project_id AND project_user.id = connection.user_id
               JOIN linked_identities AS identity
                 ON identity.project_id = connection.project_id AND identity.id = connection.linked_identity_id
               JOIN managed_provider_claim_fairness AS fairness
                 ON fairness.project_id=connection.project_id
                AND fairness.provider_configuration_id=connection.provider_configuration_id
                AND fairness.queue_kind='outbound'
              WHERE connection.state = 'active'
                AND ($3<>'revocation' OR connection.revocation_dispatch_started_at IS NULL)
                AND ($3='revocation' OR connection.revocation_requested_at IS NULL)
                AND CASE
                      WHEN $3 = 'read' THEN connection.next_synchronize_at <= $1
                      WHEN $3 = 'revocation' THEN connection.revocation_requested_at IS NOT NULL
                      WHEN $3 = 'rewrap' THEN EXISTS (
                        SELECT 1 FROM managed_provider_credentials AS rewrap_credential
                         WHERE rewrap_credential.project_id=connection.project_id
                           AND rewrap_credential.connection_id=connection.id
                           AND rewrap_credential.credential_generation=connection.credential_generation
                           AND rewrap_credential.ciphertext IS NOT NULL
                           AND rewrap_credential.key_version<>$5
                      )
                      ELSE LEAST(
                        COALESCE(connection.next_synchronize_at, 'infinity'::timestamptz),
                        COALESCE(connection.next_renewal_at, 'infinity'::timestamptz)
                      ) <= $1
                    END
                AND (connection.lease_expires_at IS NULL OR connection.lease_expires_at <= $1)
                AND (fairness.lease_expires_at IS NULL OR fairness.lease_expires_at <= $1
                     OR NOT EXISTS (
                       SELECT 1 FROM managed_provider_connections AS budget_holder
                        WHERE budget_holder.project_id=connection.project_id
                          AND budget_holder.provider_configuration_id=connection.provider_configuration_id
                          AND budget_holder.lease_owner=fairness.lease_owner
                          AND budget_holder.lease_expires_at>$1))
                AND ($3='rewrap' OR (
                    project.status='active' AND project.security_revision=connection.project_security_revision
                    AND provider.status='active' AND provider.managed_profile_enabled
                    AND provider.revision=connection.provider_revision
                    AND provider.managed_profile_revision=connection.managed_profile_revision
                    AND project_user.status='active'
                    AND project_user.security_revision=connection.user_security_revision
                    AND identity.status='active'
                    AND identity.identity_revision=connection.identity_revision))
              ORDER BY fairness.last_claimed_at ASC NULLS FIRST,
                       CASE
                         WHEN $3 = 'read' THEN connection.next_synchronize_at
                         WHEN $3 = 'revocation' THEN connection.revocation_requested_at
                         WHEN $3 = 'rewrap' THEN connection.updated_at
                         ELSE LEAST(
                           COALESCE(connection.next_synchronize_at, 'infinity'::timestamptz),
                           COALESCE(connection.next_renewal_at, 'infinity'::timestamptz)
                         )
                       END,
                       connection.project_id, connection.provider_configuration_id, connection.id
              FOR UPDATE OF connection, fairness SKIP LOCKED LIMIT 1
          ), claimed AS (
             UPDATE managed_provider_connections AS connection
                SET lease_owner = $2, lease_kind = $3, lease_expires_at = $4, updated_at = $1
               FROM candidate WHERE connection.id = candidate.id
             RETURNING connection.*
          )
          SELECT claimed.id, claimed.project_id, claimed.provider_configuration_id,
                 claimed.linked_identity_id, claimed.user_id, claimed.revision, claimed.generation,
                 claimed.credential_generation, project.security_revision AS project_security_revision,
                 claimed.provider_revision, claimed.managed_profile_revision,
                 claimed.adapter_key,claimed.adapter_capability_revision,
                 to_json(claimed.required_scopes) AS required_scopes,
                 claimed.user_security_revision, claimed.identity_revision,
                 claimed.consecutive_failures,provider.kind AS provider_legacy_kind,provider.adapter_kind AS provider_adapter_kind,provider.issuer, identity.subject,
                 provider.client_id, COALESCE(provider.secret_material_id::TEXT, provider.secret_ref) AS secret_ref,
                 CASE WHEN provider.adapter_kind='oidc' THEN egress.revision ELSE NULL END
                   AS provider_egress_policy_revision,
                 egress.mode AS current_egress_mode,
                 egress.exact_origins AS current_egress_exact_origins,
                 egress.revision AS current_egress_policy_revision,
                 credential.key_version, credential.ciphertext
            FROM claimed JOIN projects AS project ON project.id = claimed.project_id
            LEFT JOIN project_provider_egress_policies AS egress ON egress.project_id=claimed.project_id
            JOIN provider_configurations AS provider
              ON provider.project_id = claimed.project_id AND provider.id = claimed.provider_configuration_id
            JOIN linked_identities AS identity
              ON identity.project_id = claimed.project_id AND identity.id = claimed.linked_identity_id
            JOIN managed_provider_credentials AS credential
              ON credential.project_id = claimed.project_id AND credential.connection_id = claimed.id
             AND credential.credential_generation = claimed.credential_generation
             AND credential.ciphertext IS NOT NULL",
        vec![
            now.into(),
            worker_id.into(),
            kind.into(),
            lease_until.into(),
            target_key_version.into(),
        ],
    )).await.map_err(persistence)?;
    let Some(row) = row else {
        return Ok(None);
    };
    record_claim_fairness(connection, &row, kind, worker_id, now, lease_until).await?;
    Ok(Some(claim_from_row(&row, worker_id, lease_until, false)?))
}

async fn record_claim_fairness<C: ConnectionTrait>(
    connection: &C,
    row: &sea_orm::QueryResult,
    _kind: &'static str,
    worker_id: Uuid,
    now: OffsetDateTime,
    lease_until: OffsetDateTime,
) -> Result<(), ApplicationError> {
    let project_id: Uuid = get(row, "project_id")?;
    let provider_id: Uuid = get(row, "provider_configuration_id")?;
    let acquired = connection
        .execute_raw(statement(
            r"UPDATE managed_provider_claim_fairness
                  SET last_claimed_at=$4,lease_owner=$5,lease_expires_at=$6
                WHERE project_id=$1 AND provider_configuration_id=$2 AND queue_kind=$3
                  AND (lease_expires_at IS NULL OR lease_expires_at<=$4
                       OR NOT EXISTS (
                          SELECT 1 FROM managed_provider_connections AS budget_holder
                           WHERE budget_holder.project_id=$1
                             AND budget_holder.provider_configuration_id=$2
                             AND budget_holder.lease_owner=managed_provider_claim_fairness.lease_owner
                             AND budget_holder.lease_expires_at>$4))",
            vec![
                project_id.into(),
                provider_id.into(),
                "outbound".into(),
                now.into(),
                worker_id.into(),
                lease_until.into(),
            ],
        ))
        .await
        .map_err(persistence)?;
    if acquired.rows_affected() != 1 {
        return Err(ApplicationError::RevisionConflict);
    }
    Ok(())
}

fn claim_from_row(
    row: &sea_orm::QueryResult,
    worker_id: Uuid,
    lease_until: OffsetDateTime,
    allow_stale_policy_for_terminalization: bool,
) -> Result<ClaimedManagedCredential, ApplicationError> {
    let provider_kind = super::provider_row::effective_provider_kind(
        &get::<String>(row, "provider_legacy_kind")?,
        get::<Option<String>>(row, "provider_adapter_kind")?.as_deref(),
        &get::<String>(row, "issuer")?,
    )?;
    let provider_egress_policy_revision =
        get::<Option<i64>>(row, "provider_egress_policy_revision")?;
    let egress_policy = if provider_kind == ProviderKind::Oidc {
        let current_revision = get::<i64>(row, "current_egress_policy_revision")?;
        if provider_egress_policy_revision == Some(current_revision) {
            Some(provider_egress_policy_from_row(row)?)
        } else if allow_stale_policy_for_terminalization
            && provider_egress_policy_revision.is_some()
        {
            // A stale submitted operation must remain decodable only so the service can
            // terminalize it without another provider dispatch. Withhold the current policy so
            // the guard is not dispatch-capable even if a caller violates that protocol branch.
            None
        } else {
            return Err(ApplicationError::RevisionConflict);
        }
    } else {
        if provider_egress_policy_revision.is_some() {
            return Err(ApplicationError::Integrity);
        }
        None
    };
    Ok(ClaimedManagedCredential {
        guard: ConnectionGuard {
            connection_id: get(row, "id")?,
            project_id: get(row, "project_id")?,
            provider_configuration_id: get(row, "provider_configuration_id")?,
            linked_identity_id: get(row, "linked_identity_id")?,
            user_id: get(row, "user_id")?,
            connection_revision: get(row, "revision")?,
            connection_generation: get(row, "generation")?,
            credential_generation: get(row, "credential_generation")?,
            project_security_revision: get(row, "project_security_revision")?,
            provider_revision: get(row, "provider_revision")?,
            provider_egress_policy_revision,
            egress_policy,
            managed_profile_revision: get(row, "managed_profile_revision")?,
            provider_kind,
            adapter_key: get(row, "adapter_key")?,
            adapter_capability_revision: get(row, "adapter_capability_revision")?,
            required_scopes: json_strings(&get(row, "required_scopes")?)?,
            user_security_revision: get(row, "user_security_revision")?,
            identity_revision: get(row, "identity_revision")?,
            consecutive_failures: get(row, "consecutive_failures")?,
            issuer: get(row, "issuer")?,
            subject: get(row, "subject")?,
            client_id: get(row, "client_id")?,
            secret_ref: get::<Option<String>>(row, "secret_ref")?
                .ok_or(ApplicationError::Integrity)?,
        },
        protected: ProtectedValue {
            key_version: get(row, "key_version")?,
            ciphertext: get(row, "ciphertext")?,
        },
        lease_owner: worker_id,
        lease_expires_at: lease_until,
    })
}

fn provider_egress_policy_from_row(
    row: &sea_orm::QueryResult,
) -> Result<ProviderEgressPolicy, ApplicationError> {
    super::provider_row::decode_provider_egress_policy(
        &get::<String>(row, "current_egress_mode")?,
        get(row, "current_egress_exact_origins")?,
    )
}

fn prepared_from_row(
    row: &sea_orm::QueryResult,
    worker_id: Uuid,
    lease_until: OffsetDateTime,
) -> Result<PreparedRenewal, ApplicationError> {
    let operation_state = match get::<String>(row, "operation_state")?.as_str() {
        "prepared" => RenewalOperationState::Prepared,
        "submitted" => RenewalOperationState::Submitted,
        _ => return Err(ApplicationError::Integrity),
    };
    let authority_valid: bool = get(row, "authority_valid")?;
    let allow_stale_policy_for_terminalization =
        operation_state == RenewalOperationState::Submitted && !authority_valid;
    Ok(PreparedRenewal {
        operation_id: get(row, "operation_id")?,
        attempt_id: get(row, "attempt_id")?,
        claim: claim_from_row(
            row,
            worker_id,
            lease_until,
            allow_stale_policy_for_terminalization,
        )?,
        adapter_idempotent_replay: get(row, "adapter_idempotent_replay")?,
        authority_valid,
        operation_state,
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "all lifecycle authority fences are intentionally explicit"
)]
async fn lock_guard_authority<C: ConnectionTrait>(
    connection: &C,
    guard: &ConnectionGuard,
) -> Result<bool, ApplicationError> {
    // Global lock order: Project -> provider -> user -> identity. Separate statements avoid
    // allowing a PostgreSQL join plan to choose a conflicting row-lock order.
    let project_ok = lock_boolean(
        connection,
        "SELECT EXISTS (SELECT 1 FROM projects WHERE id=$1 AND status='active' AND security_revision=$2 FOR SHARE)",
        vec![guard.project_id.into(), guard.project_security_revision.into()],
    )
    .await?;
    let policy_ok = lock_guard_egress_policy(connection, guard).await?;
    let provider_ok = lock_boolean(
        connection,
        "SELECT EXISTS (SELECT 1 FROM provider_configurations WHERE project_id=$1 AND id=$2 AND status='active' AND revision=$3 AND managed_profile_enabled AND managed_profile_revision=$4 AND kind='oidc' AND adapter_kind=$5 FOR SHARE)",
        vec![guard.project_id.into(), guard.provider_configuration_id.into(), guard.provider_revision.into(), guard.managed_profile_revision.into(), guard.provider_kind.as_str().into()],
    )
    .await?;
    let user_ok = lock_boolean(
        connection,
        "SELECT EXISTS (SELECT 1 FROM project_users WHERE project_id=$1 AND id=$2 AND status='active' AND security_revision=$3 FOR UPDATE)",
        vec![guard.project_id.into(), guard.user_id.into(), guard.user_security_revision.into()],
    )
    .await?;
    let identity_ok = lock_boolean(
        connection,
        "SELECT EXISTS (SELECT 1 FROM linked_identities WHERE project_id=$1 AND id=$2 AND user_id=$3 AND status='active' AND identity_revision=$4 FOR UPDATE)",
        vec![guard.project_id.into(), guard.linked_identity_id.into(), guard.user_id.into(), guard.identity_revision.into()],
    )
    .await?;
    Ok(project_ok && policy_ok && provider_ok && user_ok && identity_ok)
}

async fn lock_guard_egress_policy<C: ConnectionTrait>(
    connection: &C,
    guard: &ConnectionGuard,
) -> Result<bool, ApplicationError> {
    if guard.provider_kind == ProviderKind::Oidc {
        let revision = guard
            .provider_egress_policy_revision
            .ok_or(ApplicationError::Integrity)?;
        lock_boolean(
            connection,
            "SELECT EXISTS (SELECT 1 FROM project_provider_egress_policies WHERE project_id=$1 AND revision=$2 FOR SHARE)",
            vec![guard.project_id.into(), revision.into()],
        )
        .await
    } else if guard.provider_egress_policy_revision.is_none() && guard.egress_policy.is_none() {
        Ok(true)
    } else {
        Err(ApplicationError::Integrity)
    }
}

async fn lock_boolean<C: ConnectionTrait>(
    connection: &C,
    sql: &str,
    values: Vec<sea_orm::Value>,
) -> Result<bool, ApplicationError> {
    let row = connection
        .query_one_raw(statement(sql, values))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?;
    get(&row, "exists")
}

async fn materialize_user_projections(
    materializer: Option<&dyn IdentityProjectionMaterializer>,
    transaction: &sea_orm::DatabaseTransaction,
    user: &project_user::Model,
    now: OffsetDateTime,
) -> Result<(), ApplicationError> {
    if let Some(materializer) = materializer {
        materializer.fan_out_user(transaction, user, now).await
    } else {
        #[cfg(test)]
        {
            fan_out_user_projections(transaction, user, now).await
        }
        #[cfg(not(test))]
        {
            Err(ApplicationError::Integrity)
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the separate successor-generation profile transaction keeps all projection guards visible"
)]
async fn commit_profile_for_guard(
    database: &DatabaseConnection,
    projection_materializer: Option<&dyn IdentityProjectionMaterializer>,
    guard: &ConnectionGuard,
    claim: Option<&SuccessorProfileClaim>,
    profile: BoundedManagedProfile,
    next_sync: OffsetDateTime,
    now: OffsetDateTime,
) -> Result<bool, ApplicationError> {
    validate_profile(&profile)?;
    let display_name = profile
        .profile
        .display_name
        .map(ProfileDisplayName::into_inner);
    let picture_url = profile
        .profile
        .picture_url
        .map(ProfilePictureUrl::into_inner);
    let locale = profile.profile.locale.map(ProfileLocale::into_inner);
    let transaction = database.begin().await.map_err(persistence)?;
    // Canonical authority locks precede user, identity, then connection locks. Separate
    // statements make the order independent of the PostgreSQL join plan.
    let project_ok = lock_boolean(
        &transaction,
        "SELECT EXISTS (SELECT 1 FROM projects WHERE id=$1 AND status='active' AND security_revision=$2 FOR SHARE)",
        vec![guard.project_id.into(), guard.project_security_revision.into()],
    )
    .await?;
    let policy_ok = lock_guard_egress_policy(&transaction, guard).await?;
    let provider_ok = lock_boolean(
        &transaction,
        "SELECT EXISTS (SELECT 1 FROM provider_configurations WHERE project_id=$1 AND id=$2 AND status='active' AND revision=$3 AND managed_profile_enabled AND managed_profile_revision=$4 AND kind='oidc' AND adapter_kind=$5 FOR SHARE)",
        vec![guard.project_id.into(), guard.provider_configuration_id.into(), guard.provider_revision.into(), guard.managed_profile_revision.into(), guard.provider_kind.as_str().into()],
    )
    .await?;
    let user_ok = lock_boolean(
        &transaction,
        "SELECT EXISTS (SELECT 1 FROM project_users WHERE project_id=$1 AND id=$2 AND status='active' AND security_revision=$3 FOR UPDATE)",
        vec![guard.project_id.into(), guard.user_id.into(), guard.user_security_revision.into()],
    )
    .await?;
    let identity_ok = lock_boolean(
        &transaction,
        "SELECT EXISTS (SELECT 1 FROM linked_identities WHERE project_id=$1 AND id=$2 AND user_id=$3 AND status='active' AND identity_revision=$4 FOR UPDATE)",
        vec![guard.project_id.into(), guard.linked_identity_id.into(), guard.user_id.into(), guard.identity_revision.into()],
    )
    .await?;
    let connection_ok = if let Some(claim) = claim {
        lock_boolean(
            &transaction,
            "SELECT EXISTS (SELECT 1 FROM managed_provider_connections WHERE project_id=$1 AND id=$2 AND user_id=$3 AND provider_configuration_id=$4 AND linked_identity_id=$5 AND state='active' AND revision=$6 AND generation=$7 AND credential_generation=$8 AND lease_owner=$9 AND lease_kind='renewal' AND lease_expires_at=$10 AND lease_expires_at>$11 FOR UPDATE)",
            vec![guard.project_id.into(), guard.connection_id.into(), guard.user_id.into(), guard.provider_configuration_id.into(), guard.linked_identity_id.into(), guard.connection_revision.into(), guard.connection_generation.into(), guard.credential_generation.into(), claim.lease_owner.into(), claim.lease_expires_at.into(), now.into()],
        )
        .await?
    } else {
        lock_boolean(
            &transaction,
            "SELECT EXISTS (SELECT 1 FROM managed_provider_connections WHERE project_id=$1 AND id=$2 AND user_id=$3 AND provider_configuration_id=$4 AND linked_identity_id=$5 AND state='active' AND revision=$6 AND generation=$7 AND credential_generation=$8 FOR UPDATE)",
            vec![guard.project_id.into(), guard.connection_id.into(), guard.user_id.into(), guard.provider_configuration_id.into(), guard.linked_identity_id.into(), guard.connection_revision.into(), guard.connection_generation.into(), guard.credential_generation.into()],
        )
        .await?
    };
    if !(project_ok && policy_ok && provider_ok && user_ok && identity_ok && connection_ok) {
        transaction.rollback().await.map_err(persistence)?;
        return Ok(false);
    }
    let identity_changed = transaction.execute_raw(statement(
        r"UPDATE linked_identities SET display_name=$1, picture_url=$2, locale=$3, observed_at=$4,
                identity_revision=identity_revision + CASE WHEN (display_name,picture_url,locale)
                    IS DISTINCT FROM ($1,$2,$3) THEN 1 ELSE 0 END,
                updated_at=CASE WHEN (display_name,picture_url,locale) IS DISTINCT FROM ($1,$2,$3)
                    THEN $5 ELSE updated_at END
           WHERE project_id=$6 AND id=$7 AND user_id=$8 AND identity_revision=$9",
        vec![display_name.clone().into(), picture_url.clone().into(), locale.clone().into(),
             profile.observed_at.into(), now.into(), guard.project_id.into(), guard.linked_identity_id.into(),
             guard.user_id.into(), guard.identity_revision.into()],
    )).await.map_err(persistence)?;
    if identity_changed.rows_affected() != 1 {
        transaction.rollback().await.map_err(persistence)?;
        return Ok(false);
    }
    let identity_revision: i64 = transaction
        .query_one_raw(statement(
            "SELECT identity_revision FROM linked_identities WHERE project_id=$1 AND id=$2",
            vec![guard.project_id.into(), guard.linked_identity_id.into()],
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?
        .try_get("", "identity_revision")
        .map_err(|_| ApplicationError::Integrity)?;
    let user = project_user::Entity::find_by_id(guard.user_id)
        .filter(project_user::Column::ProjectId.eq(guard.project_id))
        .lock_exclusive()
        .one(&transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?;
    if user.status != "active" || user.security_revision != guard.user_security_revision {
        transaction.rollback().await.map_err(persistence)?;
        return Ok(false);
    }
    if user.primary_source_kind == "provider"
        && user.primary_profile_identity_id == Some(guard.linked_identity_id)
    {
        let effective_display_name = if user.local_display_name_set {
            user.local_display_name.clone()
        } else {
            display_name
        };
        let effective_picture_url = if user.local_picture_url_set {
            user.local_picture_url.clone()
        } else {
            picture_url
        };
        let effective_locale = if user.local_locale_set {
            user.local_locale.clone()
        } else {
            locale
        };
        if (
            user.display_name.as_ref(),
            user.picture_url.as_ref(),
            user.locale.as_ref(),
        ) != (
            effective_display_name.as_ref(),
            effective_picture_url.as_ref(),
            effective_locale.as_ref(),
        ) {
            let digest = base_profile_digest(
                effective_display_name.as_deref(),
                effective_picture_url.as_deref(),
                effective_locale.as_deref(),
                None,
            )?;
            let mut active = user.into_active_model();
            active.display_name = Set(effective_display_name);
            active.picture_url = Set(effective_picture_url);
            active.locale = Set(effective_locale);
            active.base_profile_digest = Set(digest);
            active.user_revision = Set(active.user_revision.take().unwrap_or(1) + 1);
            active.updated_at = Set(now);
            let updated = active.update(&transaction).await.map_err(persistence)?;
            materialize_user_projections(projection_materializer, &transaction, &updated, now)
                .await?;
        }
    }
    let updated = if let Some(claim) = claim {
        transaction
            .execute_raw(statement(
                r"UPDATE managed_provider_connections SET last_safe_outcome='read_succeeded',
                    last_synchronized_at=$1, next_synchronize_at=$2, consecutive_failures=0,
                    identity_revision=$3, lease_owner=NULL, lease_kind=NULL,
                    lease_expires_at=NULL, updated_at=$1
               WHERE project_id=$4 AND id=$5 AND state='active' AND revision=$6
                 AND generation=$7 AND credential_generation=$8
                 AND lease_owner=$9 AND lease_kind='renewal'
                 AND lease_expires_at=$10 AND lease_expires_at>$1",
                vec![
                    now.into(),
                    next_sync.into(),
                    identity_revision.into(),
                    guard.project_id.into(),
                    guard.connection_id.into(),
                    guard.connection_revision.into(),
                    guard.connection_generation.into(),
                    guard.credential_generation.into(),
                    claim.lease_owner.into(),
                    claim.lease_expires_at.into(),
                ],
            ))
            .await
            .map_err(persistence)?
    } else {
        transaction
            .execute_raw(statement(
                r"UPDATE managed_provider_connections SET last_safe_outcome='read_succeeded',
                    last_synchronized_at=$1, next_synchronize_at=$2, consecutive_failures=0,
                    identity_revision=$3, updated_at=$1
               WHERE project_id=$4 AND id=$5 AND state='active' AND revision=$6
                 AND generation=$7 AND credential_generation=$8",
                vec![
                    now.into(),
                    next_sync.into(),
                    identity_revision.into(),
                    guard.project_id.into(),
                    guard.connection_id.into(),
                    guard.connection_revision.into(),
                    guard.connection_generation.into(),
                    guard.credential_generation.into(),
                ],
            ))
            .await
            .map_err(persistence)?
    };
    append_runtime_audit(
        &transaction,
        guard.project_id,
        "runtime_worker",
        "managed_connection.profile_synchronized",
        "managed_provider_connection",
        Some(guard.connection_id),
        Uuid::new_v4(),
    )
    .await?;
    transaction.commit().await.map_err(persistence)?;
    Ok(updated.rows_affected() == 1)
}

async fn metadata_for_owner<C: ConnectionTrait>(
    database: &C,
    project_id: Uuid,
    user_id: Uuid,
    connection_id: Uuid,
) -> Result<ManagedConnectionMetadata, ApplicationError> {
    // Qualify ownership before joining or decoding metadata. A wrong owner is exactly NotFound;
    // query and decoding failures from an owned row remain Persistence/Integrity.
    database
        .query_one_raw(statement(
            r"SELECT id FROM managed_provider_connections
                WHERE project_id=$1 AND user_id=$2 AND id=$3",
            vec![project_id.into(), user_id.into(), connection_id.into()],
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
    let metadata = metadata_by_id(database, project_id, connection_id).await?;
    if metadata.user_id != user_id {
        return Err(ApplicationError::Integrity);
    }
    Ok(metadata)
}

async fn metadata_by_id<C: ConnectionTrait>(
    database: &C,
    project_id: Uuid,
    connection_id: Uuid,
) -> Result<ManagedConnectionMetadata, ApplicationError> {
    let row = database.query_one_raw(statement(
        r"SELECT connection.id, connection.project_id, connection.provider_configuration_id,
                  connection.linked_identity_id, connection.user_id, connection.state,
                  connection.revision, connection.generation, connection.credential_generation,
                  connection.adapter_key AS capability_key,
                  to_json(connection.required_scopes) AS required_scopes, identity.source_schema,
                  connection.supports_revocation,
                  to_json(ARRAY(SELECT assignment.application_id
                      FROM application_provider_assignments AS assignment
                      JOIN applications AS application ON application.project_id=assignment.project_id
                       AND application.id=assignment.application_id
                     WHERE assignment.project_id=connection.project_id
                       AND assignment.provider_id=connection.provider_configuration_id
                       AND assignment.status='active' AND application.status='active'
                     ORDER BY assignment.application_id)) AS reauthorization_application_ids,
                  connection.last_safe_outcome,
                  connection.last_synchronized_at, connection.next_synchronize_at,
                  connection.next_renewal_at, connection.consecutive_failures
             FROM managed_provider_connections AS connection
             JOIN provider_configurations AS provider ON provider.project_id=connection.project_id AND provider.id=connection.provider_configuration_id
             JOIN linked_identities AS identity ON identity.project_id=connection.project_id AND identity.id=connection.linked_identity_id
            WHERE connection.project_id=$1 AND connection.id=$2",
        vec![project_id.into(), connection_id.into()],
    )).await.map_err(persistence)?.ok_or(ApplicationError::NotFound)?;
    let scopes: Value = get(&row, "required_scopes")?;
    Ok(ManagedConnectionMetadata {
        id: get(&row, "id")?,
        project_id: get(&row, "project_id")?,
        provider_configuration_id: get(&row, "provider_configuration_id")?,
        linked_identity_id: get(&row, "linked_identity_id")?,
        user_id: get(&row, "user_id")?,
        state: get(&row, "state")?,
        revision: get(&row, "revision")?,
        generation: get(&row, "generation")?,
        credential_generation: get(&row, "credential_generation")?,
        capability_key: get(&row, "capability_key")?,
        required_scopes: json_strings(&scopes)?,
        source_schema: get(&row, "source_schema")?,
        supports_revocation: get(&row, "supports_revocation")?,
        reauthorization_application_ids: json_uuids(&get(
            &row,
            "reauthorization_application_ids",
        )?)?,
        last_safe_outcome: get(&row, "last_safe_outcome")?,
        last_synchronized_at: get(&row, "last_synchronized_at")?,
        next_synchronize_at: get(&row, "next_synchronize_at")?,
        next_renewal_at: get(&row, "next_renewal_at")?,
        consecutive_failures: get(&row, "consecutive_failures")?,
    })
}

fn validate_profile(profile: &BoundedManagedProfile) -> Result<(), ApplicationError> {
    if profile.observed_at.unix_timestamp() < 0 {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(())
}
fn json_uuids(value: &Value) -> Result<Vec<Uuid>, ApplicationError> {
    json_strings(value)?
        .into_iter()
        .map(|value| Uuid::parse_str(&value).map_err(|_| ApplicationError::Integrity))
        .collect()
}

fn json_strings(value: &Value) -> Result<Vec<String>, ApplicationError> {
    value
        .as_array()
        .ok_or(ApplicationError::Integrity)?
        .iter()
        .map(|v| {
            v.as_str()
                .map(str::to_owned)
                .ok_or(ApplicationError::Integrity)
        })
        .collect()
}
fn get<T: sea_orm::TryGetable>(
    row: &sea_orm::QueryResult,
    column: &str,
) -> Result<T, ApplicationError> {
    row.try_get("", column)
        .map_err(|_| ApplicationError::Integrity)
}
fn statement(sql: &str, values: Vec<sea_orm::Value>) -> Statement {
    Statement::from_sql_and_values(DbBackend::Postgres, sql, values)
}
