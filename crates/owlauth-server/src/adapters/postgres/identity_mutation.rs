//! `PostgreSQL` authority for explicit identity link, unlink, and same-Project merge.
//!
//! This adapter deliberately uses raw SQL for the interaction aggregate: the migration's
//! deferred aggregate constraints and typed callback/email owners are part of the authority.
//! Runtime transactions acquire the exact incarnation fence first. Control transactions have no
//! Runtime authority and instead receive only the narrow projection materializer. Both facades use
//! `PostgreSQL`'s clock for eligibility and lifecycle timestamps; caller clocks are never authority.

use std::{collections::BTreeSet, sync::Arc};

use async_trait::async_trait;
use sea_orm::{
    ConnectionTrait, DatabaseConnection, DatabaseTransaction, DbBackend, EntityTrait, QueryResult,
    Statement, TransactionTrait,
};
use serde_json::json;
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    application::{
        AdmittedEmailMethod, ApplicationError, CandidateEvidenceMaterial,
        ClaimIdentityMutationProvider, CommitIdentityMutationEmailGeneration,
        CompleteIdentityMutationEmailProof, ControlIdentityMutationRepository,
        CreateIdentityMutationResult, EmailIdentityAliasAuthority, EmailProofKind,
        EstablishIdentityMutationMagicTransferContext,
        EstablishedIdentityMutationMagicTransferContext, FailIdentityMutationProvider,
        IdentityMutationBindingsDisposition, IdentityMutationCandidate,
        IdentityMutationCandidateEvidenceContext, IdentityMutationCandidateEvidenceEnvelope,
        IdentityMutationCandidateKind, IdentityMutationControlConfirmationPreparation,
        IdentityMutationCreateOperation, IdentityMutationDigestVersions,
        IdentityMutationEmailGenerationPreparation, IdentityMutationEmailProofDecision,
        IdentityMutationEmailProofKey, IdentityMutationEmailProofMaterial,
        IdentityMutationExistingEmailEvidence, IdentityMutationPrimarySourceDisposition,
        IdentityMutationProofAuthoritySelection, IdentityMutationProofMethodKind,
        IdentityMutationProviderDigestVersions, IdentityMutationProviderSlotAuthority,
        IdentityMutationRecord, IdentityMutationSessionsDisposition, IdentityMutationSlotRecord,
        PreparedIdentityMutationConfirmation, PreparedIdentityMutationCreate,
        PreparedIdentityMutationProviderCompletion, ProtectedValue,
        ResolveIdentityMutationMagicTransferContext, ResolvedIdentityMutationMagicTransferContext,
        RuntimeIdentityMutationRepository, VerifiedIdentityMutationEmailChallenge,
        VerifyIdentityMutationEmailProof, VersionedDigest,
    },
    domain::{
        IdentityKind, IdentityMutationKind, IdentityMutationSlotRole, IdentityMutationSlotState,
        IdentityMutationStatus, ProviderEgressPolicy, ProviderKind,
    },
};

use super::{
    audit::append_runtime_audit,
    authentication::persistence,
    entity::project_user,
    projection::{
        IdentityProjectionMaterializer, MAX_APPLICATION_BINDINGS_PER_USER, base_profile_digest,
    },
    runtime_incarnation::RuntimeIncarnationFence,
};

const CREATE_OPERATION: &str = "identity_mutation.create";
const MAX_MAGIC_CONTEXTS: i64 = 8;

#[derive(Clone)]
pub(crate) struct PostgresControlIdentityMutationRepository {
    database: DatabaseConnection,
    projection_materializer: Arc<dyn IdentityProjectionMaterializer>,
    required_runtime_process_ids: Vec<String>,
}

impl PostgresControlIdentityMutationRepository {
    pub(crate) fn new(
        database: DatabaseConnection,
        projection_materializer: Arc<dyn IdentityProjectionMaterializer>,
        required_runtime_process_ids: Vec<String>,
    ) -> Self {
        Self {
            database,
            projection_materializer,
            required_runtime_process_ids,
        }
    }

    async fn begin(&self) -> Result<DatabaseTransaction, ApplicationError> {
        self.database.begin().await.map_err(persistence)
    }
}

#[derive(Clone)]
pub(crate) struct PostgresRuntimeIdentityMutationRepository {
    database: DatabaseConnection,
    fence: RuntimeIncarnationFence,
    required_runtime_process_ids: Vec<String>,
}

impl PostgresRuntimeIdentityMutationRepository {
    pub(crate) fn new(
        database: DatabaseConnection,
        process_id: String,
        incarnation: Uuid,
        required_runtime_process_ids: Vec<String>,
    ) -> Self {
        Self {
            database,
            fence: RuntimeIncarnationFence::new(process_id, incarnation),
            required_runtime_process_ids,
        }
    }

    async fn begin(&self) -> Result<DatabaseTransaction, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        self.fence.lock(&transaction).await?;
        Ok(transaction)
    }
}

#[derive(Clone)]
struct SlotSeed {
    id: Uuid,
    ordinal: i16,
    role: IdentityMutationSlotRole,
    identity_kind: IdentityKind,
    user_id: Uuid,
    user_revision: i64,
    user_security_revision: i64,
    identity_id: Option<Uuid>,
    identity_revision: Option<i64>,
    authority: IdentityMutationProofAuthoritySelection,
}

#[derive(Clone)]
struct ProviderSnapshot {
    provider_id: Uuid,
    secret_material_id: Option<Uuid>,
    revision: i64,
    assignment_revision: i64,
    egress_policy_revision: Option<i64>,
    adapter_key: String,
    adapter_revision: i64,
    scopes: Vec<String>,
    callback_url: String,
    pkce: bool,
    nonce: bool,
}

#[derive(Clone)]
struct MethodSnapshot {
    application_revision: i64,
    provider: Option<ProviderSnapshot>,
    email_policy_revision: Option<i64>,
    email_security_revision: Option<i64>,
    email_assignment_revision: Option<i64>,
}

#[async_trait]
#[allow(
    clippy::too_many_lines,
    reason = "the repository trait is one security aggregate and keeps each transaction explicit"
)]
impl ControlIdentityMutationRepository for PostgresControlIdentityMutationRepository {
    async fn create(
        &self,
        prepared: PreparedIdentityMutationCreate,
    ) -> Result<CreateIdentityMutationResult, ApplicationError> {
        validate_digest(&prepared.hosted_handle_digest)?;
        validate_protected_range(&prepared.protected_create_result, 40, 4_096)?;
        if prepared.request_digest.len() != 32
            || prepared.intent_id.is_nil()
            || prepared.command.idempotency_key.is_empty()
        {
            return Err(ApplicationError::InvalidInput);
        }
        let transaction = self.begin().await?;
        transaction
            .execute_raw(statement(
                "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                vec![prepared.command.idempotency_key.clone().into()],
            ))
            .await
            .map_err(persistence)?;
        if let Some(authority) = transaction
            .query_one_raw(statement(
                "SELECT project_id,request_digest,state,result_resource_id,operation_kind,request_scope
                   FROM control_idempotency_records WHERE idempotency_key=$1 FOR UPDATE",
                vec![prepared.command.idempotency_key.clone().into()],
            ))
            .await
            .map_err(persistence)?
        {
            if get::<Option<Uuid>>(&authority, "project_id")?
                != Some(prepared.command.project_id)
                || get::<Vec<u8>>(&authority, "request_digest")? != prepared.request_digest
                || get::<String>(&authority, "operation_kind")? != CREATE_OPERATION
                || get::<String>(&authority, "request_scope")?
                    != prepared.command.project_id.to_string()
            {
                return Err(ApplicationError::IdempotencyConflict);
            }
            if get::<String>(&authority, "state")? != "completed" {
                return Err(ApplicationError::OperationInProgress);
            }
            let intent_id = get::<Option<Uuid>>(&authority, "result_resource_id")?
                .ok_or(ApplicationError::Integrity)?;
            expire_if_needed(&transaction, intent_id).await?;
            let result = transaction
                .query_one_raw(statement(
                    "SELECT request_digest,create_result_key_version,create_result_ciphertext,
                            expires_at,erased_at FROM identity_mutation_create_results
                      WHERE idempotency_key=$1 FOR UPDATE",
                    vec![prepared.command.idempotency_key.into()],
                ))
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::Integrity)?;
            if get::<Vec<u8>>(&result, "request_digest")? != prepared.request_digest {
                return Err(ApplicationError::Integrity);
            }
            let protected_create_result = match (
                get::<Option<Vec<u8>>>(&result, "create_result_ciphertext")?,
                get::<Option<OffsetDateTime>>(&result, "erased_at")?,
            ) {
                (Some(ciphertext), None) => Some(ProtectedValue {
                    ciphertext,
                    key_version: get(&result, "create_result_key_version")?,
                }),
                (None, Some(_)) => None,
                _ => return Err(ApplicationError::Integrity),
            };
            let record = read_record(&transaction, intent_id).await?;
            transaction.commit().await.map_err(persistence)?;
            return Ok(CreateIdentityMutationResult::Replayed {
                intent: record,
                protected_create_result,
            });
        }

        let project = transaction
            .query_one_raw(statement(
                "SELECT public_id,metadata_revision,security_revision
                   FROM projects WHERE id=$1 AND status='active' FOR SHARE",
                vec![prepared.command.project_id.into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        lock_project_graph(&transaction, prepared.command.project_id).await?;
        validate_primary_source_create(
            &transaction,
            prepared.command.project_id,
            &prepared.command.operation,
        )
        .await?;
        let slots = derive_and_lock_slots(
            &transaction,
            prepared.command.project_id,
            &prepared.command.operation,
        )
        .await?;
        let mut snapshots = Vec::with_capacity(slots.len());
        for slot in &slots {
            snapshots.push(
                snapshot_method(
                    &transaction,
                    prepared.command.project_id,
                    &get::<String>(&project, "public_id")?,
                    slot.authority,
                    &prepared,
                )
                .await?,
            );
        }
        let now = database_now(&transaction).await?;
        let expires_at = now + time::Duration::minutes(10);
        let frozen = frozen_columns(&prepared.command.operation);
        transaction
            .execute_raw(statement(
                "INSERT INTO identity_mutation_intents
                 (id,project_id,operation_kind,status,intent_revision,project_metadata_revision,
                  project_security_revision,destination_user_id,destination_user_revision,
                  destination_user_security_revision,identity_owner_user_id,
                  identity_owner_user_revision,identity_owner_user_security_revision,winner_user_id,
                  winner_user_revision,winner_user_security_revision,loser_user_id,
                  loser_user_revision,loser_user_security_revision,primary_source_disposition,
                  primary_provider_identity_id,primary_email_identity_id,
                  primary_source_identity_revision,sessions_disposition,
                  bindings_disposition,hosted_handle_digest,hosted_handle_digest_key_version,
                  browser_binding_revision,correlation_id,created_at,updated_at,expires_at)
                 VALUES ($1,$2,$3,'pending_proof',1,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,
                         $15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,0,$26,$27,$27,$28)",
                vec![
                    prepared.intent_id.into(),
                    prepared.command.project_id.into(),
                    kind_str(prepared.command.operation.kind()).into(),
                    get::<i64>(&project, "metadata_revision")?.into(),
                    get::<i64>(&project, "security_revision")?.into(),
                    frozen.destination.map(|v| v.0).into(),
                    frozen.destination.map(|v| v.1).into(),
                    frozen.destination.map(|v| v.2).into(),
                    frozen.owner.map(|v| v.0).into(),
                    frozen.owner.map(|v| v.1).into(),
                    frozen.owner.map(|v| v.2).into(),
                    frozen.winner.map(|v| v.0).into(),
                    frozen.winner.map(|v| v.1).into(),
                    frozen.winner.map(|v| v.2).into(),
                    frozen.loser.map(|v| v.0).into(),
                    frozen.loser.map(|v| v.1).into(),
                    frozen.loser.map(|v| v.2).into(),
                    frozen.primary_kind.into(),
                    frozen.primary_provider.into(),
                    frozen.primary_email.into(),
                    frozen.primary_revision.into(),
                    frozen.sessions.into(),
                    frozen.bindings.into(),
                    prepared.hosted_handle_digest.value.to_vec().into(),
                    prepared.hosted_handle_digest.key_version.into(),
                    prepared.command.correlation_id.into(),
                    now.into(),
                    expires_at.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        for (slot, snapshot) in slots.iter().zip(snapshots.iter()) {
            insert_slot(
                &transaction,
                prepared.command.project_id,
                prepared.intent_id,
                slot,
                snapshot,
                now,
            )
            .await?;
        }
        transaction
            .execute_raw(statement(
                "INSERT INTO control_idempotency_records
                 (idempotency_key,project_id,request_digest,state,result_resource_id,response,
                  operation_kind,request_scope,created_at,completed_at)
                 VALUES ($1,$2,$3,'completed',$4,$5,$6,$7,$8,$8)",
                vec![
                    prepared.command.idempotency_key.clone().into(),
                    prepared.command.project_id.into(),
                    prepared.request_digest.clone().into(),
                    prepared.intent_id.into(),
                    json!({"resource_kind":"identity_mutation","id":prepared.intent_id}).into(),
                    CREATE_OPERATION.into(),
                    prepared.command.project_id.to_string().into(),
                    now.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        transaction
            .execute_raw(statement(
                "INSERT INTO identity_mutation_create_results
                 (idempotency_key,project_id,intent_id,request_digest,create_result_key_version,
                  create_result_ciphertext,expires_at)
                 VALUES ($1,$2,$3,$4,$5,$6,$7)",
                vec![
                    prepared.command.idempotency_key.into(),
                    prepared.command.project_id.into(),
                    prepared.intent_id.into(),
                    prepared.request_digest.into(),
                    prepared.protected_create_result.key_version.into(),
                    prepared.protected_create_result.ciphertext.into(),
                    expires_at.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        append_runtime_audit(
            &transaction,
            prepared.command.project_id,
            "deployment_operator",
            "identity.mutation.created",
            "identity_mutation",
            Some(prepared.intent_id),
            prepared.command.correlation_id,
        )
        .await?;
        let record = read_record(&transaction, prepared.intent_id).await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(CreateIdentityMutationResult::Created(record))
    }

    async fn control_read(
        &self,
        project_id: Uuid,
        intent_id: Uuid,
        _now: OffsetDateTime,
    ) -> Result<IdentityMutationRecord, ApplicationError> {
        let transaction = self.begin().await?;
        expire_if_needed(&transaction, intent_id).await?;
        let record = read_record_for_project(&transaction, project_id, intent_id).await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(record)
    }

    async fn cancel(
        &self,
        project_id: Uuid,
        intent_id: Uuid,
        expected_revision: i64,
        correlation_id: Uuid,
        _now: OffsetDateTime,
    ) -> Result<IdentityMutationRecord, ApplicationError> {
        let transaction = self.begin().await?;
        let row = lock_intent(&transaction, intent_id).await?;
        require_project(&row, project_id)?;
        if expire_locked_if_needed(&transaction, &row).await? {
            let record = read_record(&transaction, intent_id).await?;
            transaction.commit().await.map_err(persistence)?;
            return Ok(record);
        }
        if get::<i64>(&row, "intent_revision")? != expected_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        if !matches!(
            get::<String>(&row, "status")?.as_str(),
            "pending_proof" | "ready"
        ) {
            return Err(ApplicationError::InvalidTransition);
        }
        terminalize(&transaction, &row, "cancelled").await?;
        append_runtime_audit(
            &transaction,
            project_id,
            "deployment_operator",
            "identity.mutation.cancelled",
            "identity_mutation",
            Some(intent_id),
            correlation_id,
        )
        .await?;
        let record = read_record(&transaction, intent_id).await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(record)
    }

    async fn prepare_control_confirmation(
        &self,
        project_id: Uuid,
        intent_id: Uuid,
        expected_revision: i64,
        expected_kind: IdentityMutationKind,
        _now: OffsetDateTime,
    ) -> Result<IdentityMutationControlConfirmationPreparation, ApplicationError> {
        let transaction = self.begin().await?;
        let row = lock_intent(&transaction, intent_id).await?;
        require_project(&row, project_id)?;
        if expire_locked_if_needed(&transaction, &row).await? {
            transaction.commit().await.map_err(persistence)?;
            return Err(ApplicationError::InvalidTransition);
        }
        require_live_ready(&transaction, &row, expected_revision, expected_kind).await?;
        let evidence = transaction
            .query_one_raw(statement(
                "SELECT evidence.*,slot.slot_role,slot.state
                   FROM identity_mutation_candidate_evidence evidence
                   JOIN identity_mutation_proof_slots slot
                     ON slot.project_id=evidence.project_id AND slot.intent_id=evidence.intent_id
                    AND slot.id=evidence.slot_id
                  WHERE evidence.project_id=$1 AND evidence.intent_id=$2
                    AND slot.slot_role='candidate_identity' AND slot.state='proved'
                  FOR SHARE OF evidence,slot",
                vec![project_id.into(), intent_id.into()],
            ))
            .await
            .map_err(persistence)?
            .map(|row| candidate_envelope(&row))
            .transpose()?;
        if (expected_kind == IdentityMutationKind::Link) != evidence.is_some() {
            return Err(ApplicationError::Integrity);
        }
        let result = IdentityMutationControlConfirmationPreparation {
            project_id,
            intent_id,
            expected_intent_revision: expected_revision,
            expected_kind,
            candidate_evidence: evidence,
        };
        transaction.commit().await.map_err(persistence)?;
        Ok(result)
    }

    async fn confirm_control(
        &self,
        confirmation: PreparedIdentityMutationConfirmation,
    ) -> Result<IdentityMutationRecord, ApplicationError> {
        let transaction = self.begin().await?;
        // Control confirmation has no Runtime process incarnation. It locks the Project graph
        // before any typed namespace and delegates projection cryptography through one narrow,
        // transaction-scoped materializer.
        lock_project_graph(&transaction, confirmation.project_id).await?;
        if confirmation.expected_kind == IdentityMutationKind::Link {
            lock_prepared_candidate_namespace(&transaction, &confirmation).await?;
        }
        let intent = lock_intent(&transaction, confirmation.intent_id).await?;
        require_project(&intent, confirmation.project_id)?;
        if expire_locked_if_needed(&transaction, &intent).await? {
            transaction.commit().await.map_err(persistence)?;
            return Err(ApplicationError::InvalidTransition);
        }
        require_live_ready(
            &transaction,
            &intent,
            confirmation.expected_intent_revision,
            confirmation.expected_kind,
        )
        .await?;
        revalidate_final_authority(&transaction, &intent, &self.required_runtime_process_ids)
            .await?;
        if confirmation.expected_kind == IdentityMutationKind::Merge
            && merge_binding_union_count(&transaction, &intent).await?
                > MAX_APPLICATION_BINDINGS_PER_USER
        {
            terminalize(&transaction, &intent, "cancelled").await?;
            append_mutation_outcome_audit(
                &transaction,
                confirmation.project_id,
                confirmation.intent_id,
                get(&intent, "correlation_id")?,
                "deployment_operator",
                "identity.mutation.merge.cancelled",
                "binding_limit_exceeded",
            )
            .await?;
            let record = read_record(&transaction, confirmation.intent_id).await?;
            transaction.commit().await.map_err(persistence)?;
            return Ok(record);
        }
        let timestamp = database_now(&transaction).await?;
        match confirmation.expected_kind {
            IdentityMutationKind::Link => {
                confirm_link(&transaction, &intent, &confirmation, timestamp).await?;
            }
            IdentityMutationKind::Unlink => {
                if confirmation.candidate.is_some() {
                    return Err(ApplicationError::Integrity);
                }
                confirm_unlink(
                    &transaction,
                    &intent,
                    self.projection_materializer.as_ref(),
                    timestamp,
                )
                .await?;
            }
            IdentityMutationKind::Merge => {
                if confirmation.candidate.is_some() {
                    return Err(ApplicationError::Integrity);
                }
                confirm_merge(
                    &transaction,
                    &intent,
                    self.projection_materializer.as_ref(),
                    timestamp,
                )
                .await?;
            }
        }
        let consumed = transaction
            .execute_raw(statement(
                "UPDATE identity_proof_receipts SET status='consumed',consumed_at=$3
                  WHERE project_id=$1 AND intent_id=$2 AND status='issued'
                    AND expires_at>clock_timestamp()",
                vec![
                    confirmation.project_id.into(),
                    confirmation.intent_id.into(),
                    timestamp.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        let slot_count = slot_count(&transaction, confirmation.intent_id).await?;
        if consumed.rows_affected()
            != u64::try_from(slot_count).map_err(|_| ApplicationError::Integrity)?
        {
            return Err(ApplicationError::RevisionConflict);
        }
        let updated = transaction
            .execute_raw(statement(
                "UPDATE identity_mutation_intents SET status='completed',
                        intent_revision=intent_revision+1,terminal_at=$3,updated_at=$3
                  WHERE project_id=$1 AND id=$2 AND status='ready' AND intent_revision=$4
                    AND expires_at>clock_timestamp()",
                vec![
                    confirmation.project_id.into(),
                    confirmation.intent_id.into(),
                    timestamp.into(),
                    confirmation.expected_intent_revision.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        if updated.rows_affected() != 1 {
            return Err(ApplicationError::RevisionConflict);
        }
        if confirmation.expected_kind == IdentityMutationKind::Merge {
            insert_merge_tombstone(&transaction, &intent, timestamp).await?;
        }
        erase_create_result(&transaction, confirmation.intent_id, timestamp).await?;
        transaction
            .execute_raw(statement(
                "DELETE FROM identity_mutation_candidate_evidence
                  WHERE project_id=$1 AND intent_id=$2",
                vec![
                    confirmation.project_id.into(),
                    confirmation.intent_id.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        append_runtime_audit(
            &transaction,
            confirmation.project_id,
            "deployment_operator",
            "identity.mutation.completed",
            "identity_mutation",
            Some(confirmation.intent_id),
            confirmation.correlation_id,
        )
        .await?;
        let record = read_record(&transaction, confirmation.intent_id).await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(record)
    }
}

#[async_trait]
#[allow(
    clippy::too_many_lines,
    reason = "the Runtime repository keeps every fenced interaction transaction explicit"
)]
impl RuntimeIdentityMutationRepository for PostgresRuntimeIdentityMutationRepository {
    async fn digest_versions(
        &self,
        intent_id: Uuid,
        _now: OffsetDateTime,
    ) -> Result<IdentityMutationDigestVersions, ApplicationError> {
        let transaction = self.begin().await?;
        if expire_if_needed(&transaction, intent_id).await? {
            transaction.commit().await.map_err(persistence)?;
            return Err(ApplicationError::NotFound);
        }
        let row = live_intent_digest_row(&transaction, intent_id).await?;
        let result = IdentityMutationDigestVersions {
            intent: get(&row, "hosted_handle_digest_key_version")?,
            browser_binding: get(&row, "browser_binding_digest_key_version")?,
            csrf: get(&row, "csrf_digest_key_version")?,
        };
        transaction.commit().await.map_err(persistence)?;
        Ok(result)
    }

    async fn provider_digest_versions(
        &self,
        intent_id: Uuid,
        proof_slot_id: Uuid,
        _now: OffsetDateTime,
    ) -> Result<IdentityMutationProviderDigestVersions, ApplicationError> {
        let transaction = self.begin().await?;
        if expire_if_needed(&transaction, intent_id).await? {
            transaction.commit().await.map_err(persistence)?;
            return Err(ApplicationError::NotFound);
        }
        let row = transaction
            .query_one_raw(statement(
                "SELECT intent.browser_binding_digest_key_version,
                        slot.upstream_state_digest_key_version,slot.oidc_nonce_digest_key_version,
                        slot.provider_pkce_key_version,slot.callback_continuation_key_version
                   FROM identity_mutation_intents intent
                   JOIN identity_mutation_proof_slots slot
                     ON slot.project_id=intent.project_id AND slot.intent_id=intent.id
                  WHERE intent.id=$1 AND slot.id=$2 AND slot.method_kind='provider'
                    AND intent.status='pending_proof' AND intent.expires_at>clock_timestamp()",
                vec![intent_id.into(), proof_slot_id.into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let result = IdentityMutationProviderDigestVersions {
            browser_binding: get::<Option<i32>>(&row, "browser_binding_digest_key_version")?
                .ok_or(ApplicationError::Integrity)?,
            upstream_state: get::<Option<i32>>(&row, "upstream_state_digest_key_version")?
                .ok_or(ApplicationError::NotFound)?,
            oidc_nonce: get(&row, "oidc_nonce_digest_key_version")?,
            provider_pkce: get(&row, "provider_pkce_key_version")?,
            callback_continuation: get(&row, "callback_continuation_key_version")?,
        };
        transaction.commit().await.map_err(persistence)?;
        Ok(result)
    }

    async fn bind_browser(
        &self,
        intent: &VersionedDigest,
        browser_binding: &VersionedDigest,
        csrf: &VersionedDigest,
        _now: OffsetDateTime,
    ) -> Result<IdentityMutationRecord, ApplicationError> {
        validate_digest(intent)?;
        validate_digest(browser_binding)?;
        validate_digest(csrf)?;
        let transaction = self.begin().await?;
        let row = transaction
            .query_one_raw(statement(
                "SELECT * FROM identity_mutation_intents
                  WHERE hosted_handle_digest=$1 AND hosted_handle_digest_key_version=$2 FOR UPDATE",
                vec![intent.value.to_vec().into(), intent.key_version.into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if expire_locked_if_needed(&transaction, &row).await? {
            transaction.commit().await.map_err(persistence)?;
            return Err(ApplicationError::NotFound);
        }
        if get::<String>(&row, "status")? != "pending_proof"
            || get::<Option<Vec<u8>>>(&row, "browser_binding_digest")?.is_some()
        {
            return Err(ApplicationError::InvalidTransition);
        }
        let timestamp = database_now(&transaction).await?;
        transaction
            .execute_raw(statement(
                "UPDATE identity_mutation_intents SET browser_binding_digest=$2,
                        browser_binding_digest_key_version=$3,csrf_digest=$4,
                        csrf_digest_key_version=$5,browser_binding_revision=1,
                        intent_revision=intent_revision+1,updated_at=$6
                  WHERE id=$1 AND status='pending_proof' AND browser_binding_digest IS NULL",
                vec![
                    get::<Uuid>(&row, "id")?.into(),
                    browser_binding.value.to_vec().into(),
                    browser_binding.key_version.into(),
                    csrf.value.to_vec().into(),
                    csrf.key_version.into(),
                    timestamp.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        let record = read_record(&transaction, get(&row, "id")?).await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(record)
    }

    async fn hosted_read(
        &self,
        intent: &VersionedDigest,
        browser_binding: &VersionedDigest,
        _now: OffsetDateTime,
    ) -> Result<IdentityMutationRecord, ApplicationError> {
        validate_digest(intent)?;
        validate_digest(browser_binding)?;
        let transaction = self.begin().await?;
        let row = transaction
            .query_one_raw(statement(
                "SELECT * FROM identity_mutation_intents
                  WHERE hosted_handle_digest=$1 AND hosted_handle_digest_key_version=$2
                    AND browser_binding_digest=$3 AND browser_binding_digest_key_version=$4 FOR UPDATE",
                vec![
                    intent.value.to_vec().into(),
                    intent.key_version.into(),
                    browser_binding.value.to_vec().into(),
                    browser_binding.key_version.into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if expire_locked_if_needed(&transaction, &row).await? {
            transaction.commit().await.map_err(persistence)?;
            return Err(ApplicationError::NotFound);
        }
        if matches!(
            get::<String>(&row, "status")?.as_str(),
            "completed" | "expired" | "cancelled"
        ) {
            return Err(ApplicationError::NotFound);
        }
        let record = read_record(&transaction, get(&row, "id")?).await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(record)
    }

    async fn start_provider(
        &self,
        intent_id: Uuid,
        proof_slot_id: Uuid,
        intent: &VersionedDigest,
        browser_binding: &VersionedDigest,
        csrf: &VersionedDigest,
        expected_revision: i64,
        upstream_state: VersionedDigest,
        oidc_nonce: VersionedDigest,
        provider_pkce: Option<ProtectedValue>,
        callback_continuation: ProtectedValue,
        _now: OffsetDateTime,
    ) -> Result<IdentityMutationRecord, ApplicationError> {
        validate_digest(&upstream_state)?;
        validate_digest(&oidc_nonce)?;
        validate_protected_range(&callback_continuation, 41, 4_096)?;
        if let Some(value) = &provider_pkce {
            validate_protected_range(value, 17, 4_096)?;
        }
        let transaction = self.begin().await?;
        let (intent_row, slot) = lock_authenticated_slot(
            &transaction,
            intent_id,
            proof_slot_id,
            intent,
            browser_binding,
            csrf,
        )
        .await?;
        if expire_locked_if_needed(&transaction, &intent_row).await? {
            transaction.commit().await.map_err(persistence)?;
            return Err(ApplicationError::InvalidTransition);
        }
        require_pending_revision(&transaction, &intent_row, expected_revision).await?;
        if get::<String>(&slot, "state")? != "pending"
            || get::<String>(&slot, "method_kind")? != "provider"
            || get::<Option<bool>>(&slot, "provider_pkce_required")?
                != Some(provider_pkce.is_some())
        {
            return Err(ApplicationError::InvalidTransition);
        }
        revalidate_slot_authority(
            &transaction,
            &intent_row,
            &slot,
            &self.required_runtime_process_ids,
        )
        .await?;
        let timestamp = database_now(&transaction).await?;
        let updated = transaction
            .execute_raw(statement(
                "UPDATE identity_mutation_proof_slots
                    SET state='provider_authorization_started',slot_revision=slot_revision+1,
                        upstream_state_digest=$3,upstream_state_digest_key_version=$4,
                        oidc_nonce_digest=$5,oidc_nonce_digest_key_version=$6,
                        provider_pkce_ciphertext=$7,provider_pkce_key_version=$8,
                        callback_continuation_ciphertext=$9,
                        callback_continuation_key_version=$10,provider_started_at=$11,updated_at=$11
                  WHERE intent_id=$1 AND id=$2 AND state='pending'",
                vec![
                    intent_id.into(),
                    proof_slot_id.into(),
                    upstream_state.value.to_vec().into(),
                    upstream_state.key_version.into(),
                    oidc_nonce.value.to_vec().into(),
                    oidc_nonce.key_version.into(),
                    provider_pkce.as_ref().map(|v| v.ciphertext.clone()).into(),
                    provider_pkce.as_ref().map(|v| v.key_version).into(),
                    callback_continuation.ciphertext.into(),
                    callback_continuation.key_version.into(),
                    timestamp.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        if updated.rows_affected() != 1 {
            return Err(ApplicationError::RevisionConflict);
        }
        transaction
            .execute_raw(statement(
                "INSERT INTO provider_callback_owners
                 (state_id,project_id,provider_configuration_id,owner_kind,
                  identity_mutation_intent_id,identity_mutation_proof_slot_id,created_at)
                 VALUES ($1,$2,$3,'identity_mutation',$4,$1,$5)",
                vec![
                    proof_slot_id.into(),
                    get::<Uuid>(&slot, "project_id")?.into(),
                    get::<Option<Uuid>>(&slot, "provider_configuration_id")?
                        .ok_or(ApplicationError::Integrity)?
                        .into(),
                    intent_id.into(),
                    timestamp.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        bump_intent(&transaction, intent_id, expected_revision, timestamp).await?;
        let record = read_record(&transaction, intent_id).await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(record)
    }

    async fn claim_provider_callback(
        &self,
        intent_id: Uuid,
        proof_slot_id: Uuid,
        project_public_id: &str,
        provider_key: &str,
        upstream_state: &VersionedDigest,
        browser_binding: &VersionedDigest,
        _now: OffsetDateTime,
    ) -> Result<ClaimIdentityMutationProvider, ApplicationError> {
        validate_digest(upstream_state)?;
        validate_digest(browser_binding)?;
        let transaction = self.begin().await?;
        let intent = lock_intent(&transaction, intent_id).await?;
        if expire_locked_if_needed(&transaction, &intent).await? {
            transaction.commit().await.map_err(persistence)?;
            return Ok(ClaimIdentityMutationProvider::TerminalizedStaleAuthority);
        }
        let slot = lock_callback_slot(
            &transaction,
            intent_id,
            proof_slot_id,
            project_public_id,
            provider_key,
            upstream_state,
            browser_binding,
        )
        .await?;
        match get::<String>(&slot, "state")?.as_str() {
            "provider_exchange_in_progress" | "provider_exchange_failed" | "proved" | "expired" => {
                let record = read_record(&transaction, intent_id).await?;
                transaction.commit().await.map_err(persistence)?;
                return Ok(ClaimIdentityMutationProvider::Duplicate(record));
            }
            "provider_authorization_started" => {}
            _ => return Err(ApplicationError::InvalidTransition),
        }
        match revalidate_slot_authority(
            &transaction,
            &intent,
            &slot,
            &self.required_runtime_process_ids,
        )
        .await
        {
            Ok(()) => {}
            Err(
                ApplicationError::RevisionConflict
                | ApplicationError::Disabled
                | ApplicationError::NotFound,
            ) => {
                terminalize(&transaction, &intent, "cancelled").await?;
                transaction.commit().await.map_err(persistence)?;
                return Ok(ClaimIdentityMutationProvider::TerminalizedStaleAuthority);
            }
            Err(error) => return Err(error),
        }
        let timestamp = database_now(&transaction).await?;
        let updated = transaction
            .execute_raw(statement(
                "UPDATE identity_mutation_proof_slots
                    SET state='provider_exchange_in_progress',slot_revision=slot_revision+1,
                        exchange_claimed_at=$3,updated_at=$3
                  WHERE intent_id=$1 AND id=$2 AND state='provider_authorization_started'",
                vec![intent_id.into(), proof_slot_id.into(), timestamp.into()],
            ))
            .await
            .map_err(persistence)?;
        if updated.rows_affected() != 1 {
            return Err(ApplicationError::RevisionConflict);
        }
        bump_intent(
            &transaction,
            intent_id,
            get(&intent, "intent_revision")?,
            timestamp,
        )
        .await?;
        let record = read_record(&transaction, intent_id).await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(ClaimIdentityMutationProvider::Claimed(record))
    }

    async fn deny_provider_callback(
        &self,
        intent_id: Uuid,
        proof_slot_id: Uuid,
        project_public_id: &str,
        provider_key: &str,
        upstream_state: &VersionedDigest,
        browser_binding: &VersionedDigest,
        safe_outcome: &'static str,
        _now: OffsetDateTime,
    ) -> Result<IdentityMutationRecord, ApplicationError> {
        let transaction = self.begin().await?;
        let intent = lock_intent(&transaction, intent_id).await?;
        if expire_locked_if_needed(&transaction, &intent).await? {
            let record = read_record(&transaction, intent_id).await?;
            transaction.commit().await.map_err(persistence)?;
            return Ok(record);
        }
        let slot = lock_callback_slot(
            &transaction,
            intent_id,
            proof_slot_id,
            project_public_id,
            provider_key,
            upstream_state,
            browser_binding,
        )
        .await?;
        if get::<String>(&slot, "state")? != "provider_authorization_started" {
            return Err(ApplicationError::InvalidTransition);
        }
        terminalize(&transaction, &intent, "cancelled").await?;
        append_mutation_outcome_audit(
            &transaction,
            get(&intent, "project_id")?,
            intent_id,
            get(&intent, "correlation_id")?,
            "runtime",
            "identity.mutation.provider.denied",
            safe_outcome,
        )
        .await?;
        let record = read_record(&transaction, intent_id).await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(record)
    }

    async fn complete_provider_callback(
        &self,
        completion: PreparedIdentityMutationProviderCompletion,
    ) -> Result<IdentityMutationRecord, ApplicationError> {
        validate_digest(&completion.receipt_digest)?;
        let transaction = self.begin().await?;
        let intent = lock_intent(&transaction, completion.claimed.id).await?;
        if expire_locked_if_needed(&transaction, &intent).await? {
            transaction.commit().await.map_err(persistence)?;
            return Err(ApplicationError::RevisionConflict);
        }
        if get::<Uuid>(&intent, "project_id")? != completion.claimed.project_id
            || get::<i64>(&intent, "intent_revision")? != completion.claimed.revision
            || get::<String>(&intent, "status")? != "pending_proof"
        {
            return Err(ApplicationError::RevisionConflict);
        }
        let slot = lock_slot(
            &transaction,
            completion.claimed.id,
            completion.proof_slot_id,
        )
        .await?;
        if get::<String>(&slot, "state")? != "provider_exchange_in_progress"
            || get::<String>(&slot, "method_kind")? != "provider"
        {
            return Err(ApplicationError::RevisionConflict);
        }
        revalidate_slot_authority(
            &transaction,
            &intent,
            &slot,
            &self.required_runtime_process_ids,
        )
        .await?;
        let role = parse_role(&get::<String>(&slot, "slot_role")?)?;
        let timestamp = database_now(&transaction).await?;
        let evidence = if role == IdentityMutationSlotRole::CandidateIdentity {
            let material = completion
                .candidate_evidence
                .as_ref()
                .ok_or(ApplicationError::Integrity)?;
            validate_candidate_material(
                material,
                completion.claimed.project_id,
                completion.claimed.id,
                completion.proof_slot_id,
                IdentityMutationCandidateKind::Provider,
            )?;
            insert_candidate_evidence(
                &transaction,
                material,
                "provider",
                get(&intent, "expires_at")?,
                timestamp,
            )
            .await?;
            ReceiptEvidence::Candidate(
                material.context.evidence_id,
                material.context.evidence_revision,
            )
        } else {
            if completion.candidate_evidence.is_some() {
                return Err(ApplicationError::Integrity);
            }
            let identity_id = get::<Option<Uuid>>(&slot, "existing_provider_identity_id")?
                .ok_or(ApplicationError::Integrity)?;
            let identity = transaction
                .query_one_raw(statement(
                    "SELECT user_id,identity_revision,status,issuer,subject
                       FROM linked_identities WHERE project_id=$1 AND id=$2 FOR UPDATE",
                    vec![completion.claimed.project_id.into(), identity_id.into()],
                ))
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::RevisionConflict)?;
            if get::<String>(&identity, "status")? != "active"
                || get::<Uuid>(&identity, "user_id")? != get::<Uuid>(&slot, "proof_user_id")?
                || get::<i64>(&identity, "identity_revision")?
                    != get::<Option<i64>>(&slot, "expected_identity_revision")?
                        .ok_or(ApplicationError::Integrity)?
                || get::<String>(&identity, "issuer")? != completion.observation.issuer
                || get::<String>(&identity, "subject")? != completion.observation.subject
            {
                return Err(ApplicationError::RevisionConflict);
            }
            ReceiptEvidence::Provider(identity_id, get::<i64>(&identity, "identity_revision")?)
        };
        prove_slot(
            &transaction,
            &intent,
            &slot,
            evidence,
            completion.receipt_id,
            &completion.receipt_digest,
            timestamp,
        )
        .await?;
        let record = read_record(&transaction, completion.claimed.id).await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(record)
    }

    async fn fail_provider_callback(
        &self,
        claimed: &IdentityMutationRecord,
        proof_slot_id: Uuid,
        safe_outcome: &'static str,
        _now: OffsetDateTime,
    ) -> Result<FailIdentityMutationProvider, ApplicationError> {
        let transaction = self.begin().await?;
        let intent = lock_intent(&transaction, claimed.id).await?;
        if expire_locked_if_needed(&transaction, &intent).await? {
            let record = read_record(&transaction, claimed.id).await?;
            transaction.commit().await.map_err(persistence)?;
            return Ok(FailIdentityMutationProvider::Terminalized(record));
        }
        let slot = lock_slot(&transaction, claimed.id, proof_slot_id).await?;
        if get::<String>(&slot, "state")? != "provider_exchange_in_progress"
            || get::<i64>(&intent, "intent_revision")? != claimed.revision
        {
            let record = read_record(&transaction, claimed.id).await?;
            transaction.commit().await.map_err(persistence)?;
            return Ok(FailIdentityMutationProvider::TerminalWinner(record));
        }
        terminalize(&transaction, &intent, "cancelled").await?;
        append_mutation_outcome_audit(
            &transaction,
            claimed.project_id,
            claimed.id,
            get(&intent, "correlation_id")?,
            "runtime",
            "identity.mutation.provider.failed",
            safe_outcome,
        )
        .await?;
        let record = read_record(&transaction, claimed.id).await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(FailIdentityMutationProvider::Terminalized(record))
    }

    async fn begin_email(
        &self,
        intent_id: Uuid,
        proof_slot_id: Uuid,
        intent: &VersionedDigest,
        browser_binding: &VersionedDigest,
        csrf: &VersionedDigest,
        expected_revision: i64,
        _now: OffsetDateTime,
    ) -> Result<IdentityMutationRecord, ApplicationError> {
        let transaction = self.begin().await?;
        let (intent_row, slot) = lock_authenticated_slot(
            &transaction,
            intent_id,
            proof_slot_id,
            intent,
            browser_binding,
            csrf,
        )
        .await?;
        if expire_locked_if_needed(&transaction, &intent_row).await? {
            transaction.commit().await.map_err(persistence)?;
            return Err(ApplicationError::InvalidTransition);
        }
        require_pending_revision(&transaction, &intent_row, expected_revision).await?;
        if get::<String>(&slot, "state")? != "pending"
            || get::<String>(&slot, "method_kind")? != "email"
        {
            return Err(ApplicationError::InvalidTransition);
        }
        revalidate_slot_authority(
            &transaction,
            &intent_row,
            &slot,
            &self.required_runtime_process_ids,
        )
        .await?;
        let timestamp = database_now(&transaction).await?;
        let updated = transaction
            .execute_raw(statement(
                "UPDATE identity_mutation_proof_slots SET state='email_address_entry',
                        slot_revision=slot_revision+1,updated_at=$3
                  WHERE intent_id=$1 AND id=$2 AND state='pending'",
                vec![intent_id.into(), proof_slot_id.into(), timestamp.into()],
            ))
            .await
            .map_err(persistence)?;
        if updated.rows_affected() != 1 {
            return Err(ApplicationError::RevisionConflict);
        }
        bump_intent(&transaction, intent_id, expected_revision, timestamp).await?;
        let record = read_record(&transaction, intent_id).await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(record)
    }

    async fn prepare_email_generation(
        &self,
        intent_id: Uuid,
        proof_slot_id: Uuid,
        intent: &VersionedDigest,
        browser_binding: &VersionedDigest,
        csrf: &VersionedDigest,
        expected_revision: i64,
        _now: OffsetDateTime,
    ) -> Result<IdentityMutationEmailGenerationPreparation, ApplicationError> {
        let transaction = self.begin().await?;
        assert_email_ready(
            &transaction,
            self.fence.process_id(),
            self.fence.incarnation(),
        )
        .await?;
        let (intent_row, slot) = lock_authenticated_slot(
            &transaction,
            intent_id,
            proof_slot_id,
            intent,
            browser_binding,
            csrf,
        )
        .await?;
        if expire_locked_if_needed(&transaction, &intent_row).await? {
            transaction.commit().await.map_err(persistence)?;
            return Err(ApplicationError::InvalidTransition);
        }
        require_pending_revision(&transaction, &intent_row, expected_revision).await?;
        if !matches!(
            get::<String>(&slot, "state")?.as_str(),
            "email_address_entry" | "email_challenge_pending"
        ) || get::<String>(&slot, "method_kind")? != "email"
        {
            return Err(ApplicationError::InvalidTransition);
        }
        revalidate_slot_authority(
            &transaction,
            &intent_row,
            &slot,
            &self.required_runtime_process_ids,
        )
        .await?;
        let aggregate = transaction
            .query_one_raw(statement(
                "SELECT COALESCE(MAX(generation),0)::SMALLINT AS generation,
                        MAX(issued_at) AS last_issued_at
                   FROM email_challenges WHERE owner_kind='identity_mutation'
                    AND project_id=$1 AND identity_mutation_intent_id=$2
                    AND identity_mutation_proof_slot_id=$3",
                vec![
                    get::<Uuid>(&intent_row, "project_id")?.into(),
                    intent_id.into(),
                    proof_slot_id.into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        let policy =
            admitted_email_method(&transaction, &slot, &self.required_runtime_process_ids).await?;
        let generation: i16 = get(&aggregate, "generation")?;
        if generation >= policy.max_generations || generation >= 5 {
            return Err(ApplicationError::InvalidTransition);
        }
        let wall = database_clock(&transaction).await?;
        if get::<Option<OffsetDateTime>>(&aggregate, "last_issued_at")?.is_some_and(|last| {
            wall < last + time::Duration::seconds(i64::from(policy.resend_after_seconds))
        }) {
            return Err(ApplicationError::InvalidTransition);
        }
        let result = IdentityMutationEmailGenerationPreparation {
            project_id: get(&intent_row, "project_id")?,
            application_id: get(&slot, "application_id")?,
            intent_id,
            proof_slot_id,
            next_generation: generation + 1,
            intent_expires_at: lock_receipts_effective_deadline(&transaction, &intent_row).await?,
            policy,
        };
        transaction.commit().await.map_err(persistence)?;
        Ok(result)
    }

    async fn commit_email_generation(
        &self,
        generation: CommitIdentityMutationEmailGeneration,
    ) -> Result<IdentityMutationRecord, ApplicationError> {
        validate_generation(&generation)?;
        let transaction = self.begin().await?;
        assert_email_ready(
            &transaction,
            self.fence.process_id(),
            self.fence.incarnation(),
        )
        .await?;
        let intent = lock_intent(&transaction, generation.intent_id).await?;
        require_project(&intent, generation.project_id)?;
        if expire_locked_if_needed(&transaction, &intent).await? {
            transaction.commit().await.map_err(persistence)?;
            return Err(ApplicationError::InvalidTransition);
        }
        require_pending_revision(&transaction, &intent, generation.expected_intent_revision)
            .await?;
        let slot = lock_slot(&transaction, generation.intent_id, generation.proof_slot_id).await?;
        if !matches!(
            get::<String>(&slot, "state")?.as_str(),
            "email_address_entry" | "email_challenge_pending"
        ) || get::<String>(&slot, "method_kind")? != "email"
            || get::<Uuid>(&slot, "application_id")? != generation.application_id
        {
            return Err(ApplicationError::InvalidTransition);
        }
        revalidate_slot_authority(
            &transaction,
            &intent,
            &slot,
            &self.required_runtime_process_ids,
        )
        .await?;
        let policy =
            admitted_email_method(&transaction, &slot, &self.required_runtime_process_ids).await?;
        if policy != generation.admitted_method {
            return Err(ApplicationError::RevisionConflict);
        }
        let aggregate = transaction
            .query_one_raw(statement(
                "SELECT COALESCE(MAX(generation),0)::SMALLINT AS generation,
                        MAX(issued_at) AS last_issued_at
                   FROM email_challenges WHERE owner_kind='identity_mutation'
                    AND project_id=$1 AND identity_mutation_intent_id=$2
                    AND identity_mutation_proof_slot_id=$3",
                vec![
                    generation.project_id.into(),
                    generation.intent_id.into(),
                    generation.proof_slot_id.into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        if get::<i16>(&aggregate, "generation")? + 1 != generation.expected_generation
            || generation.expected_generation > policy.max_generations
        {
            return Err(ApplicationError::RevisionConflict);
        }
        let timestamp = database_now(&transaction).await?;
        if get::<Option<OffsetDateTime>>(&aggregate, "last_issued_at")?.is_some_and(|last| {
            timestamp < last + time::Duration::seconds(i64::from(policy.resend_after_seconds))
        }) {
            return Err(ApplicationError::InvalidTransition);
        }
        let intent_expiry: OffsetDateTime = get(&intent, "expires_at")?;
        let otp_expiry = generation.otp_digest.as_ref().map(|_| {
            (timestamp + time::Duration::seconds(i64::from(policy.otp_validity_seconds)))
                .min(intent_expiry)
        });
        let magic_expiry = generation.magic_digest.as_ref().map(|_| {
            (timestamp + time::Duration::seconds(i64::from(policy.magic_validity_seconds)))
                .min(intent_expiry)
        });
        let challenge_expiry = otp_expiry
            .into_iter()
            .chain(magic_expiry)
            .max()
            .ok_or(ApplicationError::InvalidInput)?;
        transaction
            .execute_raw(statement(
                "UPDATE mail_outbox outbox SET status='cancelled',safe_outcome='expired',
                        lease_owner=NULL,lease_expires_at=NULL,terminal_at=$4,updated_at=$4
                   FROM email_challenges challenge
                  WHERE challenge.owner_kind='identity_mutation' AND challenge.project_id=$1
                    AND challenge.identity_mutation_intent_id=$2
                    AND challenge.identity_mutation_proof_slot_id=$3
                    AND outbox.project_id=challenge.project_id AND outbox.challenge_id=challenge.id
                    AND outbox.challenge_generation=challenge.generation
                    AND (outbox.status IN ('pending','retry','ambiguous')
                     OR (outbox.status='leased' AND outbox.lease_expires_at<=clock_timestamp()))",
                vec![
                    generation.project_id.into(),
                    generation.intent_id.into(),
                    generation.proof_slot_id.into(),
                    timestamp.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        transaction
            .execute_raw(statement(
                "UPDATE email_challenges SET status='superseded',terminal_at=$4,updated_at=$4
                  WHERE owner_kind='identity_mutation' AND project_id=$1
                    AND identity_mutation_intent_id=$2 AND identity_mutation_proof_slot_id=$3
                    AND status='pending'",
                vec![
                    generation.project_id.into(),
                    generation.intent_id.into(),
                    generation.proof_slot_id.into(),
                    timestamp.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        transaction
            .execute_raw(statement(
                "INSERT INTO email_challenges
                 (id,project_id,application_id,owner_kind,transaction_id,
                  identity_mutation_intent_id,identity_mutation_proof_slot_id,generation,status,
                  canonicalization_version,lookup_digest,lookup_digest_key_version,
                  address_ciphertext,address_key_version,otp_digest,otp_digest_key_version,
                  otp_attempts,otp_max_attempts,magic_digest,magic_digest_key_version,
                  method_policy_revision,method_security_revision,assignment_security_revision,
                  smtp_selection_kind,smtp_configuration_id,smtp_generation,
                  smtp_security_eligibility_revision,browser_binding_required,issued_at,
                  otp_expires_at,magic_expires_at,expires_at,created_at,updated_at)
                 VALUES ($1,$2,$3,'identity_mutation',NULL,$4,$5,$6,'pending',$7,$8,$9,$10,$11,
                         $12,$13,0,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$25,$25)",
                vec![
                    generation.challenge_id.into(),
                    generation.project_id.into(),
                    generation.application_id.into(),
                    generation.intent_id.into(),
                    generation.proof_slot_id.into(),
                    generation.expected_generation.into(),
                    generation.canonicalization_version.into(),
                    generation.lookup_digest.value.to_vec().into(),
                    generation.lookup_digest.key_version.into(),
                    generation.address.ciphertext.into(),
                    generation.address.key_version.into(),
                    generation.otp_digest.as_ref().map(|v| v.value.to_vec()).into(),
                    generation.otp_digest.as_ref().map(|v| v.key_version).into(),
                    policy.otp_max_attempts.into(),
                    generation.magic_digest.as_ref().map(|v| v.value.to_vec()).into(),
                    generation.magic_digest.as_ref().map(|v| v.key_version).into(),
                    policy.policy_revision.into(),
                    policy.security_revision.into(),
                    policy.assignment_security_revision.into(),
                    policy.smtp_selection_kind.clone().into(),
                    policy.smtp_configuration_id.into(),
                    policy.smtp_generation.into(),
                    policy.smtp_security_eligibility_revision.into(),
                    (!policy.transferred_magic_link_enabled).into(),
                    timestamp.into(),
                    otp_expiry.into(),
                    magic_expiry.into(),
                    challenge_expiry.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        transaction
            .execute_raw(statement(
                "INSERT INTO mail_outbox
                 (id,project_id,transaction_id,challenge_id,challenge_generation,status,
                  smtp_selection_kind,smtp_configuration_id,smtp_generation,
                  smtp_security_eligibility_revision,message_id,envelope_ciphertext,
                  envelope_key_version,body_ciphertext,body_key_version,attempts,max_attempts,
                  next_attempt_at,safe_outcome,useful_until,terminal_at,created_at,updated_at)
                 VALUES ($1,$2,NULL,$3,$4,CASE WHEN $16 THEN 'cancelled' ELSE 'pending' END,
                         $5,$6,$7,$8,$9,$10,$11,$12,$13,0,5,$14,
                         CASE WHEN $16 THEN 'policy_denied' ELSE NULL END,$15,
                         CASE WHEN $16 THEN $14 ELSE NULL END,$14,$14)",
                vec![
                    generation.outbox_id.into(),
                    generation.project_id.into(),
                    generation.challenge_id.into(),
                    generation.expected_generation.into(),
                    policy.smtp_selection_kind.into(),
                    policy.smtp_configuration_id.into(),
                    policy.smtp_generation.into(),
                    policy.smtp_security_eligibility_revision.into(),
                    generation.message_id.into(),
                    generation.envelope.ciphertext.into(),
                    generation.envelope.key_version.into(),
                    generation.body.ciphertext.into(),
                    generation.body.key_version.into(),
                    timestamp.into(),
                    challenge_expiry.into(),
                    generation.suppress_delivery.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        let updated = transaction
            .execute_raw(statement(
                "UPDATE identity_mutation_proof_slots
                    SET state='email_challenge_pending',slot_revision=slot_revision+1,updated_at=$3
                  WHERE intent_id=$1 AND id=$2
                    AND state IN ('email_address_entry','email_challenge_pending')",
                vec![
                    generation.intent_id.into(),
                    generation.proof_slot_id.into(),
                    timestamp.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        if updated.rows_affected() != 1 {
            return Err(ApplicationError::RevisionConflict);
        }
        bump_intent(
            &transaction,
            generation.intent_id,
            generation.expected_intent_revision,
            timestamp,
        )
        .await?;
        let record = read_record(&transaction, generation.intent_id).await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(record)
    }

    async fn establish_magic_transfer_context(
        &self,
        command: EstablishIdentityMutationMagicTransferContext,
    ) -> Result<EstablishedIdentityMutationMagicTransferContext, ApplicationError> {
        validate_digest(&command.context)?;
        validate_digest(&command.csrf)?;
        let transaction = self.begin().await?;
        assert_email_ready(
            &transaction,
            self.fence.process_id(),
            self.fence.incarnation(),
        )
        .await?;
        let owner = magic_transfer_owner(&transaction, command.challenge_id).await?;
        let intent = lock_intent(&transaction, owner.intent_id).await?;
        require_project(&intent, owner.project_id)?;
        if expire_locked_if_needed(&transaction, &intent).await? {
            transaction.commit().await.map_err(persistence)?;
            return Err(ApplicationError::NotFound);
        }
        let challenge = lock_owned_challenge(&transaction, &owner, true).await?;
        let timestamp = database_now(&transaction).await?;
        if get::<OffsetDateTime>(&challenge, "challenge_expires_at")? <= timestamp {
            terminalize(&transaction, &intent, "expired").await?;
            transaction.commit().await.map_err(persistence)?;
            return Err(ApplicationError::NotFound);
        }
        transaction
            .execute_raw(statement(
                "UPDATE magic_transfer_contexts SET status='expired'
                  WHERE challenge_id=$1 AND status='pending' AND expires_at<=clock_timestamp()",
                vec![owner.challenge_id.into()],
            ))
            .await
            .map_err(persistence)?;
        let count = transaction
            .query_one_raw(statement(
                "SELECT COUNT(*)::BIGINT AS count FROM magic_transfer_contexts
                  WHERE challenge_id=$1 AND status='pending' AND expires_at>clock_timestamp()",
                vec![owner.challenge_id.into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        if get::<i64>(&count, "count")? >= MAX_MAGIC_CONTEXTS {
            return Err(ApplicationError::NotFound);
        }
        let expires_at = (timestamp + time::Duration::minutes(5))
            .min(get(&challenge, "challenge_expires_at")?)
            .min(get(&challenge, "intent_expires_at")?);
        transaction
            .execute_raw(statement(
                "INSERT INTO magic_transfer_contexts
                 (id,challenge_id,context_digest,context_digest_key_version,csrf_digest,
                  csrf_digest_key_version,browser_binding_required,status,expires_at,created_at)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,'pending',$8,$9)",
                vec![
                    command.id.into(),
                    owner.challenge_id.into(),
                    command.context.value.to_vec().into(),
                    command.context.key_version.into(),
                    command.csrf.value.to_vec().into(),
                    command.csrf.key_version.into(),
                    get::<bool>(&challenge, "browser_binding_required")?.into(),
                    expires_at.into(),
                    timestamp.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        let established = EstablishedIdentityMutationMagicTransferContext {
            owner,
            project_public_id: get(&challenge, "project_public_id")?,
            expected_intent_revision: get(&intent, "intent_revision")?,
        };
        transaction.commit().await.map_err(persistence)?;
        Ok(established)
    }

    async fn resolve_magic_transfer_context(
        &self,
        command: ResolveIdentityMutationMagicTransferContext,
    ) -> Result<ResolvedIdentityMutationMagicTransferContext, ApplicationError> {
        validate_digest(&command.intent)?;
        validate_digest(&command.context)?;
        validate_digest(&command.csrf)?;
        let transaction = self.begin().await?;
        assert_email_ready(
            &transaction,
            self.fence.process_id(),
            self.fence.incarnation(),
        )
        .await?;
        let owner = magic_transfer_owner(&transaction, command.challenge_id).await?;
        let intent = lock_intent(&transaction, owner.intent_id).await?;
        require_project(&intent, owner.project_id)?;
        require_digest_columns(
            &intent,
            "hosted_handle_digest",
            "hosted_handle_digest_key_version",
            &command.intent,
        )?;
        if expire_locked_if_needed(&transaction, &intent).await? {
            transaction.commit().await.map_err(persistence)?;
            return Err(ApplicationError::NotFound);
        }
        let challenge = lock_owned_challenge(&transaction, &owner, true).await?;
        if get::<OffsetDateTime>(&challenge, "challenge_expires_at")?
            <= database_clock(&transaction).await?
        {
            terminalize(&transaction, &intent, "expired").await?;
            transaction.commit().await.map_err(persistence)?;
            return Err(ApplicationError::NotFound);
        }
        if get::<String>(&challenge, "project_public_id")? != command.project_public_id {
            return Err(ApplicationError::NotFound);
        }
        transaction
            .query_one_raw(statement(
                "SELECT id FROM magic_transfer_contexts
                  WHERE challenge_id=$1 AND context_digest=$2 AND context_digest_key_version=$3
                    AND csrf_digest=$4 AND csrf_digest_key_version=$5
                    AND status='pending' AND expires_at>clock_timestamp() FOR UPDATE",
                vec![
                    owner.challenge_id.into(),
                    command.context.value.to_vec().into(),
                    command.context.key_version.into(),
                    command.csrf.value.to_vec().into(),
                    command.csrf.key_version.into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let result = ResolvedIdentityMutationMagicTransferContext {
            owner,
            project_public_id: command.project_public_id,
            expected_intent_revision: get(&intent, "intent_revision")?,
        };
        transaction.commit().await.map_err(persistence)?;
        Ok(result)
    }

    async fn email_proof_key_version(
        &self,
        key: IdentityMutationEmailProofKey,
    ) -> Result<Option<i32>, ApplicationError> {
        let column = match key.proof_kind {
            EmailProofKind::Otp => "otp_digest_key_version",
            EmailProofKind::MagicLink => "magic_digest_key_version",
        };
        let transaction = self.begin().await?;
        assert_email_ready(
            &transaction,
            self.fence.process_id(),
            self.fence.incarnation(),
        )
        .await?;
        let intent = lock_intent(&transaction, key.intent_id).await?;
        require_project(&intent, key.project_id)?;
        if expire_locked_if_needed(&transaction, &intent).await? {
            transaction.commit().await.map_err(persistence)?;
            return Ok(None);
        }
        let sql = format!(
            "SELECT challenge.{column} AS key_version FROM email_challenges challenge
               JOIN identity_mutation_intents intent
                 ON intent.project_id=challenge.project_id
                AND intent.id=challenge.identity_mutation_intent_id
               JOIN identity_mutation_proof_slots slot
                 ON slot.project_id=challenge.project_id
                AND slot.intent_id=challenge.identity_mutation_intent_id
                AND slot.id=challenge.identity_mutation_proof_slot_id
              WHERE challenge.owner_kind='identity_mutation' AND challenge.project_id=$1
                AND challenge.identity_mutation_intent_id=$2
                AND challenge.identity_mutation_proof_slot_id=$3 AND challenge.id=$4
                AND challenge.status='pending' AND challenge.expires_at>clock_timestamp()
                AND intent.status='pending_proof' AND intent.expires_at>clock_timestamp()
                AND slot.state='email_challenge_pending'
                AND NOT EXISTS (SELECT 1 FROM email_challenges newer
                  WHERE newer.owner_kind='identity_mutation'
                    AND newer.project_id=challenge.project_id
                    AND newer.identity_mutation_intent_id=challenge.identity_mutation_intent_id
                    AND newer.identity_mutation_proof_slot_id=challenge.identity_mutation_proof_slot_id
                    AND newer.generation>challenge.generation)"
        );
        let row = transaction
            .query_one_raw(statement(
                &sql,
                vec![
                    key.project_id.into(),
                    key.intent_id.into(),
                    key.proof_slot_id.into(),
                    key.challenge_id.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        let result = row
            .as_ref()
            .map(|row| get::<Option<i32>>(row, "key_version"))
            .transpose()?
            .flatten();
        if row.is_none()
            && transaction
                .query_one_raw(statement(
                    "SELECT 1 FROM email_challenges
                      WHERE owner_kind='identity_mutation' AND project_id=$1
                        AND identity_mutation_intent_id=$2
                        AND identity_mutation_proof_slot_id=$3 AND id=$4
                        AND status='pending' AND expires_at<=clock_timestamp() FOR UPDATE",
                    vec![
                        key.project_id.into(),
                        key.intent_id.into(),
                        key.proof_slot_id.into(),
                        key.challenge_id.into(),
                    ],
                ))
                .await
                .map_err(persistence)?
                .is_some()
        {
            terminalize(&transaction, &intent, "expired").await?;
        }
        transaction.commit().await.map_err(persistence)?;
        Ok(result)
    }

    async fn verify_email_proof(
        &self,
        verification: VerifyIdentityMutationEmailProof,
    ) -> Result<IdentityMutationEmailProofDecision, ApplicationError> {
        validate_verification(&verification)?;
        let transaction = self.begin().await?;
        assert_email_ready(
            &transaction,
            self.fence.process_id(),
            self.fence.incarnation(),
        )
        .await?;
        let intent = lock_intent(&transaction, verification.intent_id).await?;
        require_project(&intent, verification.project_id)?;
        if expire_locked_if_needed(&transaction, &intent).await? {
            transaction.commit().await.map_err(persistence)?;
            return Ok(IdentityMutationEmailProofDecision::Invalid);
        }
        if get::<i64>(&intent, "intent_revision")? != verification.expected_intent_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        let slot = lock_slot(
            &transaction,
            verification.intent_id,
            verification.proof_slot_id,
        )
        .await?;
        let challenge = lock_challenge(&transaction, &verification).await?;
        if get::<String>(&challenge, "status")? == "pending"
            && get::<OffsetDateTime>(&challenge, "expires_at")?
                <= database_clock(&transaction).await?
        {
            terminalize(&transaction, &intent, "expired").await?;
            transaction.commit().await.map_err(persistence)?;
            return Ok(IdentityMutationEmailProofDecision::Invalid);
        }
        if !challenge_is_live(&transaction, &intent, &slot, &challenge, &verification).await? {
            transaction.commit().await.map_err(persistence)?;
            return Ok(IdentityMutationEmailProofDecision::Invalid);
        }
        revalidate_slot_authority(
            &transaction,
            &intent,
            &slot,
            &self.required_runtime_process_ids,
        )
        .await?;
        if !proof_matches(&challenge, &verification)? {
            if verification.proof_kind == EmailProofKind::Otp {
                let timestamp = database_now(&transaction).await?;
                let exhausts = get::<i16>(&challenge, "otp_attempts")?
                    .checked_add(1)
                    .ok_or(ApplicationError::Integrity)?
                    >= get::<i16>(&challenge, "otp_max_attempts")?;
                transaction
                    .execute_raw(statement(
                        "UPDATE email_challenges SET otp_attempts=otp_attempts+1,
                          status=CASE WHEN otp_attempts+1>=otp_max_attempts THEN 'exhausted' ELSE status END,
                          terminal_at=CASE WHEN otp_attempts+1>=otp_max_attempts THEN $2 ELSE terminal_at END,
                          updated_at=$2 WHERE id=$1 AND status='pending'",
                        vec![verification.challenge_id.into(), timestamp.into()],
                    ))
                    .await
                    .map_err(persistence)?;
                // A typed mutation challenge cannot become terminal while its aggregate remains
                // live. Complete the aggregate transition in this same transaction so the final
                // wrong OTP persists instead of failing the deferred owner constraint at commit.
                if exhausts {
                    terminalize(&transaction, &intent, "cancelled").await?;
                }
            }
            transaction.commit().await.map_err(persistence)?;
            return Ok(IdentityMutationEmailProofDecision::Invalid);
        }
        let accepted = verified_challenge(&slot, &challenge)?;
        transaction.commit().await.map_err(persistence)?;
        Ok(IdentityMutationEmailProofDecision::Accepted(accepted))
    }

    async fn complete_email_proof(
        &self,
        completion: CompleteIdentityMutationEmailProof,
    ) -> Result<IdentityMutationRecord, ApplicationError> {
        validate_verification(&completion.verification)?;
        validate_digest(&completion.verified_challenge_lookup)?;
        validate_digest(&completion.receipt_digest)?;
        let transaction = self.begin().await?;
        assert_email_ready(
            &transaction,
            self.fence.process_id(),
            self.fence.incarnation(),
        )
        .await?;
        let verification = &completion.verification;
        let intent = lock_intent(&transaction, verification.intent_id).await?;
        require_project(&intent, verification.project_id)?;
        if expire_locked_if_needed(&transaction, &intent).await? {
            transaction.commit().await.map_err(persistence)?;
            return Err(ApplicationError::InvalidTransition);
        }
        if get::<i64>(&intent, "intent_revision")? != verification.expected_intent_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        let slot = lock_slot(
            &transaction,
            verification.intent_id,
            verification.proof_slot_id,
        )
        .await?;
        let challenge = lock_challenge(&transaction, verification).await?;
        if get::<String>(&challenge, "status")? == "pending"
            && get::<OffsetDateTime>(&challenge, "expires_at")?
                <= database_clock(&transaction).await?
        {
            terminalize(&transaction, &intent, "expired").await?;
            transaction.commit().await.map_err(persistence)?;
            return Err(ApplicationError::InvalidTransition);
        }
        if !challenge_is_live(&transaction, &intent, &slot, &challenge, verification).await?
            || !proof_matches(&challenge, verification)?
        {
            return Err(ApplicationError::InvalidTransition);
        }
        revalidate_slot_authority(
            &transaction,
            &intent,
            &slot,
            &self.required_runtime_process_ids,
        )
        .await?;
        require_digest_columns(
            &challenge,
            "lookup_digest",
            "lookup_digest_key_version",
            &completion.verified_challenge_lookup,
        )?;
        let timestamp = database_now(&transaction).await?;
        let role = parse_role(&get::<String>(&slot, "slot_role")?)?;
        let evidence = match &completion.material {
            IdentityMutationEmailProofMaterial::Candidate(material) => {
                if role != IdentityMutationSlotRole::CandidateIdentity {
                    return Err(ApplicationError::Integrity);
                }
                validate_candidate_material(
                    material,
                    verification.project_id,
                    verification.intent_id,
                    verification.proof_slot_id,
                    IdentityMutationCandidateKind::Email,
                )?;
                insert_candidate_evidence(
                    &transaction,
                    material,
                    "email",
                    get(&intent, "expires_at")?,
                    timestamp,
                )
                .await?;
                ReceiptEvidence::Candidate(
                    material.context.evidence_id,
                    material.context.evidence_revision,
                )
            }
            IdentityMutationEmailProofMaterial::Existing(material) => {
                if role == IdentityMutationSlotRole::CandidateIdentity {
                    return Err(ApplicationError::Integrity);
                }
                revalidate_existing_email(
                    &transaction,
                    verification.project_id,
                    &slot,
                    material,
                    &completion.verified_challenge_lookup,
                )
                .await?;
                ReceiptEvidence::Email(material.identity_id, material.identity_revision)
            }
        };
        let consumed = transaction
            .execute_raw(statement(
                "UPDATE email_challenges SET status='consumed',consumed_at=$2,terminal_at=$2,
                        updated_at=$2 WHERE id=$1 AND status='pending'
                        AND expires_at>clock_timestamp()",
                vec![verification.challenge_id.into(), timestamp.into()],
            ))
            .await
            .map_err(persistence)?;
        if consumed.rows_affected() != 1 {
            return Err(ApplicationError::RevisionConflict);
        }
        if let Some(context) = &verification.transfer_context {
            let consumed = transaction
                .execute_raw(statement(
                    "UPDATE magic_transfer_contexts SET status='consumed',consumed_at=$6
                      WHERE challenge_id=$1 AND context_digest=$2 AND context_digest_key_version=$3
                        AND csrf_digest=$4 AND csrf_digest_key_version=$5
                        AND status='pending' AND expires_at>clock_timestamp()",
                    vec![
                        verification.challenge_id.into(),
                        context.value.to_vec().into(),
                        context.key_version.into(),
                        verification.csrf.value.to_vec().into(),
                        verification.csrf.key_version.into(),
                        timestamp.into(),
                    ],
                ))
                .await
                .map_err(persistence)?;
            if consumed.rows_affected() != 1 {
                return Err(ApplicationError::RevisionConflict);
            }
        }
        prove_slot(
            &transaction,
            &intent,
            &slot,
            evidence,
            completion.receipt_id,
            &completion.receipt_digest,
            timestamp,
        )
        .await?;
        let record = read_record(&transaction, verification.intent_id).await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(record)
    }

    async fn identity_alias_authority(
        &self,
    ) -> Result<EmailIdentityAliasAuthority, ApplicationError> {
        let transaction = self.begin().await?;
        assert_email_ready(
            &transaction,
            self.fence.process_id(),
            self.fence.incarnation(),
        )
        .await?;
        let row = transaction
            .query_one_raw(statement(
                "SELECT revision,write_version,accepted_versions
                   FROM email_identity_alias_authority WHERE singleton=TRUE FOR SHARE",
                vec![],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        let result = alias_authority(&row)?;
        transaction.commit().await.map_err(persistence)?;
        Ok(result)
    }

    async fn confirm_ready(
        &self,
        intent_id: Uuid,
        intent: &VersionedDigest,
        browser_binding: &VersionedDigest,
        csrf: &VersionedDigest,
        expected_revision: i64,
        _now: OffsetDateTime,
    ) -> Result<IdentityMutationRecord, ApplicationError> {
        let transaction = self.begin().await?;
        let row = lock_authenticated_intent(&transaction, intent_id, intent, browser_binding, csrf)
            .await?;
        if expire_locked_if_needed(&transaction, &row).await? {
            let record = read_record(&transaction, intent_id).await?;
            transaction.commit().await.map_err(persistence)?;
            return Ok(record);
        }
        require_pending_revision(&transaction, &row, expected_revision).await?;
        let count = slot_count(&transaction, intent_id).await?;
        let fresh = transaction
            .query_one_raw(statement(
                "SELECT COUNT(*)::BIGINT AS count FROM identity_mutation_proof_slots slot
                   JOIN identity_proof_receipts receipt
                     ON receipt.project_id=slot.project_id AND receipt.intent_id=slot.intent_id
                    AND receipt.slot_id=slot.id
                  WHERE slot.intent_id=$1 AND slot.state='proved' AND receipt.status='issued'
                    AND receipt.expires_at>clock_timestamp()",
                vec![intent_id.into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        if get::<i64>(&fresh, "count")? != count {
            return Err(ApplicationError::InvalidTransition);
        }
        let timestamp = database_now(&transaction).await?;
        let updated = transaction
            .execute_raw(statement(
                "UPDATE identity_mutation_intents SET status='ready',ready_at=$3,
                        intent_revision=intent_revision+1,updated_at=$3
                  WHERE id=$1 AND status='pending_proof' AND intent_revision=$2
                    AND expires_at>clock_timestamp()",
                vec![intent_id.into(), expected_revision.into(), timestamp.into()],
            ))
            .await
            .map_err(persistence)?;
        if updated.rows_affected() != 1 {
            return Err(ApplicationError::RevisionConflict);
        }
        let record = read_record(&transaction, intent_id).await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(record)
    }
}

struct FrozenColumns {
    destination: Option<(Uuid, i64, i64)>,
    owner: Option<(Uuid, i64, i64)>,
    winner: Option<(Uuid, i64, i64)>,
    loser: Option<(Uuid, i64, i64)>,
    primary_kind: &'static str,
    primary_provider: Option<Uuid>,
    primary_email: Option<Uuid>,
    primary_revision: Option<i64>,
    sessions: Option<&'static str>,
    bindings: Option<&'static str>,
}

fn frozen_columns(operation: &IdentityMutationCreateOperation) -> FrozenColumns {
    match operation {
        IdentityMutationCreateOperation::Link { destination, .. } => FrozenColumns {
            destination: Some((
                destination.user_id,
                destination.expected_user_revision,
                destination.expected_user_security_revision,
            )),
            owner: None,
            winner: None,
            loser: None,
            primary_kind: "preserve",
            primary_provider: None,
            primary_email: None,
            primary_revision: None,
            sessions: None,
            bindings: None,
        },
        IdentityMutationCreateOperation::Unlink {
            owner,
            primary_source,
            ..
        } => {
            let (kind, provider, email, revision) = primary_columns(*primary_source);
            FrozenColumns {
                destination: None,
                owner: Some((
                    owner.user_id,
                    owner.expected_user_revision,
                    owner.expected_user_security_revision,
                )),
                winner: None,
                loser: None,
                primary_kind: kind,
                primary_provider: provider,
                primary_email: email,
                primary_revision: revision,
                sessions: None,
                bindings: None,
            }
        }
        IdentityMutationCreateOperation::Merge {
            winner,
            loser,
            primary_source,
            sessions,
            bindings,
            ..
        } => {
            let (kind, provider, email, revision) = primary_columns(*primary_source);
            FrozenColumns {
                destination: None,
                owner: None,
                winner: Some((
                    winner.user_id,
                    winner.expected_user_revision,
                    winner.expected_user_security_revision,
                )),
                loser: Some((
                    loser.user_id,
                    loser.expected_user_revision,
                    loser.expected_user_security_revision,
                )),
                primary_kind: kind,
                primary_provider: provider,
                primary_email: email,
                primary_revision: revision,
                sessions: Some(match sessions {
                    IdentityMutationSessionsDisposition::LoserRevoked => "loser_revoked",
                }),
                bindings: Some(match bindings {
                    IdentityMutationBindingsDisposition::WinnerPreferred => "winner_preferred",
                }),
            }
        }
    }
}

fn primary_columns(
    disposition: IdentityMutationPrimarySourceDisposition,
) -> (&'static str, Option<Uuid>, Option<Uuid>, Option<i64>) {
    match disposition {
        IdentityMutationPrimarySourceDisposition::Preserve => ("preserve", None, None, None),
        IdentityMutationPrimarySourceDisposition::Provider(identity) => (
            "provider",
            Some(identity.identity_id),
            None,
            Some(identity.expected_identity_revision),
        ),
        IdentityMutationPrimarySourceDisposition::Email(identity) => (
            "email",
            None,
            Some(identity.identity_id),
            Some(identity.expected_identity_revision),
        ),
        IdentityMutationPrimarySourceDisposition::Clear => ("clear", None, None, None),
    }
}

async fn validate_primary_source_create(
    transaction: &DatabaseTransaction,
    project_id: Uuid,
    operation: &IdentityMutationCreateOperation,
) -> Result<(), ApplicationError> {
    let (identity, allowed_owners): (Option<crate::application::ExpectedIdentity>, Vec<Uuid>) =
        match operation {
            IdentityMutationCreateOperation::Unlink {
                owner,
                primary_source,
                ..
            } => (
                match primary_source {
                    IdentityMutationPrimarySourceDisposition::Provider(identity)
                    | IdentityMutationPrimarySourceDisposition::Email(identity) => Some(*identity),
                    IdentityMutationPrimarySourceDisposition::Preserve
                    | IdentityMutationPrimarySourceDisposition::Clear => None,
                },
                vec![owner.user_id],
            ),
            IdentityMutationCreateOperation::Merge {
                winner,
                loser,
                primary_source,
                ..
            } => (
                match primary_source {
                    IdentityMutationPrimarySourceDisposition::Provider(identity)
                    | IdentityMutationPrimarySourceDisposition::Email(identity) => Some(*identity),
                    IdentityMutationPrimarySourceDisposition::Preserve
                    | IdentityMutationPrimarySourceDisposition::Clear => None,
                },
                vec![winner.user_id, loser.user_id],
            ),
            IdentityMutationCreateOperation::Link { .. } => (None, Vec::new()),
        };
    let Some(identity) = identity else {
        return Ok(());
    };
    let table = match identity.identity_kind {
        IdentityKind::Provider => "linked_identities",
        IdentityKind::Email => "email_identities",
    };
    let sql = format!(
        "SELECT user_id,identity_revision,status FROM {table}
          WHERE project_id=$1 AND id=$2 FOR SHARE"
    );
    let row = transaction
        .query_one_raw(statement(
            &sql,
            vec![project_id.into(), identity.identity_id.into()],
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::RevisionConflict)?;
    if !allowed_owners.contains(&get::<Uuid>(&row, "user_id")?)
        || get::<i64>(&row, "identity_revision")? != identity.expected_identity_revision
        || get::<String>(&row, "status")? != "active"
    {
        return Err(ApplicationError::RevisionConflict);
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "slot derivation keeps its deterministic graph lock and frozen snapshot sequence contiguous"
)]
async fn derive_and_lock_slots(
    transaction: &DatabaseTransaction,
    project_id: Uuid,
    operation: &IdentityMutationCreateOperation,
) -> Result<Vec<SlotSeed>, ApplicationError> {
    let seeds = match operation {
        IdentityMutationCreateOperation::Link {
            destination,
            destination_identity,
            candidate_kind,
            destination_authority,
            candidate_authority,
        } => vec![
            SlotSeed {
                id: Uuid::new_v4(),
                ordinal: 1,
                role: IdentityMutationSlotRole::DestinationOwner,
                identity_kind: destination_identity.identity_kind,
                user_id: destination.user_id,
                user_revision: destination.expected_user_revision,
                user_security_revision: destination.expected_user_security_revision,
                identity_id: Some(destination_identity.identity_id),
                identity_revision: Some(destination_identity.expected_identity_revision),
                authority: *destination_authority,
            },
            SlotSeed {
                id: Uuid::new_v4(),
                ordinal: 2,
                role: IdentityMutationSlotRole::CandidateIdentity,
                identity_kind: *candidate_kind,
                user_id: destination.user_id,
                user_revision: destination.expected_user_revision,
                user_security_revision: destination.expected_user_security_revision,
                identity_id: None,
                identity_revision: None,
                authority: *candidate_authority,
            },
        ],
        IdentityMutationCreateOperation::Unlink {
            owner,
            identity,
            authority,
            ..
        } => vec![SlotSeed {
            id: Uuid::new_v4(),
            ordinal: 1,
            role: IdentityMutationSlotRole::IdentityOwner,
            identity_kind: identity.identity_kind,
            user_id: owner.user_id,
            user_revision: owner.expected_user_revision,
            user_security_revision: owner.expected_user_security_revision,
            identity_id: Some(identity.identity_id),
            identity_revision: Some(identity.expected_identity_revision),
            authority: *authority,
        }],
        IdentityMutationCreateOperation::Merge {
            winner,
            winner_identity,
            loser,
            loser_identity,
            winner_authority,
            loser_authority,
            ..
        } => vec![
            SlotSeed {
                id: Uuid::new_v4(),
                ordinal: 1,
                role: IdentityMutationSlotRole::WinnerOwner,
                identity_kind: winner_identity.identity_kind,
                user_id: winner.user_id,
                user_revision: winner.expected_user_revision,
                user_security_revision: winner.expected_user_security_revision,
                identity_id: Some(winner_identity.identity_id),
                identity_revision: Some(winner_identity.expected_identity_revision),
                authority: *winner_authority,
            },
            SlotSeed {
                id: Uuid::new_v4(),
                ordinal: 2,
                role: IdentityMutationSlotRole::LoserOwner,
                identity_kind: loser_identity.identity_kind,
                user_id: loser.user_id,
                user_revision: loser.expected_user_revision,
                user_security_revision: loser.expected_user_security_revision,
                identity_id: Some(loser_identity.identity_id),
                identity_revision: Some(loser_identity.expected_identity_revision),
                authority: *loser_authority,
            },
        ],
    };
    for seed in &seeds {
        if method_kind(seed.authority) != seed.identity_kind {
            return Err(ApplicationError::InvalidInput);
        }
    }
    let mut users = seeds.iter().map(|seed| seed.user_id).collect::<Vec<_>>();
    users.sort_unstable();
    users.dedup();
    for user_id in users {
        let row = transaction
            .query_one_raw(statement(
                "SELECT user_revision,security_revision,status FROM project_users
                  WHERE project_id=$1 AND id=$2 FOR UPDATE",
                vec![project_id.into(), user_id.into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let seed = seeds
            .iter()
            .find(|seed| seed.user_id == user_id)
            .ok_or(ApplicationError::Integrity)?;
        if get::<String>(&row, "status")? != "active"
            || get::<i64>(&row, "user_revision")? != seed.user_revision
            || get::<i64>(&row, "security_revision")? != seed.user_security_revision
        {
            return Err(ApplicationError::RevisionConflict);
        }
    }
    let mut identities = seeds
        .iter()
        .filter(|seed| seed.identity_id.is_some())
        .collect::<Vec<_>>();
    identities.sort_unstable_by_key(|seed| seed.identity_id);
    for seed in identities {
        let table = identity_table(seed.identity_kind);
        let sql = format!(
            "SELECT user_id,identity_revision,status FROM {table}
              WHERE project_id=$1 AND id=$2 FOR UPDATE"
        );
        let row = transaction
            .query_one_raw(statement(
                &sql,
                vec![project_id.into(), seed.identity_id.into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if get::<Uuid>(&row, "user_id")? != seed.user_id
            || get::<String>(&row, "status")? != "active"
            || get::<i64>(&row, "identity_revision")? != seed.identity_revision.unwrap_or_default()
        {
            return Err(ApplicationError::RevisionConflict);
        }
    }
    Ok(seeds)
}

#[allow(
    clippy::too_many_lines,
    reason = "one transaction snapshot keeps provider and email authority fencing visibly atomic"
)]
async fn snapshot_method(
    transaction: &DatabaseTransaction,
    project_id: Uuid,
    project_public_id: &str,
    authority: IdentityMutationProofAuthoritySelection,
    prepared: &PreparedIdentityMutationCreate,
) -> Result<MethodSnapshot, ApplicationError> {
    let application_id = authority_application(authority);
    let application = transaction
        .query_one_raw(statement(
            "SELECT status,security_revision FROM applications
              WHERE project_id=$1 AND id=$2 FOR SHARE",
            vec![project_id.into(), application_id.into()],
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
    if get::<String>(&application, "status")? != "active" {
        return Err(ApplicationError::Disabled);
    }
    let application_revision = get(&application, "security_revision")?;
    match authority {
        IdentityMutationProofAuthoritySelection::Provider {
            provider_configuration_id,
            ..
        } => {
            let row = transaction
                .query_one_raw(statement(
                    "SELECT provider.kind AS provider_legacy_kind,provider.adapter_kind AS provider_adapter_kind,provider.issuer,provider.provider_key,provider.revision,provider.status,
                            provider.secret_ref,provider.secret_material_id,
                            assignment.status AS assignment_status,
                            assignment.security_revision AS assignment_revision,
                            egress.revision AS egress_policy_revision
                       FROM provider_configurations provider
                       JOIN application_provider_assignments assignment
                         ON assignment.project_id=provider.project_id
                        AND assignment.provider_id=provider.id AND assignment.application_id=$3
                       LEFT JOIN project_provider_egress_policies egress
                         ON egress.project_id=provider.project_id
                      WHERE provider.project_id=$1 AND provider.id=$2
                      FOR SHARE OF provider,assignment",
                    vec![
                        project_id.into(),
                        provider_configuration_id.into(),
                        application_id.into(),
                    ],
                ))
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::NotFound)?;
            if get::<String>(&row, "status")? != "active"
                || get::<String>(&row, "assignment_status")? != "active"
                || (get::<Option<String>>(&row, "secret_ref")?.is_none()
                    == get::<Option<Uuid>>(&row, "secret_material_id")?.is_none())
            {
                return Err(ApplicationError::Disabled);
            }
            let provider_kind = super::provider_row::effective_provider_kind(
                &get::<String>(&row, "provider_legacy_kind")?,
                get::<Option<String>>(&row, "provider_adapter_kind")?.as_deref(),
                &get::<String>(&row, "issuer")?,
            )?;
            let capabilities = provider_kind.capabilities();
            if !capabilities.identity_proof {
                return Err(ApplicationError::InvalidInput);
            }
            let capability = prepared
                .provider_capabilities
                .for_kind(provider_kind)
                .ok_or(ApplicationError::InvalidInput)?
                .snapshot(
                    &prepared.runtime_base,
                    project_public_id,
                    &get::<String>(&row, "provider_key")?,
                )?;
            if capability.adapter_key() != capabilities.adapter_key {
                return Err(ApplicationError::Integrity);
            }
            Ok(MethodSnapshot {
                application_revision,
                provider: Some(ProviderSnapshot {
                    provider_id: provider_configuration_id,
                    secret_material_id: get(&row, "secret_material_id")?,
                    revision: get(&row, "revision")?,
                    assignment_revision: get(&row, "assignment_revision")?,
                    egress_policy_revision: if provider_kind == ProviderKind::Oidc {
                        Some(required(&row, "egress_policy_revision")?)
                    } else {
                        None
                    },
                    adapter_key: capability.adapter_key().to_owned(),
                    adapter_revision: capability.adapter_capability_revision(),
                    scopes: capability.exact_non_renewable_proof_scopes().to_vec(),
                    callback_url: capability.callback().as_str().to_owned(),
                    pkce: capability.provider_pkce_required(),
                    nonce: capability.oidc_nonce_required(),
                }),
                email_policy_revision: None,
                email_security_revision: None,
                email_assignment_revision: None,
            })
        }
        IdentityMutationProofAuthoritySelection::Email { .. } => {
            let row = transaction
                .query_one_raw(statement(
                    "SELECT policy.status,policy.policy_revision,policy.security_revision,
                            assignment.status AS assignment_status,
                            assignment.security_revision AS assignment_revision
                       FROM project_email_policies policy
                       JOIN application_email_assignments assignment
                         ON assignment.project_id=policy.project_id AND assignment.application_id=$2
                      WHERE policy.project_id=$1 FOR SHARE OF policy,assignment",
                    vec![project_id.into(), application_id.into()],
                ))
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::NotFound)?;
            if get::<String>(&row, "status")? != "enabled"
                || get::<String>(&row, "assignment_status")? != "active"
            {
                return Err(ApplicationError::Disabled);
            }
            Ok(MethodSnapshot {
                application_revision,
                provider: None,
                email_policy_revision: Some(get(&row, "policy_revision")?),
                email_security_revision: Some(get(&row, "security_revision")?),
                email_assignment_revision: Some(get(&row, "assignment_revision")?),
            })
        }
    }
}

async fn insert_slot(
    transaction: &DatabaseTransaction,
    project_id: Uuid,
    intent_id: Uuid,
    slot: &SlotSeed,
    snapshot: &MethodSnapshot,
    now: OffsetDateTime,
) -> Result<(), ApplicationError> {
    let provider = snapshot.provider.as_ref();
    let application_id = authority_application(slot.authority);
    let provider_identity = if slot.identity_kind == IdentityKind::Provider {
        slot.identity_id
    } else {
        None
    };
    let email_identity = if slot.identity_kind == IdentityKind::Email {
        slot.identity_id
    } else {
        None
    };
    transaction
        .execute_raw(statement(
            "INSERT INTO identity_mutation_proof_slots
             (id,project_id,intent_id,slot_ordinal,slot_role,purpose,identity_kind,proof_user_id,
              expected_user_revision,expected_user_security_revision,existing_provider_identity_id,
              existing_email_identity_id,expected_identity_revision,application_id,
              application_security_revision,method_kind,provider_adapter_key,
              provider_adapter_capability_revision,provider_configuration_id,provider_revision,
              provider_egress_policy_revision,provider_assignment_security_revision,provider_scopes,callback_url,
              provider_pkce_required,oidc_nonce_required,provider_secret_material_id,
              email_assignment_application_id,email_policy_revision,email_security_revision,
              email_assignment_security_revision,state,slot_revision,created_at,updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,
                     $21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,'pending',1,$32,$32)",
            vec![
                slot.id.into(),
                project_id.into(),
                intent_id.into(),
                slot.ordinal.into(),
                slot.role.as_str().into(),
                slot.role.purpose().into(),
                slot.identity_kind.as_str().into(),
                slot.user_id.into(),
                slot.user_revision.into(),
                slot.user_security_revision.into(),
                provider_identity.into(),
                email_identity.into(),
                slot.identity_revision.into(),
                application_id.into(),
                snapshot.application_revision.into(),
                method_str(slot.authority).into(),
                provider.map(|value| value.adapter_key.clone()).into(),
                provider.map(|value| value.adapter_revision).into(),
                provider.map(|value| value.provider_id).into(),
                provider.map(|value| value.revision).into(),
                provider.and_then(|value| value.egress_policy_revision).into(),
                provider.map(|value| value.assignment_revision).into(),
                provider.map(|value| value.scopes.clone()).into(),
                provider.map(|value| value.callback_url.clone()).into(),
                provider.map(|value| value.pkce).into(),
                provider.map(|value| value.nonce).into(),
                provider.and_then(|value| value.secret_material_id).into(),
                snapshot
                    .email_policy_revision
                    .map(|_| application_id)
                    .into(),
                snapshot.email_policy_revision.into(),
                snapshot.email_security_revision.into(),
                snapshot.email_assignment_revision.into(),
                now.into(),
            ],
        ))
        .await
        .map_err(persistence)?;
    Ok(())
}

async fn read_record_for_project(
    transaction: &DatabaseTransaction,
    project_id: Uuid,
    intent_id: Uuid,
) -> Result<IdentityMutationRecord, ApplicationError> {
    let row = transaction
        .query_one_raw(statement(
            "SELECT intent.*,project.public_id AS project_public_id
               FROM identity_mutation_intents intent JOIN projects project ON project.id=intent.project_id
              WHERE intent.project_id=$1 AND intent.id=$2",
            vec![project_id.into(), intent_id.into()],
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
    record_from_row(transaction, &row).await
}

async fn read_record(
    transaction: &DatabaseTransaction,
    intent_id: Uuid,
) -> Result<IdentityMutationRecord, ApplicationError> {
    let row = transaction
        .query_one_raw(statement(
            "SELECT intent.*,project.public_id AS project_public_id
               FROM identity_mutation_intents intent JOIN projects project ON project.id=intent.project_id
              WHERE intent.id=$1",
            vec![intent_id.into()],
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
    record_from_row(transaction, &row).await
}

async fn record_from_row(
    transaction: &DatabaseTransaction,
    row: &QueryResult,
) -> Result<IdentityMutationRecord, ApplicationError> {
    let intent_id: Uuid = get(row, "id")?;
    let intent_expires_at: OffsetDateTime = get(row, "expires_at")?;
    let receipt_deadline = transaction
        .query_one_raw(statement(
            "SELECT MIN(expires_at) AS expires_at FROM identity_proof_receipts
              WHERE project_id=$1 AND intent_id=$2",
            vec![get::<Uuid>(row, "project_id")?.into(), intent_id.into()],
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?;
    let effective_expires_at = intent_expires_at.min(
        get::<Option<OffsetDateTime>>(&receipt_deadline, "expires_at")?
            .unwrap_or(intent_expires_at),
    );
    let slots = transaction
        .query_all_raw(statement(
            "SELECT slot.*,provider.kind AS provider_legacy_kind,provider.adapter_kind AS provider_adapter_kind,provider.provider_key,provider.issuer,provider.client_id,
                    COALESCE(slot.provider_secret_material_id::TEXT, provider.secret_ref) AS secret_ref,
                    egress.mode AS current_egress_mode,
                    egress.exact_origins AS current_egress_exact_origins,
                    egress.revision AS current_egress_policy_revision
               FROM identity_mutation_proof_slots slot
               LEFT JOIN provider_configurations provider
                 ON provider.project_id=slot.project_id AND provider.id=slot.provider_configuration_id
               LEFT JOIN project_provider_egress_policies egress ON egress.project_id=slot.project_id
              WHERE slot.intent_id=$1 ORDER BY slot.slot_ordinal",
            vec![intent_id.into()],
        ))
        .await
        .map_err(persistence)?
        .iter()
        .map(slot_record)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(IdentityMutationRecord {
        id: intent_id,
        project_id: get(row, "project_id")?,
        project_public_id: get(row, "project_public_id")?,
        kind: parse_kind(&get::<String>(row, "operation_kind")?)?,
        status: parse_status(&get::<String>(row, "status")?)?,
        revision: get(row, "intent_revision")?,
        browser_binding_key_version: get(row, "browser_binding_digest_key_version")?,
        csrf_key_version: get(row, "csrf_digest_key_version")?,
        expires_at: effective_expires_at,
        slots,
    })
}

fn slot_record(row: &QueryResult) -> Result<IdentityMutationSlotRecord, ApplicationError> {
    let method_kind = parse_method(&get::<String>(row, "method_kind")?)?;
    let slot_state = parse_slot_state(&get::<String>(row, "state")?)?;
    let provider = if method_kind == IdentityMutationProofMethodKind::Provider {
        let issuer = required::<String>(row, "issuer")?;
        let provider_kind = super::provider_row::effective_provider_kind(
            &required::<String>(row, "provider_legacy_kind")?,
            get::<Option<String>>(row, "provider_adapter_kind")?.as_deref(),
            &issuer,
        )?;
        let capabilities = provider_kind.capabilities();
        let adapter_key = required::<String>(row, "provider_adapter_key")?;
        if !capabilities.identity_proof
            || !provider_kind.issuer_matches(&issuer)
            || adapter_key != capabilities.adapter_key
        {
            return Err(ApplicationError::Integrity);
        }
        let provider_egress_policy_revision =
            get::<Option<i64>>(row, "provider_egress_policy_revision")?;
        let egress_policy = if provider_kind == ProviderKind::Oidc {
            match provider_egress_policy_revision {
                Some(revision)
                    if revision == required::<i64>(row, "current_egress_policy_revision")? =>
                {
                    Some(provider_egress_policy_from_row(row)?)
                }
                None if matches!(
                    slot_state,
                    IdentityMutationSlotState::ProviderExchangeFailed
                        | IdentityMutationSlotState::Proved
                        | IdentityMutationSlotState::Expired
                ) =>
                {
                    None
                }
                _ => return Err(ApplicationError::RevisionConflict),
            }
        } else {
            if provider_egress_policy_revision.is_some() {
                return Err(ApplicationError::Integrity);
            }
            None
        };
        Some(IdentityMutationProviderSlotAuthority {
            provider_configuration_id: required(row, "provider_configuration_id")?,
            provider_kind,
            provider_configuration_revision: required(row, "provider_revision")?,
            provider_egress_policy_revision,
            egress_policy,
            provider_key: required(row, "provider_key")?,
            issuer,
            client_id: required(row, "client_id")?,
            secret_ref: required(row, "secret_ref")?,
            callback_url: required(row, "callback_url")?,
            adapter_key,
            adapter_capability_revision: required(row, "provider_adapter_capability_revision")?,
            exact_scopes: required(row, "provider_scopes")?,
            provider_pkce_required: required(row, "provider_pkce_required")?,
            oidc_nonce_required: required(row, "oidc_nonce_required")?,
            upstream_state_key_version: get(row, "upstream_state_digest_key_version")?,
            oidc_nonce: optional_digest(row, "oidc_nonce_digest", "oidc_nonce_digest_key_version")?,
            provider_pkce: optional_protected(
                row,
                "provider_pkce_ciphertext",
                "provider_pkce_key_version",
            )?,
            callback_continuation: optional_protected(
                row,
                "callback_continuation_ciphertext",
                "callback_continuation_key_version",
            )?,
        })
    } else {
        None
    };
    Ok(IdentityMutationSlotRecord {
        id: get(row, "id")?,
        role: parse_role(&get::<String>(row, "slot_role")?)?,
        identity_kind: parse_identity_kind(&get::<String>(row, "identity_kind")?)?,
        method_kind,
        state: slot_state,
        revision: get(row, "slot_revision")?,
        existing_identity_id: get::<Option<Uuid>>(row, "existing_provider_identity_id")?.or(get::<
            Option<Uuid>,
        >(
            row,
            "existing_email_identity_id",
        )?),
        provider,
    })
}

fn provider_egress_policy_from_row(
    row: &QueryResult,
) -> Result<ProviderEgressPolicy, ApplicationError> {
    super::provider_row::decode_provider_egress_policy(
        &required::<String>(row, "current_egress_mode")?,
        required(row, "current_egress_exact_origins")?,
    )
}

async fn lock_intent(
    transaction: &DatabaseTransaction,
    intent_id: Uuid,
) -> Result<QueryResult, ApplicationError> {
    transaction
        .query_one_raw(statement(
            "SELECT * FROM identity_mutation_intents WHERE id=$1 FOR UPDATE",
            vec![intent_id.into()],
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)
}

async fn lock_slot(
    transaction: &DatabaseTransaction,
    intent_id: Uuid,
    slot_id: Uuid,
) -> Result<QueryResult, ApplicationError> {
    transaction
        .query_one_raw(statement(
            "SELECT * FROM identity_mutation_proof_slots
              WHERE intent_id=$1 AND id=$2 FOR UPDATE",
            vec![intent_id.into(), slot_id.into()],
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)
}

async fn lock_authenticated_intent(
    transaction: &DatabaseTransaction,
    intent_id: Uuid,
    intent: &VersionedDigest,
    browser: &VersionedDigest,
    csrf: &VersionedDigest,
) -> Result<QueryResult, ApplicationError> {
    validate_digest(intent)?;
    validate_digest(browser)?;
    validate_digest(csrf)?;
    transaction
        .query_one_raw(statement(
            "SELECT * FROM identity_mutation_intents WHERE id=$1
                AND hosted_handle_digest=$2 AND hosted_handle_digest_key_version=$3
                AND browser_binding_digest=$4 AND browser_binding_digest_key_version=$5
                AND csrf_digest=$6 AND csrf_digest_key_version=$7 FOR UPDATE",
            vec![
                intent_id.into(),
                intent.value.to_vec().into(),
                intent.key_version.into(),
                browser.value.to_vec().into(),
                browser.key_version.into(),
                csrf.value.to_vec().into(),
                csrf.key_version.into(),
            ],
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)
}

async fn lock_authenticated_slot(
    transaction: &DatabaseTransaction,
    intent_id: Uuid,
    slot_id: Uuid,
    intent: &VersionedDigest,
    browser: &VersionedDigest,
    csrf: &VersionedDigest,
) -> Result<(QueryResult, QueryResult), ApplicationError> {
    let intent_row =
        lock_authenticated_intent(transaction, intent_id, intent, browser, csrf).await?;
    let slot = lock_slot(transaction, intent_id, slot_id).await?;
    Ok((intent_row, slot))
}

async fn lock_callback_slot(
    transaction: &DatabaseTransaction,
    intent_id: Uuid,
    slot_id: Uuid,
    project_public_id: &str,
    provider_key: &str,
    upstream_state: &VersionedDigest,
    browser: &VersionedDigest,
) -> Result<QueryResult, ApplicationError> {
    validate_digest(upstream_state)?;
    validate_digest(browser)?;
    let row = transaction
        .query_one_raw(statement(
            "SELECT slot.*,project.public_id,provider.provider_key,
                    intent.browser_binding_digest,intent.browser_binding_digest_key_version
               FROM identity_mutation_proof_slots slot
               JOIN identity_mutation_intents intent
                 ON intent.project_id=slot.project_id AND intent.id=slot.intent_id
               JOIN projects project ON project.id=slot.project_id
               JOIN provider_configurations provider
                 ON provider.project_id=slot.project_id AND provider.id=slot.provider_configuration_id
               JOIN provider_callback_owners owner ON owner.state_id=slot.id
                AND owner.project_id=slot.project_id AND owner.owner_kind='identity_mutation'
                AND owner.identity_mutation_intent_id=slot.intent_id
                AND owner.identity_mutation_proof_slot_id=slot.id
              WHERE slot.intent_id=$1 AND slot.id=$2 FOR UPDATE OF slot",
            vec![intent_id.into(), slot_id.into()],
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
    if get::<String>(&row, "public_id")? != project_public_id
        || get::<String>(&row, "provider_key")? != provider_key
    {
        return Err(ApplicationError::NotFound);
    }
    require_digest_columns(
        &row,
        "upstream_state_digest",
        "upstream_state_digest_key_version",
        upstream_state,
    )?;
    require_digest_columns(
        &row,
        "browser_binding_digest",
        "browser_binding_digest_key_version",
        browser,
    )?;
    Ok(row)
}

async fn require_pending_revision(
    transaction: &DatabaseTransaction,
    intent: &QueryResult,
    expected_revision: i64,
) -> Result<(), ApplicationError> {
    if get::<i64>(intent, "intent_revision")? != expected_revision {
        return Err(ApplicationError::RevisionConflict);
    }
    if get::<String>(intent, "status")? != "pending_proof"
        || lock_receipts_effective_deadline(transaction, intent).await?
            <= database_clock(transaction).await?
    {
        return Err(ApplicationError::InvalidTransition);
    }
    Ok(())
}

async fn require_live_ready(
    transaction: &DatabaseTransaction,
    intent: &QueryResult,
    expected_revision: i64,
    expected_kind: IdentityMutationKind,
) -> Result<(), ApplicationError> {
    if get::<i64>(intent, "intent_revision")? != expected_revision {
        return Err(ApplicationError::RevisionConflict);
    }
    if get::<String>(intent, "status")? != "ready"
        || get::<String>(intent, "operation_kind")? != expected_kind.as_str()
        || get::<OffsetDateTime>(intent, "expires_at")? <= database_clock(transaction).await?
    {
        return Err(ApplicationError::InvalidTransition);
    }
    let count = slot_count(transaction, get(intent, "id")?).await?;
    if lock_receipts_effective_deadline(transaction, intent).await?
        <= database_clock(transaction).await?
    {
        return Err(ApplicationError::InvalidTransition);
    }
    let row = transaction
        .query_one_raw(statement(
            "SELECT COUNT(*)::BIGINT AS count FROM identity_proof_receipts
              WHERE project_id=$1 AND intent_id=$2 AND status='issued'
                AND expires_at>clock_timestamp()",
            vec![
                get::<Uuid>(intent, "project_id")?.into(),
                get::<Uuid>(intent, "id")?.into(),
            ],
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?;
    if get::<i64>(&row, "count")? != count {
        return Err(ApplicationError::InvalidTransition);
    }
    Ok(())
}

async fn bump_intent(
    transaction: &DatabaseTransaction,
    intent_id: Uuid,
    expected_revision: i64,
    now: OffsetDateTime,
) -> Result<(), ApplicationError> {
    let result = transaction
        .execute_raw(statement(
            "UPDATE identity_mutation_intents SET intent_revision=intent_revision+1,updated_at=$3
              WHERE id=$1 AND intent_revision=$2 AND status='pending_proof'
                AND expires_at>clock_timestamp()",
            vec![intent_id.into(), expected_revision.into(), now.into()],
        ))
        .await
        .map_err(persistence)?;
    if result.rows_affected() != 1 {
        return Err(ApplicationError::RevisionConflict);
    }
    Ok(())
}

async fn slot_count(
    transaction: &DatabaseTransaction,
    intent_id: Uuid,
) -> Result<i64, ApplicationError> {
    transaction
        .query_one_raw(statement(
            "SELECT COUNT(*)::BIGINT AS count FROM identity_mutation_proof_slots WHERE intent_id=$1",
            vec![intent_id.into()],
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?
        .try_get("", "count")
        .map_err(persistence)
}

async fn live_intent_digest_row(
    transaction: &DatabaseTransaction,
    intent_id: Uuid,
) -> Result<QueryResult, ApplicationError> {
    transaction
        .query_one_raw(statement(
            "SELECT hosted_handle_digest_key_version,browser_binding_digest_key_version,
                    csrf_digest_key_version FROM identity_mutation_intents
              WHERE id=$1 AND status IN ('pending_proof','ready')
                AND expires_at>clock_timestamp()",
            vec![intent_id.into()],
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)
}

async fn lock_receipts_effective_deadline(
    transaction: &DatabaseTransaction,
    intent: &QueryResult,
) -> Result<OffsetDateTime, ApplicationError> {
    let mut deadline: OffsetDateTime = get(intent, "expires_at")?;
    let receipts = transaction
        .query_all_raw(statement(
            "SELECT expires_at FROM identity_proof_receipts
              WHERE project_id=$1 AND intent_id=$2 ORDER BY slot_id,id FOR UPDATE",
            vec![
                get::<Uuid>(intent, "project_id")?.into(),
                get::<Uuid>(intent, "id")?.into(),
            ],
        ))
        .await
        .map_err(persistence)?;
    for receipt in receipts {
        deadline = deadline.min(get(&receipt, "expires_at")?);
    }
    Ok(deadline)
}

pub(super) async fn expire_locked_if_needed(
    transaction: &DatabaseTransaction,
    intent: &QueryResult,
) -> Result<bool, ApplicationError> {
    if matches!(
        get::<String>(intent, "status")?.as_str(),
        "pending_proof" | "ready"
    ) && lock_receipts_effective_deadline(transaction, intent).await?
        <= database_clock(transaction).await?
    {
        terminalize(transaction, intent, "expired").await?;
        return Ok(true);
    }
    Ok(false)
}

async fn expire_if_needed(
    transaction: &DatabaseTransaction,
    intent_id: Uuid,
) -> Result<bool, ApplicationError> {
    let Some(intent) = transaction
        .query_one_raw(statement(
            "SELECT * FROM identity_mutation_intents WHERE id=$1 FOR UPDATE",
            vec![intent_id.into()],
        ))
        .await
        .map_err(persistence)?
    else {
        return Ok(false);
    };
    expire_locked_if_needed(transaction, &intent).await
}

async fn terminalize(
    transaction: &DatabaseTransaction,
    intent: &QueryResult,
    status: &str,
) -> Result<(), ApplicationError> {
    if !matches!(status, "expired" | "cancelled") {
        return Err(ApplicationError::Integrity);
    }
    let project_id: Uuid = get(intent, "project_id")?;
    let intent_id: Uuid = get(intent, "id")?;
    let timestamp = database_now(transaction).await?;
    transaction
        .execute_raw(statement(
            "UPDATE mail_outbox outbox SET status='cancelled',safe_outcome='expired',
                    lease_owner=NULL,lease_expires_at=NULL,terminal_at=$3,updated_at=$3
               FROM email_challenges challenge
              WHERE challenge.owner_kind='identity_mutation' AND challenge.project_id=$1
                AND challenge.identity_mutation_intent_id=$2
                AND outbox.project_id=challenge.project_id AND outbox.challenge_id=challenge.id
                AND outbox.challenge_generation=challenge.generation
                AND (outbox.status IN ('pending','retry','ambiguous')
                     OR (outbox.status='leased' AND outbox.lease_expires_at<=clock_timestamp()))",
            vec![project_id.into(), intent_id.into(), timestamp.into()],
        ))
        .await
        .map_err(persistence)?;
    transaction
        .execute_raw(statement(
            "UPDATE email_challenges SET status='expired',consumed_at=NULL,
                    terminal_at=COALESCE(terminal_at,$3),updated_at=$3
              WHERE owner_kind='identity_mutation' AND project_id=$1
                AND identity_mutation_intent_id=$2 AND status IN ('pending','consumed')",
            vec![project_id.into(), intent_id.into(), timestamp.into()],
        ))
        .await
        .map_err(persistence)?;
    transaction
        .execute_raw(statement(
            "UPDATE identity_proof_receipts SET status='expired'
              WHERE project_id=$1 AND intent_id=$2 AND status='issued'",
            vec![project_id.into(), intent_id.into()],
        ))
        .await
        .map_err(persistence)?;
    transaction
        .execute_raw(statement(
            "UPDATE identity_mutation_proof_slots SET state='expired',
                    slot_revision=slot_revision+1,terminal_at=COALESCE(terminal_at,$3),
                    provider_pkce_ciphertext=NULL,provider_pkce_key_version=NULL,
                    callback_continuation_ciphertext=NULL,callback_continuation_key_version=NULL,
                    exchange_claimed_at=NULL,proved_at=NULL,
                    updated_at=$3 WHERE project_id=$1 AND intent_id=$2 AND state<>'expired'",
            vec![project_id.into(), intent_id.into(), timestamp.into()],
        ))
        .await
        .map_err(persistence)?;
    let updated = transaction
        .execute_raw(statement(
            "UPDATE identity_mutation_intents SET status=$3,intent_revision=intent_revision+1,
                    terminal_at=$4,updated_at=$4 WHERE project_id=$1 AND id=$2
                    AND status IN ('pending_proof','ready')",
            vec![
                project_id.into(),
                intent_id.into(),
                status.into(),
                timestamp.into(),
            ],
        ))
        .await
        .map_err(persistence)?;
    if updated.rows_affected() != 1 {
        return Err(ApplicationError::InvalidTransition);
    }
    erase_create_result(transaction, intent_id, timestamp).await?;
    transaction
        .execute_raw(statement(
            "DELETE FROM identity_mutation_candidate_evidence
              WHERE project_id=$1 AND intent_id=$2",
            vec![project_id.into(), intent_id.into()],
        ))
        .await
        .map_err(persistence)?;
    Ok(())
}

pub(super) async fn terminalize_due_identity_mutations(
    transaction: &DatabaseTransaction,
    limit: i64,
) -> Result<u64, ApplicationError> {
    let intents = transaction
        .query_all_raw(statement(
            "SELECT intent.* FROM identity_mutation_intents intent
              WHERE intent.status IN ('pending_proof','ready') AND (
                    intent.expires_at<=clock_timestamp()
                 OR EXISTS (SELECT 1 FROM identity_proof_receipts receipt
                      WHERE receipt.project_id=intent.project_id
                        AND receipt.intent_id=intent.id
                        AND receipt.expires_at<=clock_timestamp())
                 OR EXISTS (SELECT 1 FROM email_challenges challenge
                      WHERE challenge.owner_kind='identity_mutation'
                        AND challenge.project_id=intent.project_id
                        AND challenge.identity_mutation_intent_id=intent.id
                        AND challenge.status='pending'
                        AND challenge.expires_at<=clock_timestamp())
                 OR EXISTS (SELECT 1 FROM email_challenges challenge
                      JOIN mail_outbox outbox
                        ON outbox.project_id=challenge.project_id
                       AND outbox.challenge_id=challenge.id
                       AND outbox.challenge_generation=challenge.generation
                      WHERE challenge.owner_kind='identity_mutation'
                        AND challenge.project_id=intent.project_id
                        AND challenge.identity_mutation_intent_id=intent.id
                        AND (outbox.attempts>=outbox.max_attempts
                             OR outbox.useful_until<=clock_timestamp())
                        AND (outbox.status<>'leased'
                             OR outbox.lease_expires_at<=clock_timestamp())))
              ORDER BY intent.expires_at,intent.id LIMIT $1
              FOR UPDATE OF intent SKIP LOCKED",
            vec![limit.into()],
        ))
        .await
        .map_err(persistence)?;
    let count = u64::try_from(intents.len()).map_err(|_| ApplicationError::Integrity)?;
    for intent in intents {
        terminalize(transaction, &intent, "expired").await?;
    }
    Ok(count)
}

pub(super) async fn terminalize_unreadable_identity_mutations(
    transaction: &DatabaseTransaction,
    readable_versions: serde_json::Value,
) -> Result<u64, ApplicationError> {
    let intents = transaction
        .query_all_raw(statement(
            "SELECT intent.* FROM identity_mutation_intents intent
              WHERE intent.status IN ('pending_proof','ready')
                AND EXISTS (SELECT 1 FROM email_challenges challenge
                  WHERE challenge.owner_kind='identity_mutation'
                    AND challenge.project_id=intent.project_id
                    AND challenge.identity_mutation_intent_id=intent.id
                    AND challenge.status='pending' AND (
                      NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text($1) version
                        WHERE version::INT=challenge.address_key_version)
                      OR (challenge.otp_digest_key_version IS NOT NULL AND NOT EXISTS
                        (SELECT 1 FROM jsonb_array_elements_text($1) version
                          WHERE version::INT=challenge.otp_digest_key_version))
                      OR (challenge.magic_digest_key_version IS NOT NULL AND NOT EXISTS
                        (SELECT 1 FROM jsonb_array_elements_text($1) version
                          WHERE version::INT=challenge.magic_digest_key_version))))
              ORDER BY intent.id LIMIT 100 FOR UPDATE OF intent SKIP LOCKED",
            vec![readable_versions.into()],
        ))
        .await
        .map_err(persistence)?;
    let count = u64::try_from(intents.len()).map_err(|_| ApplicationError::Integrity)?;
    for intent in intents {
        terminalize(transaction, &intent, "cancelled").await?;
    }
    Ok(count)
}

async fn erase_create_result(
    transaction: &DatabaseTransaction,
    intent_id: Uuid,
    timestamp: OffsetDateTime,
) -> Result<(), ApplicationError> {
    let result = transaction
        .execute_raw(statement(
            "UPDATE identity_mutation_create_results SET create_result_ciphertext=NULL,erased_at=$2
              WHERE intent_id=$1 AND create_result_ciphertext IS NOT NULL",
            vec![intent_id.into(), timestamp.into()],
        ))
        .await
        .map_err(persistence)?;
    if result.rows_affected() > 1 {
        return Err(ApplicationError::Integrity);
    }
    Ok(())
}

async fn lock_project_graph(
    transaction: &DatabaseTransaction,
    project_id: Uuid,
) -> Result<(), ApplicationError> {
    transaction
        .execute_raw(statement(
            "SELECT pg_advisory_xact_lock(hashtextextended('owlauth-project-identity-graph:' || $1::TEXT,0))",
            vec![project_id.into()],
        ))
        .await
        .map_err(persistence)?;
    Ok(())
}

async fn database_now<C: ConnectionTrait>(
    connection: &C,
) -> Result<OffsetDateTime, ApplicationError> {
    connection
        .query_one_raw(statement(
            "SELECT clock_timestamp() AS database_now",
            vec![],
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?
        .try_get("", "database_now")
        .map_err(persistence)
}

async fn database_clock<C: ConnectionTrait>(
    connection: &C,
) -> Result<OffsetDateTime, ApplicationError> {
    database_now(connection).await
}

#[allow(
    clippy::too_many_lines,
    reason = "authority revalidation keeps every exact frozen revision check in one fail-closed sequence"
)]
async fn revalidate_slot_authority(
    transaction: &DatabaseTransaction,
    intent: &QueryResult,
    slot: &QueryResult,
    required_runtime_process_ids: &[String],
) -> Result<(), ApplicationError> {
    let project_id: Uuid = get(intent, "project_id")?;
    let owners = transaction
        .query_one_raw(statement(
            "SELECT project.status AS project_status,project.metadata_revision,
                    project.security_revision,application.status AS application_status,
                    application.security_revision AS application_revision,
                    project_user.status AS user_status,project_user.user_revision,
                    project_user.security_revision AS user_security_revision
               FROM projects project
               JOIN applications application ON application.project_id=project.id AND application.id=$2
               JOIN project_users project_user ON project_user.project_id=project.id AND project_user.id=$3
              WHERE project.id=$1 FOR SHARE OF project,application,project_user",
            vec![
                project_id.into(),
                get::<Uuid>(slot, "application_id")?.into(),
                get::<Uuid>(slot, "proof_user_id")?.into(),
            ],
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::RevisionConflict)?;
    if get::<String>(&owners, "project_status")? != "active"
        || get::<i64>(&owners, "metadata_revision")?
            != get::<i64>(intent, "project_metadata_revision")?
        || get::<i64>(&owners, "security_revision")?
            != get::<i64>(intent, "project_security_revision")?
        || get::<String>(&owners, "application_status")? != "active"
        || get::<i64>(&owners, "application_revision")?
            != get::<i64>(slot, "application_security_revision")?
        || get::<String>(&owners, "user_status")? != "active"
        || get::<i64>(&owners, "user_revision")? != get::<i64>(slot, "expected_user_revision")?
        || get::<i64>(&owners, "user_security_revision")?
            != get::<i64>(slot, "expected_user_security_revision")?
    {
        return Err(ApplicationError::RevisionConflict);
    }
    match get::<String>(slot, "method_kind")?.as_str() {
        "provider" => {
            let row = transaction
                .query_one_raw(statement(
                    "SELECT provider.status,provider.revision,provider.secret_ref,
                            provider.secret_material_id,provider.kind AS provider_legacy_kind,
                            provider.adapter_kind AS provider_adapter_kind,provider.issuer,
                            assignment.status AS assignment_status,
                            assignment.security_revision AS assignment_revision
                       FROM provider_configurations provider
                       JOIN application_provider_assignments assignment
                         ON assignment.project_id=provider.project_id
                        AND assignment.provider_id=provider.id AND assignment.application_id=$3
                      WHERE provider.project_id=$1 AND provider.id=$2
                      FOR SHARE OF provider,assignment",
                    vec![
                        project_id.into(),
                        required::<Uuid>(slot, "provider_configuration_id")?.into(),
                        get::<Uuid>(slot, "application_id")?.into(),
                    ],
                ))
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::RevisionConflict)?;
            let provider_kind = super::provider_row::effective_provider_kind(
                &get::<String>(&row, "provider_legacy_kind")?,
                get::<Option<String>>(&row, "provider_adapter_kind")?.as_deref(),
                &get::<String>(&row, "issuer")?,
            )?;
            let policy_revision = get::<Option<i64>>(slot, "provider_egress_policy_revision")?;
            let policy_valid = if provider_kind == ProviderKind::Oidc {
                let current = transaction
                    .query_one_raw(statement(
                        "SELECT revision FROM project_provider_egress_policies
                          WHERE project_id=$1 FOR SHARE",
                        vec![project_id.into()],
                    ))
                    .await
                    .map_err(persistence)?
                    .ok_or(ApplicationError::RevisionConflict)?;
                policy_revision == Some(get(&current, "revision")?)
            } else {
                policy_revision.is_none()
            };
            if !policy_valid
                || get::<String>(&row, "status")? != "active"
                || get::<String>(&row, "assignment_status")? != "active"
                || (get::<Option<String>>(&row, "secret_ref")?.is_none()
                    == get::<Option<Uuid>>(&row, "secret_material_id")?.is_none())
                || get::<Option<Uuid>>(&row, "secret_material_id")?
                    != get::<Option<Uuid>>(slot, "provider_secret_material_id")?
                || get::<i64>(&row, "revision")? != required::<i64>(slot, "provider_revision")?
                || get::<i64>(&row, "assignment_revision")?
                    != required::<i64>(slot, "provider_assignment_security_revision")?
            {
                return Err(ApplicationError::RevisionConflict);
            }
        }
        "email" => {
            let row = transaction
                .query_one_raw(statement(
                    "SELECT policy.status,policy.policy_revision,policy.security_revision,
                            assignment.status AS assignment_status,
                            assignment.security_revision AS assignment_revision
                       FROM project_email_policies policy
                       JOIN application_email_assignments assignment
                         ON assignment.project_id=policy.project_id AND assignment.application_id=$2
                      WHERE policy.project_id=$1 FOR SHARE OF policy,assignment",
                    vec![
                        project_id.into(),
                        get::<Uuid>(slot, "application_id")?.into(),
                    ],
                ))
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::RevisionConflict)?;
            if get::<String>(&row, "status")? != "enabled"
                || get::<String>(&row, "assignment_status")? != "active"
                || get::<i64>(&row, "policy_revision")?
                    != required::<i64>(slot, "email_policy_revision")?
                || get::<i64>(&row, "security_revision")?
                    != required::<i64>(slot, "email_security_revision")?
                || get::<i64>(&row, "assignment_revision")?
                    != required::<i64>(slot, "email_assignment_security_revision")?
            {
                return Err(ApplicationError::RevisionConflict);
            }
            if get::<String>(slot, "state")? == "email_challenge_pending"
                || get::<String>(slot, "state")? == "proved"
            {
                let challenge = transaction
                    .query_one_raw(statement(
                        "SELECT smtp_selection_kind,smtp_configuration_id,smtp_generation,
                                smtp_security_eligibility_revision
                           FROM email_challenges WHERE owner_kind='identity_mutation'
                            AND project_id=$1 AND identity_mutation_intent_id=$2
                            AND identity_mutation_proof_slot_id=$3
                            AND status IN ('pending','consumed') FOR SHARE",
                        vec![
                            project_id.into(),
                            get::<Uuid>(slot, "intent_id")?.into(),
                            get::<Uuid>(slot, "id")?.into(),
                        ],
                    ))
                    .await
                    .map_err(persistence)?
                    .ok_or(ApplicationError::RevisionConflict)?;
                assert_smtp_authority(
                    transaction,
                    project_id,
                    &challenge,
                    required_runtime_process_ids,
                )
                .await?;
            }
        }
        _ => return Err(ApplicationError::Integrity),
    }
    Ok(())
}

async fn admitted_email_method(
    transaction: &DatabaseTransaction,
    slot: &QueryResult,
    required_runtime_process_ids: &[String],
) -> Result<AdmittedEmailMethod, ApplicationError> {
    let project_id: Uuid = get(slot, "project_id")?;
    let application_id: Uuid = get(slot, "application_id")?;
    let row = transaction
        .query_one_raw(statement(
            "SELECT policy.*,assignment.status AS assignment_status,
                    assignment.security_revision AS assignment_revision,
                    smtp.id AS smtp_id,smtp.generation AS smtp_generation,
                    smtp.security_eligibility_revision AS smtp_revision,
                    deployment.generation AS deployment_generation,
                    deployment.security_eligibility_revision AS deployment_revision
               FROM project_email_policies policy
               JOIN application_email_assignments assignment
                 ON assignment.project_id=policy.project_id AND assignment.application_id=$2
               LEFT JOIN LATERAL (
                 SELECT id,generation,security_eligibility_revision
                   FROM project_smtp_configurations WHERE project_id=policy.project_id
                    AND status='active' ORDER BY generation DESC LIMIT 1
               ) smtp ON TRUE
               LEFT JOIN LATERAL (
                 SELECT generation,security_eligibility_revision
                   FROM deployment_smtp_generations WHERE status='active'
                    ORDER BY generation DESC LIMIT 1
               ) deployment ON TRUE
              WHERE policy.project_id=$1 FOR SHARE OF policy,assignment",
            vec![project_id.into(), application_id.into()],
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::RevisionConflict)?;
    if get::<String>(&row, "status")? != "enabled"
        || get::<String>(&row, "assignment_status")? != "active"
        || get::<i64>(&row, "policy_revision")? != required::<i64>(slot, "email_policy_revision")?
        || get::<i64>(&row, "security_revision")?
            != required::<i64>(slot, "email_security_revision")?
        || get::<i64>(&row, "assignment_revision")?
            != required::<i64>(slot, "email_assignment_security_revision")?
    {
        return Err(ApplicationError::RevisionConflict);
    }
    let (selection, configuration, generation, revision) =
        if let Some(id) = get::<Option<Uuid>>(&row, "smtp_id")? {
            (
                "project".to_owned(),
                Some(id),
                required::<i32>(&row, "smtp_generation")?,
                required::<i64>(&row, "smtp_revision")?,
            )
        } else if get::<bool>(&row, "allow_deployment_default")? {
            (
                "deployment_default".to_owned(),
                None,
                required::<i32>(&row, "deployment_generation")?,
                required::<i64>(&row, "deployment_revision")?,
            )
        } else {
            return Err(ApplicationError::Disabled);
        };
    let authority = SyntheticSmtpAuthority {
        selection: selection.clone(),
        configuration,
        generation,
        revision,
    };
    assert_smtp_values(
        transaction,
        project_id,
        &authority,
        required_runtime_process_ids,
    )
    .await?;
    Ok(AdmittedEmailMethod {
        policy_revision: get(&row, "policy_revision")?,
        security_revision: get(&row, "security_revision")?,
        assignment_security_revision: get(&row, "assignment_revision")?,
        otp_enabled: get(&row, "otp_enabled")?,
        magic_link_enabled: get(&row, "magic_link_enabled")?,
        otp_digits: get(&row, "otp_digits")?,
        otp_validity_seconds: get(&row, "otp_validity_seconds")?,
        otp_max_attempts: get(&row, "otp_max_attempts")?,
        resend_after_seconds: get(&row, "resend_after_seconds")?,
        max_generations: get(&row, "max_generations")?,
        magic_validity_seconds: get(&row, "magic_validity_seconds")?,
        signup_enabled: get(&row, "signup_enabled")?,
        transferred_magic_link_enabled: get(&row, "transferred_magic_link_enabled")?,
        smtp_selection_kind: selection,
        smtp_configuration_id: configuration,
        smtp_generation: generation,
        smtp_security_eligibility_revision: revision,
    })
}

struct SyntheticSmtpAuthority {
    selection: String,
    configuration: Option<Uuid>,
    generation: i32,
    revision: i64,
}

async fn assert_smtp_authority(
    transaction: &DatabaseTransaction,
    project_id: Uuid,
    row: &QueryResult,
    required_runtime_process_ids: &[String],
) -> Result<(), ApplicationError> {
    assert_smtp_values(
        transaction,
        project_id,
        &SyntheticSmtpAuthority {
            selection: get(row, "smtp_selection_kind")?,
            configuration: get(row, "smtp_configuration_id")?,
            generation: get(row, "smtp_generation")?,
            revision: get(row, "smtp_security_eligibility_revision")?,
        },
        required_runtime_process_ids,
    )
    .await
}

async fn assert_smtp_values(
    transaction: &DatabaseTransaction,
    project_id: Uuid,
    authority: &SyntheticSmtpAuthority,
    required_runtime_process_ids: &[String],
) -> Result<(), ApplicationError> {
    let present = if authority.selection == "project" {
        transaction
            .query_one_raw(statement(
                "SELECT 1 FROM project_smtp_configurations smtp
                  WHERE smtp.project_id=$1 AND smtp.id=$2 AND smtp.generation=$3
                    AND smtp.security_eligibility_revision=$4
                    AND (smtp.status='active' OR (smtp.status='retained'
                         AND smtp.retained_until>clock_timestamp()))
                    AND NOT EXISTS (
                      SELECT required.process_id FROM jsonb_array_elements_text($5::jsonb) required(process_id)
                       WHERE NOT EXISTS (
                         SELECT 1 FROM project_smtp_runtime_readiness readiness
                          JOIN runtime_process_incarnations incarnation
                            ON incarnation.process_id=readiness.process_id
                           AND incarnation.process_incarnation=readiness.process_incarnation
                         WHERE readiness.project_id=smtp.project_id
                           AND readiness.configuration_id=smtp.id
                           AND readiness.generation=smtp.generation
                           AND readiness.process_id=required.process_id
                           AND readiness.state='ready'
                           AND readiness.lease_expires_at>clock_timestamp()))
                  FOR SHARE OF smtp",
                vec![
                    project_id.into(),
                    authority.configuration.into(),
                    authority.generation.into(),
                    authority.revision.into(),
                    json!(required_runtime_process_ids).into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .is_some()
    } else if authority.selection == "deployment_default" && authority.configuration.is_none() {
        transaction
            .query_one_raw(statement(
                "SELECT 1 FROM deployment_smtp_generations WHERE generation=$1
                    AND security_eligibility_revision=$2 AND (status='active'
                         OR (status='retained' AND retained_until>clock_timestamp())) FOR SHARE",
                vec![authority.generation.into(), authority.revision.into()],
            ))
            .await
            .map_err(persistence)?
            .is_some()
    } else {
        false
    };
    present.then_some(()).ok_or(ApplicationError::Disabled)
}

async fn assert_email_ready(
    transaction: &DatabaseTransaction,
    process_id: &str,
    incarnation: Uuid,
) -> Result<(), ApplicationError> {
    let ready = transaction
        .query_one_raw(statement(
            "SELECT 1 FROM email_protection_runtime_readiness readiness
               JOIN runtime_process_incarnations current
                 ON current.process_id=readiness.process_id
                AND current.process_incarnation=readiness.process_incarnation
              WHERE readiness.process_id=$1 AND readiness.process_incarnation=$2
                AND readiness.state='ready' AND readiness.lease_expires_at>clock_timestamp()
              FOR SHARE OF readiness,current",
            vec![process_id.to_owned().into(), incarnation.into()],
        ))
        .await
        .map_err(persistence)?
        .is_some();
    ready.then_some(()).ok_or(ApplicationError::Disabled)
}

enum ReceiptEvidence {
    Provider(Uuid, i64),
    Email(Uuid, i64),
    Candidate(Uuid, i64),
}

async fn insert_candidate_evidence(
    transaction: &DatabaseTransaction,
    material: &CandidateEvidenceMaterial,
    kind: &str,
    intent_expires_at: OffsetDateTime,
    now: OffsetDateTime,
) -> Result<(), ApplicationError> {
    let retain_until =
        (intent_expires_at + time::Duration::minutes(15)).min(now + time::Duration::minutes(25));
    transaction
        .execute_raw(statement(
            "INSERT INTO identity_mutation_candidate_evidence
             (id,project_id,intent_id,slot_id,identity_kind,candidate_revision,
              protector_key_version,evidence_ciphertext,evidence_digest,created_at,retain_until)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
            vec![
                material.context.evidence_id.into(),
                material.context.project_id.into(),
                material.context.intent_id.into(),
                material.context.proof_slot_id.into(),
                kind.into(),
                material.context.evidence_revision.into(),
                material.ciphertext.key_version.into(),
                material.ciphertext.ciphertext.clone().into(),
                material.digest.value.to_vec().into(),
                now.into(),
                retain_until.into(),
            ],
        ))
        .await
        .map_err(persistence)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn prove_slot(
    transaction: &DatabaseTransaction,
    intent: &QueryResult,
    slot: &QueryResult,
    evidence: ReceiptEvidence,
    receipt_id: Uuid,
    receipt_digest: &VersionedDigest,
    timestamp: OffsetDateTime,
) -> Result<(), ApplicationError> {
    let expected_state = match get::<String>(slot, "method_kind")?.as_str() {
        "provider" => "provider_exchange_in_progress",
        "email" => "email_challenge_pending",
        _ => return Err(ApplicationError::Integrity),
    };
    if get::<String>(slot, "state")? != expected_state {
        return Err(ApplicationError::RevisionConflict);
    }
    let result = transaction
        .execute_raw(statement(
            "UPDATE identity_mutation_proof_slots SET state='proved',
                    slot_revision=slot_revision+1,proved_at=$3,
                    provider_pkce_ciphertext=NULL,provider_pkce_key_version=NULL,
                    callback_continuation_ciphertext=NULL,callback_continuation_key_version=NULL,
                    exchange_claimed_at=NULL,updated_at=$3
              WHERE intent_id=$1 AND id=$2 AND state=$4",
            vec![
                get::<Uuid>(intent, "id")?.into(),
                get::<Uuid>(slot, "id")?.into(),
                timestamp.into(),
                expected_state.into(),
            ],
        ))
        .await
        .map_err(persistence)?;
    if result.rows_affected() != 1 {
        return Err(ApplicationError::RevisionConflict);
    }
    let (kind, provider_id, email_id, candidate_id, evidence_revision) = match evidence {
        ReceiptEvidence::Provider(id, revision) => {
            ("existing_identity", Some(id), None, None, revision)
        }
        ReceiptEvidence::Email(id, revision) => {
            ("existing_identity", None, Some(id), None, revision)
        }
        ReceiptEvidence::Candidate(id, revision) => {
            ("candidate_evidence", None, None, Some(id), revision)
        }
    };
    let expires_at =
        (timestamp + time::Duration::minutes(5)).min(get::<OffsetDateTime>(intent, "expires_at")?);
    transaction
        .execute_raw(statement(
            "INSERT INTO identity_proof_receipts
             (id,project_id,intent_id,slot_id,evidence_kind,identity_kind,provider_identity_id,
              email_identity_id,candidate_evidence_id,evidence_revision,proof_user_id,
              proof_user_revision,proof_user_security_revision,interaction_browser_binding_digest,
              interaction_browser_binding_digest_key_version,interaction_browser_binding_revision,
              captured_intent_revision,purpose,receipt_digest,receipt_digest_key_version,status,
              issued_at,expires_at,created_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,
                     $19,$20,'issued',$21,$22,$21)",
            vec![
                receipt_id.into(),
                get::<Uuid>(intent, "project_id")?.into(),
                get::<Uuid>(intent, "id")?.into(),
                get::<Uuid>(slot, "id")?.into(),
                kind.into(),
                get::<String>(slot, "identity_kind")?.into(),
                provider_id.into(),
                email_id.into(),
                candidate_id.into(),
                evidence_revision.into(),
                get::<Uuid>(slot, "proof_user_id")?.into(),
                get::<i64>(slot, "expected_user_revision")?.into(),
                get::<i64>(slot, "expected_user_security_revision")?.into(),
                required::<Vec<u8>>(intent, "browser_binding_digest")?.into(),
                required::<i32>(intent, "browser_binding_digest_key_version")?.into(),
                get::<i64>(intent, "browser_binding_revision")?.into(),
                get::<i64>(intent, "intent_revision")?.into(),
                get::<String>(slot, "purpose")?.into(),
                receipt_digest.value.to_vec().into(),
                receipt_digest.key_version.into(),
                timestamp.into(),
                expires_at.into(),
            ],
        ))
        .await
        .map_err(persistence)?;
    bump_intent(
        transaction,
        get(intent, "id")?,
        get(intent, "intent_revision")?,
        timestamp,
    )
    .await
}

async fn magic_transfer_owner(
    transaction: &DatabaseTransaction,
    challenge_id: Uuid,
) -> Result<crate::application::IdentityMutationMagicTransferOwner, ApplicationError> {
    let row = transaction
        .query_one_raw(statement(
            "SELECT project_id,identity_mutation_intent_id,identity_mutation_proof_slot_id,
                    generation
               FROM email_challenges
              WHERE id=$1 AND owner_kind='identity_mutation'",
            vec![challenge_id.into()],
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
    Ok(crate::application::IdentityMutationMagicTransferOwner {
        project_id: get(&row, "project_id")?,
        intent_id: required(&row, "identity_mutation_intent_id")?,
        proof_slot_id: required(&row, "identity_mutation_proof_slot_id")?,
        challenge_id,
        generation: get(&row, "generation")?,
    })
}

async fn lock_owned_challenge(
    transaction: &DatabaseTransaction,
    owner: &crate::application::IdentityMutationMagicTransferOwner,
    require_magic: bool,
) -> Result<QueryResult, ApplicationError> {
    let row = transaction
        .query_one_raw(statement(
            "SELECT challenge.expires_at AS challenge_expires_at,
                    intent.expires_at AS intent_expires_at,project.public_id AS project_public_id,
                    challenge.magic_digest,challenge.status,challenge.browser_binding_required,
                    slot.state
               FROM email_challenges challenge
               JOIN identity_mutation_intents intent
                 ON intent.project_id=challenge.project_id
                AND intent.id=challenge.identity_mutation_intent_id
               JOIN identity_mutation_proof_slots slot
                 ON slot.project_id=challenge.project_id
                AND slot.intent_id=challenge.identity_mutation_intent_id
                AND slot.id=challenge.identity_mutation_proof_slot_id
               JOIN projects project ON project.id=challenge.project_id
              WHERE challenge.owner_kind='identity_mutation' AND challenge.project_id=$1
                AND challenge.identity_mutation_intent_id=$2
                AND challenge.identity_mutation_proof_slot_id=$3 AND challenge.id=$4
                AND challenge.generation=$5 AND challenge.status='pending'
                AND slot.state='email_challenge_pending' AND intent.status='pending_proof'
                AND NOT EXISTS (SELECT 1 FROM email_challenges newer
                  WHERE newer.owner_kind='identity_mutation'
                    AND newer.project_id=challenge.project_id
                    AND newer.identity_mutation_intent_id=challenge.identity_mutation_intent_id
                    AND newer.identity_mutation_proof_slot_id=challenge.identity_mutation_proof_slot_id
                    AND newer.generation>challenge.generation)
              FOR UPDATE OF challenge",
            vec![
                owner.project_id.into(),
                owner.intent_id.into(),
                owner.proof_slot_id.into(),
                owner.challenge_id.into(),
                owner.generation.into(),
            ],
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
    if require_magic && get::<Option<Vec<u8>>>(&row, "magic_digest")?.is_none() {
        return Err(ApplicationError::NotFound);
    }
    Ok(row)
}

async fn lock_challenge(
    transaction: &DatabaseTransaction,
    verification: &VerifyIdentityMutationEmailProof,
) -> Result<QueryResult, ApplicationError> {
    transaction
        .query_one_raw(statement(
            "SELECT challenge.*,intent.browser_binding_digest,
                    intent.browser_binding_digest_key_version,intent.csrf_digest,
                    intent.csrf_digest_key_version,intent.expires_at AS intent_expires_at,
                    intent.status AS intent_status
               FROM email_challenges challenge
               JOIN identity_mutation_intents intent
                 ON intent.project_id=challenge.project_id
                AND intent.id=challenge.identity_mutation_intent_id
              WHERE challenge.owner_kind='identity_mutation' AND challenge.project_id=$1
                AND challenge.identity_mutation_intent_id=$2
                AND challenge.identity_mutation_proof_slot_id=$3 AND challenge.id=$4
                AND challenge.generation=$5 FOR UPDATE OF challenge",
            vec![
                verification.project_id.into(),
                verification.intent_id.into(),
                verification.proof_slot_id.into(),
                verification.challenge_id.into(),
                verification.generation.into(),
            ],
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)
}

async fn challenge_is_live(
    transaction: &DatabaseTransaction,
    intent: &QueryResult,
    slot: &QueryResult,
    challenge: &QueryResult,
    verification: &VerifyIdentityMutationEmailProof,
) -> Result<bool, ApplicationError> {
    let wall = database_clock(transaction).await?;
    if get::<String>(intent, "status")? != "pending_proof"
        || get::<String>(slot, "state")? != "email_challenge_pending"
        || get::<String>(challenge, "status")? != "pending"
        || get::<OffsetDateTime>(intent, "expires_at")? <= wall
        || get::<OffsetDateTime>(challenge, "expires_at")? <= wall
    {
        return Ok(false);
    }
    let newest = transaction
        .query_one_raw(statement(
            "SELECT MAX(generation)::SMALLINT AS generation FROM email_challenges
              WHERE owner_kind='identity_mutation' AND project_id=$1
                AND identity_mutation_intent_id=$2 AND identity_mutation_proof_slot_id=$3",
            vec![
                verification.project_id.into(),
                verification.intent_id.into(),
                verification.proof_slot_id.into(),
            ],
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?;
    if get::<i16>(&newest, "generation")? != verification.generation {
        return Ok(false);
    }
    let expiry_column = match verification.proof_kind {
        EmailProofKind::Otp => "otp_expires_at",
        EmailProofKind::MagicLink => "magic_expires_at",
    };
    let issued_at: OffsetDateTime = get(challenge, "issued_at")?;
    if get::<Option<OffsetDateTime>>(challenge, expiry_column)?
        .is_none_or(|expiry| expiry <= issued_at || expiry <= wall)
    {
        return Ok(false);
    }
    validate_email_context(transaction, challenge, verification).await?;
    Ok(true)
}

async fn validate_email_context(
    transaction: &DatabaseTransaction,
    challenge: &QueryResult,
    verification: &VerifyIdentityMutationEmailProof,
) -> Result<(), ApplicationError> {
    if let Some(context) = &verification.transfer_context {
        if verification.proof_kind != EmailProofKind::MagicLink {
            return Err(ApplicationError::NotFound);
        }
        let transfer = transaction
            .query_one_raw(statement(
                "SELECT id,browser_binding_required FROM magic_transfer_contexts
                  WHERE challenge_id=$1
                    AND context_digest=$2 AND context_digest_key_version=$3
                    AND csrf_digest=$4 AND csrf_digest_key_version=$5
                    AND status='pending' AND expires_at>clock_timestamp() FOR UPDATE",
                vec![
                    verification.challenge_id.into(),
                    context.value.to_vec().into(),
                    context.key_version.into(),
                    verification.csrf.value.to_vec().into(),
                    verification.csrf.key_version.into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let binding_required: bool = get(&transfer, "browser_binding_required")?;
        if binding_required && verification.browser_binding.is_none() {
            return Err(ApplicationError::NotFound);
        }
        if let Some(browser) = &verification.browser_binding {
            require_digest_columns(
                challenge,
                "browser_binding_digest",
                "browser_binding_digest_key_version",
                browser,
            )?;
        }
    } else {
        require_digest_columns(
            challenge,
            "csrf_digest",
            "csrf_digest_key_version",
            &verification.csrf,
        )?;
        require_digest_columns(
            challenge,
            "browser_binding_digest",
            "browser_binding_digest_key_version",
            verification
                .browser_binding
                .as_ref()
                .ok_or(ApplicationError::NotFound)?,
        )?;
    }
    Ok(())
}

fn proof_matches(
    challenge: &QueryResult,
    verification: &VerifyIdentityMutationEmailProof,
) -> Result<bool, ApplicationError> {
    let (digest_column, version_column) = match verification.proof_kind {
        EmailProofKind::Otp => ("otp_digest", "otp_digest_key_version"),
        EmailProofKind::MagicLink => ("magic_digest", "magic_digest_key_version"),
    };
    let stored: Option<Vec<u8>> = get(challenge, digest_column)?;
    let version: Option<i32> = get(challenge, version_column)?;
    Ok(version == Some(verification.proof_digest.key_version)
        && stored.as_deref().is_some_and(|value| {
            bool::from(value.ct_eq(verification.proof_digest.value.as_slice()))
        }))
}

fn verified_challenge(
    slot: &QueryResult,
    challenge: &QueryResult,
) -> Result<VerifiedIdentityMutationEmailChallenge, ApplicationError> {
    Ok(VerifiedIdentityMutationEmailChallenge {
        project_id: get(challenge, "project_id")?,
        application_id: get(challenge, "application_id")?,
        intent_id: required(challenge, "identity_mutation_intent_id")?,
        proof_slot_id: required(challenge, "identity_mutation_proof_slot_id")?,
        slot_role: parse_role(&get::<String>(slot, "slot_role")?)?,
        challenge_id: get(challenge, "id")?,
        generation: get(challenge, "generation")?,
        address: ProtectedValue {
            ciphertext: get(challenge, "address_ciphertext")?,
            key_version: get(challenge, "address_key_version")?,
        },
        canonicalization_version: get(challenge, "canonicalization_version")?,
        lookup_digest: VersionedDigest {
            value: bytes32(get(challenge, "lookup_digest")?)?,
            key_version: get(challenge, "lookup_digest_key_version")?,
        },
        existing_identity_id: get::<Option<Uuid>>(slot, "existing_email_identity_id")?,
        existing_identity_revision: get(slot, "expected_identity_revision")?,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "final confirmation revalidates Project, user, primary-source, slot, and receipt authority before mutation"
)]
async fn revalidate_final_authority(
    transaction: &DatabaseTransaction,
    intent: &QueryResult,
    required_runtime_process_ids: &[String],
) -> Result<(), ApplicationError> {
    let project_id: Uuid = get(intent, "project_id")?;
    let project = transaction
        .query_one_raw(statement(
            "SELECT status,metadata_revision,security_revision FROM projects WHERE id=$1 FOR SHARE",
            vec![project_id.into()],
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::RevisionConflict)?;
    if get::<String>(&project, "status")? != "active"
        || get::<i64>(&project, "metadata_revision")?
            != get::<i64>(intent, "project_metadata_revision")?
        || get::<i64>(&project, "security_revision")?
            != get::<i64>(intent, "project_security_revision")?
    {
        return Err(ApplicationError::RevisionConflict);
    }
    let mut users = [
        get::<Option<Uuid>>(intent, "destination_user_id")?,
        get::<Option<Uuid>>(intent, "identity_owner_user_id")?,
        get::<Option<Uuid>>(intent, "winner_user_id")?,
        get::<Option<Uuid>>(intent, "loser_user_id")?,
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    users.sort_unstable();
    users.dedup();
    for user_id in users {
        let row = transaction
            .query_one_raw(statement(
                "SELECT status,user_revision,security_revision FROM project_users
                  WHERE project_id=$1 AND id=$2 FOR UPDATE",
                vec![project_id.into(), user_id.into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::RevisionConflict)?;
        let (revision, security) =
            if Some(user_id) == get::<Option<Uuid>>(intent, "destination_user_id")? {
                (
                    "destination_user_revision",
                    "destination_user_security_revision",
                )
            } else if Some(user_id) == get::<Option<Uuid>>(intent, "identity_owner_user_id")? {
                (
                    "identity_owner_user_revision",
                    "identity_owner_user_security_revision",
                )
            } else if Some(user_id) == get::<Option<Uuid>>(intent, "winner_user_id")? {
                ("winner_user_revision", "winner_user_security_revision")
            } else {
                ("loser_user_revision", "loser_user_security_revision")
            };
        if get::<String>(&row, "status")? != "active"
            || Some(get::<i64>(&row, "user_revision")?) != get(intent, revision)?
            || Some(get::<i64>(&row, "security_revision")?) != get(intent, security)?
        {
            return Err(ApplicationError::RevisionConflict);
        }
    }
    revalidate_primary_source(transaction, intent, project_id).await?;
    let slots = transaction
        .query_all_raw(statement(
            "SELECT * FROM identity_mutation_proof_slots
              WHERE project_id=$1 AND intent_id=$2 ORDER BY slot_ordinal FOR UPDATE",
            vec![project_id.into(), get::<Uuid>(intent, "id")?.into()],
        ))
        .await
        .map_err(persistence)?;
    for slot in &slots {
        if get::<String>(slot, "state")? != "proved" {
            return Err(ApplicationError::InvalidTransition);
        }
        revalidate_slot_authority(transaction, intent, slot, required_runtime_process_ids).await?;
        if let Some(id) = get::<Option<Uuid>>(slot, "existing_provider_identity_id")? {
            require_identity(
                transaction,
                "linked_identities",
                project_id,
                id,
                get(slot, "proof_user_id")?,
                required(slot, "expected_identity_revision")?,
            )
            .await?;
        }
        if let Some(id) = get::<Option<Uuid>>(slot, "existing_email_identity_id")? {
            require_identity(
                transaction,
                "email_identities",
                project_id,
                id,
                get(slot, "proof_user_id")?,
                required(slot, "expected_identity_revision")?,
            )
            .await?;
        }
    }
    Ok(())
}

async fn revalidate_primary_source(
    transaction: &DatabaseTransaction,
    intent: &QueryResult,
    project_id: Uuid,
) -> Result<(), ApplicationError> {
    let disposition: String = get(intent, "primary_source_disposition")?;
    let (table, identity_id) = match disposition.as_str() {
        "provider" => (
            "linked_identities",
            required::<Uuid>(intent, "primary_provider_identity_id")?,
        ),
        "email" => (
            "email_identities",
            required::<Uuid>(intent, "primary_email_identity_id")?,
        ),
        "preserve" | "clear" => return Ok(()),
        _ => return Err(ApplicationError::Integrity),
    };
    let sql = format!(
        "SELECT user_id,identity_revision,status FROM {table}
          WHERE project_id=$1 AND id=$2 FOR UPDATE"
    );
    let row = transaction
        .query_one_raw(statement(&sql, vec![project_id.into(), identity_id.into()]))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::RevisionConflict)?;
    let owner: Uuid = get(&row, "user_id")?;
    let operation: String = get(intent, "operation_kind")?;
    let owner_valid = match operation.as_str() {
        "unlink" => Some(owner) == get(intent, "identity_owner_user_id")?,
        "merge" => {
            Some(owner) == get(intent, "winner_user_id")?
                || Some(owner) == get(intent, "loser_user_id")?
        }
        _ => false,
    };
    if !owner_valid
        || get::<String>(&row, "status")? != "active"
        || Some(get::<i64>(&row, "identity_revision")?)
            != get(intent, "primary_source_identity_revision")?
    {
        return Err(ApplicationError::RevisionConflict);
    }
    Ok(())
}

async fn require_identity(
    transaction: &DatabaseTransaction,
    table: &str,
    project_id: Uuid,
    identity_id: Uuid,
    user_id: Uuid,
    revision: i64,
) -> Result<(), ApplicationError> {
    let sql = format!(
        "SELECT user_id,identity_revision,status FROM {table}
          WHERE project_id=$1 AND id=$2 FOR UPDATE"
    );
    let row = transaction
        .query_one_raw(statement(&sql, vec![project_id.into(), identity_id.into()]))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::RevisionConflict)?;
    if get::<Uuid>(&row, "user_id")? != user_id
        || get::<i64>(&row, "identity_revision")? != revision
        || get::<String>(&row, "status")? != "active"
    {
        return Err(ApplicationError::RevisionConflict);
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "link finalization keeps namespace locking, evidence CAS, and graph mutation atomic"
)]
async fn confirm_link(
    transaction: &DatabaseTransaction,
    intent: &QueryResult,
    confirmation: &PreparedIdentityMutationConfirmation,
    timestamp: OffsetDateTime,
) -> Result<(), ApplicationError> {
    let prepared = confirmation
        .candidate
        .as_ref()
        .ok_or(ApplicationError::Integrity)?;
    let evidence = transaction
        .query_one_raw(statement(
            "SELECT evidence.*,slot.slot_role,slot.identity_kind,slot.proof_user_id,
                    slot.provider_configuration_id,slot.provider_revision,
                    slot.provider_adapter_key,slot.provider_adapter_capability_revision
               FROM identity_mutation_candidate_evidence evidence
               JOIN identity_mutation_proof_slots slot
                 ON slot.project_id=evidence.project_id AND slot.intent_id=evidence.intent_id
                AND slot.id=evidence.slot_id
              WHERE evidence.project_id=$1 AND evidence.intent_id=$2 AND evidence.id=$3
                AND evidence.slot_id=$4 FOR UPDATE OF evidence,slot",
            vec![
                confirmation.project_id.into(),
                confirmation.intent_id.into(),
                prepared.context.evidence_id.into(),
                prepared.context.proof_slot_id.into(),
            ],
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::RevisionConflict)?;
    let expected_kind = match get::<String>(&evidence, "identity_kind")?.as_str() {
        "provider" => IdentityMutationCandidateKind::Provider,
        "email" => IdentityMutationCandidateKind::Email,
        _ => return Err(ApplicationError::Integrity),
    };
    require_candidate_context(
        &prepared.context,
        confirmation.project_id,
        confirmation.intent_id,
        get(&evidence, "slot_id")?,
        expected_kind,
    )?;
    if get::<String>(&evidence, "slot_role")? != "candidate_identity"
        || get::<i64>(&evidence, "candidate_revision")? != prepared.context.evidence_revision
        || get::<i32>(&evidence, "protector_key_version")? != prepared.evidence_digest.key_version
        || !bool::from(
            get::<Vec<u8>>(&evidence, "evidence_digest")?
                .as_slice()
                .ct_eq(prepared.evidence_digest.value.as_slice()),
        )
        || get::<Uuid>(&evidence, "proof_user_id")?
            != required::<Uuid>(intent, "destination_user_id")?
    {
        return Err(ApplicationError::RevisionConflict);
    }
    match &prepared.candidate {
        IdentityMutationCandidate::Provider(candidate) => {
            if expected_kind != IdentityMutationCandidateKind::Provider
                || candidate.registration.provider_configuration_id
                    != required::<Uuid>(&evidence, "provider_configuration_id")?
                || candidate.registration.provider_configuration_revision
                    != required::<i64>(&evidence, "provider_revision")?
                || candidate.registration.adapter_key
                    != required::<String>(&evidence, "provider_adapter_key")?
                || candidate.registration.adapter_capability_revision
                    != required::<i64>(&evidence, "provider_adapter_capability_revision")?
                || candidate.registration.issuer != candidate.issuer
            {
                return Err(ApplicationError::RevisionConflict);
            }
            let provider = transaction
                .query_one_raw(statement(
                    "SELECT status,revision,issuer FROM provider_configurations
                      WHERE project_id=$1 AND id=$2 FOR SHARE",
                    vec![
                        confirmation.project_id.into(),
                        candidate.registration.provider_configuration_id.into(),
                    ],
                ))
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::RevisionConflict)?;
            if get::<String>(&provider, "status")? != "active"
                || get::<i64>(&provider, "revision")?
                    != candidate.registration.provider_configuration_revision
                || get::<String>(&provider, "issuer")? != candidate.issuer
            {
                return Err(ApplicationError::RevisionConflict);
            }
            // `confirm_control` already holds this exact namespace after the Project graph lock.
            if transaction
                .query_one_raw(statement(
                    "SELECT id FROM linked_identities WHERE project_id=$1 AND issuer=$2
                        AND subject=$3 FOR UPDATE",
                    vec![
                        confirmation.project_id.into(),
                        candidate.issuer.clone().into(),
                        candidate.subject.clone().into(),
                    ],
                ))
                .await
                .map_err(persistence)?
                .is_some()
            {
                return Err(ApplicationError::RevisionConflict);
            }
            transaction
                .execute_raw(statement(
                    "INSERT INTO linked_identities
                     (id,project_id,user_id,created_via_provider_configuration_id,issuer,subject,
                      status,identity_revision,display_name,picture_url,locale,observed_at,
                      source_kind,source_schema,created_at,updated_at)
                     VALUES ($1,$2,$3,$4,$5,$6,'active',1,$7,$8,NULL,$9,
                             'provider','owlauth.provider-profile.v1',$9,$9)",
                    vec![
                        Uuid::new_v4().into(),
                        confirmation.project_id.into(),
                        required::<Uuid>(intent, "destination_user_id")?.into(),
                        candidate.registration.provider_configuration_id.into(),
                        candidate.issuer.clone().into(),
                        candidate.subject.clone().into(),
                        candidate.admitted_profile.display_name.clone().into(),
                        candidate.admitted_profile.picture_url.clone().into(),
                        timestamp.into(),
                    ],
                ))
                .await
                .map_err(namespace_error)?;
        }
        IdentityMutationCandidate::Email(candidate) => {
            if expected_kind != IdentityMutationCandidateKind::Email {
                return Err(ApplicationError::Integrity);
            }
            validate_email_candidate(candidate)?;
            // `confirm_control` already holds the Project-wide email namespace after the graph.
            let authority_row = transaction
                .query_one_raw(statement(
                    "SELECT revision,write_version,accepted_versions
                       FROM email_identity_alias_authority WHERE singleton=TRUE FOR SHARE",
                    vec![],
                ))
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::Integrity)?;
            let authority = alias_authority(&authority_row)?;
            require_email_authority(candidate, &authority)?;
            for alias in &candidate.lookup_aliases {
                if transaction
                    .query_one_raw(statement(
                        "SELECT identity_id FROM email_identity_aliases WHERE project_id=$1
                            AND canonicalization_version=$2 AND digest_key_version=$3
                            AND lookup_digest=$4 FOR UPDATE",
                        vec![
                            confirmation.project_id.into(),
                            candidate.canonicalization_version.into(),
                            alias.key_version.into(),
                            alias.value.to_vec().into(),
                        ],
                    ))
                    .await
                    .map_err(persistence)?
                    .is_some()
                {
                    return Err(ApplicationError::RevisionConflict);
                }
            }
            transaction
                .execute_raw(statement(
                    "INSERT INTO email_identities
                     (id,project_id,user_id,status,identity_revision,canonicalization_version,
                      address_ciphertext,address_key_version,verified_at,created_at,updated_at)
                     VALUES ($1,$2,$3,'active',1,$4,$5,$6,$7,$7,$7)",
                    vec![
                        candidate.identity_id.into(),
                        confirmation.project_id.into(),
                        required::<Uuid>(intent, "destination_user_id")?.into(),
                        candidate.canonicalization_version.into(),
                        candidate.durable_address.ciphertext.clone().into(),
                        candidate.durable_address.key_version.into(),
                        timestamp.into(),
                    ],
                ))
                .await
                .map_err(namespace_error)?;
            for alias in &candidate.lookup_aliases {
                transaction
                    .execute_raw(statement(
                        "INSERT INTO email_identity_aliases
                         (project_id,identity_id,canonicalization_version,digest_key_version,
                          lookup_digest,created_at) VALUES ($1,$2,$3,$4,$5,$6)",
                        vec![
                            confirmation.project_id.into(),
                            candidate.identity_id.into(),
                            candidate.canonicalization_version.into(),
                            alias.key_version.into(),
                            alias.value.to_vec().into(),
                            timestamp.into(),
                        ],
                    ))
                    .await
                    .map_err(namespace_error)?;
            }
        }
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "unlink finalization keeps credential destruction and identity graph mutation atomic"
)]
async fn confirm_unlink(
    transaction: &DatabaseTransaction,
    intent: &QueryResult,
    projection_materializer: &dyn IdentityProjectionMaterializer,
    timestamp: OffsetDateTime,
) -> Result<(), ApplicationError> {
    let project_id: Uuid = get(intent, "project_id")?;
    let user_id: Uuid = required(intent, "identity_owner_user_id")?;
    let count = transaction
        .query_one_raw(statement(
            "SELECT ((SELECT COUNT(*) FROM linked_identities
                       WHERE project_id=$1 AND user_id=$2 AND status='active')
                    +(SELECT COUNT(*) FROM email_identities
                       WHERE project_id=$1 AND user_id=$2 AND status='active'))::BIGINT AS count",
            vec![project_id.into(), user_id.into()],
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?;
    if get::<i64>(&count, "count")? <= 1 {
        return Err(ApplicationError::InvalidTransition);
    }
    let slot = transaction
        .query_one_raw(statement(
            "SELECT * FROM identity_mutation_proof_slots WHERE project_id=$1 AND intent_id=$2
                AND slot_role='identity_owner' FOR UPDATE",
            vec![project_id.into(), get::<Uuid>(intent, "id")?.into()],
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?;
    let (kind, table, identity_id) =
        if let Some(id) = get::<Option<Uuid>>(&slot, "existing_provider_identity_id")? {
            ("provider", "linked_identities", id)
        } else {
            (
                "email",
                "email_identities",
                required(&slot, "existing_email_identity_id")?,
            )
        };
    if kind == "provider" {
        disconnect_managed_identity(transaction, project_id, identity_id, timestamp).await?;
    }
    let sql = format!(
        "UPDATE {table} SET status='disabled',identity_revision=identity_revision+1,updated_at=$3
          WHERE project_id=$1 AND id=$2 AND user_id=$4 AND status='active'"
    );
    let result = transaction
        .execute_raw(statement(
            &sql,
            vec![
                project_id.into(),
                identity_id.into(),
                timestamp.into(),
                user_id.into(),
            ],
        ))
        .await
        .map_err(persistence)?;
    if result.rows_affected() != 1 {
        return Err(ApplicationError::RevisionConflict);
    }
    let disposition: String = get(intent, "primary_source_disposition")?;
    let user = project_user::Entity::find_by_id(user_id)
        .one(transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?;
    let is_primary = user.primary_profile_identity_id == Some(identity_id)
        || user.primary_email_identity_id == Some(identity_id);
    match disposition.as_str() {
        "preserve" if is_primary => return Err(ApplicationError::Integrity),
        "preserve" => return Ok(()),
        "clear" if !is_primary => return Err(ApplicationError::Integrity),
        "clear" => {
            let user = update_user_primary(
                transaction,
                user.clone(),
                user.primary_source_kind.as_str(),
                user.primary_profile_identity_id,
                user.primary_email_identity_id,
                true,
                timestamp,
            )
            .await?;
            projection_materializer
                .fan_out_user(transaction, &user, timestamp)
                .await?;
        }
        "provider" => {
            let source: Uuid = required(intent, "primary_provider_identity_id")?;
            if source == identity_id {
                return Err(ApplicationError::Integrity);
            }
            require_identity(
                transaction,
                "linked_identities",
                project_id,
                source,
                user_id,
                required(intent, "primary_source_identity_revision")?,
            )
            .await?;
            let user = update_user_primary(
                transaction,
                user,
                "provider",
                Some(source),
                None,
                false,
                timestamp,
            )
            .await?;
            projection_materializer
                .fan_out_user(transaction, &user, timestamp)
                .await?;
        }
        "email" => {
            let source: Uuid = required(intent, "primary_email_identity_id")?;
            if source == identity_id {
                return Err(ApplicationError::Integrity);
            }
            require_identity(
                transaction,
                "email_identities",
                project_id,
                source,
                user_id,
                required(intent, "primary_source_identity_revision")?,
            )
            .await?;
            let user = update_user_primary(
                transaction,
                user,
                "email",
                None,
                Some(source),
                false,
                timestamp,
            )
            .await?;
            projection_materializer
                .fan_out_user(transaction, &user, timestamp)
                .await?;
        }
        _ => return Err(ApplicationError::Integrity),
    }
    Ok(())
}

async fn update_user_primary(
    transaction: &DatabaseTransaction,
    user: project_user::Model,
    source_kind: &str,
    provider_id: Option<Uuid>,
    email_id: Option<Uuid>,
    clear_source: bool,
    timestamp: OffsetDateTime,
) -> Result<project_user::Model, ApplicationError> {
    let provider_profile = if source_kind == "provider" && !clear_source {
        let id = provider_id.ok_or(ApplicationError::Integrity)?;
        let row = transaction
            .query_one_raw(statement(
                "SELECT display_name,picture_url,locale,status,user_id FROM linked_identities
                  WHERE project_id=$1 AND id=$2 FOR SHARE",
                vec![user.project_id.into(), id.into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        if get::<String>(&row, "status")? != "active" || get::<Uuid>(&row, "user_id")? != user.id {
            return Err(ApplicationError::RevisionConflict);
        }
        Some((
            get::<Option<String>>(&row, "display_name")?,
            get::<Option<String>>(&row, "picture_url")?,
            get::<Option<String>>(&row, "locale")?,
        ))
    } else {
        None
    };
    let display_name = if user.local_display_name_set {
        user.local_display_name.clone()
    } else {
        provider_profile.as_ref().and_then(|value| value.0.clone())
    };
    let picture_url = if user.local_picture_url_set {
        user.local_picture_url.clone()
    } else {
        provider_profile.as_ref().and_then(|value| value.1.clone())
    };
    let locale = if user.local_locale_set {
        user.local_locale.clone()
    } else {
        provider_profile.as_ref().and_then(|value| value.2.clone())
    };
    let digest = base_profile_digest(
        display_name.as_deref(),
        picture_url.as_deref(),
        locale.as_deref(),
        None,
    )?;
    let result = transaction
        .execute_raw(statement(
            "UPDATE project_users SET primary_source_kind=$2,primary_profile_identity_id=$3,
                    primary_email_identity_id=$4,display_name=$5,picture_url=$6,locale=$7,
                    base_profile_digest=$8,user_revision=user_revision+1,updated_at=$9
              WHERE id=$1 AND status='active'",
            vec![
                user.id.into(),
                source_kind.into(),
                provider_id.into(),
                email_id.into(),
                display_name.into(),
                picture_url.into(),
                locale.into(),
                digest.into(),
                timestamp.into(),
            ],
        ))
        .await
        .map_err(persistence)?;
    if result.rows_affected() != 1 {
        return Err(ApplicationError::RevisionConflict);
    }
    project_user::Entity::find_by_id(user.id)
        .one(transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)
}

async fn identity_revision(
    transaction: &DatabaseTransaction,
    table: &str,
    project_id: Uuid,
    identity_id: Uuid,
) -> Result<i64, ApplicationError> {
    let sql = format!("SELECT identity_revision FROM {table} WHERE project_id=$1 AND id=$2");
    transaction
        .query_one_raw(statement(&sql, vec![project_id.into(), identity_id.into()]))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::RevisionConflict)?
        .try_get("", "identity_revision")
        .map_err(persistence)
}

async fn merge_binding_union_count(
    transaction: &DatabaseTransaction,
    intent: &QueryResult,
) -> Result<usize, ApplicationError> {
    let row = transaction
        .query_one_raw(statement(
            "SELECT COUNT(DISTINCT application_id)::BIGINT AS count
               FROM application_user_bindings WHERE project_id=$1
                AND user_id IN ($2,$3) AND status IN ('active','disabled')",
            vec![
                get::<Uuid>(intent, "project_id")?.into(),
                required::<Uuid>(intent, "winner_user_id")?.into(),
                required::<Uuid>(intent, "loser_user_id")?.into(),
            ],
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?;
    usize::try_from(get::<i64>(&row, "count")?).map_err(|_| ApplicationError::Integrity)
}

#[allow(
    clippy::too_many_lines,
    reason = "merge finalization keeps deterministic locks and all graph consequences atomic"
)]
async fn confirm_merge(
    transaction: &DatabaseTransaction,
    intent: &QueryResult,
    projection_materializer: &dyn IdentityProjectionMaterializer,
    timestamp: OffsetDateTime,
) -> Result<(), ApplicationError> {
    let project_id: Uuid = get(intent, "project_id")?;
    let winner_id: Uuid = required(intent, "winner_user_id")?;
    let loser_id: Uuid = required(intent, "loser_user_id")?;
    // Lock managed children and binding graph before movement, each in a stable order.
    transaction
        .query_all_raw(statement(
            "SELECT connection.id FROM managed_provider_connections connection
               JOIN linked_identities identity ON identity.project_id=connection.project_id
                AND identity.id=connection.linked_identity_id
              WHERE connection.project_id=$1 AND identity.user_id IN ($2,$3)
              ORDER BY connection.id FOR UPDATE OF connection",
            vec![project_id.into(), winner_id.into(), loser_id.into()],
        ))
        .await
        .map_err(persistence)?;
    transaction
        .query_all_raw(statement(
            "SELECT id FROM application_user_bindings WHERE project_id=$1
                AND user_id IN ($2,$3) ORDER BY application_id,id FOR UPDATE",
            vec![project_id.into(), winner_id.into(), loser_id.into()],
        ))
        .await
        .map_err(persistence)?;
    revoke_loser_sessions(transaction, project_id, loser_id, timestamp).await?;

    // Clear the loser's immediate primary-identity foreign keys before moving those identities.
    // The merged-user attribution and tombstone constraints are deferred and validate the exact
    // final graph at commit; the identity ownership foreign key itself is immediate.
    let loser_result = transaction
        .execute_raw(statement(
            "UPDATE project_users SET status='merged',merged_into_user_id=$3,
                    primary_profile_identity_id=NULL,primary_email_identity_id=NULL,
                    display_name=NULL,picture_url=NULL,locale=NULL,
                    base_profile_digest=$4,user_revision=user_revision+1,
                    security_revision=security_revision+1,updated_at=$5
              WHERE project_id=$1 AND id=$2 AND status='active'",
            vec![
                project_id.into(),
                loser_id.into(),
                winner_id.into(),
                base_profile_digest(None, None, None, None)?.into(),
                timestamp.into(),
            ],
        ))
        .await
        .map_err(persistence)?;
    if loser_result.rows_affected() != 1 {
        return Err(ApplicationError::RevisionConflict);
    }
    let mut disabled_loser = project_user::Entity::find_by_id(loser_id)
        .one(transaction)
        .await
        .map_err(persistence)?
        .filter(|user| user.project_id == project_id)
        .ok_or(ApplicationError::Integrity)?;
    // A merged Project user is externally unusable, but the public projection vocabulary is
    // deliberately active/disabled. Publish that terminal loser view before bindings move or a
    // duplicate projection is erased, so every previously bound Application can retire its old
    // local user while immutable history remains attributed to the retained binding.
    "disabled".clone_into(&mut disabled_loser.status);
    projection_materializer
        .fan_out_user(transaction, &disabled_loser, timestamp)
        .await?;

    // Identity revision advances because durable ownership changed. Managed connections follow
    // the same new owner/revision under the deferrable exact-owner FK.
    transaction
        .execute_raw(statement(
            "UPDATE linked_identities SET user_id=$3,identity_revision=identity_revision+1,
                    updated_at=$4 WHERE project_id=$1 AND user_id=$2",
            vec![
                project_id.into(),
                loser_id.into(),
                winner_id.into(),
                timestamp.into(),
            ],
        ))
        .await
        .map_err(persistence)?;
    transaction
        .execute_raw(statement(
            "UPDATE email_identities SET user_id=$3,identity_revision=identity_revision+1,
                    updated_at=$4 WHERE project_id=$1 AND user_id=$2",
            vec![
                project_id.into(),
                loser_id.into(),
                winner_id.into(),
                timestamp.into(),
            ],
        ))
        .await
        .map_err(persistence)?;
    let winner_security: i64 = required(intent, "winner_user_security_revision")?;
    transaction
        .execute_raw(statement(
            "UPDATE managed_provider_connections connection SET user_id=$3,
                    identity_revision=identity.identity_revision,user_security_revision=$4,
                    revision=connection.revision+1,last_safe_outcome='owner_merged',updated_at=$5
               FROM linked_identities identity
              WHERE connection.project_id=$1 AND connection.user_id=$2
                AND identity.project_id=connection.project_id
                AND identity.id=connection.linked_identity_id AND identity.user_id=$3",
            vec![
                project_id.into(),
                loser_id.into(),
                winner_id.into(),
                winner_security.into(),
                timestamp.into(),
            ],
        ))
        .await
        .map_err(persistence)?;

    merge_bindings(transaction, project_id, winner_id, loser_id, timestamp).await?;
    let winner = project_user::Entity::find_by_id(winner_id)
        .one(transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?;
    let primary_kind: String = get(intent, "primary_source_disposition")?;
    let winner = match primary_kind.as_str() {
        "provider" => {
            let source: Uuid = required(intent, "primary_provider_identity_id")?;
            require_identity(
                transaction,
                "linked_identities",
                project_id,
                source,
                winner_id,
                identity_revision(transaction, "linked_identities", project_id, source).await?,
            )
            .await?;
            update_user_primary(
                transaction,
                winner,
                "provider",
                Some(source),
                None,
                false,
                timestamp,
            )
            .await?
        }
        "email" => {
            let source: Uuid = required(intent, "primary_email_identity_id")?;
            require_identity(
                transaction,
                "email_identities",
                project_id,
                source,
                winner_id,
                identity_revision(transaction, "email_identities", project_id, source).await?,
            )
            .await?;
            update_user_primary(
                transaction,
                winner,
                "email",
                None,
                Some(source),
                false,
                timestamp,
            )
            .await?
        }
        _ => return Err(ApplicationError::Integrity),
    };
    projection_materializer
        .fan_out_user(transaction, &winner, timestamp)
        .await?;
    Ok(())
}

async fn revoke_loser_sessions(
    transaction: &DatabaseTransaction,
    project_id: Uuid,
    loser_id: Uuid,
    timestamp: OffsetDateTime,
) -> Result<(), ApplicationError> {
    transaction
        .execute_raw(statement(
            "UPDATE refresh_families SET status='revoked',family_revision=family_revision+1,
                    revoked_at=$3,revocation_reason='owner_invalidated',updated_at=$3
              WHERE project_id=$1 AND user_id=$2 AND status='active'",
            vec![project_id.into(), loser_id.into(), timestamp.into()],
        ))
        .await
        .map_err(persistence)?;
    transaction
        .execute_raw(statement(
            "UPDATE application_sessions SET status='revoked',session_revision=session_revision+1,
                    revoked_at=$3,updated_at=$3
              WHERE project_id=$1 AND user_id=$2 AND status='active'",
            vec![project_id.into(), loser_id.into(), timestamp.into()],
        ))
        .await
        .map_err(persistence)?;
    transaction
        .execute_raw(statement(
            "UPDATE project_browser_sessions SET status='terminated',
                    session_revision=session_revision+1,terminated_at=$3,updated_at=$3
              WHERE project_id=$1 AND user_id=$2 AND status='active'",
            vec![project_id.into(), loser_id.into(), timestamp.into()],
        ))
        .await
        .map_err(persistence)?;
    transaction
        .execute_raw(statement(
            "UPDATE handoff_tickets SET status='expired'
              WHERE project_id=$1 AND user_id=$2 AND status='issued'",
            vec![project_id.into(), loser_id.into()],
        ))
        .await
        .map_err(persistence)?;
    Ok(())
}

async fn merge_bindings(
    transaction: &DatabaseTransaction,
    project_id: Uuid,
    winner_id: Uuid,
    loser_id: Uuid,
    timestamp: OffsetDateTime,
) -> Result<(), ApplicationError> {
    let loser_bindings = transaction
        .query_all_raw(statement(
            "SELECT id,application_id,status FROM application_user_bindings
              WHERE project_id=$1 AND user_id=$2 AND status IN ('active','disabled')
              ORDER BY application_id,id FOR UPDATE",
            vec![project_id.into(), loser_id.into()],
        ))
        .await
        .map_err(persistence)?;
    for binding in loser_bindings {
        let binding_id: Uuid = get(&binding, "id")?;
        let application_id: Uuid = get(&binding, "application_id")?;
        let binding_status: String = get(&binding, "status")?;
        let winner = transaction
            .query_one_raw(statement(
                "SELECT id FROM application_user_bindings WHERE project_id=$1
                    AND application_id=$2 AND user_id=$3 AND status IN ('active','disabled')
                    FOR UPDATE",
                vec![project_id.into(), application_id.into(), winner_id.into()],
            ))
            .await
            .map_err(persistence)?;
        if let Some(winner) = winner {
            // The retained winner projection is authoritative after final fan-out. The duplicate
            // loser projection has no terminal status and must not retain stale encrypted PII.
            transaction
                .execute_raw(statement(
                    "DELETE FROM application_user_projections
                      WHERE project_id=$1 AND binding_id=$2",
                    vec![project_id.into(), binding_id.into()],
                ))
                .await
                .map_err(persistence)?;
            transaction
                .execute_raw(statement(
                    "UPDATE application_user_bindings SET status='merged',merged_into_binding_id=$3,
                            merged_at=$4,binding_revision=binding_revision+1,updated_at=$4
                      WHERE project_id=$1 AND id=$2",
                    vec![
                        project_id.into(),
                        binding_id.into(),
                        get::<Uuid>(&winner, "id")?.into(),
                        timestamp.into(),
                    ],
                ))
                .await
                .map_err(persistence)?;
        } else {
            if binding_status == "disabled" {
                // A disabled binding is not part of projection fan-out and cannot become visible
                // again. Erase its obsolete current projection (including protected PII) before
                // moving durable binding/history attribution to the winner.
                transaction
                    .execute_raw(statement(
                        "DELETE FROM application_user_projections
                          WHERE project_id=$1 AND binding_id=$2",
                        vec![project_id.into(), binding_id.into()],
                    ))
                    .await
                    .map_err(persistence)?;
            } else if binding_status != "active" {
                return Err(ApplicationError::Integrity);
            }
            transaction
                .execute_raw(statement(
                    "UPDATE application_user_bindings SET user_id=$3,
                            binding_revision=binding_revision+1,updated_at=$4
                      WHERE project_id=$1 AND id=$2",
                    vec![
                        project_id.into(),
                        binding_id.into(),
                        winner_id.into(),
                        timestamp.into(),
                    ],
                ))
                .await
                .map_err(persistence)?;
            // For an active binding, keep the projection's prior owner visible until winner
            // fan-out. Its deferred owner foreign key permits this transaction-local state; the
            // materializer treats the owner change as a public semantic revision and updates it.
        }
    }
    Ok(())
}

async fn insert_merge_tombstone(
    transaction: &DatabaseTransaction,
    intent: &QueryResult,
    timestamp: OffsetDateTime,
) -> Result<(), ApplicationError> {
    transaction
        .execute_raw(statement(
            "INSERT INTO project_user_merge_tombstones
             (project_id,loser_user_id,winner_user_id,loser_user_revision,winner_user_revision,
              primary_source_kind,primary_provider_identity_id,primary_email_identity_id,
              sessions_disposition,bindings_disposition,merged_at,correlation_id,
              identity_mutation_intent_id)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
            vec![
                get::<Uuid>(intent, "project_id")?.into(),
                required::<Uuid>(intent, "loser_user_id")?.into(),
                required::<Uuid>(intent, "winner_user_id")?.into(),
                required::<i64>(intent, "loser_user_revision")?.into(),
                required::<i64>(intent, "winner_user_revision")?.into(),
                get::<String>(intent, "primary_source_disposition")?.into(),
                get::<Option<Uuid>>(intent, "primary_provider_identity_id")?.into(),
                get::<Option<Uuid>>(intent, "primary_email_identity_id")?.into(),
                required::<String>(intent, "sessions_disposition")?.into(),
                required::<String>(intent, "bindings_disposition")?.into(),
                timestamp.into(),
                get::<Uuid>(intent, "correlation_id")?.into(),
                get::<Uuid>(intent, "id")?.into(),
            ],
        ))
        .await
        .map_err(persistence)?;
    Ok(())
}

async fn revalidate_existing_email(
    transaction: &DatabaseTransaction,
    project_id: Uuid,
    slot: &QueryResult,
    material: &IdentityMutationExistingEmailEvidence,
    challenge_lookup: &VersionedDigest,
) -> Result<(), ApplicationError> {
    if material.verified_challenge_lookup != *challenge_lookup
        || get::<Option<Uuid>>(slot, "existing_email_identity_id")? != Some(material.identity_id)
        || get::<Option<i64>>(slot, "expected_identity_revision")?
            != Some(material.identity_revision)
    {
        return Err(ApplicationError::RevisionConflict);
    }
    let authority_row = transaction
        .query_one_raw(statement(
            "SELECT revision,write_version,accepted_versions
               FROM email_identity_alias_authority WHERE singleton=TRUE FOR SHARE",
            vec![],
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?;
    let authority = alias_authority(&authority_row)?;
    if authority.revision != material.alias_authority_revision
        || material.active_alias.key_version != authority.write_version
        || material
            .lookup_aliases
            .iter()
            .map(|v| v.key_version)
            .collect::<BTreeSet<_>>()
            != authority
                .accepted_versions
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
        || !material.lookup_aliases.contains(&material.active_alias)
        || !material.lookup_aliases.contains(challenge_lookup)
    {
        return Err(ApplicationError::RevisionConflict);
    }
    let identity = transaction
        .query_one_raw(statement(
            "SELECT user_id,status,identity_revision,canonicalization_version
               FROM email_identities WHERE project_id=$1 AND id=$2 FOR UPDATE",
            vec![project_id.into(), material.identity_id.into()],
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::RevisionConflict)?;
    if get::<String>(&identity, "status")? != "active"
        || get::<Uuid>(&identity, "user_id")? != get::<Uuid>(slot, "proof_user_id")?
        || get::<i64>(&identity, "identity_revision")? != material.identity_revision
    {
        return Err(ApplicationError::RevisionConflict);
    }
    let canonicalization: i32 = get(&identity, "canonicalization_version")?;
    let rows = transaction
        .query_all_raw(statement(
            "SELECT digest_key_version,lookup_digest FROM email_identity_aliases
              WHERE project_id=$1 AND identity_id=$2 ORDER BY digest_key_version FOR UPDATE",
            vec![project_id.into(), material.identity_id.into()],
        ))
        .await
        .map_err(persistence)?;
    let stored = rows
        .iter()
        .map(|row| {
            Ok((
                get::<i32>(row, "digest_key_version")?,
                bytes32(get(row, "lookup_digest")?)?,
            ))
        })
        .collect::<Result<BTreeSet<_>, ApplicationError>>()?;
    let supplied = material
        .lookup_aliases
        .iter()
        .map(|alias| (alias.key_version, alias.value))
        .collect::<BTreeSet<_>>();
    if canonicalization <= 0 || stored != supplied {
        return Err(ApplicationError::RevisionConflict);
    }
    Ok(())
}

fn candidate_envelope(
    row: &QueryResult,
) -> Result<IdentityMutationCandidateEvidenceEnvelope, ApplicationError> {
    let kind = match get::<String>(row, "identity_kind")?.as_str() {
        "provider" => IdentityMutationCandidateKind::Provider,
        "email" => IdentityMutationCandidateKind::Email,
        _ => return Err(ApplicationError::Integrity),
    };
    let key_version: i32 = get(row, "protector_key_version")?;
    Ok(IdentityMutationCandidateEvidenceEnvelope {
        context: IdentityMutationCandidateEvidenceContext {
            project_id: get(row, "project_id")?,
            intent_id: get(row, "intent_id")?,
            proof_slot_id: get(row, "slot_id")?,
            evidence_id: get(row, "id")?,
            evidence_revision: get(row, "candidate_revision")?,
            candidate_kind: kind,
        },
        ciphertext: ProtectedValue {
            ciphertext: get(row, "evidence_ciphertext")?,
            key_version,
        },
        digest: VersionedDigest {
            value: bytes32(get(row, "evidence_digest")?)?,
            key_version,
        },
    })
}

fn validate_candidate_material(
    material: &CandidateEvidenceMaterial,
    project_id: Uuid,
    intent_id: Uuid,
    slot_id: Uuid,
    kind: IdentityMutationCandidateKind,
) -> Result<(), ApplicationError> {
    require_candidate_context(&material.context, project_id, intent_id, slot_id, kind)?;
    validate_digest(&material.digest)?;
    validate_protected_range(&material.ciphertext, 41, 16_384)?;
    if material.digest.key_version != material.ciphertext.key_version {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(())
}

fn require_candidate_context(
    context: &IdentityMutationCandidateEvidenceContext,
    project_id: Uuid,
    intent_id: Uuid,
    slot_id: Uuid,
    kind: IdentityMutationCandidateKind,
) -> Result<(), ApplicationError> {
    if context.project_id != project_id
        || context.intent_id != intent_id
        || context.proof_slot_id != slot_id
        || context.evidence_id.is_nil()
        || context.evidence_revision <= 0
        || context.candidate_kind != kind
    {
        return Err(ApplicationError::Integrity);
    }
    Ok(())
}

fn alias_authority(row: &QueryResult) -> Result<EmailIdentityAliasAuthority, ApplicationError> {
    let accepted: serde_json::Value = get(row, "accepted_versions")?;
    let accepted_versions: Vec<i32> =
        serde_json::from_value(accepted).map_err(|_| ApplicationError::Integrity)?;
    let authority = EmailIdentityAliasAuthority {
        revision: get(row, "revision")?,
        write_version: get(row, "write_version")?,
        accepted_versions,
    };
    let versions = authority
        .accepted_versions
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if authority.revision <= 0
        || authority.write_version <= 0
        || versions.is_empty()
        || versions.len() != authority.accepted_versions.len()
        || !versions.contains(&authority.write_version)
    {
        return Err(ApplicationError::Integrity);
    }
    Ok(authority)
}

fn validate_email_candidate(
    candidate: &crate::application::IdentityMutationEmailCandidate,
) -> Result<(), ApplicationError> {
    if candidate.identity_id.is_nil()
        || candidate.canonicalization_version <= 0
        || candidate.alias_authority_revision <= 0
        || candidate.lookup_aliases.is_empty()
        || candidate.lookup_aliases.len() > 16
    {
        return Err(ApplicationError::InvalidInput);
    }
    crate::domain::CanonicalEmail::parse_v1(&candidate.normalized_address)
        .map_err(|_| ApplicationError::InvalidInput)?;
    validate_protected_range(&candidate.durable_address, 41, 2_048)?;
    for alias in &candidate.lookup_aliases {
        validate_digest(alias)?;
    }
    validate_digest(&candidate.active_alias)?;
    Ok(())
}

fn require_email_authority(
    candidate: &crate::application::IdentityMutationEmailCandidate,
    authority: &EmailIdentityAliasAuthority,
) -> Result<(), ApplicationError> {
    let supplied = candidate
        .lookup_aliases
        .iter()
        .map(|alias| alias.key_version)
        .collect::<BTreeSet<_>>();
    let accepted = authority
        .accepted_versions
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if candidate.alias_authority_revision != authority.revision
        || supplied != accepted
        || candidate.lookup_aliases.len() != supplied.len()
        || candidate.active_alias.key_version != authority.write_version
        || !candidate.lookup_aliases.contains(&candidate.active_alias)
    {
        return Err(ApplicationError::RevisionConflict);
    }
    Ok(())
}

async fn lock_provider_namespace(
    transaction: &DatabaseTransaction,
    project_id: Uuid,
    issuer: &str,
    subject: &str,
) -> Result<(), ApplicationError> {
    transaction
        .execute_raw(statement(
            "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
            vec![format!("{project_id}\u{1f}{issuer}\u{1f}{subject}").into()],
        ))
        .await
        .map_err(persistence)?;
    Ok(())
}

fn validate_generation(
    value: &CommitIdentityMutationEmailGeneration,
) -> Result<(), ApplicationError> {
    validate_digest(&value.lookup_digest)?;
    validate_protected_range(&value.address, 41, 2_048)?;
    validate_protected_range(&value.envelope, 41, 8_192)?;
    validate_protected_range(&value.body, 41, 65_536)?;
    if let Some(digest) = &value.otp_digest {
        validate_digest(digest)?;
    }
    if let Some(digest) = &value.magic_digest {
        validate_digest(digest)?;
    }
    if value.challenge_id.is_nil()
        || value.outbox_id.is_nil()
        || value.expected_generation <= 0
        || value.canonicalization_version <= 0
        || value.message_id.is_empty()
        || value.otp_digest.is_none() && value.magic_digest.is_none()
        || value.otp_digest.is_some() != value.admitted_method.otp_enabled
            && value.magic_digest.is_none()
    {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(())
}

fn validate_verification(value: &VerifyIdentityMutationEmailProof) -> Result<(), ApplicationError> {
    validate_digest(&value.proof_digest)?;
    validate_digest(&value.csrf)?;
    if let Some(binding) = &value.browser_binding {
        validate_digest(binding)?;
    }
    if let Some(context) = &value.transfer_context {
        validate_digest(context)?;
    }
    if value.generation <= 0 {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(())
}

fn validate_digest(value: &VersionedDigest) -> Result<(), ApplicationError> {
    if value.key_version <= 0 {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(())
}

fn validate_protected_range(
    value: &ProtectedValue,
    minimum: usize,
    maximum: usize,
) -> Result<(), ApplicationError> {
    if value.key_version <= 0
        || value.ciphertext.len() < minimum
        || value.ciphertext.len() > maximum
    {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(())
}

fn require_digest_columns(
    row: &QueryResult,
    digest_column: &str,
    version_column: &str,
    supplied: &VersionedDigest,
) -> Result<(), ApplicationError> {
    let stored: Option<Vec<u8>> = get(row, digest_column)?;
    let version: Option<i32> = get(row, version_column)?;
    if version != Some(supplied.key_version)
        || !stored
            .as_deref()
            .is_some_and(|digest| bool::from(digest.ct_eq(supplied.value.as_slice())))
    {
        return Err(ApplicationError::NotFound);
    }
    Ok(())
}

fn optional_digest(
    row: &QueryResult,
    digest_column: &str,
    version_column: &str,
) -> Result<Option<VersionedDigest>, ApplicationError> {
    match (
        get::<Option<Vec<u8>>>(row, digest_column)?,
        get::<Option<i32>>(row, version_column)?,
    ) {
        (None, None) => Ok(None),
        (Some(value), Some(key_version)) => Ok(Some(VersionedDigest {
            value: bytes32(value)?,
            key_version,
        })),
        _ => Err(ApplicationError::Integrity),
    }
}

fn optional_protected(
    row: &QueryResult,
    ciphertext_column: &str,
    version_column: &str,
) -> Result<Option<ProtectedValue>, ApplicationError> {
    match (
        get::<Option<Vec<u8>>>(row, ciphertext_column)?,
        get::<Option<i32>>(row, version_column)?,
    ) {
        (None, None) => Ok(None),
        (Some(ciphertext), Some(key_version)) => Ok(Some(ProtectedValue {
            ciphertext,
            key_version,
        })),
        _ => Err(ApplicationError::Integrity),
    }
}

fn bytes32(value: Vec<u8>) -> Result<[u8; 32], ApplicationError> {
    value.try_into().map_err(|_| ApplicationError::Integrity)
}

fn get<T>(row: &QueryResult, column: &str) -> Result<T, ApplicationError>
where
    T: sea_orm::TryGetable,
{
    row.try_get("", column).map_err(persistence)
}

fn required<T>(row: &QueryResult, column: &str) -> Result<T, ApplicationError>
where
    T: sea_orm::TryGetable,
{
    get::<Option<T>>(row, column)?.ok_or(ApplicationError::Integrity)
}

fn statement(sql: &str, values: Vec<sea_orm::Value>) -> Statement {
    Statement::from_sql_and_values(DbBackend::Postgres, sql, values)
}

fn require_project(row: &QueryResult, project_id: Uuid) -> Result<(), ApplicationError> {
    if get::<Uuid>(row, "project_id")? != project_id {
        return Err(ApplicationError::NotFound);
    }
    Ok(())
}

fn method_kind(authority: IdentityMutationProofAuthoritySelection) -> IdentityKind {
    match authority {
        IdentityMutationProofAuthoritySelection::Provider { .. } => IdentityKind::Provider,
        IdentityMutationProofAuthoritySelection::Email { .. } => IdentityKind::Email,
    }
}

fn authority_application(authority: IdentityMutationProofAuthoritySelection) -> Uuid {
    match authority {
        IdentityMutationProofAuthoritySelection::Provider { application_id, .. }
        | IdentityMutationProofAuthoritySelection::Email { application_id } => application_id,
    }
}

fn method_str(authority: IdentityMutationProofAuthoritySelection) -> &'static str {
    match authority {
        IdentityMutationProofAuthoritySelection::Provider { .. } => "provider",
        IdentityMutationProofAuthoritySelection::Email { .. } => "email",
    }
}

fn identity_table(kind: IdentityKind) -> &'static str {
    match kind {
        IdentityKind::Provider => "linked_identities",
        IdentityKind::Email => "email_identities",
    }
}

fn kind_str(kind: IdentityMutationKind) -> &'static str {
    kind.as_str()
}

fn parse_kind(value: &str) -> Result<IdentityMutationKind, ApplicationError> {
    match value {
        "link" => Ok(IdentityMutationKind::Link),
        "unlink" => Ok(IdentityMutationKind::Unlink),
        "merge" => Ok(IdentityMutationKind::Merge),
        _ => Err(ApplicationError::Integrity),
    }
}

fn parse_status(value: &str) -> Result<IdentityMutationStatus, ApplicationError> {
    match value {
        "pending_proof" => Ok(IdentityMutationStatus::PendingProof),
        "ready" => Ok(IdentityMutationStatus::Ready),
        "completed" => Ok(IdentityMutationStatus::Completed),
        "expired" => Ok(IdentityMutationStatus::Expired),
        "cancelled" => Ok(IdentityMutationStatus::Cancelled),
        _ => Err(ApplicationError::Integrity),
    }
}

fn parse_role(value: &str) -> Result<IdentityMutationSlotRole, ApplicationError> {
    match value {
        "destination_owner" => Ok(IdentityMutationSlotRole::DestinationOwner),
        "candidate_identity" => Ok(IdentityMutationSlotRole::CandidateIdentity),
        "identity_owner" => Ok(IdentityMutationSlotRole::IdentityOwner),
        "winner_owner" => Ok(IdentityMutationSlotRole::WinnerOwner),
        "loser_owner" => Ok(IdentityMutationSlotRole::LoserOwner),
        _ => Err(ApplicationError::Integrity),
    }
}

fn parse_identity_kind(value: &str) -> Result<IdentityKind, ApplicationError> {
    match value {
        "provider" => Ok(IdentityKind::Provider),
        "email" => Ok(IdentityKind::Email),
        _ => Err(ApplicationError::Integrity),
    }
}

fn parse_method(value: &str) -> Result<IdentityMutationProofMethodKind, ApplicationError> {
    match value {
        "provider" => Ok(IdentityMutationProofMethodKind::Provider),
        "email" => Ok(IdentityMutationProofMethodKind::Email),
        _ => Err(ApplicationError::Integrity),
    }
}

fn parse_slot_state(value: &str) -> Result<IdentityMutationSlotState, ApplicationError> {
    match value {
        "pending" => Ok(IdentityMutationSlotState::Pending),
        "provider_authorization_started" => {
            Ok(IdentityMutationSlotState::ProviderAuthorizationStarted)
        }
        "provider_exchange_in_progress" => {
            Ok(IdentityMutationSlotState::ProviderExchangeInProgress)
        }
        "provider_exchange_failed" => Ok(IdentityMutationSlotState::ProviderExchangeFailed),
        "email_address_entry" => Ok(IdentityMutationSlotState::EmailAddressEntry),
        "email_challenge_pending" => Ok(IdentityMutationSlotState::EmailChallengePending),
        "proved" => Ok(IdentityMutationSlotState::Proved),
        "expired" => Ok(IdentityMutationSlotState::Expired),
        _ => Err(ApplicationError::Integrity),
    }
}

fn namespace_error<E: std::fmt::Display>(error: E) -> ApplicationError {
    let text = error.to_string();
    if text.contains("23505") || text.contains("unique") {
        ApplicationError::RevisionConflict
    } else {
        ApplicationError::Persistence
    }
}

async fn append_mutation_outcome_audit(
    transaction: &DatabaseTransaction,
    project_id: Uuid,
    intent_id: Uuid,
    correlation_id: Uuid,
    actor_kind: &str,
    action: &str,
    safe_outcome: &str,
) -> Result<(), ApplicationError> {
    if !matches!(actor_kind, "runtime" | "deployment_operator")
        || safe_outcome.is_empty()
        || safe_outcome.len() > 64
        || !safe_outcome
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(ApplicationError::InvalidInput);
    }
    transaction
        .execute_raw(statement(
            "INSERT INTO audit_events
             (id,project_id,actor_kind,action,target_kind,target_id,outcome,correlation_id,safe_context)
             VALUES ($1,$2,$3,$4,'identity_mutation',$5,'succeeded',$6,$7)",
            vec![
                Uuid::new_v4().into(),
                project_id.into(),
                actor_kind.into(),
                action.into(),
                intent_id.into(),
                correlation_id.into(),
                json!({"safe_outcome": safe_outcome}).into(),
            ],
        ))
        .await
        .map_err(persistence)?;
    Ok(())
}

async fn lock_prepared_candidate_namespace(
    transaction: &DatabaseTransaction,
    confirmation: &PreparedIdentityMutationConfirmation,
) -> Result<(), ApplicationError> {
    let candidate = confirmation
        .candidate
        .as_ref()
        .ok_or(ApplicationError::Integrity)?;
    match &candidate.candidate {
        IdentityMutationCandidate::Provider(provider) => {
            lock_provider_namespace(
                transaction,
                confirmation.project_id,
                &provider.issuer,
                &provider.subject,
            )
            .await
        }
        IdentityMutationCandidate::Email(_) => {
            transaction
                .execute_raw(statement(
                    "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                    vec![format!("email:{}", confirmation.project_id).into()],
                ))
                .await
                .map_err(persistence)?;
            Ok(())
        }
    }
}

async fn disconnect_managed_identity(
    transaction: &DatabaseTransaction,
    project_id: Uuid,
    identity_id: Uuid,
    timestamp: OffsetDateTime,
) -> Result<(), ApplicationError> {
    let Some(connection) = transaction
        .query_one_raw(statement(
            "SELECT id,revision,generation,credential_generation,state
               FROM managed_provider_connections
              WHERE project_id=$1 AND linked_identity_id=$2 FOR UPDATE",
            vec![project_id.into(), identity_id.into()],
        ))
        .await
        .map_err(persistence)?
    else {
        return Ok(());
    };
    if get::<String>(&connection, "state")? == "disconnected" {
        return Ok(());
    }
    let connection_id: Uuid = get(&connection, "id")?;
    let generation: i64 = get(&connection, "generation")?;
    let credential_generation: i64 = get(&connection, "credential_generation")?;
    let credential = transaction
        .query_one_raw(statement(
            "SELECT connection_generation,credential_generation,ciphertext
               FROM managed_provider_credentials WHERE project_id=$1 AND connection_id=$2
                AND credential_generation=$3 FOR UPDATE",
            vec![
                project_id.into(),
                connection_id.into(),
                credential_generation.into(),
            ],
        ))
        .await
        .map_err(persistence)?;
    if let Some(credential) = credential {
        if get::<i64>(&credential, "connection_generation")? != generation
            || get::<i64>(&credential, "credential_generation")? != credential_generation
        {
            return Err(ApplicationError::RevisionConflict);
        }
        if get::<Option<Vec<u8>>>(&credential, "ciphertext")?.is_some() {
            let result = transaction
                .execute_raw(statement(
                    "UPDATE managed_provider_credentials SET ciphertext=NULL,destroyed_at=$4
                      WHERE project_id=$1 AND connection_id=$2 AND credential_generation=$3
                        AND connection_generation=$5 AND ciphertext IS NOT NULL",
                    vec![
                        project_id.into(),
                        connection_id.into(),
                        credential_generation.into(),
                        timestamp.into(),
                        generation.into(),
                    ],
                ))
                .await
                .map_err(persistence)?;
            if result.rows_affected() != 1 {
                return Err(ApplicationError::RevisionConflict);
            }
        }
    }
    let result = transaction
        .execute_raw(statement(
            "UPDATE managed_provider_connections SET state='disconnected',revision=revision+1,
                    generation=generation+1,lease_owner=NULL,lease_kind=NULL,lease_expires_at=NULL,
                    next_synchronize_at=NULL,next_renewal_at=NULL,
                    revocation_requested_at=NULL,revocation_disposition=NULL,
                    revocation_dispatch_started_at=NULL,revocation_attempt_id=NULL,
                    last_safe_outcome='identity_unlinked',disconnected_at=$6,updated_at=$6
              WHERE project_id=$1 AND id=$2 AND linked_identity_id=$3
                AND revision=$4 AND generation=$5 AND state<>'disconnected'",
            vec![
                project_id.into(),
                connection_id.into(),
                identity_id.into(),
                get::<i64>(&connection, "revision")?.into(),
                generation.into(),
                timestamp.into(),
            ],
        ))
        .await
        .map_err(persistence)?;
    if result.rows_affected() != 1 {
        return Err(ApplicationError::RevisionConflict);
    }
    Ok(())
}
