use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseConnection, DatabaseTransaction, DbBackend, EntityTrait,
    QueryFilter, QueryResult, QuerySelect, Statement, TransactionTrait,
};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{
    audit::append_runtime_audit,
    entity::login_transaction,
    identity_mutation::{
        expire_locked_if_needed, terminalize_due_identity_mutations,
        terminalize_unreadable_identity_mutations,
    },
    provisioning::insert_audit,
    session_authority::{
        BrowserSessionCompletion, insert_handoff, lock_login_application_owners,
        lock_project_identity_graph, rotate_or_create_browser_session,
    },
};

use crate::application::{
    AdmittedEmailMethod, ApplicationError, CommitEmailGeneration, CompleteEmailProof,
    EmailGenerationPreparation, EmailIdentityAliasAuthority, EmailProofDecision, EmailProofKind,
    EstablishMagicTransferContext, IssuedHandoff, PasswordlessEmailRepository, ProtectedValue,
    ResolveMagicTransferContext, ResolvedMagicTransferContext, SelectEmailMethod,
    VerifiedEmailChallenge, VerifyEmailProof, VersionedDigest,
};

const MAX_MAGIC_TRANSFER_CONTEXTS_PER_CHALLENGE: i64 = 8;
const MAX_GLOBAL_MAIL_RECOMPARISONS: usize = 8;

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_field_names,
    reason = "the inventory names distinguish lifecycle and cryptographic purpose explicitly"
)]
pub(crate) struct EmailProtectionInventory {
    pub short_term_digest_versions: BTreeSet<i32>,
    pub short_term_protection_versions: BTreeSet<i32>,
    pub durable_digest_versions: BTreeSet<i32>,
    pub durable_protection_versions: BTreeSet<i32>,
}

fn email_alias_authority_from_row(
    row: &QueryResult,
) -> Result<EmailIdentityAliasAuthority, ApplicationError> {
    let accepted: serde_json::Value = row.try_get("", "accepted_versions").map_err(persistence)?;
    let accepted_versions =
        serde_json::from_value::<Vec<i32>>(accepted).map_err(|_| ApplicationError::Integrity)?;
    let authority = EmailIdentityAliasAuthority {
        revision: row.try_get("", "revision").map_err(persistence)?,
        write_version: row.try_get("", "write_version").map_err(persistence)?,
        accepted_versions,
    };
    let unique = authority
        .accepted_versions
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if authority.revision <= 0
        || authority.write_version <= 0
        || unique.len() != authority.accepted_versions.len()
        || unique.is_empty()
        || unique.len() > 16
        || !unique.contains(&authority.write_version)
    {
        return Err(ApplicationError::Integrity);
    }
    Ok(authority)
}

impl EmailProtectionInventory {
    fn all_versions_are_readable(
        &self,
        short_term_readable: &BTreeSet<i32>,
        email_identity_readable: &BTreeSet<i32>,
    ) -> bool {
        self.short_term_digest_versions
            .is_subset(short_term_readable)
            && self
                .short_term_protection_versions
                .is_subset(short_term_readable)
            && self
                .durable_digest_versions
                .is_subset(email_identity_readable)
            && self
                .durable_protection_versions
                .is_subset(email_identity_readable)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PostgresPasswordlessEmailRepository {
    database: DatabaseConnection,
    runtime_process_id: String,
    runtime_incarnation: Uuid,
    required_runtime_process_ids: Vec<String>,
    readiness_lease: time::Duration,
}

#[derive(Clone, Debug)]
pub(crate) struct ProjectSmtpReadinessCandidate {
    pub project_id: Uuid,
    pub configuration_id: Uuid,
    pub generation: i32,
    pub credential_ref: String,
    pub safe_fingerprint: [u8; 32],
}

impl PostgresPasswordlessEmailRepository {
    pub(crate) fn new(database: DatabaseConnection) -> Self {
        Self::new_with_runtime_identity(
            database,
            "runtime-1".to_owned(),
            Uuid::nil(),
            vec!["runtime-1".to_owned()],
            time::Duration::minutes(5),
        )
    }

    pub(crate) fn new_with_runtime_roster(
        database: DatabaseConnection,
        required_runtime_process_ids: Vec<String>,
    ) -> Self {
        Self::new_with_runtime_identity(
            database,
            "runtime-reader".to_owned(),
            Uuid::nil(),
            required_runtime_process_ids,
            time::Duration::minutes(5),
        )
    }

    pub(crate) fn new_with_runtime_identity(
        database: DatabaseConnection,
        runtime_process_id: String,
        runtime_incarnation: Uuid,
        required_runtime_process_ids: Vec<String>,
        readiness_lease: time::Duration,
    ) -> Self {
        Self {
            database,
            runtime_process_id,
            runtime_incarnation,
            required_runtime_process_ids,
            readiness_lease,
        }
    }

    fn runtime_roster_json(&self) -> serde_json::Value {
        serde_json::json!(self.required_runtime_process_ids)
    }

    /// Acquire the first lock in every Runtime-owned business transaction. The shared row lock
    /// is retained through commit and conflicts with incarnation replacement's UPSERT update.
    async fn lock_local_runtime_incarnation<C: ConnectionTrait>(
        &self,
        connection: &C,
    ) -> Result<(), ApplicationError> {
        let current = connection
            .query_one_raw(statement(
                "SELECT 1 FROM runtime_process_incarnations
                 WHERE process_id=$1 AND process_incarnation=$2 FOR SHARE",
                vec![
                    self.runtime_process_id.clone().into(),
                    self.runtime_incarnation.into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .is_some();
        if current {
            Ok(())
        } else {
            Err(ApplicationError::Disabled)
        }
    }

    pub(crate) async fn claim_runtime_incarnation(
        &self,
        now: OffsetDateTime,
    ) -> Result<(), ApplicationError> {
        self.database
            .execute_raw(statement(
                "INSERT INTO runtime_process_incarnations
                   (process_id,process_incarnation,started_at) VALUES ($1,$2,$3)
                 ON CONFLICT (process_id) DO UPDATE SET
                   process_incarnation=EXCLUDED.process_incarnation,
                   started_at=EXCLUDED.started_at",
                vec![
                    self.runtime_process_id.clone().into(),
                    self.runtime_incarnation.into(),
                    now.into(),
                ],
            ))
            .await
            .map_err(persistence)
            .map(|_| ())
    }

    pub(crate) async fn record_email_protection_readiness(
        &self,
        ready: bool,
        failure_class: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<(), ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        self.lock_local_runtime_incarnation(&transaction).await?;
        let lease_expires_at = now + self.readiness_lease;
        let result = transaction
            .execute_raw(statement(
                "INSERT INTO email_protection_runtime_readiness
                   (process_id,process_incarnation,state,failure_class,checked_at,lease_expires_at)
                 SELECT $1,$2,$3,$4,$5,$6 WHERE EXISTS (
                   SELECT 1 FROM runtime_process_incarnations current
                   WHERE current.process_id=$1 AND current.process_incarnation=$2)
                 ON CONFLICT (process_id) DO UPDATE SET
                   process_incarnation=EXCLUDED.process_incarnation,state=EXCLUDED.state,
                   failure_class=EXCLUDED.failure_class,checked_at=EXCLUDED.checked_at,
                   lease_expires_at=EXCLUDED.lease_expires_at
                 WHERE EXISTS (
                   SELECT 1 FROM runtime_process_incarnations current
                   WHERE current.process_id=$1 AND current.process_incarnation=$2)",
                vec![
                    self.runtime_process_id.clone().into(),
                    self.runtime_incarnation.into(),
                    (if ready { "ready" } else { "unavailable" }).into(),
                    failure_class.map(ToOwned::to_owned).into(),
                    now.into(),
                    lease_expires_at.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        if result.rows_affected() != 1 {
            return Err(ApplicationError::Disabled);
        }
        transaction.commit().await.map_err(persistence)
    }

    /// Fail closed only the durable email capability. The exact incarnation lock must already
    /// be the transaction's first lock; this bounded lease cannot be inherited by a successor.
    async fn assert_email_protection_ready<C: ConnectionTrait>(
        &self,
        connection: &C,
    ) -> Result<(), ApplicationError> {
        let ready = connection
            .query_one_raw(statement(
                "SELECT 1 FROM email_protection_runtime_readiness protection
                 JOIN runtime_process_incarnations current
                   ON current.process_id=protection.process_id
                  AND current.process_incarnation=protection.process_incarnation
                 WHERE protection.process_id=$1 AND protection.process_incarnation=$2
                   AND protection.state='ready'
                   AND protection.lease_expires_at>clock_timestamp()
                 FOR SHARE OF protection,current",
                vec![
                    self.runtime_process_id.clone().into(),
                    self.runtime_incarnation.into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .is_some();
        ready.then_some(()).ok_or(ApplicationError::Disabled)
    }

    /// Returns a bounded inventory of exact active or still-retained Project SMTP references.
    /// Rows with no observation are preferred, then the oldest observation, so repeated batches
    /// converge without making unrelated Runtime capabilities globally unready.
    pub(crate) async fn project_smtp_readiness_candidates(
        &self,
        now: OffsetDateTime,
        limit: u32,
    ) -> Result<Vec<ProjectSmtpReadinessCandidate>, ApplicationError> {
        self.project_smtp_readiness_candidates_before(now, now, limit)
            .await
    }

    /// Fail-close every persisted eligible observation before a restore inventory starts. This
    /// is deliberately one set-based transition: process loss at any later page remains safe,
    /// and no stale `ready` row can be admitted while startup validates the remaining pages.
    pub(crate) async fn fail_close_project_smtp_restore_inventory(
        &self,
        now: OffsetDateTime,
    ) -> Result<u64, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        self.lock_local_runtime_incarnation(&transaction).await?;
        let result = transaction
            .execute_raw(statement(
                "WITH claimed AS (
                   SELECT process_id FROM runtime_process_incarnations
                   WHERE process_id=$4 AND process_incarnation=$2),
                 cleaned AS (
                   DELETE FROM project_smtp_runtime_readiness obsolete
                   USING project_smtp_configurations smtp
                   WHERE obsolete.project_id=smtp.project_id
                     AND obsolete.configuration_id=smtp.id
                     AND obsolete.generation=smtp.generation
                     AND (smtp.status IN ('disabled','compromised','retired')
                          OR (smtp.status='retained' AND smtp.retained_until<=$1))
                   RETURNING obsolete.project_id)
                 UPDATE project_smtp_runtime_readiness readiness
                 SET state='unavailable',process_incarnation=$2,lease_expires_at=$3
                 FROM project_smtp_configurations smtp,claimed
                 WHERE readiness.project_id=smtp.project_id
                   AND readiness.configuration_id=smtp.id
                   AND readiness.generation=smtp.generation
                   AND readiness.process_id=claimed.process_id
                   AND (smtp.status IN ('pending','active')
                        OR (smtp.status='retained' AND smtp.retained_until>$1))",
                vec![
                    now.into(),
                    self.runtime_incarnation.into(),
                    (now + self.readiness_lease).into(),
                    self.runtime_process_id.clone().into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        let affected = result.rows_affected();
        transaction.commit().await.map_err(persistence)?;
        Ok(affected)
    }

    /// Inventory only rows not observed in the supplied restore epoch. Reusing one epoch while
    /// paging lets startup prove completeness rather than declaring readiness after page one.
    pub(crate) async fn project_smtp_readiness_candidates_before(
        &self,
        now: OffsetDateTime,
        checked_before: OffsetDateTime,
        limit: u32,
    ) -> Result<Vec<ProjectSmtpReadinessCandidate>, ApplicationError> {
        if limit == 0 || limit > 100 {
            return Err(ApplicationError::InvalidInput);
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        self.lock_local_runtime_incarnation(&transaction).await?;
        let rows = transaction
            .query_all_raw(statement(
                "SELECT smtp.project_id,smtp.id,smtp.generation,smtp.credential_ref,
                        smtp.safe_fingerprint
                 FROM project_smtp_configurations smtp
                 LEFT JOIN project_smtp_runtime_readiness readiness
                   ON readiness.project_id=smtp.project_id
                  AND readiness.configuration_id=smtp.id
                  AND readiness.generation=smtp.generation
                  AND readiness.process_id=$4
                 WHERE (smtp.status IN ('pending','active')
                    OR (smtp.status='retained' AND smtp.retained_until>$1))
                   AND (readiness.checked_at IS NULL OR readiness.checked_at<$2
                        OR readiness.process_incarnation<>$5)
                 ORDER BY readiness.checked_at NULLS FIRST,smtp.project_id,smtp.generation
                 LIMIT $3",
                vec![
                    now.into(),
                    checked_before.into(),
                    i64::from(limit).into(),
                    self.runtime_process_id.clone().into(),
                    self.runtime_incarnation.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        let candidates = rows
            .iter()
            .map(|row| {
                let fingerprint: Vec<u8> =
                    row.try_get("", "safe_fingerprint").map_err(persistence)?;
                Ok(ProjectSmtpReadinessCandidate {
                    project_id: row.try_get("", "project_id").map_err(persistence)?,
                    configuration_id: row.try_get("", "id").map_err(persistence)?,
                    generation: row.try_get("", "generation").map_err(persistence)?,
                    credential_ref: row.try_get("", "credential_ref").map_err(persistence)?,
                    safe_fingerprint: fingerprint
                        .try_into()
                        .map_err(|_| ApplicationError::Integrity)?,
                })
            })
            .collect::<Result<Vec<_>, ApplicationError>>()?;
        transaction.commit().await.map_err(persistence)?;
        Ok(candidates)
    }

    pub(crate) async fn record_project_smtp_readiness(
        &self,
        candidate: &ProjectSmtpReadinessCandidate,
        ready: bool,
        now: OffsetDateTime,
    ) -> Result<(), ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        self.lock_local_runtime_incarnation(&transaction).await?;
        let result = transaction
            .execute_raw(statement(
                "INSERT INTO project_smtp_runtime_readiness
             (project_id,configuration_id,generation,process_id,process_incarnation,state,checked_at,lease_expires_at)
             SELECT smtp.project_id,smtp.id,smtp.generation,$6,$7,$8,$9,$10
             FROM project_smtp_configurations smtp
             WHERE smtp.project_id=$1 AND smtp.id=$2 AND smtp.generation=$3
               AND smtp.credential_ref=$4 AND smtp.safe_fingerprint=$5
               AND EXISTS (
                 SELECT 1 FROM runtime_process_incarnations current
                 WHERE current.process_id=$6 AND current.process_incarnation=$7)
               AND (smtp.status IN ('pending','active')
                    OR (smtp.status='retained' AND smtp.retained_until>$9))
             ON CONFLICT (project_id,configuration_id,generation,process_id)
             DO UPDATE SET process_incarnation=EXCLUDED.process_incarnation,
                           state=EXCLUDED.state,checked_at=EXCLUDED.checked_at,
                           lease_expires_at=EXCLUDED.lease_expires_at",
                vec![
                    candidate.project_id.into(),
                    candidate.configuration_id.into(),
                    candidate.generation.into(),
                    candidate.credential_ref.clone().into(),
                    candidate.safe_fingerprint.to_vec().into(),
                    self.runtime_process_id.clone().into(),
                    self.runtime_incarnation.into(),
                    (if ready { "ready" } else { "unavailable" }).into(),
                    now.into(),
                    (now + self.readiness_lease).into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        if result.rows_affected() > 1 {
            return Err(ApplicationError::Integrity);
        }
        transaction.commit().await.map_err(persistence)
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "authority staging, fenced backfill, roster cutover, and bounded retirement share one serialized transaction"
    )]
    pub(crate) async fn rewrap_durable_email_identities(
        &self,
        protector: &dyn crate::application::RuntimeProtector,
        limit: u64,
        process_id: &str,
        required_process_ids: &[String],
        lease_expires_at: OffsetDateTime,
        cutover_requested: bool,
        retirement_requested: bool,
        now: OffsetDateTime,
    ) -> Result<u64, ApplicationError> {
        if limit == 0
            || limit > 100
            || (cutover_requested && retirement_requested)
            || process_id != self.runtime_process_id
        {
            return Err(ApplicationError::InvalidInput);
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        self.lock_local_runtime_incarnation(&transaction).await?;
        transaction
            .execute_raw(statement(
                "SELECT pg_advisory_xact_lock(hashtextextended('email-identity-alias-authority',0))",
                vec![],
            ))
            .await
            .map_err(persistence)?;
        let inserted = transaction
            .query_one_raw(statement(
                "INSERT INTO email_identity_alias_authority
                 (singleton,revision,write_version,target_version,accepted_versions,updated_at)
                 VALUES (TRUE,1,$1,$1,$2,$3) ON CONFLICT (singleton) DO NOTHING
                 RETURNING revision",
                vec![
                    protector.email_identity_active_version().into(),
                    serde_json::json!([protector.email_identity_active_version()]).into(),
                    now.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        if inserted.is_some() {
            transaction
                .execute_raw(statement(
                    "INSERT INTO email_identity_alias_authority_events
                     (authority_revision,action,to_write_version,affected_rows,created_at)
                     VALUES (1,'initialized',$1,0,$2)",
                    vec![protector.email_identity_active_version().into(), now.into()],
                ))
                .await
                .map_err(persistence)?;
        }
        let authority_row = transaction
            .query_one_raw(statement(
                "SELECT revision,write_version,target_version,accepted_versions,retirement_version,
                        overlap_verified_revision
                 FROM email_identity_alias_authority WHERE singleton=TRUE FOR UPDATE",
                vec![],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        let mut authority = email_alias_authority_from_row(&authority_row)?;
        let mut target_version: i32 = authority_row
            .try_get("", "target_version")
            .map_err(persistence)?;
        let mut retirement_version: Option<i32> = authority_row
            .try_get("", "retirement_version")
            .map_err(persistence)?;
        let mut overlap_verified_revision: Option<i64> = authority_row
            .try_get("", "overlap_verified_revision")
            .map_err(persistence)?;
        if target_version < authority.write_version {
            return Err(ApplicationError::Integrity);
        }
        let accepted = authority
            .accepted_versions
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let rollback_requested = protector.email_identity_active_version()
            < authority.write_version
            && cutover_requested
            && accepted.contains(&protector.email_identity_active_version());
        if protector.email_identity_active_version() < authority.write_version
            && !rollback_requested
        {
            return Err(ApplicationError::Integrity);
        }
        if protector.email_identity_active_version() > target_version {
            let next_revision = authority
                .revision
                .checked_add(1)
                .ok_or(ApplicationError::Integrity)?;
            transaction
                .execute_raw(statement(
                    "UPDATE email_identity_alias_authority
                     SET revision=$1,target_version=$2,retirement_version=NULL,
                         overlap_verified_revision=NULL,updated_at=$3
                     WHERE singleton=TRUE AND revision=$4",
                    vec![
                        next_revision.into(),
                        protector.email_identity_active_version().into(),
                        now.into(),
                        authority.revision.into(),
                    ],
                ))
                .await
                .map_err(persistence)?;
            transaction
                .execute_raw(statement(
                    "INSERT INTO email_identity_alias_authority_events
                     (authority_revision,action,from_write_version,to_write_version,affected_rows,created_at)
                     VALUES ($1,'staged',$2,$3,0,$4)",
                    vec![
                        next_revision.into(),
                        authority.write_version.into(),
                        protector.email_identity_active_version().into(),
                        now.into(),
                    ],
                ))
                .await
                .map_err(persistence)?;
            authority.revision = next_revision;
            target_version = protector.email_identity_active_version();
            retirement_version = None;
            overlap_verified_revision = None;
        }
        transaction
            .execute_raw(statement(
                "INSERT INTO email_identity_alias_runtime_observations
                 (process_id,process_incarnation,active_version,observed_authority_revision,
                  retirement_requested,retirement_request_revision,lease_expires_at,updated_at)
                 VALUES ($1,$2,$3,$4,$5,CASE WHEN $5 THEN $4 ELSE NULL END,$6,$7)
                 ON CONFLICT (process_id) DO UPDATE SET
                   process_incarnation=EXCLUDED.process_incarnation,
                   active_version=EXCLUDED.active_version,
                   observed_authority_revision=EXCLUDED.observed_authority_revision,
                   retirement_request_revision=CASE
                     WHEN EXCLUDED.retirement_requested
                          AND NOT email_identity_alias_runtime_observations.retirement_requested
                       THEN EXCLUDED.observed_authority_revision
                     WHEN EXCLUDED.retirement_requested
                       THEN email_identity_alias_runtime_observations.retirement_request_revision
                     ELSE NULL END,
                   retirement_requested=EXCLUDED.retirement_requested,
                   lease_expires_at=EXCLUDED.lease_expires_at,updated_at=EXCLUDED.updated_at",
                vec![
                    self.runtime_process_id.clone().into(),
                    self.runtime_incarnation.into(),
                    protector.email_identity_active_version().into(),
                    authority.revision.into(),
                    retirement_requested.into(),
                    lease_expires_at.into(),
                    now.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        if protector.email_identity_active_version() < target_version
            && protector.email_identity_active_version() != authority.write_version
            && !rollback_requested
        {
            transaction.commit().await.map_err(persistence)?;
            return Ok(0);
        }
        let rows = transaction
            .query_all_raw(statement(
                "SELECT identity.* FROM email_identities identity
             WHERE identity.address_key_version <> $1 OR NOT EXISTS (
               SELECT 1 FROM email_identity_aliases alias
               WHERE alias.project_id=identity.project_id AND alias.identity_id=identity.id
                 AND alias.canonicalization_version=1 AND alias.digest_key_version=$1)
             ORDER BY identity.project_id,identity.id LIMIT $2
             FOR UPDATE OF identity SKIP LOCKED",
                vec![
                    protector.email_identity_active_version().into(),
                    i64::try_from(limit)
                        .map_err(|_| ApplicationError::InvalidInput)?
                        .into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        for row in &rows {
            let project_id: Uuid = row.try_get("", "project_id").map_err(persistence)?;
            let identity_id: Uuid = row.try_get("", "id").map_err(persistence)?;
            transaction
                .query_one_raw(statement(
                    "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                    vec![project_id.to_string().into()],
                ))
                .await
                .map_err(persistence)?;
            let old = ProtectedValue {
                ciphertext: row.try_get("", "address_ciphertext").map_err(persistence)?,
                key_version: row
                    .try_get("", "address_key_version")
                    .map_err(persistence)?,
            };
            let context = email_identity_context(project_id, identity_id);
            let plaintext = protector.unprotect(
                crate::application::ProtectedPurpose::EmailIdentityAddress,
                &context,
                &old,
            )?;
            let canonical = crate::domain::CanonicalEmail::parse_v1(
                std::str::from_utf8(plaintext.as_slice())
                    .map_err(|_| ApplicationError::Integrity)?,
            )
            .map_err(|_| ApplicationError::Integrity)?;
            let alias = protector.digest(
                crate::application::OpaquePurpose::EmailIdentityLookup,
                project_id.as_bytes(),
                canonical.expose().as_bytes(),
            )?;
            transaction.execute_raw(statement(
                "INSERT INTO email_identity_aliases
                 (project_id,identity_id,canonicalization_version,digest_key_version,lookup_digest,created_at)
                 VALUES ($1,$2,1,$3,$4,$5) ON CONFLICT DO NOTHING",
                vec![project_id.into(),identity_id.into(),alias.key_version.into(),alias.value.to_vec().into(),now.into()],
            )).await.map_err(|_| ApplicationError::Integrity)?;
            let owner = transaction
                .query_one_raw(statement(
                    "SELECT identity_id FROM email_identity_aliases WHERE project_id=$1
                 AND canonicalization_version=1 AND digest_key_version=$2 AND lookup_digest=$3",
                    vec![
                        project_id.into(),
                        alias.key_version.into(),
                        alias.value.to_vec().into(),
                    ],
                ))
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::Integrity)?;
            if owner
                .try_get::<Uuid>("", "identity_id")
                .map_err(persistence)?
                != identity_id
            {
                return Err(ApplicationError::Integrity);
            }
            let replacement = protector.protect(
                crate::application::ProtectedPurpose::EmailIdentityAddress,
                &context,
                canonical.expose().as_bytes(),
            )?;
            let updated=transaction.execute_raw(statement(
                "UPDATE email_identities SET address_ciphertext=$4,address_key_version=$5,updated_at=$6
                 WHERE project_id=$1 AND id=$2 AND address_key_version=$3 AND address_ciphertext=$7",
                vec![project_id.into(),identity_id.into(),old.key_version.into(),replacement.ciphertext.into(),
                    replacement.key_version.into(),now.into(),old.ciphertext.into()],
            )).await.map_err(persistence)?;
            if updated.rows_affected() != 1 {
                return Err(ApplicationError::RevisionConflict);
            }
        }
        let rewrapped = u64::try_from(rows.len()).map_err(|_| ApplicationError::Integrity)?;
        let mut write_version = authority.write_version;
        let (roster_ready, retirement_rollout_ready) = if required_process_ids.is_empty() {
            (false, false)
        } else {
            let rows = transaction
                .query_all_raw(statement(
                    "SELECT observation.process_id,observation.active_version,
                            observation.observed_authority_revision,
                            observation.retirement_requested,observation.retirement_request_revision
                     FROM email_identity_alias_runtime_observations observation
                     JOIN runtime_process_incarnations current
                       ON current.process_id=observation.process_id
                      AND current.process_incarnation=observation.process_incarnation
                     WHERE observation.lease_expires_at>$1
                     ORDER BY observation.process_id FOR SHARE OF current",
                    vec![now.into()],
                ))
                .await
                .map_err(persistence)?;
            let observed = rows
                .iter()
                .map(|row| {
                    Ok((
                        row.try_get::<String>("", "process_id")
                            .map_err(persistence)?,
                        (
                            row.try_get::<i32>("", "active_version")
                                .map_err(persistence)?,
                            row.try_get::<i64>("", "observed_authority_revision")
                                .map_err(persistence)?,
                            row.try_get::<bool>("", "retirement_requested")
                                .map_err(persistence)?,
                            row.try_get::<Option<i64>>("", "retirement_request_revision")
                                .map_err(persistence)?,
                        ),
                    ))
                })
                .collect::<Result<BTreeMap<_, _>, ApplicationError>>()?;
            let is_current = |(version, revision, _, _): &(i32, i64, bool, Option<i64>)| {
                *version == protector.email_identity_active_version()
                    && *revision >= authority.revision
            };
            let all_live_current = observed.values().all(is_current);
            let required_current = required_process_ids
                .iter()
                .all(|process_id| observed.get(process_id).is_some_and(is_current));
            let request_after_overlap = |(version, revision, requested, request_revision): &(
                i32,
                i64,
                bool,
                Option<i64>,
            )| {
                is_current(&(*version, *revision, *requested, *request_revision))
                    && *requested
                    && overlap_verified_revision.is_some_and(|verified| {
                        request_revision.is_some_and(|request| request >= verified)
                    })
            };
            let all_live_requested_after_overlap = observed.values().all(request_after_overlap);
            let required_requested_after_overlap = required_process_ids
                .iter()
                .all(|process_id| observed.get(process_id).is_some_and(request_after_overlap));
            (
                all_live_current && required_current,
                all_live_requested_after_overlap && required_requested_after_overlap,
            )
        };
        let mut phase_changed = false;
        if rows.is_empty()
            && protector.email_identity_active_version() != authority.write_version
            && cutover_requested
            && roster_ready
        {
            let missing = transaction
                .query_one_raw(statement(
                    "SELECT COUNT(*) AS missing FROM email_identities identity
                     WHERE identity.address_key_version <> $1 OR NOT EXISTS (
                       SELECT 1 FROM email_identity_aliases alias
                       WHERE alias.project_id=identity.project_id AND alias.identity_id=identity.id
                         AND alias.canonicalization_version=1 AND alias.digest_key_version=$1)",
                    vec![protector.email_identity_active_version().into()],
                ))
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::Integrity)?
                .try_get::<i64>("", "missing")
                .map_err(persistence)?;
            if missing != 0 {
                return Err(ApplicationError::Integrity);
            }
            let next_revision = authority
                .revision
                .checked_add(1)
                .ok_or(ApplicationError::Integrity)?;
            let mut accepted = authority
                .accepted_versions
                .iter()
                .copied()
                .collect::<BTreeSet<_>>();
            accepted.insert(authority.write_version);
            accepted.insert(protector.email_identity_active_version());
            let accepted = accepted.into_iter().collect::<Vec<_>>();
            transaction
                .execute_raw(statement(
                    "UPDATE email_identity_alias_authority
                     SET revision=$1,write_version=$2,target_version=$3,accepted_versions=$4,
                         retirement_version=NULL,overlap_verified_revision=NULL,updated_at=$5
                     WHERE singleton=TRUE AND revision=$6",
                    vec![
                        next_revision.into(),
                        protector.email_identity_active_version().into(),
                        target_version
                            .max(protector.email_identity_active_version())
                            .into(),
                        serde_json::json!(accepted).into(),
                        now.into(),
                        authority.revision.into(),
                    ],
                ))
                .await
                .map_err(persistence)?;
            let action = if protector.email_identity_active_version() > authority.write_version {
                "cutover"
            } else {
                "rollback"
            };
            transaction
                .execute_raw(statement(
                    "INSERT INTO email_identity_alias_authority_events
                     (authority_revision,action,from_write_version,to_write_version,affected_rows,created_at)
                     VALUES ($1,$2,$3,$4,0,$5)",
                    vec![
                        next_revision.into(),
                        action.into(),
                        authority.write_version.into(),
                        protector.email_identity_active_version().into(),
                        now.into(),
                    ],
                ))
                .await
                .map_err(persistence)?;
            authority.revision = next_revision;
            authority.write_version = protector.email_identity_active_version();
            authority.accepted_versions = accepted;
            write_version = protector.email_identity_active_version();
            retirement_version = None;
            overlap_verified_revision = None;
            phase_changed = true;
        }
        // Complete roster observation of the overlap is itself durable authority. Retirement
        // requests already present before this revision remain stale until operators roll them
        // off and then perform a later retire-only rollout across the whole live roster.
        if !phase_changed
            && rows.is_empty()
            && write_version == protector.email_identity_active_version()
            && authority.accepted_versions.len() > 1
            && retirement_version.is_none()
            && overlap_verified_revision.is_none()
            && roster_ready
        {
            let next_revision = authority
                .revision
                .checked_add(1)
                .ok_or(ApplicationError::Integrity)?;
            transaction
                .execute_raw(statement(
                    "UPDATE email_identity_alias_authority
                     SET revision=$1,overlap_verified_revision=$1,updated_at=$2
                     WHERE singleton=TRUE AND revision=$3",
                    vec![next_revision.into(), now.into(), authority.revision.into()],
                ))
                .await
                .map_err(persistence)?;
            transaction
                .execute_raw(statement(
                    "INSERT INTO email_identity_alias_authority_events
                     (authority_revision,action,to_write_version,affected_rows,created_at)
                     VALUES ($1,'overlap_verified',$2,0,$3)",
                    vec![next_revision.into(), write_version.into(), now.into()],
                ))
                .await
                .map_err(persistence)?;
            authority.revision = next_revision;
            overlap_verified_revision = Some(next_revision);
            phase_changed = true;
        }
        // Retirement is a distinct durable phase. It cannot reuse a cutover or a request that
        // predates overlap verification. Every live/required Runtime must first observe the exact
        // overlap authority revision and then independently begin the retire-only rollout.
        if !phase_changed
            && rows.is_empty()
            && write_version == protector.email_identity_active_version()
            && retirement_requested
            && roster_ready
            && retirement_rollout_ready
            && overlap_verified_revision.is_some()
            && retirement_version != Some(write_version)
        {
            let next_revision = authority
                .revision
                .checked_add(1)
                .ok_or(ApplicationError::Integrity)?;
            transaction
                .execute_raw(statement(
                    "UPDATE email_identity_alias_authority
                     SET revision=$1,accepted_versions=$2,retirement_version=$3,updated_at=$4
                     WHERE singleton=TRUE AND revision=$5",
                    vec![
                        next_revision.into(),
                        serde_json::json!([write_version]).into(),
                        write_version.into(),
                        now.into(),
                        authority.revision.into(),
                    ],
                ))
                .await
                .map_err(persistence)?;
            transaction
                .execute_raw(statement(
                    "INSERT INTO email_identity_alias_authority_events
                     (authority_revision,action,to_write_version,affected_rows,created_at)
                     VALUES ($1,'retirement_authorized',$2,0,$3)",
                    vec![next_revision.into(), write_version.into(), now.into()],
                ))
                .await
                .map_err(persistence)?;
            authority.revision = next_revision;
            authority.accepted_versions = vec![write_version];
            retirement_version = Some(write_version);
        }
        let retired = if retirement_version == Some(write_version) {
            transaction
                .execute_raw(statement(
                    "DELETE FROM email_identity_aliases WHERE ctid IN (
                       SELECT ctid FROM email_identity_aliases
                       WHERE digest_key_version <> $1 ORDER BY project_id,identity_id
                       LIMIT $2 FOR UPDATE SKIP LOCKED)",
                    vec![
                        write_version.into(),
                        i64::try_from(limit)
                            .map_err(|_| ApplicationError::InvalidInput)?
                            .into(),
                    ],
                ))
                .await
                .map_err(persistence)?
                .rows_affected()
        } else {
            0
        };
        if retired > 0 {
            transaction
                .execute_raw(statement(
                    "INSERT INTO email_identity_alias_authority_events
                     (authority_revision,action,to_write_version,affected_rows,created_at)
                     VALUES ($1,'aliases_retired',$2,$3,$4)",
                    vec![
                        authority.revision.into(),
                        write_version.into(),
                        i64::try_from(retired)
                            .map_err(|_| ApplicationError::Integrity)?
                            .into(),
                        now.into(),
                    ],
                ))
                .await
                .map_err(persistence)?;
        }
        transaction.commit().await.map_err(persistence)?;
        Ok(rewrapped.saturating_add(retired))
    }

    pub(crate) async fn reconcile_protection_inventory(
        &self,
        short_term_readable_versions: &[i32],
        email_identity_readable_versions: &[i32],
        now: OffsetDateTime,
    ) -> Result<EmailProtectionInventory, ApplicationError> {
        let short_term_readable = short_term_readable_versions
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let email_identity_readable = email_identity_readable_versions
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if [&short_term_readable, &email_identity_readable]
            .into_iter()
            .any(|readable| {
                readable.is_empty()
                    || readable.len() > 16
                    || readable.iter().any(|version| *version <= 0)
            })
        {
            return Err(ApplicationError::InvalidInput);
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        self.lock_local_runtime_incarnation(&transaction).await?;
        terminalize_unreadable_short_term(&transaction, &short_term_readable, now).await?;
        let inventory = load_email_protection_inventory(&transaction).await?;
        if !inventory.all_versions_are_readable(&short_term_readable, &email_identity_readable) {
            return Err(ApplicationError::Integrity);
        }
        transaction.commit().await.map_err(persistence)?;
        Ok(inventory)
    }
}

#[async_trait]
#[allow(
    clippy::too_many_lines,
    reason = "security-sensitive PostgreSQL transactions keep every guard visible"
)]
impl PasswordlessEmailRepository for PostgresPasswordlessEmailRepository {
    async fn identity_alias_authority(
        &self,
    ) -> Result<EmailIdentityAliasAuthority, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        self.lock_local_runtime_incarnation(&transaction).await?;
        self.assert_email_protection_ready(&transaction).await?;
        let row = transaction
            .query_one_raw(statement(
                "SELECT revision,write_version,accepted_versions
                 FROM email_identity_alias_authority WHERE singleton=TRUE",
                vec![],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        let authority = email_alias_authority_from_row(&row)?;
        transaction.commit().await.map_err(persistence)?;
        Ok(authority)
    }

    async fn select_email_method(
        &self,
        command: SelectEmailMethod,
    ) -> Result<(), ApplicationError> {
        validate_digest(&command.browser_binding)?;
        validate_digest(&command.csrf)?;
        let transaction = self.database.begin().await.map_err(persistence)?;
        self.lock_local_runtime_incarnation(&transaction).await?;
        self.assert_email_protection_ready(&transaction).await?;
        let row = transaction
            .query_one_raw(statement(
                "SELECT login.status,login.transaction_revision,login.expires_at,login.browser_binding_digest, \
                 login.browser_binding_digest_key_version,login.csrf_digest,login.csrf_digest_key_version, \
                 login.application_id,login.project_metadata_revision,login.project_security_revision, \
                 login.application_security_revision,snapshot.* FROM login_transactions login \
                 JOIN login_email_method_snapshots snapshot ON snapshot.project_id=login.project_id \
                   AND snapshot.transaction_id=login.id \
                 WHERE login.project_id=$1 AND login.id=$2 FOR UPDATE OF login",
                vec![command.project_id.into(), command.transaction_id.into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let status: String = row.try_get("", "status").map_err(persistence)?;
        let revision: i64 = row
            .try_get("", "transaction_revision")
            .map_err(persistence)?;
        let expires_at: OffsetDateTime = row.try_get("", "expires_at").map_err(persistence)?;
        if expires_at <= command.now || status != "awaiting_method_selection" {
            return Err(ApplicationError::InvalidTransition);
        }
        if revision != command.expected_transaction_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        require_stored_digest(
            &row,
            "browser_binding_digest",
            "browser_binding_digest_key_version",
            &command.browser_binding,
        )?;
        require_stored_digest(
            &row,
            "csrf_digest",
            "csrf_digest_key_version",
            &command.csrf,
        )?;
        revalidate_policy_and_smtp(
            &transaction,
            &row,
            command.project_id,
            command.now,
            &self.runtime_process_id,
            self.runtime_incarnation,
            &self.required_runtime_process_ids,
        )
        .await?;
        let result = transaction
            .execute_raw(statement(
                "UPDATE login_transactions SET status = 'email_address_entry', selected_method = 'email', \
                 transaction_revision = transaction_revision + 1, updated_at = $3 \
                 WHERE project_id = $1 AND id = $2 AND status = 'awaiting_method_selection' \
                 AND transaction_revision = $4",
                vec![command.project_id.into(), command.transaction_id.into(), command.now.into(), revision.into()],
            ))
            .await
            .map_err(persistence)?;
        if result.rows_affected() != 1 {
            return Err(ApplicationError::RevisionConflict);
        }
        transaction.commit().await.map_err(persistence)?;
        Ok(())
    }

    async fn prepare_email_generation(
        &self,
        project_id: Uuid,
        transaction_id: Uuid,
        expected_transaction_revision: i64,
        browser_binding: &VersionedDigest,
        csrf: &VersionedDigest,
        now: OffsetDateTime,
    ) -> Result<EmailGenerationPreparation, ApplicationError> {
        validate_digest(browser_binding)?;
        validate_digest(csrf)?;
        let transaction = self.database.begin().await.map_err(persistence)?;
        self.lock_local_runtime_incarnation(&transaction).await?;
        self.assert_email_protection_ready(&transaction).await?;
        let row = transaction.query_one_raw(statement(
            "SELECT login.application_id, login.status, login.transaction_revision, login.expires_at, \
             login.browser_binding_digest, login.browser_binding_digest_key_version, login.csrf_digest, \
             login.csrf_digest_key_version, snapshot.method_policy_revision, snapshot.method_security_revision, \
             snapshot.assignment_security_revision, snapshot.otp_enabled, snapshot.magic_link_enabled, \
             snapshot.otp_digits, snapshot.otp_validity_seconds, snapshot.otp_max_attempts, \
             snapshot.resend_after_seconds, snapshot.max_generations, snapshot.magic_validity_seconds, \
             snapshot.signup_enabled, snapshot.transferred_magic_link_enabled, snapshot.smtp_selection_kind, \
             snapshot.smtp_configuration_id, snapshot.smtp_generation, snapshot.smtp_security_eligibility_revision, \
             COALESCE((SELECT MAX(generation) FROM email_challenges challenge \
                WHERE challenge.project_id = login.project_id AND challenge.transaction_id = login.id), 0)::SMALLINT AS current_generation, \
             (SELECT MAX(issued_at) FROM email_challenges challenge \
                WHERE challenge.project_id = login.project_id AND challenge.transaction_id = login.id) AS last_issued_at \
             FROM login_transactions login JOIN login_email_method_snapshots snapshot \
               ON snapshot.project_id = login.project_id AND snapshot.transaction_id = login.id \
             WHERE login.project_id = $1 AND login.id = $2",
            vec![project_id.into(), transaction_id.into()],
        )).await.map_err(persistence)?.ok_or(ApplicationError::NotFound)?;
        let status: String = row.try_get("", "status").map_err(persistence)?;
        let revision: i64 = row
            .try_get("", "transaction_revision")
            .map_err(persistence)?;
        let transaction_expires_at: OffsetDateTime =
            row.try_get("", "expires_at").map_err(persistence)?;
        if transaction_expires_at <= now
            || !matches!(
                status.as_str(),
                "email_address_entry" | "email_challenge_pending"
            )
        {
            return Err(ApplicationError::InvalidTransition);
        }
        if revision != expected_transaction_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        require_stored_digest(
            &row,
            "browser_binding_digest",
            "browser_binding_digest_key_version",
            browser_binding,
        )?;
        require_stored_digest(&row, "csrf_digest", "csrf_digest_key_version", csrf)?;
        let current_generation: i16 = row.try_get("", "current_generation").map_err(persistence)?;
        let max_generations: i16 = row.try_get("", "max_generations").map_err(persistence)?;
        if current_generation >= max_generations || current_generation >= 5 {
            return Err(ApplicationError::InvalidTransition);
        }
        let resend_after_seconds: i32 = row
            .try_get("", "resend_after_seconds")
            .map_err(persistence)?;
        let last_issued_at: Option<OffsetDateTime> =
            row.try_get("", "last_issued_at").map_err(persistence)?;
        if last_issued_at.is_some_and(|last| {
            now < last + time::Duration::seconds(i64::from(resend_after_seconds))
        }) {
            return Err(ApplicationError::InvalidTransition);
        }
        let result = EmailGenerationPreparation {
            project_id,
            application_id: row.try_get("", "application_id").map_err(persistence)?,
            transaction_id,
            next_generation: current_generation + 1,
            transaction_expires_at,
            policy: AdmittedEmailMethod {
                policy_revision: row
                    .try_get("", "method_policy_revision")
                    .map_err(persistence)?,
                security_revision: row
                    .try_get("", "method_security_revision")
                    .map_err(persistence)?,
                assignment_security_revision: row
                    .try_get("", "assignment_security_revision")
                    .map_err(persistence)?,
                otp_enabled: row.try_get("", "otp_enabled").map_err(persistence)?,
                magic_link_enabled: row.try_get("", "magic_link_enabled").map_err(persistence)?,
                otp_digits: row.try_get("", "otp_digits").map_err(persistence)?,
                otp_validity_seconds: row
                    .try_get("", "otp_validity_seconds")
                    .map_err(persistence)?,
                otp_max_attempts: row.try_get("", "otp_max_attempts").map_err(persistence)?,
                resend_after_seconds,
                max_generations,
                magic_validity_seconds: row
                    .try_get("", "magic_validity_seconds")
                    .map_err(persistence)?,
                signup_enabled: row.try_get("", "signup_enabled").map_err(persistence)?,
                transferred_magic_link_enabled: row
                    .try_get("", "transferred_magic_link_enabled")
                    .map_err(persistence)?,
                smtp_selection_kind: row
                    .try_get("", "smtp_selection_kind")
                    .map_err(persistence)?,
                smtp_configuration_id: row
                    .try_get("", "smtp_configuration_id")
                    .map_err(persistence)?,
                smtp_generation: row.try_get("", "smtp_generation").map_err(persistence)?,
                smtp_security_eligibility_revision: row
                    .try_get("", "smtp_security_eligibility_revision")
                    .map_err(persistence)?,
            },
        };
        transaction.commit().await.map_err(persistence)?;
        Ok(result)
    }

    async fn commit_email_generation(
        &self,
        command: CommitEmailGeneration,
    ) -> Result<(), ApplicationError> {
        validate_generation(&command)?;
        let transaction = self.database.begin().await.map_err(persistence)?;
        self.lock_local_runtime_incarnation(&transaction).await?;
        self.assert_email_protection_ready(&transaction).await?;
        let row = transaction.query_one_raw(statement(
            "SELECT login.status, login.transaction_revision, login.expires_at, login.application_id,
             login.project_metadata_revision, login.project_security_revision,
             login.application_security_revision, snapshot.*,
             COALESCE((SELECT MAX(generation) FROM email_challenges challenge WHERE challenge.project_id = login.project_id AND challenge.transaction_id = login.id), 0)::SMALLINT AS current_generation
             FROM login_transactions login JOIN login_email_method_snapshots snapshot ON snapshot.project_id = login.project_id AND snapshot.transaction_id = login.id
             WHERE login.project_id = $1 AND login.id = $2 FOR UPDATE OF login",
            vec![command.project_id.into(), command.transaction_id.into()],
        )).await.map_err(persistence)?.ok_or(ApplicationError::NotFound)?;
        let status: String = row.try_get("", "status").map_err(persistence)?;
        let revision: i64 = row
            .try_get("", "transaction_revision")
            .map_err(persistence)?;
        let expires_at: OffsetDateTime = row.try_get("", "expires_at").map_err(persistence)?;
        let current_generation: i16 = row.try_get("", "current_generation").map_err(persistence)?;
        if revision != command.expected_transaction_revision
            || current_generation + 1 != command.expected_generation
        {
            return Err(ApplicationError::RevisionConflict);
        }
        if expires_at <= command.issued_at
            || !matches!(
                status.as_str(),
                "email_address_entry" | "email_challenge_pending"
            )
        {
            return Err(ApplicationError::InvalidTransition);
        }
        revalidate_policy_and_smtp(
            &transaction,
            &row,
            command.project_id,
            command.issued_at,
            &self.runtime_process_id,
            self.runtime_incarnation,
            &self.required_runtime_process_ids,
        )
        .await?;
        transaction.execute_raw(statement(
            "UPDATE email_challenges SET status = 'superseded', terminal_at = $3, updated_at = $3
             WHERE project_id = $1 AND transaction_id = $2 AND status = 'pending'",
            vec![command.project_id.into(), command.transaction_id.into(), command.issued_at.into()],
        )).await.map_err(persistence)?;
        transaction.execute_raw(statement(
            "INSERT INTO email_challenges (id, project_id, application_id, transaction_id, generation, status,
             canonicalization_version, lookup_digest, lookup_digest_key_version, address_ciphertext, address_key_version,
             otp_digest, otp_digest_key_version, otp_attempts, otp_max_attempts, magic_digest, magic_digest_key_version,
             method_policy_revision, method_security_revision, assignment_security_revision, smtp_selection_kind,
             smtp_configuration_id, smtp_generation, smtp_security_eligibility_revision, browser_binding_required,
             issued_at, otp_expires_at, magic_expires_at, expires_at, created_at, updated_at)
             VALUES ($1,$2,$3,$4,$5,'pending',$6,$7,$8,$9,$10,$11,$12,0,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$24,$24)",
            vec![
                command.challenge_id.into(), command.project_id.into(), command.application_id.into(), command.transaction_id.into(),
                command.expected_generation.into(), command.canonicalization_version.into(), command.lookup_digest.value.to_vec().into(),
                command.lookup_digest.key_version.into(), command.address.ciphertext.into(), command.address.key_version.into(),
                command.otp_digest.as_ref().map(|v| v.value.to_vec()).into(), command.otp_digest.as_ref().map(|v| v.key_version).into(),
                row.try_get::<i16>("", "otp_max_attempts").map_err(persistence)?.into(),
                command.magic_digest.as_ref().map(|v| v.value.to_vec()).into(), command.magic_digest.as_ref().map(|v| v.key_version).into(),
                row.try_get::<i64>("", "method_policy_revision").map_err(persistence)?.into(),
                row.try_get::<i64>("", "method_security_revision").map_err(persistence)?.into(),
                row.try_get::<i64>("", "assignment_security_revision").map_err(persistence)?.into(),
                row.try_get::<String>("", "smtp_selection_kind").map_err(persistence)?.into(),
                row.try_get::<Option<Uuid>>("", "smtp_configuration_id").map_err(persistence)?.into(),
                row.try_get::<i32>("", "smtp_generation").map_err(persistence)?.into(),
                row.try_get::<i64>("", "smtp_security_eligibility_revision").map_err(persistence)?.into(),
                (!row.try_get::<bool>("", "transferred_magic_link_enabled").map_err(persistence)?).into(),
                command.issued_at.into(), command.otp_expires_at.into(), command.magic_expires_at.into(), command.expires_at.into(),
            ],
        )).await.map_err(persistence)?;
        transaction.execute_raw(statement(
            "INSERT INTO mail_outbox (id, project_id, transaction_id, challenge_id, challenge_generation, status,
             smtp_selection_kind, smtp_configuration_id, smtp_generation, smtp_security_eligibility_revision,
             message_id, envelope_ciphertext, envelope_key_version, body_ciphertext, body_key_version,
             attempts, max_attempts, next_attempt_at, safe_outcome, useful_until, terminal_at, created_at, updated_at)
             VALUES ($1,$2,$3,$4,$5,CASE WHEN $17 THEN 'cancelled' ELSE 'pending' END,$6,$7,$8,$9,$10,$11,$12,$13,$14,
                     0,5,$15,CASE WHEN $17 THEN 'policy_denied' ELSE NULL END,$16,
                     CASE WHEN $17 THEN $15 ELSE NULL END,$15,$15)",
            vec![command.outbox_id.into(), command.project_id.into(), command.transaction_id.into(), command.challenge_id.into(),
                command.expected_generation.into(), row.try_get::<String>("", "smtp_selection_kind").map_err(persistence)?.into(),
                row.try_get::<Option<Uuid>>("", "smtp_configuration_id").map_err(persistence)?.into(),
                row.try_get::<i32>("", "smtp_generation").map_err(persistence)?.into(),
                row.try_get::<i64>("", "smtp_security_eligibility_revision").map_err(persistence)?.into(),
                command.message_id.into(), command.envelope.ciphertext.into(), command.envelope.key_version.into(),
                command.body.ciphertext.into(), command.body.key_version.into(), command.issued_at.into(), command.expires_at.into(),
                command.suppress_delivery.into()],
        )).await.map_err(persistence)?;
        let updated = transaction.execute_raw(statement(
            "UPDATE login_transactions SET status = 'email_challenge_pending', transaction_revision = transaction_revision + 1, updated_at = $3
             WHERE project_id = $1 AND id = $2 AND transaction_revision = $4",
            vec![command.project_id.into(), command.transaction_id.into(), command.issued_at.into(), revision.into()],
        )).await.map_err(persistence)?;
        if updated.rows_affected() != 1 {
            return Err(ApplicationError::RevisionConflict);
        }
        transaction.commit().await.map_err(persistence)?;
        Ok(())
    }

    async fn establish_magic_transfer_context(
        &self,
        command: EstablishMagicTransferContext,
    ) -> Result<(), ApplicationError> {
        validate_digest(&command.context)?;
        validate_digest(&command.csrf)?;
        let transaction = self.database.begin().await.map_err(persistence)?;
        self.lock_local_runtime_incarnation(&transaction).await?;
        self.assert_email_protection_ready(&transaction).await?;
        let challenge = transaction
            .query_one_raw(statement(
                "SELECT challenge.browser_binding_required,challenge.expires_at AS challenge_expires_at, \
                        login.expires_at AS login_expires_at \
                 FROM email_challenges challenge \
                 JOIN login_transactions login ON login.project_id=challenge.project_id AND login.id=challenge.transaction_id \
                 WHERE challenge.id=$1 AND challenge.status='pending' AND challenge.magic_digest IS NOT NULL \
                   AND challenge.expires_at>$2 AND login.expires_at>$2 \
                   AND login.status='email_challenge_pending' \
                   AND NOT EXISTS (SELECT 1 FROM email_challenges newer \
                     WHERE newer.project_id=challenge.project_id AND newer.transaction_id=challenge.transaction_id \
                       AND newer.generation>challenge.generation) \
                 FOR UPDATE OF challenge",
                vec![command.challenge_id.into(), command.now.into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        transaction
            .execute_raw(statement(
                "UPDATE magic_transfer_contexts SET status='expired' \
                 WHERE challenge_id=$1 AND status='pending' AND expires_at<=$2",
                vec![command.challenge_id.into(), command.now.into()],
            ))
            .await
            .map_err(persistence)?;
        let count = transaction
            .query_one_raw(statement(
                "SELECT COUNT(*)::BIGINT AS count FROM magic_transfer_contexts \
                 WHERE challenge_id=$1 AND status='pending' AND expires_at>$2",
                vec![command.challenge_id.into(), command.now.into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?
            .try_get::<i64>("", "count")
            .map_err(persistence)?;
        if count >= MAX_MAGIC_TRANSFER_CONTEXTS_PER_CHALLENGE {
            return Err(ApplicationError::NotFound);
        }
        let challenge_expires_at: OffsetDateTime = challenge
            .try_get("", "challenge_expires_at")
            .map_err(persistence)?;
        let login_expires_at: OffsetDateTime = challenge
            .try_get("", "login_expires_at")
            .map_err(persistence)?;
        let expires_at = (command.now + time::Duration::minutes(5))
            .min(challenge_expires_at)
            .min(login_expires_at);
        transaction
            .execute_raw(statement(
                "INSERT INTO magic_transfer_contexts \
                 (id,challenge_id,context_digest,context_digest_key_version,csrf_digest, \
                  csrf_digest_key_version,browser_binding_required,status,expires_at,created_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,'pending',$8,$9)",
                vec![
                    command.id.into(),
                    command.challenge_id.into(),
                    command.context.value.to_vec().into(),
                    command.context.key_version.into(),
                    command.csrf.value.to_vec().into(),
                    command.csrf.key_version.into(),
                    challenge
                        .try_get::<bool>("", "browser_binding_required")
                        .map_err(persistence)?
                        .into(),
                    expires_at.into(),
                    command.now.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        transaction.commit().await.map_err(persistence)
    }

    async fn resolve_magic_transfer_context(
        &self,
        command: ResolveMagicTransferContext,
    ) -> Result<ResolvedMagicTransferContext, ApplicationError> {
        validate_digest(&command.context)?;
        validate_digest(&command.csrf)?;
        let transaction = self.database.begin().await.map_err(persistence)?;
        self.lock_local_runtime_incarnation(&transaction).await?;
        self.assert_email_protection_ready(&transaction).await?;
        let row = transaction.query_one_raw(statement(
            "SELECT challenge.project_id, challenge.transaction_id, project.public_id,
                    application.application_type,transfer.browser_binding_required
             FROM magic_transfer_contexts transfer
             JOIN email_challenges challenge ON challenge.id=transfer.challenge_id
             JOIN login_transactions login ON login.project_id=challenge.project_id AND login.id=challenge.transaction_id
             JOIN projects project ON project.id=challenge.project_id
             JOIN applications application ON application.project_id=login.project_id
               AND application.id=login.application_id
             WHERE transfer.challenge_id=$1 AND transfer.context_digest=$2
               AND transfer.context_digest_key_version=$3 AND transfer.csrf_digest=$4
               AND transfer.csrf_digest_key_version=$5 AND transfer.status='pending' AND transfer.expires_at > $6
               AND challenge.status='pending' AND challenge.expires_at > $6
               AND login.status='email_challenge_pending' AND login.expires_at > $6
               AND challenge.transaction_id=$7 AND project.public_id=$8 AND project.status='active'",
            vec![command.challenge_id.into(), command.context.value.to_vec().into(), command.context.key_version.into(),
                command.csrf.value.to_vec().into(), command.csrf.key_version.into(), command.now.into(),
                command.transaction_id.into(), command.project_public_id.clone().into()],
        )).await.map_err(persistence)?.ok_or(ApplicationError::NotFound)?;
        let result = ResolvedMagicTransferContext {
            project_id: row.try_get("", "project_id").map_err(persistence)?,
            project_public_id: row.try_get("", "public_id").map_err(persistence)?,
            transaction_id: row.try_get("", "transaction_id").map_err(persistence)?,
            application_type: match row
                .try_get::<String>("", "application_type")
                .map_err(persistence)?
                .as_str()
            {
                "web" => crate::domain::ApplicationType::Web,
                "native" => crate::domain::ApplicationType::Native,
                _ => return Err(ApplicationError::Integrity),
            },
            browser_binding_required: row
                .try_get("", "browser_binding_required")
                .map_err(persistence)?,
        };
        transaction.commit().await.map_err(persistence)?;
        Ok(result)
    }

    async fn email_proof_key_version(
        &self,
        project_id: Uuid,
        transaction_id: Uuid,
        challenge_id: Uuid,
        proof_kind: EmailProofKind,
    ) -> Result<Option<i32>, ApplicationError> {
        let column = match proof_kind {
            EmailProofKind::Otp => "otp_digest_key_version",
            EmailProofKind::MagicLink => "magic_digest_key_version",
        };
        let sql = format!(
            "SELECT {column} AS key_version FROM email_challenges
             WHERE project_id=$1 AND transaction_id=$2 AND id=$3"
        );
        let transaction = self.database.begin().await.map_err(persistence)?;
        self.lock_local_runtime_incarnation(&transaction).await?;
        self.assert_email_protection_ready(&transaction).await?;
        let key_version = transaction
            .query_one_raw(statement(
                &sql,
                vec![
                    project_id.into(),
                    transaction_id.into(),
                    challenge_id.into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?
            .try_get("", "key_version")
            .map_err(persistence)?;
        transaction.commit().await.map_err(persistence)?;
        Ok(key_version)
    }

    async fn verify_email_proof(
        &self,
        command: VerifyEmailProof,
    ) -> Result<EmailProofDecision, ApplicationError> {
        validate_digest(&command.proof_digest)?;
        validate_digest(&command.csrf)?;
        if let Some(context) = &command.transfer_context {
            validate_digest(context)?;
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        self.lock_local_runtime_incarnation(&transaction).await?;
        self.assert_email_protection_ready(&transaction).await?;
        // Canonical proof order is login -> Project/Application/policy/assignment -> challenge.
        // Never rely on PostgreSQL's join lock acquisition order for these contended rows.
        let login_model = login_transaction::Entity::find_by_id(command.transaction_id)
            .filter(login_transaction::Column::ProjectId.eq(command.project_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        lock_login_application_owners(&transaction, &login_model).await?;
        lock_email_method_owners(
            &transaction,
            login_model.project_id,
            login_model.application_id,
        )
        .await?;
        let row = transaction
            .query_one_raw(statement(
                "SELECT challenge.*, login.status AS login_status, login.transaction_revision,
             login.expires_at AS login_expires_at, login.project_metadata_revision,
             login.project_security_revision,login.application_security_revision,
             login.browser_binding_digest,login.browser_binding_digest_key_version,
             login.csrf_digest,login.csrf_digest_key_version
             FROM email_challenges challenge JOIN login_transactions login
               ON login.project_id = challenge.project_id AND login.id = challenge.transaction_id
             WHERE challenge.project_id = $1 AND challenge.transaction_id = $2 AND challenge.id = $3
             FOR UPDATE OF challenge",
                vec![
                    command.project_id.into(),
                    command.transaction_id.into(),
                    command.challenge_id.into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let revision: i64 = row
            .try_get("", "transaction_revision")
            .map_err(persistence)?;
        if revision != command.expected_transaction_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        validate_email_confirmation_authority(&transaction, &row, &command).await?;
        let status: String = row.try_get("", "status").map_err(persistence)?;
        let login_status: String = row.try_get("", "login_status").map_err(persistence)?;
        let expires_at: OffsetDateTime = row.try_get("", "expires_at").map_err(persistence)?;
        let login_expires_at: OffsetDateTime =
            row.try_get("", "login_expires_at").map_err(persistence)?;
        let newest: i16 = transaction.query_one_raw(statement(
            "SELECT MAX(generation)::SMALLINT AS generation FROM email_challenges WHERE project_id = $1 AND transaction_id = $2",
            vec![command.project_id.into(), command.transaction_id.into()],
        )).await.map_err(persistence)?.ok_or(ApplicationError::Integrity)?.try_get("", "generation").map_err(persistence)?;
        let generation: i16 = row.try_get("", "generation").map_err(persistence)?;
        if status != "pending"
            || login_status != "email_challenge_pending"
            || generation != newest
            || expires_at <= command.now
            || login_expires_at <= command.now
        {
            transaction.commit().await.map_err(persistence)?;
            return Ok(EmailProofDecision::Invalid);
        }
        revalidate_policy_and_smtp(
            &transaction,
            &row,
            command.project_id,
            command.now,
            &self.runtime_process_id,
            self.runtime_incarnation,
            &self.required_runtime_process_ids,
        )
        .await?;
        let (digest_column, version_column, expiry_column) = match command.proof_kind {
            EmailProofKind::Otp => ("otp_digest", "otp_digest_key_version", "otp_expires_at"),
            EmailProofKind::MagicLink => (
                "magic_digest",
                "magic_digest_key_version",
                "magic_expires_at",
            ),
        };
        let proof_expires_at: Option<OffsetDateTime> =
            row.try_get("", expiry_column).map_err(persistence)?;
        if proof_expires_at.is_none_or(|expires_at| expires_at <= command.now) {
            transaction.commit().await.map_err(persistence)?;
            return Ok(EmailProofDecision::Invalid);
        }
        let stored: Option<Vec<u8>> = row.try_get("", digest_column).map_err(persistence)?;
        let stored_version: Option<i32> = row.try_get("", version_column).map_err(persistence)?;
        let valid = stored_version == Some(command.proof_digest.key_version)
            && stored.as_deref().is_some_and(|value| {
                bool::from(value.ct_eq(command.proof_digest.value.as_slice()))
            });
        if !valid {
            if command.proof_kind == EmailProofKind::Otp {
                transaction.execute_raw(statement(
                    "UPDATE email_challenges SET otp_attempts = otp_attempts + 1,
                     status = CASE WHEN otp_attempts + 1 >= otp_max_attempts THEN 'exhausted' ELSE status END,
                     terminal_at = CASE WHEN otp_attempts + 1 >= otp_max_attempts THEN $2 ELSE terminal_at END, updated_at = $2
                     WHERE id = $1 AND status = 'pending'",
                    vec![command.challenge_id.into(), command.now.into()],
                )).await.map_err(persistence)?;
            }
            transaction.commit().await.map_err(persistence)?;
            return Ok(EmailProofDecision::Invalid);
        }
        // This read proves the candidate without consuming it. The service decrypts and
        // re-protects the address under the distinct durable identity purpose, then the
        // completion command repeats every guard and conditionally consumes the same parent
        // in the identity/session/handoff transaction.
        transaction.commit().await.map_err(persistence)?;
        Ok(EmailProofDecision::Accepted(VerifiedEmailChallenge {
            project_id: command.project_id,
            application_id: row.try_get("", "application_id").map_err(persistence)?,
            transaction_id: command.transaction_id,
            challenge_id: command.challenge_id,
            address: ProtectedValue {
                ciphertext: row.try_get("", "address_ciphertext").map_err(persistence)?,
                key_version: row
                    .try_get("", "address_key_version")
                    .map_err(persistence)?,
            },
            canonicalization_version: row
                .try_get("", "canonicalization_version")
                .map_err(persistence)?,
            lookup_digest: VersionedDigest {
                value: row
                    .try_get::<Vec<u8>>("", "lookup_digest")
                    .map_err(persistence)?
                    .try_into()
                    .map_err(|_| ApplicationError::Integrity)?,
                key_version: row
                    .try_get("", "lookup_digest_key_version")
                    .map_err(persistence)?,
            },
        }))
    }

    async fn complete_email_proof(
        &self,
        command: CompleteEmailProof,
    ) -> Result<IssuedHandoff, ApplicationError> {
        validate_digest(&command.verification.proof_digest)?;
        validate_digest(&command.verification.csrf)?;
        if let Some(context) = &command.verification.transfer_context {
            validate_digest(context)?;
        }
        validate_digest(&command.browser_credential)?;
        validate_digest(&command.handoff_ticket)?;
        validate_digest(&command.verified_challenge_lookup)?;
        if command.durable_address.key_version <= 0 || command.durable_address.ciphertext.len() < 41
        {
            return Err(ApplicationError::InvalidInput);
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        self.lock_local_runtime_incarnation(&transaction).await?;
        self.assert_email_protection_ready(&transaction).await?;
        lock_project_identity_graph(&transaction, command.verification.project_id).await?;
        // Preserve the same canonical owner order as challenge creation and mail claims.
        let login_model =
            login_transaction::Entity::find_by_id(command.verification.transaction_id)
                .filter(login_transaction::Column::ProjectId.eq(command.verification.project_id))
                .lock_exclusive()
                .one(&transaction)
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::NotFound)?;
        lock_login_application_owners(&transaction, &login_model).await?;
        let authority_row = transaction
            .query_one_raw(statement(
                "SELECT revision,write_version,accepted_versions
                 FROM email_identity_alias_authority WHERE singleton=TRUE FOR SHARE",
                vec![],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        let alias_authority = email_alias_authority_from_row(&authority_row)?;
        if alias_authority.revision != command.alias_authority_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        let row = transaction.query_one_raw(statement(
            "SELECT challenge.*, login.status AS login_status, login.transaction_revision, login.expires_at AS login_expires_at,
             login.redirect_uri, login.application_pkce_challenge, login.application_state_ciphertext, login.application_state_key_version,
             login.project_metadata_revision, login.project_security_revision,
             login.application_security_revision, login.claims_revision, login.session_revision,
             login.browser_binding_digest, login.browser_binding_digest_key_version, login.csrf_digest, login.csrf_digest_key_version
             FROM email_challenges challenge JOIN login_transactions login ON login.project_id = challenge.project_id AND login.id = challenge.transaction_id
             WHERE challenge.project_id = $1 AND challenge.transaction_id = $2 AND challenge.id = $3 FOR UPDATE OF challenge",
            vec![command.verification.project_id.into(), command.verification.transaction_id.into(), command.verification.challenge_id.into()],
        )).await.map_err(persistence)?.ok_or(ApplicationError::NotFound)?;
        let revision: i64 = row
            .try_get("", "transaction_revision")
            .map_err(persistence)?;
        if revision != command.verification.expected_transaction_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        validate_email_confirmation_authority(&transaction, &row, &command.verification).await?;
        let status: String = row.try_get("", "status").map_err(persistence)?;
        let login_status: String = row.try_get("", "login_status").map_err(persistence)?;
        let expires_at: OffsetDateTime = row.try_get("", "expires_at").map_err(persistence)?;
        let login_expires_at: OffsetDateTime =
            row.try_get("", "login_expires_at").map_err(persistence)?;
        let generation: i16 = row.try_get("", "generation").map_err(persistence)?;
        let newest: i16 = transaction.query_one_raw(statement(
            "SELECT MAX(generation)::SMALLINT AS generation FROM email_challenges WHERE project_id = $1 AND transaction_id = $2",
            vec![command.verification.project_id.into(), command.verification.transaction_id.into()],
        )).await.map_err(persistence)?.ok_or(ApplicationError::Integrity)?.try_get("", "generation").map_err(persistence)?;
        if status != "pending"
            || login_status != "email_challenge_pending"
            || generation != newest
            || expires_at <= command.verification.now
            || login_expires_at <= command.verification.now
        {
            return Err(ApplicationError::InvalidTransition);
        }
        revalidate_policy_and_smtp(
            &transaction,
            &row,
            command.verification.project_id,
            command.verification.now,
            &self.runtime_process_id,
            self.runtime_incarnation,
            &self.required_runtime_process_ids,
        )
        .await?;
        let (digest_column, version_column, expiry_column) = match command.verification.proof_kind {
            EmailProofKind::Otp => ("otp_digest", "otp_digest_key_version", "otp_expires_at"),
            EmailProofKind::MagicLink => (
                "magic_digest",
                "magic_digest_key_version",
                "magic_expires_at",
            ),
        };
        let proof_expires_at: Option<OffsetDateTime> =
            row.try_get("", expiry_column).map_err(persistence)?;
        if proof_expires_at.is_none_or(|expires_at| expires_at <= command.verification.now) {
            return Err(ApplicationError::InvalidTransition);
        }
        let stored: Option<Vec<u8>> = row.try_get("", digest_column).map_err(persistence)?;
        let stored_version: Option<i32> = row.try_get("", version_column).map_err(persistence)?;
        if stored_version != Some(command.verification.proof_digest.key_version)
            || !stored.as_deref().is_some_and(|value| {
                bool::from(value.ct_eq(command.verification.proof_digest.value.as_slice()))
            })
        {
            return Err(ApplicationError::InvalidTransition);
        }

        if command.lookup_aliases.is_empty() || command.lookup_aliases.len() > 16 {
            return Err(ApplicationError::InvalidInput);
        }
        validate_digest(&command.active_alias)?;
        if !command.lookup_aliases.contains(&command.active_alias) {
            return Err(ApplicationError::InvalidInput);
        }
        let mut versions = std::collections::BTreeSet::new();
        for alias in &command.lookup_aliases {
            validate_digest(alias)?;
            if !versions.insert(alias.key_version) {
                return Err(ApplicationError::InvalidInput);
            }
        }
        let accepted_versions = alias_authority
            .accepted_versions
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if versions != accepted_versions
            || command.active_alias.key_version != alias_authority.write_version
        {
            return Err(ApplicationError::RevisionConflict);
        }
        let stored_lookup: Vec<u8> = row.try_get("", "lookup_digest").map_err(persistence)?;
        let stored_lookup_version: i32 = row
            .try_get("", "lookup_digest_key_version")
            .map_err(persistence)?;
        if command.verified_challenge_lookup.key_version != stored_lookup_version
            || !bool::from(
                stored_lookup
                    .as_slice()
                    .ct_eq(command.verified_challenge_lookup.value.as_slice()),
            )
        {
            return Err(ApplicationError::Integrity);
        }
        // Serialize the whole Project email namespace. This deliberately excludes digest-key
        // version so an old-key and new-key completion cannot create sibling identities.
        let namespace = format!("email:{}", command.verification.project_id);
        transaction
            .execute_raw(statement(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                vec![namespace.into()],
            ))
            .await
            .map_err(persistence)?;
        let canonicalization_version: i32 = row
            .try_get("", "canonicalization_version")
            .map_err(persistence)?;
        let mut existing = None;
        let mut existing_identity_id = None;
        for alias in &command.lookup_aliases {
            let found = transaction.query_one_raw(statement(
                "SELECT identity.id AS identity_id, identity.user_id, identity.status AS identity_status,
                 project_user.public_id AS user_public_id, project_user.status AS user_status, project_user.security_revision
                 FROM email_identity_aliases alias JOIN email_identities identity ON identity.project_id = alias.project_id AND identity.id = alias.identity_id
                 JOIN project_users project_user ON project_user.project_id = identity.project_id AND project_user.id = identity.user_id
                 WHERE alias.project_id = $1 AND alias.canonicalization_version = $2
                   AND alias.digest_key_version = $3 AND alias.lookup_digest = $4
                 FOR UPDATE OF identity, project_user",
                vec![command.verification.project_id.into(), canonicalization_version.into(),
                    alias.key_version.into(), alias.value.to_vec().into()],
            )).await.map_err(persistence)?;
            if let Some(found) = found {
                let identity_id: Uuid = found.try_get("", "identity_id").map_err(persistence)?;
                if existing_identity_id.is_some_and(|current| current != identity_id) {
                    return Err(ApplicationError::Integrity);
                }
                existing_identity_id = Some(identity_id);
                existing = Some(found);
            }
        }
        let (user_id, user_public_id, user_security_revision) = if let Some(existing) = existing {
            if existing
                .try_get::<String>("", "identity_status")
                .map_err(persistence)?
                != "active"
                || existing
                    .try_get::<String>("", "user_status")
                    .map_err(persistence)?
                    != "active"
            {
                return Err(ApplicationError::Disabled);
            }
            let identity_id: Uuid = existing.try_get("", "identity_id").map_err(persistence)?;
            for alias in std::iter::once(&command.active_alias) {
                transaction.execute_raw(statement(
                    "INSERT INTO email_identity_aliases
                     (project_id, identity_id, canonicalization_version, digest_key_version, lookup_digest, created_at)
                     VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING",
                    vec![command.verification.project_id.into(), identity_id.into(), canonicalization_version.into(),
                        alias.key_version.into(), alias.value.to_vec().into(), command.verification.now.into()],
                )).await.map_err(persistence)?;
                let owner: Uuid = transaction.query_one_raw(statement(
                    "SELECT identity_id FROM email_identity_aliases WHERE project_id=$1
                     AND canonicalization_version=$2 AND digest_key_version=$3 AND lookup_digest=$4",
                    vec![command.verification.project_id.into(), canonicalization_version.into(),
                        alias.key_version.into(), alias.value.to_vec().into()],
                )).await.map_err(persistence)?.ok_or(ApplicationError::Integrity)?
                    .try_get("", "identity_id").map_err(persistence)?;
                if owner != identity_id {
                    return Err(ApplicationError::Integrity);
                }
            }
            (
                existing.try_get("", "user_id").map_err(persistence)?,
                existing
                    .try_get("", "user_public_id")
                    .map_err(persistence)?,
                existing
                    .try_get("", "security_revision")
                    .map_err(persistence)?,
            )
        } else {
            let signup_enabled: bool = transaction.query_one_raw(statement(
                "SELECT signup_enabled FROM project_email_policies WHERE project_id = $1 FOR SHARE",
                vec![command.verification.project_id.into()],
            )).await.map_err(persistence)?.ok_or(ApplicationError::Integrity)?.try_get("", "signup_enabled").map_err(persistence)?;
            if !signup_enabled {
                return Err(ApplicationError::Disabled);
            }
            transaction.execute_raw(statement(
                "INSERT INTO project_users (id, project_id, public_id, status, user_revision, security_revision, primary_profile_identity_id,
                 primary_source_kind, base_profile_digest, local_display_name_set, local_picture_url_set, local_locale_set, created_at, updated_at)
                 VALUES ($1,$2,$3,'active',1,1,NULL,'email',$4,FALSE,FALSE,FALSE,$5,$5)",
                vec![command.new_user_id.into(), command.verification.project_id.into(), command.new_user_public_id.clone().into(), super::projection::base_profile_digest(None, None, None, None)?.into(), command.verification.now.into()],
            )).await.map_err(persistence)?;
            transaction.execute_raw(statement(
                "INSERT INTO email_identities (id, project_id, user_id, status, identity_revision, canonicalization_version,
                 address_ciphertext, address_key_version, verified_at, created_at, updated_at)
                 VALUES ($1,$2,$3,'active',1,$4,$5,$6,$7,$7,$7)",
                vec![command.new_identity_id.into(), command.verification.project_id.into(), command.new_user_id.into(),
                    row.try_get::<i32>("", "canonicalization_version").map_err(persistence)?.into(), command.durable_address.ciphertext.clone().into(),
                    command.durable_address.key_version.into(), command.verification.now.into()],
            )).await.map_err(persistence)?;
            for alias in std::iter::once(&command.active_alias) {
                transaction.execute_raw(statement(
                    "INSERT INTO email_identity_aliases
                     (project_id, identity_id, canonicalization_version, digest_key_version, lookup_digest, created_at)
                     VALUES ($1,$2,$3,$4,$5,$6)",
                    vec![command.verification.project_id.into(), command.new_identity_id.into(), canonicalization_version.into(),
                        alias.key_version.into(), alias.value.to_vec().into(), command.verification.now.into()],
                )).await.map_err(persistence)?;
            }
            transaction
                .execute_raw(statement(
                    "UPDATE project_users SET primary_email_identity_id = $2 WHERE id = $1",
                    vec![command.new_user_id.into(), command.new_identity_id.into()],
                ))
                .await
                .map_err(persistence)?;
            (
                command.new_user_id,
                command.new_user_public_id.clone(),
                1_i64,
            )
        };
        let browser_session = rotate_or_create_browser_session(
            &transaction,
            BrowserSessionCompletion {
                project_id: command.verification.project_id,
                user_id,
                user_security_revision,
                browser_session_id: command.browser_session_id,
                existing_browser_credential: command.existing_browser_credential.as_ref(),
                browser_credential: &command.browser_credential,
                project_security_revision: login_model.project_security_revision,
                policy_session_revision: login_model.session_revision,
                now: command.verification.now,
            },
        )
        .await?;
        let handoff_expires_at = std::cmp::min(
            command.verification.now + time::Duration::seconds(60),
            login_expires_at,
        );
        insert_handoff(
            &transaction,
            command.handoff_id,
            &command.handoff_ticket,
            &login_model,
            user_id,
            browser_session.id,
            "email",
            command.verification.now,
            command.verification.now,
            handoff_expires_at,
            user_security_revision,
        )
        .await?;
        if let Some(context) = &command.verification.transfer_context {
            let transfer_consumed = transaction
                .execute_raw(statement(
                    "UPDATE magic_transfer_contexts SET status='consumed', consumed_at=$5
                 WHERE challenge_id=$1 AND context_digest=$2 AND context_digest_key_version=$3
                   AND csrf_digest=$4 AND status='pending' AND expires_at > $5",
                    vec![
                        command.verification.challenge_id.into(),
                        context.value.to_vec().into(),
                        context.key_version.into(),
                        command.verification.csrf.value.to_vec().into(),
                        command.verification.now.into(),
                    ],
                ))
                .await
                .map_err(persistence)?;
            if transfer_consumed.rows_affected() != 1 {
                return Err(ApplicationError::InvalidTransition);
            }
        }
        let consumed = transaction.execute_raw(statement(
            "UPDATE email_challenges SET status='consumed', consumed_at=$2, terminal_at=$2, updated_at=$2 WHERE id=$1 AND status='pending'",
            vec![command.verification.challenge_id.into(), command.verification.now.into()],
        )).await.map_err(persistence)?;
        if consumed.rows_affected() != 1 {
            return Err(ApplicationError::InvalidTransition);
        }
        let login_updated = transaction.execute_raw(statement(
            "UPDATE login_transactions SET status='handoff_issued', transaction_revision=transaction_revision+1, user_id=$3,
             authenticated_at=$4, updated_at=$4 WHERE project_id=$1 AND id=$2 AND status='email_challenge_pending' AND transaction_revision=$5",
            vec![command.verification.project_id.into(), command.verification.transaction_id.into(), user_id.into(), command.verification.now.into(), revision.into()],
        )).await.map_err(persistence)?;
        if login_updated.rows_affected() != 1 {
            return Err(ApplicationError::RevisionConflict);
        }
        append_runtime_audit(
            &transaction,
            command.verification.project_id,
            "system",
            "auth.email.completed",
            "project_user",
            Some(user_id),
            command.verification.transaction_id,
        )
        .await?;
        let result = IssuedHandoff {
            project_id: command.verification.project_id,
            application_id: row.try_get("", "application_id").map_err(persistence)?,
            user_id,
            user_public_id,
            browser_session_id: browser_session.id,
            handoff_id: command.handoff_id,
            redirect_uri: row.try_get("", "redirect_uri").map_err(persistence)?,
            application_state: ProtectedValue {
                ciphertext: row
                    .try_get("", "application_state_ciphertext")
                    .map_err(persistence)?,
                key_version: row
                    .try_get("", "application_state_key_version")
                    .map_err(persistence)?,
            },
            expires_at: handoff_expires_at,
        };
        transaction.commit().await.map_err(persistence)?;
        Ok(result)
    }
}

#[async_trait]
#[allow(
    clippy::too_many_lines,
    reason = "deployment SMTP reconciliation keeps reference reservation and generation state atomic"
)]
impl crate::application::DeploymentSmtpRegistry for PostgresPasswordlessEmailRepository {
    async fn reconcile_deployment_smtp(
        &self,
        generation: &crate::application::DeploymentSmtpGeneration,
        now: OffsetDateTime,
    ) -> Result<(), ApplicationError> {
        validate_deployment_smtp_generation(generation)?;
        let transaction = self.database.begin().await.map_err(persistence)?;
        self.lock_local_runtime_incarnation(&transaction).await?;
        transaction
            .execute_raw(statement(
                "SELECT pg_advisory_xact_lock(hashtextextended('owlauth:deployment-smtp', 0))",
                vec![],
            ))
            .await
            .map_err(persistence)?;
        if matches!(
            generation.desired_status,
            crate::application::DeploymentSmtpDesiredStatus::Reconciled
                | crate::application::DeploymentSmtpDesiredStatus::Active
        ) {
            lock_smtp_credential_reference(&transaction, &generation.credential_ref).await?;
            transaction
                .execute_raw(statement(
                    "INSERT INTO smtp_credential_reference_reservations
                 (credential_ref,state,created_at,updated_at)
                 VALUES ($1,'live',$2,$2) ON CONFLICT (credential_ref) DO NOTHING",
                    vec![generation.credential_ref.clone().into(), now.into()],
                ))
                .await
                .map_err(persistence)?;
            let reference = transaction
                .query_one_raw(statement(
                    "SELECT state FROM smtp_credential_reference_reservations
                 WHERE credential_ref=$1 FOR UPDATE",
                    vec![generation.credential_ref.clone().into()],
                ))
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::Integrity)?;
            if reference
                .try_get::<String>("", "state")
                .map_err(persistence)?
                != "live"
            {
                return Err(ApplicationError::InvalidTransition);
            }
        }
        let tls_mode = match generation.tls_mode {
            crate::application::SmtpTlsMode::ImplicitTls => "implicit_tls",
            crate::application::SmtpTlsMode::StartTlsRequired => "starttls_required",
            crate::application::SmtpTlsMode::DevelopmentLoopbackPlaintext => {
                return Err(ApplicationError::InvalidInput);
            }
        };
        let existing = transaction
            .query_one_raw(statement(
                "SELECT * FROM deployment_smtp_generations WHERE generation=$1 FOR UPDATE",
                vec![generation.generation.into()],
            ))
            .await
            .map_err(persistence)?;
        if let Some(existing) = existing {
            if deployment_smtp_is_unchanged(&existing, generation, tls_mode)? {
                return transaction.commit().await.map_err(persistence);
            }
        } else {
            transaction.execute_raw(statement(
                "INSERT INTO deployment_smtp_generations
                 (generation,status,revision,security_eligibility_revision,host,port,tls_mode,sender_address,
                  credential_ref,safe_fingerprint,explicitly_allowed_private_ips,created_at,updated_at)
                 VALUES ($1,'reconciled',1,1,$2,$3,$4,$5,$6,$7,$8,$9,$9)",
                vec![generation.generation.into(), generation.host.clone().into(), i32::from(generation.port).into(),
                    tls_mode.into(), generation.sender_address.clone().into(), generation.credential_ref.clone().into(),
                    generation.safe_fingerprint.to_vec().into(), ip_allowlist_json(&generation.explicitly_allowed_private_ips).into(), now.into()],
            )).await.map_err(persistence)?;
        }
        let action = match generation.desired_status {
            crate::application::DeploymentSmtpDesiredStatus::Reconciled => {
                "email.deployment_smtp.reconciled"
            }
            crate::application::DeploymentSmtpDesiredStatus::Active => {
                transaction.execute_raw(statement(
                    "UPDATE deployment_smtp_generations SET status='retained', retained_until=$2,
                     revision=revision+1, updated_at=$3 WHERE generation<>$1 AND status='active'",
                    vec![generation.generation.into(), (now + time::Duration::minutes(10)).into(), now.into()],
                )).await.map_err(persistence)?;
                let updated = transaction.execute_raw(statement(
                    "UPDATE deployment_smtp_generations SET status='active', retained_until=NULL,
                     revision=CASE WHEN status='active' THEN revision ELSE revision+1 END, updated_at=$2
                     WHERE generation=$1 AND status IN ('reconciled','retained','active')",
                    vec![generation.generation.into(), now.into()],
                )).await.map_err(persistence)?;
                if updated.rows_affected() != 1 {
                    return Err(ApplicationError::InvalidTransition);
                }
                "email.deployment_smtp.activated"
            }
            crate::application::DeploymentSmtpDesiredStatus::Disabled
            | crate::application::DeploymentSmtpDesiredStatus::Compromised => {
                let status = if generation.desired_status
                    == crate::application::DeploymentSmtpDesiredStatus::Compromised
                {
                    "compromised"
                } else {
                    "disabled"
                };
                let updated = transaction.execute_raw(statement(
                    "UPDATE deployment_smtp_generations SET status=$2, retained_until=NULL,
                     revision=CASE WHEN status=$2 THEN revision ELSE revision+1 END,
                     security_eligibility_revision=CASE WHEN status=$2 THEN security_eligibility_revision ELSE security_eligibility_revision+1 END,
                     updated_at=$3 WHERE generation=$1 AND status<>'retired'",
                    vec![generation.generation.into(), status.into(), now.into()],
                )).await.map_err(persistence)?;
                if updated.rows_affected() != 1 {
                    return Err(ApplicationError::InvalidTransition);
                }
                if status == "compromised" {
                    "email.deployment_smtp.compromised"
                } else {
                    "email.deployment_smtp.disabled"
                }
            }
        };
        insert_audit(
            &transaction,
            None,
            action,
            "deployment_smtp_generation",
            None,
            Uuid::nil(),
        )
        .await?;
        transaction.commit().await.map_err(persistence)
    }

    async fn assert_no_active_deployment_smtp(&self) -> Result<(), ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        self.lock_local_runtime_incarnation(&transaction).await?;
        let active = transaction
            .query_one_raw(statement(
                "SELECT 1 FROM deployment_smtp_generations WHERE status='active' LIMIT 1",
                vec![],
            ))
            .await
            .map_err(persistence)?;
        if active.is_some() {
            return Err(ApplicationError::Integrity);
        }
        transaction.commit().await.map_err(persistence)
    }
}

#[async_trait]
#[allow(
    clippy::too_many_lines,
    reason = "claim and terminal transitions remain together to expose the durable mail state machine"
)]
impl crate::application::MailOutboxRepository for PostgresPasswordlessEmailRepository {
    async fn maintain_short_term_data(
        &self,
        now: OffsetDateTime,
        row_budget: u32,
    ) -> Result<u32, ApplicationError> {
        if row_budget == 0 || row_budget > crate::application::MAX_MAINTENANCE_ROWS_PER_TICK {
            return Err(ApplicationError::InvalidInput);
        }
        let cutoff = now - crate::application::SHORT_TERM_DATA_RETENTION;
        let started = std::time::Instant::now();
        let mut failed = false;

        // Mutation-owned mail is one typed aggregate. Terminalize it first under its intent lock;
        // generic child-row cleanup below deliberately excludes this owner kind so no maintenance
        // transaction can violate the deferred challenge/slot/intent owner constraints.
        let transaction = self.database.begin().await.map_err(persistence)?;
        self.lock_local_runtime_incarnation(&transaction).await?;
        let mutation_rows =
            terminalize_due_identity_mutations(&transaction, i64::from(row_budget)).await?;
        transaction.commit().await.map_err(persistence)?;
        let mut affected = u32::try_from(mutation_rows).map_err(|_| ApplicationError::Integrity)?;

        for sql in [
            "WITH bounded AS (
               SELECT id FROM mail_outbox
               WHERE status IN ('pending','retry','ambiguous','leased') AND attempts >= max_attempts
                 AND NOT EXISTS (SELECT 1 FROM email_challenges challenge
                   WHERE challenge.project_id=mail_outbox.project_id
                     AND challenge.id=mail_outbox.challenge_id
                     AND challenge.owner_kind='identity_mutation')
                 AND (status<>'leased' OR lease_expires_at<=clock_timestamp())
                 AND $2 <= $1 ORDER BY id LIMIT $3 FOR UPDATE SKIP LOCKED)
             UPDATE mail_outbox outbox SET status='permanent_failure',
               safe_outcome=COALESCE(safe_outcome,'transient'),terminal_at=$1,
               lease_owner=NULL,lease_expires_at=NULL,updated_at=$1
             FROM bounded WHERE outbox.id=bounded.id
               AND (outbox.status<>'leased' OR outbox.lease_expires_at<=clock_timestamp())",
            "WITH bounded AS (
               SELECT id FROM mail_outbox
               WHERE status IN ('pending','retry','ambiguous','leased') AND useful_until <= $1
                 AND NOT EXISTS (SELECT 1 FROM email_challenges challenge
                   WHERE challenge.project_id=mail_outbox.project_id
                     AND challenge.id=mail_outbox.challenge_id
                     AND challenge.owner_kind='identity_mutation')
                 AND (status<>'leased' OR lease_expires_at<=clock_timestamp())
                 AND $2 <= $1 ORDER BY id LIMIT $3 FOR UPDATE SKIP LOCKED)
             UPDATE mail_outbox outbox SET status='expired',safe_outcome='expired',terminal_at=$1,
               lease_owner=NULL,lease_expires_at=NULL,updated_at=$1
             FROM bounded WHERE outbox.id=bounded.id
               AND (outbox.status<>'leased' OR outbox.lease_expires_at<=clock_timestamp())",
            "WITH bounded AS (
               SELECT id FROM email_challenges
               WHERE owner_kind='login' AND status='pending' AND expires_at <= $1
                 AND $2 <= $1 ORDER BY id LIMIT $3 FOR UPDATE SKIP LOCKED)
             UPDATE email_challenges challenge SET status='expired',terminal_at=$1,updated_at=$1
             FROM bounded WHERE challenge.id=bounded.id",
            "WITH bounded AS (
               SELECT id FROM email_challenges
               WHERE address_ciphertext IS NOT NULL
                 AND ((terminal_at IS NOT NULL AND terminal_at <= $2) OR expires_at <= $2)
                 AND $2 <= $1 ORDER BY id LIMIT $3 FOR UPDATE SKIP LOCKED)
             UPDATE email_challenges challenge SET address_ciphertext=NULL,address_key_version=NULL,
               redacted_at=$1,updated_at=$1 FROM bounded WHERE challenge.id=bounded.id",
            "WITH bounded AS (
               SELECT id FROM mail_outbox WHERE envelope_ciphertext IS NOT NULL
                 AND terminal_at IS NOT NULL AND terminal_at <= $2 AND $2 <= $1
               ORDER BY id LIMIT $3 FOR UPDATE SKIP LOCKED)
             UPDATE mail_outbox outbox SET envelope_ciphertext=NULL,envelope_key_version=NULL,
               body_ciphertext=NULL,body_key_version=NULL,redacted_at=$1,updated_at=$1
             FROM bounded WHERE outbox.id=bounded.id",
            "WITH bounded AS (
               SELECT transfer.id FROM magic_transfer_contexts transfer
               JOIN email_challenges challenge ON challenge.id=transfer.challenge_id
               WHERE $2 <= $1 AND (transfer.expires_at <= $2
                 OR (transfer.consumed_at IS NOT NULL AND transfer.consumed_at <= $2)
                 OR (challenge.terminal_at IS NOT NULL AND challenge.terminal_at <= $2))
               ORDER BY transfer.id LIMIT $3 FOR UPDATE OF transfer SKIP LOCKED)
             DELETE FROM magic_transfer_contexts transfer USING bounded WHERE transfer.id=bounded.id",
        ] {
            if affected >= row_budget || started.elapsed() >= std::time::Duration::from_millis(200) {
                break;
            }
            let remaining = row_budget - affected;
            // Each cleanup class has its own transaction. A timeout or lock conflict therefore
            // cannot roll back successful sibling cleanup, and the worker can still claim mail.
            let Ok(transaction) = self.database.begin().await else {
                failed = true;
                continue;
            };
            match self.lock_local_runtime_incarnation(&transaction).await {
                Ok(()) => {}
                Err(ApplicationError::Disabled) => return Err(ApplicationError::Disabled),
                Err(_) => {
                    failed = true;
                    continue;
                }
            }
            if transaction
                .execute_raw(statement("SET LOCAL statement_timeout = '30ms'", vec![]))
                .await
                .is_err()
            {
                failed = true;
                continue;
            }
            let result = transaction
                .execute_raw(statement(
                    sql,
                    vec![now.into(), cutoff.into(), i64::from(remaining).into()],
                ))
                .await;
            let Ok(result) = result else {
                failed = true;
                continue;
            };
            let rows = u32::try_from(result.rows_affected())
                .map_err(|_| ApplicationError::Integrity)?;
            if transaction.commit().await.is_err() {
                failed = true;
                continue;
            }
            affected = affected.saturating_add(rows);
        }
        if failed {
            Err(ApplicationError::Persistence)
        } else {
            Ok(affected)
        }
    }

    async fn claim_due_mail(
        &self,
        worker: &str,
        now: OffsetDateTime,
        lease_until: OffsetDateTime,
    ) -> Result<Option<crate::application::ClaimedMailJob>, ApplicationError> {
        if worker.is_empty()
            || worker.len() > 128
            || lease_until <= now
            || lease_until > now + time::Duration::minutes(1)
        {
            return Err(ApplicationError::InvalidInput);
        }
        let lease_millis = i64::try_from((lease_until - now).whole_milliseconds())
            .map_err(|_| ApplicationError::InvalidInput)?;
        let transaction = self.database.begin().await.map_err(persistence)?;
        self.lock_local_runtime_incarnation(&transaction).await?;
        self.assert_email_protection_ready(&transaction).await?;
        terminalize_due_identity_mutations(&transaction, 100).await?;

        // Candidate discovery is non-authoritative. A selected head may become ineligible while
        // its canonical owner/outbox locks are acquired, so always return to the same global
        // fully-eligible comparison instead of falling through to the other lane. The bound keeps
        // adversarial churn from retaining this transaction and its accumulated locks forever.
        for _ in 0..MAX_GLOBAL_MAIL_RECOMPARISONS {
            let comparison_now = database_clock(&transaction).await?;
            let Some((selected_id, mutation_is_earliest)) =
                identity_mutation_is_earliest_due(self, &transaction, comparison_now).await?
            else {
                transaction.commit().await.map_err(persistence)?;
                return Ok(None);
            };
            let claimed = if mutation_is_earliest {
                claim_due_identity_mutation_mail(
                    self,
                    &transaction,
                    worker,
                    comparison_now,
                    lease_millis,
                    selected_id,
                )
                .await?
            } else {
                claim_due_login_mail(
                    self,
                    &transaction,
                    worker,
                    comparison_now,
                    lease_millis,
                    selected_id,
                )
                .await?
            };
            if claimed.is_some() {
                transaction.commit().await.map_err(persistence)?;
                return Ok(claimed);
            }
        }
        transaction.commit().await.map_err(persistence)?;
        Ok(None)
    }

    async fn finish_mail_attempt(
        &self,
        job: &crate::application::ClaimedMailJob,
        outcome: crate::application::MailTransportOutcome,
        next_attempt_at: Option<OffsetDateTime>,
        now: OffsetDateTime,
    ) -> Result<(), ApplicationError> {
        let (status, safe_outcome, terminal) = match (outcome, next_attempt_at) {
            (crate::application::MailTransportOutcome::Delivered, _) => {
                ("delivered", "delivered", true)
            }
            (crate::application::MailTransportOutcome::Permanent, _) => {
                ("permanent_failure", "permanent", true)
            }
            (crate::application::MailTransportOutcome::PolicyDenied, _) => {
                ("permanent_failure", "policy_denied", true)
            }
            (crate::application::MailTransportOutcome::Transient, Some(_)) => {
                ("retry", "transient", false)
            }
            (crate::application::MailTransportOutcome::Ambiguous, Some(_)) => {
                ("ambiguous", "ambiguous", false)
            }
            (crate::application::MailTransportOutcome::Transient, None) => {
                ("permanent_failure", "transient", true)
            }
            (crate::application::MailTransportOutcome::Ambiguous, None) => {
                ("permanent_failure", "ambiguous", true)
            }
        };
        let next = next_attempt_at.unwrap_or(job.useful_until);
        let transaction = self.database.begin().await.map_err(persistence)?;
        self.lock_local_runtime_incarnation(&transaction).await?;
        let result = transaction.execute_raw(statement(
            "UPDATE mail_outbox SET status=$3, safe_outcome=$4, next_attempt_at=$5, lease_owner=NULL, lease_expires_at=NULL,
             delivered_at=CASE WHEN $3='delivered' THEN $6 ELSE delivered_at END,
             terminal_at=CASE WHEN $7 THEN $6 ELSE terminal_at END, updated_at=$6
             WHERE id=$1 AND status='leased' AND lease_owner=$2 AND attempts=$8
               AND lease_expires_at=$9 AND lease_expires_at>clock_timestamp()",
            vec![job.id.into(), job.lease_owner.clone().into(), status.into(), safe_outcome.into(), next.into(), now.into(), terminal.into(), job.attempts.into(), job.lease_expires_at.into()],
        )).await.map_err(persistence)?;
        if result.rows_affected() != 1 {
            return Err(ApplicationError::RevisionConflict);
        }
        transaction.commit().await.map_err(persistence)
    }

    async fn claim_smtp_test(
        &self,
        worker: &str,
        now: OffsetDateTime,
        lease_until: OffsetDateTime,
    ) -> Result<Option<crate::application::ClaimedSmtpTestJob>, ApplicationError> {
        if worker.is_empty()
            || worker.len() > 128
            || lease_until <= now
            || lease_until > now + time::Duration::minutes(1)
        {
            return Err(ApplicationError::InvalidInput);
        }
        let lease_millis = i64::try_from((lease_until - now).whole_milliseconds())
            .map_err(|_| ApplicationError::InvalidInput)?;
        let transaction = self.database.begin().await.map_err(persistence)?;
        self.lock_local_runtime_incarnation(&transaction).await?;
        let expired = transaction
            .query_all_raw(statement(
                "WITH bounded AS (
                    SELECT project_id,idempotency_key FROM project_smtp_test_operations
                    WHERE state IN ('preparing','pending') AND expires_at <= $1
                    ORDER BY expires_at LIMIT 100 FOR UPDATE SKIP LOCKED)
                 UPDATE project_smtp_test_operations test
                 SET state='failed',safe_outcome='transient',completed_at=$1,provisioning_token=NULL
                 FROM bounded WHERE test.project_id=bounded.project_id
                   AND test.idempotency_key=bounded.idempotency_key
                 RETURNING test.project_id,test.configuration_id,test.correlation_id",
                vec![now.into()],
            ))
            .await
            .map_err(persistence)?;
        append_smtp_test_terminal_audits(&transaction, &expired, "email.smtp.test_expired", now)
            .await?;
        let ambiguous = transaction
            .query_all_raw(statement(
                "WITH bounded AS (
                    SELECT project_id,idempotency_key FROM project_smtp_test_operations
                    WHERE state='submitting' AND lease_expires_at <= clock_timestamp()
                    ORDER BY lease_expires_at LIMIT 100 FOR UPDATE SKIP LOCKED)
                 UPDATE project_smtp_test_operations test
                 SET state='ambiguous',safe_outcome='ambiguous',completed_at=$1,
                     lease_owner=NULL,lease_expires_at=NULL
                 FROM bounded WHERE test.project_id=bounded.project_id
                   AND test.idempotency_key=bounded.idempotency_key
                 RETURNING test.project_id,test.configuration_id,test.correlation_id",
                vec![now.into()],
            ))
            .await
            .map_err(persistence)?;
        append_smtp_test_terminal_audits(
            &transaction,
            &ambiguous,
            "email.smtp.test_ambiguous",
            now,
        )
        .await?;
        let denied = transaction.query_all_raw(statement(
            "WITH bounded AS (
                SELECT test.project_id,test.idempotency_key
                FROM project_smtp_test_operations test
                LEFT JOIN project_smtp_configurations smtp
                  ON smtp.project_id=test.project_id AND smtp.id=test.configuration_id
                 AND smtp.generation=test.configuration_generation
                 AND smtp.revision=test.configuration_revision
                 AND smtp.security_eligibility_revision=test.configuration_security_eligibility_revision
                 AND (smtp.status IN ('reconciled','pending','active')
                      OR (smtp.status='retained' AND smtp.retained_until > $1))
                WHERE test.state='pending' AND smtp.id IS NULL
                ORDER BY test.created_at LIMIT 100 FOR UPDATE OF test SKIP LOCKED)
             UPDATE project_smtp_test_operations test
             SET state='failed',safe_outcome='policy_denied',completed_at=$1
             FROM bounded WHERE test.project_id=bounded.project_id
               AND test.idempotency_key=bounded.idempotency_key
             RETURNING test.project_id,test.configuration_id,test.correlation_id",
            vec![now.into()],
        )).await.map_err(persistence)?;
        append_smtp_test_terminal_audits(
            &transaction,
            &denied,
            "email.smtp.test_policy_denied",
            now,
        )
        .await?;
        let row = transaction
            .query_one_raw(statement(
                "SELECT test.*,smtp.safe_fingerprint,
                        '[]'::jsonb AS explicitly_allowed_private_ips
             FROM project_smtp_test_operations test
             JOIN project_smtp_configurations smtp
               ON smtp.project_id=test.project_id AND smtp.id=test.configuration_id
              AND smtp.generation=test.configuration_generation
              AND smtp.revision=test.configuration_revision
              AND smtp.security_eligibility_revision=test.configuration_security_eligibility_revision
             WHERE test.state='pending'
               AND (smtp.status IN ('reconciled','pending','active')
                    OR (smtp.status='retained' AND smtp.retained_until > $1))
             ORDER BY test.created_at,test.project_id LIMIT 1
             FOR UPDATE OF test SKIP LOCKED",
                vec![now.into()],
            ))
            .await
            .map_err(persistence)?;
        let Some(row) = row else {
            transaction.commit().await.map_err(persistence)?;
            return Ok(None);
        };
        let project_id: Uuid = row.try_get("", "project_id").map_err(persistence)?;
        let key: String = row.try_get("", "idempotency_key").map_err(persistence)?;
        let claimed = transaction
            .query_one_raw(statement(
                "UPDATE project_smtp_test_operations
             SET state='submitting',lease_owner=$3,
                 lease_expires_at=clock_timestamp()+($4*interval '1 millisecond'),attempts=1
             WHERE project_id=$1 AND idempotency_key=$2 AND state='pending' AND attempts=0
             RETURNING lease_expires_at",
                vec![
                    project_id.into(),
                    key.clone().into(),
                    worker.to_owned().into(),
                    lease_millis.into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::RevisionConflict)?;
        let lease_expires_at = claimed
            .try_get("", "lease_expires_at")
            .map_err(persistence)?;
        let tls_mode: String = row.try_get("", "tls_mode").map_err(persistence)?;
        let job = crate::application::ClaimedSmtpTestJob {
            project_id,
            configuration_id: row.try_get("", "configuration_id").map_err(persistence)?,
            configuration_generation: row
                .try_get("", "configuration_generation")
                .map_err(persistence)?,
            configuration_revision: row
                .try_get("", "configuration_revision")
                .map_err(persistence)?,
            configuration_security_eligibility_revision: row
                .try_get("", "configuration_security_eligibility_revision")
                .map_err(persistence)?,
            idempotency_key: key,
            message_id: row.try_get("", "message_id").map_err(persistence)?,
            recipient_ref: row.try_get("", "recipient_ref").map_err(persistence)?,
            endpoint: crate::application::SmtpEndpoint {
                hostname: row.try_get("", "host").map_err(persistence)?,
                port: u16::try_from(row.try_get::<i32>("", "port").map_err(persistence)?)
                    .map_err(|_| ApplicationError::Integrity)?,
                tls_mode: parse_tls_mode(&tls_mode)?,
                explicitly_allowed_private_ips: parse_ip_allowlist(
                    &row.try_get("", "explicitly_allowed_private_ips")
                        .map_err(persistence)?,
                )?,
                development_plaintext_enabled: false,
            },
            envelope_from: row.try_get("", "sender_address").map_err(persistence)?,
            credential_ref: row.try_get("", "credential_ref").map_err(persistence)?,
            safe_fingerprint: row
                .try_get::<Vec<u8>>("", "safe_fingerprint")
                .map_err(persistence)?
                .try_into()
                .map_err(|_| ApplicationError::Integrity)?,
            lease_owner: worker.to_owned(),
            lease_expires_at,
        };
        transaction.commit().await.map_err(persistence)?;
        Ok(Some(job))
    }

    async fn finish_smtp_test(
        &self,
        job: &crate::application::ClaimedSmtpTestJob,
        outcome: crate::application::MailTransportOutcome,
        now: OffsetDateTime,
    ) -> Result<(), ApplicationError> {
        let (state, safe, action) = match outcome {
            crate::application::MailTransportOutcome::Delivered => {
                ("delivered", "delivered", "email.smtp.test_delivered")
            }
            crate::application::MailTransportOutcome::Ambiguous => {
                ("ambiguous", "ambiguous", "email.smtp.test_ambiguous")
            }
            crate::application::MailTransportOutcome::Transient => {
                ("failed", "transient", "email.smtp.test_failed")
            }
            crate::application::MailTransportOutcome::Permanent => {
                ("failed", "permanent", "email.smtp.test_failed")
            }
            crate::application::MailTransportOutcome::PolicyDenied => {
                ("failed", "policy_denied", "email.smtp.test_failed")
            }
        };
        let transaction = self.database.begin().await.map_err(persistence)?;
        self.lock_local_runtime_incarnation(&transaction).await?;
        let row = transaction
            .query_one_raw(statement(
                "UPDATE project_smtp_test_operations SET state=$4,safe_outcome=$5,completed_at=$6,
                    lease_owner=NULL,lease_expires_at=NULL
             WHERE project_id=$1 AND idempotency_key=$2 AND state='submitting' AND lease_owner=$3
               AND lease_expires_at=$7 AND lease_expires_at>clock_timestamp()
             RETURNING correlation_id",
                vec![
                    job.project_id.into(),
                    job.idempotency_key.clone().into(),
                    job.lease_owner.clone().into(),
                    state.into(),
                    safe.into(),
                    now.into(),
                    job.lease_expires_at.into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::RevisionConflict)?;
        let correlation_id: Uuid = row.try_get("", "correlation_id").map_err(persistence)?;
        if outcome == crate::application::MailTransportOutcome::Delivered {
            let readiness = transaction
                .execute_raw(statement(
                    "INSERT INTO project_smtp_runtime_readiness
                       (project_id,configuration_id,generation,process_id,process_incarnation,
                        state,checked_at,lease_expires_at)
                     SELECT smtp.project_id,smtp.id,smtp.generation,$8,$9,'ready',$10,$11
                     FROM project_smtp_configurations smtp
                     WHERE smtp.project_id=$1 AND smtp.id=$2 AND smtp.generation=$3
                       AND smtp.revision=$4 AND smtp.security_eligibility_revision=$5
                       AND smtp.credential_ref=$6 AND smtp.safe_fingerprint=$7
                       AND (smtp.status IN ('pending','active') OR
                            (smtp.status='retained' AND smtp.retained_until>$10))
                       AND EXISTS (
                         SELECT 1 FROM runtime_process_incarnations current
                         WHERE current.process_id=$8 AND current.process_incarnation=$9)
                     ON CONFLICT (project_id,configuration_id,generation,process_id)
                     DO UPDATE SET process_incarnation=EXCLUDED.process_incarnation,
                                   state='ready',checked_at=EXCLUDED.checked_at,
                                   lease_expires_at=EXCLUDED.lease_expires_at",
                    vec![
                        job.project_id.into(),
                        job.configuration_id.into(),
                        job.configuration_generation.into(),
                        job.configuration_revision.into(),
                        job.configuration_security_eligibility_revision.into(),
                        job.credential_ref.clone().into(),
                        job.safe_fingerprint.to_vec().into(),
                        self.runtime_process_id.clone().into(),
                        self.runtime_incarnation.into(),
                        now.into(),
                        (now + self.readiness_lease).into(),
                    ],
                ))
                .await
                .map_err(persistence)?;
            if readiness.rows_affected() > 1 {
                return Err(ApplicationError::Integrity);
            }
            if readiness.rows_affected() == 0 {
                self.lock_local_runtime_incarnation(&transaction).await?;
            }
        }
        transaction.execute_raw(statement(
            "INSERT INTO audit_events (id,project_id,actor_kind,action,target_kind,target_id,outcome,correlation_id,safe_context,occurred_at)
             VALUES ($1,$2,'system',$3,'smtp_configuration',$4,'success',$5,'{}'::jsonb,$6)",
            vec![Uuid::new_v4().into(),job.project_id.into(),action.into(),job.configuration_id.into(),correlation_id.into(),now.into()],
        )).await.map_err(persistence)?;
        transaction.commit().await.map_err(persistence)
    }

    async fn claim_smtp_secret_cleanup(
        &self,
        worker: &str,
        now: OffsetDateTime,
        lease_until: OffsetDateTime,
    ) -> Result<Option<crate::application::ClaimedSmtpSecretCleanup>, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        self.lock_local_runtime_incarnation(&transaction).await?;
        let stale = transaction
            .query_all_raw(statement(
                "WITH bounded AS (
               SELECT project_id,idempotency_key FROM project_smtp_test_operations
               WHERE state='preparing' AND created_at + INTERVAL '5 minutes' <= $1
               ORDER BY created_at LIMIT 100 FOR UPDATE SKIP LOCKED)
             UPDATE project_smtp_test_operations test
             SET state='ambiguous',safe_outcome='ambiguous',completed_at=$1,provisioning_token=NULL
             FROM bounded WHERE test.project_id=bounded.project_id
               AND test.idempotency_key=bounded.idempotency_key
             RETURNING test.project_id,test.configuration_id,test.correlation_id",
                vec![now.into()],
            ))
            .await
            .map_err(persistence)?;
        append_smtp_test_terminal_audits(
            &transaction,
            &stale,
            "email.smtp.test_prepare_abandoned",
            now,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;

        let transaction = self.database.begin().await.map_err(persistence)?;
        self.lock_local_runtime_incarnation(&transaction).await?;
        let row = transaction
            .query_one_raw(statement(
                "SELECT project_id,id,idempotency_key,recipient_ref FROM project_smtp_test_operations
             WHERE state IN ('delivered','failed','ambiguous') AND recipient_erased_at IS NULL
               AND (cleanup_lease_owner IS NULL OR cleanup_lease_expires_at <= $1)
             ORDER BY completed_at LIMIT 1",
                vec![now.into()],
            ))
            .await
            .map_err(persistence)?;
        let Some(row) = row else {
            transaction.commit().await.map_err(persistence)?;
            return Ok(None);
        };
        let project_id: Uuid = row.try_get("", "project_id").map_err(persistence)?;
        let operation_id: Uuid = row.try_get("", "id").map_err(persistence)?;
        let key: String = row.try_get("", "idempotency_key").map_err(persistence)?;
        let recipient_ref: String = row.try_get("", "recipient_ref").map_err(persistence)?;
        lock_smtp_credential_reference(&transaction, &recipient_ref).await?;
        let owner = transaction
            .query_one_raw(statement(
                "SELECT 1 AS present FROM project_smtp_test_operations
             WHERE project_id=$1 AND idempotency_key=$2 AND id=$3 AND recipient_ref=$4
               AND state IN ('delivered','failed','ambiguous') AND recipient_erased_at IS NULL
               AND (cleanup_lease_owner IS NULL OR cleanup_lease_expires_at <= $5) FOR UPDATE",
                vec![
                    project_id.into(),
                    key.clone().into(),
                    operation_id.into(),
                    recipient_ref.clone().into(),
                    now.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        if owner.is_none() {
            transaction.commit().await.map_err(persistence)?;
            return Ok(None);
        }
        let reservation = transaction
            .query_one_raw(statement(
                "UPDATE smtp_test_recipient_reference_reservations
                 SET state='reserved',updated_at=$3
                 WHERE recipient_ref=$1 AND operation_id=$2 AND state='live'
                 RETURNING state,operation_id",
                vec![
                    recipient_ref.clone().into(),
                    operation_id.into(),
                    now.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        let reservation = match reservation {
            Some(row) => row,
            None => transaction
                .query_one_raw(statement(
                    "SELECT state,operation_id FROM smtp_test_recipient_reference_reservations
                     WHERE recipient_ref=$1 FOR UPDATE",
                    vec![recipient_ref.clone().into()],
                ))
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::Integrity)?,
        };
        let reservation_state: String = reservation.try_get("", "state").map_err(persistence)?;
        if reservation
            .try_get::<Uuid>("", "operation_id")
            .map_err(persistence)?
            != operation_id
        {
            return Err(ApplicationError::Integrity);
        }
        if reservation_state == "erased" {
            transaction
                .execute_raw(statement(
                    "UPDATE project_smtp_test_operations SET recipient_erased_at=COALESCE(recipient_erased_at,$3),
                         cleanup_lease_owner=NULL,cleanup_lease_expires_at=NULL
                     WHERE project_id=$1 AND idempotency_key=$2",
                    vec![project_id.into(), key.into(), now.into()],
                ))
                .await
                .map_err(persistence)?;
            transaction.commit().await.map_err(persistence)?;
            return Ok(None);
        }
        if reservation_state != "reserved" {
            return Err(ApplicationError::InvalidTransition);
        }
        let updated=transaction.execute_raw(statement(
            "UPDATE project_smtp_test_operations SET cleanup_lease_owner=$3,cleanup_lease_expires_at=$4
             WHERE project_id=$1 AND idempotency_key=$2 AND recipient_erased_at IS NULL
               AND (cleanup_lease_owner IS NULL OR cleanup_lease_expires_at <= $5)",
            vec![project_id.into(),key.clone().into(),worker.to_owned().into(),lease_until.into(),now.into()],
        )).await.map_err(persistence)?;
        if updated.rows_affected() != 1 {
            return Err(ApplicationError::RevisionConflict);
        }
        let cleanup = crate::application::ClaimedSmtpSecretCleanup {
            project_id,
            idempotency_key: key,
            recipient_ref,
            lease_owner: worker.to_owned(),
        };
        transaction.commit().await.map_err(persistence)?;
        Ok(Some(cleanup))
    }

    async fn finish_smtp_secret_cleanup(
        &self,
        cleanup: &crate::application::ClaimedSmtpSecretCleanup,
        now: OffsetDateTime,
    ) -> Result<(), ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        self.lock_local_runtime_incarnation(&transaction).await?;
        let owner = transaction
            .query_one_raw(statement(
                "SELECT id,recipient_ref FROM project_smtp_test_operations
                 WHERE project_id=$1 AND idempotency_key=$2 AND cleanup_lease_owner=$3
                   AND recipient_erased_at IS NULL FOR UPDATE",
                vec![
                    cleanup.project_id.into(),
                    cleanup.idempotency_key.clone().into(),
                    cleanup.lease_owner.clone().into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::RevisionConflict)?;
        let operation_id: Uuid = owner.try_get("", "id").map_err(persistence)?;
        let recipient_ref: String = owner.try_get("", "recipient_ref").map_err(persistence)?;
        if recipient_ref != cleanup.recipient_ref {
            return Err(ApplicationError::Integrity);
        }
        lock_smtp_credential_reference(&transaction, &recipient_ref).await?;
        let tombstoned = transaction
            .execute_raw(statement(
                "UPDATE smtp_test_recipient_reference_reservations
                 SET state='erased',erased_at=$3,updated_at=$3
                 WHERE recipient_ref=$1 AND operation_id=$2 AND state='reserved'",
                vec![recipient_ref.into(), operation_id.into(), now.into()],
            ))
            .await
            .map_err(persistence)?;
        if tombstoned.rows_affected() != 1 {
            return Err(ApplicationError::RevisionConflict);
        }
        let result = transaction
            .execute_raw(statement(
                "UPDATE project_smtp_test_operations SET recipient_erased_at=$4,
                    cleanup_lease_owner=NULL,cleanup_lease_expires_at=NULL
                 WHERE project_id=$1 AND idempotency_key=$2 AND cleanup_lease_owner=$3
                   AND recipient_erased_at IS NULL",
                vec![
                    cleanup.project_id.into(),
                    cleanup.idempotency_key.clone().into(),
                    cleanup.lease_owner.clone().into(),
                    now.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        if result.rows_affected() != 1 {
            return Err(ApplicationError::RevisionConflict);
        }
        transaction.commit().await.map_err(persistence)
    }

    async fn claim_smtp_credential_cleanup(
        &self,
        worker: &str,
        now: OffsetDateTime,
        lease_until: OffsetDateTime,
    ) -> Result<Option<crate::application::ClaimedSmtpCredentialCleanup>, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        self.lock_local_runtime_incarnation(&transaction).await?;
        let retired_projects = transaction
            .query_all_raw(statement(
                "WITH bounded AS (
                   SELECT smtp.project_id,smtp.id,smtp.generation,smtp.credential_ref
                   FROM project_smtp_configurations smtp
                   WHERE ((smtp.status='retained' AND smtp.retained_until <= $1)
                          OR smtp.status IN ('disabled','compromised'))
                     AND NOT EXISTS (
                       SELECT 1 FROM login_email_method_snapshots snapshot
                       JOIN login_transactions login ON login.project_id=snapshot.project_id
                         AND login.id=snapshot.transaction_id
                       WHERE snapshot.smtp_selection_kind='project'
                         AND snapshot.project_id=smtp.project_id
                         AND snapshot.smtp_configuration_id=smtp.id
                         AND login.terminal_at IS NULL AND login.expires_at>$1)
                     AND NOT EXISTS (
                       SELECT 1 FROM email_challenges challenge
                       WHERE challenge.smtp_selection_kind='project'
                         AND challenge.project_id=smtp.project_id
                         AND challenge.smtp_configuration_id=smtp.id
                         AND challenge.status='pending' AND challenge.expires_at>$1)
                     AND NOT EXISTS (
                       SELECT 1 FROM mail_outbox outbox
                       WHERE outbox.smtp_selection_kind='project'
                         AND outbox.project_id=smtp.project_id
                         AND outbox.smtp_configuration_id=smtp.id
                         AND outbox.status IN ('pending','leased','retry','ambiguous')
                         AND outbox.useful_until>$1)
                     AND NOT EXISTS (
                       SELECT 1 FROM project_smtp_test_operations test
                       WHERE test.project_id=smtp.project_id AND test.configuration_id=smtp.id
                         AND test.state IN ('preparing','pending','submitting'))
                   ORDER BY COALESCE(smtp.retained_until,smtp.updated_at),smtp.project_id,smtp.generation
                   LIMIT 25 FOR UPDATE OF smtp SKIP LOCKED)
                 UPDATE project_smtp_configurations smtp
                 SET status='retired',retained_until=NULL,revision=revision+1,
                     security_eligibility_revision=security_eligibility_revision+1,updated_at=$1
                 FROM bounded WHERE smtp.project_id=bounded.project_id AND smtp.id=bounded.id
                 RETURNING smtp.project_id,smtp.id,smtp.generation,smtp.credential_ref",
                vec![now.into()],
            ))
            .await
            .map_err(persistence)?;
        for row in &retired_projects {
            let project_id: Uuid = row.try_get("", "project_id").map_err(persistence)?;
            let configuration_id: Uuid = row.try_get("", "id").map_err(persistence)?;
            let generation: i32 = row.try_get("", "generation").map_err(persistence)?;
            transaction
                .execute_raw(statement(
                    "INSERT INTO smtp_credential_cleanup_operations
                     (id,scope,project_id,generation,credential_ref,state,created_at)
                     VALUES ($1,'project',$2,$3,$4,'pending',$5)
                     ON CONFLICT (scope,project_id,generation) DO NOTHING",
                    vec![
                        Uuid::new_v4().into(),
                        project_id.into(),
                        generation.into(),
                        row.try_get::<String>("", "credential_ref")
                            .map_err(persistence)?
                            .into(),
                        now.into(),
                    ],
                ))
                .await
                .map_err(persistence)?;
            transaction.execute_raw(statement(
                "INSERT INTO audit_events
                 (id,project_id,actor_kind,action,target_kind,target_id,outcome,correlation_id,safe_context,occurred_at)
                 VALUES ($1,$2,'system','email.smtp.generation_retired','smtp_configuration',$3,'success',$4,$5,$6)",
                vec![Uuid::new_v4().into(),project_id.into(),configuration_id.into(),Uuid::new_v4().into(),
                    serde_json::json!({"generation":generation}).into(),now.into()],
            )).await.map_err(persistence)?;
        }
        let retired_deployments = transaction
            .query_all_raw(statement(
                "WITH bounded AS (
                   SELECT smtp.generation,smtp.credential_ref
                   FROM deployment_smtp_generations smtp
                   WHERE ((smtp.status='retained' AND smtp.retained_until <= $1)
                          OR smtp.status IN ('disabled','compromised'))
                     AND NOT EXISTS (
                       SELECT 1 FROM login_email_method_snapshots snapshot
                       JOIN login_transactions login ON login.project_id=snapshot.project_id
                         AND login.id=snapshot.transaction_id
                       WHERE snapshot.smtp_selection_kind='deployment_default'
                         AND snapshot.smtp_generation=smtp.generation
                         AND login.terminal_at IS NULL AND login.expires_at>$1)
                     AND NOT EXISTS (
                       SELECT 1 FROM email_challenges challenge
                       WHERE challenge.smtp_selection_kind='deployment_default'
                         AND challenge.smtp_generation=smtp.generation
                         AND challenge.status='pending' AND challenge.expires_at>$1)
                     AND NOT EXISTS (
                       SELECT 1 FROM mail_outbox outbox
                       WHERE outbox.smtp_selection_kind='deployment_default'
                         AND outbox.smtp_generation=smtp.generation
                         AND outbox.status IN ('pending','leased','retry','ambiguous')
                         AND outbox.useful_until>$1)
                   ORDER BY COALESCE(smtp.retained_until,smtp.updated_at),smtp.generation
                   LIMIT 25 FOR UPDATE OF smtp SKIP LOCKED)
                 UPDATE deployment_smtp_generations smtp
                 SET status='retired',retained_until=NULL,revision=revision+1,
                     security_eligibility_revision=security_eligibility_revision+1,updated_at=$1
                 FROM bounded WHERE smtp.generation=bounded.generation
                 RETURNING smtp.generation,smtp.credential_ref",
                vec![now.into()],
            ))
            .await
            .map_err(persistence)?;
        for row in &retired_deployments {
            let generation: i32 = row.try_get("", "generation").map_err(persistence)?;
            transaction
                .execute_raw(statement(
                    "INSERT INTO smtp_credential_cleanup_operations
                     (id,scope,project_id,generation,credential_ref,state,created_at)
                     VALUES ($1,'deployment_default',NULL,$2,$3,'pending',$4)
                     ON CONFLICT (scope,project_id,generation) DO NOTHING",
                    vec![
                        Uuid::new_v4().into(),
                        generation.into(),
                        row.try_get::<String>("", "credential_ref")
                            .map_err(persistence)?
                            .into(),
                        now.into(),
                    ],
                ))
                .await
                .map_err(persistence)?;
            transaction.execute_raw(statement(
                "INSERT INTO audit_events
                 (id,project_id,actor_kind,action,target_kind,target_id,outcome,correlation_id,safe_context,occurred_at)
                 VALUES ($1,NULL,'system','email.smtp.default_generation_retired','deployment_smtp_generation',NULL,'success',$2,$3,$4)",
                vec![Uuid::new_v4().into(),Uuid::new_v4().into(),serde_json::json!({"generation":generation}).into(),now.into()],
            )).await.map_err(persistence)?;
        }
        // Retirement and operation creation commit before reference reservation. The cleanup
        // transaction therefore never holds an SMTP generation row while waiting for the shared
        // per-reference lock used by registration/reconciliation.
        transaction.commit().await.map_err(persistence)?;
        let transaction = self.database.begin().await.map_err(persistence)?;
        self.lock_local_runtime_incarnation(&transaction).await?;
        let row = transaction
            .query_one_raw(statement(
                "SELECT cleanup.id,cleanup.credential_ref
                 FROM smtp_credential_cleanup_operations cleanup
                 LEFT JOIN smtp_credential_reference_reservations reservation
                   ON reservation.credential_ref=cleanup.credential_ref
                 WHERE (cleanup.state='pending' OR
                        (cleanup.state='leased' AND cleanup.lease_expires_at <= $1))
                   AND (reservation.state IS DISTINCT FROM 'reserved'
                        OR reservation.cleanup_id=cleanup.id)
                 ORDER BY CASE WHEN reservation.state='reserved' THEN 0 ELSE 1 END,
                          cleanup.created_at,cleanup.id
                 LIMIT 1 FOR UPDATE OF cleanup SKIP LOCKED",
                vec![now.into()],
            ))
            .await
            .map_err(persistence)?;
        let Some(row) = row else {
            transaction.commit().await.map_err(persistence)?;
            return Ok(None);
        };
        let id: Uuid = row.try_get("", "id").map_err(persistence)?;
        let credential_ref: String = row.try_get("", "credential_ref").map_err(persistence)?;
        lock_smtp_credential_reference(&transaction, &credential_ref).await?;
        let live_reference = transaction
            .query_one_raw(statement(
                "SELECT 1 AS present FROM project_smtp_configurations
             WHERE credential_ref=$1 AND status<>'retired'
             UNION ALL
             SELECT 1 AS present FROM deployment_smtp_generations
             WHERE credential_ref=$1 AND status<>'retired' LIMIT 1",
                vec![credential_ref.clone().into()],
            ))
            .await
            .map_err(persistence)?;
        if live_reference.is_some() {
            transaction.commit().await.map_err(persistence)?;
            return Ok(None);
        }
        let reservation = transaction
            .query_one_raw(statement(
                "INSERT INTO smtp_credential_reference_reservations
             (credential_ref,state,cleanup_id,created_at,updated_at)
             VALUES ($1,'reserved',$2,$3,$3)
             ON CONFLICT (credential_ref) DO UPDATE
               SET state='reserved',cleanup_id=EXCLUDED.cleanup_id,updated_at=EXCLUDED.updated_at,
                   erased_at=NULL
             WHERE smtp_credential_reference_reservations.state='live'
             RETURNING state,cleanup_id",
                vec![credential_ref.clone().into(), id.into(), now.into()],
            ))
            .await
            .map_err(persistence)?;
        let reservation = match reservation {
            Some(reservation) => reservation,
            None => transaction
                .query_one_raw(statement(
                    "SELECT state,cleanup_id FROM smtp_credential_reference_reservations
                 WHERE credential_ref=$1 FOR UPDATE",
                    vec![credential_ref.clone().into()],
                ))
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::Integrity)?,
        };
        let reservation_state: String = reservation.try_get("", "state").map_err(persistence)?;
        let reservation_cleanup: Option<Uuid> =
            reservation.try_get("", "cleanup_id").map_err(persistence)?;
        if reservation_state == "erased" {
            transaction
                .execute_raw(statement(
                    "UPDATE smtp_credential_cleanup_operations
                 SET state='erased',lease_owner=NULL,lease_expires_at=NULL,erased_at=$2
                 WHERE id=$1 AND state<>'erased'",
                    vec![id.into(), now.into()],
                ))
                .await
                .map_err(persistence)?;
            transaction.commit().await.map_err(persistence)?;
            return Ok(None);
        }
        if reservation_state != "reserved" || reservation_cleanup != Some(id) {
            transaction.commit().await.map_err(persistence)?;
            return Ok(None);
        }
        let updated = transaction
            .execute_raw(statement(
                "UPDATE smtp_credential_cleanup_operations
                 SET state='leased',lease_owner=$2,lease_expires_at=$3
                 WHERE id=$1 AND (state='pending' OR (state='leased' AND lease_expires_at <= $4))",
                vec![
                    id.into(),
                    worker.to_owned().into(),
                    lease_until.into(),
                    now.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        if updated.rows_affected() != 1 {
            return Err(ApplicationError::RevisionConflict);
        }
        let cleanup = crate::application::ClaimedSmtpCredentialCleanup {
            id,
            credential_ref,
            lease_owner: worker.to_owned(),
        };
        transaction.commit().await.map_err(persistence)?;
        Ok(Some(cleanup))
    }

    async fn finish_smtp_credential_cleanup(
        &self,
        cleanup: &crate::application::ClaimedSmtpCredentialCleanup,
        now: OffsetDateTime,
    ) -> Result<(), ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        self.lock_local_runtime_incarnation(&transaction).await?;
        lock_smtp_credential_reference(&transaction, &cleanup.credential_ref).await?;
        let row = transaction
            .query_one_raw(statement(
                "UPDATE smtp_credential_cleanup_operations
                 SET state='erased',lease_owner=NULL,lease_expires_at=NULL,erased_at=$3
                 WHERE id=$1 AND state='leased' AND lease_owner=$2
                 RETURNING scope,project_id,generation",
                vec![
                    cleanup.id.into(),
                    cleanup.lease_owner.clone().into(),
                    now.into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::RevisionConflict)?;
        let scope: String = row.try_get("", "scope").map_err(persistence)?;
        let project_id: Option<Uuid> = row.try_get("", "project_id").map_err(persistence)?;
        let generation: i32 = row.try_get("", "generation").map_err(persistence)?;
        let reserved = transaction
            .execute_raw(statement(
                "UPDATE smtp_credential_reference_reservations
             SET state='erased',cleanup_id=NULL,erased_at=$3,updated_at=$3
             WHERE credential_ref=$1 AND state='reserved' AND cleanup_id=$2",
                vec![
                    cleanup.credential_ref.clone().into(),
                    cleanup.id.into(),
                    now.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        if reserved.rows_affected() != 1 {
            return Err(ApplicationError::RevisionConflict);
        }
        transaction.execute_raw(statement(
            "INSERT INTO audit_events
             (id,project_id,actor_kind,action,target_kind,target_id,outcome,correlation_id,safe_context,occurred_at)
             VALUES ($1,$2,'system','email.smtp.credential_erased','smtp_credential',NULL,'success',$3,$4,$5)",
            vec![Uuid::new_v4().into(),project_id.into(),Uuid::new_v4().into(),
                serde_json::json!({"scope":scope,"generation":generation}).into(),now.into()],
        )).await.map_err(persistence)?;
        transaction.commit().await.map_err(persistence)?;
        Ok(())
    }
}

async fn append_smtp_test_terminal_audits(
    transaction: &DatabaseTransaction,
    rows: &[QueryResult],
    action: &str,
    now: OffsetDateTime,
) -> Result<(), ApplicationError> {
    for row in rows {
        transaction.execute_raw(statement(
            "INSERT INTO audit_events
             (id,project_id,actor_kind,action,target_kind,target_id,outcome,correlation_id,safe_context,occurred_at)
             VALUES ($1,$2,'system',$3,'smtp_configuration',$4,'success',$5,'{}'::jsonb,$6)",
            vec![Uuid::new_v4().into(),row.try_get::<Uuid>("","project_id").map_err(persistence)?.into(),
                action.to_owned().into(),row.try_get::<Uuid>("","configuration_id").map_err(persistence)?.into(),
                row.try_get::<Uuid>("","correlation_id").map_err(persistence)?.into(),now.into()],
        )).await.map_err(persistence)?;
    }
    Ok(())
}

async fn lock_smtp_credential_reference(
    transaction: &DatabaseTransaction,
    credential_ref: &str,
) -> Result<(), ApplicationError> {
    transaction
        .execute_raw(statement(
            "SELECT pg_advisory_xact_lock(hashtextextended('owlauth:smtp-credential:' || $1,0))",
            vec![credential_ref.to_owned().into()],
        ))
        .await
        .map_err(persistence)?;
    Ok(())
}

fn validate_deployment_smtp_generation(
    generation: &crate::application::DeploymentSmtpGeneration,
) -> Result<(), ApplicationError> {
    generation.endpoint().validate()?;
    if generation.generation <= 0
        || generation.sender_address.is_empty()
        || generation.sender_address.len() > 254
        || generation.credential_ref.is_empty()
        || generation.credential_ref.len() > 512
    {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(())
}

fn deployment_smtp_is_unchanged(
    existing: &QueryResult,
    generation: &crate::application::DeploymentSmtpGeneration,
    tls_mode: &str,
) -> Result<bool, ApplicationError> {
    validate_deployment_smtp_metadata(existing, generation, tls_mode)?;
    let desired = match generation.desired_status {
        crate::application::DeploymentSmtpDesiredStatus::Reconciled => "reconciled",
        crate::application::DeploymentSmtpDesiredStatus::Active => "active",
        crate::application::DeploymentSmtpDesiredStatus::Disabled => "disabled",
        crate::application::DeploymentSmtpDesiredStatus::Compromised => "compromised",
    };
    Ok(existing
        .try_get::<String>("", "status")
        .map_err(persistence)?
        == desired)
}

fn validate_deployment_smtp_metadata(
    existing: &QueryResult,
    generation: &crate::application::DeploymentSmtpGeneration,
    tls_mode: &str,
) -> Result<(), ApplicationError> {
    let fingerprint: Vec<u8> = existing
        .try_get("", "safe_fingerprint")
        .map_err(persistence)?;
    let matches = existing
        .try_get::<String>("", "host")
        .map_err(persistence)?
        == generation.host
        && existing.try_get::<i32>("", "port").map_err(persistence)? == i32::from(generation.port)
        && existing
            .try_get::<String>("", "tls_mode")
            .map_err(persistence)?
            == tls_mode
        && existing
            .try_get::<String>("", "sender_address")
            .map_err(persistence)?
            == generation.sender_address
        && existing
            .try_get::<String>("", "credential_ref")
            .map_err(persistence)?
            == generation.credential_ref
        && bool::from(
            fingerprint
                .as_slice()
                .ct_eq(generation.safe_fingerprint.as_slice()),
        )
        && parse_ip_allowlist(
            &existing
                .try_get("", "explicitly_allowed_private_ips")
                .map_err(persistence)?,
        )? == generation.explicitly_allowed_private_ips;
    if !matches {
        return Err(ApplicationError::IdempotencyConflict);
    }
    Ok(())
}

fn claimed_mail_job(
    row: &QueryResult,
    id: Uuid,
    worker: &str,
    lease_expires_at: OffsetDateTime,
    safe_fingerprint: [u8; 32],
) -> Result<crate::application::ClaimedMailJob, ApplicationError> {
    let tls_mode: String = row.try_get("", "tls_mode").map_err(persistence)?;
    let endpoint = crate::application::SmtpEndpoint {
        hostname: row.try_get("", "host").map_err(persistence)?,
        port: u16::try_from(row.try_get::<i32>("", "port").map_err(persistence)?)
            .map_err(|_| ApplicationError::Integrity)?,
        tls_mode: match tls_mode.as_str() {
            "implicit_tls" => crate::application::SmtpTlsMode::ImplicitTls,
            "starttls_required" => crate::application::SmtpTlsMode::StartTlsRequired,
            "development_loopback_plaintext" => {
                crate::application::SmtpTlsMode::DevelopmentLoopbackPlaintext
            }
            _ => return Err(ApplicationError::Integrity),
        },
        explicitly_allowed_private_ips: parse_ip_allowlist(
            &row.try_get("", "allowed_private_ips")
                .map_err(persistence)?,
        )?,
        development_plaintext_enabled: tls_mode == "development_loopback_plaintext",
    };
    endpoint.validate()?;
    let transaction_id: Option<Uuid> = row.try_get("", "transaction_id").map_err(persistence)?;
    let mutation_intent_id: Option<Uuid> = row
        .try_get("", "identity_mutation_intent_id")
        .map_err(persistence)?;
    let mutation_slot_id: Option<Uuid> = row
        .try_get("", "identity_mutation_proof_slot_id")
        .map_err(persistence)?;
    let owner = match (transaction_id, mutation_intent_id, mutation_slot_id) {
        (Some(transaction_id), None, None) => {
            crate::application::MailChallengeOwner::Login { transaction_id }
        }
        (None, Some(intent_id), Some(proof_slot_id)) => {
            crate::application::MailChallengeOwner::IdentityMutation {
                intent_id,
                proof_slot_id,
            }
        }
        _ => return Err(ApplicationError::Integrity),
    };
    Ok(crate::application::ClaimedMailJob {
        id,
        project_id: row.try_get("", "project_id").map_err(persistence)?,
        owner,
        challenge_id: row.try_get("", "challenge_id").map_err(persistence)?,
        challenge_generation: row
            .try_get("", "challenge_generation")
            .map_err(persistence)?,
        message_id: row.try_get("", "message_id").map_err(persistence)?,
        envelope: ProtectedValue {
            ciphertext: row
                .try_get("", "envelope_ciphertext")
                .map_err(persistence)?,
            key_version: row
                .try_get("", "envelope_key_version")
                .map_err(persistence)?,
        },
        body: ProtectedValue {
            ciphertext: row.try_get("", "body_ciphertext").map_err(persistence)?,
            key_version: row.try_get("", "body_key_version").map_err(persistence)?,
        },
        endpoint,
        envelope_from: row.try_get("", "sender_address").map_err(persistence)?,
        sender_name: row.try_get("", "sender_name").map_err(persistence)?,
        reply_to: row.try_get("", "reply_to").map_err(persistence)?,
        credential_ref: row.try_get("", "credential_ref").map_err(persistence)?,
        safe_fingerprint,
        lease_owner: worker.to_owned(),
        lease_expires_at,
        attempts: row.try_get::<i16>("", "attempts").map_err(persistence)? + 1,
        max_attempts: row.try_get("", "max_attempts").map_err(persistence)?,
        useful_until: row.try_get("", "useful_until").map_err(persistence)?,
    })
}

async fn terminalize_unreadable_short_term(
    database: &DatabaseTransaction,
    readable: &BTreeSet<i32>,
    now: OffsetDateTime,
) -> Result<(), ApplicationError> {
    let versions = serde_json::Value::Array(
        readable
            .iter()
            .map(|version| serde_json::Value::from(*version))
            .collect(),
    );
    loop {
        if terminalize_unreadable_identity_mutations(database, versions.clone()).await? == 0 {
            break;
        }
    }
    loop {
        let result = database.execute_raw(statement(
            "WITH bounded AS (
               SELECT outbox.id FROM mail_outbox outbox
               JOIN email_challenges challenge ON challenge.project_id=outbox.project_id AND challenge.id=outbox.challenge_id
               WHERE outbox.status IN ('pending','retry','ambiguous','leased')
                AND challenge.owner_kind<>'identity_mutation' AND
                (NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text($1) v WHERE v::INT=outbox.envelope_key_version)
                 OR NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text($1) v WHERE v::INT=outbox.body_key_version)
                 OR NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text($1) v WHERE v::INT=challenge.address_key_version)
                 OR (challenge.otp_digest_key_version IS NOT NULL AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text($1) v WHERE v::INT=challenge.otp_digest_key_version))
                 OR (challenge.magic_digest_key_version IS NOT NULL AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text($1) v WHERE v::INT=challenge.magic_digest_key_version)))
               ORDER BY outbox.id LIMIT 100 FOR UPDATE OF outbox SKIP LOCKED)
             UPDATE mail_outbox outbox SET status='permanent_failure',safe_outcome='permanent',terminal_at=$2,
               lease_owner=NULL,lease_expires_at=NULL,updated_at=$2 FROM bounded WHERE outbox.id=bounded.id",
            vec![versions.clone().into(),now.into()],
        )).await.map_err(persistence)?;
        if result.rows_affected() == 0 {
            break;
        }
    }
    loop {
        let result=database.execute_raw(statement(
            "WITH bounded AS (SELECT project_id,id FROM email_challenges
             WHERE owner_kind<>'identity_mutation' AND status='pending' AND
              (NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text($1) v WHERE v::INT=address_key_version)
               OR (otp_digest_key_version IS NOT NULL AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text($1) v WHERE v::INT=otp_digest_key_version))
               OR (magic_digest_key_version IS NOT NULL AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text($1) v WHERE v::INT=magic_digest_key_version)))
              ORDER BY project_id,id LIMIT 100 FOR UPDATE SKIP LOCKED)
             UPDATE email_challenges challenge SET status='delivery_unavailable',terminal_at=$2,updated_at=$2
             FROM bounded WHERE challenge.project_id=bounded.project_id AND challenge.id=bounded.id",
            vec![versions.clone().into(),now.into()],
        )).await.map_err(persistence)?;
        if result.rows_affected() == 0 {
            break;
        }
    }
    loop {
        let result=database.execute_raw(statement(
            "WITH bounded AS (SELECT id FROM magic_transfer_contexts WHERE status='pending' AND
              (NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text($1) v WHERE v::INT=context_digest_key_version)
               OR NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text($1) v WHERE v::INT=csrf_digest_key_version))
              ORDER BY id LIMIT 100 FOR UPDATE SKIP LOCKED)
             UPDATE magic_transfer_contexts transfer SET status='expired' FROM bounded WHERE transfer.id=bounded.id",
            vec![versions.clone().into()],
        )).await.map_err(persistence)?;
        if result.rows_affected() == 0 {
            break;
        }
    }
    Ok(())
}

async fn load_email_protection_inventory(
    database: &DatabaseTransaction,
) -> Result<EmailProtectionInventory, ApplicationError> {
    let rows = database.query_all_raw(statement(
        "SELECT DISTINCT purpose,key_version FROM (
           SELECT 'durable_digest' purpose,lookup_digest_key_version key_version FROM email_challenges WHERE status='pending'
           UNION ALL SELECT 'short_digest',otp_digest_key_version FROM email_challenges WHERE status='pending' AND otp_digest_key_version IS NOT NULL
           UNION ALL SELECT 'short_digest',magic_digest_key_version FROM email_challenges WHERE status='pending' AND magic_digest_key_version IS NOT NULL
           UNION ALL SELECT 'short_digest',context_digest_key_version FROM magic_transfer_contexts WHERE status='pending'
           UNION ALL SELECT 'short_digest',csrf_digest_key_version FROM magic_transfer_contexts WHERE status='pending'
           UNION ALL SELECT 'short_protection',address_key_version FROM email_challenges WHERE status='pending'
           UNION ALL SELECT 'short_protection',envelope_key_version FROM mail_outbox WHERE status IN ('pending','retry','ambiguous','leased')
           UNION ALL SELECT 'short_protection',body_key_version FROM mail_outbox WHERE status IN ('pending','retry','ambiguous','leased')
           UNION ALL SELECT 'durable_digest',digest_key_version FROM email_identity_aliases
           UNION ALL SELECT 'durable_protection',address_key_version FROM email_identities
         ) inventory WHERE key_version IS NOT NULL ORDER BY purpose,key_version",
        vec![],
    )).await.map_err(persistence)?;
    let mut inventory = EmailProtectionInventory {
        short_term_digest_versions: BTreeSet::new(),
        short_term_protection_versions: BTreeSet::new(),
        durable_digest_versions: BTreeSet::new(),
        durable_protection_versions: BTreeSet::new(),
    };
    for row in rows {
        let version: i32 = row.try_get("", "key_version").map_err(persistence)?;
        match row
            .try_get::<String>("", "purpose")
            .map_err(persistence)?
            .as_str()
        {
            "short_digest" => inventory.short_term_digest_versions.insert(version),
            "short_protection" => inventory.short_term_protection_versions.insert(version),
            "durable_digest" => inventory.durable_digest_versions.insert(version),
            "durable_protection" => inventory.durable_protection_versions.insert(version),
            _ => return Err(ApplicationError::Integrity),
        };
    }
    Ok(inventory)
}

fn ip_allowlist_json(values: &[std::net::IpAddr]) -> serde_json::Value {
    serde_json::Value::Array(
        values
            .iter()
            .map(|value| serde_json::Value::String(value.to_string()))
            .collect(),
    )
}

fn parse_tls_mode(value: &str) -> Result<crate::application::SmtpTlsMode, ApplicationError> {
    match value {
        "implicit_tls" => Ok(crate::application::SmtpTlsMode::ImplicitTls),
        "starttls_required" => Ok(crate::application::SmtpTlsMode::StartTlsRequired),
        _ => Err(ApplicationError::Integrity),
    }
}

fn parse_ip_allowlist(
    value: &serde_json::Value,
) -> Result<Vec<std::net::IpAddr>, ApplicationError> {
    let values = value.as_array().ok_or(ApplicationError::Integrity)?;
    if values.len() > 16 {
        return Err(ApplicationError::Integrity);
    }
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or(ApplicationError::Integrity)?
                .parse()
                .map_err(|_| ApplicationError::Integrity)
        })
        .collect()
}

fn email_identity_context(project_id: Uuid, identity_id: Uuid) -> Vec<u8> {
    let mut context = Vec::with_capacity(58);
    context.extend_from_slice(b"owlauth-email-identity-v1\0");
    context.extend_from_slice(project_id.as_bytes());
    context.extend_from_slice(identity_id.as_bytes());
    context
}

fn statement(sql: &str, values: Vec<sea_orm::Value>) -> Statement {
    Statement::from_sql_and_values(DbBackend::Postgres, sql, values)
}

fn validate_digest(value: &VersionedDigest) -> Result<(), ApplicationError> {
    if value.key_version <= 0 {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(())
}

fn validate_generation(command: &CommitEmailGeneration) -> Result<(), ApplicationError> {
    validate_digest(&command.lookup_digest)?;
    if command.expected_generation < 1
        || command.expected_generation > 5
        || command.expires_at <= command.issued_at
        || command.expires_at > command.issued_at + time::Duration::minutes(10)
        || command.otp_digest.is_none() && command.magic_digest.is_none()
        || command.otp_digest.is_some() != command.otp_expires_at.is_some()
        || command.magic_digest.is_some() != command.magic_expires_at.is_some()
        || command.otp_expires_at.is_some_and(|expires_at| {
            expires_at <= command.issued_at || expires_at > command.expires_at
        })
        || command.magic_expires_at.is_some_and(|expires_at| {
            expires_at <= command.issued_at || expires_at > command.expires_at
        })
        || command.message_id.len() < 16
        || command.message_id.len() > 255
    {
        return Err(ApplicationError::InvalidInput);
    }
    if let Some(value) = &command.otp_digest {
        validate_digest(value)?;
    }
    if let Some(value) = &command.magic_digest {
        validate_digest(value)?;
    }
    Ok(())
}

fn require_stored_digest(
    row: &sea_orm::QueryResult,
    value_column: &str,
    version_column: &str,
    presented: &VersionedDigest,
) -> Result<(), ApplicationError> {
    let value: Option<Vec<u8>> = row.try_get("", value_column).map_err(persistence)?;
    let version: Option<i32> = row.try_get("", version_column).map_err(persistence)?;
    if version != Some(presented.key_version)
        || !value
            .as_deref()
            .is_some_and(|stored| bool::from(stored.ct_eq(presented.value.as_slice())))
    {
        return Err(ApplicationError::NotFound);
    }
    Ok(())
}

async fn lock_email_method_owners(
    transaction: &DatabaseTransaction,
    project_id: Uuid,
    application_id: Uuid,
) -> Result<(), ApplicationError> {
    transaction
        .query_one_raw(statement(
            "SELECT 1 FROM project_email_policies policy
             JOIN application_email_assignments assignment
               ON assignment.project_id=policy.project_id
              AND assignment.application_id=$2
             WHERE policy.project_id=$1
             FOR SHARE OF policy,assignment",
            vec![project_id.into(), application_id.into()],
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::RevisionConflict)?;
    Ok(())
}

async fn validate_email_confirmation_authority(
    transaction: &DatabaseTransaction,
    row: &sea_orm::QueryResult,
    command: &VerifyEmailProof,
) -> Result<(), ApplicationError> {
    if let Some(context) = &command.transfer_context {
        if command.proof_kind != EmailProofKind::MagicLink {
            return Err(ApplicationError::NotFound);
        }
        let transfer = transaction
            .query_one_raw(statement(
                "SELECT browser_binding_required FROM magic_transfer_contexts
             WHERE challenge_id=$1 AND context_digest=$2 AND context_digest_key_version=$3
               AND csrf_digest=$4 AND csrf_digest_key_version=$5
               AND status='pending' AND expires_at > $6 FOR UPDATE",
                vec![
                    command.challenge_id.into(),
                    context.value.to_vec().into(),
                    context.key_version.into(),
                    command.csrf.value.to_vec().into(),
                    command.csrf.key_version.into(),
                    command.now.into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let binding_required: bool = transfer
            .try_get("", "browser_binding_required")
            .map_err(persistence)?;
        if binding_required
            != row
                .try_get::<bool>("", "browser_binding_required")
                .map_err(persistence)?
        {
            return Err(ApplicationError::Integrity);
        }
        if binding_required && command.browser_binding.is_none() {
            return Err(ApplicationError::NotFound);
        }
        if let Some(binding) = &command.browser_binding {
            require_stored_digest(
                row,
                "browser_binding_digest",
                "browser_binding_digest_key_version",
                binding,
            )?;
        }
    } else {
        require_stored_digest(row, "csrf_digest", "csrf_digest_key_version", &command.csrf)?;
        let binding = command
            .browser_binding
            .as_ref()
            .ok_or(ApplicationError::NotFound)?;
        require_stored_digest(
            row,
            "browser_binding_digest",
            "browser_binding_digest_key_version",
            binding,
        )?;
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "proof revalidation keeps Project readiness and exact SMTP authority predicates visible"
)]
async fn revalidate_policy_and_smtp(
    transaction: &sea_orm::DatabaseTransaction,
    row: &sea_orm::QueryResult,
    project_id: Uuid,
    now: OffsetDateTime,
    runtime_process_id: &str,
    runtime_incarnation: Uuid,
    required_runtime_process_ids: &[String],
) -> Result<(), ApplicationError> {
    let local_runtime_is_current = transaction
        .query_one_raw(statement(
            "SELECT 1 FROM runtime_process_incarnations
             WHERE process_id=$1 AND process_incarnation=$2",
            vec![
                runtime_process_id.to_owned().into(),
                runtime_incarnation.into(),
            ],
        ))
        .await
        .map_err(persistence)?
        .is_some();
    if !local_runtime_is_current {
        return Err(ApplicationError::Disabled);
    }
    // Match the provider path's authority order: the already-locked login is fenced by its
    // captured Project and Application revisions before method policy or SMTP is consulted.
    let owners = transaction.query_one_raw(statement(
        "SELECT project.status AS project_status,project.metadata_revision AS project_metadata_revision,
                project.security_revision AS project_security_revision,
                application.status AS application_status,
                application.security_revision AS application_security_revision
         FROM projects project JOIN applications application ON application.project_id=project.id
         WHERE project.id=$1 AND application.id=$2 FOR SHARE OF project,application",
        vec![project_id.into(), row.try_get::<Uuid>("", "application_id").map_err(persistence)?.into()],
    )).await.map_err(persistence)?.ok_or(ApplicationError::RevisionConflict)?;
    if owners
        .try_get::<String>("", "project_status")
        .map_err(persistence)?
        != "active"
        || owners
            .try_get::<i64>("", "project_metadata_revision")
            .map_err(persistence)?
            != row
                .try_get::<i64>("", "project_metadata_revision")
                .map_err(persistence)?
        || owners
            .try_get::<i64>("", "project_security_revision")
            .map_err(persistence)?
            != row
                .try_get::<i64>("", "project_security_revision")
                .map_err(persistence)?
        || owners
            .try_get::<String>("", "application_status")
            .map_err(persistence)?
            != "active"
        || owners
            .try_get::<i64>("", "application_security_revision")
            .map_err(persistence)?
            != row
                .try_get::<i64>("", "application_security_revision")
                .map_err(persistence)?
    {
        return Err(ApplicationError::RevisionConflict);
    }
    let policy = transaction.query_one_raw(statement(
        "SELECT policy.policy_revision, policy.security_revision, assignment.security_revision AS assignment_security_revision
         FROM project_email_policies policy JOIN application_email_assignments assignment ON assignment.project_id = policy.project_id
         WHERE policy.project_id = $1 AND assignment.application_id = $2 AND policy.status = 'enabled' AND assignment.status = 'active'
         FOR SHARE OF policy,assignment",
        vec![project_id.into(), row.try_get::<Uuid>("", "application_id").map_err(persistence)?.into()],
    )).await.map_err(persistence)?.ok_or(ApplicationError::RevisionConflict)?;
    if policy
        .try_get::<i64>("", "policy_revision")
        .map_err(persistence)?
        != row
            .try_get::<i64>("", "method_policy_revision")
            .map_err(persistence)?
        || policy
            .try_get::<i64>("", "security_revision")
            .map_err(persistence)?
            != row
                .try_get::<i64>("", "method_security_revision")
                .map_err(persistence)?
        || policy
            .try_get::<i64>("", "assignment_security_revision")
            .map_err(persistence)?
            != row
                .try_get::<i64>("", "assignment_security_revision")
                .map_err(persistence)?
    {
        return Err(ApplicationError::RevisionConflict);
    }
    let selection: String = row
        .try_get("", "smtp_selection_kind")
        .map_err(persistence)?;
    let generation: i32 = row.try_get("", "smtp_generation").map_err(persistence)?;
    let revision: i64 = row
        .try_get("", "smtp_security_eligibility_revision")
        .map_err(persistence)?;
    let eligible = if selection == "project" {
        transaction
            .query_one_raw(statement(
                "SELECT 1 FROM project_smtp_configurations smtp
             WHERE smtp.project_id = $1 AND smtp.id = $2 AND smtp.generation = $3
             AND smtp.security_eligibility_revision = $4
             AND (smtp.status = 'active' OR (smtp.status = 'retained' AND smtp.retained_until > $5))
             AND NOT EXISTS (
               SELECT required.process_id
               FROM jsonb_array_elements_text($6::jsonb) AS required(process_id)
               WHERE NOT EXISTS (
                 SELECT 1 FROM project_smtp_runtime_readiness readiness
                 WHERE readiness.project_id=smtp.project_id
                   AND readiness.configuration_id=smtp.id
                   AND readiness.generation=smtp.generation
                   AND readiness.process_id=required.process_id
                   AND readiness.state='ready'
                   AND readiness.lease_expires_at>$5
                   AND EXISTS (
                     SELECT 1 FROM runtime_process_incarnations current
                     WHERE current.process_id=readiness.process_id
                       AND current.process_incarnation=readiness.process_incarnation)))
             FOR SHARE OF smtp",
                vec![
                    project_id.into(),
                    row.try_get::<Option<Uuid>>("", "smtp_configuration_id")
                        .map_err(persistence)?
                        .into(),
                    generation.into(),
                    revision.into(),
                    now.into(),
                    serde_json::json!(required_runtime_process_ids).into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .is_some()
    } else {
        transaction.query_one_raw(statement(
            "SELECT 1 FROM deployment_smtp_generations WHERE generation = $1 AND security_eligibility_revision = $2
             AND (status = 'active' OR (status = 'retained' AND retained_until > $3)) FOR SHARE",
            vec![generation.into(), revision.into(), now.into()],
        )).await.map_err(persistence)?.is_some()
    };
    if !eligible {
        return Err(ApplicationError::Disabled);
    }
    Ok(())
}

fn persistence<E: std::fmt::Display>(_error: E) -> ApplicationError {
    ApplicationError::Persistence
}

async fn database_clock(
    transaction: &DatabaseTransaction,
) -> Result<OffsetDateTime, ApplicationError> {
    transaction
        .query_one_raw(statement("SELECT clock_timestamp() AS now", vec![]))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Persistence)?
        .try_get("", "now")
        .map_err(persistence)
}

#[allow(
    clippy::too_many_lines,
    reason = "the login mail claim keeps its canonical authority lock order contiguous"
)]
async fn claim_due_login_mail(
    repository: &PostgresPasswordlessEmailRepository,
    transaction: &DatabaseTransaction,
    worker: &str,
    now: OffsetDateTime,
    lease_millis: i64,
    selected_id: Uuid,
) -> Result<Option<crate::application::ClaimedMailJob>, ApplicationError> {
    // Candidate discovery is intentionally non-authoritative. Every owner and child row is
    // reloaded under the same transaction in the canonical login -> Project/Application ->
    // policy/assignment -> challenge -> SMTP -> outbox order before the lease mutates.
    let candidate = transaction
            .query_one_raw(statement(
                "SELECT outbox.id,outbox.project_id,outbox.transaction_id,outbox.challenge_id
                 FROM mail_outbox outbox
                 JOIN email_challenges challenge ON challenge.project_id=outbox.project_id
                   AND challenge.id=outbox.challenge_id
                 JOIN login_transactions login ON login.project_id=outbox.project_id
                   AND login.id=outbox.transaction_id
                 JOIN projects project ON project.id=login.project_id
                 JOIN applications application ON application.project_id=login.project_id
                   AND application.id=login.application_id
                 JOIN project_email_policies policy ON policy.project_id=login.project_id
                 JOIN application_email_assignments assignment ON assignment.project_id=login.project_id
                   AND assignment.application_id=login.application_id
                 LEFT JOIN project_smtp_configurations project_smtp
                   ON outbox.smtp_selection_kind='project'
                  AND project_smtp.project_id=outbox.project_id
                  AND project_smtp.id=outbox.smtp_configuration_id
                  AND project_smtp.generation=outbox.smtp_generation
                  AND project_smtp.security_eligibility_revision=outbox.smtp_security_eligibility_revision
                 LEFT JOIN deployment_smtp_generations deployment_smtp
                   ON outbox.smtp_selection_kind='deployment_default'
                  AND deployment_smtp.generation=outbox.smtp_generation
                  AND deployment_smtp.security_eligibility_revision=outbox.smtp_security_eligibility_revision
                 WHERE (outbox.status IN ('pending','retry','ambiguous')
                        OR (outbox.status='leased' AND outbox.lease_expires_at <= clock_timestamp()))
                   AND outbox.attempts < outbox.max_attempts
                   AND outbox.next_attempt_at <= $1 AND outbox.useful_until > $1
                   AND outbox.id=$5
                   AND login.status='email_challenge_pending' AND login.expires_at>$1
                   AND project.status='active'
                   AND project.metadata_revision=login.project_metadata_revision
                   AND project.security_revision=login.project_security_revision
                   AND application.status='active'
                   AND application.security_revision=login.application_security_revision
                   AND policy.status='enabled'
                   AND policy.policy_revision=challenge.method_policy_revision
                   AND policy.security_revision=challenge.method_security_revision
                   AND assignment.status='active'
                   AND assignment.security_revision=challenge.assignment_security_revision
                   AND challenge.status='pending' AND challenge.expires_at>$1
                   AND NOT EXISTS (SELECT 1 FROM email_challenges newer
                     WHERE newer.project_id=challenge.project_id
                       AND newer.transaction_id=challenge.transaction_id
                       AND newer.generation>challenge.generation)
                   AND EXISTS (
                     SELECT 1 FROM runtime_process_incarnations local_runtime
                     WHERE local_runtime.process_id=$3
                       AND local_runtime.process_incarnation=$4)
                   AND ((outbox.smtp_selection_kind='project'
                         AND (project_smtp.status='active' OR
                              (project_smtp.status='retained' AND project_smtp.retained_until>$1))
                         AND NOT EXISTS (
                           SELECT required.process_id
                           FROM jsonb_array_elements_text($2::jsonb) AS required(process_id)
                           WHERE NOT EXISTS (
                             SELECT 1 FROM project_smtp_runtime_readiness readiness
                             WHERE readiness.project_id=project_smtp.project_id
                               AND readiness.configuration_id=project_smtp.id
                               AND readiness.generation=project_smtp.generation
                               AND readiness.process_id=required.process_id
                               AND readiness.state='ready'
                               AND readiness.lease_expires_at>$1
                               AND EXISTS (
                                 SELECT 1 FROM runtime_process_incarnations current
                                 WHERE current.process_id=readiness.process_id
                                   AND current.process_incarnation=readiness.process_incarnation))))
                     OR (outbox.smtp_selection_kind='deployment_default'
                         AND (deployment_smtp.status='active' OR
                              (deployment_smtp.status='retained' AND deployment_smtp.retained_until>$1))))
                 ORDER BY outbox.next_attempt_at,outbox.id LIMIT 1",
                vec![
                    now.into(),
                    repository.runtime_roster_json().into(),
                    repository.runtime_process_id.clone().into(),
                    repository.runtime_incarnation.into(),
                    selected_id.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
    let Some(candidate) = candidate else {
        return Ok(None);
    };
    let id: Uuid = candidate.try_get("", "id").map_err(persistence)?;
    let project_id: Uuid = candidate.try_get("", "project_id").map_err(persistence)?;
    let transaction_id: Uuid = candidate
        .try_get("", "transaction_id")
        .map_err(persistence)?;
    let challenge_id: Uuid = candidate.try_get("", "challenge_id").map_err(persistence)?;

    // A shared login lock serializes a claim against resend/supersession, proof completion,
    // and login terminalization. A claim that wins this lock may finish physically; a later
    // state transition waits until the lease commit, exactly matching the external-I/O rule.
    let login = transaction
        .query_one_raw(statement(
            "SELECT application_id,status,expires_at,project_metadata_revision,
                        project_security_revision,application_security_revision
                 FROM login_transactions WHERE project_id=$1 AND id=$2 FOR SHARE",
            vec![project_id.into(), transaction_id.into()],
        ))
        .await
        .map_err(persistence)?;
    let Some(login) = login else {
        return Ok(None);
    };
    let application_id: Uuid = login.try_get("", "application_id").map_err(persistence)?;
    if login.try_get::<String>("", "status").map_err(persistence)? != "email_challenge_pending"
        || login
            .try_get::<OffsetDateTime>("", "expires_at")
            .map_err(persistence)?
            <= now
    {
        return Ok(None);
    }

    let owners = transaction
        .query_one_raw(statement(
            "SELECT project.status AS project_status,
                        project.metadata_revision AS project_metadata_revision,
                        project.security_revision AS project_security_revision,
                        application.status AS application_status,
                        application.security_revision AS application_security_revision
                 FROM projects project JOIN applications application
                   ON application.project_id=project.id
                 WHERE project.id=$1 AND application.id=$2
                 FOR SHARE OF project,application",
            vec![project_id.into(), application_id.into()],
        ))
        .await
        .map_err(persistence)?;
    let owners_current = owners.as_ref().is_some_and(|owners| {
        owners
            .try_get::<String>("", "project_status")
            .ok()
            .as_deref()
            == Some("active")
            && owners.try_get::<i64>("", "project_metadata_revision").ok()
                == login.try_get::<i64>("", "project_metadata_revision").ok()
            && owners.try_get::<i64>("", "project_security_revision").ok()
                == login.try_get::<i64>("", "project_security_revision").ok()
            && owners
                .try_get::<String>("", "application_status")
                .ok()
                .as_deref()
                == Some("active")
            && owners
                .try_get::<i64>("", "application_security_revision")
                .ok()
                == login
                    .try_get::<i64>("", "application_security_revision")
                    .ok()
    });
    if !owners_current {
        return Ok(None);
    }

    let policy = transaction
        .query_one_raw(statement(
            "SELECT policy.status AS policy_status,policy.policy_revision,
                        policy.security_revision AS method_security_revision,
                        assignment.status AS assignment_status,
                        assignment.security_revision AS assignment_security_revision
                 FROM project_email_policies policy
                 JOIN application_email_assignments assignment
                   ON assignment.project_id=policy.project_id
                 WHERE policy.project_id=$1 AND assignment.application_id=$2
                 FOR SHARE OF policy,assignment",
            vec![project_id.into(), application_id.into()],
        ))
        .await
        .map_err(persistence)?;
    let Some(policy) = policy else {
        return Ok(None);
    };

    let challenge = transaction
        .query_one_raw(statement(
            "SELECT challenge.*,
                        (SELECT MAX(newest.generation)::SMALLINT FROM email_challenges newest
                         WHERE newest.project_id=challenge.project_id
                           AND newest.transaction_id=challenge.transaction_id) AS newest_generation
                 FROM email_challenges challenge
                 WHERE challenge.project_id=$1 AND challenge.transaction_id=$2 AND challenge.id=$3
                 FOR SHARE OF challenge",
            vec![
                project_id.into(),
                transaction_id.into(),
                challenge_id.into(),
            ],
        ))
        .await
        .map_err(persistence)?;
    let Some(challenge) = challenge else {
        return Ok(None);
    };
    let policy_current = policy
        .try_get::<String>("", "policy_status")
        .map_err(persistence)?
        == "enabled"
        && policy
            .try_get::<String>("", "assignment_status")
            .map_err(persistence)?
            == "active"
        && policy
            .try_get::<i64>("", "policy_revision")
            .map_err(persistence)?
            == challenge
                .try_get::<i64>("", "method_policy_revision")
                .map_err(persistence)?
        && policy
            .try_get::<i64>("", "method_security_revision")
            .map_err(persistence)?
            == challenge
                .try_get::<i64>("", "method_security_revision")
                .map_err(persistence)?
        && policy
            .try_get::<i64>("", "assignment_security_revision")
            .map_err(persistence)?
            == challenge
                .try_get::<i64>("", "assignment_security_revision")
                .map_err(persistence)?;
    let challenge_current = challenge
        .try_get::<String>("", "status")
        .map_err(persistence)?
        == "pending"
        && challenge
            .try_get::<OffsetDateTime>("", "expires_at")
            .map_err(persistence)?
            > now
        && challenge
            .try_get::<i16>("", "generation")
            .map_err(persistence)?
            == challenge
                .try_get::<i16>("", "newest_generation")
                .map_err(persistence)?;
    if !policy_current || !challenge_current {
        return Ok(None);
    }

    let selection: String = challenge
        .try_get("", "smtp_selection_kind")
        .map_err(persistence)?;
    let smtp_configuration_id: Option<Uuid> = challenge
        .try_get("", "smtp_configuration_id")
        .map_err(persistence)?;
    let smtp_generation: i32 = challenge
        .try_get("", "smtp_generation")
        .map_err(persistence)?;
    let smtp_security_revision: i64 = challenge
        .try_get("", "smtp_security_eligibility_revision")
        .map_err(persistence)?;
    let smtp = if selection == "project" {
        transaction
                .query_one_raw(statement(
                    "SELECT smtp.host,smtp.port,smtp.tls_mode,smtp.sender_address,
                            smtp.sender_name,smtp.reply_to,smtp.credential_ref,smtp.safe_fingerprint,
                            '[]'::jsonb AS allowed_private_ips,smtp.status,smtp.retained_until,
                            smtp.security_eligibility_revision
                     FROM project_smtp_configurations smtp
                     WHERE smtp.project_id=$1 AND smtp.id=$2 AND smtp.generation=$3
                       AND NOT EXISTS (
                         SELECT required.process_id
                         FROM jsonb_array_elements_text($4::jsonb) AS required(process_id)
                         WHERE NOT EXISTS (
                           SELECT 1 FROM project_smtp_runtime_readiness readiness
                           WHERE readiness.project_id=smtp.project_id
                             AND readiness.configuration_id=smtp.id
                             AND readiness.generation=smtp.generation
                             AND readiness.process_id=required.process_id
                             AND readiness.state='ready'
                             AND readiness.lease_expires_at>$5
                             AND EXISTS (
                               SELECT 1 FROM runtime_process_incarnations current
                               WHERE current.process_id=readiness.process_id
                                 AND current.process_incarnation=readiness.process_incarnation)))
                     FOR SHARE OF smtp",
                    vec![
                        project_id.into(),
                        smtp_configuration_id.into(),
                        smtp_generation.into(),
                        repository.runtime_roster_json().into(),
                        now.into(),
                    ],
                ))
                .await
                .map_err(persistence)?
    } else if selection == "deployment_default" && smtp_configuration_id.is_none() {
        // Generation insertion/activation uses the conflicting exclusive advisory lock;
        // compromise/disable conflicts on the exact row lock below.
        transaction
                .execute_raw(statement(
                    "SELECT pg_advisory_xact_lock_shared(hashtextextended('owlauth:deployment-smtp',0))",
                    vec![],
                ))
                .await
                .map_err(persistence)?;
        transaction
                .query_one_raw(statement(
                    "SELECT smtp.host,smtp.port,smtp.tls_mode,smtp.sender_address,
                            NULL::TEXT AS sender_name,NULL::TEXT AS reply_to,smtp.credential_ref,
                            smtp.safe_fingerprint,smtp.explicitly_allowed_private_ips AS allowed_private_ips,
                            smtp.status,smtp.retained_until,smtp.security_eligibility_revision
                     FROM deployment_smtp_generations smtp WHERE smtp.generation=$1
                     FOR SHARE OF smtp",
                    vec![smtp_generation.into()],
                ))
                .await
                .map_err(persistence)?
    } else {
        None
    };
    let Some(smtp) = smtp else {
        return Ok(None);
    };
    let smtp_status: String = smtp.try_get("", "status").map_err(persistence)?;
    let smtp_retained_until: Option<OffsetDateTime> =
        smtp.try_get("", "retained_until").map_err(persistence)?;
    let smtp_is_eligible = smtp_status == "active"
        || (smtp_status == "retained" && smtp_retained_until.is_some_and(|until| until > now));
    if !smtp_is_eligible
        || smtp
            .try_get::<i64>("", "security_eligibility_revision")
            .map_err(persistence)?
            != smtp_security_revision
    {
        return Ok(None);
    }

    // Only after every authority fence has succeeded do we lock/reload the outbox and make
    // the sole lease mutation. All failed paths above leave attempt, lease, login, and proof
    // state byte-for-byte unchanged.
    let row = transaction
            .query_one_raw(statement(
                "SELECT outbox.*,$2::TEXT AS host,$3::INTEGER AS port,$4::TEXT AS tls_mode,
                        $5::TEXT AS sender_address,$6::TEXT AS sender_name,$7::TEXT AS reply_to,
                        $8::TEXT AS credential_ref,$9::JSONB AS allowed_private_ips,
                        NULL::UUID AS identity_mutation_intent_id,
                        NULL::UUID AS identity_mutation_proof_slot_id
                 FROM mail_outbox outbox
                 WHERE outbox.id=$1 AND outbox.project_id=$10 AND outbox.transaction_id=$11
                   AND outbox.challenge_id=$12
                   AND outbox.challenge_generation=$13
                   AND outbox.smtp_selection_kind=$14
                   AND outbox.smtp_configuration_id IS NOT DISTINCT FROM $15
                   AND outbox.smtp_generation=$16
                   AND outbox.smtp_security_eligibility_revision=$17
                   AND (outbox.status IN ('pending','retry','ambiguous')
                        OR (outbox.status='leased' AND outbox.lease_expires_at <= clock_timestamp()))
                   AND outbox.attempts < outbox.max_attempts
                   AND outbox.next_attempt_at <= $18 AND outbox.useful_until > $18
                 FOR UPDATE OF outbox",
                vec![
                    id.into(),
                    smtp.try_get::<String>("", "host")
                        .map_err(persistence)?
                        .into(),
                    smtp.try_get::<i32>("", "port").map_err(persistence)?.into(),
                    smtp.try_get::<String>("", "tls_mode")
                        .map_err(persistence)?
                        .into(),
                    smtp.try_get::<String>("", "sender_address")
                        .map_err(persistence)?
                        .into(),
                    smtp.try_get::<Option<String>>("", "sender_name")
                        .map_err(persistence)?
                        .into(),
                    smtp.try_get::<Option<String>>("", "reply_to")
                        .map_err(persistence)?
                        .into(),
                    smtp.try_get::<String>("", "credential_ref")
                        .map_err(persistence)?
                        .into(),
                    smtp.try_get::<serde_json::Value>("", "allowed_private_ips")
                        .map_err(persistence)?
                        .into(),
                    project_id.into(),
                    transaction_id.into(),
                    challenge_id.into(),
                    challenge
                        .try_get::<i16>("", "generation")
                        .map_err(persistence)?
                        .into(),
                    selection.into(),
                    smtp_configuration_id.into(),
                    smtp_generation.into(),
                    smtp_security_revision.into(),
                    now.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
    let Some(row) = row else {
        return Ok(None);
    };

    // The outbox lock may have waited across any clock-governed authority deadline. Use a
    // fresh PostgreSQL clock and rerun the same fully-eligible global comparison while all
    // canonical owner/configuration locks are still held. This covers login/challenge expiry,
    // retained SMTP and readiness leases, revisions, supersession, and outbox usefulness.
    let final_now = database_clock(transaction).await?;
    repository
        .assert_email_protection_ready(transaction)
        .await?;
    if identity_mutation_is_earliest_due(repository, transaction, final_now).await?
        != Some((id, false))
    {
        return Ok(None);
    }
    let claimed = transaction
        .query_one_raw(statement(
            "UPDATE mail_outbox SET status='leased',lease_owner=$2,
                    lease_expires_at=clock_timestamp()+($3*interval '1 millisecond'),
                    attempts=attempts+1,updated_at=clock_timestamp()
             WHERE id=$1 AND (status IN ('pending','retry','ambiguous')
               OR (status='leased' AND lease_expires_at <= clock_timestamp()))
               AND attempts<max_attempts AND next_attempt_at<=clock_timestamp()
               AND useful_until>clock_timestamp()
             RETURNING lease_expires_at",
            vec![id.into(), worker.to_owned().into(), lease_millis.into()],
        ))
        .await
        .map_err(persistence)?;
    let Some(claimed) = claimed else {
        return Ok(None);
    };
    let lease_expires_at = claimed
        .try_get("", "lease_expires_at")
        .map_err(persistence)?;
    let safe_fingerprint = smtp
        .try_get::<Vec<u8>>("", "safe_fingerprint")
        .map_err(persistence)?
        .try_into()
        .map_err(|_| ApplicationError::Integrity)?;
    let result = claimed_mail_job(&row, id, worker, lease_expires_at, safe_fingerprint)?;
    Ok(Some(result))
}

/// Chooses the typed owner queue using the same durable due-order keys used by both claim paths.
/// This discovery is deliberately non-authoritative; each selected path still revalidates every
/// frozen owner and child under locks before leasing.
#[allow(
    clippy::too_many_lines,
    reason = "the single SQL statement must compare both lanes under one fully eligible global order"
)]
async fn identity_mutation_is_earliest_due(
    repository: &PostgresPasswordlessEmailRepository,
    transaction: &DatabaseTransaction,
    now: OffsetDateTime,
) -> Result<Option<(Uuid, bool)>, ApplicationError> {
    let owner = transaction
        .query_one_raw(statement(
            "SELECT outbox.id,challenge.owner_kind
               FROM mail_outbox outbox
               JOIN email_challenges challenge ON challenge.project_id=outbox.project_id
                AND challenge.id=outbox.challenge_id
              WHERE outbox.challenge_generation=challenge.generation
                AND (outbox.status IN ('pending','retry','ambiguous')
                    OR (outbox.status='leased' AND outbox.lease_expires_at<=clock_timestamp()))
                AND outbox.attempts<outbox.max_attempts
                AND outbox.next_attempt_at<=$1 AND outbox.useful_until>$1
                AND challenge.status='pending' AND challenge.expires_at>$1
                AND ((challenge.owner_kind='login' AND outbox.transaction_id IS NOT NULL
                      AND EXISTS (SELECT 1 FROM login_transactions login
                        JOIN projects project ON project.id=login.project_id
                        JOIN applications application ON application.project_id=login.project_id
                         AND application.id=login.application_id
                        JOIN project_email_policies policy ON policy.project_id=login.project_id
                        JOIN application_email_assignments assignment
                          ON assignment.project_id=login.project_id
                         AND assignment.application_id=login.application_id
                        WHERE login.project_id=outbox.project_id
                          AND login.id=outbox.transaction_id
                          AND login.status='email_challenge_pending' AND login.expires_at>$1
                          AND project.status='active'
                          AND project.metadata_revision=login.project_metadata_revision
                          AND project.security_revision=login.project_security_revision
                          AND application.status='active'
                          AND application.security_revision=login.application_security_revision
                          AND policy.status='enabled'
                          AND policy.policy_revision=challenge.method_policy_revision
                          AND policy.security_revision=challenge.method_security_revision
                          AND assignment.status='active'
                          AND assignment.security_revision=challenge.assignment_security_revision)
                      AND NOT EXISTS (SELECT 1 FROM email_challenges newer
                        WHERE newer.owner_kind='login'
                          AND newer.project_id=challenge.project_id
                          AND newer.transaction_id=challenge.transaction_id
                          AND newer.generation>challenge.generation))
                  OR (challenge.owner_kind='identity_mutation' AND outbox.transaction_id IS NULL
                      AND EXISTS (SELECT 1 FROM identity_mutation_intents intent
                        JOIN identity_mutation_proof_slots slot
                          ON slot.project_id=intent.project_id AND slot.intent_id=intent.id
                         AND slot.id=challenge.identity_mutation_proof_slot_id
                        JOIN projects project ON project.id=intent.project_id
                        JOIN applications application ON application.project_id=intent.project_id
                         AND application.id=challenge.application_id
                        JOIN project_email_policies policy ON policy.project_id=intent.project_id
                        JOIN application_email_assignments assignment
                          ON assignment.project_id=intent.project_id
                         AND assignment.application_id=challenge.application_id
                        WHERE intent.project_id=challenge.project_id
                          AND intent.id=challenge.identity_mutation_intent_id
                          AND intent.status='pending_proof' AND intent.expires_at>$1
                          AND NOT EXISTS (SELECT 1 FROM identity_proof_receipts receipt
                            WHERE receipt.project_id=intent.project_id
                              AND receipt.intent_id=intent.id AND receipt.expires_at<=$1)
                          AND slot.state='email_challenge_pending'
                          AND project.status='active'
                          AND project.metadata_revision=intent.project_metadata_revision
                          AND project.security_revision=intent.project_security_revision
                          AND application.status='active'
                          AND application.security_revision=slot.application_security_revision
                          AND policy.status='enabled'
                          AND policy.policy_revision=challenge.method_policy_revision
                          AND policy.security_revision=challenge.method_security_revision
                          AND assignment.status='active'
                          AND assignment.security_revision=challenge.assignment_security_revision)
                      AND NOT EXISTS (SELECT 1 FROM email_challenges newer
                        WHERE newer.owner_kind='identity_mutation'
                          AND newer.project_id=challenge.project_id
                          AND newer.identity_mutation_intent_id=challenge.identity_mutation_intent_id
                          AND newer.identity_mutation_proof_slot_id=challenge.identity_mutation_proof_slot_id
                          AND newer.generation>challenge.generation)))
                AND ((outbox.smtp_selection_kind='project' AND EXISTS (
                       SELECT 1 FROM project_smtp_configurations smtp
                        WHERE smtp.project_id=outbox.project_id
                          AND smtp.id=outbox.smtp_configuration_id
                          AND smtp.generation=outbox.smtp_generation
                          AND smtp.security_eligibility_revision=outbox.smtp_security_eligibility_revision
                          AND (smtp.status='active' OR
                               (smtp.status='retained' AND smtp.retained_until>$1))
                          AND NOT EXISTS (
                            SELECT required.process_id
                              FROM jsonb_array_elements_text($2::jsonb) required(process_id)
                             WHERE NOT EXISTS (
                               SELECT 1 FROM project_smtp_runtime_readiness readiness
                               JOIN runtime_process_incarnations current
                                 ON current.process_id=readiness.process_id
                                AND current.process_incarnation=readiness.process_incarnation
                              WHERE readiness.project_id=smtp.project_id
                                AND readiness.configuration_id=smtp.id
                                AND readiness.generation=smtp.generation
                                AND readiness.process_id=required.process_id
                                AND readiness.state='ready'
                                AND readiness.lease_expires_at>$1))))
                  OR (outbox.smtp_selection_kind='deployment_default'
                      AND outbox.smtp_configuration_id IS NULL AND EXISTS (
                       SELECT 1 FROM deployment_smtp_generations smtp
                        WHERE smtp.generation=outbox.smtp_generation
                          AND smtp.security_eligibility_revision=outbox.smtp_security_eligibility_revision
                          AND (smtp.status='active' OR
                               (smtp.status='retained' AND smtp.retained_until>$1)))))
              ORDER BY outbox.next_attempt_at,outbox.id LIMIT 1",
            vec![now.into(), repository.runtime_roster_json().into()],
        ))
        .await
        .map_err(persistence)?;
    owner
        .map(|row| {
            let id = row.try_get::<Uuid>("", "id").map_err(persistence)?;
            let kind = row
                .try_get::<String>("", "owner_kind")
                .map_err(persistence)?;
            Ok((id, kind == "identity_mutation"))
        })
        .transpose()
}

/// Claims mutation-owned mail under its typed intent/slot authority. Mutation challenges have no
/// login transaction by design, so the ordinary login-owned worker path cannot safely infer their
/// owner. The Runtime-incarnation and email-protection fences are already held by the caller.
#[allow(
    clippy::too_many_lines,
    reason = "the typed mail claim keeps its canonical lock and authority revalidation order contiguous"
)]
async fn claim_due_identity_mutation_mail(
    repository: &PostgresPasswordlessEmailRepository,
    transaction: &DatabaseTransaction,
    worker: &str,
    now: OffsetDateTime,
    lease_millis: i64,
    selected_id: Uuid,
) -> Result<Option<crate::application::ClaimedMailJob>, ApplicationError> {
    let candidate = transaction
        .query_one_raw(statement(
            "SELECT outbox.id,outbox.project_id,outbox.challenge_id,
                    challenge.identity_mutation_intent_id AS intent_id,
                    challenge.identity_mutation_proof_slot_id AS slot_id,
                    challenge.application_id
               FROM mail_outbox outbox
               JOIN email_challenges challenge ON challenge.project_id=outbox.project_id
                AND challenge.id=outbox.challenge_id
               JOIN identity_mutation_intents intent ON intent.project_id=challenge.project_id
                AND intent.id=challenge.identity_mutation_intent_id
               JOIN identity_mutation_proof_slots slot ON slot.project_id=challenge.project_id
                AND slot.intent_id=challenge.identity_mutation_intent_id
                AND slot.id=challenge.identity_mutation_proof_slot_id
               JOIN projects project ON project.id=intent.project_id
               JOIN applications application ON application.project_id=intent.project_id
                AND application.id=challenge.application_id
               JOIN project_email_policies policy ON policy.project_id=intent.project_id
               JOIN application_email_assignments assignment ON assignment.project_id=intent.project_id
                AND assignment.application_id=challenge.application_id
               LEFT JOIN project_smtp_configurations project_smtp
                 ON outbox.smtp_selection_kind='project'
                AND project_smtp.project_id=outbox.project_id
                AND project_smtp.id=outbox.smtp_configuration_id
                AND project_smtp.generation=outbox.smtp_generation
                AND project_smtp.security_eligibility_revision=outbox.smtp_security_eligibility_revision
               LEFT JOIN deployment_smtp_generations deployment_smtp
                 ON outbox.smtp_selection_kind='deployment_default'
                AND deployment_smtp.generation=outbox.smtp_generation
                AND deployment_smtp.security_eligibility_revision=outbox.smtp_security_eligibility_revision
              WHERE challenge.owner_kind='identity_mutation' AND outbox.transaction_id IS NULL
                AND outbox.id=$3
                AND challenge.status='pending' AND challenge.expires_at>$1
                AND intent.status='pending_proof' AND intent.expires_at>$1
                AND NOT EXISTS (SELECT 1 FROM identity_proof_receipts receipt
                  WHERE receipt.project_id=intent.project_id AND receipt.intent_id=intent.id
                    AND receipt.expires_at<=$1)
                AND slot.state='email_challenge_pending'
                AND project.status='active'
                AND project.metadata_revision=intent.project_metadata_revision
                AND project.security_revision=intent.project_security_revision
                AND application.status='active'
                AND application.security_revision=slot.application_security_revision
                AND policy.status='enabled'
                AND policy.policy_revision=challenge.method_policy_revision
                AND policy.security_revision=challenge.method_security_revision
                AND assignment.status='active'
                AND assignment.security_revision=challenge.assignment_security_revision
                AND ((outbox.smtp_selection_kind='project'
                      AND (project_smtp.status='active' OR
                           (project_smtp.status='retained' AND project_smtp.retained_until>$1))
                      AND NOT EXISTS (
                        SELECT required.process_id
                          FROM jsonb_array_elements_text($2::jsonb) required(process_id)
                         WHERE NOT EXISTS (
                           SELECT 1 FROM project_smtp_runtime_readiness readiness
                            JOIN runtime_process_incarnations current
                              ON current.process_id=readiness.process_id
                             AND current.process_incarnation=readiness.process_incarnation
                           WHERE readiness.project_id=project_smtp.project_id
                             AND readiness.configuration_id=project_smtp.id
                             AND readiness.generation=project_smtp.generation
                             AND readiness.process_id=required.process_id
                             AND readiness.state='ready' AND readiness.lease_expires_at>$1)))
                     OR (outbox.smtp_selection_kind='deployment_default'
                      AND outbox.smtp_configuration_id IS NULL
                      AND (deployment_smtp.status='active' OR
                           (deployment_smtp.status='retained' AND deployment_smtp.retained_until>$1))))
                AND NOT EXISTS (SELECT 1 FROM email_challenges newer
                  WHERE newer.owner_kind='identity_mutation'
                    AND newer.project_id=challenge.project_id
                    AND newer.identity_mutation_intent_id=challenge.identity_mutation_intent_id
                    AND newer.identity_mutation_proof_slot_id=challenge.identity_mutation_proof_slot_id
                    AND newer.generation>challenge.generation)
                AND (outbox.status IN ('pending','retry','ambiguous')
                     OR (outbox.status='leased' AND outbox.lease_expires_at<=clock_timestamp()))
                AND outbox.attempts<outbox.max_attempts AND outbox.next_attempt_at<=$1
                AND outbox.useful_until>$1
              ORDER BY outbox.next_attempt_at,outbox.id LIMIT 1",
            vec![
                now.into(),
                repository.runtime_roster_json().into(),
                selected_id.into(),
            ],
        ))
        .await
        .map_err(persistence)?;
    let Some(candidate) = candidate else {
        return Ok(None);
    };
    let id: Uuid = candidate.try_get("", "id").map_err(persistence)?;
    let project_id: Uuid = candidate.try_get("", "project_id").map_err(persistence)?;
    let challenge_id: Uuid = candidate.try_get("", "challenge_id").map_err(persistence)?;
    let intent_id: Uuid = candidate.try_get("", "intent_id").map_err(persistence)?;
    let slot_id: Uuid = candidate.try_get("", "slot_id").map_err(persistence)?;
    let application_id: Uuid = candidate
        .try_get("", "application_id")
        .map_err(persistence)?;

    let intent = transaction
        .query_one_raw(statement(
            "SELECT * FROM identity_mutation_intents
              WHERE project_id=$1 AND id=$2 FOR UPDATE",
            vec![project_id.into(), intent_id.into()],
        ))
        .await
        .map_err(persistence)?;
    let Some(intent) = intent else {
        return Ok(None);
    };
    if expire_locked_if_needed(transaction, &intent).await?
        || intent
            .try_get::<String>("", "status")
            .map_err(persistence)?
            != "pending_proof"
    {
        return Ok(None);
    }
    let owners = transaction
        .query_one_raw(statement(
            "SELECT project.status AS project_status,project.metadata_revision,
                    project.security_revision,application.status AS application_status,
                    application.security_revision AS application_security_revision
               FROM projects project JOIN applications application
                 ON application.project_id=project.id
              WHERE project.id=$1 AND application.id=$2 FOR SHARE OF project,application",
            vec![project_id.into(), application_id.into()],
        ))
        .await
        .map_err(persistence)?;
    let Some(owners) = owners else {
        return Ok(None);
    };
    if owners
        .try_get::<String>("", "project_status")
        .map_err(persistence)?
        != "active"
        || owners
            .try_get::<String>("", "application_status")
            .map_err(persistence)?
            != "active"
        || owners
            .try_get::<i64>("", "metadata_revision")
            .map_err(persistence)?
            != intent
                .try_get::<i64>("", "project_metadata_revision")
                .map_err(persistence)?
        || owners
            .try_get::<i64>("", "security_revision")
            .map_err(persistence)?
            != intent
                .try_get::<i64>("", "project_security_revision")
                .map_err(persistence)?
    {
        return Ok(None);
    }
    let policy = transaction
        .query_one_raw(statement(
            "SELECT policy.status AS policy_status,policy.policy_revision,
                    policy.security_revision,assignment.status AS assignment_status,
                    assignment.security_revision AS assignment_revision
               FROM project_email_policies policy
               JOIN application_email_assignments assignment
                 ON assignment.project_id=policy.project_id AND assignment.application_id=$2
              WHERE policy.project_id=$1 FOR SHARE OF policy,assignment",
            vec![project_id.into(), application_id.into()],
        ))
        .await
        .map_err(persistence)?;
    let Some(policy) = policy else {
        return Ok(None);
    };
    let challenge = transaction
        .query_one_raw(statement(
            "SELECT challenge.*,slot.state AS slot_state,
                    (SELECT MAX(newer.generation)::SMALLINT FROM email_challenges newer
                      WHERE newer.owner_kind='identity_mutation'
                        AND newer.project_id=challenge.project_id
                        AND newer.identity_mutation_intent_id=challenge.identity_mutation_intent_id
                        AND newer.identity_mutation_proof_slot_id=challenge.identity_mutation_proof_slot_id)
                      AS newest_generation
               FROM email_challenges challenge
               JOIN identity_mutation_proof_slots slot
                 ON slot.project_id=challenge.project_id
                AND slot.intent_id=challenge.identity_mutation_intent_id
                AND slot.id=challenge.identity_mutation_proof_slot_id
              WHERE challenge.project_id=$1 AND challenge.id=$2
                AND challenge.identity_mutation_intent_id=$3
                AND challenge.identity_mutation_proof_slot_id=$4 FOR SHARE OF challenge,slot",
            vec![project_id.into(), challenge_id.into(), intent_id.into(), slot_id.into()],
        ))
        .await
        .map_err(persistence)?;
    let Some(challenge) = challenge else {
        return Ok(None);
    };
    if challenge
        .try_get::<String>("", "status")
        .map_err(persistence)?
        != "pending"
        || challenge
            .try_get::<String>("", "slot_state")
            .map_err(persistence)?
            != "email_challenge_pending"
        || challenge
            .try_get::<OffsetDateTime>("", "expires_at")
            .map_err(persistence)?
            <= now
        || challenge
            .try_get::<i16>("", "generation")
            .map_err(persistence)?
            != challenge
                .try_get::<i16>("", "newest_generation")
                .map_err(persistence)?
        || policy
            .try_get::<String>("", "policy_status")
            .map_err(persistence)?
            != "enabled"
        || policy
            .try_get::<String>("", "assignment_status")
            .map_err(persistence)?
            != "active"
        || policy
            .try_get::<i64>("", "policy_revision")
            .map_err(persistence)?
            != challenge
                .try_get::<i64>("", "method_policy_revision")
                .map_err(persistence)?
        || policy
            .try_get::<i64>("", "security_revision")
            .map_err(persistence)?
            != challenge
                .try_get::<i64>("", "method_security_revision")
                .map_err(persistence)?
        || policy
            .try_get::<i64>("", "assignment_revision")
            .map_err(persistence)?
            != challenge
                .try_get::<i64>("", "assignment_security_revision")
                .map_err(persistence)?
        || owners
            .try_get::<i64>("", "application_security_revision")
            .map_err(persistence)?
            != transaction
                .query_one_raw(statement(
                    "SELECT application_security_revision FROM identity_mutation_proof_slots
                      WHERE project_id=$1 AND intent_id=$2 AND id=$3",
                    vec![project_id.into(), intent_id.into(), slot_id.into()],
                ))
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::Integrity)?
                .try_get::<i64>("", "application_security_revision")
                .map_err(persistence)?
    {
        return Ok(None);
    }

    let selection: String = challenge
        .try_get("", "smtp_selection_kind")
        .map_err(persistence)?;
    let smtp_id: Option<Uuid> = challenge
        .try_get("", "smtp_configuration_id")
        .map_err(persistence)?;
    let generation: i32 = challenge
        .try_get("", "smtp_generation")
        .map_err(persistence)?;
    let security_revision: i64 = challenge
        .try_get("", "smtp_security_eligibility_revision")
        .map_err(persistence)?;
    let smtp = if selection == "project" {
        transaction
            .query_one_raw(statement(
                "SELECT smtp.host,smtp.port,smtp.tls_mode,smtp.sender_address,smtp.sender_name,
                        smtp.reply_to,smtp.credential_ref,smtp.safe_fingerprint,
                        '[]'::jsonb AS allowed_private_ips,smtp.status,smtp.retained_until,
                        smtp.security_eligibility_revision
                   FROM project_smtp_configurations smtp WHERE smtp.project_id=$1 AND smtp.id=$2
                    AND smtp.generation=$3 AND NOT EXISTS (
                      SELECT required.process_id
                        FROM jsonb_array_elements_text($4::jsonb) required(process_id)
                       WHERE NOT EXISTS (
                         SELECT 1 FROM project_smtp_runtime_readiness readiness
                          JOIN runtime_process_incarnations current
                            ON current.process_id=readiness.process_id
                           AND current.process_incarnation=readiness.process_incarnation
                         WHERE readiness.project_id=smtp.project_id
                           AND readiness.configuration_id=smtp.id
                           AND readiness.generation=smtp.generation
                           AND readiness.process_id=required.process_id
                           AND readiness.state='ready' AND readiness.lease_expires_at>$5))
                   FOR SHARE OF smtp",
                vec![
                    project_id.into(),
                    smtp_id.into(),
                    generation.into(),
                    repository.runtime_roster_json().into(),
                    now.into(),
                ],
            ))
            .await
            .map_err(persistence)?
    } else if selection == "deployment_default" && smtp_id.is_none() {
        transaction
            .execute_raw(statement(
                "SELECT pg_advisory_xact_lock_shared(hashtextextended('owlauth:deployment-smtp',0))",
                vec![],
            ))
            .await
            .map_err(persistence)?;
        transaction
            .query_one_raw(statement(
                "SELECT smtp.host,smtp.port,smtp.tls_mode,smtp.sender_address,
                        NULL::TEXT AS sender_name,NULL::TEXT AS reply_to,smtp.credential_ref,
                        smtp.safe_fingerprint,smtp.explicitly_allowed_private_ips AS allowed_private_ips,
                        smtp.status,smtp.retained_until,smtp.security_eligibility_revision
                   FROM deployment_smtp_generations smtp WHERE smtp.generation=$1 FOR SHARE OF smtp",
                vec![generation.into()],
            ))
            .await
            .map_err(persistence)?
    } else {
        None
    };
    let Some(smtp) = smtp else {
        return Ok(None);
    };
    let smtp_status: String = smtp.try_get("", "status").map_err(persistence)?;
    if (smtp_status != "active"
        && !(smtp_status == "retained"
            && smtp
                .try_get::<Option<OffsetDateTime>>("", "retained_until")
                .map_err(persistence)?
                .is_some_and(|until| until > now)))
        || smtp
            .try_get::<i64>("", "security_eligibility_revision")
            .map_err(persistence)?
            != security_revision
    {
        return Ok(None);
    }
    let row = transaction
        .query_one_raw(statement(
            "SELECT outbox.*,$2::TEXT AS host,$3::INTEGER AS port,$4::TEXT AS tls_mode,
                    $5::TEXT AS sender_address,$6::TEXT AS sender_name,$7::TEXT AS reply_to,
                    $8::TEXT AS credential_ref,$9::JSONB AS allowed_private_ips,
                    $14::UUID AS identity_mutation_intent_id,
                    $15::UUID AS identity_mutation_proof_slot_id
               FROM mail_outbox outbox WHERE outbox.id=$1 AND outbox.project_id=$10
                AND outbox.transaction_id IS NULL AND outbox.challenge_id=$11
                AND outbox.challenge_generation=$12
                AND (outbox.status IN ('pending','retry','ambiguous')
                     OR (outbox.status='leased' AND outbox.lease_expires_at<=clock_timestamp()))
                AND outbox.attempts<outbox.max_attempts AND outbox.next_attempt_at<=$13
                AND outbox.useful_until>$13 FOR UPDATE OF outbox",
            vec![
                id.into(),
                smtp.try_get::<String>("", "host")
                    .map_err(persistence)?
                    .into(),
                smtp.try_get::<i32>("", "port").map_err(persistence)?.into(),
                smtp.try_get::<String>("", "tls_mode")
                    .map_err(persistence)?
                    .into(),
                smtp.try_get::<String>("", "sender_address")
                    .map_err(persistence)?
                    .into(),
                smtp.try_get::<Option<String>>("", "sender_name")
                    .map_err(persistence)?
                    .into(),
                smtp.try_get::<Option<String>>("", "reply_to")
                    .map_err(persistence)?
                    .into(),
                smtp.try_get::<String>("", "credential_ref")
                    .map_err(persistence)?
                    .into(),
                smtp.try_get::<serde_json::Value>("", "allowed_private_ips")
                    .map_err(persistence)?
                    .into(),
                project_id.into(),
                challenge_id.into(),
                challenge
                    .try_get::<i16>("", "generation")
                    .map_err(persistence)?
                    .into(),
                now.into(),
                intent_id.into(),
                slot_id.into(),
            ],
        ))
        .await
        .map_err(persistence)?;
    let Some(row) = row else {
        return Ok(None);
    };

    // Receipt/intent expiry is aggregate authority, not merely outbox authority. Recheck it only
    // after the final outbox wait, while the intent, receipt set, and outbox are all locked, so an
    // elapsed effective deadline atomically terminalizes and erases the mutation before return.
    if expire_locked_if_needed(transaction, &intent).await? {
        return Ok(None);
    }
    let final_now = database_clock(transaction).await?;
    repository
        .assert_email_protection_ready(transaction)
        .await?;
    if identity_mutation_is_earliest_due(repository, transaction, final_now).await?
        != Some((id, true))
    {
        return Ok(None);
    }
    let claimed = transaction
        .query_one_raw(statement(
            "UPDATE mail_outbox SET status='leased',lease_owner=$2,
                    lease_expires_at=clock_timestamp()+($3*interval '1 millisecond'),
                    attempts=attempts+1,updated_at=clock_timestamp()
              WHERE id=$1 AND (status IN ('pending','retry','ambiguous')
                    OR (status='leased' AND lease_expires_at<=clock_timestamp()))
                AND attempts<max_attempts AND next_attempt_at<=clock_timestamp()
                AND useful_until>clock_timestamp()
              RETURNING lease_expires_at",
            vec![id.into(), worker.to_owned().into(), lease_millis.into()],
        ))
        .await
        .map_err(persistence)?;
    let Some(claimed) = claimed else {
        return Ok(None);
    };
    let lease_expires_at = claimed
        .try_get("", "lease_expires_at")
        .map_err(persistence)?;
    let safe_fingerprint = smtp
        .try_get::<Vec<u8>>("", "safe_fingerprint")
        .map_err(persistence)?
        .try_into()
        .map_err(|_| ApplicationError::Integrity)?;
    Ok(Some(claimed_mail_job(
        &row,
        id,
        worker,
        lease_expires_at,
        safe_fingerprint,
    )?))
}
