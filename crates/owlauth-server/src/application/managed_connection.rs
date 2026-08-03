use std::{
    collections::BTreeSet,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use async_trait::async_trait;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::domain::{BoundedProviderProfile, ManagedProfileCapability, RenewalReplay};

use super::{ApplicationError, Clock, ProtectedValue};

const READ_RETRY_MIN: Duration = Duration::seconds(30);
const READ_RETRY_MAX: Duration = Duration::hours(6);
const PROFILE_SUCCESS_INTERVAL: Duration = Duration::hours(6);
// A renewal/profile operation has four persistence boundaries (claim, submitted, successor,
// profile). The adapter separately declares its maximum provider-I/O budget. The safety margin
// covers scheduling jitter and keeps the final exact-lease CAS away from the expiry edge.
const WORKER_PERSISTENCE_BUDGET: Duration = Duration::seconds(20);
const WORKER_LEASE_SAFETY_MARGIN: Duration = Duration::seconds(20);
const MAX_ADAPTER_OPERATION_BUDGET: Duration = Duration::minutes(10);
const MAX_BACKOFF_EXPONENT: u32 = 10;

fn worker_lease_for_adapter_budget(
    adapter_budget: std::time::Duration,
) -> Result<Duration, ApplicationError> {
    let adapter_budget =
        Duration::try_from(adapter_budget).map_err(|_| ApplicationError::Integrity)?;
    if adapter_budget <= Duration::ZERO || adapter_budget > MAX_ADAPTER_OPERATION_BUDGET {
        return Err(ApplicationError::Integrity);
    }
    adapter_budget
        .checked_add(WORKER_PERSISTENCE_BUDGET)
        .and_then(|budget| budget.checked_add(WORKER_LEASE_SAFETY_MARGIN))
        .ok_or(ApplicationError::Integrity)
}

fn require_worker_completion(completed: bool) -> Result<(), ApplicationError> {
    if completed {
        Ok(())
    } else {
        Err(ApplicationError::RevisionConflict)
    }
}

/// Exact authenticated context for one renewable credential generation. Any field change must
/// make decryption fail, including restoring ciphertext under another deployment or connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedCredentialContext {
    pub project_id: Uuid,
    pub provider_configuration_id: Uuid,
    pub linked_identity_id: Uuid,
    pub connection_id: Uuid,
    pub connection_generation: i64,
    pub credential_generation: i64,
}

impl ManagedCredentialContext {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut value = Vec::with_capacity(16 * 4 + 16);
        value.extend_from_slice(self.project_id.as_bytes());
        value.extend_from_slice(self.provider_configuration_id.as_bytes());
        value.extend_from_slice(self.linked_identity_id.as_bytes());
        value.extend_from_slice(self.connection_id.as_bytes());
        value.extend_from_slice(&self.connection_generation.to_be_bytes());
        value.extend_from_slice(&self.credential_generation.to_be_bytes());
        value
    }
}

pub(crate) trait ManagedCredentialProtector: Send + Sync {
    fn protect_credential(
        &self,
        context: &ManagedCredentialContext,
        credential: &[u8],
    ) -> Result<ProtectedValue, ApplicationError>;

    fn unprotect_credential(
        &self,
        context: &ManagedCredentialContext,
        value: &ProtectedValue,
    ) -> Result<Zeroizing<Vec<u8>>, ApplicationError>;

    /// Versions which must remain available for active credentials and submitted operations.
    fn readable_key_versions(&self) -> BTreeSet<i32>;

    fn active_key_version(&self) -> i32;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedConnectionMetadata {
    pub id: Uuid,
    pub project_id: Uuid,
    pub provider_configuration_id: Uuid,
    pub linked_identity_id: Uuid,
    pub user_id: Uuid,
    pub state: String,
    pub revision: i64,
    pub generation: i64,
    pub credential_generation: i64,
    pub capability_key: String,
    pub required_scopes: Vec<String>,
    pub source_schema: String,
    pub supports_revocation: bool,
    pub reauthorization_application_ids: Vec<Uuid>,
    pub last_safe_outcome: String,
    pub last_synchronized_at: Option<OffsetDateTime>,
    pub next_synchronize_at: Option<OffsetDateTime>,
    pub next_renewal_at: Option<OffsetDateTime>,
    pub consecutive_failures: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ConnectionGuard {
    pub connection_id: Uuid,
    pub project_id: Uuid,
    pub provider_configuration_id: Uuid,
    pub linked_identity_id: Uuid,
    pub user_id: Uuid,
    pub connection_revision: i64,
    pub connection_generation: i64,
    pub credential_generation: i64,
    pub project_security_revision: i64,
    pub provider_revision: i64,
    pub managed_profile_revision: i64,
    pub adapter_key: String,
    pub adapter_capability_revision: i64,
    /// Exact frozen grant used when RFC 6749 permits a refresh response to omit `scope`.
    pub required_scopes: Vec<String>,
    pub user_security_revision: i64,
    pub identity_revision: i64,
    pub consecutive_failures: i32,
    pub issuer: String,
    pub subject: String,
    pub client_id: String,
    pub secret_ref: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClaimedManagedCredential {
    pub guard: ConnectionGuard,
    pub protected: ProtectedValue,
    pub lease_owner: Uuid,
    pub lease_expires_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SuccessorProfileClaim {
    pub guard: ConnectionGuard,
    pub lease_owner: Uuid,
    pub lease_expires_at: OffsetDateTime,
}

impl std::ops::Deref for SuccessorProfileClaim {
    type Target = ConnectionGuard;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PreparedRenewal {
    pub operation_id: Uuid,
    pub attempt_id: Uuid,
    pub claim: ClaimedManagedCredential,
    pub adapter_idempotent_replay: bool,
    pub authority_valid: bool,
    pub operation_state: RenewalOperationState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    dead_code,
    reason = "successor_committed is persisted and parsed by inventory/recovery tooling"
)]
pub(crate) enum RenewalOperationState {
    Prepared,
    Submitted,
    SuccessorCommitted,
    ReauthRequired,
    Abandoned,
}

impl RenewalOperationState {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Submitted => "submitted",
            Self::SuccessorCommitted => "successor_committed",
            Self::ReauthRequired => "reauth_required",
            Self::Abandoned => "abandoned",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BoundedManagedProfile {
    pub profile: BoundedProviderProfile,
    pub observed_at: OffsetDateTime,
}

/// Intentionally has no Debug/Serialize implementation. It is memory-only and zeroized.
pub(crate) struct RenewedCredential {
    pub renewable: Zeroizing<Vec<u8>>,
    pub access: Zeroizing<Vec<u8>>,
    pub granted_scopes: Vec<String>,
}

#[allow(
    dead_code,
    reason = "authoritative revocation is available to adapters with that classifier"
)]
pub(crate) enum ProviderRenewalResult {
    Success(RenewedCredential),
    TransientBeforeDispatch,
    AmbiguousAfterDispatch,
    InvalidGrant,
    ScopeLost,
    AuthoritativelyRevoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    dead_code,
    reason = "authoritative revocation is available to adapters with that classifier"
)]
pub(crate) enum ProviderReadError {
    Transient,
    Ambiguous,
    InvalidCredential,
    AuthoritativelyRevoked,
    InvalidProfile,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    dead_code,
    reason = "generic OIDC explicitly reports unsupported revocation"
)]
pub(crate) enum ProviderRevocationResult {
    Confirmed,
    Unsupported,
    Ambiguous,
}

#[async_trait]
#[allow(
    dead_code,
    reason = "revocation is capability-gated and generic OIDC disables it"
)]
pub(crate) trait ManagedProfileAdapter: Send + Sync {
    fn capability(&self) -> Option<&'static ManagedProfileCapability>;

    /// Declared upper bound for the complete provider-I/O sequence of one renewal followed by
    /// its profile read. This includes every discovery, token and `UserInfo` request made by the
    /// adapter, not merely one HTTP request timeout.
    fn maximum_renewal_profile_duration(&self) -> std::time::Duration;

    async fn fetch_profile(
        &self,
        guard: &ConnectionGuard,
        credential: Zeroizing<Vec<u8>>,
    ) -> Result<BoundedManagedProfile, ProviderReadError>;

    async fn renew(
        &self,
        guard: &ConnectionGuard,
        credential: Zeroizing<Vec<u8>>,
        stable_attempt_id: Uuid,
    ) -> ProviderRenewalResult;

    async fn revoke(
        &self,
        guard: &ConnectionGuard,
        credential: Zeroizing<Vec<u8>>,
    ) -> ProviderRevocationResult;
}

#[async_trait]
#[allow(
    dead_code,
    clippy::too_many_arguments,
    reason = "worker supervision and key-retirement composition consume explicit fenced lane ports in Block C closure"
)]
pub(crate) trait ManagedConnectionRepository: Send + Sync {
    async fn list_metadata(
        &self,
        project_id: Uuid,
        user_id: Uuid,
        limit: u64,
    ) -> Result<Vec<ManagedConnectionMetadata>, ApplicationError>;

    /// Exact ownership lookup used by Control mutations. It must never be implemented as a
    /// bounded list scan.
    async fn metadata_for_owner(
        &self,
        project_id: Uuid,
        user_id: Uuid,
        connection_id: Uuid,
    ) -> Result<ManagedConnectionMetadata, ApplicationError>;

    /// Claims are ordered fairly by due time, Project, provider, then connection. The lease is
    /// scheduling only; every commit must compare every value in `ConnectionGuard`.
    async fn claim_next_read(
        &self,
        worker_id: Uuid,
        now: OffsetDateTime,
        lease_until: OffsetDateTime,
    ) -> Result<Option<ClaimedManagedCredential>, ApplicationError>;

    async fn commit_read_profile(
        &self,
        claim: &ClaimedManagedCredential,
        profile: BoundedManagedProfile,
        next_sync: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<bool, ApplicationError>;

    async fn finish_read_failure(
        &self,
        claim: &ClaimedManagedCredential,
        safe_outcome: &'static str,
        retry_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<bool, ApplicationError>;

    async fn prepare_next_renewal(
        &self,
        worker_id: Uuid,
        now: OffsetDateTime,
        lease_until: OffsetDateTime,
        adapter_idempotent_replay: bool,
    ) -> Result<Option<PreparedRenewal>, ApplicationError>;

    async fn mark_renewal_submitted(
        &self,
        renewal: &PreparedRenewal,
        now: OffsetDateTime,
    ) -> Result<bool, ApplicationError>;

    async fn commit_renewal_successor(
        &self,
        renewal: &PreparedRenewal,
        protected: ProtectedValue,
        now: OffsetDateTime,
    ) -> Result<Option<SuccessorProfileClaim>, ApplicationError>;

    async fn commit_successor_profile(
        &self,
        claim: &SuccessorProfileClaim,
        profile: BoundedManagedProfile,
        next_sync: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<bool, ApplicationError>;

    async fn commit_reauthorization_profile(
        &self,
        guard: &ConnectionGuard,
        profile: BoundedManagedProfile,
        next_sync: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<bool, ApplicationError>;

    async fn finish_successor_profile_failure(
        &self,
        claim: &SuccessorProfileClaim,
        safe_outcome: &'static str,
        retry_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<bool, ApplicationError>;

    async fn finish_successor_without_profile(
        &self,
        claim: &SuccessorProfileClaim,
        now: OffsetDateTime,
    ) -> Result<bool, ApplicationError>;

    async fn release_prepared_failure(
        &self,
        renewal: &PreparedRenewal,
        safe_outcome: &'static str,
        retry_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<bool, ApplicationError>;

    async fn terminalize_renewal(
        &self,
        renewal: &PreparedRenewal,
        state: RenewalOperationState,
        safe_outcome: &'static str,
        now: OffsetDateTime,
    ) -> Result<bool, ApplicationError>;

    async fn request_synchronize(
        &self,
        project_id: Uuid,
        user_id: Uuid,
        connection_id: Uuid,
        expected_revision: i64,
        expected_generation: i64,
        now: OffsetDateTime,
    ) -> Result<ManagedConnectionMetadata, ApplicationError>;

    async fn disconnect(
        &self,
        project_id: Uuid,
        user_id: Uuid,
        connection_id: Uuid,
        expected_revision: i64,
        expected_generation: i64,
        now: OffsetDateTime,
    ) -> Result<ManagedConnectionMetadata, ApplicationError>;

    async fn request_revocation(
        &self,
        project_id: Uuid,
        user_id: Uuid,
        connection_id: Uuid,
        expected_revision: i64,
        expected_generation: i64,
        correlation_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<ManagedConnectionMetadata, ApplicationError>;

    async fn claim_next_revocation(
        &self,
        worker_id: Uuid,
        now: OffsetDateTime,
        lease_until: OffsetDateTime,
    ) -> Result<Option<ClaimedManagedCredential>, ApplicationError>;

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
    ) -> Result<ClaimedManagedCredential, ApplicationError>;

    /// Commits the destructive pre-dispatch boundary. It atomically makes the persistent
    /// credential inaccessible while the caller retains only its zeroizing in-memory copy.
    async fn mark_revocation_dispatched(
        &self,
        claim: &ClaimedManagedCredential,
        now: OffsetDateTime,
    ) -> Result<bool, ApplicationError>;

    async fn finish_revocation(
        &self,
        claim: &ClaimedManagedCredential,
        result: ProviderRevocationResult,
        now: OffsetDateTime,
    ) -> Result<ManagedConnectionMetadata, ApplicationError>;

    /// Releases a revocation lease when no provider request was dispatched (for example a local
    /// protector/key failure). The exact guard and lease owner must still match.
    async fn release_revocation_claim(
        &self,
        claim: &ClaimedManagedCredential,
        now: OffsetDateTime,
    ) -> Result<bool, ApplicationError>;

    async fn fence_successor_read_evidence(
        &self,
        claim: &SuccessorProfileClaim,
        revoked: bool,
        safe_outcome: &'static str,
        now: OffsetDateTime,
    ) -> Result<bool, ApplicationError>;

    async fn fence_read_evidence(
        &self,
        guard: &ConnectionGuard,
        revoked: bool,
        safe_outcome: &'static str,
        now: OffsetDateTime,
    ) -> Result<bool, ApplicationError>;

    /// Terminalizes bounded, nonterminal managed reauthorization material that cannot be read
    /// by the restored Runtime protector. This short-lived material is recoverable by asking the
    /// operator to create a new interaction and must not make unrelated Runtime startup fail.
    async fn terminalize_unreadable_interactions(
        &self,
        readable_runtime_key_versions: &BTreeSet<i32>,
        readable_target_key_versions: &BTreeSet<i32>,
        limit: u64,
        now: OffsetDateTime,
    ) -> Result<u64, ApplicationError>;

    /// Bounded periodic sweep for abandoned interactions that expired without another request.
    async fn terminalize_expired_interactions(
        &self,
        limit: u64,
        now: OffsetDateTime,
    ) -> Result<u64, ApplicationError>;

    /// Long-term managed credential versions only. Missing members fail readiness closed.
    async fn required_key_versions(&self) -> Result<BTreeSet<i32>, ApplicationError>;

    async fn claim_next_rewrap(
        &self,
        worker_id: Uuid,
        target_key_version: i32,
        now: OffsetDateTime,
        lease_until: OffsetDateTime,
    ) -> Result<Option<ClaimedManagedCredential>, ApplicationError>;

    async fn finish_rewrap(
        &self,
        claim: &ClaimedManagedCredential,
        expected_key_version: i32,
        protected: ProtectedValue,
        now: OffsetDateTime,
    ) -> Result<bool, ApplicationError>;

    async fn rewrap_credential(
        &self,
        guard: &ConnectionGuard,
        expected_key_version: i32,
        protected: ProtectedValue,
        now: OffsetDateTime,
    ) -> Result<bool, ApplicationError>;
}

/// Narrow short-term cleanup capability. It owns only the Runtime ring's readable version
/// inventory and cannot encrypt, decrypt, inventory, or rewrap renewable credentials.
pub(crate) struct ManagedInteractionCleanupService {
    repository: Arc<dyn ManagedConnectionRepository>,
    readable_runtime_key_versions: BTreeSet<i32>,
    readable_target_key_versions: BTreeSet<i32>,
    clock: Arc<dyn Clock>,
}

impl ManagedInteractionCleanupService {
    pub(crate) fn new(
        repository: Arc<dyn ManagedConnectionRepository>,
        readable_runtime_key_versions: BTreeSet<i32>,
        readable_target_key_versions: BTreeSet<i32>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, ApplicationError> {
        if readable_runtime_key_versions.is_empty()
            || readable_target_key_versions.is_empty()
            || readable_runtime_key_versions
                .iter()
                .chain(readable_target_key_versions.iter())
                .any(|version| *version <= 0)
        {
            return Err(ApplicationError::Integrity);
        }
        Ok(Self {
            repository,
            readable_runtime_key_versions,
            readable_target_key_versions,
            clock,
        })
    }

    pub(crate) async fn cleanup(&self, limit: u64) -> Result<u64, ApplicationError> {
        let now = self.clock.now();
        let unreadable = self
            .repository
            .terminalize_unreadable_interactions(
                &self.readable_runtime_key_versions,
                &self.readable_target_key_versions,
                limit,
                now,
            )
            .await?;
        let expired = self
            .repository
            .terminalize_expired_interactions(limit, now)
            .await?;
        Ok(unreadable + expired)
    }
}

pub(crate) struct ManagedConnectionService {
    repository: Arc<dyn ManagedConnectionRepository>,
    protector: Arc<dyn ManagedCredentialProtector>,
    interaction_cleanup: Arc<ManagedInteractionCleanupService>,
    adapter: Arc<dyn ManagedProfileAdapter>,
    clock: Arc<dyn Clock>,
    worker_lease: Duration,
    key_ready: AtomicBool,
}

impl ManagedConnectionService {
    pub(crate) fn new(
        repository: Arc<dyn ManagedConnectionRepository>,
        protector: Arc<dyn ManagedCredentialProtector>,
        interaction_cleanup: Arc<ManagedInteractionCleanupService>,
        adapter: Arc<dyn ManagedProfileAdapter>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, ApplicationError> {
        adapter
            .capability()
            .ok_or(ApplicationError::Disabled)?
            .validate()
            .map_err(ApplicationError::from)?;
        if protector.readable_key_versions().is_empty() {
            return Err(ApplicationError::Integrity);
        }
        let worker_lease =
            worker_lease_for_adapter_budget(adapter.maximum_renewal_profile_duration())?;
        Ok(Self {
            repository,
            protector,
            interaction_cleanup,
            adapter,
            clock,
            worker_lease,
            key_ready: AtomicBool::new(false),
        })
    }

    /// One lease covers renewal discovery, token exchange, successor commit, profile discovery,
    /// `UserInfo`, profile commit, and a deliberate expiry-edge margin.
    pub(crate) fn provider_operation_lease(&self) -> Duration {
        self.worker_lease
    }

    #[allow(
        dead_code,
        reason = "focused protocol tests use the named profile synchronization entry point"
    )]
    pub(crate) async fn synchronize_one_read(
        &self,
        worker_id: Uuid,
        lease: Duration,
    ) -> Result<bool, ApplicationError> {
        // Stored material is a renewable credential, never a UserInfo bearer. Every standalone
        // synchronization therefore enters the durable renewal protocol first; only the
        // memory-only access token returned by that attempt may be used for profile I/O.
        self.renew_one(worker_id, lease).await
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the security protocol keeps prepared/submitted/result branches visible"
    )]
    pub(crate) async fn renew_one(
        &self,
        worker_id: Uuid,
        lease: Duration,
    ) -> Result<bool, ApplicationError> {
        let capability = self
            .adapter
            .capability()
            .ok_or(ApplicationError::Disabled)?;
        let replayable = capability.renewal_replay == RenewalReplay::StableAttemptId;
        let now = self.clock.now();
        let Some(renewal) = self
            .repository
            .prepare_next_renewal(worker_id, now, now + lease, replayable)
            .await?
        else {
            return Ok(false);
        };
        // Recovery requires both the operation's frozen protocol decision and the currently
        // compatible adapter capability. A later capability change can only make replay safer
        // by refusing it, never by upgrading an already-submitted operation.
        let can_replay_submitted = replayable && renewal.adapter_idempotent_replay;
        let adapter_matches = renewal.claim.guard.adapter_key == capability.adapter_key
            && renewal.claim.guard.adapter_capability_revision == capability.adapter_revision;
        if !adapter_matches {
            return self
                .repository
                .terminalize_renewal(
                    &renewal,
                    RenewalOperationState::ReauthRequired,
                    "renewal_adapter_stale",
                    self.clock.now(),
                )
                .await;
        }
        if renewal.operation_state == RenewalOperationState::Submitted && !renewal.authority_valid {
            return self
                .repository
                .terminalize_renewal(
                    &renewal,
                    RenewalOperationState::ReauthRequired,
                    "renewal_authority_stale",
                    self.clock.now(),
                )
                .await;
        }
        if renewal.operation_state == RenewalOperationState::Submitted && !can_replay_submitted {
            return self
                .repository
                .terminalize_renewal(
                    &renewal,
                    RenewalOperationState::ReauthRequired,
                    "submitted_response_ambiguous",
                    now,
                )
                .await;
        }
        let context = context_for(&renewal.claim.guard);
        let credential = match self
            .protector
            .unprotect_credential(&context, &renewal.claim.protected)
        {
            Ok(value) => value,
            Err(error) => {
                // Still prepared: no provider call was made. Preserve the stable attempt and
                // release only its scheduling lease so key repair/rewrap can recover it.
                self.repository
                    .release_prepared_failure(
                        &renewal,
                        "local_credential_unavailable",
                        now + READ_RETRY_MAX,
                        now,
                    )
                    .await?;
                return Err(error);
            }
        };
        if renewal.operation_state == RenewalOperationState::Prepared
            && !self
                .repository
                .mark_renewal_submitted(&renewal, self.clock.now())
                .await?
        {
            return Ok(false);
        }
        // This is the only dispatch point and is reachable only after submitted is durable.
        match self
            .adapter
            .renew(&renewal.claim.guard, credential, renewal.attempt_id)
            .await
        {
            ProviderRenewalResult::Success(successor) => {
                if !capability.scopes_match(&successor.granted_scopes) {
                    return self
                        .repository
                        .terminalize_renewal(
                            &renewal,
                            RenewalOperationState::ReauthRequired,
                            "required_scope_lost",
                            self.clock.now(),
                        )
                        .await;
                }
                let RenewedCredential {
                    renewable,
                    access,
                    granted_scopes: _,
                } = successor;
                let successor_context = ManagedCredentialContext {
                    connection_generation: renewal.claim.guard.connection_generation + 1,
                    credential_generation: renewal.claim.guard.credential_generation + 1,
                    ..context
                };
                let protected = self
                    .protector
                    .protect_credential(&successor_context, renewable.as_ref())?;
                // This commit advances both generations, destroys the predecessor, restores
                // active, completes the durable operation and audit boundary before profile I/O.
                let Some(successor_claim) = self
                    .repository
                    .commit_renewal_successor(&renewal, protected, self.clock.now())
                    .await?
                else {
                    // The provider may already have consumed/rotated the predecessor. A stale
                    // local authority fence must therefore destroy it immediately rather than
                    // leave submitted material appearing usable until lease recovery.
                    return self
                        .repository
                        .terminalize_renewal(
                            &renewal,
                            RenewalOperationState::ReauthRequired,
                            "successor_commit_fenced",
                            self.clock.now(),
                        )
                        .await;
                };
                if !capability.read_retry_safe {
                    require_worker_completion(
                        self.repository
                            .finish_successor_without_profile(&successor_claim, self.clock.now())
                            .await?,
                    )?;
                    return Ok(true);
                }
                let profile_result = self
                    .adapter
                    .fetch_profile(&successor_claim.guard, access)
                    .await;
                self.finish_transient_profile(successor_claim, profile_result)
                    .await?;
                Ok(true)
            }
            ProviderRenewalResult::TransientBeforeDispatch => {
                // `submitted` was made durable immediately before entering the adapter. Even if
                // the adapter can prove that this particular attempt did not reach its token
                // endpoint, a crash boundary must be recovered from the durable state rather
                // than rewriting submitted history as abandoned.
                if can_replay_submitted {
                    Ok(false)
                } else {
                    self.repository
                        .terminalize_renewal(
                            &renewal,
                            RenewalOperationState::ReauthRequired,
                            "submitted_prerequisite_failed",
                            self.clock.now(),
                        )
                        .await
                }
            }
            ProviderRenewalResult::AmbiguousAfterDispatch => {
                if can_replay_submitted {
                    // The submitted row and stable attempt ID remain reclaimable.
                    Ok(false)
                } else {
                    self.repository
                        .terminalize_renewal(
                            &renewal,
                            RenewalOperationState::ReauthRequired,
                            "renewal_ambiguous",
                            self.clock.now(),
                        )
                        .await
                }
            }
            ProviderRenewalResult::InvalidGrant => {
                self.repository
                    .terminalize_renewal(
                        &renewal,
                        RenewalOperationState::ReauthRequired,
                        "invalid_grant",
                        self.clock.now(),
                    )
                    .await
            }
            ProviderRenewalResult::ScopeLost => {
                self.repository
                    .terminalize_renewal(
                        &renewal,
                        RenewalOperationState::ReauthRequired,
                        "required_scope_lost",
                        self.clock.now(),
                    )
                    .await
            }
            ProviderRenewalResult::AuthoritativelyRevoked => {
                self.repository
                    .terminalize_renewal(
                        &renewal,
                        RenewalOperationState::ReauthRequired,
                        "provider_confirmed_revocation",
                        self.clock.now(),
                    )
                    .await
            }
        }
    }

    async fn finish_transient_profile(
        &self,
        claim: SuccessorProfileClaim,
        result: Result<BoundedManagedProfile, ProviderReadError>,
    ) -> Result<(), ApplicationError> {
        let now = self.clock.now();
        match result {
            Ok(profile) => {
                let completed = self
                    .repository
                    .commit_successor_profile(
                        &claim,
                        profile,
                        jittered(
                            now + PROFILE_SUCCESS_INTERVAL,
                            claim.guard.connection_id,
                            300,
                        ),
                        now,
                    )
                    .await?;
                require_worker_completion(completed)?;
            }
            Err(ProviderReadError::InvalidCredential) => {
                require_worker_completion(
                    self.repository
                        .fence_successor_read_evidence(
                            &claim,
                            false,
                            "read_invalid_credential",
                            now,
                        )
                        .await?,
                )?;
            }
            Err(ProviderReadError::AuthoritativelyRevoked) => {
                require_worker_completion(
                    self.repository
                        .fence_successor_read_evidence(
                            &claim,
                            true,
                            "read_confirmed_revocation",
                            now,
                        )
                        .await?,
                )?;
            }
            Err(error) => {
                let (outcome, base) = match error {
                    ProviderReadError::Transient => ("read_transient", READ_RETRY_MIN),
                    ProviderReadError::Ambiguous => ("read_ambiguous", READ_RETRY_MIN * 2),
                    ProviderReadError::InvalidProfile => ("read_invalid_profile", READ_RETRY_MAX),
                    ProviderReadError::InvalidCredential
                    | ProviderReadError::AuthoritativelyRevoked => unreachable!(),
                };
                let retry =
                    bounded_backoff(base, claim.guard.consecutive_failures.saturating_add(1));
                require_worker_completion(
                    self.repository
                        .finish_successor_profile_failure(
                            &claim,
                            outcome,
                            jittered(now + retry, claim.guard.connection_id, 30),
                            now,
                        )
                        .await?,
                )?;
            }
        }
        Ok(())
    }

    #[allow(
        dead_code,
        reason = "Control composition invokes capability-aware revoke when an adapter advertises it"
    )]
    pub(crate) async fn revoke(
        &self,
        project_id: Uuid,
        user_id: Uuid,
        connection_id: Uuid,
        expected_revision: i64,
        expected_generation: i64,
        lease: Duration,
    ) -> Result<ManagedConnectionMetadata, ApplicationError> {
        let capability = self
            .adapter
            .capability()
            .ok_or(ApplicationError::Disabled)?;
        if !capability.supports_revocation || lease <= Duration::ZERO {
            return Err(ApplicationError::Disabled);
        }
        let now = self.clock.now();
        let claim = self
            .repository
            .claim_for_revocation(
                project_id,
                user_id,
                connection_id,
                expected_revision,
                expected_generation,
                Uuid::new_v4(),
                now,
                now + lease,
            )
            .await?;
        let credential = match self
            .protector
            .unprotect_credential(&context_for(&claim.guard), &claim.protected)
        {
            Ok(credential) => credential,
            Err(error) => {
                self.repository
                    .release_revocation_claim(&claim, self.clock.now())
                    .await?;
                return Err(error);
            }
        };
        if !self
            .repository
            .mark_revocation_dispatched(&claim, self.clock.now())
            .await?
        {
            return Err(ApplicationError::RevisionConflict);
        }
        // Only this zeroizing in-memory copy survives the durable dispatch boundary.
        let result = self.adapter.revoke(&claim.guard, credential).await;
        self.repository
            .finish_revocation(&claim, result, self.clock.now())
            .await
    }

    pub(crate) async fn revoke_one(
        &self,
        worker_id: Uuid,
        lease: Duration,
    ) -> Result<bool, ApplicationError> {
        let capability = self
            .adapter
            .capability()
            .ok_or(ApplicationError::Disabled)?;
        if !capability.supports_revocation || lease <= Duration::ZERO {
            return Err(ApplicationError::Disabled);
        }
        let now = self.clock.now();
        let Some(claim) = self
            .repository
            .claim_next_revocation(worker_id, now, now + lease)
            .await?
        else {
            return Ok(false);
        };
        if claim.guard.adapter_key != capability.adapter_key
            || claim.guard.adapter_capability_revision != capability.adapter_revision
        {
            if !self
                .repository
                .mark_revocation_dispatched(&claim, self.clock.now())
                .await?
            {
                return Ok(false);
            }
            self.repository
                .finish_revocation(
                    &claim,
                    ProviderRevocationResult::Ambiguous,
                    self.clock.now(),
                )
                .await?;
            return Ok(true);
        }
        let credential = match self
            .protector
            .unprotect_credential(&context_for(&claim.guard), &claim.protected)
        {
            Ok(credential) => credential,
            Err(error) => {
                self.repository
                    .release_revocation_claim(&claim, self.clock.now())
                    .await?;
                return Err(error);
            }
        };
        if !self
            .repository
            .mark_revocation_dispatched(&claim, self.clock.now())
            .await?
        {
            return Ok(false);
        }
        let result = self.adapter.revoke(&claim.guard, credential).await;
        self.repository
            .finish_revocation(&claim, result, self.clock.now())
            .await?;
        Ok(true)
    }

    #[allow(
        dead_code,
        reason = "final supervisor readiness consumes the exact lane inventory"
    )]
    pub(crate) async fn required_key_versions(&self) -> Result<BTreeSet<i32>, ApplicationError> {
        self.repository.required_key_versions().await
    }

    pub(crate) async fn rewrap_one(
        &self,
        worker_id: Uuid,
        lease: Duration,
    ) -> Result<bool, ApplicationError> {
        let target = self.protector.active_key_version();
        if target <= 0 || lease <= Duration::ZERO {
            return Err(ApplicationError::Integrity);
        }
        let now = self.clock.now();
        let Some(claim) = self
            .repository
            .claim_next_rewrap(worker_id, target, now, now + lease)
            .await?
        else {
            return Ok(false);
        };
        let context = context_for(&claim.guard);
        let plaintext = self
            .protector
            .unprotect_credential(&context, &claim.protected)?;
        let protected = self
            .protector
            .protect_credential(&context, plaintext.as_ref())?;
        if protected.key_version != target {
            return Err(ApplicationError::Integrity);
        }
        self.repository
            .finish_rewrap(
                &claim,
                claim.protected.key_version,
                protected,
                self.clock.now(),
            )
            .await
    }

    /// Reconciles bounded short-lived interaction material before any Runtime claim is served,
    /// then fails closed if any long-lived credential generation remains unreadable.
    pub(crate) async fn restore_key_state(&self) -> Result<bool, ApplicationError> {
        // Short-lived loss never gates unrelated credentials: do one bounded startup batch and
        // let the Runtime worker converge any backlog. Hosted claim paths also resolve every
        // frozen key version before their claim CAS, so an unreadable remainder cannot mutate.
        self.cleanup_unreadable_interactions(256).await?;
        self.refresh_key_readiness().await
    }

    pub(crate) async fn refresh_key_readiness(&self) -> Result<bool, ApplicationError> {
        let ready = self.assert_key_readiness().await.is_ok();
        self.key_ready.store(ready, Ordering::Release);
        Ok(ready)
    }

    pub(crate) fn managed_claims_ready(&self) -> bool {
        self.key_ready.load(Ordering::Acquire)
    }

    pub(crate) async fn cleanup_unreadable_interactions(
        &self,
        limit: u64,
    ) -> Result<u64, ApplicationError> {
        self.interaction_cleanup.cleanup(limit).await
    }

    pub(crate) async fn assert_key_readiness(&self) -> Result<(), ApplicationError> {
        let required = self.repository.required_key_versions().await?;
        let readable = self.protector.readable_key_versions();
        if required.is_subset(&readable) {
            Ok(())
        } else {
            Err(ApplicationError::Integrity)
        }
    }
}

fn bounded_backoff(base: Duration, failures: i32) -> Duration {
    let exponent = u32::try_from(failures.max(0))
        .unwrap_or(MAX_BACKOFF_EXPONENT)
        .min(MAX_BACKOFF_EXPONENT);
    (base * (1_i32 << exponent)).min(READ_RETRY_MAX)
}

fn jittered(value: OffsetDateTime, key: Uuid, bound_seconds: i64) -> OffsetDateTime {
    let bytes = key.as_bytes();
    let seed = i64::from(u16::from_be_bytes([bytes[0], bytes[1]]));
    value + Duration::seconds(seed % (bound_seconds.max(1) + 1))
}

fn context_for(guard: &ConnectionGuard) -> ManagedCredentialContext {
    ManagedCredentialContext {
        project_id: guard.project_id,
        provider_configuration_id: guard.provider_configuration_id,
        linked_identity_id: guard.linked_identity_id,
        connection_id: guard.connection_id,
        connection_generation: guard.connection_generation,
        credential_generation: guard.credential_generation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_retry_backoff_is_exponential_and_bounded() {
        assert_eq!(bounded_backoff(READ_RETRY_MIN, 0), READ_RETRY_MIN);
        assert_eq!(bounded_backoff(READ_RETRY_MIN, 1), READ_RETRY_MIN * 2);
        assert_eq!(bounded_backoff(READ_RETRY_MIN, 2), READ_RETRY_MIN * 4);
        assert_eq!(bounded_backoff(READ_RETRY_MIN, 32), READ_RETRY_MAX);
        assert_eq!(bounded_backoff(READ_RETRY_MAX, 1), READ_RETRY_MAX);
    }

    #[test]
    fn worker_lease_covers_cumulative_delayed_adapter_sequence() {
        // Discovery, token, profile discovery and UserInfo can each take nine seconds: every call
        // remains below the ten-second request timeout while their 36-second cumulative duration
        // already exceeds the rejected fixed 30-second lease.
        let individual_delays = [9_u64; 4];
        let cumulative = std::time::Duration::from_secs(individual_delays.into_iter().sum());
        assert!(cumulative > std::time::Duration::from_secs(30));

        let lease = worker_lease_for_adapter_budget(std::time::Duration::from_secs(40))
            .expect("declared OIDC end-to-end budget is valid");
        assert_eq!(lease, Duration::seconds(80));
        assert!(lease > Duration::try_from(cumulative).expect("test duration fits"));
    }

    #[test]
    fn false_profile_completion_is_an_explicit_worker_conflict() {
        assert_eq!(require_worker_completion(true), Ok(()));
        assert_eq!(
            require_worker_completion(false),
            Err(ApplicationError::RevisionConflict)
        );
    }
}
