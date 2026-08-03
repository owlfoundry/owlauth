use std::{
    collections::{BTreeSet, HashMap, HashSet, VecDeque},
    sync::{Arc, Mutex},
    time::Instant,
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use sha2::Sha256;

const SCHEMA_VERSION: &str = "v1";
const LOCAL_CAPACITY: usize = 8_192;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[allow(
    dead_code,
    reason = "identity mutation endpoint policies precede their HTTP composition"
)]
pub(crate) enum AdmissionEndpoint {
    PublicConfig,
    ProjectJwks,
    LoginStart,
    HostedInteraction,
    HostedIdentityMutation,
    ManagedReauthorizationStart,
    IdentityMutationMethod,
    IdentityMutationEmailChallenge,
    IdentityMutationEmailOtpVerify,
    IdentityMutationEmailMagicConfirm,
    IdentityMutationConfirm,
    ProviderSelection,
    EmailSelection,
    EmailChallenge,
    EmailResend,
    EmailOtpVerify,
    EmailMagicRead,
    EmailMagicConfirm,
    SessionReuse,
    ProviderCallback,
    HandoffExchange,
    Refresh,
    CurrentUser,
    ApplicationLogout,
    BrowserLogoutPrepare,
    BrowserLogoutRead,
    BrowserLogoutConfirm,
}

impl AdmissionEndpoint {
    #[cfg(test)]
    const ALL: [Self; 27] = [
        Self::PublicConfig,
        Self::ProjectJwks,
        Self::LoginStart,
        Self::HostedInteraction,
        Self::HostedIdentityMutation,
        Self::ManagedReauthorizationStart,
        Self::IdentityMutationMethod,
        Self::IdentityMutationEmailChallenge,
        Self::IdentityMutationEmailOtpVerify,
        Self::IdentityMutationEmailMagicConfirm,
        Self::IdentityMutationConfirm,
        Self::ProviderSelection,
        Self::EmailSelection,
        Self::EmailChallenge,
        Self::EmailResend,
        Self::EmailOtpVerify,
        Self::EmailMagicRead,
        Self::EmailMagicConfirm,
        Self::SessionReuse,
        Self::ProviderCallback,
        Self::HandoffExchange,
        Self::Refresh,
        Self::CurrentUser,
        Self::ApplicationLogout,
        Self::BrowserLogoutPrepare,
        Self::BrowserLogoutRead,
        Self::BrowserLogoutConfirm,
    ];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::PublicConfig => "public_config",
            Self::ProjectJwks => "project_jwks",
            Self::LoginStart => "login_start",
            Self::HostedInteraction => "hosted_interaction",
            Self::HostedIdentityMutation => "hosted_identity_mutation",
            Self::ManagedReauthorizationStart => "managed_reauthorization_start",
            Self::IdentityMutationMethod => "identity_mutation_method",
            Self::IdentityMutationEmailChallenge => "identity_mutation_email_challenge",
            Self::IdentityMutationEmailOtpVerify => "identity_mutation_email_otp_verify",
            Self::IdentityMutationEmailMagicConfirm => "identity_mutation_email_magic_confirm",
            Self::IdentityMutationConfirm => "identity_mutation_confirm",
            Self::ProviderSelection => "provider_selection",
            Self::EmailSelection => "email_selection",
            Self::EmailChallenge => "email_challenge",
            Self::EmailResend => "email_resend",
            Self::EmailOtpVerify => "email_otp_verify",
            Self::EmailMagicRead => "email_magic_read",
            Self::EmailMagicConfirm => "email_magic_confirm",
            Self::SessionReuse => "session_reuse",
            Self::ProviderCallback => "provider_callback",
            Self::HandoffExchange => "handoff_exchange",
            Self::Refresh => "refresh",
            Self::CurrentUser => "current_user",
            Self::ApplicationLogout => "application_logout",
            Self::BrowserLogoutPrepare => "browser_logout_prepare",
            Self::BrowserLogoutRead => "browser_logout_read",
            Self::BrowserLogoutConfirm => "browser_logout_confirm",
        }
    }

    const fn policy(self) -> AdmissionPolicy {
        let limit = match self {
            Self::PublicConfig | Self::ProjectJwks | Self::CurrentUser => 600,
            Self::HostedInteraction | Self::HostedIdentityMutation => 300,
            Self::Refresh => 240,
            Self::EmailSelection
            | Self::EmailChallenge
            | Self::EmailResend
            | Self::IdentityMutationEmailChallenge => 256,
            Self::LoginStart | Self::BrowserLogoutPrepare => 120,
            Self::ProviderCallback | Self::HandoffExchange | Self::ApplicationLogout => 96,
            Self::ManagedReauthorizationStart
            | Self::IdentityMutationMethod
            | Self::IdentityMutationEmailOtpVerify
            | Self::IdentityMutationEmailMagicConfirm
            | Self::IdentityMutationConfirm
            | Self::ProviderSelection
            | Self::EmailOtpVerify
            | Self::EmailMagicRead
            | Self::EmailMagicConfirm
            | Self::SessionReuse
            | Self::BrowserLogoutRead
            | Self::BrowserLogoutConfirm => 64,
        };
        AdmissionPolicy {
            limit,
            window_millis: 60_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdmissionDimensionKind {
    Project,
    Application,
    Credential,
    Provider,
    Email,
}

impl AdmissionDimensionKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::Application => "application",
            Self::Credential => "credential",
            Self::Provider => "provider",
            Self::Email => "email_admission_v1",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct AdmissionDimension<'a> {
    pub kind: AdmissionDimensionKind,
    pub value: &'a str,
    /// Email quotas are keyed inside the authoritative Project/Application boundary. Ordinary
    /// dimensions deliberately carry no scope and retain their existing derivation.
    pub email_scope: Option<(&'a str, &'a str)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AdmissionPolicy {
    limit: u32,
    window_millis: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AdmissionBucket {
    pub key: String,
    pub limit: u32,
    pub window_millis: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdmissionRejectionReason {
    Quota,
    LocalCapacity,
}

impl AdmissionRejectionReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Quota => "quota",
            Self::LocalCapacity => "local_capacity",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdmissionDecision {
    Allowed,
    Rejected {
        retry_after_seconds: u64,
        reason: AdmissionRejectionReason,
        /// True only when the sole saturated quota class is the server-derived, scoped email
        /// address bucket. HTTP may persist an indistinguishable non-delivery challenge for this
        /// case; client/Project/Application/interaction quotas and capacity failures remain 429.
        suppression_eligible: bool,
    },
}

#[async_trait]
pub(crate) trait DistributedAdmissionCounter: Send + Sync {
    async fn evaluate(
        &self,
        buckets: &[AdmissionBucket],
    ) -> Result<AdmissionDecision, DistributedAdmissionError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DistributedAdmissionError;

#[derive(Clone, Debug)]
struct LocalEntry {
    accepted_at: VecDeque<u64>,
    expires_at_millis: u64,
}

#[derive(Debug)]
struct LocalCounters {
    entries: HashMap<String, LocalEntry>,
    // Exactly one tuple per entry. This permits bounded ordered whole-entry expiry instead of a
    // capacity-triggered scan over all attacker-controlled keys.
    expiration_index: BTreeSet<(u64, String)>,
    capacity: usize,
}

impl LocalCounters {
    fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(capacity),
            expiration_index: BTreeSet::new(),
            capacity,
        }
    }

    fn evaluate(
        &mut self,
        buckets: &[AdmissionBucket],
        now_millis: u64,
        window_millis: u64,
    ) -> AdmissionDecision {
        self.expire_whole_entries(now_millis);
        for bucket in buckets {
            if let Some(entry) = self.entries.get_mut(&bucket.key) {
                prune_expired(entry, now_millis, window_millis);
            }
        }

        let saturated = buckets
            .iter()
            .filter_map(|bucket| {
                let entry = self.entries.get(&bucket.key)?;
                (entry.accepted_at.len() >= bucket.limit as usize).then(|| {
                    (
                        entry_retry_millis(entry, now_millis, window_millis),
                        bucket.key.contains(":email_admission_v1:"),
                    )
                })
            })
            .collect::<Vec<_>>();
        if let Some(retry_millis) = saturated.iter().map(|(retry, _)| *retry).max() {
            return AdmissionDecision::Rejected {
                retry_after_seconds: retry_seconds(retry_millis),
                reason: AdmissionRejectionReason::Quota,
                suppression_eligible: saturated.iter().all(|(_, scoped_email)| *scoped_email),
            };
        }

        let missing = missing_bucket_count(&self.entries, buckets);
        if self.entries.len().saturating_add(missing) > self.capacity {
            let retry_millis = self
                .expiration_index
                .first()
                .map_or(window_millis, |(expires_at_millis, _)| {
                    expires_at_millis.saturating_sub(now_millis)
                });
            return AdmissionDecision::Rejected {
                retry_after_seconds: retry_seconds(retry_millis),
                reason: AdmissionRejectionReason::LocalCapacity,
                suppression_eligible: false,
            };
        }

        let expires_at_millis = now_millis.saturating_add(window_millis);
        for bucket in buckets {
            if let Some(entry) = self.entries.get_mut(&bucket.key) {
                let old_expiration = entry.expires_at_millis;
                entry.accepted_at.push_back(now_millis);
                entry.expires_at_millis = expires_at_millis;
                self.expiration_index
                    .remove(&(old_expiration, bucket.key.clone()));
            } else {
                self.entries.insert(
                    bucket.key.clone(),
                    LocalEntry {
                        accepted_at: VecDeque::from([now_millis]),
                        expires_at_millis,
                    },
                );
            }
            self.expiration_index
                .insert((expires_at_millis, bucket.key.clone()));
        }
        debug_assert_eq!(self.expiration_index.len(), self.entries.len());
        AdmissionDecision::Allowed
    }

    fn expire_whole_entries(&mut self, now_millis: u64) {
        while let Some((expires_at_millis, key)) = self.expiration_index.first().cloned() {
            if expires_at_millis > now_millis {
                break;
            }
            self.expiration_index
                .remove(&(expires_at_millis, key.clone()));
            if self
                .entries
                .get(&key)
                .is_some_and(|entry| entry.expires_at_millis == expires_at_millis)
            {
                self.entries.remove(&key);
            }
        }
        debug_assert_eq!(self.expiration_index.len(), self.entries.len());
    }
}

fn prune_expired(entry: &mut LocalEntry, now_millis: u64, window_millis: u64) {
    while entry
        .accepted_at
        .front()
        .is_some_and(|accepted_at| now_millis.saturating_sub(*accepted_at) >= window_millis)
    {
        entry.accepted_at.pop_front();
    }
}

fn entry_retry_millis(entry: &LocalEntry, now_millis: u64, window_millis: u64) -> u64 {
    entry
        .accepted_at
        .front()
        .map_or(window_millis, |accepted_at| {
            window_millis.saturating_sub(now_millis.saturating_sub(*accepted_at))
        })
}

fn missing_bucket_count(
    entries: &HashMap<String, LocalEntry>,
    buckets: &[AdmissionBucket],
) -> usize {
    buckets
        .iter()
        .filter(|bucket| !entries.contains_key(&bucket.key))
        .map(|bucket| bucket.key.as_str())
        .collect::<HashSet<_>>()
        .len()
}

pub(crate) trait MonotonicClock: Send + Sync {
    fn elapsed_millis(&self) -> u64;
}

struct SystemMonotonicClock(Instant);

impl SystemMonotonicClock {
    fn new() -> Self {
        Self(Instant::now())
    }
}

impl MonotonicClock for SystemMonotonicClock {
    fn elapsed_millis(&self) -> u64 {
        u64::try_from(self.0.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

#[derive(Debug, Default)]
struct BackendState {
    fallback_until_millis: u64,
    degraded: bool,
}

pub(crate) struct AdmissionService {
    namespace: Arc<str>,
    digest_key: [u8; 32],
    maximum_processes: u32,
    distributed: Option<Arc<dyn DistributedAdmissionCounter>>,
    local: Mutex<LocalCounters>,
    backend_state: Mutex<BackendState>,
    monotonic: Arc<dyn MonotonicClock>,
}

impl AdmissionService {
    pub(crate) fn new(
        namespace: String,
        digest_root: [u8; 32],
        maximum_processes: u32,
        distributed: Option<Arc<dyn DistributedAdmissionCounter>>,
    ) -> Self {
        Self::new_with_monotonic(
            namespace,
            digest_root,
            maximum_processes,
            distributed,
            Arc::new(SystemMonotonicClock::new()),
        )
    }

    fn new_with_monotonic(
        namespace: String,
        digest_root: [u8; 32],
        maximum_processes: u32,
        distributed: Option<Arc<dyn DistributedAdmissionCounter>>,
        monotonic: Arc<dyn MonotonicClock>,
    ) -> Self {
        let mut mac = HmacSha256::new_from_slice(&digest_root).expect("HMAC accepts any key size");
        mac.update(b"owlauth/runtime-admission/key/v1");
        let digest_key: [u8; 32] = mac.finalize().into_bytes().into();
        Self {
            namespace: Arc::from(namespace),
            digest_key,
            maximum_processes,
            distributed,
            local: Mutex::new(LocalCounters::new(LOCAL_CAPACITY)),
            backend_state: Mutex::new(BackendState::default()),
            monotonic,
        }
    }

    #[cfg(test)]
    pub(crate) fn new_with_test_monotonic(
        namespace: String,
        digest_root: [u8; 32],
        maximum_processes: u32,
        distributed: Option<Arc<dyn DistributedAdmissionCounter>>,
        monotonic: Arc<dyn MonotonicClock>,
    ) -> Self {
        Self::new_with_monotonic(
            namespace,
            digest_root,
            maximum_processes,
            distributed,
            monotonic,
        )
    }

    pub(crate) async fn admit(
        &self,
        endpoint: AdmissionEndpoint,
        client_address: &str,
        dimensions: &[AdmissionDimension<'_>],
    ) -> AdmissionDecision {
        self.admit_stage(endpoint, Some(client_address), dimensions, "combined")
            .await
    }

    /// Hard request-derived gate for email challenge authority. This stage is deliberately
    /// limited to dimensions available without `PostgreSQL`: the transport client and the opaque
    /// interaction credential. Its purpose-separated keys cannot consume or replenish the later
    /// owner-scoped quota.
    pub(crate) async fn admit_email_pre_authority(
        &self,
        endpoint: AdmissionEndpoint,
        client_address: &str,
        interaction: &str,
    ) -> AdmissionDecision {
        let dimensions = [AdmissionDimension {
            kind: AdmissionDimensionKind::Credential,
            value: interaction,
            email_scope: None,
        }];
        self.admit_stage(endpoint, Some(client_address), &dimensions, "pre_authority")
            .await
    }

    /// Owner-scoped second stage after interaction authority has established Project and
    /// Application ownership. Client and interaction buckets are intentionally not charged a
    /// second time; both stages must pass, so splitting them cannot grant additional quota.
    pub(crate) async fn admit_email_authoritative(
        &self,
        endpoint: AdmissionEndpoint,
        dimensions: &[AdmissionDimension<'_>],
    ) -> AdmissionDecision {
        self.admit_stage(endpoint, None, dimensions, "authoritative")
            .await
    }

    async fn admit_stage(
        &self,
        endpoint: AdmissionEndpoint,
        client_address: Option<&str>,
        dimensions: &[AdmissionDimension<'_>],
        stage: &str,
    ) -> AdmissionDecision {
        let policy = endpoint.policy();
        let local_limit = policy.limit / self.maximum_processes;
        debug_assert!(local_limit > 0);
        let distributed_buckets = self.buckets(
            endpoint,
            client_address,
            dimensions,
            policy.limit,
            policy.window_millis,
            stage,
        );
        let local_buckets = self.buckets(
            endpoint,
            client_address,
            dimensions,
            local_limit,
            policy.window_millis,
            stage,
        );
        let attempt_started_millis = self.monotonic.elapsed_millis();
        let fallback_is_sticky = attempt_started_millis
            < self
                .backend_state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .fallback_until_millis;

        let decision = if !fallback_is_sticky && let Some(distributed) = &self.distributed {
            match distributed.evaluate(&distributed_buckets).await {
                Ok(AdmissionDecision::Allowed) => {
                    self.mark_backend_recovered(attempt_started_millis, endpoint);
                    // Every accepted Redis request must also consume this process's local share.
                    // Therefore Redis loss, flush, failover, or recovery cannot add quota.
                    self.evaluate_local(&local_buckets, policy)
                }
                Ok(rejected @ AdmissionDecision::Rejected { .. }) => {
                    self.mark_backend_recovered(attempt_started_millis, endpoint);
                    rejected
                }
                Err(_) => {
                    Self::observe_backend_error(endpoint);
                    self.enter_fallback(policy, endpoint);
                    self.evaluate_local(&local_buckets, policy)
                }
            }
        } else {
            self.evaluate_local(&local_buckets, policy)
        };
        Self::observe_decision(endpoint, decision);
        decision
    }

    fn evaluate_local(
        &self,
        buckets: &[AdmissionBucket],
        policy: AdmissionPolicy,
    ) -> AdmissionDecision {
        let now = self.monotonic.elapsed_millis();
        self.local
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .evaluate(buckets, now, policy.window_millis)
    }

    fn observe_backend_error(endpoint: AdmissionEndpoint) {
        tracing::warn!(
            event = "runtime_admission_backend_error",
            backend = "distributed",
            endpoint = endpoint.as_str(),
            "the Runtime admission backend operation failed"
        );
    }

    fn observe_decision(endpoint: AdmissionEndpoint, decision: AdmissionDecision) {
        if let AdmissionDecision::Rejected {
            retry_after_seconds,
            reason,
            ..
        } = decision
        {
            tracing::warn!(
                event = "runtime_admission_rejected",
                endpoint = endpoint.as_str(),
                reason = reason.as_str(),
                retry_after_seconds,
                "a Runtime request was rejected before authority work"
            );
        }
    }

    fn enter_fallback(&self, policy: AdmissionPolicy, endpoint: AdmissionEndpoint) {
        let now = self.monotonic.elapsed_millis();
        let window = now / policy.window_millis;
        let until = window
            .saturating_add(1)
            .saturating_mul(policy.window_millis);
        let entered = {
            let mut state = self
                .backend_state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let entered = !state.degraded;
            state.degraded = true;
            state.fallback_until_millis = state.fallback_until_millis.max(until);
            entered
        };
        if entered {
            tracing::warn!(
                event = "runtime_admission_fallback_entered",
                backend = "distributed",
                endpoint = endpoint.as_str(),
                "Runtime admission entered conservative local fallback"
            );
        }
    }

    fn mark_backend_recovered(&self, attempt_started_millis: u64, endpoint: AdmissionEndpoint) {
        let recovered = {
            let mut state = self
                .backend_state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // A success that began before a concurrent failure established the sticky interval
            // cannot cancel that newer failure. Only a post-interval attempt proves recovery.
            if state.degraded && attempt_started_millis >= state.fallback_until_millis {
                state.degraded = false;
                state.fallback_until_millis = 0;
                true
            } else {
                false
            }
        };
        if recovered {
            tracing::info!(
                event = "runtime_admission_backend_recovered",
                backend = "distributed",
                endpoint = endpoint.as_str(),
                "the Runtime admission backend recovered"
            );
        }
    }

    fn buckets(
        &self,
        endpoint: AdmissionEndpoint,
        client_address: Option<&str>,
        dimensions: &[AdmissionDimension<'_>],
        limit: u32,
        window_millis: u64,
        stage: &str,
    ) -> Vec<AdmissionBucket> {
        let mut buckets =
            Vec::with_capacity(dimensions.len() + usize::from(client_address.is_some()));
        if let Some(client_address) = client_address {
            buckets.push(AdmissionBucket {
                key: format!(
                    "{}:{}:{}:{}:client:{}",
                    self.namespace,
                    SCHEMA_VERSION,
                    endpoint.as_str(),
                    stage,
                    self.digest("client", client_address),
                ),
                limit,
                window_millis,
            });
        }
        buckets.extend(dimensions.iter().map(|dimension| {
            let kind = dimension.kind.as_str();
            let digest = if dimension.kind == AdmissionDimensionKind::Email {
                self.scoped_email_digest(dimension)
            } else {
                self.digest(kind, dimension.value)
            };
            AdmissionBucket {
                key: format!(
                    "{}:{}:{}:{}:{}:{}",
                    self.namespace,
                    SCHEMA_VERSION,
                    endpoint.as_str(),
                    stage,
                    kind,
                    digest,
                ),
                // Challenge/resend use a reviewed 4:1 owner/client-to-address ratio. The scoped
                // address bucket can therefore saturate alone; process-local division remains
                // conservative because both 256 and 64 cover the maximum 64-process roster.
                limit: if dimension.kind == AdmissionDimensionKind::Email {
                    limit / 4
                } else {
                    limit
                },
                window_millis,
            }
        }));
        buckets
    }

    fn scoped_email_digest(&self, dimension: &AdmissionDimension<'_>) -> String {
        let mut mac =
            HmacSha256::new_from_slice(&self.digest_key).expect("HMAC accepts any key size");
        mac.update(b"owlauth/runtime-admission/scoped-email/v1");
        let Some((project_id, application_id)) = dimension.email_scope else {
            // Only server-resolved interaction authority constructs Email dimensions. Retain a
            // fail-closed domain if an internal caller violates that contract.
            mac.update(b"\0missing-authoritative-scope");
            return URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        };
        for (label, value) in [
            (b"project".as_slice(), project_id),
            (b"application".as_slice(), application_id),
            (b"canonical-email".as_slice(), dimension.value),
        ] {
            mac.update(&[0]);
            mac.update(label);
            mac.update(&[0]);
            mac.update(value.as_bytes());
        }
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }

    fn digest(&self, kind: &str, value: &str) -> String {
        let mut mac =
            HmacSha256::new_from_slice(&self.digest_key).expect("HMAC accepts any key size");
        mac.update(kind.as_bytes());
        mac.update(&[0]);
        mac.update(value.as_bytes());
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }
}

fn retry_seconds(milliseconds: u64) -> u64 {
    milliseconds.div_ceil(1_000).clamp(1, 60)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use tokio::sync::Notify;

    use super::*;

    struct TestClock {
        monotonic_millis: AtomicU64,
    }

    impl TestClock {
        fn new(seconds: u64) -> Self {
            Self {
                monotonic_millis: AtomicU64::new(seconds * 1_000),
            }
        }

        fn set(&self, seconds: u64) {
            self.monotonic_millis
                .store(seconds * 1_000, Ordering::Relaxed);
        }
    }

    impl MonotonicClock for TestClock {
        fn elapsed_millis(&self) -> u64 {
            self.monotonic_millis.load(Ordering::Relaxed)
        }
    }

    fn service(clock: Arc<TestClock>, maximum_processes: u32) -> AdmissionService {
        AdmissionService::new_with_monotonic(
            "test".to_owned(),
            [7; 32],
            maximum_processes,
            None,
            clock,
        )
    }

    struct FailedDistributedCounter;

    struct TransitionDistributedCounter(AtomicU64);

    struct ConcurrentTransitionCounter {
        calls: AtomicU64,
        success_started: Notify,
        release_success: Notify,
    }

    struct CrossWindowFailureCounter {
        calls: AtomicU64,
        old_started: Notify,
        release_old: Notify,
    }

    #[async_trait]
    impl DistributedAdmissionCounter for CrossWindowFailureCounter {
        async fn evaluate(
            &self,
            _buckets: &[AdmissionBucket],
        ) -> Result<AdmissionDecision, DistributedAdmissionError> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                self.old_started.notify_one();
                self.release_old.notified().await;
            }
            Err(DistributedAdmissionError)
        }
    }

    #[async_trait]
    impl DistributedAdmissionCounter for ConcurrentTransitionCounter {
        async fn evaluate(
            &self,
            _buckets: &[AdmissionBucket],
        ) -> Result<AdmissionDecision, DistributedAdmissionError> {
            match self.calls.fetch_add(1, Ordering::SeqCst) {
                0 => {
                    self.success_started.notify_one();
                    self.release_success.notified().await;
                    Ok(AdmissionDecision::Allowed)
                }
                1 => Err(DistributedAdmissionError),
                _ => Ok(AdmissionDecision::Allowed),
            }
        }
    }

    #[async_trait]
    impl DistributedAdmissionCounter for TransitionDistributedCounter {
        async fn evaluate(
            &self,
            _buckets: &[AdmissionBucket],
        ) -> Result<AdmissionDecision, DistributedAdmissionError> {
            match self.0.fetch_add(1, Ordering::Relaxed) {
                1 => Err(DistributedAdmissionError),
                _ => Ok(AdmissionDecision::Allowed),
            }
        }
    }

    #[async_trait]
    impl DistributedAdmissionCounter for FailedDistributedCounter {
        async fn evaluate(
            &self,
            _buckets: &[AdmissionBucket],
        ) -> Result<AdmissionDecision, DistributedAdmissionError> {
            Err(DistributedAdmissionError)
        }
    }

    #[test]
    fn every_endpoint_has_a_unique_stable_name() {
        let names = AdmissionEndpoint::ALL.map(AdmissionEndpoint::as_str);
        assert_eq!(
            names,
            [
                "public_config",
                "project_jwks",
                "login_start",
                "hosted_interaction",
                "hosted_identity_mutation",
                "managed_reauthorization_start",
                "identity_mutation_method",
                "identity_mutation_email_challenge",
                "identity_mutation_email_otp_verify",
                "identity_mutation_email_magic_confirm",
                "identity_mutation_confirm",
                "provider_selection",
                "email_selection",
                "email_challenge",
                "email_resend",
                "email_otp_verify",
                "email_magic_read",
                "email_magic_confirm",
                "session_reuse",
                "provider_callback",
                "handoff_exchange",
                "refresh",
                "current_user",
                "application_logout",
                "browser_logout_prepare",
                "browser_logout_read",
                "browser_logout_confirm",
            ]
        );
        assert_eq!(
            names.into_iter().collect::<BTreeSet<_>>().len(),
            names.len()
        );
    }

    #[test]
    fn every_endpoint_has_a_reviewed_policy_that_supports_the_process_bound() {
        for endpoint in AdmissionEndpoint::ALL {
            let policy = endpoint.policy();
            assert!(policy.limit >= 64);
            assert_eq!(policy.window_millis, 60_000);
        }
    }

    #[test]
    fn scoped_email_keys_are_atomic_and_isolated_by_authoritative_owners() {
        let service = service(Arc::new(TestClock::new(10)), 1);
        let dimensions = |project, application| {
            vec![
                AdmissionDimension {
                    kind: AdmissionDimensionKind::Project,
                    value: project,
                    email_scope: None,
                },
                AdmissionDimension {
                    kind: AdmissionDimensionKind::Application,
                    value: application,
                    email_scope: None,
                },
                AdmissionDimension {
                    kind: AdmissionDimensionKind::Credential,
                    value: "interaction",
                    email_scope: None,
                },
                AdmissionDimension {
                    kind: AdmissionDimensionKind::Email,
                    value: "equal@example.test",
                    email_scope: Some((project, application)),
                },
            ]
        };
        let first = service.buckets(
            AdmissionEndpoint::EmailChallenge,
            Some("203.0.113.10"),
            &dimensions("project-a", "application-a"),
            64,
            60_000,
            "combined",
        );
        let other_application = service.buckets(
            AdmissionEndpoint::EmailChallenge,
            Some("203.0.113.10"),
            &dimensions("project-a", "application-b"),
            64,
            60_000,
            "combined",
        );
        let other_project = service.buckets(
            AdmissionEndpoint::EmailChallenge,
            Some("203.0.113.10"),
            &dimensions("project-b", "application-a"),
            64,
            60_000,
            "combined",
        );
        assert_eq!(first.len(), 5);
        for kind in [
            "client",
            "project",
            "application",
            "credential",
            "email_admission_v1",
        ] {
            assert_eq!(
                first
                    .iter()
                    .filter(|bucket| bucket.key.contains(&format!(":{kind}:")))
                    .count(),
                1,
                "one atomic evaluation increments {kind} exactly once"
            );
        }
        let email_key = |buckets: &[AdmissionBucket]| {
            buckets
                .iter()
                .find(|bucket| bucket.key.contains(":email_admission_v1:"))
                .expect("scoped email bucket")
                .key
                .clone()
        };
        assert_ne!(email_key(&first), email_key(&other_application));
        assert_ne!(email_key(&first), email_key(&other_project));
    }

    #[tokio::test]
    async fn email_pre_authority_gate_is_hard_and_purpose_separated() {
        let service = service(Arc::new(TestClock::new(10)), 1);
        for _ in 0..256 {
            assert_eq!(
                service
                    .admit_email_pre_authority(
                        AdmissionEndpoint::EmailChallenge,
                        "203.0.113.10",
                        "opaque-interaction",
                    )
                    .await,
                AdmissionDecision::Allowed
            );
        }
        assert!(matches!(
            service
                .admit_email_pre_authority(
                    AdmissionEndpoint::EmailChallenge,
                    "203.0.113.10",
                    "opaque-interaction",
                )
                .await,
            AdmissionDecision::Rejected {
                reason: AdmissionRejectionReason::Quota,
                suppression_eligible: false,
                ..
            }
        ));

        // The authoritative stage neither grants another pre-authority attempt nor double-charges
        // its client/credential dimensions. It has independent owner-scoped keys and must also pass.
        assert_eq!(
            service
                .admit_email_authoritative(
                    AdmissionEndpoint::EmailChallenge,
                    &[AdmissionDimension {
                        kind: AdmissionDimensionKind::Project,
                        value: "server-resolved-project",
                        email_scope: None,
                    }],
                )
                .await,
            AdmissionDecision::Allowed
        );
        assert!(matches!(
            service
                .admit_email_pre_authority(
                    AdmissionEndpoint::EmailChallenge,
                    "203.0.113.10",
                    "opaque-interaction",
                )
                .await,
            AdmissionDecision::Rejected { .. }
        ));
    }

    #[tokio::test]
    async fn scoped_email_quota_does_not_cross_project_or_application() {
        let service = service(Arc::new(TestClock::new(10)), 1);
        for request in 0..64 {
            let client = format!("203.0.113.{request}");
            assert_eq!(
                service
                    .admit(
                        AdmissionEndpoint::EmailChallenge,
                        &client,
                        &[AdmissionDimension {
                            kind: AdmissionDimensionKind::Email,
                            value: "equal@example.test",
                            email_scope: Some(("project-a", "application-a")),
                        }],
                    )
                    .await,
                AdmissionDecision::Allowed
            );
        }
        assert!(matches!(
            service
                .admit(
                    AdmissionEndpoint::EmailChallenge,
                    "198.51.100.1",
                    &[AdmissionDimension {
                        kind: AdmissionDimensionKind::Email,
                        value: "equal@example.test",
                        email_scope: Some(("project-a", "application-a")),
                    }],
                )
                .await,
            AdmissionDecision::Rejected {
                reason: AdmissionRejectionReason::Quota,
                suppression_eligible: true,
                ..
            }
        ));
        for scope in [
            ("project-a", "application-b"),
            ("project-b", "application-a"),
        ] {
            assert_eq!(
                service
                    .admit(
                        AdmissionEndpoint::EmailChallenge,
                        "198.51.100.2",
                        &[AdmissionDimension {
                            kind: AdmissionDimensionKind::Email,
                            value: "equal@example.test",
                            email_scope: Some(scope),
                        }],
                    )
                    .await,
                AdmissionDecision::Allowed
            );
        }
    }

    #[test]
    fn keys_do_not_contain_raw_dimensions() {
        let clock = Arc::new(TestClock::new(10));
        let service = service(clock, 1);
        let buckets = service.buckets(
            AdmissionEndpoint::Refresh,
            Some("203.0.113.9"),
            &[
                AdmissionDimension {
                    kind: AdmissionDimensionKind::Project,
                    value: "project-secret",
                    email_scope: None,
                },
                AdmissionDimension {
                    kind: AdmissionDimensionKind::Credential,
                    value: "refresh-secret",
                    email_scope: None,
                },
            ],
            10,
            60_000,
            "combined",
        );
        let joined = buckets
            .iter()
            .map(|bucket| bucket.key.as_str())
            .collect::<Vec<_>>()
            .join("|");
        assert!(!joined.contains("203.0.113.9"));
        assert!(!joined.contains("project-secret"));
        assert!(!joined.contains("refresh-secret"));
        assert!(joined.contains("test:v1:refresh"));
    }

    #[tokio::test]
    async fn local_limit_rejects_exactly_and_recovers_after_the_rolling_window() {
        let clock = Arc::new(TestClock::new(1));
        let service = service(Arc::clone(&clock), 64);
        for _ in 0..3 {
            assert_eq!(
                service
                    .admit(AdmissionEndpoint::PublicConfig, "client", &[])
                    .await,
                AdmissionDecision::Allowed
            );
        }
        // Public config has a local quota of floor(600 / 64) = 9.
        for _ in 3..9 {
            assert_eq!(
                service
                    .admit(AdmissionEndpoint::PublicConfig, "client", &[])
                    .await,
                AdmissionDecision::Allowed
            );
        }
        assert_eq!(
            service
                .admit(AdmissionEndpoint::PublicConfig, "client", &[])
                .await,
            AdmissionDecision::Rejected {
                retry_after_seconds: 60,
                reason: AdmissionRejectionReason::Quota,
                suppression_eligible: false,
            }
        );
        clock.set(61);
        assert_eq!(
            service
                .admit(AdmissionEndpoint::PublicConfig, "client", &[])
                .await,
            AdmissionDecision::Allowed
        );
    }

    #[tokio::test]
    async fn local_guard_does_not_reset_at_a_fixed_window_boundary() {
        let clock = Arc::new(TestClock::new(59));
        let service = service(Arc::clone(&clock), 64);
        assert_eq!(
            service
                .admit(AdmissionEndpoint::ProviderSelection, "client", &[])
                .await,
            AdmissionDecision::Allowed
        );

        clock.set(60);
        assert!(matches!(
            service
                .admit(AdmissionEndpoint::ProviderSelection, "client", &[])
                .await,
            AdmissionDecision::Rejected { .. }
        ));
        clock.set(119);
        assert_eq!(
            service
                .admit(AdmissionEndpoint::ProviderSelection, "client", &[])
                .await,
            AdmissionDecision::Allowed
        );
    }

    #[tokio::test]
    async fn backend_transition_cannot_add_quota_within_one_window() {
        let clock = Arc::new(TestClock::new(1));
        let distributed = Arc::new(TransitionDistributedCounter(AtomicU64::new(0)));
        let service = AdmissionService::new_with_monotonic(
            "test".to_owned(),
            [7; 32],
            64,
            Some(distributed.clone()),
            clock.clone(),
        );
        assert_eq!(
            service
                .admit(AdmissionEndpoint::ProviderSelection, "client", &[])
                .await,
            AdmissionDecision::Allowed
        );
        assert!(matches!(
            service
                .admit(AdmissionEndpoint::ProviderSelection, "client", &[])
                .await,
            AdmissionDecision::Rejected { .. }
        ));
        assert!(matches!(
            service
                .admit(AdmissionEndpoint::ProviderSelection, "client", &[])
                .await,
            AdmissionDecision::Rejected { .. }
        ));
        assert_eq!(distributed.0.load(Ordering::Relaxed), 2);
        assert!(
            service
                .backend_state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .degraded
        );

        clock.set(61);
        assert_eq!(
            service
                .admit(AdmissionEndpoint::ProviderSelection, "client", &[])
                .await,
            AdmissionDecision::Allowed
        );
        assert_eq!(distributed.0.load(Ordering::Relaxed), 3);
        assert!(
            !service
                .backend_state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .degraded
        );
    }

    #[tokio::test]
    async fn concurrent_distributed_success_and_failure_cannot_add_local_quota() {
        let clock = Arc::new(TestClock::new(1));
        let distributed = Arc::new(ConcurrentTransitionCounter {
            calls: AtomicU64::new(0),
            success_started: Notify::new(),
            release_success: Notify::new(),
        });
        let service = Arc::new(AdmissionService::new_with_monotonic(
            "test".to_owned(),
            [7; 32],
            64,
            Some(distributed.clone()),
            clock,
        ));
        let successful_redis_request = {
            let service = Arc::clone(&service);
            tokio::spawn(async move {
                service
                    .admit(AdmissionEndpoint::ProviderSelection, "client", &[])
                    .await
            })
        };
        distributed.success_started.notified().await;

        let fallback_request = service
            .admit(AdmissionEndpoint::ProviderSelection, "client", &[])
            .await;
        distributed.release_success.notify_one();
        let redis_request = successful_redis_request.await.unwrap();

        assert_eq!(fallback_request, AdmissionDecision::Allowed);
        assert!(matches!(redis_request, AdmissionDecision::Rejected { .. }));
        assert_eq!(distributed.calls.load(Ordering::SeqCst), 2);
        let state = service
            .backend_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(state.degraded);
        assert_eq!(state.fallback_until_millis, 60_000);
    }

    #[tokio::test]
    async fn distributed_failure_uses_the_conservative_bounded_local_fallback() {
        let clock = Arc::new(TestClock::new(1));
        let service = AdmissionService::new_with_monotonic(
            "test".to_owned(),
            [7; 32],
            64,
            Some(Arc::new(FailedDistributedCounter)),
            clock,
        );
        assert_eq!(
            service
                .admit(AdmissionEndpoint::ProviderSelection, "client", &[])
                .await,
            AdmissionDecision::Allowed
        );
        assert!(matches!(
            service
                .admit(AdmissionEndpoint::ProviderSelection, "client", &[])
                .await,
            AdmissionDecision::Rejected { .. }
        ));
    }

    #[tokio::test]
    async fn old_distributed_failure_cannot_end_a_newer_sticky_window() {
        let clock = Arc::new(TestClock::new(59));
        let distributed = Arc::new(CrossWindowFailureCounter {
            calls: AtomicU64::new(0),
            old_started: Notify::new(),
            release_old: Notify::new(),
        });
        let service = Arc::new(AdmissionService::new_with_monotonic(
            "test".to_owned(),
            [7; 32],
            64,
            Some(distributed.clone()),
            clock.clone(),
        ));
        let old_request = {
            let service = Arc::clone(&service);
            tokio::spawn(async move {
                service
                    .admit(AdmissionEndpoint::ProviderSelection, "client", &[])
                    .await
            })
        };
        distributed.old_started.notified().await;

        clock.set(60);
        assert_eq!(
            service
                .admit(AdmissionEndpoint::ProviderSelection, "client", &[])
                .await,
            AdmissionDecision::Allowed
        );
        distributed.release_old.notify_one();
        assert!(matches!(
            old_request.await.unwrap(),
            AdmissionDecision::Rejected { .. }
        ));
        assert!(matches!(
            service
                .admit(AdmissionEndpoint::ProviderSelection, "client", &[])
                .await,
            AdmissionDecision::Rejected { .. }
        ));
        assert_eq!(distributed.calls.load(Ordering::SeqCst), 2);

        clock.set(120);
        assert_eq!(
            service
                .admit(AdmissionEndpoint::ProviderSelection, "client", &[])
                .await,
            AdmissionDecision::Allowed
        );
        assert_eq!(distributed.calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn suppression_requires_only_the_scoped_email_bucket_to_be_saturated() {
        let mut local = LocalCounters::new(8);
        let bucket = |key: &str| AdmissionBucket {
            key: key.to_owned(),
            limit: 1,
            window_millis: 60_000,
        };
        let email = bucket("test:v1:email_challenge:email_admission_v1:digest");
        let project = bucket("test:v1:email_challenge:project:digest");
        assert_eq!(
            local.evaluate(std::slice::from_ref(&email), 0, 60_000),
            AdmissionDecision::Allowed
        );
        assert!(matches!(
            local.evaluate(std::slice::from_ref(&email), 1, 60_000),
            AdmissionDecision::Rejected {
                suppression_eligible: true,
                ..
            }
        ));

        let mut mixed = LocalCounters::new(8);
        assert_eq!(
            mixed.evaluate(&[email.clone(), project.clone()], 0, 60_000),
            AdmissionDecision::Allowed
        );
        assert!(matches!(
            mixed.evaluate(&[email, project], 1, 60_000),
            AdmissionDecision::Rejected {
                suppression_eligible: false,
                ..
            }
        ));
    }

    #[test]
    fn local_multi_bucket_rejection_does_not_partially_increment() {
        let mut local = LocalCounters::new(8);
        let bucket = |key: &str, limit| AdmissionBucket {
            key: key.to_owned(),
            limit,
            window_millis: 60_000,
        };
        assert_eq!(
            local.evaluate(&[bucket("full", 1)], 0, 60_000),
            AdmissionDecision::Allowed
        );
        assert!(matches!(
            local.evaluate(&[bucket("fresh", 1), bucket("full", 1)], 0, 60_000),
            AdmissionDecision::Rejected { .. }
        ));
        assert_eq!(
            local.evaluate(&[bucket("fresh", 1)], 0, 60_000),
            AdmissionDecision::Allowed
        );
    }

    #[test]
    fn local_map_fails_closed_at_capacity_and_only_expires_old_events() {
        let mut local = LocalCounters::new(2);
        let bucket = |key: &str, limit| AdmissionBucket {
            key: key.to_owned(),
            limit,
            window_millis: 60_000,
        };
        assert_eq!(
            local.evaluate(&[bucket("target", 1)], 0, 60_000),
            AdmissionDecision::Allowed
        );
        assert_eq!(
            local.evaluate(&[bucket("churn-a", 10)], 0, 60_000),
            AdmissionDecision::Allowed
        );
        assert!(matches!(
            local.evaluate(&[bucket("churn-b", 10)], 0, 60_000),
            AdmissionDecision::Rejected { .. }
        ));
        assert!(matches!(
            local.evaluate(&[bucket("target", 1)], 0, 60_000),
            AdmissionDecision::Rejected { .. }
        ));
        assert_eq!(local.entries.len(), 2);
        assert_eq!(local.expiration_index.len(), 2);
        assert!(local.entries.contains_key("target"));

        assert_eq!(
            local.evaluate(&[bucket("churn-b", 10)], 60_000, 60_000),
            AdmissionDecision::Allowed
        );
        assert_eq!(local.entries.len(), 1);
        assert_eq!(local.expiration_index.len(), 1);
        assert!(local.entries.contains_key("churn-b"));
    }

    #[test]
    fn local_capacity_uses_ordered_last_acceptance_expiry_for_retry_after() {
        let mut local = LocalCounters::new(2);
        let bucket = |key: &str| AdmissionBucket {
            key: key.to_owned(),
            limit: 10,
            window_millis: 60_000,
        };

        assert_eq!(
            local.evaluate(&[bucket("older-first-event")], 0, 60_000),
            AdmissionDecision::Allowed
        );
        assert_eq!(
            local.evaluate(&[bucket("expires-first")], 10_000, 60_000),
            AdmissionDecision::Allowed
        );
        // Refreshing this entry proves capacity is released by its last accepted event, not its
        // first event. The other entry is therefore the first whole entry that can be removed.
        assert_eq!(
            local.evaluate(&[bucket("older-first-event")], 30_000, 60_000),
            AdmissionDecision::Allowed
        );
        assert_eq!(
            local.evaluate(&[bucket("new")], 40_000, 60_000),
            AdmissionDecision::Rejected {
                retry_after_seconds: 30,
                reason: AdmissionRejectionReason::LocalCapacity,
                suppression_eligible: false,
            }
        );
        assert_eq!(local.expiration_index.len(), local.entries.len());

        assert_eq!(
            local.evaluate(&[bucket("new")], 70_000, 60_000),
            AdmissionDecision::Allowed
        );
        assert!(local.entries.contains_key("older-first-event"));
        assert!(!local.entries.contains_key("expires-first"));
        assert!(local.entries.contains_key("new"));
        assert_eq!(local.expiration_index.len(), local.entries.len());
    }

    #[test]
    fn rejection_reason_labels_are_an_exhaustive_low_cardinality_set() {
        assert_eq!(AdmissionRejectionReason::Quota.as_str(), "quota");
        assert_eq!(
            AdmissionRejectionReason::LocalCapacity.as_str(),
            "local_capacity"
        );
    }

    #[test]
    fn process_quota_uses_floor_and_never_exceeds_deployment_quota() {
        for endpoint in AdmissionEndpoint::ALL {
            let deployment = endpoint.policy().limit;
            for processes in 1..=64 {
                let local = deployment / processes;
                assert!(local >= 1);
                assert!(local * processes <= deployment);
            }
        }
    }
}
