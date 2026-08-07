use std::{
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;
use zeroize::Zeroizing;

use crate::{
    BrowserLogoutPreparation, CompletionResponse, CredentialPair, CredentialPairRecord,
    CredentialPairWire, CurrentUser, Error, ErrorCategory, HandoffGuard, HandoffRequest,
    HttpMethod, HttpRequest, HttpResponse, JwksDocument, LocalAction, LoginStart,
    LoginStartRequest, LoginStartResponse, PendingLogin, PendingLoginRecord, PublicConfiguration,
    RefreshRequest, RetryPolicy, RuntimeErrorWire, Transport, TransportFailure,
    TransportFailureKind, ValidatedCallback,
    error::{configuration, protocol},
    transport::default_transport,
};

const MAX_RESPONSE_BYTES: usize = 65_536;
const PENDING_SCHEMA_VERSION: u8 = 1;

#[derive(Clone, Copy)]
struct ResponsePolicy {
    operation: &'static str,
    expected_status: u16,
    sensitive: bool,
    action: LocalAction,
}

impl ResponsePolicy {
    const fn new(
        operation: &'static str,
        expected_status: u16,
        sensitive: bool,
        action: LocalAction,
    ) -> Self {
        Self {
            operation,
            expected_status,
            sensitive,
            action,
        }
    }
}

/// Cloneable caller-controlled cancellation boundary for one SDK operation.
#[derive(Clone, Default)]
pub struct CancellationToken {
    inner: Arc<CancellationState>,
}

#[derive(Default)]
struct CancellationState {
    cancelled: AtomicBool,
    notify: tokio::sync::Notify,
}

impl CancellationToken {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests cancellation. Calling this method more than once has no additional effect.
    pub fn cancel(&self) {
        if !self.inner.cancelled.swap(true, Ordering::AcqRel) {
            self.inner.notify.notify_waiters();
        }
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::Acquire)
    }

    async fn cancelled(&self) {
        loop {
            if self.is_cancelled() {
                return;
            }
            let notified = self.inner.notify.notified();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

impl std::fmt::Debug for CancellationToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CancellationToken")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

/// Optional controls for one SDK operation.
#[derive(Clone, Debug, Default)]
pub struct OperationOptions {
    cancellation: Option<CancellationToken>,
}

impl OperationOptions {
    #[must_use]
    pub const fn new() -> Self {
        Self { cancellation: None }
    }

    #[must_use]
    pub fn with_cancellation(cancellation: CancellationToken) -> Self {
        Self {
            cancellation: Some(cancellation),
        }
    }

    #[must_use]
    pub const fn cancellation(&self) -> Option<&CancellationToken> {
        self.cancellation.as_ref()
    }
}

/// Immutable one-Project/one-Application client configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientConfig {
    pub runtime_url: String,
    pub project_id: String,
    pub application_id: String,
    pub publishable_key: String,
    pub allow_insecure_loopback: bool,
    pub deadline: Duration,
}

impl ClientConfig {
    #[must_use]
    pub fn new(
        runtime_url: impl Into<String>,
        project_id: impl Into<String>,
        application_id: impl Into<String>,
        publishable_key: impl Into<String>,
    ) -> Self {
        Self {
            runtime_url: runtime_url.into(),
            project_id: project_id.into(),
            application_id: application_id.into(),
            publishable_key: publishable_key.into(),
            allow_insecure_loopback: false,
            deadline: Duration::from_secs(30),
        }
    }
}

/// Injectable entropy source used only to make deterministic tests possible.
pub trait EntropySource: Send + Sync {
    /// Fills the destination with cryptographically secure random bytes.
    ///
    /// # Errors
    /// Returns an error when secure entropy is unavailable.
    fn fill(&self, destination: &mut [u8]) -> Result<(), Error>;
}

/// Injectable Unix clock.
pub trait Clock: Send + Sync {
    fn now_unix_seconds(&self) -> i64;
}

#[derive(Debug)]
struct OsEntropy;
impl EntropySource for OsEntropy {
    fn fill(&self, destination: &mut [u8]) -> Result<(), Error> {
        getrandom::fill(destination).map_err(|_| {
            Error::new(
                ErrorCategory::Transport,
                "entropy_unavailable",
                "Secure randomness is unavailable.",
                RetryPolicy::Never,
                LocalAction::None,
                "start_login",
            )
        })
    }
}

#[derive(Debug)]
struct SystemClock;
impl Clock for SystemClock {
    fn now_unix_seconds(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |value| {
                i64::try_from(value.as_secs()).unwrap_or(i64::MAX)
            })
    }
}

/// Async Project Auth protocol client. It owns no pending or credential persistence.
#[derive(Clone)]
pub struct Client {
    base: Url,
    origin: String,
    project_id: String,
    application_id: String,
    publishable_key: String,
    deadline: Duration,
    transport: Arc<dyn Transport>,
    entropy: Arc<dyn EntropySource>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Client")
            .field("base_url", &self.base.as_str())
            .field("project_id", &self.project_id)
            .field("application_id", &self.application_id)
            .field("publishable_key", &self.publishable_key)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// Creates a client with the production HTTP transport, OS entropy, and system clock.
    ///
    /// # Errors
    /// Returns a configuration error when URL, identifiers, or deadline are invalid.
    pub fn new(config: ClientConfig) -> Result<Self, Error> {
        Self::with_dependencies(
            config,
            default_transport()?,
            Arc::new(OsEntropy),
            Arc::new(SystemClock),
        )
    }

    /// Constructs a client with explicit protocol dependencies for deterministic tests and custom transport policy.
    ///
    /// # Errors
    /// Returns a configuration error when URL, identifiers, or deadline are invalid.
    pub fn with_dependencies(
        config: ClientConfig,
        transport: Arc<dyn Transport>,
        entropy: Arc<dyn EntropySource>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, Error> {
        let base = validate_base_url(&config.runtime_url, config.allow_insecure_loopback)?;
        validate_identifier(&config.project_id, 96, "project_id")?;
        validate_identifier(&config.application_id, 96, "application_id")?;
        validate_identifier(&config.publishable_key, 128, "publishable_key")?;
        if !(Duration::from_millis(1)..=Duration::from_mins(2)).contains(&config.deadline) {
            return Err(configuration(
                "invalid_deadline",
                "The Runtime deadline is outside the supported range.",
            ));
        }
        let origin = base.origin().ascii_serialization();
        Ok(Self {
            base,
            origin,
            project_id: config.project_id,
            application_id: config.application_id,
            publishable_key: config.publishable_key,
            deadline: config.deadline,
            transport,
            entropy,
            clock,
        })
    }

    #[must_use]
    pub fn base_url(&self) -> &str {
        self.base.as_str()
    }
    #[must_use]
    pub fn project_id(&self) -> &str {
        &self.project_id
    }
    #[must_use]
    pub fn application_id(&self) -> &str {
        &self.application_id
    }

    /// Restores an explicitly exported pending-login record into this exact client without I/O.
    ///
    /// # Errors
    /// Returns a configuration error for a stale, malformed, or cross-context record.
    pub fn restore_pending_login(&self, value: PendingLoginRecord) -> Result<PendingLogin, Error> {
        let now = self.clock.now_unix_seconds();
        let now = i128::from(now);
        let created_at = i128::from(value.created_at);
        let expires_at = i128::from(value.expires_at);
        if value.schema_version != PENDING_SCHEMA_VERSION
            || value.runtime_origin != self.origin
            || value.runtime_base_path != self.base.path()
            || value.project_id != self.project_id
            || value.application_id != self.application_id
            || validate_redirect(&value.redirect_uri).is_err()
            || !(43..=128).contains(&value.verifier.len())
            || !value
                .verifier
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            || value.state.is_empty()
            || value.state.chars().count() > 1024
            || created_at > now + 60
            || expires_at < created_at - 60
            || expires_at > created_at + 660
            || expires_at > now + 660
            || now > expires_at + 60
        {
            return Err(configuration(
                "invalid_pending_record",
                "The pending-login record is invalid or belongs to another client.",
            ));
        }
        Ok(PendingLogin {
            schema_version: value.schema_version,
            runtime_origin: value.runtime_origin,
            runtime_base_path: value.runtime_base_path,
            project_id: value.project_id,
            application_id: value.application_id,
            redirect_uri: value.redirect_uri,
            verifier: Zeroizing::new(value.verifier),
            state: Zeroizing::new(value.state),
            created_at: value.created_at,
            expires_at: value.expires_at,
            guard: Arc::new(HandoffGuard::new()),
        })
    }

    /// Restores an explicitly exported credential generation into this exact client without I/O.
    ///
    /// # Errors
    /// Returns a configuration error for a malformed, expired, or cross-context record.
    pub fn restore_credentials(
        &self,
        value: CredentialPairRecord,
    ) -> Result<CredentialPair, Error> {
        let now = self.clock.now_unix_seconds();
        let now_bound = i128::from(now);
        let access_expiry = i128::from(value.access_expires_at);
        let remaining =
            i64::try_from((access_expiry - now_bound).clamp(0, 3600)).unwrap_or_default();
        let session_expiry = parse_time(&value.session_expires_at, "restore_credentials").ok();
        if value.schema_version != 1
            || value.runtime_origin != self.origin
            || value.runtime_base_path != self.base.path()
            || value.project_id != self.project_id
            || value.application_id != self.application_id
            || value.user_id.is_empty()
            || value.user_id.len() > 96
            || value.session_id.is_empty()
            || value.session_id.len() > 64
            || value.refresh_generation <= 0
            || !valid_bearer_token(&value.access_token, 16_384)
            || !valid_opaque_token(&value.refresh_token, 256)
            || value.token_type != "Bearer"
            || access_expiry > now_bound + 3660
            || value.projection_revision <= 0
            || value.projection_revision != value.projection.projection_revision
            || value.user_id != value.projection.user_id
            || !valid_projection(&value.projection)
            || session_expiry.is_none_or(|expiry| i128::from(expiry) < now_bound - 60)
        {
            return Err(configuration(
                "invalid_credential_record",
                "The credential record is invalid or belongs to another client.",
            ));
        }
        Ok(CredentialPair::from_record(value, remaining))
    }

    /// Fetches bounded public Project/Application configuration.
    ///
    /// # Errors
    /// Returns a typed transport, Runtime, or protocol error.
    pub async fn public_configuration(&self) -> Result<PublicConfiguration, Error> {
        self.public_configuration_with_options(&OperationOptions::default())
            .await
    }

    /// Fetches public configuration with explicit operation controls.
    ///
    /// # Errors
    /// Returns a typed transport, Runtime, or protocol error.
    pub async fn public_configuration_with_options(
        &self,
        options: &OperationOptions,
    ) -> Result<PublicConfiguration, Error> {
        let mut url = self.endpoint(&format!(
            "v1/projects/{}/auth/config",
            encode_path(&self.project_id)
        ))?;
        url.query_pairs_mut()
            .append_pair("application_id", &self.application_id);
        let value: PublicConfiguration = self
            .get_json(url, "get_public_application_config", 200, options)
            .await?;
        if value.project_public_id != self.project_id
            || value.application_public_id != self.application_id
            || !value
                .publishable_keys
                .iter()
                .any(|key| key == &self.publishable_key)
        {
            return Err(protocol(
                "get_public_application_config",
                "context_mismatch",
            ));
        }
        if value.project_display_name.is_empty()
            || value.project_display_name.chars().count() > 128
            || value.application_display_name.is_empty()
            || value.application_display_name.chars().count() > 128
            || value.providers.len() > 50
            || value.publishable_keys.len() > 50
            || value
                .publishable_keys
                .iter()
                .any(|key| key.is_empty() || key.len() > 128)
            || value.providers.iter().any(|provider| {
                provider.key.is_empty()
                    || provider.key.len() > 64
                    || provider.display_name.is_empty()
                    || provider.display_name.chars().count() > 128
                    || !matches!(provider.kind.as_str(), "oidc" | "google" | "github")
            })
            || {
                let mut keys = std::collections::BTreeSet::new();
                value
                    .providers
                    .iter()
                    .any(|provider| !keys.insert(&provider.key))
            }
        {
            return Err(protocol(
                "get_public_application_config",
                "invalid_response",
            ));
        }
        Ok(value)
    }

    /// Fetches Project JWKS and signing revision metadata.
    ///
    /// # Errors
    /// Returns a typed transport, Runtime, or protocol error.
    pub async fn project_jwks(&self) -> Result<JwksDocument, Error> {
        self.project_jwks_with_options(&OperationOptions::default())
            .await
    }

    /// Fetches Project JWKS with explicit operation controls.
    ///
    /// # Errors
    /// Returns a typed transport, Runtime, or protocol error.
    pub async fn project_jwks_with_options(
        &self,
        options: &OperationOptions,
    ) -> Result<JwksDocument, Error> {
        let url = self.endpoint(&format!(
            "projects/{}/.well-known/jwks.json",
            encode_path(&self.project_id)
        ))?;
        let value: JwksDocument = self.get_json(url, "get_project_jwks", 200, options).await?;
        if value.keys.len() > 100
            || value.revision <= 0
            || value.signing_epoch <= 0
            || value.keys.iter().any(|key| {
                key.kty != "OKP"
                    || key.crv != "Ed25519"
                    || key.alg != "EdDSA"
                    || key.key_use != "sig"
                    || key.kid.is_empty()
                    || key.kid.len() > 128
                    || !valid_ed25519_key(&key.x)
            })
            || {
                let mut kids = std::collections::BTreeSet::new();
                value.keys.iter().any(|key| !kids.insert(&key.kid))
            }
        {
            return Err(protocol("get_project_jwks", "invalid_response"));
        }
        Ok(value)
    }

    /// Creates fresh S256 PKCE/state and starts a generic Hosted login without navigation.
    ///
    /// # Errors
    /// Returns a configuration, entropy, transport, login, or protocol error.
    pub async fn begin_login(
        &self,
        redirect_uri: &str,
        application_state: Option<&str>,
        presentation_hint: Option<&str>,
    ) -> Result<LoginStart, Error> {
        self.begin_login_with_options(
            redirect_uri,
            application_state,
            presentation_hint,
            &OperationOptions::default(),
        )
        .await
    }

    /// Starts Hosted login with explicit operation controls.
    ///
    /// # Errors
    /// Returns a configuration, entropy, transport, login, or protocol error.
    pub async fn begin_login_with_options(
        &self,
        redirect_uri: &str,
        application_state: Option<&str>,
        presentation_hint: Option<&str>,
        options: &OperationOptions,
    ) -> Result<LoginStart, Error> {
        validate_redirect(redirect_uri)?;
        if presentation_hint.is_some_and(|value| value.is_empty() || value.chars().count() > 64) {
            return Err(configuration(
                "invalid_presentation_hint",
                "The presentation hint is invalid.",
            ));
        }
        let verifier = self.random_base64(32, "start_login")?;
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let state = match application_state {
            Some(value) if !value.is_empty() && value.chars().count() <= 1024 => value.to_owned(),
            Some(_) => {
                return Err(configuration(
                    "invalid_application_state",
                    "The Application state is invalid.",
                ));
            }
            None => self.random_base64(32, "start_login")?,
        };
        let request = LoginStartRequest {
            application_id: &self.application_id,
            publishable_key: &self.publishable_key,
            redirect_uri,
            pkce_challenge: &challenge,
            state: &state,
            presentation_hint,
        };
        let url = self.endpoint(&format!(
            "v1/projects/{}/auth/login/start",
            encode_path(&self.project_id)
        ))?;
        let created_at = self.clock.now_unix_seconds();
        let response: LoginStartResponse = self
            .post_json(
                url,
                &request,
                ResponsePolicy::new("start_login", 201, false, LocalAction::DiscardPendingLogin),
                None,
                options,
            )
            .await?;
        if response.hosted_url.chars().count() > 512 || has_ambiguous_url_path(&response.hosted_url)
        {
            return Err(protocol("start_login", "invalid_hosted_url"));
        }
        let hosted = Url::parse(&response.hosted_url)
            .map_err(|_| protocol("start_login", "invalid_hosted_url"))?;
        if hosted.origin().ascii_serialization() != self.origin
            || !hosted.path().starts_with(self.base.path())
            || hosted.username() != ""
            || hosted.password().is_some()
            || hosted.fragment().is_some()
        {
            return Err(protocol("start_login", "invalid_hosted_url"));
        }
        let expires_at = parse_time(&response.expires_at, "start_login")?;
        let created_at_bound = i128::from(created_at);
        let expires_at_bound = i128::from(expires_at);
        if expires_at_bound < created_at_bound - 60 || expires_at_bound > created_at_bound + 660 {
            return Err(protocol("start_login", "invalid_expiry"));
        }
        Ok(LoginStart {
            hosted_url: hosted.to_string(),
            pending: PendingLogin {
                schema_version: PENDING_SCHEMA_VERSION,
                runtime_origin: self.origin.clone(),
                runtime_base_path: self.base.path().to_owned(),
                project_id: self.project_id.clone(),
                application_id: self.application_id.clone(),
                redirect_uri: redirect_uri.to_owned(),
                verifier: Zeroizing::new(verifier),
                state: Zeroizing::new(state),
                created_at,
                expires_at,
                guard: Arc::new(HandoffGuard::new()),
            },
        })
    }

    /// Validates local callback input without consuming pending state on malformed input.
    /// A successful validation returns a value sharing the pending login's one-use guard.
    ///
    /// # Errors
    /// Returns a handoff error for expiry, state, redirect, or context mismatch.
    pub fn validate_callback(
        &self,
        callback_url: &str,
        pending: &PendingLogin,
    ) -> Result<ValidatedCallback, Error> {
        let fail = |code| {
            Error::new(
                ErrorCategory::Handoff,
                code,
                "The login callback is invalid or expired.",
                RetryPolicy::Never,
                LocalAction::DiscardPendingLogin,
                "exchange_handoff",
            )
        };
        if !pending.available() {
            return Err(fail("pending_consumed"));
        }
        if pending.schema_version != PENDING_SCHEMA_VERSION
            || pending.runtime_origin != self.origin
            || pending.runtime_base_path != self.base.path()
            || pending.project_id != self.project_id
            || pending.application_id != self.application_id
            || i128::from(self.clock.now_unix_seconds()) > i128::from(pending.expires_at) + 60
        {
            return Err(fail("pending_context_mismatch"));
        }
        if callback_url.len() > 4096 {
            return Err(fail("invalid_callback"));
        }
        let callback = Url::parse(callback_url).map_err(|_| fail("invalid_callback"))?;
        let expected = Url::parse(&pending.redirect_uri).map_err(|_| fail("invalid_callback"))?;
        if callback.scheme() != expected.scheme()
            || callback.host_str() != expected.host_str()
            || callback.port_or_known_default() != expected.port_or_known_default()
            || callback.path() != expected.path()
            || callback.fragment().is_some()
            || callback.username() != ""
            || callback.password().is_some()
        {
            return Err(fail("redirect_mismatch"));
        }
        let expected_query: Vec<(String, String)> = expected
            .query_pairs()
            .map(|(a, b)| (a.into_owned(), b.into_owned()))
            .collect();
        if expected_query
            .iter()
            .any(|(key, _)| matches!(key.as_str(), "handoff" | "state" | "error"))
        {
            return Err(fail("invalid_callback"));
        }
        let mut handoff = None;
        let mut callback_error = None;
        let mut state = None;
        let mut remaining = Vec::new();
        for (key, value) in callback.query_pairs() {
            match key.as_ref() {
                "handoff" if handoff.is_none() => handoff = Some(value.into_owned()),
                "error" if callback_error.is_none() => callback_error = Some(value.into_owned()),
                "state" if state.is_none() => state = Some(value.into_owned()),
                "handoff" | "error" | "state" => return Err(fail("invalid_callback")),
                _ => remaining.push((key.into_owned(), value.into_owned())),
            }
        }
        let state = state
            .filter(|value| !value.is_empty() && value.chars().count() <= 1024)
            .ok_or_else(|| fail("state_mismatch"))?;
        if remaining != expected_query
            || !bool::from(state.as_bytes().ct_eq(pending.state.as_bytes()))
            || handoff.is_some() == callback_error.is_some()
        {
            return Err(fail("invalid_callback"));
        }
        if callback_error
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > 64)
        {
            return Err(fail("invalid_callback"));
        }
        if callback_error.is_some() {
            return Err(fail("login_failed"));
        }
        let handoff = handoff
            .filter(|value| !value.is_empty() && value.len() <= 256)
            .ok_or_else(|| fail("missing_handoff"))?;
        Ok(ValidatedCallback {
            handoff: Zeroizing::new(handoff),
            verifier: pending.verifier.clone(),
            guard: Arc::clone(&pending.guard),
        })
    }

    /// Exchanges locally validated one-use handoff material without automatic retry.
    ///
    /// # Errors
    /// Returns `Indeterminate` when a post-dispatch outcome cannot be known safely.
    pub async fn exchange_handoff(
        &self,
        callback: &ValidatedCallback,
    ) -> Result<CredentialPair, Error> {
        self.exchange_handoff_with_options(callback, &OperationOptions::default())
            .await
    }

    /// Exchanges handoff material with explicit operation controls.
    ///
    /// # Errors
    /// Returns `Indeterminate` when a post-dispatch outcome cannot be known safely.
    pub async fn exchange_handoff_with_options(
        &self,
        callback: &ValidatedCallback,
        options: &OperationOptions,
    ) -> Result<CredentialPair, Error> {
        let request = HandoffRequest {
            application_id: &self.application_id,
            publishable_key: &self.publishable_key,
            handoff: callback.handoff.as_str(),
            pkce_verifier: callback.verifier.as_str(),
        };
        let url = self.endpoint(&format!(
            "v1/projects/{}/auth/handoff/exchange",
            encode_path(&self.project_id)
        ))?;
        let wire: CredentialPairWire = self
            .post_json(
                url,
                &request,
                ResponsePolicy::new(
                    "exchange_handoff",
                    200,
                    true,
                    LocalAction::QuarantinePendingLogin,
                ),
                Some(&callback.guard),
                options,
            )
            .await?;
        self.validate_credentials(
            wire,
            "exchange_handoff",
            LocalAction::QuarantinePendingLogin,
        )
    }

    /// Validates a callback and exchanges its handoff as one explicit operation.
    ///
    /// # Errors
    /// Returns a handoff, transport, protocol, or indeterminate error.
    pub async fn complete_login(
        &self,
        callback_url: &str,
        pending: &PendingLogin,
    ) -> Result<CredentialPair, Error> {
        self.complete_login_with_options(callback_url, pending, &OperationOptions::default())
            .await
    }

    /// Validates and exchanges a login callback with explicit operation controls.
    ///
    /// # Errors
    /// Returns a handoff, transport, protocol, cancellation, or indeterminate error.
    pub async fn complete_login_with_options(
        &self,
        callback_url: &str,
        pending: &PendingLogin,
        options: &OperationOptions,
    ) -> Result<CredentialPair, Error> {
        let callback = self.validate_callback(callback_url, pending)?;
        self.exchange_handoff_with_options(&callback, options).await
    }

    /// Rotates one explicit credential generation without automatic retry.
    ///
    /// # Errors
    /// Returns a refresh, protocol, transport, or indeterminate error.
    pub async fn refresh(&self, current: &CredentialPair) -> Result<CredentialPair, Error> {
        self.refresh_with_options(current, &OperationOptions::default())
            .await
    }

    /// Rotates one credential generation with explicit operation controls.
    ///
    /// # Errors
    /// Returns a refresh, protocol, transport, cancellation, or indeterminate error.
    pub async fn refresh_with_options(
        &self,
        current: &CredentialPair,
        options: &OperationOptions,
    ) -> Result<CredentialPair, Error> {
        self.check_pair_context(current, "refresh_session")?;
        let request = RefreshRequest {
            application_id: &self.application_id,
            publishable_key: &self.publishable_key,
            refresh_token: current.refresh_token().expose(),
        };
        let url = self.endpoint(&format!(
            "v1/projects/{}/auth/sessions/refresh",
            encode_path(&self.project_id)
        ))?;
        let wire: CredentialPairWire = self
            .post_json(
                url,
                &request,
                ResponsePolicy::new(
                    "refresh_session",
                    200,
                    true,
                    LocalAction::QuarantineCredentials,
                ),
                None,
                options,
            )
            .await?;
        let next =
            self.validate_credentials(wire, "refresh_session", LocalAction::QuarantineCredentials)?;
        if next.user_id() != current.user_id()
            || next.session_id() != current.session_id()
            || current
                .refresh_generation()
                .checked_add(1)
                .is_none_or(|generation| next.refresh_generation() != generation)
        {
            return Err(indeterminate_response(
                "refresh_session",
                "invalid_response_after_dispatch",
                LocalAction::QuarantineCredentials,
                200,
            ));
        }
        Ok(next)
    }

    /// Retrieves the bounded current Project user for an exact context-bound credential pair.
    ///
    /// # Errors
    /// Returns an authentication, protocol, or transport error.
    pub async fn current_user(&self, credentials: &CredentialPair) -> Result<CurrentUser, Error> {
        self.current_user_with_options(credentials, &OperationOptions::default())
            .await
    }

    /// Retrieves the current user with explicit operation controls.
    ///
    /// # Errors
    /// Returns an authentication, protocol, transport, or cancellation error.
    pub async fn current_user_with_options(
        &self,
        credentials: &CredentialPair,
        options: &OperationOptions,
    ) -> Result<CurrentUser, Error> {
        let url = self.endpoint(&format!(
            "v1/projects/{}/auth/users/me",
            encode_path(&self.project_id)
        ))?;
        let value: CurrentUser = self
            .bearer_json(
                HttpMethod::Get,
                url,
                credentials,
                ResponsePolicy::new("get_current_user", 200, false, LocalAction::None),
                options,
            )
            .await?;
        if value.project_id != self.project_id
            || value.application_id != self.application_id
            || value.user_id != value.projection.user_id
            || value.projection_revision != value.projection.projection_revision
            || !valid_projection(&value.projection)
            || parse_time(&value.authenticated_at, "get_current_user").is_err()
            || parse_time(&value.session_expires_at, "get_current_user").map_or(true, |expiry| {
                i128::from(expiry) < i128::from(self.clock.now_unix_seconds()) - 60
            })
        {
            return Err(protocol("get_current_user", "context_mismatch"));
        }
        Ok(value)
    }

    /// Revokes only the exact Application session represented by a context-bound pair.
    ///
    /// # Errors
    /// Returns a session error or `Indeterminate` after an ambiguous dispatch.
    pub async fn logout_application(&self, credentials: &CredentialPair) -> Result<(), Error> {
        self.logout_application_with_options(credentials, &OperationOptions::default())
            .await
    }

    /// Revokes an Application session with explicit operation controls.
    ///
    /// # Errors
    /// Returns a session, cancellation, or indeterminate error.
    pub async fn logout_application_with_options(
        &self,
        credentials: &CredentialPair,
        options: &OperationOptions,
    ) -> Result<(), Error> {
        let url = self.endpoint(&format!(
            "v1/projects/{}/auth/sessions/logout",
            encode_path(&self.project_id)
        ))?;
        let value: CompletionResponse = self
            .bearer_json(
                HttpMethod::Post,
                url,
                credentials,
                ResponsePolicy::new(
                    "logout_application_session",
                    200,
                    true,
                    LocalAction::QuarantineCredentials,
                ),
                options,
            )
            .await?;
        if !value.completed {
            return Err(indeterminate_response(
                "logout_application_session",
                "invalid_response_after_dispatch",
                LocalAction::QuarantineCredentials,
                200,
            ));
        }
        Ok(())
    }

    /// Creates a Hosted Project-browser logout target without navigating to it.
    ///
    /// # Errors
    /// Returns a session, protocol, transport, or indeterminate error.
    pub async fn prepare_browser_logout(
        &self,
        credentials: &CredentialPair,
    ) -> Result<BrowserLogoutPreparation, Error> {
        self.prepare_browser_logout_with_options(credentials, &OperationOptions::default())
            .await
    }

    /// Creates a browser logout target with explicit operation controls.
    ///
    /// # Errors
    /// Returns a session, protocol, transport, cancellation, or indeterminate error.
    pub async fn prepare_browser_logout_with_options(
        &self,
        credentials: &CredentialPair,
        options: &OperationOptions,
    ) -> Result<BrowserLogoutPreparation, Error> {
        let url = self.endpoint(&format!(
            "v1/projects/{}/auth/browser-logout/prepare",
            encode_path(&self.project_id)
        ))?;
        let value: BrowserLogoutPreparation = self
            .bearer_json(
                HttpMethod::Post,
                url,
                credentials,
                ResponsePolicy::new(
                    "prepare_browser_logout",
                    201,
                    true,
                    LocalAction::QuarantineCredentials,
                ),
                options,
            )
            .await?;
        if value.hosted_url.chars().count() > 512 || has_ambiguous_url_path(&value.hosted_url) {
            return Err(indeterminate_response(
                "prepare_browser_logout",
                "invalid_response_after_dispatch",
                LocalAction::QuarantineCredentials,
                201,
            ));
        }
        let hosted = Url::parse(&value.hosted_url).map_err(|_| {
            indeterminate_response(
                "prepare_browser_logout",
                "invalid_response_after_dispatch",
                LocalAction::QuarantineCredentials,
                201,
            )
        })?;
        if hosted.origin().ascii_serialization() != self.origin
            || !hosted.path().starts_with(self.base.path())
            || hosted.fragment().is_some()
            || hosted.username() != ""
            || hosted.password().is_some()
        {
            return Err(indeterminate_response(
                "prepare_browser_logout",
                "invalid_response_after_dispatch",
                LocalAction::QuarantineCredentials,
                201,
            ));
        }
        let expires_at = parse_time(&value.expires_at, "prepare_browser_logout").map_err(|_| {
            indeterminate_response(
                "prepare_browser_logout",
                "invalid_response_after_dispatch",
                LocalAction::QuarantineCredentials,
                201,
            )
        })?;
        let received_at = i128::from(self.clock.now_unix_seconds());
        let expires_at_bound = i128::from(expires_at);
        if expires_at_bound < received_at - 60 || expires_at_bound > received_at + 120 {
            return Err(indeterminate_response(
                "prepare_browser_logout",
                "invalid_response_after_dispatch",
                LocalAction::QuarantineCredentials,
                201,
            ));
        }
        Ok(value)
    }

    fn random_base64(&self, size: usize, operation: &'static str) -> Result<String, Error> {
        let mut bytes = vec![0_u8; size];
        self.entropy.fill(&mut bytes).map_err(|_| {
            Error::new(
                ErrorCategory::Transport,
                "entropy_unavailable",
                "Secure randomness is unavailable.",
                RetryPolicy::Never,
                LocalAction::None,
                operation,
            )
        })?;
        Ok(URL_SAFE_NO_PAD.encode(bytes))
    }

    fn endpoint(&self, relative: &str) -> Result<Url, Error> {
        self.base
            .join(relative)
            .map_err(|_| protocol("configuration", "invalid_endpoint"))
    }

    async fn get_json<T: DeserializeOwned>(
        &self,
        url: Url,
        operation: &'static str,
        expected_status: u16,
        options: &OperationOptions,
    ) -> Result<T, Error> {
        self.execute(
            HttpRequest {
                method: HttpMethod::Get,
                url: url.to_string(),
                headers: vec![("accept".into(), "application/json".into())],
                body: None,
                max_response_bytes: MAX_RESPONSE_BYTES,
            },
            ResponsePolicy::new(operation, expected_status, false, LocalAction::None),
            None,
            options,
        )
        .await
    }

    async fn post_json<T: DeserializeOwned, B: Serialize + Sync>(
        &self,
        url: Url,
        body: &B,
        policy: ResponsePolicy,
        one_use_guard: Option<&Arc<HandoffGuard>>,
        options: &OperationOptions,
    ) -> Result<T, Error> {
        let body = serde_json::to_vec(body)
            .map_err(|_| protocol(policy.operation, "request_serialization"))?;
        self.execute(
            HttpRequest {
                method: HttpMethod::Post,
                url: url.to_string(),
                headers: vec![
                    ("accept".into(), "application/json".into()),
                    ("content-type".into(), "application/json".into()),
                ],
                body: Some(body),
                max_response_bytes: MAX_RESPONSE_BYTES,
            },
            policy,
            one_use_guard,
            options,
        )
        .await
    }

    async fn bearer_json<T: DeserializeOwned>(
        &self,
        method: HttpMethod,
        url: Url,
        credentials: &CredentialPair,
        policy: ResponsePolicy,
        options: &OperationOptions,
    ) -> Result<T, Error> {
        self.check_pair_context(credentials, policy.operation)?;
        self.execute(
            HttpRequest {
                method,
                url: url.to_string(),
                headers: vec![
                    ("accept".into(), "application/json".into()),
                    (
                        "authorization".into(),
                        format!("Bearer {}", credentials.access_token().expose()),
                    ),
                ],
                body: None,
                max_response_bytes: MAX_RESPONSE_BYTES,
            },
            policy,
            None,
            options,
        )
        .await
    }

    async fn execute<T: DeserializeOwned>(
        &self,
        request: HttpRequest,
        policy: ResponsePolicy,
        one_use_guard: Option<&Arc<HandoffGuard>>,
        options: &OperationOptions,
    ) -> Result<T, Error> {
        if options
            .cancellation()
            .is_some_and(CancellationToken::is_cancelled)
        {
            return Err(transport_error(
                TransportFailure::new(TransportFailureKind::Cancelled, false),
                policy.operation,
                policy.sensitive,
                policy.action,
            ));
        }
        if one_use_guard.is_some_and(|guard| !guard.reserve()) {
            return Err(Error::new(
                ErrorCategory::Handoff,
                "pending_consumed",
                "The pending login has already been reserved or consumed.",
                RetryPolicy::Never,
                LocalAction::DiscardPendingLogin,
                policy.operation,
            ));
        }

        let send = self.transport.send(request, self.deadline);
        tokio::pin!(send);
        let outcome = if let Some(cancellation) = options.cancellation() {
            tokio::select! {
                biased;
                response = &mut send => response,
                () = cancellation.cancelled() => Err(TransportFailure::new(
                    TransportFailureKind::Cancelled,
                    true,
                )),
            }
        } else {
            send.await
        };
        let response = match outcome {
            Ok(response) => {
                if let Some(guard) = one_use_guard {
                    guard.consume();
                }
                response
            }
            Err(failure) => {
                if let Some(guard) = one_use_guard {
                    if failure.dispatched {
                        guard.consume();
                    } else {
                        guard.release();
                    }
                }
                return Err(transport_error(
                    failure,
                    policy.operation,
                    policy.sensitive,
                    policy.action,
                ));
            }
        };
        parse_response(
            &response,
            policy.operation,
            policy.expected_status,
            policy.sensitive,
            policy.action,
        )
    }

    fn validate_credentials(
        &self,
        wire: CredentialPairWire,
        operation: &'static str,
        action: LocalAction,
    ) -> Result<CredentialPair, Error> {
        let now = self.clock.now_unix_seconds();
        if wire.project_id != self.project_id
            || wire.application_id != self.application_id
            || wire.user_id.is_empty()
            || wire.user_id.len() > 96
            || wire.session_id.is_empty()
            || wire.session_id.len() > 64
            || wire.refresh_generation <= 0
            || !valid_bearer_token(&wire.access_token, 16_384)
            || !valid_opaque_token(&wire.refresh_token, 256)
            || wire.token_type != "Bearer"
            || !(1..=3600).contains(&wire.expires_in)
            || wire.projection_revision <= 0
            || wire.projection_revision != wire.projection.projection_revision
            || wire.user_id != wire.projection.user_id
            || !valid_projection(&wire.projection)
            || parse_time(&wire.session_expires_at, operation)
                .map_or(true, |expiry| i128::from(expiry) < i128::from(now) - 60)
        {
            return Err(indeterminate_response(
                operation,
                "invalid_response_after_dispatch",
                action,
                200,
            ));
        }
        let access_expires_at = now.checked_add(wire.expires_in).ok_or_else(|| {
            indeterminate_response(operation, "invalid_response_after_dispatch", action, 200)
        })?;
        Ok(CredentialPair::from_wire(
            wire,
            self.origin.clone(),
            self.base.path().to_owned(),
            access_expires_at,
        ))
    }

    fn check_pair_context(
        &self,
        pair: &CredentialPair,
        operation: &'static str,
    ) -> Result<(), Error> {
        if pair.runtime_origin() != self.origin
            || pair.runtime_base_path() != self.base.path()
            || pair.project_id() != self.project_id
            || pair.application_id() != self.application_id
            || pair.refresh_generation() <= 0
        {
            return Err(protocol(operation, "credential_context_mismatch"));
        }
        Ok(())
    }
}

fn validate_base_url(value: &str, allow_loopback: bool) -> Result<Url, Error> {
    if has_ambiguous_url_path(value) {
        return Err(configuration(
            "invalid_runtime_url",
            "The Runtime URL is invalid.",
        ));
    }
    let mut url = Url::parse(value)
        .map_err(|_| configuration("invalid_runtime_url", "The Runtime URL is invalid."))?;
    if url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.host_str().is_none()
    {
        return Err(configuration(
            "invalid_runtime_url",
            "The Runtime URL is invalid.",
        ));
    }
    let loopback = url.host_str().is_some_and(is_loopback_host);
    if url.scheme() != "https" && !(allow_loopback && loopback && url.scheme() == "http") {
        return Err(configuration(
            "insecure_runtime_url",
            "HTTPS is required outside explicit loopback development.",
        ));
    }
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    Ok(url)
}

fn has_ambiguous_url_path(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if value.contains('\\')
        || lower.contains("%2f")
        || lower.contains("%5c")
        || lower.contains("%25")
    {
        return true;
    }
    let Some((_, authority_and_path)) = value.split_once("://") else {
        return true;
    };
    let Some(path_start) = authority_and_path.find('/') else {
        return false;
    };
    let path = &authority_and_path[path_start..];
    let path = path.split_once('?').map_or(path, |(path, _)| path);
    let path = path.split_once('#').map_or(path, |(path, _)| path);
    path.split('/').any(|segment| {
        let decoded = segment.to_ascii_lowercase().replace("%2e", ".");
        decoded == "." || decoded == ".."
    })
}

fn validate_identifier(value: &str, maximum: usize, field: &str) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > maximum
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(configuration(
            "invalid_identifier",
            &format!("The configured {field} is invalid."),
        ));
    }
    Ok(())
}

fn validate_redirect(value: &str) -> Result<(), Error> {
    let invalid = || configuration("invalid_redirect_uri", "The redirect URI is invalid.");
    let lower = value.to_ascii_lowercase();
    if !(8..=2048).contains(&value.len())
        || value.contains('\\')
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
        || lower.contains("%2f")
        || lower.contains("%5c")
    {
        return Err(invalid());
    }
    let url = Url::parse(value).map_err(|_| invalid())?;
    if url.as_str() != value
        || url.fragment().is_some()
        || url.username() != ""
        || url.password().is_some()
        || url.host_str().is_some_and(|host| host.contains('*'))
        || url
            .query_pairs()
            .any(|(name, _)| matches!(name.as_ref(), "handoff" | "error" | "state"))
    {
        return Err(invalid());
    }
    let admitted = match url.scheme() {
        "https" => url.host_str().is_some(),
        "http" => url.host_str().is_some_and(is_loopback_host),
        scheme => {
            scheme.contains('.')
                && url.host_str().is_none()
                && !matches!(
                    scheme,
                    "about"
                        | "blob"
                        | "data"
                        | "file"
                        | "ftp"
                        | "javascript"
                        | "mailto"
                        | "vbscript"
                        | "ws"
                        | "wss"
                )
        }
    };
    if !admitted {
        return Err(invalid());
    }
    Ok(())
}

fn is_loopback_host(host: &str) -> bool {
    host == "localhost"
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn encode_path(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn parse_time(value: &str, operation: &'static str) -> Result<i64, Error> {
    if value.len() > 64 {
        return Err(protocol(operation, "invalid_timestamp"));
    }
    OffsetDateTime::parse(value, &Rfc3339)
        .map(OffsetDateTime::unix_timestamp)
        .map_err(|_| protocol(operation, "invalid_timestamp"))
}

fn valid_ed25519_key(value: &str) -> bool {
    URL_SAFE_NO_PAD
        .decode(value)
        .is_ok_and(|bytes| bytes.len() == 32 && URL_SAFE_NO_PAD.encode(bytes) == value)
}

fn valid_bearer_token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/' | b'=')
        })
}

fn valid_opaque_token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

fn valid_projection(value: &crate::UserProjection) -> bool {
    !value.user_id.is_empty()
        && value.user_id.len() <= 96
        && value.user_revision > 0
        && value.projection_schema == "owlauth.user.v1"
        && value.projection_revision > 0
        && value
            .display_name
            .as_ref()
            .is_none_or(|name| name.chars().count() <= 128)
        && value
            .picture_url
            .as_ref()
            .is_none_or(|url| url.chars().count() <= 2048)
        && value.locale.as_ref().is_none_or(|locale| {
            (2..=35).contains(&locale.len())
                && !locale.starts_with('-')
                && !locale.ends_with('-')
                && !locale.contains("--")
                && locale
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
        && value.verified_email.as_ref().is_none_or(|email| {
            (3..=320).contains(&email.chars().count()) && !email.chars().any(char::is_control)
        })
        && value.status == "active"
        && parse_time(&value.created_at, "projection").is_ok()
        && parse_time(&value.updated_at, "projection").is_ok()
}

fn transport_error(
    failure: TransportFailure,
    operation: &'static str,
    sensitive: bool,
    action: LocalAction,
) -> Error {
    if sensitive && failure.dispatched {
        return Error::new(
            ErrorCategory::Indeterminate,
            "outcome_indeterminate",
            "The Runtime outcome cannot be determined safely.",
            RetryPolicy::Never,
            action,
            operation,
        );
    }
    let (category, code, message) = match failure.kind {
        TransportFailureKind::Timeout => (
            ErrorCategory::Timeout,
            "timeout",
            "The Runtime request timed out.",
        ),
        TransportFailureKind::Cancelled => (
            ErrorCategory::Cancelled,
            "cancelled",
            "The Runtime request was cancelled.",
        ),
        TransportFailureKind::ResponseTooLarge => (
            ErrorCategory::Protocol,
            "invalid_response",
            "Runtime returned an invalid or incompatible response.",
        ),
        TransportFailureKind::Transport => (
            ErrorCategory::Transport,
            "transport_error",
            "The Runtime request could not be completed.",
        ),
    };
    Error::new(
        category,
        code,
        message,
        if failure.kind == TransportFailureKind::ResponseTooLarge {
            RetryPolicy::Never
        } else {
            RetryPolicy::ApplicationDecision
        },
        if failure.dispatched {
            action
        } else {
            LocalAction::None
        },
        operation,
    )
}

fn protocol_with_action(operation: &'static str, code: &str, action: LocalAction) -> Error {
    Error::new(
        ErrorCategory::Protocol,
        code,
        "Runtime returned an invalid or incompatible response.",
        RetryPolicy::Never,
        action,
        operation,
    )
}

fn indeterminate_response(
    operation: &'static str,
    code: &str,
    action: LocalAction,
    status: u16,
) -> Error {
    Error::new(
        ErrorCategory::Indeterminate,
        code,
        "Runtime may have committed the operation; do not replay it.",
        RetryPolicy::Never,
        action,
        operation,
    )
    .with_runtime(status, None)
}

fn invalid_response(
    operation: &'static str,
    _code: &str,
    sensitive: bool,
    action: LocalAction,
    status: u16,
) -> Error {
    if sensitive {
        indeterminate_response(operation, "invalid_response_after_dispatch", action, status)
    } else {
        protocol_with_action(operation, "invalid_response", action).with_runtime(status, None)
    }
}

fn parse_response<T: DeserializeOwned>(
    response: &HttpResponse,
    operation: &'static str,
    expected_status: u16,
    sensitive: bool,
    action: LocalAction,
) -> Result<T, Error> {
    if response.body.len() > MAX_RESPONSE_BYTES {
        return Err(invalid_response(
            operation,
            "response_too_large",
            sensitive,
            action,
            response.status,
        ));
    }
    let content_types: Vec<&str> = response
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .map(|(_, value)| value.split(';').next().unwrap_or_default().trim())
        .collect();
    if content_types.len() != 1 || !content_types[0].eq_ignore_ascii_case("application/json") {
        return Err(invalid_response(
            operation,
            "invalid_content_type",
            sensitive,
            action,
            response.status,
        ));
    }
    if response.status == expected_status {
        return serde_json::from_slice(&response.body).map_err(|_| {
            invalid_response(
                operation,
                "invalid_json_response",
                sensitive,
                action,
                response.status,
            )
        });
    }
    if !allowed_error_statuses(operation).contains(&response.status) {
        return Err(invalid_response(
            operation,
            "unexpected_status",
            sensitive,
            action,
            response.status,
        ));
    }
    parse_runtime_error(response, operation, sensitive, action)
}

fn parse_runtime_error<T>(
    response: &HttpResponse,
    operation: &'static str,
    sensitive: bool,
    action: LocalAction,
) -> Result<T, Error> {
    let wire = serde_json::from_slice::<RuntimeErrorWire>(&response.body).map_err(|_| {
        invalid_response(
            operation,
            "invalid_error_response",
            sensitive,
            action,
            response.status,
        )
    })?;
    if wire.message.is_empty()
        || wire.message.chars().count() > 256
        || wire.request_id.is_empty()
        || wire.request_id.chars().count() > 128
    {
        return Err(invalid_response(
            operation,
            "invalid_error_response",
            sensitive,
            action,
            response.status,
        ));
    }
    let retry_after_seconds = if response.status == 429 {
        if wire.code != "rate_limited" {
            return Err(invalid_response(
                operation,
                "invalid_rate_limit_response",
                sensitive,
                action,
                response.status,
            ));
        }
        Some(retry_after_seconds(response).ok_or_else(|| {
            invalid_response(
                operation,
                "invalid_rate_limit_response",
                sensitive,
                action,
                response.status,
            )
        })?)
    } else {
        None
    };
    let request_id = sanitize_request_id(Some(wire.request_id));
    let code = wire.code;
    if !valid_runtime_error_code(&code) {
        return Err(invalid_response(
            operation,
            "invalid_error_response",
            sensitive,
            action,
            response.status,
        ));
    }
    if sensitive && response.status >= 500 {
        return Err(indeterminate_response(
            operation,
            "runtime_5xx_after_dispatch",
            action,
            response.status,
        ));
    }
    let (category, retry, local_action) =
        runtime_error_semantics(response.status, &code, operation, action);
    let mut error = Error::new(
        category,
        code,
        "Runtime rejected the Project Auth operation.",
        retry,
        local_action,
        operation,
    )
    .with_runtime(response.status, request_id);
    if let Some(seconds) = retry_after_seconds {
        error = error.with_retry_after(seconds);
    }
    Err(error)
}

fn sanitize_request_id(value: Option<String>) -> Option<String> {
    value.filter(|value| {
        !value.is_empty()
            && value.len() <= 128
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
    })
}

fn valid_runtime_error_code(code: &str) -> bool {
    let mut bytes = code.bytes();
    code.len() <= 64
        && bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn allowed_error_statuses(operation: &str) -> &'static [u16] {
    match operation {
        "get_public_application_config" | "start_login" => &[400, 404, 429, 503],
        "get_project_jwks" => &[404, 429, 503],
        "exchange_handoff" | "refresh_session" => &[400, 409, 429, 503],
        "get_current_user" | "logout_application_session" | "prepare_browser_logout" => {
            &[401, 429, 503]
        }
        _ => &[],
    }
}

fn retry_after_seconds(response: &HttpResponse) -> Option<u64> {
    let values: Vec<&str> = response
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("retry-after"))
        .map(|(_, value)| value.as_str())
        .collect();
    if values.len() != 1
        || values[0].is_empty()
        || !values[0].bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    values[0]
        .parse::<u64>()
        .ok()
        .filter(|seconds| *seconds <= 86_400)
}

fn runtime_error_semantics(
    status: u16,
    code: &str,
    operation: &'static str,
    action: LocalAction,
) -> (ErrorCategory, RetryPolicy, LocalAction) {
    if status == 429 && code == "rate_limited" {
        return match operation {
            "exchange_handoff" => (
                ErrorCategory::RateLimited,
                RetryPolicy::Never,
                LocalAction::DiscardPendingLogin,
            ),
            "refresh_session" | "logout_application_session" | "prepare_browser_logout" => (
                ErrorCategory::RateLimited,
                RetryPolicy::ApplicationDecision,
                LocalAction::None,
            ),
            _ => (
                ErrorCategory::RateLimited,
                RetryPolicy::SafeAfterDelay,
                LocalAction::None,
            ),
        };
    }
    match operation {
        "start_login" => (
            ErrorCategory::Login,
            RetryPolicy::Never,
            LocalAction::DiscardPendingLogin,
        ),
        "exchange_handoff" => (
            ErrorCategory::Handoff,
            RetryPolicy::Never,
            LocalAction::DiscardPendingLogin,
        ),
        "refresh_session" => (
            ErrorCategory::Refresh,
            RetryPolicy::Never,
            LocalAction::ClearCredentials,
        ),
        "get_current_user" => (
            ErrorCategory::Authentication,
            RetryPolicy::Never,
            LocalAction::Reauthenticate,
        ),
        "logout_application_session" | "prepare_browser_logout" => {
            (ErrorCategory::Session, RetryPolicy::Never, action)
        }
        _ if status >= 500 => (
            ErrorCategory::Transport,
            RetryPolicy::ApplicationDecision,
            action,
        ),
        _ => (ErrorCategory::Protocol, RetryPolicy::Never, action),
    }
}
