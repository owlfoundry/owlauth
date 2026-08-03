use std::{
    sync::Arc,
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
    AccessToken, BrowserLogoutPreparation, CompletionResponse, CredentialPair, CredentialPairWire,
    CurrentUser, Error, ErrorCategory, HandoffRequest, HttpMethod, HttpRequest, HttpResponse,
    JwksDocument, LocalAction, LoginStart, LoginStartRequest, LoginStartResponse, PendingLogin,
    PublicConfiguration, RefreshRequest, RetryPolicy, RuntimeErrorWire, Transport,
    TransportFailure, TransportFailureKind, ValidatedCallback,
    error::{configuration, protocol},
    transport::default_transport,
};

const MAX_RESPONSE_BYTES: usize = 1_048_576;
const PENDING_SCHEMA_VERSION: u8 = 1;

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
                "begin_login",
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

    /// Fetches bounded public Project/Application configuration.
    ///
    /// # Errors
    /// Returns a typed transport, Runtime, or protocol error.
    pub async fn public_configuration(&self) -> Result<PublicConfiguration, Error> {
        let mut url = self.endpoint(&format!(
            "v1/projects/{}/auth/config",
            encode_path(&self.project_id)
        ))?;
        url.query_pairs_mut()
            .append_pair("application_id", &self.application_id);
        let value: PublicConfiguration = self.get_json(url, "public_configuration").await?;
        if value.project_public_id != self.project_id
            || value.application_public_id != self.application_id
            || value.project_display_name.is_empty()
            || value.project_display_name.len() > 128
            || value.application_display_name.is_empty()
            || value.application_display_name.len() > 128
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
                    || provider.display_name.len() > 128
                    || provider.kind.is_empty()
                    || provider.kind.len() > 32
            })
        {
            return Err(protocol("public_configuration", "context_mismatch"));
        }
        Ok(value)
    }

    /// Fetches Project JWKS and signing revision metadata.
    ///
    /// # Errors
    /// Returns a typed transport, Runtime, or protocol error.
    pub async fn project_jwks(&self) -> Result<JwksDocument, Error> {
        let url = self.endpoint(&format!(
            "projects/{}/.well-known/jwks.json",
            encode_path(&self.project_id)
        ))?;
        let value: JwksDocument = self.get_json(url, "project_jwks").await?;
        if value.keys.len() > 100
            || value.revision <= 0
            || value.signing_epoch <= 0
            || value
                .keys
                .iter()
                .any(|key| key.kid.len() > 128 || key.x.len() > 64)
        {
            return Err(protocol("project_jwks", "invalid_jwks"));
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
        validate_redirect(redirect_uri)?;
        if presentation_hint.is_some_and(|value| value.is_empty() || value.len() > 64) {
            return Err(configuration(
                "invalid_presentation_hint",
                "The presentation hint is invalid.",
            ));
        }
        let verifier = self.random_base64(32, "begin_login")?;
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let state = match application_state {
            Some(value) if !value.is_empty() && value.len() <= 1024 => value.to_owned(),
            Some(_) => {
                return Err(configuration(
                    "invalid_application_state",
                    "The Application state is invalid.",
                ));
            }
            None => self.random_base64(32, "begin_login")?,
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
        let response: LoginStartResponse = self
            .post_json(
                url,
                &request,
                "begin_login",
                false,
                LocalAction::DiscardPendingLogin,
            )
            .await?;
        let hosted = Url::parse(&response.hosted_url)
            .map_err(|_| protocol("begin_login", "invalid_hosted_url"))?;
        if hosted.origin().ascii_serialization() != self.origin
            || !hosted.path().starts_with(self.base.path())
            || hosted.username() != ""
            || hosted.password().is_some()
            || hosted.fragment().is_some()
        {
            return Err(protocol("begin_login", "invalid_hosted_url"));
        }
        let expires_at = parse_time(&response.expires_at, "begin_login")?;
        let created_at = self.clock.now_unix_seconds();
        if expires_at <= created_at || expires_at - created_at > 660 {
            return Err(protocol("begin_login", "invalid_expiry"));
        }
        Ok(LoginStart {
            hosted_url: hosted.to_string(),
            pending: PendingLogin {
                schema_version: PENDING_SCHEMA_VERSION,
                runtime_origin: self.origin.clone(),
                project_id: self.project_id.clone(),
                application_id: self.application_id.clone(),
                redirect_uri: redirect_uri.to_owned(),
                verifier: Zeroizing::new(verifier),
                state: Zeroizing::new(state),
                created_at,
                expires_at,
            },
        })
    }

    /// Consumes and locally validates one pending login before any handoff request.
    ///
    /// # Errors
    /// Returns a handoff error for expiry, state, redirect, or context mismatch.
    pub fn validate_callback(
        &self,
        callback_url: &str,
        pending: PendingLogin,
    ) -> Result<ValidatedCallback, Error> {
        let fail = |code| {
            Error::new(
                ErrorCategory::Handoff,
                code,
                "The login callback is invalid or expired.",
                RetryPolicy::Never,
                LocalAction::DiscardPendingLogin,
                "validate_callback",
            )
        };
        if pending.schema_version != PENDING_SCHEMA_VERSION
            || pending.runtime_origin != self.origin
            || pending.project_id != self.project_id
            || pending.application_id != self.application_id
            || pending.expires_at <= self.clock.now_unix_seconds()
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
        {
            return Err(fail("redirect_mismatch"));
        }
        let mut handoff = None;
        let mut state = None;
        let expected_query: Vec<(String, String)> = expected
            .query_pairs()
            .map(|(a, b)| (a.into_owned(), b.into_owned()))
            .collect();
        let mut remaining = Vec::new();
        for (key, value) in callback.query_pairs() {
            match key.as_ref() {
                "handoff" if handoff.is_none() => handoff = Some(value.into_owned()),
                "state" if state.is_none() => state = Some(value.into_owned()),
                "handoff" | "state" => return Err(fail("invalid_callback")),
                _ => remaining.push((key.into_owned(), value.into_owned())),
            }
        }
        let handoff = handoff
            .filter(|value| !value.is_empty() && value.len() <= 256)
            .ok_or_else(|| fail("missing_handoff"))?;
        let state = state
            .filter(|value| !value.is_empty() && value.len() <= 1024)
            .ok_or_else(|| fail("state_mismatch"))?;
        if remaining != expected_query
            || !bool::from(state.as_bytes().ct_eq(pending.state.as_bytes()))
        {
            return Err(fail("state_mismatch"));
        }
        Ok(ValidatedCallback {
            handoff: Zeroizing::new(handoff),
            verifier: pending.verifier,
        })
    }

    /// Exchanges locally validated one-use handoff material without automatic retry.
    ///
    /// # Errors
    /// Returns `Indeterminate` when a post-dispatch outcome cannot be known safely.
    pub async fn exchange_handoff(
        &self,
        callback: ValidatedCallback,
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
                "exchange_handoff",
                true,
                LocalAction::QuarantinePendingLogin,
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
        pending: PendingLogin,
    ) -> Result<CredentialPair, Error> {
        let callback = self.validate_callback(callback_url, pending)?;
        self.exchange_handoff(callback).await
    }

    /// Rotates one explicit credential generation without automatic retry.
    ///
    /// # Errors
    /// Returns a refresh, protocol, transport, or indeterminate error.
    pub async fn refresh(&self, current: &CredentialPair) -> Result<CredentialPair, Error> {
        self.check_pair_context(current, "refresh")?;
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
                "refresh",
                true,
                LocalAction::QuarantineCredentials,
            )
            .await?;
        let next =
            self.validate_credentials(wire, "refresh", LocalAction::QuarantineCredentials)?;
        if next.user_id() != current.user_id()
            || next.session_id() != current.session_id()
            || next.refresh_generation() != current.refresh_generation().saturating_add(1)
        {
            return Err(protocol_with_action(
                "refresh",
                "credential_generation_mismatch",
                LocalAction::QuarantineCredentials,
            ));
        }
        Ok(next)
    }

    /// Retrieves the bounded current Project user for an explicit access token.
    ///
    /// # Errors
    /// Returns an authentication, protocol, or transport error.
    pub async fn current_user(&self, access_token: &AccessToken) -> Result<CurrentUser, Error> {
        let url = self.endpoint(&format!(
            "v1/projects/{}/auth/users/me",
            encode_path(&self.project_id)
        ))?;
        let value: CurrentUser = self
            .bearer_json(HttpMethod::Get, url, access_token, "current_user", false)
            .await?;
        if value.project_id != self.project_id
            || value.application_id != self.application_id
            || value.user_id != value.projection.user_id
            || value.projection_revision != value.projection.projection_revision
            || !valid_projection(&value.projection)
            || parse_time(&value.authenticated_at, "current_user").is_err()
            || parse_time(&value.session_expires_at, "current_user").is_err()
        {
            return Err(protocol("current_user", "context_mismatch"));
        }
        Ok(value)
    }

    /// Revokes only the exact Application session represented by the access token.
    ///
    /// # Errors
    /// Returns a session error or `Indeterminate` after an ambiguous dispatch.
    pub async fn logout_application(&self, access_token: &AccessToken) -> Result<(), Error> {
        let url = self.endpoint(&format!(
            "v1/projects/{}/auth/sessions/logout",
            encode_path(&self.project_id)
        ))?;
        let value: CompletionResponse = self
            .bearer_json(
                HttpMethod::Post,
                url,
                access_token,
                "logout_application",
                true,
            )
            .await?;
        if !value.completed {
            return Err(protocol("logout_application", "logout_not_confirmed"));
        }
        Ok(())
    }

    /// Creates a Hosted Project-browser logout target without navigating to it.
    ///
    /// # Errors
    /// Returns a session, protocol, transport, or indeterminate error.
    pub async fn prepare_browser_logout(
        &self,
        access_token: &AccessToken,
    ) -> Result<BrowserLogoutPreparation, Error> {
        let url = self.endpoint(&format!(
            "v1/projects/{}/auth/browser-logout/prepare",
            encode_path(&self.project_id)
        ))?;
        let value: BrowserLogoutPreparation = self
            .bearer_json(
                HttpMethod::Post,
                url,
                access_token,
                "prepare_browser_logout",
                true,
            )
            .await?;
        let hosted = Url::parse(&value.hosted_url)
            .map_err(|_| protocol("prepare_browser_logout", "invalid_hosted_url"))?;
        if hosted.origin().ascii_serialization() != self.origin
            || !hosted.path().starts_with(self.base.path())
            || hosted.fragment().is_some()
            || hosted.username() != ""
            || hosted.password().is_some()
        {
            return Err(protocol("prepare_browser_logout", "invalid_hosted_url"));
        }
        parse_time(&value.expires_at, "prepare_browser_logout")?;
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
    ) -> Result<T, Error> {
        self.execute(
            HttpRequest {
                method: HttpMethod::Get,
                url: url.to_string(),
                headers: vec![("accept".into(), "application/json".into())],
                body: None,
                max_response_bytes: MAX_RESPONSE_BYTES,
            },
            operation,
            false,
            LocalAction::None,
        )
        .await
    }

    async fn post_json<T: DeserializeOwned, B: Serialize + Sync>(
        &self,
        url: Url,
        body: &B,
        operation: &'static str,
        sensitive: bool,
        action: LocalAction,
    ) -> Result<T, Error> {
        let body =
            serde_json::to_vec(body).map_err(|_| protocol(operation, "request_serialization"))?;
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
            operation,
            sensitive,
            action,
        )
        .await
    }

    async fn bearer_json<T: DeserializeOwned>(
        &self,
        method: HttpMethod,
        url: Url,
        token: &AccessToken,
        operation: &'static str,
        sensitive: bool,
    ) -> Result<T, Error> {
        self.execute(
            HttpRequest {
                method,
                url: url.to_string(),
                headers: vec![
                    ("accept".into(), "application/json".into()),
                    ("authorization".into(), format!("Bearer {}", token.expose())),
                ],
                body: (method == HttpMethod::Post).then(|| b"{}".to_vec()),
                max_response_bytes: MAX_RESPONSE_BYTES,
            },
            operation,
            sensitive,
            LocalAction::QuarantineCredentials,
        )
        .await
    }

    async fn execute<T: DeserializeOwned>(
        &self,
        request: HttpRequest,
        operation: &'static str,
        sensitive: bool,
        action: LocalAction,
    ) -> Result<T, Error> {
        let response = self
            .transport
            .send(request, self.deadline)
            .await
            .map_err(|failure| transport_error(failure, operation, sensitive, action))?;
        parse_response(&response, operation, action)
    }

    fn validate_credentials(
        &self,
        wire: CredentialPairWire,
        operation: &'static str,
        action: LocalAction,
    ) -> Result<CredentialPair, Error> {
        if wire.project_id != self.project_id
            || wire.application_id != self.application_id
            || wire.user_id.is_empty()
            || wire.user_id.len() > 96
            || wire.session_id.len() > 64
            || wire.refresh_generation <= 0
            || wire.access_token.is_empty()
            || wire.access_token.len() > 16_384
            || wire.refresh_token.is_empty()
            || wire.refresh_token.len() > 256
            || wire.token_type != "Bearer"
            || !(1..=3600).contains(&wire.expires_in)
            || wire.projection_revision <= 0
            || wire.projection_revision != wire.projection.projection_revision
            || wire.user_id != wire.projection.user_id
            || !valid_projection(&wire.projection)
            || parse_time(&wire.session_expires_at, operation).is_err()
        {
            return Err(protocol_with_action(
                operation,
                "credential_context_mismatch",
                action,
            ));
        }
        Ok(CredentialPair::from_wire(wire))
    }

    fn check_pair_context(
        &self,
        pair: &CredentialPair,
        operation: &'static str,
    ) -> Result<(), Error> {
        if pair.project_id() != self.project_id
            || pair.application_id() != self.application_id
            || pair.refresh_generation() <= 0
        {
            return Err(protocol(operation, "credential_context_mismatch"));
        }
        Ok(())
    }
}

fn validate_base_url(value: &str, allow_loopback: bool) -> Result<Url, Error> {
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
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
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
    if value.len() > 2048 {
        return Err(configuration(
            "invalid_redirect_uri",
            "The redirect URI is invalid.",
        ));
    }
    let url = Url::parse(value)
        .map_err(|_| configuration("invalid_redirect_uri", "The redirect URI is invalid."))?;
    if url.fragment().is_some() || url.username() != "" || url.password().is_some() {
        return Err(configuration(
            "invalid_redirect_uri",
            "The redirect URI is invalid.",
        ));
    }
    Ok(())
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

fn valid_projection(value: &crate::UserProjection) -> bool {
    !value.user_id.is_empty()
        && value.user_id.len() <= 96
        && value.user_revision > 0
        && value.projection_schema == "owlauth.user.v1"
        && value.projection_revision > 0
        && value
            .display_name
            .as_ref()
            .is_none_or(|name| name.len() <= 128)
        && value
            .picture_url
            .as_ref()
            .is_none_or(|url| url.len() <= 2048)
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
            (3..=320).contains(&email.len()) && !email.chars().any(char::is_control)
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
            "response_too_large",
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
        RetryPolicy::ApplicationDecision,
        action,
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

fn parse_response<T: DeserializeOwned>(
    response: &HttpResponse,
    operation: &'static str,
    action: LocalAction,
) -> Result<T, Error> {
    if response.body.len() > MAX_RESPONSE_BYTES {
        return Err(protocol_with_action(
            operation,
            "response_too_large",
            action,
        ));
    }
    if (200..300).contains(&response.status) {
        return serde_json::from_slice(&response.body)
            .map_err(|_| protocol_with_action(operation, "invalid_json_response", action));
    }
    let wire = serde_json::from_slice::<RuntimeErrorWire>(&response.body).ok();
    let request_id = wire
        .as_ref()
        .map(|value| value.request_id.clone())
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 128
                && value.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
                })
        });
    let code = wire.as_ref().map_or_else(
        || "runtime_error".to_owned(),
        |value| {
            if value.code.is_empty() || value.code.len() > 64 {
                "runtime_error".to_owned()
            } else {
                value.code.clone()
            }
        },
    );
    let _safe_message = wire.as_ref().filter(|value| value.message.len() <= 256);
    let (category, retry, local_action) =
        runtime_error_semantics(response.status, operation, action);
    let code = if code
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        code
    } else {
        "runtime_error".to_owned()
    };
    let known = matches!(
        code.as_str(),
        "not_found"
            | "invalid_request"
            | "invalid_state"
            | "authority_unavailable"
            | "unauthorized"
            | "origin_not_allowed"
            | "invalid_preflight"
            | "forbidden_hosted_request"
            | "invalid_cookie"
    );
    if !known && category != ErrorCategory::RateLimited {
        return Err(Error::new(
            ErrorCategory::Protocol,
            code,
            "Runtime returned an unrecognized error.",
            RetryPolicy::Never,
            local_action,
            operation,
        )
        .with_runtime(response.status, request_id));
    }
    Err(Error::new(
        category,
        code,
        "Runtime rejected the Project Auth operation.",
        retry,
        local_action,
        operation,
    )
    .with_runtime(response.status, request_id))
}

fn runtime_error_semantics(
    status: u16,
    operation: &'static str,
    action: LocalAction,
) -> (ErrorCategory, RetryPolicy, LocalAction) {
    if status == 429 {
        return (
            ErrorCategory::RateLimited,
            RetryPolicy::SafeAfterDelay,
            LocalAction::None,
        );
    }
    match operation {
        "begin_login" => (
            ErrorCategory::Login,
            RetryPolicy::Never,
            LocalAction::DiscardPendingLogin,
        ),
        "exchange_handoff" => (
            ErrorCategory::Handoff,
            RetryPolicy::Never,
            LocalAction::DiscardPendingLogin,
        ),
        "refresh" => (
            ErrorCategory::Refresh,
            RetryPolicy::Never,
            LocalAction::ClearCredentials,
        ),
        "current_user" => (
            ErrorCategory::Authentication,
            RetryPolicy::Never,
            LocalAction::Reauthenticate,
        ),
        "logout_application" | "prepare_browser_logout" => {
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
