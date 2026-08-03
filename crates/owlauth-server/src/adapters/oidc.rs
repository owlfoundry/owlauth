use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures_util::StreamExt as _;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use reqwest::redirect::Policy;
use reqwest::{Client, StatusCode};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};
use time::OffsetDateTime;
use tokio::sync::Semaphore;
use url::Url;
use zeroize::Zeroizing;

use crate::application::{
    BoundedManagedProfile, ConnectionGuard, ManagedProfileAdapter, ProviderAuthorization,
    ProviderAuthorizationRequest, ProviderCallbackRequest, ProviderExchangeError, ProviderIdentity,
    ProviderReadError, ProviderRenewalResult, ProviderRequestProfile, ProviderRevocationResult,
    ProviderSecretResolver, RenewableProviderCredential, RenewedCredential, UpstreamProviderClient,
};
use crate::domain::{
    BoundedProviderProfile, ManagedProfileCapability, ProfileDisplayName, ProfileLocale,
    ProfilePictureUrl, RenewalReplay,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const DISCOVERY_BODY_LIMIT: usize = 32 * 1024;
const TOKEN_BODY_LIMIT: usize = 32 * 1024;
const JWKS_BODY_LIMIT: usize = 128 * 1024;
const ID_TOKEN_LIMIT: usize = 16 * 1024;
const JWT_PART_LIMIT: usize = 12 * 1024;
const MAX_JWKS_KEYS: usize = 32;
const MAX_KID_BYTES: usize = 128;
const MAX_ISSUER_BYTES: usize = 2048;
const MAX_ENDPOINT_BYTES: usize = 2048;
const MAX_CLIENT_ID_BYTES: usize = 512;
const MAX_CLIENT_SECRET_BYTES: usize = 4096;
const MAX_CALLBACK_BYTES: usize = 2048;
const MAX_CODE_BYTES: usize = 4096;
const MAX_STATE_BYTES: usize = 512;
const MAX_NONCE_BYTES: usize = 512;
const MAX_PKCE_VERIFIER_BYTES: usize = 128;
const MAX_SUBJECT_BYTES: usize = 512;
const MAX_NAME_CHARACTERS: usize = 128;
const MAX_PICTURE_BYTES: usize = 2048;
const MAX_AUDIENCES: usize = 8;
const MAX_ID_TOKEN_LIFETIME_SECONDS: i64 = 24 * 60 * 60;
const REQUIRED_CLOCK_SKEW_SECONDS: i64 = 60;
#[cfg(test)]
const PROVIDER_EXCHANGE_CONCURRENCY_LIMIT: usize = 16;

/// A deliberately narrow OIDC client. Every issuer and endpoint origin must be explicitly
/// admitted when the client is constructed; the HTTP client follows no redirects and reads no
/// process proxy configuration.
#[derive(Clone)]
pub(crate) struct RestrictedOidcProviderClient {
    http: Client,
    endpoint_policy: Arc<EndpointPolicy>,
    callback_allow_http_loopback: bool,
    exchange_budget: Arc<Semaphore>,
    request_timeout: Duration,
}

impl RestrictedOidcProviderClient {
    #[cfg(test)]
    pub(crate) fn new<I, S>(
        allowed_endpoint_origins: I,
        allow_http_loopback: bool,
    ) -> Result<Self, ProviderExchangeError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self::new_with_budget(
            allowed_endpoint_origins,
            allow_http_loopback,
            Arc::new(Semaphore::new(PROVIDER_EXCHANGE_CONCURRENCY_LIMIT)),
        )
    }

    pub(crate) fn new_with_budget<I, S>(
        allowed_endpoint_origins: I,
        allow_http_loopback: bool,
        exchange_budget: Arc<Semaphore>,
    ) -> Result<Self, ProviderExchangeError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self::new_with_budget_and_callback_policy(
            allowed_endpoint_origins,
            allow_http_loopback,
            allow_http_loopback,
            exchange_budget,
        )
    }

    pub(crate) fn new_with_budget_and_callback_policy<I, S>(
        allowed_endpoint_origins: I,
        allow_http_loopback_endpoints: bool,
        callback_allow_http_loopback: bool,
        exchange_budget: Arc<Semaphore>,
    ) -> Result<Self, ProviderExchangeError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self::build(
            allowed_endpoint_origins,
            allow_http_loopback_endpoints,
            callback_allow_http_loopback,
            REQUEST_TIMEOUT,
            exchange_budget,
        )
    }

    fn build<I, S>(
        allowed_endpoint_origins: I,
        allow_http_loopback_endpoints: bool,
        callback_allow_http_loopback: bool,
        request_timeout: Duration,
        exchange_budget: Arc<Semaphore>,
    ) -> Result<Self, ProviderExchangeError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let endpoint_policy =
            EndpointPolicy::new(allowed_endpoint_origins, allow_http_loopback_endpoints)?;
        let http = Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(request_timeout)
            .redirect(Policy::none())
            .no_proxy()
            .build()
            .map_err(|_| ProviderExchangeError::UnavailableBeforeDispatch)?;
        if exchange_budget.available_permits() == 0 {
            return Err(ProviderExchangeError::UnavailableBeforeDispatch);
        }
        Ok(Self {
            http,
            endpoint_policy: Arc::new(endpoint_policy),
            callback_allow_http_loopback,
            exchange_budget,
            request_timeout,
        })
    }

    #[cfg(test)]
    fn for_loopback_tests(origin: &str) -> Self {
        Self::for_loopback_tests_with_exchange_limit(origin, PROVIDER_EXCHANGE_CONCURRENCY_LIMIT)
    }

    #[cfg(test)]
    fn for_loopback_tests_with_exchange_limit(origin: &str, limit: usize) -> Self {
        Self::build(
            [origin],
            true,
            true,
            Duration::from_millis(250),
            Arc::new(Semaphore::new(limit)),
        )
        .expect("loopback test origin and concurrency limit must be valid")
    }

    async fn discover(
        &self,
        issuer: &str,
        network_error: ProviderExchangeError,
    ) -> Result<DiscoveryDocument, ProviderExchangeError> {
        let issuer_url = self.endpoint_policy.validate_issuer(issuer)?;
        let discovery_url = discovery_url(&issuer_url);
        self.endpoint_policy.validate_endpoint(&discovery_url)?;
        let response = self
            .fetch_bounded(discovery_url, DISCOVERY_BODY_LIMIT)
            .await;
        let (status, content_type, body) = response.map_err(|()| network_error)?;
        if !status.is_success() || !is_json_content_type(content_type.as_deref()) {
            return Err(network_error);
        }
        let value = parse_unique_json(&body).map_err(|()| network_error)?;
        if !object_has_at_most(&value, 32) {
            return Err(network_error);
        }
        let document: DiscoveryDocument =
            serde_json::from_value(value).map_err(|_| network_error)?;
        if document.issuer != issuer {
            return Err(network_error);
        }
        document.validate(&self.endpoint_policy)?;
        Ok(document)
    }

    async fn fetch_bounded(
        &self,
        url: Url,
        limit: usize,
    ) -> Result<(StatusCode, Option<String>, Vec<u8>), ()> {
        let response = self.http.get(url).send().await.map_err(|_| ())?;
        if response
            .headers()
            .contains_key(reqwest::header::CONTENT_ENCODING)
        {
            return Err(());
        }
        if response
            .content_length()
            .is_some_and(|length| length > limit as u64)
        {
            return Err(());
        }
        let status = response.status();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let mut stream = response.bytes_stream();
        let mut body = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| ())?;
            if body
                .len()
                .checked_add(chunk.len())
                .is_none_or(|size| size > limit)
            {
                return Err(());
            }
            body.extend_from_slice(&chunk);
        }
        Ok((status, content_type, body))
    }

    async fn fetch_bearer_bounded(
        &self,
        url: Url,
        bearer: &[u8],
        limit: usize,
    ) -> Result<(StatusCode, Option<String>, Vec<u8>), ()> {
        let bearer = std::str::from_utf8(bearer).map_err(|_| ())?;
        if bearer.is_empty() || bearer.len() > 8192 {
            return Err(());
        }
        let response = self
            .http
            .get(url)
            .bearer_auth(bearer)
            .send()
            .await
            .map_err(|_| ())?;
        if response
            .headers()
            .contains_key(reqwest::header::CONTENT_ENCODING)
            || response
                .content_length()
                .is_some_and(|length| length > limit as u64)
        {
            return Err(());
        }
        let status = response.status();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let mut stream = response.bytes_stream();
        let mut body = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| ())?;
            if body
                .len()
                .checked_add(chunk.len())
                .is_none_or(|size| size > limit)
            {
                return Err(());
            }
            body.extend_from_slice(&chunk);
        }
        Ok((status, content_type, body))
    }

    async fn exchange_once(
        &self,
        token_endpoint: Url,
        request: &ProviderCallbackRequest,
    ) -> Result<TokenResponse, ProviderExchangeError> {
        let form = [
            ("grant_type", "authorization_code"),
            ("code", request.code.as_str()),
            ("redirect_uri", request.callback_url.as_str()),
            ("client_id", request.client_id.as_str()),
            ("client_secret", request.client_secret.as_str()),
            ("code_verifier", request.pkce_verifier.as_str()),
        ];
        // This POST is intentionally issued exactly once. No branch in this method repeats it.
        let response = self
            .http
            .post(token_endpoint)
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&form)
            .send()
            .await
            .map_err(|_| ProviderExchangeError::AmbiguousAfterDispatch)?;
        if response
            .headers()
            .contains_key(reqwest::header::CONTENT_ENCODING)
            || response
                .content_length()
                .is_some_and(|length| length > TOKEN_BODY_LIMIT as u64)
        {
            return Err(ProviderExchangeError::AmbiguousAfterDispatch);
        }
        let status = response.status();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let mut stream = response.bytes_stream();
        let mut body = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| ProviderExchangeError::AmbiguousAfterDispatch)?;
            if body
                .len()
                .checked_add(chunk.len())
                .is_none_or(|size| size > TOKEN_BODY_LIMIT)
            {
                return Err(ProviderExchangeError::AmbiguousAfterDispatch);
            }
            body.extend_from_slice(&chunk);
        }
        if status.is_client_error() {
            return Err(ProviderExchangeError::Rejected);
        }
        if !status.is_success() || !is_json_content_type(content_type.as_deref()) {
            return Err(ProviderExchangeError::AmbiguousAfterDispatch);
        }
        let value =
            parse_unique_json(&body).map_err(|()| ProviderExchangeError::AmbiguousAfterDispatch)?;
        if !object_has_at_most(&value, 16) {
            return Err(ProviderExchangeError::AmbiguousAfterDispatch);
        }
        let token: RawTokenResponse = serde_json::from_value(value)
            .map_err(|_| ProviderExchangeError::AmbiguousAfterDispatch)?;
        if token.id_token.is_empty() || token.id_token.len() > ID_TOKEN_LIMIT {
            return Err(ProviderExchangeError::InvalidProof);
        }
        // RFC 6749 permits `scope` to be omitted when it is unchanged. The omitted value is
        // therefore derived only from OwlAuth's exact request profile; an explicit provider value
        // remains an exact canonical set assertion and can never widen caller authority.
        let expected_scopes = requested_scopes(request.kind, request.profile);
        let granted_scopes = token
            .scope
            .as_deref()
            .map(parse_scopes)
            .transpose()
            .map_err(|()| ProviderExchangeError::InvalidProof)?
            .unwrap_or_else(|| expected_scopes.clone());
        if granted_scopes != expected_scopes {
            return Err(ProviderExchangeError::InvalidProof);
        }
        let refresh_token = token.refresh_token.and_then(|value| {
            (!value.is_empty() && value.len() <= 8192).then(|| Zeroizing::new(value.into_bytes()))
        });
        Ok(TokenResponse {
            id_token: Zeroizing::new(token.id_token),
            refresh_token,
            granted_scopes,
        })
    }

    async fn fetch_jwks(&self, jwks_uri: Url) -> Result<JwkSet, ProviderExchangeError> {
        let (status, content_type, body) = self
            .fetch_bounded(jwks_uri, JWKS_BODY_LIMIT)
            .await
            .map_err(|()| ProviderExchangeError::AmbiguousAfterDispatch)?;
        if !status.is_success() || !is_json_content_type(content_type.as_deref()) {
            return Err(ProviderExchangeError::AmbiguousAfterDispatch);
        }
        let value = parse_unique_json(&body).map_err(|()| ProviderExchangeError::InvalidProof)?;
        let valid_shape = value
            .as_object()
            .filter(|object| object.len() <= 4)
            .and_then(|object| object.get("keys"))
            .and_then(Value::as_array)
            .is_some_and(|keys| {
                !keys.is_empty()
                    && keys.len() <= MAX_JWKS_KEYS
                    && keys.iter().all(|key| object_has_at_most(key, 16))
            });
        if !valid_shape {
            return Err(ProviderExchangeError::InvalidProof);
        }
        let jwks: JwkSet =
            serde_json::from_value(value).map_err(|_| ProviderExchangeError::InvalidProof)?;
        jwks.validate()?;
        Ok(jwks)
    }
}

#[async_trait]
impl UpstreamProviderClient for RestrictedOidcProviderClient {
    fn issuer_allowed(&self, kind: crate::domain::ProviderKind, issuer: &str) -> bool {
        matches!(
            kind,
            crate::domain::ProviderKind::Oidc | crate::domain::ProviderKind::Google
        ) && kind.issuer_matches(issuer)
            && self.endpoint_policy.validate_issuer(issuer).is_ok()
    }

    async fn authorization_url(
        &self,
        request: ProviderAuthorizationRequest,
    ) -> Result<ProviderAuthorization, ProviderExchangeError> {
        if !self.issuer_allowed(request.kind, &request.issuer) {
            return Err(ProviderExchangeError::UnavailableBeforeDispatch);
        }
        validate_authorization_request(
            &request,
            &self.endpoint_policy,
            self.callback_allow_http_loopback,
        )?;
        let discovery = self
            .discover(
                &request.issuer,
                ProviderExchangeError::UnavailableBeforeDispatch,
            )
            .await?;
        if request.profile.is_managed_profile()
            && !managed_discovery_supported(request.kind, &discovery)
        {
            return Err(ProviderExchangeError::UnavailableBeforeDispatch);
        }
        let managed_supports_revocation = request
            .profile
            .is_managed_profile()
            .then_some(discovery.revocation_endpoint.is_some());
        Ok(ProviderAuthorization {
            url: build_authorization_url(discovery.authorization_endpoint, &request)?,
            managed_supports_revocation,
        })
    }

    async fn exchange_code(
        &self,
        request: ProviderCallbackRequest,
    ) -> Result<ProviderIdentity, ProviderExchangeError> {
        if !self.issuer_allowed(request.kind, &request.issuer) {
            return Err(ProviderExchangeError::UnavailableBeforeDispatch);
        }
        validate_callback_request(
            &request,
            &self.endpoint_policy,
            self.callback_allow_http_loopback,
        )?;
        // Provider exchange capacity is deliberately process-local and fail-fast. Waiting for a
        // permit would create an unbounded queue behind a slow or unavailable provider.
        let _permit = self
            .exchange_budget
            .try_acquire()
            .map_err(|_| ProviderExchangeError::UnavailableBeforeDispatch)?;
        let discovery = self
            .discover(
                &request.issuer,
                ProviderExchangeError::UnavailableBeforeDispatch,
            )
            .await?;
        if request.profile.is_managed_profile()
            && !managed_discovery_supported(request.kind, &discovery)
        {
            return Err(ProviderExchangeError::UnavailableBeforeDispatch);
        }
        let supports_revocation = discovery.revocation_endpoint.is_some();
        let token = self
            .exchange_once(discovery.token_endpoint, &request)
            .await?;
        let header = validated_header(&token.id_token)?;
        let first_jwks = self.fetch_jwks(discovery.jwks_uri.clone()).await?;
        let jwk = if let Some(key) = first_jwks.find(&header.kid) {
            key.clone()
        } else {
            // An unknown kid is the sole condition that permits one additional safe GET.
            let refreshed = self.fetch_jwks(discovery.jwks_uri).await?;
            refreshed
                .find(&header.kid)
                .ok_or(ProviderExchangeError::InvalidProof)?
                .clone()
        };
        let mut identity = validate_id_token(&token.id_token, &jwk, &request)?;
        if request.profile.is_managed_profile()
            && token.granted_scopes == managed_profile_scopes(request.kind)
        {
            identity.renewable_credential =
                token
                    .refresh_token
                    .map(|value| RenewableProviderCredential {
                        value,
                        granted_scopes: token.granted_scopes,
                        supports_revocation,
                    });
        }
        Ok(identity)
    }
}

const CONTROLLED_OIDC_MANAGED_CAPABILITY: ManagedProfileCapability = ManagedProfileCapability {
    adapter_key: "controlled_oidc_profile_v1",
    adapter_revision: 1,
    exact_scopes: &["offline_access", "openid", "profile"],
    provider_pkce_required: true,
    oidc_nonce_required: true,
    credential_rotates: true,
    read_retry_safe: true,
    renewal_replay: RenewalReplay::Never,
    supports_revocation: true,
    profile_schema: "owlauth.provider-profile.v1",
    maximum_body_bytes: 16 * 1024,
    maximum_latency_seconds: 10,
};

const GOOGLE_OIDC_MANAGED_CAPABILITY: ManagedProfileCapability = ManagedProfileCapability {
    adapter_key: "google_oidc_profile_v1",
    adapter_revision: 1,
    exact_scopes: &["openid", "profile"],
    provider_pkce_required: true,
    oidc_nonce_required: true,
    credential_rotates: true,
    read_retry_safe: true,
    renewal_replay: RenewalReplay::Never,
    supports_revocation: true,
    profile_schema: "owlauth.provider-profile.v1",
    maximum_body_bytes: 16 * 1024,
    maximum_latency_seconds: 10,
};

pub(crate) fn controlled_oidc_managed_capability() -> &'static ManagedProfileCapability {
    &CONTROLLED_OIDC_MANAGED_CAPABILITY
}

pub(crate) fn google_oidc_managed_capability() -> &'static ManagedProfileCapability {
    &GOOGLE_OIDC_MANAGED_CAPABILITY
}

pub(crate) fn managed_profile_capabilities() -> crate::domain::ManagedProfileCapabilities {
    crate::domain::ManagedProfileCapabilities::new(
        controlled_oidc_managed_capability(),
        google_oidc_managed_capability(),
    )
}

#[derive(Clone)]
pub(crate) struct RestrictedOidcManagedProfileAdapter {
    oidc: RestrictedOidcProviderClient,
    google: RestrictedOidcProviderClient,
    secrets: Arc<dyn ProviderSecretResolver>,
}

impl RestrictedOidcManagedProfileAdapter {
    pub(crate) fn new(
        oidc: RestrictedOidcProviderClient,
        google: RestrictedOidcProviderClient,
        secrets: Arc<dyn ProviderSecretResolver>,
    ) -> Self {
        Self {
            oidc,
            google,
            secrets,
        }
    }

    fn client(&self, guard: &ConnectionGuard) -> Result<&RestrictedOidcProviderClient, ()> {
        match guard.provider_kind {
            crate::domain::ProviderKind::Oidc => Ok(&self.oidc),
            crate::domain::ProviderKind::Google => Ok(&self.google),
            crate::domain::ProviderKind::Github => Err(()),
        }
    }
}

#[derive(Deserialize)]
struct RenewalDocument {
    access_token: String,
    refresh_token: String,
    #[serde(default)]
    scope: Option<String>,
}

#[derive(Deserialize)]
struct ManagedProfileDocument {
    sub: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    picture: Option<String>,
    #[serde(default)]
    locale: Option<String>,
}

#[async_trait]
impl ManagedProfileAdapter for RestrictedOidcManagedProfileAdapter {
    fn capability(&self) -> Option<&'static ManagedProfileCapability> {
        Some(&CONTROLLED_OIDC_MANAGED_CAPABILITY)
    }

    fn capability_for(
        &self,
        kind: crate::domain::ProviderKind,
    ) -> Option<&'static ManagedProfileCapability> {
        managed_profile_capabilities().for_kind(kind)
    }

    fn maximum_renewal_profile_duration(&self) -> Duration {
        // Renewal discovery + token exchange + profile discovery + UserInfo. Each request is
        // independently bounded by the configured client timeout.
        self.oidc
            .request_timeout
            .max(self.google.request_timeout)
            .saturating_mul(4)
    }

    async fn fetch_profile(
        &self,
        guard: &ConnectionGuard,
        credential: Zeroizing<Vec<u8>>,
    ) -> Result<BoundedManagedProfile, ProviderReadError> {
        let client = self
            .client(guard)
            .map_err(|()| ProviderReadError::Transient)?;
        let discovery = client
            .discover(
                &guard.issuer,
                ProviderExchangeError::UnavailableBeforeDispatch,
            )
            .await
            .map_err(|_| ProviderReadError::Transient)?;
        let endpoint = discovery
            .userinfo_endpoint
            .ok_or(ProviderReadError::InvalidProfile)?;
        let (status, content_type, body) = client
            .fetch_bearer_bounded(endpoint, credential.as_ref(), 16 * 1024)
            .await
            .map_err(|()| ProviderReadError::Ambiguous)?;
        if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
            return Err(ProviderReadError::InvalidCredential);
        }
        if !status.is_success() || !is_json_content_type(content_type.as_deref()) {
            return Err(ProviderReadError::Transient);
        }
        let value = parse_unique_json(&body).map_err(|()| ProviderReadError::InvalidProfile)?;
        if !object_has_at_most(&value, 16) {
            return Err(ProviderReadError::InvalidProfile);
        }
        let profile: ManagedProfileDocument =
            serde_json::from_value(value).map_err(|_| ProviderReadError::InvalidProfile)?;
        if profile.sub != guard.subject {
            return Err(ProviderReadError::InvalidProfile);
        }
        Ok(BoundedManagedProfile {
            profile: BoundedProviderProfile {
                display_name: profile
                    .name
                    .map(ProfileDisplayName::parse)
                    .transpose()
                    .map_err(|_| ProviderReadError::InvalidProfile)?,
                picture_url: profile
                    .picture
                    .map(ProfilePictureUrl::parse)
                    .transpose()
                    .map_err(|_| ProviderReadError::InvalidProfile)?,
                locale: profile
                    .locale
                    .map(ProfileLocale::parse)
                    .transpose()
                    .map_err(|_| ProviderReadError::InvalidProfile)?,
            },
            observed_at: OffsetDateTime::now_utc(),
        })
    }

    async fn renew(
        &self,
        guard: &ConnectionGuard,
        credential: Zeroizing<Vec<u8>>,
        stable_attempt_id: uuid::Uuid,
    ) -> ProviderRenewalResult {
        let Ok(client) = self.client(guard) else {
            return ProviderRenewalResult::TransientBeforeDispatch;
        };
        let Ok(discovery) = client
            .discover(
                &guard.issuer,
                ProviderExchangeError::UnavailableBeforeDispatch,
            )
            .await
        else {
            return ProviderRenewalResult::TransientBeforeDispatch;
        };
        let Ok(secret) = self.secrets.resolve(&guard.secret_ref).await else {
            return ProviderRenewalResult::TransientBeforeDispatch;
        };
        let Ok(refresh_token) = std::str::from_utf8(credential.as_ref()) else {
            return ProviderRenewalResult::InvalidGrant;
        };
        let form = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", guard.client_id.as_str()),
            ("client_secret", secret.as_str()),
        ];
        let Ok(response) = client
            .http
            .post(discovery.token_endpoint)
            .header("OwlAuth-Renewal-Attempt", stable_attempt_id.to_string())
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&form)
            .send()
            .await
        else {
            return ProviderRenewalResult::AmbiguousAfterDispatch;
        };
        let Ok((status, _, body)) = read_response_bounded(response, TOKEN_BODY_LIMIT).await else {
            return ProviderRenewalResult::AmbiguousAfterDispatch;
        };
        if status == StatusCode::BAD_REQUEST {
            let error = parse_unique_json(&body).ok().and_then(|value| {
                value
                    .get("error")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            });
            return match error.as_deref() {
                Some("invalid_grant") => ProviderRenewalResult::InvalidGrant,
                Some("invalid_scope") => ProviderRenewalResult::ScopeLost,
                _ => ProviderRenewalResult::AmbiguousAfterDispatch,
            };
        }
        if !status.is_success() {
            return ProviderRenewalResult::AmbiguousAfterDispatch;
        }
        let Some(document): Option<RenewalDocument> = parse_unique_json(&body)
            .ok()
            .and_then(|value| serde_json::from_value(value).ok())
        else {
            return ProviderRenewalResult::AmbiguousAfterDispatch;
        };
        // RFC 6749 section 6 defines an omitted scope as unchanged. Only the exact frozen
        // connection grant is authoritative here; explicit response scope is still compared as a
        // strict canonical set, including duplicate rejection.
        let Some(expected_scopes) = canonical_scope_set(&guard.required_scopes) else {
            return ProviderRenewalResult::ScopeLost;
        };
        let granted_scopes = match document.scope.as_deref() {
            Some(scope) => {
                let Ok(scopes) = parse_scopes(scope) else {
                    return ProviderRenewalResult::ScopeLost;
                };
                if scopes != expected_scopes {
                    return ProviderRenewalResult::ScopeLost;
                }
                scopes
            }
            None => expected_scopes,
        };
        if document.refresh_token.is_empty()
            || document.refresh_token.len() > 8192
            || document.access_token.is_empty()
            || document.access_token.len() > 8192
        {
            return ProviderRenewalResult::AmbiguousAfterDispatch;
        }
        ProviderRenewalResult::Success(RenewedCredential {
            renewable: Zeroizing::new(document.refresh_token.into_bytes()),
            access: Zeroizing::new(document.access_token.into_bytes()),
            granted_scopes,
        })
    }

    async fn revoke(
        &self,
        guard: &ConnectionGuard,
        credential: Zeroizing<Vec<u8>>,
    ) -> ProviderRevocationResult {
        let Ok(client) = self.client(guard) else {
            return ProviderRevocationResult::Ambiguous;
        };
        let Ok(discovery) = client
            .discover(
                &guard.issuer,
                ProviderExchangeError::UnavailableBeforeDispatch,
            )
            .await
        else {
            return ProviderRevocationResult::Ambiguous;
        };
        let Some(endpoint) = discovery.revocation_endpoint else {
            return ProviderRevocationResult::Unsupported;
        };
        let Ok(secret) = self.secrets.resolve(&guard.secret_ref).await else {
            return ProviderRevocationResult::Ambiguous;
        };
        let Ok(refresh_token) = std::str::from_utf8(credential.as_ref()) else {
            return ProviderRevocationResult::Ambiguous;
        };
        let form = [
            ("token", refresh_token),
            ("token_type_hint", "refresh_token"),
            ("client_id", guard.client_id.as_str()),
            ("client_secret", secret.as_str()),
        ];
        let Ok(response) = client
            .http
            .post(endpoint)
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&form)
            .send()
            .await
        else {
            return ProviderRevocationResult::Ambiguous;
        };
        let Ok((status, _, _)) = read_response_bounded(response, TOKEN_BODY_LIMIT).await else {
            return ProviderRevocationResult::Ambiguous;
        };
        if status.is_success() {
            ProviderRevocationResult::Confirmed
        } else if matches!(status, StatusCode::NOT_FOUND | StatusCode::NOT_IMPLEMENTED) {
            ProviderRevocationResult::Unsupported
        } else {
            ProviderRevocationResult::Ambiguous
        }
    }
}

async fn read_response_bounded(
    response: reqwest::Response,
    limit: usize,
) -> Result<(StatusCode, Option<String>, Vec<u8>), ()> {
    if response
        .headers()
        .contains_key(reqwest::header::CONTENT_ENCODING)
        || response
            .content_length()
            .is_some_and(|length| length > limit as u64)
    {
        return Err(());
    }
    let status = response.status();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| ())?;
        if body
            .len()
            .checked_add(chunk.len())
            .is_none_or(|size| size > limit)
        {
            return Err(());
        }
        body.extend_from_slice(&chunk);
    }
    Ok((status, content_type, body))
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Origin {
    scheme: String,
    host: String,
    port: u16,
}

impl Origin {
    fn from_url(url: &Url) -> Result<Self, ProviderExchangeError> {
        let host = url
            .host_str()
            .ok_or(ProviderExchangeError::UnavailableBeforeDispatch)?;
        let port = url
            .port_or_known_default()
            .ok_or(ProviderExchangeError::UnavailableBeforeDispatch)?;
        Ok(Self {
            scheme: url.scheme().to_owned(),
            host: host.to_owned(),
            port,
        })
    }
}

#[derive(Debug)]
struct EndpointPolicy {
    allowed_origins: HashSet<Origin>,
    allow_http_loopback: bool,
}

impl EndpointPolicy {
    fn new<I, S>(origins: I, allow_http_loopback: bool) -> Result<Self, ProviderExchangeError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut allowed_origins = HashSet::new();
        for value in origins {
            let url = Url::parse(value.as_ref())
                .map_err(|_| ProviderExchangeError::UnavailableBeforeDispatch)?;
            if url.cannot_be_a_base()
                || url.username() != ""
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
                || url.path() != "/"
                || !Self::secure_scheme(&url, allow_http_loopback)
            {
                return Err(ProviderExchangeError::UnavailableBeforeDispatch);
            }
            allowed_origins.insert(Origin::from_url(&url)?);
        }
        if allowed_origins.is_empty() {
            return Err(ProviderExchangeError::UnavailableBeforeDispatch);
        }
        Ok(Self {
            allowed_origins,
            allow_http_loopback,
        })
    }

    fn secure_scheme(url: &Url, allow_http_loopback: bool) -> bool {
        url.scheme() == "https"
            || (allow_http_loopback
                && url.scheme() == "http"
                && matches!(url.host_str(), Some("127.0.0.1" | "::1" | "[::1]")))
    }

    fn validate_issuer(&self, issuer: &str) -> Result<Url, ProviderExchangeError> {
        if issuer.is_empty() || issuer.len() > MAX_ISSUER_BYTES {
            return Err(ProviderExchangeError::UnavailableBeforeDispatch);
        }
        let url =
            Url::parse(issuer).map_err(|_| ProviderExchangeError::UnavailableBeforeDispatch)?;
        self.validate_common(&url)?;
        if url.query().is_some() || url.fragment().is_some() {
            return Err(ProviderExchangeError::UnavailableBeforeDispatch);
        }
        Ok(url)
    }

    fn validate_endpoint(&self, url: &Url) -> Result<(), ProviderExchangeError> {
        if url.as_str().len() > MAX_ENDPOINT_BYTES
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(ProviderExchangeError::UnavailableBeforeDispatch);
        }
        self.validate_common(url)
    }

    fn validate_common(&self, url: &Url) -> Result<(), ProviderExchangeError> {
        if url.cannot_be_a_base()
            || url.username() != ""
            || url.password().is_some()
            || !Self::secure_scheme(url, self.allow_http_loopback)
            || !self.allowed_origins.contains(&Origin::from_url(url)?)
        {
            return Err(ProviderExchangeError::UnavailableBeforeDispatch);
        }
        Ok(())
    }
}

pub(super) fn validate_runtime_callback(
    url: &Url,
    allow_http_loopback: bool,
) -> Result<(), ProviderExchangeError> {
    if url.as_str().len() > MAX_CALLBACK_BYTES
        || url.query().is_some()
        || url.fragment().is_some()
        || url.username() != ""
        || url.password().is_some()
        || !EndpointPolicy::secure_scheme(url, allow_http_loopback)
    {
        return Err(ProviderExchangeError::UnavailableBeforeDispatch);
    }
    Ok(())
}

#[derive(Deserialize)]
struct DiscoveryDocument {
    issuer: String,
    authorization_endpoint: Url,
    token_endpoint: Url,
    jwks_uri: Url,
    #[serde(default)]
    userinfo_endpoint: Option<Url>,
    #[serde(default)]
    revocation_endpoint: Option<Url>,
    response_types_supported: Vec<String>,
    #[serde(default)]
    response_modes_supported: Vec<String>,
    subject_types_supported: Vec<String>,
    id_token_signing_alg_values_supported: Vec<String>,
    #[serde(default)]
    scopes_supported: Vec<String>,
    #[serde(default)]
    code_challenge_methods_supported: Vec<String>,
}

impl DiscoveryDocument {
    fn validate(&self, policy: &EndpointPolicy) -> Result<(), ProviderExchangeError> {
        if self.issuer.is_empty()
            || self.issuer.len() > MAX_ISSUER_BYTES
            || self.response_types_supported.len() > 16
            || self.response_modes_supported.len() > 16
            || self.subject_types_supported.len() > 16
            || self.id_token_signing_alg_values_supported.len() > 16
            || self.scopes_supported.len() > 32
            || self.code_challenge_methods_supported.len() > 16
            || !contains_exact(&self.response_types_supported, "code")
            || (!self.response_modes_supported.is_empty()
                && !contains_exact(&self.response_modes_supported, "query"))
            || !contains_exact(&self.subject_types_supported, "public")
            || !contains_exact(&self.id_token_signing_alg_values_supported, "RS256")
            || !contains_exact(&self.scopes_supported, "openid")
            || !contains_exact(&self.scopes_supported, "profile")
            || !contains_exact(&self.code_challenge_methods_supported, "S256")
        {
            return Err(ProviderExchangeError::UnavailableBeforeDispatch);
        }
        policy.validate_endpoint(&self.authorization_endpoint)?;
        policy.validate_endpoint(&self.token_endpoint)?;
        policy.validate_endpoint(&self.jwks_uri)?;
        if let Some(endpoint) = &self.userinfo_endpoint {
            policy.validate_endpoint(endpoint)?;
        }
        if let Some(endpoint) = &self.revocation_endpoint {
            policy.validate_endpoint(endpoint)?;
        }
        Ok(())
    }
}

fn contains_exact(values: &[String], expected: &str) -> bool {
    values.iter().any(|value| value == expected)
}

fn discovery_url(issuer: &Url) -> Url {
    let mut url = issuer.clone();
    let path = issuer.path().trim_end_matches('/');
    url.set_path(&format!("{path}/.well-known/openid-configuration"));
    url.set_query(None);
    url.set_fragment(None);
    url
}

fn validate_authorization_request(
    request: &ProviderAuthorizationRequest,
    policy: &EndpointPolicy,
    callback_allow_http_loopback: bool,
) -> Result<(), ProviderExchangeError> {
    policy.validate_issuer(&request.issuer)?;
    let callback = Url::parse(&request.callback_url)
        .map_err(|_| ProviderExchangeError::UnavailableBeforeDispatch)?;
    validate_runtime_callback(&callback, callback_allow_http_loopback)?;
    if request.client_id.is_empty()
        || request.client_id.len() > MAX_CLIENT_ID_BYTES
        || request.state.is_empty()
        || request.state.len() > MAX_STATE_BYTES
        || request.nonce.is_empty()
        || request.nonce.len() > MAX_NONCE_BYTES
        || request.pkce_challenge.len() != 43
        || !is_base64url(&request.pkce_challenge)
    {
        return Err(ProviderExchangeError::UnavailableBeforeDispatch);
    }
    Ok(())
}

fn validate_callback_request(
    request: &ProviderCallbackRequest,
    policy: &EndpointPolicy,
    callback_allow_http_loopback: bool,
) -> Result<(), ProviderExchangeError> {
    policy.validate_issuer(&request.issuer)?;
    let callback = Url::parse(&request.callback_url)
        .map_err(|_| ProviderExchangeError::UnavailableBeforeDispatch)?;
    validate_runtime_callback(&callback, callback_allow_http_loopback)?;
    if request.client_id.is_empty()
        || request.client_id.len() > MAX_CLIENT_ID_BYTES
        || request.client_secret.is_empty()
        || request.client_secret.len() > MAX_CLIENT_SECRET_BYTES
        || request.code.is_empty()
        || request.code.len() > MAX_CODE_BYTES
        || !(43..=MAX_PKCE_VERIFIER_BYTES).contains(&request.pkce_verifier.len())
        || !is_pkce_verifier(&request.pkce_verifier)
        || request.expected_nonce.is_empty()
        || request.expected_nonce.len() > MAX_NONCE_BYTES
        || request.allowed_clock_skew_seconds != REQUIRED_CLOCK_SKEW_SECONDS
    {
        return Err(ProviderExchangeError::UnavailableBeforeDispatch);
    }
    Ok(())
}

fn build_authorization_url(
    mut endpoint: Url,
    request: &ProviderAuthorizationRequest,
) -> Result<String, ProviderExchangeError> {
    if endpoint.query().is_some() || endpoint.fragment().is_some() {
        return Err(ProviderExchangeError::UnavailableBeforeDispatch);
    }
    endpoint
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("response_mode", "query")
        .append_pair("client_id", &request.client_id)
        .append_pair("redirect_uri", &request.callback_url)
        .append_pair(
            "scope",
            requested_scope_parameter(request.kind, request.profile),
        )
        .append_pair("state", &request.state)
        .append_pair("nonce", &request.nonce)
        .append_pair("code_challenge", &request.pkce_challenge)
        .append_pair("code_challenge_method", "S256");
    if request.kind == crate::domain::ProviderKind::Google
        && request.profile == ProviderRequestProfile::ManagedProfile
    {
        endpoint
            .query_pairs_mut()
            .append_pair("access_type", "offline")
            .append_pair("prompt", "consent");
    }
    if endpoint.as_str().len() > 8192 {
        return Err(ProviderExchangeError::UnavailableBeforeDispatch);
    }
    Ok(endpoint.into())
}

fn managed_discovery_supported(
    kind: crate::domain::ProviderKind,
    discovery: &DiscoveryDocument,
) -> bool {
    discovery.userinfo_endpoint.is_some()
        && match kind {
            crate::domain::ProviderKind::Oidc => {
                contains_exact(&discovery.scopes_supported, "offline_access")
            }
            crate::domain::ProviderKind::Google => true,
            crate::domain::ProviderKind::Github => false,
        }
}

fn managed_profile_scopes(kind: crate::domain::ProviderKind) -> Vec<String> {
    requested_scopes(kind, ProviderRequestProfile::ManagedProfile)
}

fn requested_scope_parameter(
    kind: crate::domain::ProviderKind,
    profile: ProviderRequestProfile,
) -> &'static str {
    match (kind, profile) {
        (crate::domain::ProviderKind::Oidc, ProviderRequestProfile::ManagedProfile) => {
            "offline_access openid profile"
        }
        (_, _) => "openid profile",
    }
}

fn requested_scopes(
    kind: crate::domain::ProviderKind,
    profile: ProviderRequestProfile,
) -> Vec<String> {
    requested_scope_parameter(kind, profile)
        .split_ascii_whitespace()
        .map(str::to_owned)
        .collect()
}

fn canonical_scope_set(scopes: &[String]) -> Option<Vec<String>> {
    if scopes.is_empty() || scopes.len() > 16 || scopes.iter().any(String::is_empty) {
        return None;
    }
    let mut canonical = scopes.to_vec();
    canonical.sort_unstable();
    let before = canonical.len();
    canonical.dedup();
    (canonical.len() == before).then_some(canonical)
}

fn parse_scopes(value: &str) -> Result<Vec<String>, ()> {
    if value.is_empty() || value.len() > 1024 {
        return Err(());
    }
    let mut scopes: Vec<String> = value.split_ascii_whitespace().map(str::to_owned).collect();
    if scopes.is_empty() || scopes.len() > 16 || scopes.iter().any(|scope| scope.len() > 128) {
        return Err(());
    }
    scopes.sort_unstable();
    let before = scopes.len();
    scopes.dedup();
    if scopes.len() != before {
        return Err(());
    }
    Ok(scopes)
}

fn is_base64url(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn is_pkce_verifier(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

fn is_json_content_type(value: Option<&str>) -> bool {
    value.is_some_and(|value| {
        value
            .split(';')
            .next()
            .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"))
    })
}

struct TokenResponse {
    id_token: Zeroizing<String>,
    refresh_token: Option<Zeroizing<Vec<u8>>>,
    granted_scopes: Vec<String>,
}

#[derive(Deserialize)]
struct RawTokenResponse {
    id_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

#[derive(Clone, Deserialize)]
struct JwkSet {
    keys: Vec<RsaJwk>,
}

impl JwkSet {
    fn validate(&self) -> Result<(), ProviderExchangeError> {
        if self.keys.is_empty() || self.keys.len() > MAX_JWKS_KEYS {
            return Err(ProviderExchangeError::InvalidProof);
        }
        let mut kids = HashSet::new();
        for key in &self.keys {
            key.validate()?;
            if !kids.insert(&key.kid) {
                return Err(ProviderExchangeError::InvalidProof);
            }
        }
        Ok(())
    }

    fn find(&self, kid: &str) -> Option<&RsaJwk> {
        self.keys.iter().find(|key| key.kid == kid)
    }
}

#[derive(Clone, Deserialize)]
struct RsaJwk {
    kty: String,
    kid: String,
    #[serde(rename = "use")]
    use_: Option<String>,
    alg: Option<String>,
    n: String,
    e: String,
}

impl RsaJwk {
    fn validate(&self) -> Result<(), ProviderExchangeError> {
        if self.kty != "RSA"
            || self.kid.is_empty()
            || self.kid.len() > MAX_KID_BYTES
            || self.use_.as_deref().is_some_and(|value| value != "sig")
            || self.alg.as_deref().is_some_and(|value| value != "RS256")
            || self.n.is_empty()
            || self.n.len() > 2048
            || self.e.is_empty()
            || self.e.len() > 16
            || !is_base64url(&self.n)
            || !is_base64url(&self.e)
        {
            return Err(ProviderExchangeError::InvalidProof);
        }
        let modulus = URL_SAFE_NO_PAD
            .decode(&self.n)
            .map_err(|_| ProviderExchangeError::InvalidProof)?;
        let exponent = URL_SAFE_NO_PAD
            .decode(&self.e)
            .map_err(|_| ProviderExchangeError::InvalidProof)?;
        if !(256..=512).contains(&modulus.len()) || !(1..=8).contains(&exponent.len()) {
            return Err(ProviderExchangeError::InvalidProof);
        }
        Ok(())
    }
}

struct ValidatedHeader {
    kid: String,
}

fn validated_header(token: &str) -> Result<ValidatedHeader, ProviderExchangeError> {
    let (header_bytes, _) = inspect_compact_jwt(token)?;
    let header_value =
        parse_unique_json(&header_bytes).map_err(|()| ProviderExchangeError::InvalidProof)?;
    let object = header_value
        .as_object()
        .ok_or(ProviderExchangeError::InvalidProof)?;
    if object.len() > 3
        || object
            .keys()
            .any(|key| !matches!(key.as_str(), "alg" | "kid" | "typ"))
        || object.get("alg").and_then(Value::as_str) != Some("RS256")
        || object.get("kid").and_then(Value::as_str).is_none()
        || object
            .get("typ")
            .is_some_and(|value| value.as_str() != Some("JWT"))
    {
        return Err(ProviderExchangeError::InvalidProof);
    }
    let header = decode_header(token).map_err(|_| ProviderExchangeError::InvalidProof)?;
    if header.alg != Algorithm::RS256 {
        return Err(ProviderExchangeError::InvalidProof);
    }
    let kid = header.kid.ok_or(ProviderExchangeError::InvalidProof)?;
    if kid.is_empty() || kid.len() > MAX_KID_BYTES {
        return Err(ProviderExchangeError::InvalidProof);
    }
    Ok(ValidatedHeader { kid })
}

#[derive(Deserialize)]
struct IdTokenClaims {
    iss: String,
    sub: String,
    aud: Audience,
    #[serde(default)]
    azp: Option<String>,
    exp: i64,
    iat: i64,
    nbf: i64,
    nonce: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    picture: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn values(&self) -> Vec<&str> {
        match self {
            Self::One(value) => vec![value],
            Self::Many(values) => values.iter().map(String::as_str).collect(),
        }
    }
}

fn validate_id_token(
    token: &str,
    jwk: &RsaJwk,
    request: &ProviderCallbackRequest,
) -> Result<ProviderIdentity, ProviderExchangeError> {
    let header = validated_header(token)?;
    if header.kid != jwk.kid {
        return Err(ProviderExchangeError::InvalidProof);
    }
    jwk.validate()?;
    let (_, claims_bytes) = inspect_compact_jwt(token)?;
    let claims_value =
        parse_unique_json(&claims_bytes).map_err(|()| ProviderExchangeError::InvalidProof)?;
    if !object_has_at_most(&claims_value, 32) {
        return Err(ProviderExchangeError::InvalidProof);
    }

    let key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
        .map_err(|_| ProviderExchangeError::InvalidProof)?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    let claims = decode::<IdTokenClaims>(token, &key, &validation)
        .map_err(|_| ProviderExchangeError::InvalidProof)?
        .claims;
    validate_claims(claims, request)
}

fn inspect_compact_jwt(token: &str) -> Result<(Vec<u8>, Vec<u8>), ProviderExchangeError> {
    if token.is_empty() || token.len() > ID_TOKEN_LIMIT {
        return Err(ProviderExchangeError::InvalidProof);
    }
    let mut parts = token.split('.');
    let header = parts.next().ok_or(ProviderExchangeError::InvalidProof)?;
    let claims = parts.next().ok_or(ProviderExchangeError::InvalidProof)?;
    let signature = parts.next().ok_or(ProviderExchangeError::InvalidProof)?;
    if parts.next().is_some()
        || header.is_empty()
        || claims.is_empty()
        || signature.is_empty()
        || header.len() > JWT_PART_LIMIT
        || claims.len() > JWT_PART_LIMIT
        || signature.len() > JWT_PART_LIMIT
    {
        return Err(ProviderExchangeError::InvalidProof);
    }
    let header = URL_SAFE_NO_PAD
        .decode(header)
        .map_err(|_| ProviderExchangeError::InvalidProof)?;
    let claims = URL_SAFE_NO_PAD
        .decode(claims)
        .map_err(|_| ProviderExchangeError::InvalidProof)?;
    if header.len() > 4096 || claims.len() > 8192 {
        return Err(ProviderExchangeError::InvalidProof);
    }
    Ok((header, claims))
}

fn validate_claims(
    claims: IdTokenClaims,
    request: &ProviderCallbackRequest,
) -> Result<ProviderIdentity, ProviderExchangeError> {
    if claims.iss != request.issuer
        || claims.sub.is_empty()
        || claims.sub.len() > MAX_SUBJECT_BYTES
        || claims.nonce != request.expected_nonce.as_str()
    {
        return Err(ProviderExchangeError::InvalidProof);
    }
    let audiences = claims.aud.values();
    if audiences.is_empty()
        || audiences.len() > MAX_AUDIENCES
        || audiences
            .iter()
            .any(|audience| audience.is_empty() || audience.len() > MAX_CLIENT_ID_BYTES)
        || !audiences
            .iter()
            .any(|audience| *audience == request.client_id)
        || (audiences.len() > 1 && claims.azp.as_deref() != Some(request.client_id.as_str()))
        || claims
            .azp
            .as_deref()
            .is_some_and(|azp| azp != request.client_id)
    {
        return Err(ProviderExchangeError::InvalidProof);
    }
    let now = request.now.unix_timestamp();
    let skew = request.allowed_clock_skew_seconds;
    if skew != REQUIRED_CLOCK_SKEW_SECONDS
        || claims.iat > now.saturating_add(skew)
        || claims.nbf > now.saturating_add(skew)
        || claims.exp <= now.saturating_sub(skew)
        || claims.exp <= claims.iat
        || claims.exp <= claims.nbf
        || claims.exp.saturating_sub(claims.iat) > MAX_ID_TOKEN_LIFETIME_SECONDS
    {
        return Err(ProviderExchangeError::InvalidProof);
    }
    let display_name = claims
        .name
        .map(validate_display_name)
        .transpose()?
        .flatten();
    let picture_url = claims
        .picture
        .as_deref()
        .map(validate_picture)
        .transpose()?
        .flatten();
    Ok(ProviderIdentity {
        issuer: claims.iss,
        subject: claims.sub,
        display_name,
        picture_url,
        renewable_credential: None,
    })
}

fn validate_display_name(value: String) -> Result<Option<String>, ProviderExchangeError> {
    if value.chars().count() > MAX_NAME_CHARACTERS || value.chars().any(char::is_control) {
        return Err(ProviderExchangeError::InvalidProof);
    }
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(value))
    }
}

fn validate_picture(value: &str) -> Result<Option<String>, ProviderExchangeError> {
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > MAX_PICTURE_BYTES {
        return Err(ProviderExchangeError::InvalidProof);
    }
    let url = Url::parse(value).map_err(|_| ProviderExchangeError::InvalidProof)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.username() != ""
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(ProviderExchangeError::InvalidProof);
    }
    Ok(Some(url.into()))
}

/// Parses JSON while rejecting duplicate member names at every object depth.
fn object_has_at_most(value: &Value, maximum: usize) -> bool {
    value
        .as_object()
        .is_some_and(|object| object.len() <= maximum)
}

fn parse_unique_json(bytes: &[u8]) -> Result<Value, ()> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = UniqueValueSeed
        .deserialize(&mut deserializer)
        .map_err(|_| ())?;
    deserializer.end().map_err(|_| ())?;
    Ok(value)
}

struct UniqueValueSeed;

impl<'de> DeserializeSeed<'de> for UniqueValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueValueVisitor)
    }
}

struct UniqueValueVisitor;

impl<'de> Visitor<'de> for UniqueValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object members")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        UniqueValueSeed.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(UniqueValueSeed)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate JSON member"));
            }
            let value = object.next_value_seed(UniqueValueSeed)?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

#[cfg(test)]
#[path = "oidc_tests.rs"]
mod tests;
