use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use futures_util::StreamExt as _;
use reqwest::{Client, StatusCode, redirect::Policy};
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::Semaphore;
use url::Url;
use zeroize::Zeroizing;

use crate::{
    application::{
        ProviderAuthorization, ProviderAuthorizationRequest, ProviderCallbackRequest,
        ProviderExchangeError, ProviderIdentity, ProviderRequestProfile, UpstreamProviderClient,
    },
    domain::{GITHUB_ISSUER, ProviderKind},
};

const AUTHORIZATION_URL: &str = "https://github.com/login/oauth/authorize";
const TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
const USER_URL: &str = "https://api.github.com/user";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const BODY_LIMIT: usize = 32 * 1024;
#[cfg(test)]
const EXCHANGE_CONCURRENCY_LIMIT: usize = 16;

#[derive(Clone)]
pub(crate) struct GithubOAuthProviderClient {
    http: Client,
    authorization_url: Url,
    token_url: Url,
    user_url: Url,
    exchange_budget: Arc<Semaphore>,
    callback_allow_http_loopback: bool,
}

impl GithubOAuthProviderClient {
    #[cfg(test)]
    pub(crate) fn new_with_budget(
        exchange_budget: Arc<Semaphore>,
    ) -> Result<Self, ProviderExchangeError> {
        Self::new_with_budget_and_callback_policy(exchange_budget, false)
    }

    pub(crate) fn new_with_budget_and_callback_policy(
        exchange_budget: Arc<Semaphore>,
        callback_allow_http_loopback: bool,
    ) -> Result<Self, ProviderExchangeError> {
        if exchange_budget.available_permits() == 0 {
            return Err(ProviderExchangeError::UnavailableBeforeDispatch);
        }
        let http = Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .redirect(Policy::none())
            .no_proxy()
            .build()
            .map_err(|_| ProviderExchangeError::UnavailableBeforeDispatch)?;
        Ok(Self {
            http,
            authorization_url: Url::parse(AUTHORIZATION_URL)
                .map_err(|_| ProviderExchangeError::UnavailableBeforeDispatch)?,
            token_url: Url::parse(TOKEN_URL)
                .map_err(|_| ProviderExchangeError::UnavailableBeforeDispatch)?,
            user_url: Url::parse(USER_URL)
                .map_err(|_| ProviderExchangeError::UnavailableBeforeDispatch)?,
            exchange_budget,
            callback_allow_http_loopback,
        })
    }

    #[cfg(test)]
    fn with_client(http: Client, origin: &str) -> Self {
        let origin = Url::parse(origin).unwrap();
        Self {
            http,
            authorization_url: origin.join("login/oauth/authorize").unwrap(),
            token_url: origin.join("login/oauth/access_token").unwrap(),
            user_url: origin.join("user").unwrap(),
            exchange_budget: Arc::new(Semaphore::new(EXCHANGE_CONCURRENCY_LIMIT)),
            callback_allow_http_loopback: true,
        }
    }

    fn accepts(kind: ProviderKind, issuer: &str, profile: ProviderRequestProfile) -> bool {
        kind == ProviderKind::Github
            && issuer == GITHUB_ISSUER
            && profile == ProviderRequestProfile::Login
    }

    async fn read_bounded(
        response: reqwest::Response,
    ) -> Result<(StatusCode, Option<String>, Vec<u8>), ()> {
        if response
            .headers()
            .contains_key(reqwest::header::CONTENT_ENCODING)
            || response
                .content_length()
                .is_some_and(|length| length > BODY_LIMIT as u64)
        {
            return Err(());
        }
        let status = response.status();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| ())?;
            if body
                .len()
                .checked_add(chunk.len())
                .is_none_or(|length| length > BODY_LIMIT)
            {
                return Err(());
            }
            body.extend_from_slice(&chunk);
        }
        Ok((status, content_type, body))
    }
}

#[derive(Deserialize)]
struct GithubTokenResponse {
    access_token: String,
    token_type: String,
    scope: String,
}

#[derive(Deserialize)]
struct GithubUserResponse {
    id: u64,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    avatar_url: Option<String>,
}

#[async_trait]
impl UpstreamProviderClient for GithubOAuthProviderClient {
    fn issuer_allowed(&self, kind: ProviderKind, issuer: &str) -> bool {
        kind == ProviderKind::Github && issuer == GITHUB_ISSUER
    }

    async fn authorization_url(
        &self,
        request: ProviderAuthorizationRequest,
    ) -> Result<ProviderAuthorization, ProviderExchangeError> {
        if !Self::accepts(request.kind, &request.issuer, request.profile)
            || request.client_id.is_empty()
            || request.client_id.len() > 512
            || request.state.is_empty()
            || request.state.len() > 512
            || request.pkce_challenge.len() != 43
            || !request
                .pkce_challenge
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(ProviderExchangeError::UnavailableBeforeDispatch);
        }
        let callback = Url::parse(&request.callback_url)
            .map_err(|_| ProviderExchangeError::UnavailableBeforeDispatch)?;
        super::oidc::validate_runtime_callback(&callback, self.callback_allow_http_loopback)?;
        let mut url = self.authorization_url.clone();
        url.query_pairs_mut()
            .append_pair("client_id", &request.client_id)
            .append_pair("redirect_uri", &request.callback_url)
            .append_pair("scope", crate::domain::GITHUB_SCOPES[0])
            .append_pair("state", &request.state)
            .append_pair("code_challenge", &request.pkce_challenge)
            .append_pair("code_challenge_method", "S256");
        Ok(ProviderAuthorization {
            url: url.to_string(),
            managed_supports_revocation: None,
        })
    }

    async fn exchange_code(
        &self,
        request: ProviderCallbackRequest,
    ) -> Result<ProviderIdentity, ProviderExchangeError> {
        if !Self::accepts(request.kind, &request.issuer, request.profile)
            || request.client_id.is_empty()
            || request.client_id.len() > 512
            || request.client_secret.is_empty()
            || request.client_secret.len() > 4096
            || request.code.is_empty()
            || request.code.len() > 4096
            || request.pkce_verifier.len() < 43
            || request.pkce_verifier.len() > 128
        {
            return Err(ProviderExchangeError::UnavailableBeforeDispatch);
        }
        let callback = Url::parse(&request.callback_url)
            .map_err(|_| ProviderExchangeError::UnavailableBeforeDispatch)?;
        super::oidc::validate_runtime_callback(&callback, self.callback_allow_http_loopback)?;
        let _permit = self
            .exchange_budget
            .try_acquire()
            .map_err(|_| ProviderExchangeError::UnavailableBeforeDispatch)?;
        let form = [
            ("client_id", request.client_id.as_str()),
            ("client_secret", request.client_secret.as_str()),
            ("code", request.code.as_str()),
            ("redirect_uri", request.callback_url.as_str()),
            ("code_verifier", request.pkce_verifier.as_str()),
        ];
        let response = self
            .http
            .post(self.token_url.clone())
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&form)
            .send()
            .await
            .map_err(|_| ProviderExchangeError::AmbiguousAfterDispatch)?;
        let (status, content_type, body) = Self::read_bounded(response)
            .await
            .map_err(|()| ProviderExchangeError::AmbiguousAfterDispatch)?;
        if status.is_client_error() {
            return Err(ProviderExchangeError::Rejected);
        }
        if !status.is_success() || !is_json(content_type.as_deref()) {
            return Err(ProviderExchangeError::AmbiguousAfterDispatch);
        }
        let token_value: Value = serde_json::from_slice(&body)
            .map_err(|_| ProviderExchangeError::AmbiguousAfterDispatch)?;
        if token_value.as_object().is_none_or(|value| value.len() > 8) {
            return Err(ProviderExchangeError::AmbiguousAfterDispatch);
        }
        let token: GithubTokenResponse = serde_json::from_value(token_value)
            .map_err(|_| ProviderExchangeError::AmbiguousAfterDispatch)?;
        if token.access_token.is_empty()
            || token.access_token.len() > 8192
            || !token.token_type.eq_ignore_ascii_case("bearer")
            || token.scope != crate::domain::GITHUB_SCOPES[0]
        {
            return Err(ProviderExchangeError::InvalidProof);
        }
        let access_token = Zeroizing::new(token.access_token);
        let response = self
            .http
            .get(self.user_url.clone())
            .bearer_auth(access_token.as_str())
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .header(reqwest::header::USER_AGENT, "owlauth-server")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await
            .map_err(|_| ProviderExchangeError::AmbiguousAfterDispatch)?;
        let (status, content_type, body) = Self::read_bounded(response)
            .await
            .map_err(|()| ProviderExchangeError::AmbiguousAfterDispatch)?;
        if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
            return Err(ProviderExchangeError::InvalidProof);
        }
        if !status.is_success() || !is_json(content_type.as_deref()) {
            return Err(ProviderExchangeError::AmbiguousAfterDispatch);
        }
        let user_value: Value =
            serde_json::from_slice(&body).map_err(|_| ProviderExchangeError::InvalidProof)?;
        if user_value.as_object().is_none_or(|value| value.len() > 64) {
            return Err(ProviderExchangeError::InvalidProof);
        }
        let user: GithubUserResponse =
            serde_json::from_value(user_value).map_err(|_| ProviderExchangeError::InvalidProof)?;
        if user.id == 0 {
            return Err(ProviderExchangeError::InvalidProof);
        }
        Ok(ProviderIdentity {
            issuer: GITHUB_ISSUER.to_owned(),
            subject: user.id.to_string(),
            display_name: user.name,
            picture_url: user.avatar_url,
            renewable_credential: None,
        })
    }
}

fn is_json(content_type: Option<&str>) -> bool {
    content_type.is_some_and(|value| {
        value
            .split(';')
            .next()
            .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_is_login_only_and_builds_fixed_pkce_authorization() {
        let client = GithubOAuthProviderClient::with_client(
            Client::builder().redirect(Policy::none()).build().unwrap(),
            "https://github.com",
        );
        assert!(client.issuer_allowed(ProviderKind::Github, GITHUB_ISSUER));
        assert!(!client.issuer_allowed(ProviderKind::Oidc, GITHUB_ISSUER));
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let authorization = runtime
            .block_on(client.authorization_url(ProviderAuthorizationRequest {
                kind: ProviderKind::Github,
                issuer: GITHUB_ISSUER.to_owned(),
                client_id: "client".to_owned(),
                callback_url: "https://runtime.example/callback".to_owned(),
                state: "state".to_owned(),
                nonce: "unused-nonce".to_owned(),
                pkce_challenge: "A".repeat(43),
                profile: ProviderRequestProfile::Login,
                egress_policy: None,
            }))
            .unwrap();
        let url = Url::parse(&authorization.url).unwrap();
        assert_eq!(url.origin().ascii_serialization(), "https://github.com");
        let query = url
            .query_pairs()
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            query.get("scope").map(std::convert::AsRef::as_ref),
            Some(crate::domain::GITHUB_SCOPES[0])
        );
        assert_eq!(
            query
                .get("code_challenge_method")
                .map(std::convert::AsRef::as_ref),
            Some("S256")
        );

        let managed = runtime.block_on(client.authorization_url(ProviderAuthorizationRequest {
            kind: ProviderKind::Github,
            issuer: GITHUB_ISSUER.to_owned(),
            client_id: "client".to_owned(),
            callback_url: "https://runtime.example/callback".to_owned(),
            state: "state".to_owned(),
            nonce: "unused-nonce".to_owned(),
            pkce_challenge: "A".repeat(43),
            profile: ProviderRequestProfile::ManagedProfile,
            egress_policy: None,
        }));
        assert_eq!(
            managed,
            Err(ProviderExchangeError::UnavailableBeforeDispatch)
        );

        let plaintext_remote =
            runtime.block_on(client.authorization_url(ProviderAuthorizationRequest {
                kind: ProviderKind::Github,
                issuer: GITHUB_ISSUER.to_owned(),
                client_id: "client".to_owned(),
                callback_url: "http://runtime.example/callback".to_owned(),
                state: "state".to_owned(),
                nonce: "unused-nonce".to_owned(),
                pkce_challenge: "A".repeat(43),
                profile: ProviderRequestProfile::Login,
                egress_policy: None,
            }));
        assert_eq!(
            plaintext_remote,
            Err(ProviderExchangeError::UnavailableBeforeDispatch)
        );
    }

    #[tokio::test]
    async fn github_exchange_uses_numeric_id_and_never_returns_renewable_material() {
        use axum::{
            Json, Router,
            http::HeaderMap,
            routing::{get, post},
        };
        use serde_json::json;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let router = Router::new()
            .route(
                "/login/oauth/access_token",
                post(|| async {
                    Json(json!({
                        "access_token": "token-value",
                        "token_type": "bearer",
                        "scope": "read:user"
                    }))
                }),
            )
            .route(
                "/user",
                get(|headers: HeaderMap| async move {
                    assert_eq!(
                        headers
                            .get(reqwest::header::AUTHORIZATION)
                            .and_then(|value| value.to_str().ok()),
                        Some("Bearer token-value")
                    );
                    Json(json!({
                        "id": 123_456_789_u64,
                        "login": "mutable-name-is-ignored",
                        "name": "Octo User",
                        "avatar_url": "https://avatars.githubusercontent.com/u/123456789"
                    }))
                }),
            );
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = GithubOAuthProviderClient::with_client(
            Client::builder()
                .redirect(Policy::none())
                .no_proxy()
                .build()
                .unwrap(),
            &origin,
        );
        let identity = client
            .exchange_code(ProviderCallbackRequest {
                kind: ProviderKind::Github,
                issuer: GITHUB_ISSUER.to_owned(),
                client_id: "client".to_owned(),
                client_secret: Zeroizing::new("secret".to_owned()),
                callback_url: "https://runtime.example/callback".to_owned(),
                code: Zeroizing::new("one-use-code".to_owned()),
                pkce_verifier: Zeroizing::new("A".repeat(43)),
                expected_nonce: Zeroizing::new("unused".to_owned()),
                now: time::OffsetDateTime::now_utc(),
                allowed_clock_skew_seconds: 60,
                profile: ProviderRequestProfile::Login,
                egress_policy: None,
            })
            .await
            .unwrap();
        server.abort();
        assert_eq!(identity.issuer, GITHUB_ISSUER);
        assert_eq!(identity.subject, "123456789");
        assert_eq!(identity.display_name.as_deref(), Some("Octo User"));
        assert!(identity.renewable_credential.is_none());
    }
}
