use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::Router;
use axum::body::Body;
use axum::extract::{Form, State};
use axum::http::{Response, StatusCode};
use axum::routing::{get, post};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::Serialize;
use serde_json::{Value, json};
use time::OffsetDateTime;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use url::Url;
use zeroize::Zeroizing;

use super::*;

const TEST_KID: &str = "rsa-2026-01";
const TEST_N: &str = "z9GcoB_1gGq14ziCjVKMks5OodFg_ZQDgc4Hi4o-aJBnbGY5xTWA09M985U9a4I5H0QHZQVlUtG21RQVjjmtUecb5CEVHwLXwmQi3XOxT2wgKTiZ2h04RBAnrpOecaOfAPeUP35unKo6pgUbc2YC17GO05gvqhNiJi55YLFSH22v3H3F7RdKcYPscSxFOWPsHJ1DOEslajW0l4A-iEa7aqumZidUbr8Ggi--PBKMf_jQGvXYn-T_Kzfy3mES20-TnGWBBG3wgYZVaT7jQZCI9b82eY6mjarvyfFGQR-zF6nOVE9d8vw3q7HSZPZQgP6cvHrmaqQ58BWvJqh0W2Ultw";
const TEST_KEY: &str = r"-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDP0ZygH/WAarXj
OIKNUoySzk6h0WD9lAOBzgeLij5okGdsZjnFNYDT0z3zlT1rgjkfRAdlBWVS0bbV
FBWOOa1R5xvkIRUfAtfCZCLdc7FPbCApOJnaHThEECeuk55xo58A95Q/fm6cqjqm
BRtzZgLXsY7TmC+qE2ImLnlgsVIfba/cfcXtF0pxg+xxLEU5Y+wcnUM4SyVqNbSX
gD6IRrtqq6ZmJ1RuvwaCL748Eox/+NAa9dif5P8rN/LeYRLbT5OcZYEEbfCBhlVp
PuNBkIj1vzZ5jqaNqu/J8UZBH7MXqc5UT13y/DersdJk9lCA/py8euZqpDnwFa8m
qHRbZSW3AgMBAAECggEAVgZeL9ha3yAND7QuMoLXxtNYsFpELGOvOfXHoMcGg3E3
JqOASXaWz9hzHhgKdyzOKXeXGgWsRiaiaLyqGZgdezhQDtR08kPSfVjHJ+VCoe5P
t9CCu0t6JY6MZpMbtM22vYc+mjPjZL2AjoWxscip55BL36HxJRVl/Qki3Fg6duBI
1xmWY/XXIGUSOD+293HDHwXK+1xe6qIsg9jpV4/WN2XsOhj/i3MvW4pYl8mVuWZw
88NXZGSI97M1iIvkYgRysddnFjBDEx+RknKjcRZst3kezOuxprA0bfyyvI4eYFhh
sKuU5t35LOSd/2kghav/1CQx1GCAyOPPt+5IjEXmoQKBgQD2p0yG9nKbV5w0d+Mt
iryrvtVQ31S5xitA70bsDEzZUInr6zr6MEXgdBnu+FrG2P3Y0n1WZVnhxm+E5h+H
pU25B8LRJGPRRGSlU4La7wWHZ+0r0XmQTJP5FAPTiyNvONlUfD7zLdx3PAFobTXy
B9Z6ahHGqD7RnjjjvE/YodhN4QKBgQDXsZc0Fly139quUmVKqqGVivgH2hzlPYo5
7Ipoq386kCAUoKYGbwIQz6kNSP3A6k3SB8G2IKtFcLWGonDIr7UjIYXHXKagBBrk
Q6afOafBpVGuzPSwxQ++XigjAKO1UTFN5Ib7cBZp7+3pwLnCZPBP4V6nip9zSAdW
nd/fTxn2lwKBgEWCbjGWoEOg0/eBVbdO4s6vr+PjnDfiXewlwmHhMYMIjGW829kH
45lWfrx2pvZkzlzdLM89LrBOwLy+MWKDtjyPsFpKHAsscASbXUQfmfpH0nHHza9Z
tVW7SzzBeFHuvmhtvzu+z+OWOHtaU5qKlOnYnHvUjCd8pGGhfwr4yUFhAoGAK6Tu
sIZ52f9i03Uus84VBhppl8UlpakvKAtZ8lYJV4NESog7MAAUTeyHC34ign+moYIa
S00O+u0UfhqucZ1ELMiitjVkLerGujuKIpva+w8FmTY1qPMm/WE2A+ckORMlw9oj
CgujLWp0HKF3tQMRsUgsDAC7xOrlOTyWySvLWB8CgYBBUTbqEeR1VsZiwyXCJEQF
f2OeUG/jSKe0SnJsbA9Fq92ketafhMLC+BevO8IMfbPvpmbLX0qj0RVN4YgJxSMA
Hh/diz/PskWdnbyB2pP1HdDGxfLuUCq/1mpmwbunuYIOYoIIyc+wuAC1Hh4cZneo
xCH2vBNtpE7zqOhj6qmdvw==
-----END PRIVATE KEY-----";
const NOW: i64 = 1_800_000_000;

#[derive(Clone, Serialize)]
struct TestClaims {
    iss: String,
    sub: String,
    aud: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    azp: Option<String>,
    exp: i64,
    iat: i64,
    nbf: i64,
    nonce: String,
    name: String,
    picture: String,
}

fn claims(issuer: &str) -> TestClaims {
    TestClaims {
        iss: issuer.to_owned(),
        sub: "subject-123".to_owned(),
        aud: json!("client-123"),
        azp: None,
        exp: NOW + 600,
        iat: NOW,
        nbf: NOW - 1,
        nonce: "nonce-123".to_owned(),
        name: "Ada Lovelace".to_owned(),
        picture: "https://images.example/ada.png".to_owned(),
    }
}

fn sign(claims: &TestClaims, kid: &str) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_owned());
    encode(
        &header,
        claims,
        &EncodingKey::from_rsa_pem(TEST_KEY.as_bytes()).unwrap(),
    )
    .unwrap()
}

fn jwk(kid: &str) -> RsaJwk {
    RsaJwk {
        kty: "RSA".to_owned(),
        kid: kid.to_owned(),
        use_: Some("sig".to_owned()),
        alg: Some("RS256".to_owned()),
        n: TEST_N.to_owned(),
        e: "AQAB".to_owned(),
    }
}

fn callback_request(issuer: &str) -> ProviderCallbackRequest {
    ProviderCallbackRequest {
        issuer: issuer.to_owned(),
        client_id: "client-123".to_owned(),
        client_secret: Zeroizing::new("secret-123".to_owned()),
        callback_url: format!("{issuer}/callback"),
        code: Zeroizing::new("one-use-code".to_owned()),
        pkce_verifier: Zeroizing::new("v".repeat(43)),
        expected_nonce: Zeroizing::new("nonce-123".to_owned()),
        now: OffsetDateTime::from_unix_timestamp(NOW).unwrap(),
        allowed_clock_skew_seconds: 60,
    }
}

#[test]
fn pure_jwt_validation_accepts_only_the_fixed_profile() {
    let issuer = "https://issuer.example";
    let request = callback_request(issuer);
    let valid = claims(issuer);
    let identity = validate_id_token(&sign(&valid, TEST_KID), &jwk(TEST_KID), &request).unwrap();
    assert_eq!(identity.issuer, issuer);
    assert_eq!(identity.subject, "subject-123");
    assert_eq!(identity.display_name.as_deref(), Some("Ada Lovelace"));

    let mut bad_issuer = valid.clone();
    bad_issuer.iss = "https://different.example".to_owned();
    assert_eq!(
        validate_id_token(&sign(&bad_issuer, TEST_KID), &jwk(TEST_KID), &request),
        Err(ProviderExchangeError::InvalidProof)
    );

    let mut bad_nonce = valid.clone();
    bad_nonce.nonce = "other".to_owned();
    assert_eq!(
        validate_id_token(&sign(&bad_nonce, TEST_KID), &jwk(TEST_KID), &request),
        Err(ProviderExchangeError::InvalidProof)
    );

    let mut bad_audience = valid.clone();
    bad_audience.aud = json!("another-client");
    assert_eq!(
        validate_id_token(&sign(&bad_audience, TEST_KID), &jwk(TEST_KID), &request),
        Err(ProviderExchangeError::InvalidProof)
    );

    let mut expired = valid.clone();
    expired.exp = NOW - 61;
    assert_eq!(
        validate_id_token(&sign(&expired, TEST_KID), &jwk(TEST_KID), &request),
        Err(ProviderExchangeError::InvalidProof)
    );

    let mut future = valid.clone();
    future.iat = NOW + 61;
    future.exp = NOW + 700;
    assert_eq!(
        validate_id_token(&sign(&future, TEST_KID), &jwk(TEST_KID), &request),
        Err(ProviderExchangeError::InvalidProof)
    );

    let mut multi_audience = valid;
    multi_audience.aud = json!(["client-123", "other"]);
    assert_eq!(
        validate_id_token(&sign(&multi_audience, TEST_KID), &jwk(TEST_KID), &request),
        Err(ProviderExchangeError::InvalidProof)
    );
}

#[test]
fn malformed_signature_duplicate_json_and_collection_bounds_are_rejected() {
    let issuer = "https://issuer.example";
    let request = callback_request(issuer);
    let token = sign(&claims(issuer), TEST_KID);
    let mut broken = token.into_bytes();
    *broken.last_mut().unwrap() = if *broken.last().unwrap() == b'A' {
        b'B'
    } else {
        b'A'
    };
    let broken = String::from_utf8(broken).unwrap();
    assert_eq!(
        validate_id_token(&broken, &jwk(TEST_KID), &request),
        Err(ProviderExchangeError::InvalidProof)
    );
    assert!(parse_unique_json(br#"{"nonce":"one","nonce":"two"}"#).is_err());

    let too_many = JwkSet {
        keys: (0..=MAX_JWKS_KEYS)
            .map(|index| jwk(&format!("kid-{index}")))
            .collect(),
    };
    assert_eq!(
        too_many.validate(),
        Err(ProviderExchangeError::InvalidProof)
    );
    let duplicate = JwkSet {
        keys: vec![jwk(TEST_KID), jwk(TEST_KID)],
    };
    assert_eq!(
        duplicate.validate(),
        Err(ProviderExchangeError::InvalidProof)
    );
}

#[test]
fn production_policy_rejects_plain_http_and_non_origin_allowlist_entries() {
    assert_eq!(
        RestrictedOidcProviderClient::new(["http://127.0.0.1:9999"]).err(),
        Some(ProviderExchangeError::UnavailableBeforeDispatch)
    );
    assert_eq!(
        RestrictedOidcProviderClient::new(["https://issuer.example/not-an-origin"]).err(),
        Some(ProviderExchangeError::UnavailableBeforeDispatch)
    );
}

#[derive(Clone, Copy)]
enum TokenBehavior {
    Success,
    Reject,
    Fail,
    Timeout,
    Malformed,
    Oversized,
    BadProof,
}

struct ProviderState {
    origin: String,
    token: String,
    token_behavior: TokenBehavior,
    token_calls: AtomicUsize,
    jwks_calls: AtomicUsize,
    rotate_jwks: bool,
    submitted_form: std::sync::Mutex<Option<HashMap<String, String>>>,
}

struct TestProvider {
    origin: String,
    state: Arc<ProviderState>,
    task: JoinHandle<()>,
}

impl Drop for TestProvider {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn discovery(State(state): State<Arc<ProviderState>>) -> Response<Body> {
    json_response(
        StatusCode::OK,
        json!({
            "issuer": state.origin,
            "authorization_endpoint": format!("{}/authorize", state.origin),
            "token_endpoint": format!("{}/token", state.origin),
            "jwks_uri": format!("{}/jwks", state.origin),
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": ["openid", "profile"],
            "code_challenge_methods_supported": ["S256"]
        })
        .to_string(),
    )
}

async fn token(
    State(state): State<Arc<ProviderState>>,
    Form(form): Form<HashMap<String, String>>,
) -> Response<Body> {
    state.token_calls.fetch_add(1, Ordering::SeqCst);
    let pkce_matches = form
        .get("code_verifier")
        .is_some_and(|value| value == &"v".repeat(43));
    *state.submitted_form.lock().unwrap() = Some(form);
    if !pkce_matches {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({"error": "invalid_grant"}).to_string(),
        );
    }
    match state.token_behavior {
        TokenBehavior::Success => json_response(
            StatusCode::OK,
            json!({"id_token": state.token, "access_token": "discard-me", "token_type": "Bearer"})
                .to_string(),
        ),
        TokenBehavior::Reject => json_response(
            StatusCode::BAD_REQUEST,
            json!({"error": "invalid_grant", "vendor_secret": "not surfaced"}).to_string(),
        ),
        TokenBehavior::Fail => json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error": "provider_failure"}).to_string(),
        ),
        TokenBehavior::Timeout => {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            json_response(StatusCode::OK, json!({"id_token": state.token}).to_string())
        }
        TokenBehavior::Malformed => json_response(StatusCode::OK, "{".to_owned()),
        TokenBehavior::Oversized => json_response(StatusCode::OK, "x".repeat(TOKEN_BODY_LIMIT + 1)),
        TokenBehavior::BadProof => json_response(
            StatusCode::OK,
            json!({"id_token": format!("{}x", state.token)}).to_string(),
        ),
    }
}

async fn jwks(State(state): State<Arc<ProviderState>>) -> Response<Body> {
    let call = state.jwks_calls.fetch_add(1, Ordering::SeqCst);
    let kid = if state.rotate_jwks && call == 0 {
        "previous-kid"
    } else {
        TEST_KID
    };
    json_response(
        StatusCode::OK,
        json!({"keys": [{"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": TEST_N, "e": "AQAB"}]}).to_string(),
    )
}

fn json_response(status: StatusCode, body: String) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

async fn start_provider(behavior: TokenBehavior, rotate_jwks: bool) -> TestProvider {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let state = Arc::new(ProviderState {
        token: sign(&claims(&origin), TEST_KID),
        origin: origin.clone(),
        token_behavior: behavior,
        token_calls: AtomicUsize::new(0),
        jwks_calls: AtomicUsize::new(0),
        rotate_jwks,
        submitted_form: std::sync::Mutex::new(None),
    });
    let router = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/token", post(token))
        .route("/jwks", get(jwks))
        .with_state(Arc::clone(&state));
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    TestProvider {
        origin,
        state,
        task,
    }
}

#[tokio::test]
async fn controlled_provider_success_refreshes_unknown_kid_once_and_discards_tokens() {
    let provider = start_provider(TokenBehavior::Success, true).await;
    let client = RestrictedOidcProviderClient::for_loopback_tests(&provider.origin);
    let identity = client
        .exchange_code(callback_request(&provider.origin))
        .await
        .unwrap();
    assert_eq!(identity.subject, "subject-123");
    assert_eq!(provider.state.token_calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.state.jwks_calls.load(Ordering::SeqCst), 2);
    let form = provider.state.submitted_form.lock().unwrap();
    let form = form.as_ref().unwrap();
    assert_eq!(
        form.get("grant_type").map(String::as_str),
        Some("authorization_code")
    );
    assert_eq!(form.get("code").map(String::as_str), Some("one-use-code"));
    assert_eq!(
        form.get("code_verifier").map(String::as_str),
        Some("vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv")
    );
    assert!(!form.contains_key("scope"));
    assert!(!form.contains_key("refresh_token"));
}

#[tokio::test]
async fn controlled_provider_rejects_a_wrong_pkce_verifier_after_one_post() {
    let provider = start_provider(TokenBehavior::Success, false).await;
    let client = RestrictedOidcProviderClient::for_loopback_tests(&provider.origin);
    let mut request = callback_request(&provider.origin);
    request.pkce_verifier = Zeroizing::new("z".repeat(43));
    assert_eq!(
        client.exchange_code(request).await,
        Err(ProviderExchangeError::Rejected)
    );
    assert_eq!(provider.state.token_calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.state.jwks_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn known_kid_invalid_proof_does_not_refresh_jwks() {
    let provider = start_provider(TokenBehavior::BadProof, false).await;
    let client = RestrictedOidcProviderClient::for_loopback_tests(&provider.origin);
    assert_eq!(
        client
            .exchange_code(callback_request(&provider.origin))
            .await,
        Err(ProviderExchangeError::InvalidProof)
    );
    assert_eq!(provider.state.token_calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.state.jwks_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn code_post_is_never_retried_and_errors_are_stage_classified() {
    for (behavior, expected) in [
        (TokenBehavior::Reject, ProviderExchangeError::Rejected),
        (
            TokenBehavior::Fail,
            ProviderExchangeError::AmbiguousAfterDispatch,
        ),
        (
            TokenBehavior::Timeout,
            ProviderExchangeError::AmbiguousAfterDispatch,
        ),
        (
            TokenBehavior::Malformed,
            ProviderExchangeError::AmbiguousAfterDispatch,
        ),
        (
            TokenBehavior::Oversized,
            ProviderExchangeError::AmbiguousAfterDispatch,
        ),
    ] {
        let provider = start_provider(behavior, false).await;
        let client = RestrictedOidcProviderClient::for_loopback_tests(&provider.origin);
        assert_eq!(
            client
                .exchange_code(callback_request(&provider.origin))
                .await,
            Err(expected)
        );
        assert_eq!(provider.state.token_calls.load(Ordering::SeqCst), 1);
        assert_eq!(provider.state.jwks_calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn authorization_request_has_only_the_fixed_oidc_profile() {
    let provider = start_provider(TokenBehavior::Success, false).await;
    let client = RestrictedOidcProviderClient::for_loopback_tests(&provider.origin);
    let url = client
        .authorization_url(ProviderAuthorizationRequest {
            issuer: provider.origin.clone(),
            client_id: "client-123".to_owned(),
            callback_url: format!("{}/callback", provider.origin),
            state: "state-123".to_owned(),
            nonce: "nonce-123".to_owned(),
            pkce_challenge: "c".repeat(43),
        })
        .await
        .unwrap();
    let url = Url::parse(&url).unwrap();
    assert_eq!(url.path(), "/authorize");
    let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(query.len(), 9);
    assert_eq!(query.get("response_type").map(String::as_str), Some("code"));
    assert_eq!(
        query.get("response_mode").map(String::as_str),
        Some("query")
    );
    assert_eq!(
        query.get("scope").map(String::as_str),
        Some("openid profile")
    );
    assert_eq!(
        query.get("code_challenge_method").map(String::as_str),
        Some("S256")
    );
    assert_eq!(query.get("nonce").map(String::as_str), Some("nonce-123"));
}

#[tokio::test]
async fn redirects_oversized_documents_and_endpoint_mismatch_fail_before_dispatch() {
    async fn run(body: String, status: StatusCode) -> ProviderExchangeError {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let response_body = Arc::new(body.replace("$ORIGIN", &origin));
        let router = Router::new().route(
            "/.well-known/openid-configuration",
            get({
                let response_body = Arc::clone(&response_body);
                move || {
                    let response_body = Arc::clone(&response_body);
                    async move {
                        Response::builder()
                            .status(status)
                            .header("content-type", "application/json")
                            .header("location", "/elsewhere")
                            .body(Body::from(response_body.as_str().to_owned()))
                            .unwrap()
                    }
                }
            }),
        );
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let client = RestrictedOidcProviderClient::for_loopback_tests(&origin);
        let error = client
            .authorization_url(ProviderAuthorizationRequest {
                issuer: origin.clone(),
                client_id: "client-123".to_owned(),
                callback_url: format!("{origin}/callback"),
                state: "state".to_owned(),
                nonce: "nonce".to_owned(),
                pkce_challenge: "c".repeat(43),
            })
            .await
            .unwrap_err();
        task.abort();
        error
    }

    assert_eq!(
        run("redirect".to_owned(), StatusCode::FOUND).await,
        ProviderExchangeError::UnavailableBeforeDispatch
    );
    assert_eq!(
        run("x".repeat(DISCOVERY_BODY_LIMIT + 1), StatusCode::OK).await,
        ProviderExchangeError::UnavailableBeforeDispatch
    );

    let mismatch = json!({
        "issuer": "$ORIGIN",
        "authorization_endpoint": "https://unlisted.example/authorize",
        "token_endpoint": "https://unlisted.example/token",
        "jwks_uri": "https://unlisted.example/jwks",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile"],
        "code_challenge_methods_supported": ["S256"]
    })
    .to_string();
    assert_eq!(
        run(mismatch, StatusCode::OK).await,
        ProviderExchangeError::UnavailableBeforeDispatch
    );
}
