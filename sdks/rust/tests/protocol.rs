use std::{
    collections::{BTreeSet, VecDeque},
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use owlauth_client::{
    Client, ClientConfig, Clock, EntropySource, Error, ErrorCategory, HttpRequest, HttpResponse,
    LocalAction, RetryPolicy, Transport, TransportFailure, TransportFailureKind,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[derive(Default)]
struct MockTransport {
    outcomes: Mutex<VecDeque<Result<HttpResponse, TransportFailure>>>,
    requests: Mutex<Vec<HttpRequest>>,
}

impl MockTransport {
    fn with(outcomes: Vec<Result<HttpResponse, TransportFailure>>) -> Self {
        Self {
            outcomes: Mutex::new(outcomes.into()),
            requests: Mutex::new(Vec::new()),
        }
    }

    fn request_count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }

    fn bodies(&self) -> Vec<Value> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter_map(|request| {
                request
                    .body
                    .as_ref()
                    .and_then(|body| serde_json::from_slice(body).ok())
            })
            .collect()
    }
}

#[async_trait]
impl Transport for MockTransport {
    async fn send(
        &self,
        request: HttpRequest,
        _deadline: Duration,
    ) -> Result<HttpResponse, TransportFailure> {
        self.requests.lock().unwrap().push(request);
        self.outcomes
            .lock()
            .unwrap()
            .pop_front()
            .expect("mock response")
    }
}

struct DeterministicEntropy {
    calls: Mutex<u8>,
}
impl DeterministicEntropy {
    fn new() -> Self {
        Self {
            calls: Mutex::new(0),
        }
    }
}
impl EntropySource for DeterministicEntropy {
    fn fill(&self, destination: &mut [u8]) -> Result<(), Error> {
        let mut calls = self.calls.lock().unwrap();
        destination.fill(*calls);
        *calls = calls.saturating_add(1);
        Ok(())
    }
}

struct FixedClock(i64);
impl Clock for FixedClock {
    fn now_unix_seconds(&self) -> i64 {
        self.0
    }
}

#[allow(clippy::needless_pass_by_value, clippy::unnecessary_wraps)]
fn response(status: u16, body: Value) -> Result<HttpResponse, TransportFailure> {
    Ok(HttpResponse {
        status,
        headers: Vec::new(),
        body: serde_json::to_vec(&body).unwrap(),
    })
}

#[allow(clippy::unnecessary_wraps)]
fn raw_response(status: u16, body: &[u8]) -> Result<HttpResponse, TransportFailure> {
    Ok(HttpResponse {
        status,
        headers: Vec::new(),
        body: body.to_vec(),
    })
}

fn begin_response() -> Result<HttpResponse, TransportFailure> {
    response(
        201,
        json!({
            "hosted_url": "https://runtime.example/base/auth/interactions/opaque",
            "expires_at": "1970-01-01T00:10:00Z"
        }),
    )
}

fn projection() -> Value {
    json!({
        "user_id": "user_public",
        "user_revision": 1,
        "projection_schema": "owlauth.user.v1",
        "projection_revision": 1,
        "display_name": "Example User",
        "picture_url": null,
        "locale": "en-GB",
        "verified_email": null,
        "status": "active",
        "created_at": "1970-01-01T00:00:00Z",
        "updated_at": "1970-01-01T00:00:00Z"
    })
}

fn credentials(generation: i64) -> Value {
    json!({
        "project_id": "project_public",
        "application_id": "application_public",
        "user_id": "user_public",
        "session_id": "00000000-0000-0000-0000-000000000001",
        "refresh_generation": generation,
        "access_token": format!("access-token-{generation}"),
        "refresh_token": format!("refresh-token-{generation}"),
        "token_type": "Bearer",
        "expires_in": 300,
        "projection": projection(),
        "projection_revision": 1,
        "session_expires_at": "1970-01-30T00:00:00Z"
    })
}

fn client(transport: Arc<MockTransport>) -> Client {
    Client::with_dependencies(
        ClientConfig::new(
            "https://runtime.example/base/",
            "project_public",
            "application_public",
            "publishable_key",
        ),
        transport,
        Arc::new(DeterministicEntropy::new()),
        Arc::new(FixedClock(0)),
    )
    .unwrap()
}

#[test]
fn url_policy_preserves_prefix_and_requires_explicit_loopback() {
    let transport = Arc::new(MockTransport::default());
    let configured = client(transport);
    assert_eq!(configured.base_url(), "https://runtime.example/base/");

    let mut loopback = ClientConfig::new(
        "http://127.0.0.1:8080/runtime",
        "project",
        "application",
        "key",
    );
    assert!(
        Client::with_dependencies(
            loopback.clone(),
            Arc::new(MockTransport::default()),
            Arc::new(DeterministicEntropy::new()),
            Arc::new(FixedClock(0))
        )
        .is_err()
    );
    loopback.allow_insecure_loopback = true;
    assert!(
        Client::with_dependencies(
            loopback,
            Arc::new(MockTransport::default()),
            Arc::new(DeterministicEntropy::new()),
            Arc::new(FixedClock(0))
        )
        .is_ok()
    );
}

#[tokio::test]
async fn begin_login_uses_deterministic_s256_and_keeps_provider_selection_out() {
    let transport = Arc::new(MockTransport::with(vec![begin_response()]));
    let client = client(Arc::clone(&transport));
    let login = client
        .begin_login("https://app.example/callback", None, Some("work"))
        .await
        .unwrap();
    let body = &transport.bodies()[0];
    let verifier = URL_SAFE_NO_PAD.encode([0_u8; 32]);
    let expected_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    assert_eq!(body["pkce_challenge"], expected_challenge);
    assert_eq!(body["state"], URL_SAFE_NO_PAD.encode([1_u8; 32]));
    assert!(body.get("provider_key").is_none());
    assert!(format!("{:?}", login.pending).contains("[REDACTED]"));
    assert!(!format!("{:?}", login.pending).contains(&verifier));
}

#[tokio::test]
async fn callback_mismatch_dispatches_nothing_and_consumes_only_local_value() {
    let transport = Arc::new(MockTransport::with(vec![begin_response()]));
    let client = client(Arc::clone(&transport));
    let login = client
        .begin_login("https://app.example/callback", None, None)
        .await
        .unwrap();
    let error = client
        .validate_callback(
            "https://app.example/callback?handoff=ticket&state=wrong",
            login.pending,
        )
        .unwrap_err();
    assert_eq!(error.category(), ErrorCategory::Handoff);
    assert_eq!(error.local_action(), LocalAction::DiscardPendingLogin);
    assert_eq!(transport.request_count(), 1);
}

#[tokio::test]
async fn handoff_refresh_current_user_and_logout_use_explicit_atomic_values() {
    let state = URL_SAFE_NO_PAD.encode([1_u8; 32]);
    let transport = Arc::new(MockTransport::with(vec![
        begin_response(),
        response(200, credentials(1)),
        response(200, credentials(2)),
        response(
            200,
            json!({
                "project_id": "project_public", "application_id": "application_public",
                "user_id": "user_public", "projection": projection(), "projection_revision": 1,
                "authenticated_at": "1970-01-01T00:00:00Z", "session_expires_at": "1970-01-30T00:00:00Z"
            }),
        ),
        response(200, json!({"completed": true})),
        response(
            201,
            json!({"hosted_url": "https://runtime.example/base/auth/browser-logout/prep", "expires_at": "1970-01-01T00:01:00Z"}),
        ),
    ]));
    let client = client(Arc::clone(&transport));
    let login = client
        .begin_login("https://app.example/callback", None, None)
        .await
        .unwrap();
    let pair = client
        .complete_login(
            &format!("https://app.example/callback?handoff=ticket&state={state}"),
            login.pending,
        )
        .await
        .unwrap();
    assert_eq!(pair.refresh_generation(), 1);
    let next = client.refresh(&pair).await.unwrap();
    assert_eq!(next.refresh_generation(), 2);
    let user = client.current_user(next.access_token()).await.unwrap();
    assert_eq!(user.user_id, "user_public");
    client
        .logout_application(next.access_token())
        .await
        .unwrap();
    let logout = client
        .prepare_browser_logout(next.access_token())
        .await
        .unwrap();
    assert!(logout.hosted_url.ends_with("/auth/browser-logout/prep"));
    assert_eq!(transport.request_count(), 6);
    let bodies = transport.bodies();
    assert_eq!(bodies[1]["handoff"], "ticket");
    assert_eq!(bodies[2]["refresh_token"], "refresh-token-1");
    let debug = format!("{next:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("access-token-2"));
    assert!(!debug.contains("refresh-token-2"));
}

#[tokio::test]
async fn post_dispatch_handoff_failure_is_indeterminate_and_never_retried() {
    let state = URL_SAFE_NO_PAD.encode([1_u8; 32]);
    let transport = Arc::new(MockTransport::with(vec![
        begin_response(),
        Err(TransportFailure::new(TransportFailureKind::Timeout, true)),
    ]));
    let client = client(Arc::clone(&transport));
    let login = client
        .begin_login("https://app.example/callback", None, None)
        .await
        .unwrap();
    let error = client
        .complete_login(
            &format!("https://app.example/callback?handoff=synthetic-ticket&state={state}"),
            login.pending,
        )
        .await
        .unwrap_err();
    assert_eq!(error.category(), ErrorCategory::Indeterminate);
    assert_eq!(error.retry_policy(), RetryPolicy::Never);
    assert_eq!(error.local_action(), LocalAction::QuarantinePendingLogin);
    assert_eq!(transport.request_count(), 2);
    assert!(!format!("{error:?}").contains("synthetic-ticket"));
}

#[tokio::test]
async fn malformed_handoff_success_quarantines_pending_without_retry_or_secret_disclosure() {
    let state = URL_SAFE_NO_PAD.encode([1_u8; 32]);
    let transport = Arc::new(MockTransport::with(vec![
        begin_response(),
        raw_response(200, br#"{"access_token":"leaked-handoff-access""#),
    ]));
    let client = client(Arc::clone(&transport));
    let login = client
        .begin_login("https://app.example/callback", None, None)
        .await
        .unwrap();
    let error = client
        .complete_login(
            &format!("https://app.example/callback?handoff=sensitive-handoff-ticket&state={state}"),
            login.pending,
        )
        .await
        .unwrap_err();

    assert_eq!(error.category(), ErrorCategory::Protocol);
    assert_eq!(error.retry_policy(), RetryPolicy::Never);
    assert_eq!(error.local_action(), LocalAction::QuarantinePendingLogin);
    assert_eq!(transport.request_count(), 2);
    let debug = format!("{error:?}");
    assert!(!debug.contains("sensitive-handoff-ticket"));
    assert!(!debug.contains("leaked-handoff-access"));
}

#[tokio::test]
async fn mismatched_handoff_success_quarantines_pending_without_retry_or_secret_disclosure() {
    let state = URL_SAFE_NO_PAD.encode([1_u8; 32]);
    let mut mismatched = credentials(1);
    mismatched["project_id"] = json!("another_project");
    mismatched["access_token"] = json!("leaked-handoff-access");
    mismatched["refresh_token"] = json!("leaked-handoff-refresh");
    let transport = Arc::new(MockTransport::with(vec![
        begin_response(),
        response(200, mismatched),
    ]));
    let client = client(Arc::clone(&transport));
    let login = client
        .begin_login("https://app.example/callback", None, None)
        .await
        .unwrap();
    let error = client
        .complete_login(
            &format!("https://app.example/callback?handoff=ticket&state={state}"),
            login.pending,
        )
        .await
        .unwrap_err();

    assert_eq!(error.category(), ErrorCategory::Protocol);
    assert_eq!(error.retry_policy(), RetryPolicy::Never);
    assert_eq!(error.local_action(), LocalAction::QuarantinePendingLogin);
    assert_eq!(transport.request_count(), 2);
    let debug = format!("{error:?}");
    assert!(!debug.contains("leaked-handoff-access"));
    assert!(!debug.contains("leaked-handoff-refresh"));
}

#[tokio::test]
async fn malformed_refresh_success_quarantines_without_retry_or_secret_disclosure() {
    let state = URL_SAFE_NO_PAD.encode([1_u8; 32]);
    let transport = Arc::new(MockTransport::with(vec![
        begin_response(),
        response(200, credentials(1)),
        raw_response(200, br#"{"refresh_token":"leaked-refresh-token""#),
    ]));
    let client = client(Arc::clone(&transport));
    let login = client
        .begin_login("https://app.example/callback", None, None)
        .await
        .unwrap();
    let pair = client
        .complete_login(
            &format!("https://app.example/callback?handoff=ticket&state={state}"),
            login.pending,
        )
        .await
        .unwrap();
    let error = client.refresh(&pair).await.unwrap_err();

    assert_eq!(error.category(), ErrorCategory::Protocol);
    assert_eq!(error.retry_policy(), RetryPolicy::Never);
    assert_eq!(error.local_action(), LocalAction::QuarantineCredentials);
    assert_eq!(transport.request_count(), 3);
    let debug = format!("{error:?}");
    assert!(!debug.contains("refresh-token-1"));
    assert!(!debug.contains("leaked-refresh-token"));
}

#[tokio::test]
async fn mismatched_refresh_success_quarantines_without_retry_or_secret_disclosure() {
    let state = URL_SAFE_NO_PAD.encode([1_u8; 32]);
    let mut mismatched = credentials(2);
    mismatched["session_id"] = json!("00000000-0000-0000-0000-000000000002");
    mismatched["access_token"] = json!("leaked-refresh-access");
    mismatched["refresh_token"] = json!("leaked-refresh-token");
    let transport = Arc::new(MockTransport::with(vec![
        begin_response(),
        response(200, credentials(1)),
        response(200, mismatched),
    ]));
    let client = client(Arc::clone(&transport));
    let login = client
        .begin_login("https://app.example/callback", None, None)
        .await
        .unwrap();
    let pair = client
        .complete_login(
            &format!("https://app.example/callback?handoff=ticket&state={state}"),
            login.pending,
        )
        .await
        .unwrap();
    let error = client.refresh(&pair).await.unwrap_err();

    assert_eq!(error.category(), ErrorCategory::Protocol);
    assert_eq!(error.retry_policy(), RetryPolicy::Never);
    assert_eq!(error.local_action(), LocalAction::QuarantineCredentials);
    assert_eq!(transport.request_count(), 3);
    let debug = format!("{error:?}");
    assert!(!debug.contains("refresh-token-1"));
    assert!(!debug.contains("leaked-refresh-access"));
    assert!(!debug.contains("leaked-refresh-token"));
}

#[tokio::test]
async fn post_dispatch_refresh_cancellation_quarantines_without_retry() {
    let state = URL_SAFE_NO_PAD.encode([1_u8; 32]);
    let transport = Arc::new(MockTransport::with(vec![
        begin_response(),
        response(200, credentials(1)),
        Err(TransportFailure::new(TransportFailureKind::Cancelled, true)),
    ]));
    let client = client(Arc::clone(&transport));
    let login = client
        .begin_login("https://app.example/callback", None, None)
        .await
        .unwrap();
    let pair = client
        .complete_login(
            &format!("https://app.example/callback?handoff=ticket&state={state}"),
            login.pending,
        )
        .await
        .unwrap();
    let error = client.refresh(&pair).await.unwrap_err();
    assert_eq!(error.category(), ErrorCategory::Indeterminate);
    assert_eq!(error.local_action(), LocalAction::QuarantineCredentials);
    assert_eq!(error.retry_policy(), RetryPolicy::Never);
    assert_eq!(transport.request_count(), 3);
}

#[tokio::test]
async fn unknown_runtime_error_is_conservative_and_safe() {
    let transport = Arc::new(MockTransport::with(vec![response(
        418,
        json!({
            "code": "future_runtime_code", "message": "do not trust raw provider detail", "request_id": "request-1"
        }),
    )]));
    let error = client(transport).public_configuration().await.unwrap_err();
    assert_eq!(error.category(), ErrorCategory::Protocol);
    assert_eq!(error.code(), "future_runtime_code");
    assert_eq!(error.retry_policy(), RetryPolicy::Never);
    assert!(!error.to_string().contains("provider detail"));
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConformanceCorpus {
    schema_version: u64,
    cases: Vec<ConformanceCase>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConformanceCase {
    name: String,
    fixture: String,
    required: bool,
    capability: String,
    operation: String,
    minimum_corpus_schema: u64,
    configured_context: Option<ConfiguredContext>,
    expected: ExpectedOutcome,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConfiguredContext {
    project_id: String,
    application_id: String,
    publishable_key: String,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExpectedOutcome {
    outcome: String,
    category: Option<String>,
    code: Option<String>,
    retry: Option<String>,
    action: Option<String>,
    project_id: Option<String>,
    application_id: Option<String>,
    provider_keys: Option<Vec<String>>,
    login_available: Option<bool>,
    user_id: Option<String>,
    refresh_generation: Option<i64>,
    projection_revision: Option<i64>,
    redacted: Option<bool>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FixtureEnvelope {
    schema_version: u64,
    synthetic: bool,
    response_status: u16,
    response: Value,
    #[serde(default)]
    redaction_sentinels: Vec<String>,
}

#[tokio::test]
async fn shared_conformance_corpus_executes_every_required_case() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../spec");
    let corpus_path = root.join("conformance/cases.json");
    let bytes = fs::read(&corpus_path).expect("conformance corpus");
    assert!(bytes.len() <= 1_048_576);
    let corpus: ConformanceCorpus = serde_json::from_slice(&bytes).expect("valid strict corpus");
    assert_eq!(corpus.schema_version, 2, "unsupported corpus schema");
    let fixture_root = root.join("fixtures").canonicalize().expect("fixture root");
    let credential_fixture: FixtureEnvelope =
        load_bounded_json(&fixture_root.join("credential-pair.json"));
    let mut names = BTreeSet::new();
    for case in corpus.cases {
        assert!(!case.name.is_empty() && names.insert(case.name.clone()));
        assert!(case.required, "optional cases must be declared separately");
        assert!(!case.capability.is_empty());
        assert!(case.minimum_corpus_schema <= corpus.schema_version);
        let referenced = corpus_path
            .parent()
            .unwrap()
            .join(&case.fixture)
            .canonicalize()
            .expect("fixture reference");
        assert!(referenced.starts_with(&fixture_root));
        let fixture: FixtureEnvelope = load_bounded_json(&referenced);
        assert_eq!(fixture.schema_version, 2);
        assert!(fixture.synthetic);
        execute_conformance_case(&case, &fixture, &credential_fixture).await;
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the strict shared-case dispatcher keeps each required observable assertion together"
)]
async fn execute_conformance_case(
    case: &ConformanceCase,
    fixture: &FixtureEnvelope,
    credential_fixture: &FixtureEnvelope,
) {
    let context = case
        .configured_context
        .clone()
        .unwrap_or(ConfiguredContext {
            project_id: "prj_conformance".into(),
            application_id: "app_conformance".into(),
            publishable_key: "owl_app_conformance".into(),
        });
    let fixture_result = response(fixture.response_status, fixture.response.clone());
    let credential_result = response(
        credential_fixture.response_status,
        credential_fixture.response.clone(),
    );
    let outcomes = match case.operation.as_str() {
        "public_configuration" => vec![fixture_result],
        "handoff" | "credential_response" => vec![begin_response(), fixture_result],
        "refresh" | "current_user" | "current_user_response" => {
            vec![begin_response(), credential_result, fixture_result]
        }
        other => panic!("unsupported required conformance operation: {other}"),
    };
    let transport = Arc::new(MockTransport::with(outcomes));
    let sdk = conformance_client(&context, Arc::clone(&transport));
    let state = URL_SAFE_NO_PAD.encode([1_u8; 32]);
    let result: Result<String, Error> = match case.operation.as_str() {
        "public_configuration" => sdk.public_configuration().await.map(|value| {
            assert_eq!(
                Some(value.project_public_id.as_str()),
                case.expected.project_id.as_deref()
            );
            assert_eq!(
                Some(value.application_public_id.as_str()),
                case.expected.application_id.as_deref()
            );
            assert_eq!(
                value
                    .providers
                    .iter()
                    .map(|provider| provider.key.clone())
                    .collect::<Vec<_>>(),
                case.expected.provider_keys.clone().unwrap_or_default()
            );
            assert_eq!(Some(value.login_available), case.expected.login_available);
            format!("{value:?}")
        }),
        "handoff" | "credential_response" => {
            let login = sdk
                .begin_login("https://app.example/callback", None, None)
                .await
                .unwrap();
            sdk.complete_login(
                &format!("https://app.example/callback?handoff=ticket&state={state}"),
                login.pending,
            )
            .await
            .map(|pair| {
                assert_eq!(Some(pair.project_id()), case.expected.project_id.as_deref());
                assert_eq!(
                    Some(pair.application_id()),
                    case.expected.application_id.as_deref()
                );
                assert_eq!(Some(pair.user_id()), case.expected.user_id.as_deref());
                assert_eq!(
                    Some(pair.refresh_generation()),
                    case.expected.refresh_generation
                );
                assert_eq!(
                    Some(pair.projection_revision()),
                    case.expected.projection_revision
                );
                format!("{pair:?}")
            })
        }
        "refresh" => {
            let pair = conformance_credentials(&sdk, &state).await;
            sdk.refresh(&pair).await.map(|value| format!("{value:?}"))
        }
        "current_user" | "current_user_response" => {
            let pair = conformance_credentials(&sdk, &state).await;
            sdk.current_user(pair.access_token()).await.map(|user| {
                assert_eq!(
                    Some(user.project_id.as_str()),
                    case.expected.project_id.as_deref()
                );
                assert_eq!(
                    Some(user.application_id.as_str()),
                    case.expected.application_id.as_deref()
                );
                assert_eq!(
                    Some(user.user_id.as_str()),
                    case.expected.user_id.as_deref()
                );
                assert_eq!(
                    Some(user.projection_revision),
                    case.expected.projection_revision
                );
                format!("{user:?}")
            })
        }
        _ => unreachable!(),
    };
    match (&case.expected.outcome[..], result) {
        ("success", Ok(debug)) => {
            if case.expected.redacted == Some(true) {
                assert!(debug.contains("[REDACTED]"));
            }
            assert_sentinels_absent(&debug, &fixture.redaction_sentinels);
        }
        ("error", Err(error)) => {
            assert_eq!(
                category_name(error.category()),
                case.expected.category.as_deref().unwrap()
            );
            assert_eq!(error.code(), case.expected.code.as_deref().unwrap());
            assert_eq!(
                retry_name(error.retry_policy()),
                case.expected.retry.as_deref().unwrap()
            );
            assert_eq!(
                action_name(error.local_action()),
                case.expected.action.as_deref().unwrap()
            );
            let diagnostics = format!("{error:?} {error}");
            assert_sentinels_absent(&diagnostics, &fixture.redaction_sentinels);
        }
        (expected, actual) => panic!("case {} expected {expected}, got {actual:?}", case.name),
    }
}

async fn conformance_credentials(sdk: &Client, state: &str) -> owlauth_client::CredentialPair {
    let login = sdk
        .begin_login("https://app.example/callback", None, None)
        .await
        .unwrap();
    sdk.complete_login(
        &format!("https://app.example/callback?handoff=ticket&state={state}"),
        login.pending,
    )
    .await
    .unwrap()
}

fn conformance_client(context: &ConfiguredContext, transport: Arc<MockTransport>) -> Client {
    Client::with_dependencies(
        ClientConfig::new(
            "https://runtime.example/base/",
            &context.project_id,
            &context.application_id,
            &context.publishable_key,
        ),
        transport,
        Arc::new(DeterministicEntropy::new()),
        Arc::new(FixedClock(0)),
    )
    .unwrap()
}

fn category_name(value: ErrorCategory) -> &'static str {
    match value {
        ErrorCategory::Configuration => "configuration",
        ErrorCategory::Protocol => "protocol",
        ErrorCategory::Login => "login",
        ErrorCategory::Handoff => "handoff",
        ErrorCategory::Authentication => "authentication",
        ErrorCategory::Session => "session",
        ErrorCategory::Refresh => "refresh",
        ErrorCategory::RateLimited => "rate_limited",
        ErrorCategory::Transport => "transport",
        ErrorCategory::Timeout => "timeout",
        ErrorCategory::Cancelled => "cancelled",
        ErrorCategory::Indeterminate => "indeterminate",
        _ => "unknown",
    }
}

fn retry_name(value: RetryPolicy) -> &'static str {
    match value {
        RetryPolicy::Never => "never",
        RetryPolicy::SafeAfterDelay => "safe_after_delay",
        RetryPolicy::ApplicationDecision => "application_decision",
        _ => "unknown",
    }
}

fn action_name(value: LocalAction) -> &'static str {
    match value {
        LocalAction::None => "none",
        LocalAction::DiscardPendingLogin => "discard_pending",
        LocalAction::QuarantinePendingLogin => "quarantine_pending",
        LocalAction::ClearCredentials => "invalidate_credentials",
        LocalAction::QuarantineCredentials => "quarantine_credentials",
        LocalAction::Reauthenticate => "reauthenticate",
        _ => "unknown",
    }
}

fn assert_sentinels_absent(value: &str, sentinels: &[String]) {
    for sentinel in sentinels {
        assert!(!value.contains(sentinel), "sentinel leaked");
    }
}

fn load_bounded_json<T: for<'de> Deserialize<'de>>(path: &Path) -> T {
    let bytes = fs::read(path).expect("fixture");
    assert!(bytes.len() <= 1_048_576);
    serde_json::from_slice(&bytes).expect("valid strict fixture JSON")
}

#[tokio::test]
async fn user_projection_requires_exact_schema_and_explicit_nullable_fields() {
    fn current_response(projection: &Value) -> Result<HttpResponse, TransportFailure> {
        response(
            200,
            json!({
                "project_id": "project_public",
                "application_id": "application_public",
                "user_id": "user_public",
                "projection": projection,
                "projection_revision": 1,
                "authenticated_at": "1970-01-01T00:00:00Z",
                "session_expires_at": "1970-01-30T00:00:00Z"
            }),
        )
    }

    let mut nullable = projection();
    nullable["locale"] = Value::Null;
    nullable["verified_email"] = Value::Null;
    let mut wrong_schema = projection();
    wrong_schema["projection_schema"] = json!("owlauth.project_user.v1");
    let mut missing_locale = projection();
    missing_locale.as_object_mut().unwrap().remove("locale");
    let mut unknown_field = projection();
    unknown_field["unexpected"] = json!(true);

    let fixture: Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../spec/fixtures/user-projection-invalid-values.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let mut cases = vec![
        (nullable, true),
        (wrong_schema, false),
        (missing_locale, false),
        (unknown_field, false),
    ];
    for patch in fixture["invalidPatches"].as_array().unwrap() {
        let mut invalid = fixture["projection"].clone();
        let field = patch["field"].as_str().unwrap();
        invalid[field] = patch["value"].clone();
        cases.push((invalid, false));
    }

    for (wire_projection, should_accept) in cases {
        let state = URL_SAFE_NO_PAD.encode([1_u8; 32]);
        let transport = Arc::new(MockTransport::with(vec![
            begin_response(),
            response(200, credentials(1)),
            current_response(&wire_projection),
        ]));
        let client = client(transport);
        let login = client
            .begin_login("https://app.example/callback", None, None)
            .await
            .unwrap();
        let pair = client
            .complete_login(
                &format!("https://app.example/callback?handoff=ticket&state={state}"),
                login.pending,
            )
            .await
            .unwrap();
        let result = client.current_user(pair.access_token()).await;
        assert_eq!(result.is_ok(), should_accept);
        if let Ok(accepted) = result {
            assert!(accepted.projection.locale.is_none());
            assert!(accepted.projection.verified_email.is_none());
        }
    }
}
