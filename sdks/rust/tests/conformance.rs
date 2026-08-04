use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicI64, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use base64::Engine;
use owlauth_client::{
    Client, ClientConfig, Clock, EntropySource, Error, ErrorCategory, HttpMethod, HttpRequest,
    HttpResponse, LocalAction, RetryPolicy, Transport, TransportFailure, TransportFailureKind,
};
use serde::Deserialize;
use serde_json::Value;

const SCHEMA_VERSION: u64 = 3;
const NOW: i64 = 4_070_908_800;
const BASE_URL: &str = "https://runtime.conformance.example/";
const REDIRECT: &str = "https://application.example/callback";
const STATE: &str = "state_conformance";

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

    fn last_request(&self) -> Option<HttpRequest> {
        self.requests.lock().unwrap().last().cloned()
    }

    fn request_count(&self) -> usize {
        self.requests.lock().unwrap().len()
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
            .expect("fixture outcome")
    }
}

struct DeterministicEntropy;
impl EntropySource for DeterministicEntropy {
    fn fill(&self, destination: &mut [u8]) -> Result<(), Error> {
        destination.fill(7);
        Ok(())
    }
}

struct MutableClock(AtomicI64);
impl MutableClock {
    fn new() -> Self {
        Self(AtomicI64::new(NOW))
    }

    fn set_offset(&self, offset: i64) {
        self.0.store(NOW.saturating_add(offset), Ordering::Relaxed);
    }
}
impl Clock for MutableClock {
    fn now_unix_seconds(&self) -> i64 {
        self.0.load(Ordering::Relaxed)
    }
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Corpus {
    schema_version: u64,
    required_case_names: Vec<String>,
    cases: Vec<Case>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Case {
    name: String,
    required: bool,
    capability: String,
    operation_id: String,
    fixture: String,
    precondition: String,
    request_phase: String,
    response_received: bool,
    evidence_level: String,
    configured_context: ConfiguredContext,
    expected: Expected,
    #[serde(default)]
    platform_capability: Option<String>,
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
struct Expected {
    outcome: String,
    pending_disposition: String,
    credential_disposition: String,
    #[serde(default)]
    values: Option<Value>,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    retry: Option<String>,
    #[serde(default)]
    action: Option<String>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Fixture {
    schema_version: u64,
    synthetic: bool,
    exchange: Exchange,
    #[serde(default)]
    redaction_sentinels: Vec<String>,
}

#[derive(Clone, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum Exchange {
    #[serde(rename = "http")]
    Http {
        status: u16,
        headers: BTreeMap<String, String>,
        body: Body,
        #[serde(default)]
        request: Option<RequestAssertion>,
    },
    #[serde(rename = "callback")]
    Callback {
        attempts: Vec<String>,
        #[serde(rename = "clockOffsetSeconds")]
        clock_offset_seconds: i64,
    },
    #[serde(rename = "transportFailure")]
    TransportFailure {
        #[serde(rename = "failureKind")]
        failure_kind: String,
        #[serde(rename = "requestPhase")]
        request_phase: String,
    },
}

#[derive(Clone, Deserialize)]
#[serde(tag = "encoding", deny_unknown_fields)]
enum Body {
    #[serde(rename = "json")]
    Json { value: Value },
    #[serde(rename = "text")]
    Text { value: String },
    #[serde(rename = "empty")]
    Empty,
    #[serde(rename = "base64")]
    Base64 { value: String },
    #[serde(rename = "repeat")]
    Repeat { value: String, count: usize },
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestAssertion {
    method: String,
    body: String,
}

struct Setup {
    login: Fixture,
    credential: Fixture,
}

#[derive(Debug)]
struct Execution {
    diagnostics: String,
    pending_consumed: Option<bool>,
}

fn load_fixture(path: &Path) -> Fixture {
    let bytes = fs::read(path).expect("fixture");
    assert!(bytes.len() <= 1_048_576);
    let fixture: Fixture = serde_json::from_slice(&bytes).expect("strict fixture");
    validate_fixture(&fixture);
    fixture
}

fn validate_fixture(fixture: &Fixture) {
    assert_eq!(fixture.schema_version, SCHEMA_VERSION);
    assert!(fixture.synthetic);
    assert!(
        fixture
            .redaction_sentinels
            .iter()
            .all(|value| !value.is_empty() && value.len() <= 256)
    );
    match &fixture.exchange {
        Exchange::Http {
            status,
            headers,
            body,
            request,
        } => {
            assert!((100..=599).contains(status));
            assert!(headers.iter().all(|(name, value)| {
                !name.is_empty() && name.len() <= 128 && value.len() <= 512
            }));
            match body {
                Body::Text { value } => assert!(!value.is_empty() && value.len() <= 65_536),
                Body::Base64 { value } => assert!(
                    !value.is_empty()
                        && value.len() <= 87_384
                        && base64::engine::general_purpose::STANDARD
                            .decode(value)
                            .is_ok_and(|body| body.len() <= 65_536)
                ),
                Body::Repeat { value, count } => {
                    assert_eq!(value.len(), 1);
                    assert!(*count <= 65_537);
                }
                Body::Json { .. } | Body::Empty => {}
            }
            if let Some(assertion) = request {
                assert!(matches!(assertion.method.as_str(), "GET" | "POST"));
                assert!(matches!(assertion.body.as_str(), "absent" | "json"));
            }
        }
        Exchange::Callback {
            attempts,
            clock_offset_seconds,
        } => {
            assert!(!attempts.is_empty());
            assert!(attempts.iter().all(|value| matches!(
                value.as_str(),
                "success" | "error" | "ambiguous" | "state_mismatch"
            )));
            assert!((0..=86_400).contains(clock_offset_seconds));
        }
        Exchange::TransportFailure {
            failure_kind,
            request_phase,
        } => {
            assert!(matches!(
                failure_kind.as_str(),
                "transport" | "timeout" | "cancelled"
            ));
            assert!(matches!(
                request_phase.as_str(),
                "before_dispatch" | "possibly_dispatched"
            ));
        }
    }
}

fn validate_case(case: &Case, names: &mut BTreeSet<String>) {
    assert!(!case.name.is_empty() && case.name.len() <= 128 && names.insert(case.name.clone()));
    assert!(case.required);
    assert!(!case.capability.is_empty() && case.capability.len() <= 64);
    assert!(!case.fixture.is_empty() && case.fixture.len() <= 256);
    assert!(matches!(
        case.operation_id.as_str(),
        "get_public_application_config"
            | "get_project_jwks"
            | "start_login"
            | "exchange_handoff"
            | "refresh_session"
            | "get_current_user"
            | "logout_application_session"
            | "prepare_browser_logout"
    ));
    assert!(matches!(
        case.precondition.as_str(),
        "none" | "pending_login" | "credential_pair"
    ));
    assert!(matches!(
        case.request_phase.as_str(),
        "before_dispatch" | "possibly_dispatched" | "response_received"
    ));
    assert_eq!(
        case.response_received,
        case.request_phase == "response_received"
    );
    assert_eq!(case.evidence_level, "deterministic");
    assert!(
        !case.configured_context.project_id.is_empty()
            && case.configured_context.project_id.len() <= 128
    );
    assert!(
        !case.configured_context.application_id.is_empty()
            && case.configured_context.application_id.len() <= 128
    );
    assert!(
        !case.configured_context.publishable_key.is_empty()
            && case.configured_context.publishable_key.len() <= 128
    );
    if let Some(capability) = &case.platform_capability {
        assert!(!capability.is_empty() && capability.len() <= 64);
    }
    validate_expected(&case.expected);
}

fn validate_expected(expected: &Expected) {
    assert!(matches!(expected.outcome.as_str(), "success" | "error"));
    assert!(matches!(
        expected.pending_disposition.as_str(),
        "not_applicable" | "preserved" | "discard_required" | "quarantined" | "consumed"
    ));
    assert!(matches!(
        expected.credential_disposition.as_str(),
        "not_applicable"
            | "preserved"
            | "replaced"
            | "cleared"
            | "invalidated"
            | "quarantined"
            | "reauthentication_required"
    ));
    if expected.outcome == "success" {
        assert!(expected.category.is_none());
        assert!(expected.code.is_none());
        assert!(expected.retry.is_none());
        assert!(expected.action.is_none());
        return;
    }
    assert!(expected.values.is_none());
    for value in [
        &expected.category,
        &expected.code,
        &expected.retry,
        &expected.action,
    ] {
        assert!(
            value
                .as_ref()
                .is_some_and(|item| !item.is_empty() && item.len() <= 64)
        );
    }
    let action = expected.action.as_deref().unwrap();
    match expected.pending_disposition.as_str() {
        "discard_required" => assert_eq!(action, "discard_pending"),
        "quarantined" => assert_eq!(action, "quarantine_pending"),
        _ => {}
    }
    match expected.credential_disposition.as_str() {
        "invalidated" => assert_eq!(action, "invalidate_credentials"),
        "quarantined" => assert_eq!(action, "quarantine_credentials"),
        "reauthentication_required" => assert_eq!(action, "reauthenticate"),
        "preserved" => assert_eq!(action, "none"),
        _ => {}
    }
}

fn http_response(fixture: &Fixture) -> HttpResponse {
    let Exchange::Http {
        status,
        headers,
        body,
        ..
    } = &fixture.exchange
    else {
        panic!("HTTP fixture")
    };
    let body = match body {
        Body::Json { value } => serde_json::to_vec(value).unwrap(),
        Body::Text { value } => value.as_bytes().to_vec(),
        Body::Empty => Vec::new(),
        Body::Base64 { value } => base64::engine::general_purpose::STANDARD
            .decode(value)
            .unwrap(),
        Body::Repeat { value, count } => value.as_bytes().repeat(*count),
    };
    HttpResponse {
        status: *status,
        headers: headers
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect(),
        body,
    }
}

fn transport_failure(fixture: &Fixture) -> Result<HttpResponse, TransportFailure> {
    let Exchange::TransportFailure {
        failure_kind,
        request_phase,
    } = &fixture.exchange
    else {
        panic!("transport fixture")
    };
    let kind = match failure_kind.as_str() {
        "timeout" => TransportFailureKind::Timeout,
        "cancelled" => TransportFailureKind::Cancelled,
        _ => TransportFailureKind::Transport,
    };
    Err(TransportFailure::new(
        kind,
        request_phase == "possibly_dispatched",
    ))
}

fn client_for(
    context: &ConfiguredContext,
    transport: Arc<MockTransport>,
    clock: Arc<MutableClock>,
) -> Client {
    Client::with_dependencies(
        ClientConfig::new(
            BASE_URL,
            &context.project_id,
            &context.application_id,
            &context.publishable_key,
        ),
        transport,
        Arc::new(DeterministicEntropy),
        clock,
    )
    .unwrap()
}

fn callback_url(kind: &str) -> String {
    match kind {
        "success" => format!("{REDIRECT}?handoff=synthetic-handoff&state={STATE}"),
        "error" => format!("{REDIRECT}?error=provider_rejected&state={STATE}"),
        "ambiguous" => {
            format!("{REDIRECT}?handoff=synthetic-handoff&error=provider_rejected&state={STATE}")
        }
        _ => format!("{REDIRECT}?handoff=synthetic-handoff&state=wrong"),
    }
}

async fn setup_credentials(client: &Client) -> Result<owlauth_client::CredentialPair, Error> {
    let login = client.begin_login(REDIRECT, Some(STATE), None).await?;
    client
        .complete_login(&callback_url("success"), login.pending)
        .await
}

fn success_values(case: &Case) -> &serde_json::Map<String, Value> {
    case.expected
        .values
        .as_ref()
        .and_then(Value::as_object)
        .expect("success values")
}

async fn execute_http(
    case: &Case,
    fixture: &Fixture,
    setup: &Setup,
) -> (Result<Execution, Error>, Arc<MockTransport>) {
    let mut outcomes = Vec::new();
    if case.precondition == "pending_login" {
        outcomes.push(Ok(http_response(&setup.login)));
    } else if case.precondition == "credential_pair" {
        outcomes.push(Ok(http_response(&setup.login)));
        outcomes.push(Ok(http_response(&setup.credential)));
    }
    outcomes.push(Ok(http_response(fixture)));
    let transport = Arc::new(MockTransport::with(outcomes));
    let clock = Arc::new(MutableClock::new());
    let client = client_for(&case.configured_context, Arc::clone(&transport), clock);
    let result = async {
        let diagnostics = match case.operation_id.as_str() {
            "get_public_application_config" => {
                let value = client.public_configuration().await?;
                let expected = success_values(case);
                assert_eq!(
                    expected.get("projectId").and_then(Value::as_str),
                    Some(value.project_public_id.as_str())
                );
                assert_eq!(
                    expected.get("applicationId").and_then(Value::as_str),
                    Some(value.application_public_id.as_str())
                );
                format!("{value:?}")
            }
            "get_project_jwks" => {
                let value = client.project_jwks().await?;
                let expected = success_values(case);
                assert_eq!(
                    expected.get("revision").and_then(Value::as_i64),
                    Some(value.revision)
                );
                assert_eq!(
                    expected.get("signingEpoch").and_then(Value::as_i64),
                    Some(value.signing_epoch)
                );
                format!("{value:?}")
            }
            "start_login" => {
                let value = client.begin_login(REDIRECT, Some(STATE), None).await?;
                format!("{value:?}")
            }
            "exchange_handoff" => {
                let login = client.begin_login(REDIRECT, Some(STATE), None).await?;
                let value = client
                    .complete_login(&callback_url("success"), login.pending)
                    .await?;
                format!("{value:?}")
            }
            "refresh_session" => {
                let credentials = setup_credentials(&client).await?;
                let value = client.refresh(&credentials).await?;
                format!("{value:?}")
            }
            "get_current_user" => {
                let credentials = setup_credentials(&client).await?;
                let value = client.current_user(credentials.access_token()).await?;
                let expected = success_values(case);
                assert_eq!(
                    expected.get("userId").and_then(Value::as_str),
                    Some(value.user_id.as_str())
                );
                format!("{value:?}")
            }
            "logout_application_session" => {
                let credentials = setup_credentials(&client).await?;
                client
                    .logout_application(credentials.access_token())
                    .await?;
                "logout completed".to_owned()
            }
            "prepare_browser_logout" => {
                let credentials = setup_credentials(&client).await?;
                let value = client
                    .prepare_browser_logout(credentials.access_token())
                    .await?;
                format!("{value:?}")
            }
            other => panic!("unsupported operation {other}"),
        };
        Ok(Execution {
            diagnostics,
            pending_consumed: None,
        })
    }
    .await;
    (result, transport)
}

async fn execute_callback(
    case: &Case,
    fixture: &Fixture,
    setup: &Setup,
) -> (Result<Execution, Error>, Arc<MockTransport>) {
    let Exchange::Callback {
        attempts,
        clock_offset_seconds,
    } = &fixture.exchange
    else {
        panic!("callback fixture")
    };
    let transport = Arc::new(MockTransport::with(vec![Ok(http_response(&setup.login))]));
    let clock = Arc::new(MutableClock::new());
    let client = client_for(
        &case.configured_context,
        Arc::clone(&transport),
        Arc::clone(&clock),
    );
    let result = async {
        let pending = client
            .begin_login(REDIRECT, Some(STATE), None)
            .await?
            .pending;
        clock.set_offset(*clock_offset_seconds);
        let mut diagnostics = String::new();
        for (index, attempt) in attempts.iter().enumerate() {
            match client.validate_callback(&callback_url(attempt), &pending) {
                Ok(value) => diagnostics = format!("{value:?}"),
                Err(error) if index + 1 != attempts.len() => {
                    diagnostics = format!("{error:?}");
                }
                Err(error) => return Err(error),
            }
        }
        Ok(Execution {
            diagnostics,
            pending_consumed: Some(pending.consumed()),
        })
    }
    .await;
    (result, transport)
}

async fn execute_transport(
    case: &Case,
    fixture: &Fixture,
    setup: &Setup,
) -> (Result<Execution, Error>, Arc<MockTransport>) {
    let mut outcomes = Vec::new();
    if case.precondition == "pending_login" {
        outcomes.push(Ok(http_response(&setup.login)));
    } else if case.precondition == "credential_pair" {
        outcomes.push(Ok(http_response(&setup.login)));
        outcomes.push(Ok(http_response(&setup.credential)));
    }
    outcomes.push(transport_failure(fixture));
    let transport = Arc::new(MockTransport::with(outcomes));
    let clock = Arc::new(MutableClock::new());
    let client = client_for(&case.configured_context, Arc::clone(&transport), clock);
    let result = async {
        let diagnostics = match case.operation_id.as_str() {
            "get_public_application_config" => {
                format!("{:?}", client.public_configuration().await?)
            }
            "exchange_handoff" => {
                let login = client.begin_login(REDIRECT, Some(STATE), None).await?;
                format!(
                    "{:?}",
                    client
                        .complete_login(&callback_url("success"), login.pending)
                        .await?
                )
            }
            "refresh_session" => {
                let credentials = setup_credentials(&client).await?;
                format!("{:?}", client.refresh(&credentials).await?)
            }
            other => panic!("unsupported transport operation {other}"),
        };
        Ok(Execution {
            diagnostics,
            pending_consumed: None,
        })
    }
    .await;
    (result, transport)
}

async fn assert_pending_disposition(case: &Case, fixture: &Fixture, setup: &Setup) {
    if case.operation_id == "start_login" {
        let transport = Arc::new(MockTransport::with(vec![Ok(http_response(fixture))]));
        let client = client_for(
            &case.configured_context,
            Arc::clone(&transport),
            Arc::new(MutableClock::new()),
        );
        let login = client
            .begin_login(REDIRECT, Some(STATE), None)
            .await
            .unwrap();
        assert!(!login.pending.consumed(), "{}", case.name);
        assert_eq!(transport.request_count(), 1, "{}", case.name);
        return;
    }
    if case.precondition != "pending_login" {
        return;
    }

    let mut outcomes = vec![Ok(http_response(&setup.login))];
    match &fixture.exchange {
        Exchange::Http { .. } => outcomes.push(Ok(http_response(fixture))),
        Exchange::TransportFailure { .. } => outcomes.push(transport_failure(fixture)),
        Exchange::Callback { .. } => {}
    }
    let transport = Arc::new(MockTransport::with(outcomes));
    let clock = Arc::new(MutableClock::new());
    let client = client_for(
        &case.configured_context,
        Arc::clone(&transport),
        Arc::clone(&clock),
    );
    let pending = client
        .begin_login(REDIRECT, Some(STATE), None)
        .await
        .unwrap()
        .pending;
    if let Exchange::Callback {
        attempts,
        clock_offset_seconds,
    } = &fixture.exchange
    {
        clock.set_offset(*clock_offset_seconds);
        for attempt in attempts {
            let _ = client.validate_callback(&callback_url(attempt), &pending);
        }
        assert!(matches!(
            case.expected.pending_disposition.as_str(),
            "preserved" | "discard_required"
        ));
        assert!(!pending.consumed(), "{}", case.name);
        assert_eq!(transport.request_count(), 1, "{}", case.name);
        return;
    }

    assert!(matches!(
        case.expected.pending_disposition.as_str(),
        "discard_required" | "quarantined"
    ));
    let first = client
        .validate_callback(&callback_url("success"), &pending)
        .unwrap();
    let replay = client
        .validate_callback(&callback_url("success"), &pending)
        .unwrap();
    let _ = client.exchange_handoff(first).await;
    assert!(pending.consumed(), "{}", case.name);
    let request_count = transport.request_count();
    let replay_error = client.exchange_handoff(replay).await.unwrap_err();
    assert_eq!(replay_error.code(), "pending_consumed", "{}", case.name);
    assert_eq!(transport.request_count(), request_count, "{}", case.name);
    assert_eq!(request_count, 2, "{}", case.name);
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

fn validate_fixture_phase(case: &Case, fixture: &Fixture) {
    match &fixture.exchange {
        Exchange::Http { .. } => {
            assert_eq!(case.request_phase, "response_received");
            assert!(case.response_received);
        }
        Exchange::Callback { .. } => {
            assert_eq!(case.request_phase, "before_dispatch");
            assert!(!case.response_received);
        }
        Exchange::TransportFailure { request_phase, .. } => {
            assert_eq!(&case.request_phase, request_phase);
            assert!(!case.response_received);
        }
    }
}

fn assert_execution(
    case: &Case,
    fixture: &Fixture,
    result: Result<Execution, Error>,
    transport: &MockTransport,
) {
    match (case.expected.outcome.as_str(), result) {
        ("success", Ok(execution)) => {
            for sentinel in &fixture.redaction_sentinels {
                assert!(!execution.diagnostics.contains(sentinel), "{}", case.name);
            }
            if case.expected.pending_disposition == "preserved"
                && let Some(consumed) = execution.pending_consumed
            {
                assert!(!consumed, "{}", case.name);
            }
            if let Exchange::Http {
                request: Some(assertion),
                ..
            } = &fixture.exchange
            {
                let request = transport.last_request().expect("request");
                let method = if assertion.method == "POST" {
                    HttpMethod::Post
                } else {
                    HttpMethod::Get
                };
                assert_eq!(request.method, method, "{}", case.name);
                assert_eq!(
                    request.body.is_none(),
                    assertion.body == "absent",
                    "{}",
                    case.name
                );
            }
        }
        ("error", Err(error)) => {
            assert_eq!(
                category_name(error.category()),
                case.expected.category.as_deref().unwrap(),
                "{}",
                case.name
            );
            assert_eq!(
                error.code(),
                case.expected.code.as_deref().unwrap(),
                "{}",
                case.name
            );
            assert_eq!(error.operation(), case.operation_id, "{}", case.name);
            assert_eq!(
                retry_name(error.retry_policy()),
                case.expected.retry.as_deref().unwrap(),
                "{}",
                case.name
            );
            assert_eq!(
                action_name(error.local_action()),
                case.expected.action.as_deref().unwrap(),
                "{}",
                case.name
            );
            let diagnostics = format!("{error:?} {error}");
            for sentinel in &fixture.redaction_sentinels {
                assert!(!diagnostics.contains(sentinel), "{}", case.name);
            }
        }
        (expected, actual) => panic!("{} expected {expected}, got {actual:?}", case.name),
    }
}

#[tokio::test]
async fn every_required_schema_v3_case_executes_through_the_public_sdk() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../spec");
    let corpus_path = root.join("conformance/cases.json");
    let corpus_bytes = fs::read(&corpus_path).expect("corpus");
    assert!(corpus_bytes.len() <= 1_048_576);
    let corpus: Corpus = serde_json::from_slice(&corpus_bytes).expect("strict corpus");
    assert_eq!(corpus.schema_version, SCHEMA_VERSION);
    assert!(!corpus.required_case_names.is_empty());
    assert!(
        corpus
            .required_case_names
            .iter()
            .all(|name| !name.is_empty() && name.len() <= 128)
    );
    assert_eq!(
        corpus
            .required_case_names
            .iter()
            .collect::<BTreeSet<_>>()
            .len(),
        corpus.required_case_names.len()
    );
    assert!(!corpus.cases.is_empty());
    let fixture_root = root.join("fixtures").canonicalize().expect("fixture root");
    let setup = Setup {
        login: load_fixture(&fixture_root.join("login-start.json")),
        credential: load_fixture(&fixture_root.join("credential-pair.json")),
    };
    let mut names = BTreeSet::new();
    for case in corpus.cases {
        validate_case(&case, &mut names);
        let fixture_path = corpus_path
            .parent()
            .unwrap()
            .join(&case.fixture)
            .canonicalize()
            .expect("fixture reference");
        assert!(fixture_path.starts_with(&fixture_root));
        let fixture = load_fixture(&fixture_path);
        validate_fixture_phase(&case, &fixture);
        assert_pending_disposition(&case, &fixture, &setup).await;
        let (result, transport) = match &fixture.exchange {
            Exchange::Http { .. } => execute_http(&case, &fixture, &setup).await,
            Exchange::Callback { .. } => execute_callback(&case, &fixture, &setup).await,
            Exchange::TransportFailure { .. } => execute_transport(&case, &fixture, &setup).await,
        };
        assert_execution(&case, &fixture, result, &transport);
    }
    assert_eq!(names.len(), corpus.required_case_names.len());
    assert_eq!(
        names,
        corpus
            .required_case_names
            .into_iter()
            .collect::<BTreeSet<_>>()
    );
}

type Mutation = Box<dyn Fn(&mut Value)>;

#[test]
fn schema_v3_deserialization_rejects_unknown_missing_and_unsupported_shape() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../spec");
    let original: Value =
        serde_json::from_slice(&fs::read(root.join("conformance/cases.json")).expect("corpus"))
            .unwrap();
    let mutations: Vec<Mutation> = vec![
        Box::new(|value| value["schemaVersion"] = Value::from(99)),
        Box::new(|value| value["cases"][0]["unknownRequiredField"] = Value::Bool(true)),
        Box::new(|value| {
            value["cases"][0]
                .as_object_mut()
                .unwrap()
                .remove("operationId");
        }),
        Box::new(|value| value["cases"][0]["operationId"] = Value::from("future_operation")),
        Box::new(|value| {
            value["cases"].as_array_mut().unwrap().pop();
        }),
    ];
    for mutation in mutations {
        let mut value = original.clone();
        mutation(&mut value);
        let parsed = serde_json::from_value::<Corpus>(value);
        if let Ok(corpus) = parsed {
            if corpus.schema_version != SCHEMA_VERSION {
                continue;
            }
            let mut names = BTreeSet::new();
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    for case in &corpus.cases {
                        validate_case(case, &mut names);
                    }
                    assert_eq!(names.len(), corpus.required_case_names.len());
                    assert_eq!(
                        names,
                        corpus
                            .required_case_names
                            .iter()
                            .cloned()
                            .collect::<BTreeSet<_>>()
                    );
                }))
                .is_err()
            );
        }
    }
}
