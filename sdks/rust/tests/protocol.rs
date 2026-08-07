use std::{
    collections::VecDeque,
    future::pending,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use owlauth_client::{
    CancellationToken, Client, ClientConfig, Clock, CredentialPairRecord, EntropySource, Error,
    ErrorCategory, HttpRequest, HttpResponse, LocalAction, OperationOptions, PendingLoginRecord,
    RetryPolicy, Transport, TransportFailure, TransportFailureKind,
};
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

#[derive(Default)]
struct BlockingTransport {
    outcomes: Mutex<VecDeque<Result<HttpResponse, TransportFailure>>>,
    requests: Mutex<Vec<HttpRequest>>,
    entered_block: tokio::sync::Notify,
}

impl BlockingTransport {
    fn with_prefix(outcomes: Vec<Result<HttpResponse, TransportFailure>>) -> Self {
        Self {
            outcomes: Mutex::new(outcomes.into()),
            ..Self::default()
        }
    }

    fn request_count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
}

#[async_trait]
impl Transport for BlockingTransport {
    async fn send(
        &self,
        request: HttpRequest,
        _deadline: Duration,
    ) -> Result<HttpResponse, TransportFailure> {
        self.requests.lock().unwrap().push(request);
        let outcome = self.outcomes.lock().unwrap().pop_front();
        if let Some(outcome) = outcome {
            return outcome;
        }
        self.entered_block.notify_one();
        pending().await
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
        headers: vec![("content-type".into(), "application/json".into())],
        body: serde_json::to_vec(&body).unwrap(),
    })
}

#[allow(clippy::unnecessary_wraps)]
fn raw_response(status: u16, body: &[u8]) -> Result<HttpResponse, TransportFailure> {
    Ok(HttpResponse {
        status,
        headers: vec![("content-type".into(), "application/json".into())],
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

fn client_with_transport(transport: Arc<dyn Transport>) -> Client {
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

fn client(transport: Arc<MockTransport>) -> Client {
    client_with_transport(transport)
}

#[test]
fn url_policy_preserves_prefix_and_requires_explicit_loopback() {
    let transport = Arc::new(MockTransport::default());
    let configured = client(transport);
    assert_eq!(configured.base_url(), "https://runtime.example/base/");

    for base_url in [
        "https://runtime.example/runtime\\control",
        "https://runtime.example/runtime/%2f/control",
        "https://runtime.example/runtime/%5c/control",
        "https://runtime.example/runtime/../control",
        "https://runtime.example/runtime/%2e%2e/control",
        "https://runtime.example/runtime/%252e%252e/control",
    ] {
        let config = ClientConfig::new(base_url, "project", "application", "key");
        assert!(
            Client::with_dependencies(
                config,
                Arc::new(MockTransport::default()),
                Arc::new(DeterministicEntropy::new()),
                Arc::new(FixedClock(0)),
            )
            .is_err(),
            "ambiguous Runtime path must fail: {base_url}"
        );
    }

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
async fn unicode_state_and_pending_records_round_trip_without_io() {
    let transport = Arc::new(MockTransport::with(vec![begin_response()]));
    let client = client(Arc::clone(&transport));
    let state = "return=東京/资料";
    let login = client
        .begin_login("https://app.example/callback", Some(state), None)
        .await
        .unwrap();
    assert_eq!(transport.bodies()[0]["state"], state);

    let record = login.pending.export_record().unwrap();
    let mut encoded = serde_json::to_value(&record).unwrap();
    assert_eq!(transport.request_count(), 1);
    let decoded: PendingLoginRecord = serde_json::from_value(encoded.clone()).unwrap();
    assert_eq!(decoded, record);
    let restored = client.restore_pending_login(decoded).unwrap();
    assert_eq!(transport.request_count(), 1);

    let mut callback = url::Url::parse("https://app.example/callback").unwrap();
    callback
        .query_pairs_mut()
        .append_pair("handoff", "ticket")
        .append_pair("state", state);
    client
        .validate_callback(callback.as_str(), &restored)
        .unwrap();

    encoded["unexpected"] = json!(true);
    assert!(serde_json::from_value::<PendingLoginRecord>(encoded).is_err());

    let mut future = serde_json::to_value(record).unwrap();
    future["created_at"] = json!(10_000);
    future["expires_at"] = json!(10_600);
    let future: PendingLoginRecord = serde_json::from_value(future).unwrap();
    assert!(client.restore_pending_login(future).is_err());
    assert_eq!(transport.request_count(), 1);
}

#[tokio::test]
async fn credential_records_are_closed_context_bound_and_restore_without_io() {
    let state = URL_SAFE_NO_PAD.encode([1_u8; 32]);
    let transport = Arc::new(MockTransport::with(vec![
        begin_response(),
        response(200, credentials(1)),
    ]));
    let client = client(Arc::clone(&transport));
    let login = client
        .begin_login("https://app.example/callback", None, None)
        .await
        .unwrap();
    let pair = client
        .complete_login(
            &format!("https://app.example/callback?handoff=ticket&state={state}"),
            &login.pending,
        )
        .await
        .unwrap();
    let record = pair.export_record();
    let encoded = serde_json::to_value(&record).unwrap();
    let decoded: CredentialPairRecord = serde_json::from_value(encoded.clone()).unwrap();
    assert_eq!(decoded, record);
    let restored = client.restore_credentials(decoded).unwrap();
    assert_eq!(restored.access_token().expose(), "access-token-1");
    assert_eq!(restored.refresh_token().expose(), "refresh-token-1");
    assert_eq!(transport.request_count(), 2);

    let mut additive = encoded.clone();
    additive["unexpected"] = json!(true);
    assert!(serde_json::from_value::<CredentialPairRecord>(additive).is_err());

    let other = Client::with_dependencies(
        ClientConfig::new(
            "https://runtime.example/base/",
            "project_public",
            "another_application",
            "publishable_key",
        ),
        transport.clone(),
        Arc::new(DeterministicEntropy::new()),
        Arc::new(FixedClock(0)),
    )
    .unwrap();
    let cross_context: CredentialPairRecord = serde_json::from_value(encoded).unwrap();
    assert!(other.restore_credentials(cross_context).is_err());
    assert_eq!(transport.request_count(), 2);
}

#[tokio::test]
async fn cancellation_before_sensitive_dispatch_preserves_pending_state() {
    let state = URL_SAFE_NO_PAD.encode([1_u8; 32]);
    let transport = Arc::new(MockTransport::with(vec![begin_response()]));
    let client = client(Arc::clone(&transport));
    let login = client
        .begin_login("https://app.example/callback", None, None)
        .await
        .unwrap();
    let callback = client
        .validate_callback(
            &format!("https://app.example/callback?handoff=ticket&state={state}"),
            &login.pending,
        )
        .unwrap();
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let error = client
        .exchange_handoff_with_options(
            &callback,
            &OperationOptions::with_cancellation(cancellation),
        )
        .await
        .unwrap_err();
    assert_eq!(error.category(), ErrorCategory::Cancelled);
    assert_eq!(error.local_action(), LocalAction::None);
    assert!(login.pending.available());
    assert!(login.pending.export_record().is_ok());
    assert_eq!(transport.request_count(), 1);
}

#[tokio::test]
async fn cancellation_after_sensitive_dispatch_is_indeterminate_and_consumes_pending() {
    let state = URL_SAFE_NO_PAD.encode([1_u8; 32]);
    let transport = Arc::new(BlockingTransport::with_prefix(vec![begin_response()]));
    let client = client_with_transport(transport.clone());
    let login = client
        .begin_login("https://app.example/callback", None, None)
        .await
        .unwrap();
    let callback = client
        .validate_callback(
            &format!("https://app.example/callback?handoff=ticket&state={state}"),
            &login.pending,
        )
        .unwrap();
    let cancellation = CancellationToken::new();
    let cancellation_for_task = cancellation.clone();
    let transport_for_task = Arc::clone(&transport);
    let canceller = tokio::spawn(async move {
        transport_for_task.entered_block.notified().await;
        cancellation_for_task.cancel();
    });
    let error = client
        .exchange_handoff_with_options(
            &callback,
            &OperationOptions::with_cancellation(cancellation),
        )
        .await
        .unwrap_err();
    canceller.await.unwrap();
    assert_eq!(error.category(), ErrorCategory::Indeterminate);
    assert_eq!(error.local_action(), LocalAction::QuarantinePendingLogin);
    assert_eq!(error.retry_policy(), RetryPolicy::Never);
    assert!(login.pending.consumed());
    assert!(login.pending.export_record().is_err());
    assert_eq!(transport.request_count(), 2);
}

#[tokio::test]
async fn callback_mismatch_dispatches_nothing_and_preserves_pending_value() {
    let transport = Arc::new(MockTransport::with(vec![begin_response()]));
    let client = client(Arc::clone(&transport));
    let login = client
        .begin_login("https://app.example/callback", None, None)
        .await
        .unwrap();
    let error = client
        .validate_callback(
            "https://app.example/callback?handoff=ticket&state=wrong",
            &login.pending,
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
            &login.pending,
        )
        .await
        .unwrap();
    assert_eq!(pair.refresh_generation(), 1);
    let next = client.refresh(&pair).await.unwrap();
    assert_eq!(next.refresh_generation(), 2);
    let user = client.current_user(&next).await.unwrap();
    assert_eq!(user.user_id, "user_public");
    client.logout_application(&next).await.unwrap();
    let logout = client.prepare_browser_logout(&next).await.unwrap();
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
            &login.pending,
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
            &login.pending,
        )
        .await
        .unwrap_err();

    assert_eq!(error.category(), ErrorCategory::Indeterminate);
    assert_eq!(error.code(), "invalid_response_after_dispatch");
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
            &login.pending,
        )
        .await
        .unwrap_err();

    assert_eq!(error.category(), ErrorCategory::Indeterminate);
    assert_eq!(error.code(), "invalid_response_after_dispatch");
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
            &login.pending,
        )
        .await
        .unwrap();
    let error = client.refresh(&pair).await.unwrap_err();

    assert_eq!(error.category(), ErrorCategory::Indeterminate);
    assert_eq!(error.code(), "invalid_response_after_dispatch");
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
            &login.pending,
        )
        .await
        .unwrap();
    let error = client.refresh(&pair).await.unwrap_err();

    assert_eq!(error.category(), ErrorCategory::Indeterminate);
    assert_eq!(error.code(), "invalid_response_after_dispatch");
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
            &login.pending,
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
async fn incomplete_rate_limit_envelopes_are_indeterminate_for_refresh() {
    for request_id in [None, Some(Value::Null)] {
        let state = URL_SAFE_NO_PAD.encode([1_u8; 32]);
        let mut body = json!({"code": "rate_limited", "message": "limited"});
        if let Some(request_id) = request_id {
            body["request_id"] = request_id;
        }
        let rate_limited = Ok(HttpResponse {
            status: 429,
            headers: vec![
                ("content-type".into(), "application/json".into()),
                ("retry-after".into(), "1".into()),
            ],
            body: serde_json::to_vec(&body).unwrap(),
        });
        let transport = Arc::new(MockTransport::with(vec![
            begin_response(),
            response(200, credentials(1)),
            rate_limited,
        ]));
        let client = client(transport);
        let login = client
            .begin_login("https://app.example/callback", None, None)
            .await
            .unwrap();
        let pair = client
            .complete_login(
                &format!("https://app.example/callback?handoff=ticket&state={state}"),
                &login.pending,
            )
            .await
            .unwrap();
        let error = client.refresh(&pair).await.unwrap_err();
        assert_eq!(error.category(), ErrorCategory::Indeterminate);
        assert_eq!(error.local_action(), LocalAction::QuarantineCredentials);
    }
}

#[tokio::test]
async fn unsafe_but_present_request_id_is_not_exposed() {
    let response = Ok(HttpResponse {
        status: 429,
        headers: vec![
            ("content-type".into(), "application/json".into()),
            ("retry-after".into(), "7".into()),
        ],
        body: br#"{"code":"rate_limited","message":"limited","request_id":"bad id"}"#.to_vec(),
    });
    let error = client(Arc::new(MockTransport::with(vec![response])))
        .public_configuration()
        .await
        .unwrap_err();
    assert_eq!(error.category(), ErrorCategory::RateLimited);
    assert_eq!(error.retry_after_seconds(), Some(7));
    assert_eq!(error.request_id(), None);
}

#[tokio::test]
async fn complete_login_pre_cancel_preserves_caller_owned_pending() {
    let state = URL_SAFE_NO_PAD.encode([1_u8; 32]);
    let transport = Arc::new(MockTransport::with(vec![begin_response()]));
    let client = client(Arc::clone(&transport));
    let login = client
        .begin_login("https://app.example/callback", None, None)
        .await
        .unwrap();
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let error = client
        .complete_login_with_options(
            &format!("https://app.example/callback?handoff=ticket&state={state}"),
            &login.pending,
            &OperationOptions::with_cancellation(cancellation),
        )
        .await
        .unwrap_err();
    assert_eq!(error.category(), ErrorCategory::Cancelled);
    assert!(login.pending.available());
    assert!(login.pending.export_record().is_ok());
    assert_eq!(transport.request_count(), 1);
}

#[tokio::test]
async fn production_response_overflow_signal_is_protocol_for_reads() {
    let failure = TransportFailure::new(TransportFailureKind::ResponseTooLarge, true);
    let error = client(Arc::new(MockTransport::with(vec![Err(failure)])))
        .public_configuration()
        .await
        .unwrap_err();
    assert_eq!(error.category(), ErrorCategory::Protocol);
    assert_eq!(error.code(), "invalid_response");
    assert_eq!(error.retry_policy(), RetryPolicy::Never);
}

#[tokio::test]
async fn closed_jwk_rejects_additive_fields_while_document_stays_open() {
    let transport = Arc::new(MockTransport::with(vec![response(
        200,
        json!({
            "keys": [{
                "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig",
                "kid": "key", "x": URL_SAFE_NO_PAD.encode([1_u8; 32]), "unexpected": true
            }],
            "revision": 1,
            "signing_epoch": 1,
            "future": true
        }),
    )]));
    let error = client(transport).project_jwks().await.unwrap_err();
    assert_eq!(error.category(), ErrorCategory::Protocol);
}

#[tokio::test]
async fn credential_records_reject_header_controls_and_empty_session_ids() {
    let state = URL_SAFE_NO_PAD.encode([1_u8; 32]);
    let transport = Arc::new(MockTransport::with(vec![
        begin_response(),
        response(200, credentials(1)),
    ]));
    let client = client(transport);
    let login = client
        .begin_login("https://app.example/callback", None, None)
        .await
        .unwrap();
    let pair = client
        .complete_login(
            &format!("https://app.example/callback?handoff=ticket&state={state}"),
            &login.pending,
        )
        .await
        .unwrap();
    for (field, value) in [("access_token", "bad\r\nheader"), ("session_id", "")] {
        let mut encoded = serde_json::to_value(pair.export_record()).unwrap();
        encoded[field] = json!(value);
        let record: CredentialPairRecord = serde_json::from_value(encoded).unwrap();
        assert!(client.restore_credentials(record).is_err());
    }
}

#[tokio::test]
async fn unicode_runtime_error_message_uses_character_bounds() {
    let transport = Arc::new(MockTransport::with(vec![response(
        503,
        json!({
            "code": "authority_unavailable",
            "message": "界".repeat(100),
            "request_id": "request-1"
        }),
    )]));
    let error = client(transport).public_configuration().await.unwrap_err();
    assert_eq!(error.code(), "authority_unavailable");
}

#[tokio::test]
async fn uncontracted_runtime_status_is_invalid_even_with_safe_error_envelope() {
    let transport = Arc::new(MockTransport::with(vec![response(
        418,
        json!({
            "code": "future_runtime_code", "message": "do not trust raw provider detail", "request_id": "request-1"
        }),
    )]));
    let error = client(transport).public_configuration().await.unwrap_err();
    assert_eq!(error.category(), ErrorCategory::Protocol);
    assert_eq!(error.code(), "invalid_response");
    assert_eq!(error.retry_policy(), RetryPolicy::Never);
    assert!(!error.to_string().contains("provider detail"));
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
                &login.pending,
            )
            .await
            .unwrap();
        let result = client.current_user(&pair).await;
        assert_eq!(result.is_ok(), should_accept);
        if let Ok(accepted) = result {
            assert!(accepted.projection.locale.is_none());
            assert!(accepted.projection.verified_email.is_none());
        }
    }
}
