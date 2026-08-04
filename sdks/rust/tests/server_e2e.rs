use std::{env, time::Duration};

use owlauth_client::{
    Client, ClientConfig, CredentialPair, Error, ErrorCategory, LocalAction, RetryPolicy, VERSION,
    ValidatedCallback,
};
use reqwest::{Client as HttpClient, Response, header};
use serde::Deserialize;
use serde_json::json;
use url::Url;

#[derive(Deserialize)]
struct InteractionBootstrap {
    project_id: String,
    revision: i64,
    csrf: String,
}

#[derive(Deserialize)]
struct Navigation {
    url: String,
}

#[derive(Deserialize)]
struct LogoutBootstrap {
    project_id: String,
    revision: i64,
    csrf: String,
}

#[derive(Deserialize)]
struct FaultEvents {
    items: Vec<FaultEvent>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FaultEvent {
    label: String,
    operation: String,
    upstream_status: u16,
}

/// Runs against one already provisioned real Runtime and controlled auto-authorizing provider.
///
/// Required environment:
/// `OWLAUTH_E2E_RUNTIME_URL`, `OWLAUTH_E2E_PROJECT_ID`, `OWLAUTH_E2E_APPLICATION_ID`,
/// `OWLAUTH_E2E_PUBLISHABLE_KEY`, `OWLAUTH_E2E_REDIRECT_URI`, and
/// `OWLAUTH_E2E_PROVIDER_KEY`. Set `OWLAUTH_E2E_ALLOW_INSECURE_LOOPBACK=1` only for a
/// loopback Runtime. The controlled provider authorization endpoint must immediately redirect
/// to Runtime's callback while validating its normal OIDC request.
#[tokio::test]
#[ignore = "requires a real provisioned OwlAuth Runtime, PostgreSQL, signer stores, and controlled OIDC provider"]
#[allow(
    clippy::too_many_lines,
    reason = "the ignored product journey intentionally shows the complete cross-boundary ordering"
)]
async fn real_runtime_project_auth_lifecycle() {
    let runtime_url = required("OWLAUTH_E2E_RUNTIME_URL");
    let project_id = required("OWLAUTH_E2E_PROJECT_ID");
    let application_id = required("OWLAUTH_E2E_APPLICATION_ID");
    let publishable_key = required("OWLAUTH_E2E_PUBLISHABLE_KEY");
    let redirect_uri = required("OWLAUTH_E2E_REDIRECT_URI");
    let provider_key = required("OWLAUTH_E2E_PROVIDER_KEY");
    let other_project_id = required("OWLAUTH_E2E_OTHER_PROJECT_ID");
    let other_application_id = required("OWLAUTH_E2E_OTHER_APPLICATION_ID");
    assert_eq!(VERSION, required("OWLAUTH_E2E_EXPECTED_SDK_VERSION"));

    let mut config =
        ClientConfig::new(&runtime_url, &project_id, &application_id, &publishable_key);
    config.allow_insecure_loopback =
        env::var("OWLAUTH_E2E_ALLOW_INSECURE_LOOPBACK").as_deref() == Ok("1");
    config.deadline = Duration::from_secs(20);
    let sdk = Client::new(config).expect("valid E2E SDK configuration");
    let http = HttpClient::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("raw browser helper");
    let runtime = Url::parse(sdk.base_url()).expect("validated base");
    let runtime_origin = runtime.origin().ascii_serialization();

    let public = sdk
        .public_configuration()
        .await
        .expect("public configuration");
    assert!(public.login_available);
    assert!(
        public
            .providers
            .iter()
            .any(|provider| provider.key == provider_key)
    );
    assert_eq!(public.project_public_id, project_id);
    assert_eq!(public.application_public_id, application_id);
    assert_context_rejected(
        &runtime_url,
        &other_project_id,
        &application_id,
        &publishable_key,
    )
    .await;
    assert_context_rejected(
        &runtime_url,
        &project_id,
        &other_application_id,
        &publishable_key,
    )
    .await;
    assert_context_rejected(
        &runtime_url,
        &project_id,
        &application_id,
        &mutate(&publishable_key),
    )
    .await;
    let jwks = sdk.project_jwks().await.expect("Project JWKS");
    assert!(jwks.revision > 0 && jwks.signing_epoch > 0 && !jwks.keys.is_empty());
    let (first, project_cookie) = login(
        &sdk,
        &http,
        &runtime,
        &runtime_origin,
        &project_id,
        &provider_key,
        &redirect_uri,
        true,
    )
    .await;
    let current = sdk
        .current_user(first.access_token())
        .await
        .expect("current user");
    assert_eq!(current.user_id, first.user_id());
    let successor = sdk.refresh(&first).await.expect("strict refresh rotation");
    let browser_logout = sdk
        .prepare_browser_logout(successor.access_token())
        .await
        .expect("browser logout preparation");

    let logout_page = http
        .get(&browser_logout.hosted_url)
        .header(header::COOKIE, &project_cookie)
        .header("sec-fetch-dest", "document")
        .header("sec-fetch-mode", "navigate")
        .send()
        .await
        .expect("browser logout navigation");
    assert!(logout_page.status().is_success());
    let logout_html = logout_page.text().await.expect("bounded logout HTML");
    let logout: LogoutBootstrap = bootstrap(&logout_html);
    assert_eq!(logout.project_id, project_id);
    let preparation = last_path_segment(&browser_logout.hosted_url);
    let confirm_url = runtime
        .join(&format!(
            "v1/projects/{project_id}/auth/browser-logout/{preparation}/confirm"
        ))
        .expect("logout confirmation URL");
    let confirmed = http
        .post(confirm_url)
        .header(header::COOKIE, project_cookie)
        .header(header::ORIGIN, &runtime_origin)
        .header("sec-fetch-site", "same-origin")
        .header("sec-fetch-mode", "cors")
        .header("sec-fetch-dest", "empty")
        .json(&json!({"expected_revision": logout.revision, "csrf": logout.csrf}))
        .send()
        .await
        .expect("browser logout confirmation");
    assert!(confirmed.status().is_success());
    let blocked = sdk
        .refresh(&successor)
        .await
        .expect_err("browser logout must revoke the Application session");
    assert_eq!(blocked.category(), ErrorCategory::Refresh);
    sdk.logout_application(successor.access_token())
        .await
        .expect("idempotent Application logout confirmation");

    let (concurrent, _) = login(
        &sdk,
        &http,
        &runtime,
        &runtime_origin,
        &project_id,
        &provider_key,
        &redirect_uri,
        false,
    )
    .await;
    let (left, right) = tokio::join!(sdk.refresh(&concurrent), sdk.refresh(&concurrent));
    let ((Ok(concurrent_successor), Err(concurrent_error))
    | (Err(concurrent_error), Ok(concurrent_successor))) = (left, right)
    else {
        panic!("concurrent refresh must produce one winner and one replay");
    };
    assert_eq!(concurrent_error.category(), ErrorCategory::Refresh);
    let revoked = sdk
        .refresh(&concurrent_successor)
        .await
        .expect_err("concurrent predecessor replay must revoke the successor family");
    assert_eq!(revoked.category(), ErrorCategory::Refresh);

    let fault_token = required("OWLAUTH_E2E_FAULT_PROXY_TOKEN");
    let (handoff, _, _) = login_callback(
        &sdk,
        &http,
        &runtime,
        &runtime_origin,
        &project_id,
        &provider_key,
        &redirect_uri,
        false,
    )
    .await;
    arm_fault(
        &http,
        &runtime,
        &fault_token,
        "exchange_handoff",
        "rust-handoff",
    )
    .await;
    let handoff_error = sdk
        .exchange_handoff(handoff)
        .await
        .expect_err("dropped handoff response must be indeterminate");
    assert_indeterminate(&handoff_error, LocalAction::QuarantinePendingLogin);
    assert_fault_observed(
        &http,
        &runtime,
        &fault_token,
        "rust-handoff",
        "exchange_handoff",
    )
    .await;

    let (refresh_fault, _) = login(
        &sdk,
        &http,
        &runtime,
        &runtime_origin,
        &project_id,
        &provider_key,
        &redirect_uri,
        false,
    )
    .await;
    arm_fault(
        &http,
        &runtime,
        &fault_token,
        "refresh_session",
        "rust-refresh",
    )
    .await;
    let refresh_error = sdk
        .refresh(&refresh_fault)
        .await
        .expect_err("dropped refresh response must be indeterminate");
    assert_indeterminate(&refresh_error, LocalAction::QuarantineCredentials);
    assert_fault_observed(
        &http,
        &runtime,
        &fault_token,
        "rust-refresh",
        "refresh_session",
    )
    .await;
    let replayed = sdk
        .refresh(&refresh_fault)
        .await
        .expect_err("ambiguous refresh predecessor must not be replayable");
    assert_eq!(replayed.category(), ErrorCategory::Refresh);

    let (logout_fault, _) = login(
        &sdk,
        &http,
        &runtime,
        &runtime_origin,
        &project_id,
        &provider_key,
        &redirect_uri,
        false,
    )
    .await;
    arm_fault(
        &http,
        &runtime,
        &fault_token,
        "logout_application_session",
        "rust-logout",
    )
    .await;
    let logout_error = sdk
        .logout_application(logout_fault.access_token())
        .await
        .expect_err("dropped logout response must be indeterminate");
    assert_indeterminate(&logout_error, LocalAction::QuarantineCredentials);
    assert_fault_observed(
        &http,
        &runtime,
        &fault_token,
        "rust-logout",
        "logout_application_session",
    )
    .await;
    let logged_out = sdk
        .current_user(logout_fault.access_token())
        .await
        .expect_err("ambiguous logout must commit at Runtime");
    assert_eq!(logged_out.category(), ErrorCategory::Authentication);
}

#[allow(
    clippy::too_many_arguments,
    reason = "the helper crosses the complete real browser flow"
)]
async fn login(
    sdk: &Client,
    http: &HttpClient,
    runtime: &Url,
    runtime_origin: &str,
    project_id: &str,
    provider_key: &str,
    redirect_uri: &str,
    verify_replay: bool,
) -> (CredentialPair, String) {
    let (callback, replay, project_cookie) = login_callback(
        sdk,
        http,
        runtime,
        runtime_origin,
        project_id,
        provider_key,
        redirect_uri,
        verify_replay,
    )
    .await;
    let credentials = sdk
        .exchange_handoff(callback)
        .await
        .expect("handoff exchange");
    if let Some(replay) = replay {
        let error = sdk
            .exchange_handoff(replay)
            .await
            .expect_err("handoff callback must be one use");
        assert_eq!(error.category(), ErrorCategory::Handoff);
        assert_eq!(error.local_action(), LocalAction::DiscardPendingLogin);
    }
    (credentials, project_cookie)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the helper crosses the complete real browser flow"
)]
async fn login_callback(
    sdk: &Client,
    http: &HttpClient,
    runtime: &Url,
    runtime_origin: &str,
    project_id: &str,
    provider_key: &str,
    redirect_uri: &str,
    verify_replay: bool,
) -> (ValidatedCallback, Option<ValidatedCallback>, String) {
    let login = sdk
        .begin_login(redirect_uri, None, None)
        .await
        .expect("login start");
    let hosted = http
        .get(&login.hosted_url)
        .header("sec-fetch-dest", "document")
        .header("sec-fetch-mode", "navigate")
        .send()
        .await
        .expect("Hosted interaction navigation");
    assert!(hosted.status().is_success());
    let binding_cookie = cookie(&hosted, "owl_runtime_");
    let interaction_html = hosted.text().await.expect("bounded Hosted HTML");
    let interaction: InteractionBootstrap = bootstrap(&interaction_html);
    assert_eq!(interaction.project_id, project_id);
    let interaction_handle = last_path_segment(&login.hosted_url);
    let select_url = runtime
        .join(&format!(
            "v1/projects/{project_id}/auth/interactions/{interaction_handle}/method"
        ))
        .expect("selection URL");
    let selected = http
        .post(select_url)
        .header(header::COOKIE, &binding_cookie)
        .header(header::ORIGIN, runtime_origin)
        .header("sec-fetch-site", "same-origin")
        .header("sec-fetch-mode", "cors")
        .header("sec-fetch-dest", "empty")
        .json(&json!({
            "expected_revision": interaction.revision,
            "csrf": interaction.csrf,
            "provider_key": provider_key,
        }))
        .send()
        .await
        .expect("Hosted provider selection");
    assert!(selected.status().is_success());
    let navigation: Navigation = selected.json().await.expect("selection response");
    let provider = http
        .get(&navigation.url)
        .send()
        .await
        .expect("controlled provider authorization");
    assert!(provider.status().is_redirection());
    let runtime_callback = location(&provider);
    let callback = http
        .get(runtime_callback)
        .header(header::COOKIE, &binding_cookie)
        .send()
        .await
        .expect("Runtime provider callback");
    assert!(callback.status().is_redirection());
    let application_callback = location(&callback);
    let project_cookie = cookie(&callback, "owl_project_");
    let callback = sdk
        .validate_callback(&application_callback, &login.pending)
        .expect("validated handoff callback");
    let replay = verify_replay.then(|| {
        sdk.validate_callback(&application_callback, &login.pending)
            .expect("second local callback view")
    });
    (callback, replay, project_cookie)
}

async fn arm_fault(http: &HttpClient, runtime: &Url, token: &str, operation: &str, label: &str) {
    let response = http
        .post(runtime.join("__e2e/arm").expect("fault arm URL"))
        .bearer_auth(token)
        .json(&json!({"operation": operation, "label": label}))
        .send()
        .await
        .expect("arm bounded Runtime fault");
    assert_eq!(response.status(), 200);
}

async fn assert_fault_observed(
    http: &HttpClient,
    runtime: &Url,
    token: &str,
    label: &str,
    operation: &str,
) {
    let events: FaultEvents = http
        .get(runtime.join("__e2e/events").expect("fault events URL"))
        .bearer_auth(token)
        .send()
        .await
        .expect("read Runtime fault evidence")
        .json()
        .await
        .expect("typed Runtime fault evidence");
    assert!(events.items.iter().any(|event| {
        event.label == label && event.operation == operation && event.upstream_status == 200
    }));
}

fn assert_indeterminate(error: &Error, action: LocalAction) {
    assert_eq!(error.category(), ErrorCategory::Indeterminate);
    assert_eq!(error.code(), "outcome_indeterminate");
    assert_eq!(error.retry_policy(), RetryPolicy::Never);
    assert_eq!(error.local_action(), action);
}

async fn assert_context_rejected(
    runtime_url: &str,
    project_id: &str,
    application_id: &str,
    publishable_key: &str,
) {
    let mut config = ClientConfig::new(runtime_url, project_id, application_id, publishable_key);
    config.allow_insecure_loopback = true;
    config.deadline = Duration::from_secs(20);
    let client = Client::new(config).expect("valid isolated SDK context");
    let error = client
        .public_configuration()
        .await
        .expect_err("Runtime must reject an isolated SDK context mismatch");
    assert_eq!(error.operation(), "get_public_application_config");
    if let Some(request_id) = error.request_id() {
        assert!(!request_id.is_empty() && request_id.len() <= 128);
    }
}

fn mutate(value: &str) -> String {
    let mut result = value.to_owned();
    let replacement = if result.ends_with('A') { 'B' } else { 'A' };
    result.pop();
    result.push(replacement);
    result
}

fn required(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("missing required E2E environment variable {name}"))
}

fn cookie(response: &Response, prefix: &str) -> String {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|value| value.split(';').next())
        .find(|value| value.starts_with(prefix))
        .map(str::to_owned)
        .expect("expected hardened Runtime cookie")
}

fn location(response: &Response) -> String {
    response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .expect("expected redirect location")
}

fn last_path_segment(value: &str) -> String {
    Url::parse(value)
        .ok()
        .and_then(|url| url.path_segments()?.next_back().map(str::to_owned))
        .filter(|value| !value.is_empty())
        .expect("opaque URL handle")
}

fn bootstrap<T: for<'de> Deserialize<'de>>(html: &str) -> T {
    let marker = "name=\"owlauth-runtime-bootstrap\"";
    let start = html.find(marker).expect("Runtime bootstrap meta");
    let remainder = &html[start + marker.len()..];
    let content = "content=\"";
    let start = remainder.find(content).expect("bootstrap content") + content.len();
    let remainder = &remainder[start..];
    let end = remainder.find('"').expect("bootstrap content end");
    let decoded = remainder[..end]
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&");
    serde_json::from_str(&decoded).expect("typed Runtime bootstrap")
}
