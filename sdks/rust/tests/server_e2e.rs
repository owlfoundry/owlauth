use std::{env, time::Duration};

use owlauth_client::{Client, ClientConfig, ErrorCategory};
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
    let login = sdk
        .begin_login(&redirect_uri, None, None)
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
        .header(header::ORIGIN, &runtime_origin)
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

    let first = sdk
        .complete_login(&application_callback, login.pending)
        .await
        .expect("handoff exchange");
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
        .header(header::ORIGIN, runtime_origin)
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
