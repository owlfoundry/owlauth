use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::get,
};
use owlauth_types::{
    HealthResponse,
    control::{ServiceDescriptor, SystemCapabilities},
};
use tower::limit::ConcurrencyLimitLayer;
use tower_http::{catch_panic::CatchPanicLayer, timeout::TimeoutLayer};
use tracing::info;
use uuid::Uuid;

use crate::{
    config::{ListenerConfig, OperatorApiKey, ServerConfig},
    web_assets::{self, WebPlane},
};

#[derive(Clone, Copy, Debug)]
enum HttpPlane {
    Runtime,
    Control,
}

impl HttpPlane {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Runtime => "runtime",
            Self::Control => "control",
        }
    }
}

#[derive(Clone)]
struct ProbeState {
    ready: Arc<AtomicBool>,
    base_path: Arc<str>,
}

#[derive(Clone)]
struct ControlState {
    probe: ProbeState,
    operator_key: Arc<OperatorApiKey>,
    descriptor: Arc<ServiceDescriptor>,
}

pub(crate) struct PlaneRouters {
    pub runtime: Option<Router>,
    pub control: Option<Router>,
    runtime_ready: Arc<AtomicBool>,
    control_ready: Arc<AtomicBool>,
}

impl PlaneRouters {
    pub fn mark_ready(&self) {
        if self.runtime.is_some() {
            self.runtime_ready.store(true, Ordering::Release);
        }
        if self.control.is_some() {
            self.control_ready.store(true, Ordering::Release);
        }
    }

    pub fn mark_unready(&self) {
        self.runtime_ready.store(false, Ordering::Release);
        self.control_ready.store(false, Ordering::Release);
    }
}

pub(crate) fn build_routers(config: &ServerConfig) -> PlaneRouters {
    let runtime_ready = Arc::new(AtomicBool::new(false));
    let control_ready = Arc::new(AtomicBool::new(false));

    let runtime = config.mode.has_runtime().then(|| {
        runtime_router(
            &config.runtime,
            ProbeState {
                ready: Arc::clone(&runtime_ready),
                base_path: Arc::from(config.runtime.external_base.path()),
            },
            config,
        )
    });
    let control = config.mode.has_control().then(|| {
        control_router(
            &config.control,
            ControlState {
                probe: ProbeState {
                    ready: Arc::clone(&control_ready),
                    base_path: Arc::from(config.control.external_base.path()),
                },
                operator_key: Arc::new(
                    config
                        .control_api_key
                        .clone()
                        .expect("validated Control configuration has an operator key"),
                ),
                descriptor: Arc::new(ServiceDescriptor {
                    schema_version: "1".to_owned(),
                    product: "owlauth-server".to_owned(),
                    instance_id: config
                        .instance_id
                        .clone()
                        .expect("validated Control configuration has an instance ID"),
                    api_base_url: config
                        .control
                        .external_base
                        .join("v1/")
                        .expect("validated base accepts a relative API path")
                        .to_string(),
                    api_versions: vec!["v1".to_owned()],
                    credential_class: "operator-api-key".to_owned(),
                    mcp_url: None,
                }),
            },
            config,
        )
    });

    PlaneRouters {
        runtime,
        control,
        runtime_ready,
        control_ready,
    }
}

fn runtime_router(listener: &ListenerConfig, state: ProbeState, config: &ServerConfig) -> Router {
    let router = Router::new()
        .route("/", get(runtime_root))
        .route("/auth/", get(runtime_shell))
        .route("/auth/assets/{*path}", get(runtime_asset))
        .route("/health", get(liveness))
        .route("/ready", get(runtime_readiness))
        .with_state(state);
    mount_and_bound(
        listener,
        router,
        HttpPlane::Runtime,
        config.request_timeout,
        config.max_request_bytes,
        256,
    )
}

fn control_router(listener: &ListenerConfig, state: ControlState, config: &ServerConfig) -> Router {
    let application = Router::new()
        .route("/", get(control_root))
        .route("/console/", get(control_shell))
        .route("/console/assets/{*path}", get(control_asset))
        .route("/console/{*path}", get(control_shell))
        .route("/health", get(liveness))
        .route("/ready", get(control_readiness))
        .route("/v1/system", get(system_capabilities))
        .with_state(state.clone());
    let descriptor = Router::new()
        .route("/.well-known/owlauth", get(service_descriptor))
        .with_state(state);
    let router = if listener.external_base.path() == "/" {
        application.merge(descriptor)
    } else {
        Router::new()
            .nest(
                listener.external_base.path().trim_end_matches('/'),
                application,
            )
            .merge(descriptor)
    };
    bound(
        router,
        HttpPlane::Control,
        config.request_timeout,
        config.max_request_bytes,
        64,
    )
}

fn mount_and_bound(
    listener: &ListenerConfig,
    router: Router,
    plane: HttpPlane,
    request_timeout: std::time::Duration,
    max_request_bytes: usize,
    concurrency: usize,
) -> Router {
    let router = if listener.external_base.path() == "/" {
        router
    } else {
        Router::new().nest(listener.external_base.path().trim_end_matches('/'), router)
    };

    bound(
        router,
        plane,
        request_timeout,
        max_request_bytes,
        concurrency,
    )
}

fn bound(
    router: Router,
    plane: HttpPlane,
    request_timeout: std::time::Duration,
    max_request_bytes: usize,
    concurrency: usize,
) -> Router {
    router
        .layer(middleware::from_fn(move |request, next| {
            response_policy(plane, request, next)
        }))
        .layer(DefaultBodyLimit::max(max_request_bytes))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            request_timeout,
        ))
        .layer(ConcurrencyLimitLayer::new(concurrency))
        .layer(CatchPanicLayer::new())
}

async fn runtime_root(State(state): State<ProbeState>) -> Redirect {
    Redirect::temporary(&format!("{}auth/", state.base_path))
}

async fn runtime_shell(State(state): State<ProbeState>) -> Response {
    web_assets::shell(WebPlane::Runtime, &state.base_path)
}

async fn runtime_asset(Path(path): Path<String>, headers: HeaderMap) -> Response {
    web_assets::asset(WebPlane::Runtime, &format!("assets/{path}"), &headers)
}

async fn control_root(State(state): State<ControlState>) -> Redirect {
    Redirect::temporary(&format!("{}console/", state.probe.base_path))
}

async fn control_shell(State(state): State<ControlState>) -> Response {
    web_assets::shell(WebPlane::Control, &state.probe.base_path)
}

async fn control_asset(Path(path): Path<String>, headers: HeaderMap) -> Response {
    web_assets::asset(WebPlane::Control, &format!("assets/{path}"), &headers)
}

async fn liveness() -> Json<HealthResponse> {
    Json(HealthResponse::ok())
}

async fn runtime_readiness(State(state): State<ProbeState>) -> Response {
    readiness_response(state.ready.load(Ordering::Acquire))
}

async fn control_readiness(State(state): State<ControlState>) -> Response {
    readiness_response(state.probe.ready.load(Ordering::Acquire))
}

fn readiness_response(ready: bool) -> Response {
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let body = if ready {
        HealthResponse::ok()
    } else {
        HealthResponse::unavailable()
    };
    (status, Json(body)).into_response()
}

async fn service_descriptor(State(state): State<ControlState>) -> Json<ServiceDescriptor> {
    Json((*state.descriptor).clone())
}

async fn system_capabilities(State(state): State<ControlState>, headers: HeaderMap) -> Response {
    if !valid_control_authorization(&headers, &state.operator_key) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    Json(SystemCapabilities {
        product: "owlauth-server".to_owned(),
        project_auth: false,
    })
    .into_response()
}

fn valid_control_authorization(headers: &HeaderMap, expected: &OperatorApiKey) -> bool {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    value
        .to_str()
        .ok()
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|candidate| expected.matches(candidate.as_bytes()))
}

async fn response_policy(plane: HttpPlane, mut request: Request, next: Next) -> Response {
    let correlation_id = Uuid::new_v4().to_string();
    request.extensions_mut().insert(correlation_id.clone());
    let method = request.method().clone();
    let mut response = next.run(request).await;

    response.headers_mut().insert(
        HeaderName::from_static("x-request-id"),
        HeaderValue::from_str(&correlation_id).expect("UUID is a valid header value"),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response.headers_mut().insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    response.headers_mut().insert(
        HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; font-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; worker-src 'none'; manifest-src 'none'",
        ),
    );
    if !response.headers().contains_key(header::CACHE_CONTROL) {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }

    info!(
        event = "http_request_completed",
        plane = plane.as_str(),
        %correlation_id,
        method = %method,
        status = response.status().as_u16(),
        "request completed"
    );
    response
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use tower::ServiceExt;

    use super::*;
    use crate::config::PlaneMode;

    fn test_config(mode: PlaneMode) -> ServerConfig {
        let key = format!("owl_ctrl_v1_{}", "A".repeat(43));
        let mut values = BTreeMap::from([
            (
                "OWLAUTH_POSTGRES_URL".to_owned(),
                "postgres://owlauth:test@127.0.0.1/owlauth".to_owned(),
            ),
            ("OWLAUTH_CONTROL_API_KEY".to_owned(), key),
            (
                "OWLAUTH_INSTANCE_ID".to_owned(),
                "test-deployment".to_owned(),
            ),
            (
                "OWLAUTH_MODE".to_owned(),
                match mode {
                    PlaneMode::All => "all",
                    PlaneMode::Runtime => "runtime",
                    PlaneMode::Control => "control",
                }
                .to_owned(),
            ),
        ]);
        if mode == PlaneMode::All {
            values.insert(
                "OWLAUTH_RUNTIME_BASE_URL".to_owned(),
                "https://identity.example/runtime/".to_owned(),
            );
            values.insert(
                "OWLAUTH_CONTROL_BASE_URL".to_owned(),
                "https://identity.example/control/".to_owned(),
            );
        }
        ServerConfig::from_values_for_test(&values).expect("test config should parse")
    }

    #[tokio::test]
    async fn runtime_router_never_routes_control() {
        let config = test_config(PlaneMode::Runtime);
        let mut routers = build_routers(&config);
        let unready = routers
            .runtime
            .as_ref()
            .expect("Runtime router should exist")
            .clone()
            .oneshot(Request::get("/ready").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(unready.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            &to_bytes(unready.into_body(), 1024).await.unwrap()[..],
            br#"{"status":"unavailable"}"#
        );

        routers.mark_ready();
        let runtime = routers.runtime.take().expect("Runtime router should exist");

        let health = runtime
            .clone()
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::OK);
        assert!(health.headers().contains_key("x-request-id"));

        let control = runtime
            .oneshot(Request::get("/v1/system").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(control.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn control_authentication_is_strict_and_base_scoped() {
        let config = test_config(PlaneMode::All);
        let mut routers = build_routers(&config);
        routers.mark_ready();
        let control = routers.control.take().expect("Control router should exist");
        let uri = "/control/v1/system";

        let discovery = control
            .clone()
            .oneshot(
                Request::get("/.well-known/owlauth")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(discovery.status(), StatusCode::OK);
        assert_eq!(discovery.headers()[header::CACHE_CONTROL], "no-store");
        let descriptor: ServiceDescriptor =
            serde_json::from_slice(&to_bytes(discovery.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(descriptor.instance_id, "test-deployment");
        assert_eq!(
            descriptor.api_base_url,
            "https://identity.example/control/v1/"
        );

        let misplaced_discovery = control
            .clone()
            .oneshot(
                Request::get("/control/.well-known/owlauth")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(misplaced_discovery.status(), StatusCode::NOT_FOUND);

        let denied = control
            .clone()
            .oneshot(Request::get(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);

        let accepted = control
            .clone()
            .oneshot(
                Request::get(uri)
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer owl_ctrl_v1_{}", "A".repeat(43)),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::OK);
        let body = to_bytes(accepted.into_body(), 1024).await.unwrap();
        assert_eq!(
            &body[..],
            br#"{"product":"owlauth-server","project_auth":false}"#
        );

        let runtime_path = control
            .oneshot(Request::get("/runtime/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(runtime_path.status(), StatusCode::NOT_FOUND);
    }

    fn attribute(document: &str, name: &str) -> String {
        let marker = format!("{name}=\"");
        let start = document
            .find(&marker)
            .expect("shell attribute should exist")
            + marker.len();
        let end = document[start..]
            .find('"')
            .expect("shell attribute should terminate")
            + start;
        document[start..end].to_owned()
    }

    #[tokio::test]
    async fn embedded_assets_are_plane_local_and_representation_correct() {
        let config = test_config(PlaneMode::All);
        let mut routers = build_routers(&config);
        routers.mark_ready();
        let runtime = routers.runtime.take().expect("Runtime router should exist");
        let control = routers.control.take().expect("Control router should exist");

        let runtime_shell = runtime
            .clone()
            .oneshot(Request::get("/runtime/auth/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(runtime_shell.status(), StatusCode::OK);
        assert_eq!(
            runtime_shell.headers()[header::CACHE_CONTROL],
            HeaderValue::from_static("no-store")
        );
        let runtime_document = String::from_utf8(
            to_bytes(runtime_shell.into_body(), 1_000_000)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(runtime_document.contains("name=\"owlauth-runtime-base\" content=\"/runtime/\""));
        assert!(!runtime_document.contains("<script>"));
        let runtime_asset_path = attribute(&runtime_document, "src");
        assert!(runtime_asset_path.starts_with("/runtime/auth/assets/runtime-"));

        let compressed = runtime
            .clone()
            .oneshot(
                Request::get(&runtime_asset_path)
                    .header(header::ACCEPT_ENCODING, "gzip;q=0.8, br")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(compressed.status(), StatusCode::OK);
        assert_eq!(compressed.headers()[header::CONTENT_ENCODING], "br");
        assert_eq!(compressed.headers()[header::VARY], "Accept-Encoding");
        assert_eq!(
            compressed.headers()[header::CACHE_CONTROL],
            "public, max-age=31536000, immutable"
        );
        let etag = compressed.headers()[header::ETAG].clone();
        let not_modified = runtime
            .clone()
            .oneshot(
                Request::get(&runtime_asset_path)
                    .header(header::ACCEPT_ENCODING, "br")
                    .header(header::IF_NONE_MATCH, etag)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);

        let runtime_filename = runtime_asset_path
            .rsplit('/')
            .next()
            .expect("asset path should have a filename");
        let cross_plane = control
            .clone()
            .oneshot(
                Request::get(format!("/control/console/assets/{runtime_filename}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cross_plane.status(), StatusCode::NOT_FOUND);

        let control_shell = control
            .oneshot(
                Request::get("/control/console/settings")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(control_shell.status(), StatusCode::OK);
        let control_document = String::from_utf8(
            to_bytes(control_shell.into_body(), 1_000_000)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(control_document.contains("name=\"owlauth-control-base\" content=\"/control/\""));
        assert!(
            attribute(&control_document, "src").starts_with("/control/console/assets/control-")
        );
    }
}
