use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use axum::{
    Extension, Json, Router,
    extract::{DefaultBodyLimit, FromRequest, Path, Query, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post, put},
};
use owlauth_types::{
    HealthResponse,
    control::{self as control_types, ServiceDescriptor, SystemCapabilities},
    runtime as runtime_types,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tower::limit::ConcurrencyLimitLayer;
use tower_http::{catch_panic::CatchPanicLayer, timeout::TimeoutLayer};
use tracing::info;
use uuid::Uuid;

use crate::{
    adapters::{
        postgres::{
            DatabasePools, provisioning::PostgresProvisioningAdapter,
            readiness::PostgresReadinessAdapter,
        },
        software_store::EncryptedFileStore,
    },
    application::{
        self, ApplicationError, CreateApplication, CreateProject, CreateProvider,
        ProvisioningService, ReadinessService, ReplaceApplicationConfiguration, UpdateApplication,
        UpdateProject, UpdateProjectPolicy,
    },
    config::{ListenerConfig, OperatorApiKey, ServerConfig},
    domain::ApplicationType,
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
struct RuntimeState {
    probe: ProbeState,
    readiness: Option<Arc<ReadinessService>>,
}

#[derive(Clone)]
struct ControlState {
    probe: ProbeState,
    operator_key: Arc<OperatorApiKey>,
    descriptor: Arc<ServiceDescriptor>,
    provisioning: Option<Arc<ProvisioningService>>,
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

pub(crate) fn build_routers(config: &ServerConfig, pools: Option<&DatabasePools>) -> PlaneRouters {
    let runtime_ready = Arc::new(AtomicBool::new(false));
    let control_ready = Arc::new(AtomicBool::new(false));

    let runtime = config.mode.has_runtime().then(|| {
        let readiness = pools
            .and_then(|pools| pools.runtime.clone())
            .map(|database| {
                Arc::new(ReadinessService::new(Arc::new(
                    PostgresReadinessAdapter::new(
                        database,
                        config.runtime_process_id.clone(),
                        config.publication_lease_ttl,
                    ),
                )))
            });
        runtime_router(
            &config.runtime,
            RuntimeState {
                probe: ProbeState {
                    ready: Arc::clone(&runtime_ready),
                    base_path: Arc::from(config.runtime.external_base.path()),
                },
                readiness,
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
                provisioning: pools
                    .and_then(|pools| pools.control.clone())
                    .map(|database| {
                        let provisioning = config
                            .provisioning
                            .as_ref()
                            .expect("validated Control configuration has provisioning stores");
                        Arc::new(ProvisioningService::new(Arc::new(
                            PostgresProvisioningAdapter::new(
                                database,
                                EncryptedFileStore::new(
                                    provisioning.signer_store_root.clone(),
                                    provisioning.signer_store_key.expose_copy(),
                                )
                                .expect("validated signer store configuration"),
                                EncryptedFileStore::new(
                                    provisioning.configuration_secret_store_root.clone(),
                                    provisioning.configuration_secret_store_key.expose_copy(),
                                )
                                .expect("validated secret store configuration"),
                                config.runtime.external_base.clone(),
                                config.required_runtime_process_ids.clone(),
                                config.key_propagation_delay,
                                config.signing_verification_retention,
                            ),
                        )))
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

fn runtime_router(listener: &ListenerConfig, state: RuntimeState, config: &ServerConfig) -> Router {
    let router = Router::new()
        .route("/", get(runtime_root))
        .route("/auth/", get(runtime_shell))
        .route("/auth/assets/{*path}", get(runtime_asset))
        .route("/health", get(liveness))
        .route("/ready", get(runtime_readiness))
        .route(
            "/v1/projects/{project_public_id}/auth/config",
            get(public_application_config),
        )
        .route(
            "/projects/{project_public_id}/.well-known/jwks.json",
            get(project_jwks),
        )
        .route_layer(middleware::from_fn(reject_runtime_authorization))
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
    let protected = Router::new()
        .route("/system", get(system_capabilities))
        .route("/projects", get(list_projects).post(create_project))
        .route(
            "/projects/{project_id}",
            get(get_project).patch(update_project),
        )
        .route(
            "/projects/{project_id}/policy",
            get(get_project_policy).put(update_project_policy),
        )
        .route("/projects/{project_id}/disable", post(disable_project))
        .route(
            "/projects/{project_id}/applications",
            get(list_applications).post(create_application),
        )
        .route(
            "/projects/{project_id}/applications/{application_id}",
            get(get_application).patch(update_application),
        )
        .route(
            "/projects/{project_id}/applications/{application_id}/configuration",
            put(replace_application_configuration),
        )
        .route(
            "/projects/{project_id}/applications/{application_id}/disable",
            post(disable_application),
        )
        .route(
            "/projects/{project_id}/signing-keys",
            get(list_signing_keys).post(create_signing_key),
        )
        .route(
            "/projects/{project_id}/signing-keys/{key_id}/activate",
            post(activate_signing_key),
        )
        .route(
            "/projects/{project_id}/signing-keys/{key_id}/retire",
            post(retire_signing_key),
        )
        .route(
            "/projects/{project_id}/signing-keys/{key_id}/revoke",
            post(revoke_signing_key),
        )
        .route(
            "/projects/{project_id}/providers",
            get(list_providers).post(create_provider),
        )
        .route(
            "/projects/{project_id}/providers/{provider_id}/disable",
            post(disable_provider),
        )
        .route(
            "/projects/{project_id}/providers/{provider_id}/assignments/{application_id}",
            put(assign_provider).delete(unassign_provider),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_operator,
        ));
    let application = Router::new()
        .route("/", get(control_root))
        .route("/console/", get(control_shell))
        .route("/console/assets/{*path}", get(control_asset))
        .route("/console/{*path}", get(control_shell))
        .route("/health", get(liveness))
        .route("/ready", get(control_readiness))
        .nest("/v1", protected)
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

async fn runtime_root(State(state): State<RuntimeState>) -> Redirect {
    Redirect::temporary(&format!("{}auth/", state.probe.base_path))
}

async fn runtime_shell(State(state): State<RuntimeState>) -> Response {
    web_assets::shell(WebPlane::Runtime, &state.probe.base_path)
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

async fn runtime_readiness(State(state): State<RuntimeState>) -> Response {
    readiness_response(state.probe.ready.load(Ordering::Acquire))
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

async fn system_capabilities() -> Json<SystemCapabilities> {
    Json(SystemCapabilities {
        product: "owlauth-server".to_owned(),
        project_auth: true,
    })
}

async fn reject_runtime_authorization(request: Request, next: Next) -> Response {
    if request.headers().contains_key(header::AUTHORIZATION) {
        let request_id = request
            .extensions()
            .get::<String>()
            .cloned()
            .unwrap_or_else(|| "unavailable".to_owned());
        return (
            StatusCode::BAD_REQUEST,
            Json(runtime_types::RuntimeError {
                code: "unexpected_authorization".to_owned(),
                message: "This public Runtime endpoint does not accept credentials.".to_owned(),
                request_id,
            }),
        )
            .into_response();
    }
    next.run(request).await
}

struct ControlJson<T>(T);

impl<S, T> FromRequest<S> for ControlJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = Response;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        let request_id = request
            .extensions()
            .get::<String>()
            .cloned()
            .unwrap_or_else(|| "unavailable".to_owned());
        Json::<T>::from_request(request, state)
            .await
            .map(|Json(value)| Self(value))
            .map_err(|_| {
                control_problem(
                    StatusCode::BAD_REQUEST,
                    "invalid_json",
                    "Invalid JSON request",
                    "The request body must be bounded JSON matching the operation schema.",
                    &request_id,
                )
            })
    }
}

async fn require_operator(
    State(state): State<ControlState>,
    request: Request,
    next: Next,
) -> Response {
    if !valid_control_authorization(request.headers(), &state.operator_key) {
        let request_id = request
            .extensions()
            .get::<String>()
            .cloned()
            .unwrap_or_else(|| "unavailable".to_owned());
        return control_problem(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Authentication required",
            "A single valid deployment operator Bearer credential is required.",
            &request_id,
        );
    }
    next.run(request).await
}

fn provisioning(state: &ControlState) -> Result<&ProvisioningService, ApplicationError> {
    state
        .provisioning
        .as_deref()
        .ok_or(ApplicationError::Persistence)
}

fn readiness(state: &RuntimeState) -> Result<&ReadinessService, ApplicationError> {
    state
        .readiness
        .as_deref()
        .ok_or(ApplicationError::Persistence)
}

#[derive(Deserialize)]
struct ListProjectsQuery {
    belongs_to: Option<String>,
}

async fn list_projects(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Query(query): Query<ListProjectsQuery>,
) -> Response {
    match provisioning(&state) {
        Ok(service) => match service.list_projects(query.belongs_to).await {
            Ok(items) => control_json(
                items
                    .into_iter()
                    .map(control_project)
                    .collect::<Result<Vec<_>, _>>()
                    .map(|items| control_types::ProjectList { items }),
                &request_id,
            ),
            Err(error) => application_problem(error, &request_id),
        },
        Err(error) => application_problem(error, &request_id),
    }
}

async fn create_project(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    headers: HeaderMap,
    ControlJson(body): ControlJson<control_types::CreateProjectRequest>,
) -> Response {
    let Ok(idempotency_key) = idempotency_key(&headers) else {
        return invalid_idempotency(&request_id);
    };
    let correlation_id = request_uuid(&request_id);
    match provisioning(&state) {
        Ok(service) => match service
            .create_project(
                CreateProject {
                    display_name: body.display_name,
                    belongs_to: body.belongs_to,
                    idempotency_key,
                },
                correlation_id,
            )
            .await
        {
            Ok(project) => control_json(control_project(project), &request_id),
            Err(error) => application_problem(error, &request_id),
        },
        Err(error) => application_problem(error, &request_id),
    }
}

async fn get_project(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path(project_id): Path<String>,
) -> Response {
    let project_id = match resource_uuid(&project_id, &request_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    match provisioning(&state) {
        Ok(service) => match service.get_project(project_id).await {
            Ok(project) => control_json(control_project(project), &request_id),
            Err(error) => application_problem(error, &request_id),
        },
        Err(error) => application_problem(error, &request_id),
    }
}

async fn update_project(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path(project_id): Path<String>,
    ControlJson(body): ControlJson<control_types::UpdateProjectRequest>,
) -> Response {
    let project_id = match resource_uuid(&project_id, &request_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    match provisioning(&state) {
        Ok(service) => match service
            .update_project(
                project_id,
                UpdateProject {
                    display_name: body.display_name,
                    belongs_to: body.belongs_to,
                    expected_metadata_revision: body.expected_metadata_revision,
                },
                request_uuid(&request_id),
            )
            .await
        {
            Ok(project) => control_json(control_project(project), &request_id),
            Err(error) => application_problem(error, &request_id),
        },
        Err(error) => application_problem(error, &request_id),
    }
}

async fn get_project_policy(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path(project_id): Path<String>,
) -> Response {
    let project_id = match resource_uuid(&project_id, &request_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    match provisioning(&state) {
        Ok(service) => match service.get_project_policy(project_id).await {
            Ok(policy) => Json(control_project_policy(&policy)).into_response(),
            Err(error) => application_problem(error, &request_id),
        },
        Err(error) => application_problem(error, &request_id),
    }
}

async fn update_project_policy(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path(project_id): Path<String>,
    ControlJson(body): ControlJson<control_types::UpdateProjectPolicyRequest>,
) -> Response {
    let project_id = match resource_uuid(&project_id, &request_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    match provisioning(&state) {
        Ok(service) => match service
            .update_project_policy(
                project_id,
                UpdateProjectPolicy {
                    access_token_lifetime_seconds: body.access_token_lifetime_seconds,
                    browser_session_reuse: body.browser_session_reuse,
                    expected_claims_revision: body.expected_claims_revision,
                    expected_session_revision: body.expected_session_revision,
                },
                request_uuid(&request_id),
            )
            .await
        {
            Ok(policy) => Json(control_project_policy(&policy)).into_response(),
            Err(error) => application_problem(error, &request_id),
        },
        Err(error) => application_problem(error, &request_id),
    }
}

async fn disable_project(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path(project_id): Path<String>,
    ControlJson(body): ControlJson<control_types::ExpectedSecurityRevision>,
) -> Response {
    let project_id = match resource_uuid(&project_id, &request_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    match provisioning(&state) {
        Ok(service) => match service
            .disable_project(
                project_id,
                body.expected_security_revision,
                request_uuid(&request_id),
            )
            .await
        {
            Ok(project) => control_json(control_project(project), &request_id),
            Err(error) => application_problem(error, &request_id),
        },
        Err(error) => application_problem(error, &request_id),
    }
}

async fn list_applications(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path(project_id): Path<String>,
) -> Response {
    let project_id = match resource_uuid(&project_id, &request_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    match provisioning(&state) {
        Ok(service) => match service.list_applications(project_id).await {
            Ok(items) => control_json(
                items
                    .into_iter()
                    .map(control_application)
                    .collect::<Result<Vec<_>, _>>()
                    .map(|items| control_types::ApplicationList { items }),
                &request_id,
            ),
            Err(error) => application_problem(error, &request_id),
        },
        Err(error) => application_problem(error, &request_id),
    }
}

async fn create_application(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path(project_id): Path<String>,
    headers: HeaderMap,
    ControlJson(body): ControlJson<control_types::CreateApplicationRequest>,
) -> Response {
    let project_id = match resource_uuid(&project_id, &request_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    let Ok(idempotency_key) = idempotency_key(&headers) else {
        return invalid_idempotency(&request_id);
    };
    let application_type = match body.application_type {
        control_types::ApplicationType::Web => ApplicationType::Web,
        control_types::ApplicationType::Native => ApplicationType::Native,
    };
    match provisioning(&state) {
        Ok(service) => match service
            .create_application(
                project_id,
                CreateApplication {
                    display_name: body.display_name,
                    application_type,
                    idempotency_key,
                },
                request_uuid(&request_id),
            )
            .await
        {
            Ok(application) => control_json(control_application(application), &request_id),
            Err(error) => application_problem(error, &request_id),
        },
        Err(error) => application_problem(error, &request_id),
    }
}

async fn get_application(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, application_id)): Path<(String, String)>,
) -> Response {
    let (project_id, application_id) =
        match resource_pair(&project_id, &application_id, &request_id) {
            Ok(ids) => ids,
            Err(response) => return response,
        };
    match provisioning(&state) {
        Ok(service) => match service.get_application(project_id, application_id).await {
            Ok(application) => control_json(control_application(application), &request_id),
            Err(error) => application_problem(error, &request_id),
        },
        Err(error) => application_problem(error, &request_id),
    }
}

async fn update_application(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, application_id)): Path<(String, String)>,
    ControlJson(body): ControlJson<control_types::UpdateApplicationRequest>,
) -> Response {
    let (project_id, application_id) =
        match resource_pair(&project_id, &application_id, &request_id) {
            Ok(ids) => ids,
            Err(response) => return response,
        };
    match provisioning(&state) {
        Ok(service) => match service
            .update_application(
                project_id,
                application_id,
                UpdateApplication {
                    display_name: body.display_name,
                    expected_metadata_revision: body.expected_metadata_revision,
                },
                request_uuid(&request_id),
            )
            .await
        {
            Ok(application) => control_json(control_application(application), &request_id),
            Err(error) => application_problem(error, &request_id),
        },
        Err(error) => application_problem(error, &request_id),
    }
}

async fn replace_application_configuration(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, application_id)): Path<(String, String)>,
    ControlJson(body): ControlJson<control_types::ReplaceApplicationConfigurationRequest>,
) -> Response {
    let (project_id, application_id) =
        match resource_pair(&project_id, &application_id, &request_id) {
            Ok(ids) => ids,
            Err(response) => return response,
        };
    match provisioning(&state) {
        Ok(service) => match service
            .replace_application_configuration(
                project_id,
                application_id,
                ReplaceApplicationConfiguration {
                    redirect_uris: body.redirect_uris,
                    allowed_origins: body.allowed_origins,
                    expected_security_revision: body.expected_security_revision,
                },
                request_uuid(&request_id),
            )
            .await
        {
            Ok(application) => control_json(control_application(application), &request_id),
            Err(error) => application_problem(error, &request_id),
        },
        Err(error) => application_problem(error, &request_id),
    }
}

async fn disable_application(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, application_id)): Path<(String, String)>,
    ControlJson(body): ControlJson<control_types::ExpectedSecurityRevision>,
) -> Response {
    let (project_id, application_id) =
        match resource_pair(&project_id, &application_id, &request_id) {
            Ok(ids) => ids,
            Err(response) => return response,
        };
    match provisioning(&state) {
        Ok(service) => match service
            .disable_application(
                project_id,
                application_id,
                body.expected_security_revision,
                request_uuid(&request_id),
            )
            .await
        {
            Ok(application) => control_json(control_application(application), &request_id),
            Err(error) => application_problem(error, &request_id),
        },
        Err(error) => application_problem(error, &request_id),
    }
}

async fn list_signing_keys(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path(project_id): Path<String>,
) -> Response {
    let project_id = match resource_uuid(&project_id, &request_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    match provisioning(&state) {
        Ok(service) => match service.list_signing_keys(project_id).await {
            Ok(items) => control_json(
                items
                    .into_iter()
                    .map(control_signing_key)
                    .collect::<Result<Vec<_>, _>>()
                    .map(|items| control_types::SigningKeyList { items }),
                &request_id,
            ),
            Err(error) => application_problem(error, &request_id),
        },
        Err(error) => application_problem(error, &request_id),
    }
}

async fn create_signing_key(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path(project_id): Path<String>,
    headers: HeaderMap,
    ControlJson(body): ControlJson<control_types::CreateSigningKeyRequest>,
) -> Response {
    let project_id = match resource_uuid(&project_id, &request_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    let Ok(operation_alias) = idempotency_key(&headers) else {
        return invalid_idempotency(&request_id);
    };
    match provisioning(&state) {
        Ok(service) => match service
            .provision_signing_key(
                project_id,
                operation_alias,
                body.expected_project_revision,
                request_uuid(&request_id),
            )
            .await
        {
            Ok(key) => control_json(control_signing_key(key), &request_id),
            Err(error) => application_problem(error, &request_id),
        },
        Err(error) => application_problem(error, &request_id),
    }
}

async fn activate_signing_key(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, key_id)): Path<(String, String)>,
    ControlJson(body): ControlJson<control_types::KeyTransitionRequest>,
) -> Response {
    signing_key_transition(state, request_id, project_id, key_id, body, "activate").await
}

async fn retire_signing_key(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, key_id)): Path<(String, String)>,
    ControlJson(body): ControlJson<control_types::KeyTransitionRequest>,
) -> Response {
    signing_key_transition(state, request_id, project_id, key_id, body, "retire").await
}

async fn revoke_signing_key(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, key_id)): Path<(String, String)>,
    ControlJson(body): ControlJson<control_types::KeyTransitionRequest>,
) -> Response {
    signing_key_transition(state, request_id, project_id, key_id, body, "revoke").await
}

async fn signing_key_transition(
    state: ControlState,
    request_id: String,
    project_id: String,
    key_id: String,
    body: control_types::KeyTransitionRequest,
    operation: &str,
) -> Response {
    let (project_id, key_id) = match resource_pair(&project_id, &key_id, &request_id) {
        Ok(ids) => ids,
        Err(response) => return response,
    };
    let service = match provisioning(&state) {
        Ok(service) => service,
        Err(error) => return application_problem(error, &request_id),
    };
    let correlation_id = request_uuid(&request_id);
    let result = match operation {
        "activate" => {
            service
                .activate_signing_key(
                    project_id,
                    key_id,
                    body.expected_ring_revision,
                    correlation_id,
                )
                .await
        }
        "retire" => {
            service
                .retire_signing_key(
                    project_id,
                    key_id,
                    body.expected_ring_revision,
                    correlation_id,
                )
                .await
        }
        _ => {
            service
                .revoke_signing_key(
                    project_id,
                    key_id,
                    body.expected_ring_revision,
                    correlation_id,
                )
                .await
        }
    };
    match result {
        Ok(key) => control_json(control_signing_key(key), &request_id),
        Err(error) => application_problem(error, &request_id),
    }
}

async fn list_providers(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path(project_id): Path<String>,
) -> Response {
    let project_id = match resource_uuid(&project_id, &request_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    match provisioning(&state) {
        Ok(service) => match service.list_providers(project_id).await {
            Ok(items) => control_json(
                items
                    .into_iter()
                    .map(control_provider)
                    .collect::<Result<Vec<_>, _>>()
                    .map(|items| control_types::ProviderList { items }),
                &request_id,
            ),
            Err(error) => application_problem(error, &request_id),
        },
        Err(error) => application_problem(error, &request_id),
    }
}

async fn create_provider(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path(project_id): Path<String>,
    headers: HeaderMap,
    ControlJson(body): ControlJson<control_types::CreateProviderRequest>,
) -> Response {
    let project_id = match resource_uuid(&project_id, &request_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    let Ok(idempotency_key) = idempotency_key(&headers) else {
        return invalid_idempotency(&request_id);
    };
    match provisioning(&state) {
        Ok(service) => match service
            .create_provider(
                project_id,
                CreateProvider {
                    provider_key: body.provider_key,
                    display_name: body.display_name,
                    issuer: body.issuer,
                    client_id: body.client_id,
                    client_secret: zeroize::Zeroizing::new(body.client_secret),
                    idempotency_key,
                    expected_project_revision: body.expected_project_revision,
                },
                request_uuid(&request_id),
            )
            .await
        {
            Ok(provider) => control_json(control_provider(provider), &request_id),
            Err(error) => application_problem(error, &request_id),
        },
        Err(error) => application_problem(error, &request_id),
    }
}

async fn disable_provider(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, provider_id)): Path<(String, String)>,
    ControlJson(body): ControlJson<control_types::ProviderRevisionRequest>,
) -> Response {
    let (project_id, provider_id) = match resource_pair(&project_id, &provider_id, &request_id) {
        Ok(ids) => ids,
        Err(response) => return response,
    };
    match provisioning(&state) {
        Ok(service) => match service
            .disable_provider(
                project_id,
                provider_id,
                body.expected_provider_revision,
                request_uuid(&request_id),
            )
            .await
        {
            Ok(provider) => control_json(control_provider(provider), &request_id),
            Err(error) => application_problem(error, &request_id),
        },
        Err(error) => application_problem(error, &request_id),
    }
}

async fn assign_provider(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, provider_id, application_id)): Path<(String, String, String)>,
    ControlJson(body): ControlJson<control_types::ProviderAssignmentRequest>,
) -> Response {
    provider_assignment(
        state,
        request_id,
        project_id,
        provider_id,
        application_id,
        body,
        true,
    )
    .await
}

async fn unassign_provider(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, provider_id, application_id)): Path<(String, String, String)>,
    ControlJson(body): ControlJson<control_types::ProviderAssignmentRequest>,
) -> Response {
    provider_assignment(
        state,
        request_id,
        project_id,
        provider_id,
        application_id,
        body,
        false,
    )
    .await
}

async fn provider_assignment(
    state: ControlState,
    request_id: String,
    project_id: String,
    provider_id: String,
    application_id: String,
    body: control_types::ProviderAssignmentRequest,
    assign: bool,
) -> Response {
    let project_id = match resource_uuid(&project_id, &request_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    let provider_id = match resource_uuid(&provider_id, &request_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    let application_id = match resource_uuid(&application_id, &request_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    let service = match provisioning(&state) {
        Ok(service) => service,
        Err(error) => return application_problem(error, &request_id),
    };
    let result = if assign {
        service
            .assign_provider(
                project_id,
                provider_id,
                application_id,
                body.expected_application_revision,
                request_uuid(&request_id),
            )
            .await
    } else {
        service
            .unassign_provider(
                project_id,
                provider_id,
                application_id,
                body.expected_application_revision,
                request_uuid(&request_id),
            )
            .await
    };
    match result {
        Ok(provider) => control_json(control_provider(provider), &request_id),
        Err(error) => application_problem(error, &request_id),
    }
}

#[derive(serde::Deserialize)]
struct PublicConfigQuery {
    application_id: String,
}

async fn public_application_config(
    State(state): State<RuntimeState>,
    Extension(request_id): Extension<String>,
    Path(project_public_id): Path<String>,
    query: Result<Query<PublicConfigQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let Ok(Query(query)) = query else {
        return runtime_problem(ApplicationError::InvalidInput, &request_id);
    };
    let service = match readiness(&state) {
        Ok(service) => service,
        Err(error) => return runtime_problem(error, &request_id),
    };
    match service
        .public_application_config(&project_public_id, &query.application_id)
        .await
    {
        Ok(config) => {
            let providers = config
                .providers
                .into_iter()
                .map(runtime_provider)
                .collect::<Result<Vec<_>, _>>();
            runtime_json(
                providers.map(|providers| runtime_types::PublicApplicationConfig {
                    project_public_id: config.project_public_id,
                    project_display_name: config.project_display_name,
                    application_public_id: config.application_public_id,
                    application_display_name: config.application_display_name,
                    publishable_keys: config.publishable_keys,
                    providers,
                    login_available: config.login_available,
                }),
                &request_id,
            )
        }
        Err(error) => runtime_problem(error, &request_id),
    }
}

async fn project_jwks(
    State(state): State<RuntimeState>,
    Extension(request_id): Extension<String>,
    Path(project_public_id): Path<String>,
) -> Response {
    let service = match readiness(&state) {
        Ok(service) => service,
        Err(error) => return runtime_problem(error, &request_id),
    };
    match service.project_jwks(&project_public_id).await {
        Ok(document) => runtime_json(
            document
                .keys
                .into_iter()
                .map(|key| serde_json::from_value(key).map_err(|_| ApplicationError::Integrity))
                .collect::<Result<Vec<_>, _>>()
                .map(|keys| runtime_types::JwksDocument {
                    keys,
                    revision: document.revision,
                    signing_epoch: document.signing_epoch,
                }),
            &request_id,
        ),
        Err(error) => runtime_problem(error, &request_id),
    }
}

fn runtime_provider(
    provider: application::PublicProvider,
) -> Result<runtime_types::PublicProvider, ApplicationError> {
    let kind = match provider.kind.as_str() {
        "oidc" => runtime_types::ProviderKind::Oidc,
        _ => return Err(ApplicationError::Integrity),
    };
    Ok(runtime_types::PublicProvider {
        key: provider.key,
        display_name: provider.display_name,
        kind,
    })
}

fn runtime_json<T>(result: Result<T, ApplicationError>, request_id: &str) -> Response
where
    T: Serialize,
{
    match result {
        Ok(value) => Json(value).into_response(),
        Err(error) => runtime_problem(error, request_id),
    }
}

fn control_project_policy(
    policy: &application::ProjectPolicyRecord,
) -> control_types::ProjectPolicy {
    control_types::ProjectPolicy {
        project_id: policy.project_id.to_string(),
        access_token_lifetime_seconds: policy.access_token_lifetime_seconds,
        browser_session_reuse: policy.browser_session_reuse,
        claims_revision: policy.claims_revision,
        session_revision: policy.session_revision,
    }
}

fn control_project(
    project: application::ProjectRecord,
) -> Result<control_types::Project, ApplicationError> {
    let status = match project.status.as_str() {
        "active" => control_types::ProjectStatus::Active,
        "disabled" => control_types::ProjectStatus::Disabled,
        _ => return Err(ApplicationError::Integrity),
    };
    Ok(control_types::Project {
        id: project.id.to_string(),
        public_id: project.public_id,
        display_name: project.display_name,
        belongs_to: project.belongs_to,
        status,
        metadata_revision: project.metadata_revision,
        security_revision: project.security_revision,
    })
}

fn control_application(
    application: application::ApplicationRecord,
) -> Result<control_types::Application, ApplicationError> {
    let application_type = match application.application_type.as_str() {
        "web" => control_types::ApplicationType::Web,
        "native" => control_types::ApplicationType::Native,
        _ => return Err(ApplicationError::Integrity),
    };
    let status = match application.status.as_str() {
        "active" => control_types::ApplicationStatus::Active,
        "disabled" => control_types::ApplicationStatus::Disabled,
        _ => return Err(ApplicationError::Integrity),
    };
    Ok(control_types::Application {
        id: application.id.to_string(),
        project_id: application.project_id.to_string(),
        public_id: application.public_id,
        display_name: application.display_name,
        application_type,
        status,
        metadata_revision: application.metadata_revision,
        security_revision: application.security_revision,
        configuration: control_types::ApplicationConfiguration {
            redirect_uris: application.configuration.redirect_uris,
            allowed_origins: application.configuration.allowed_origins,
            publishable_keys: application.configuration.publishable_keys,
        },
    })
}

fn control_signing_key(
    key: application::SigningKeyRecord,
) -> Result<control_types::SigningKey, ApplicationError> {
    let algorithm = match key.algorithm.as_str() {
        "EdDSA" => runtime_types::SigningAlgorithm::EdDsa,
        _ => return Err(ApplicationError::Integrity),
    };
    let state = match key.state.as_str() {
        "provisioning" => control_types::SigningKeyState::Provisioning,
        "published" => control_types::SigningKeyState::Published,
        "active" => control_types::SigningKeyState::Active,
        "retiring" => control_types::SigningKeyState::Retiring,
        "retired" => control_types::SigningKeyState::Retired,
        "revoked" => control_types::SigningKeyState::Revoked,
        "abandoned" => control_types::SigningKeyState::Abandoned,
        _ => return Err(ApplicationError::Integrity),
    };
    let public_jwk =
        serde_json::from_value(key.public_jwk).map_err(|_| ApplicationError::Integrity)?;
    Ok(control_types::SigningKey {
        id: key.id.to_string(),
        project_id: key.project_id.to_string(),
        kid: key.kid,
        algorithm,
        state,
        ring_revision: key.ring_revision,
        signing_epoch: key.signing_epoch,
        sign_not_before: key.sign_not_before.map(|value| value.to_string()),
        verify_not_after: key.verify_not_after.map(|value| value.to_string()),
        public_jwk,
    })
}

fn control_provider(
    provider: application::ProviderRecord,
) -> Result<control_types::Provider, ApplicationError> {
    let kind = match provider.kind.as_str() {
        "oidc" => runtime_types::ProviderKind::Oidc,
        _ => return Err(ApplicationError::Integrity),
    };
    let status = match provider.status.as_str() {
        "provisioning" => control_types::ProviderStatus::Provisioning,
        "active" => control_types::ProviderStatus::Active,
        "disabled" => control_types::ProviderStatus::Disabled,
        _ => return Err(ApplicationError::Integrity),
    };
    Ok(control_types::Provider {
        id: provider.id.to_string(),
        project_id: provider.project_id.to_string(),
        provider_key: provider.provider_key,
        kind,
        display_name: provider.display_name,
        issuer: provider.issuer,
        client_id: provider.client_id,
        callback_url: provider.callback_url,
        status,
        revision: provider.revision,
        assigned_application_ids: provider
            .assigned_application_ids
            .into_iter()
            .map(|id| id.to_string())
            .collect(),
    })
}

fn control_json<T>(result: Result<T, ApplicationError>, request_id: &str) -> Response
where
    T: Serialize,
{
    match result {
        Ok(value) => Json(value).into_response(),
        Err(error) => application_problem(error, request_id),
    }
}

fn application_problem(error: ApplicationError, request_id: &str) -> Response {
    let (status, code, title, detail) = match error {
        ApplicationError::InvalidInput => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid request",
            "One or more request values are invalid.",
        ),
        ApplicationError::NotFound => (
            StatusCode::NOT_FOUND,
            "not_found",
            "Resource not found",
            "The requested resource does not exist in this Project.",
        ),
        ApplicationError::Disabled => (
            StatusCode::CONFLICT,
            "resource_disabled",
            "Resource disabled",
            "The requested operation is not available for a disabled resource.",
        ),
        ApplicationError::RevisionConflict => (
            StatusCode::CONFLICT,
            "revision_conflict",
            "Revision conflict",
            "Refresh the resource and retry with its current revision.",
        ),
        ApplicationError::IdempotencyConflict => (
            StatusCode::CONFLICT,
            "idempotency_conflict",
            "Idempotency conflict",
            "The idempotency key was already used for a different request.",
        ),
        ApplicationError::OperationInProgress => (
            StatusCode::CONFLICT,
            "operation_in_progress",
            "Operation in progress",
            "The durable operation has not completed yet.",
        ),
        ApplicationError::PublicationPending => (
            StatusCode::CONFLICT,
            "publication_pending",
            "Publication pending",
            "Runtime has not observed this key revision for the propagation interval.",
        ),
        ApplicationError::InvalidTransition => (
            StatusCode::CONFLICT,
            "invalid_transition",
            "Invalid state transition",
            "The requested lifecycle transition is not allowed.",
        ),
        ApplicationError::Integrity => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "authority_integrity_failure",
            "Authority integrity failure",
            "The authoritative state could not be validated.",
        ),
        ApplicationError::Persistence | ApplicationError::ExternalStore => (
            StatusCode::SERVICE_UNAVAILABLE,
            "authority_unavailable",
            "Authority unavailable",
            "The authoritative store is temporarily unavailable.",
        ),
    };
    control_problem(status, code, title, detail, request_id)
}

fn control_problem(
    status: StatusCode,
    code: &str,
    title: &str,
    detail: &str,
    request_id: &str,
) -> Response {
    (
        status,
        Json(control_types::ProblemDetails {
            type_uri: format!("https://owlauth.dev/problems/{code}"),
            code: code.to_owned(),
            title: title.to_owned(),
            status: status.as_u16(),
            detail: detail.to_owned(),
            request_id: request_id.to_owned(),
        }),
    )
        .into_response()
}

fn runtime_problem(error: ApplicationError, request_id: &str) -> Response {
    let (status, code, message) = match error {
        ApplicationError::NotFound | ApplicationError::Disabled => (
            StatusCode::NOT_FOUND,
            "not_found",
            "The requested public resource was not found.",
        ),
        ApplicationError::InvalidInput => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "The public request is invalid.",
        ),
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            "authority_unavailable",
            "The Runtime authority is temporarily unavailable.",
        ),
    };
    (
        status,
        Json(runtime_types::RuntimeError {
            code: code.to_owned(),
            message: message.to_owned(),
            request_id: request_id.to_owned(),
        }),
    )
        .into_response()
}

#[allow(
    clippy::result_large_err,
    reason = "the error is returned immediately as the HTTP response at every call site"
)]
fn resource_uuid(value: &str, request_id: &str) -> Result<Uuid, Response> {
    let parsed = Uuid::parse_str(value).map_err(|_| {
        control_problem(
            StatusCode::BAD_REQUEST,
            "invalid_resource_id",
            "Invalid resource identifier",
            "Resource identifiers must be canonical UUID values.",
            request_id,
        )
    })?;
    if parsed.to_string() != value {
        return Err(control_problem(
            StatusCode::BAD_REQUEST,
            "invalid_resource_id",
            "Invalid resource identifier",
            "Resource identifiers must be canonical UUID values.",
            request_id,
        ));
    }
    Ok(parsed)
}

#[allow(
    clippy::result_large_err,
    reason = "the error is returned immediately as the HTTP response at every call site"
)]
fn resource_pair(left: &str, right: &str, request_id: &str) -> Result<(Uuid, Uuid), Response> {
    Ok((
        resource_uuid(left, request_id)?,
        resource_uuid(right, request_id)?,
    ))
}

fn request_uuid(request_id: &str) -> Uuid {
    Uuid::parse_str(request_id).unwrap_or_else(|_| Uuid::new_v4())
}

fn idempotency_key(headers: &HeaderMap) -> Result<String, ()> {
    let name = HeaderName::from_static("idempotency-key");
    let mut values = headers.get_all(name).iter();
    let value = values.next().ok_or(())?;
    if values.next().is_some() {
        return Err(());
    }
    let value = value.to_str().map_err(|_| ())?;
    if !(8..=128).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(());
    }
    Ok(value.to_owned())
}

fn invalid_idempotency(request_id: &str) -> Response {
    control_problem(
        StatusCode::BAD_REQUEST,
        "invalid_idempotency_key",
        "Invalid idempotency key",
        "A single 8 to 128 character URL-safe Idempotency-Key is required.",
        request_id,
    )
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
            (
                "OWLAUTH_RUNTIME_PROCESS_ID".to_owned(),
                "http-test-runtime".to_owned(),
            ),
            ("OWLAUTH_CONTROL_API_KEY".to_owned(), key),
            (
                "OWLAUTH_SIGNER_STORE_ROOT".to_owned(),
                "/tmp/owlauth-http-test-signers".to_owned(),
            ),
            (
                "OWLAUTH_SIGNER_STORE_KEY".to_owned(),
                "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE".to_owned(),
            ),
            (
                "OWLAUTH_CONFIGURATION_SECRET_STORE_ROOT".to_owned(),
                "/tmp/owlauth-http-test-secrets".to_owned(),
            ),
            (
                "OWLAUTH_CONFIGURATION_SECRET_STORE_KEY".to_owned(),
                "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI".to_owned(),
            ),
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
        let mut routers = build_routers(&config, None);
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

        let malformed_query = runtime
            .clone()
            .oneshot(
                Request::get("/v1/projects/example/auth/config")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(malformed_query.status(), StatusCode::BAD_REQUEST);
        let malformed_body: runtime_types::RuntimeError =
            serde_json::from_slice(&to_bytes(malformed_query.into_body(), 4096).await.unwrap())
                .unwrap();
        assert_eq!(malformed_body.code, "invalid_request");

        let control = runtime
            .oneshot(Request::get("/v1/system").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(control.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn control_authentication_is_strict_and_base_scoped() {
        let config = test_config(PlaneMode::All);
        let mut routers = build_routers(&config, None);
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
            br#"{"product":"owlauth-server","project_auth":true}"#
        );

        let noncanonical_id = control
            .clone()
            .oneshot(
                Request::get("/control/v1/projects/550E8400-E29B-41D4-A716-446655440000")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer owl_ctrl_v1_{}", "A".repeat(43)),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(noncanonical_id.status(), StatusCode::BAD_REQUEST);
        let problem: control_types::ProblemDetails =
            serde_json::from_slice(&to_bytes(noncanonical_id.into_body(), 4096).await.unwrap())
                .unwrap();
        assert_eq!(problem.code, "invalid_resource_id");

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
        let mut routers = build_routers(&config, None);
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
