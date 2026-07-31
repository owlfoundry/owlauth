use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

use axum::{
    Extension, Json, Router,
    extract::{DefaultBodyLimit, FromRequest, Path, Query, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post, put},
};
use owlauth_types::{
    FEDERATED_PROJECT_AUTH_AVAILABLE, HealthResponse,
    control::{self as control_types, ServiceDescriptor, SystemCapabilities},
    runtime as runtime_types,
};
use sea_orm::DatabaseConnection;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tower::limit::ConcurrencyLimitLayer;
use tower_http::{catch_panic::CatchPanicLayer, timeout::TimeoutLayer};
use tracing::info;
use uuid::Uuid;

use crate::{
    adapters::{
        oidc::RestrictedOidcProviderClient,
        postgres::{
            DatabasePools, authentication::PostgresAuthenticationRepository,
            control_lifecycle::PostgresControlLifecycleRepository,
            provisioning::PostgresProvisioningAdapter, readiness::PostgresReadinessAdapter,
            runtime_authority::PostgresRuntimeAuthorityRepository,
            session_authority::PostgresSessionAuthorityRepository,
        },
        runtime_security::{
            EncryptedFileProviderSecretResolver, EncryptedFileRuntimeSigner, RuntimeKeyMaterial,
            SoftwareRuntimeProtector,
        },
        software_store::EncryptedFileStore,
        system::{Sha256RequestDigester, SystemClock, SystemEntropy},
    },
    application::{
        self, ApplicationError, BeginLogin, ConfirmProjectBrowserLogout, ConfirmSessionReuse,
        ControlLifecycleService, CreateApplication, CreateProject, CreateProvider, ExchangeHandoff,
        ProviderCallback, ProvisioningInfrastructure, ProvisioningService, ReadinessService,
        RefreshSession, ReplaceApplicationConfiguration, RuntimeAuthService, SelectProvider,
        UpdateApplication, UpdateProject, UpdateProjectPolicy,
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
    auth: Option<Arc<RuntimeAuthService>>,
    cookie_path: Arc<str>,
    external_origin: Arc<str>,
}

#[derive(Clone)]
struct ControlState {
    probe: ProbeState,
    operator_key: Arc<OperatorApiKey>,
    descriptor: Arc<ServiceDescriptor>,
    provisioning: Option<Arc<ProvisioningService>>,
    lifecycle: Option<Arc<ControlLifecycleService>>,
}

pub(crate) struct PlaneRouters {
    pub runtime: Option<Router>,
    pub control: Option<Router>,
    pub runtime_auth: Option<Arc<RuntimeAuthService>>,
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
    let runtime_auth = (config.mode.has_runtime() && FEDERATED_PROJECT_AUTH_AVAILABLE)
        .then(|| {
            pools
                .and_then(|pools| pools.runtime.clone())
                .map(|database| build_runtime_auth_service(database, config))
        })
        .flatten();

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
                auth: runtime_auth.clone(),
                cookie_path: Arc::from(config.runtime.external_base.path()),
                external_origin: Arc::from(
                    config.runtime.external_base.origin().ascii_serialization(),
                ),
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
                    .map(|database| build_provisioning_service(database, config)),
                lifecycle: pools
                    .and_then(|pools| pools.control.clone())
                    .map(|database| {
                        Arc::new(ControlLifecycleService::new(
                            Arc::new(PostgresControlLifecycleRepository::new(database)),
                            Arc::new(SystemClock),
                        ))
                    }),
            },
            config,
        )
    });

    PlaneRouters {
        runtime,
        control,
        runtime_auth,
        runtime_ready,
        control_ready,
    }
}

fn build_provisioning_service(
    database: DatabaseConnection,
    config: &ServerConfig,
) -> Arc<ProvisioningService> {
    let provisioning = config
        .provisioning
        .as_ref()
        .expect("validated Control configuration has provisioning stores");
    let signer_store = EncryptedFileStore::new(
        provisioning.signer_store_root.clone(),
        provisioning.signer_store_key.expose_copy(),
    )
    .expect("validated signer store configuration");
    let secret_store = EncryptedFileStore::new(
        provisioning.configuration_secret_store_root.clone(),
        provisioning.configuration_secret_store_key.expose_copy(),
    )
    .expect("validated secret store configuration");
    Arc::new(ProvisioningService::new(
        Arc::new(PostgresProvisioningAdapter::new(
            database,
            config.runtime.external_base.clone(),
            config.required_runtime_process_ids.clone(),
            config.key_propagation_delay,
            config.signing_verification_retention,
        )),
        ProvisioningInfrastructure::new(
            signer_store,
            secret_store,
            SystemClock,
            SystemEntropy,
            Sha256RequestDigester,
            config.provider_allow_http_loopback,
        ),
    ))
}

fn build_runtime_auth_service(
    database: DatabaseConnection,
    config: &ServerConfig,
) -> Arc<RuntimeAuthService> {
    let stores = config
        .provisioning
        .as_ref()
        .expect("validated Runtime configuration has signer and provider-secret stores");
    let protection = config
        .runtime_protection
        .as_ref()
        .expect("validated Runtime configuration has protection keys");
    let signer_store = EncryptedFileStore::new(
        stores.signer_store_root.clone(),
        stores.signer_store_key.expose_copy(),
    )
    .expect("validated signer store configuration");
    let secret_store = EncryptedFileStore::new(
        stores.configuration_secret_store_root.clone(),
        stores.configuration_secret_store_key.expose_copy(),
    )
    .expect("validated provider-secret store configuration");
    let active = RuntimeKeyMaterial::new(
        protection.active.digest_key.expose_copy(),
        protection.active.protection_key.expose_copy(),
    );
    let retained = protection
        .retained
        .iter()
        .map(|(version, keys)| {
            (
                *version,
                RuntimeKeyMaterial::new(
                    keys.digest_key.expose_copy(),
                    keys.protection_key.expose_copy(),
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let protector = SoftwareRuntimeProtector::new(
        config
            .instance_id
            .clone()
            .expect("validated Runtime configuration has an instance ID"),
        protection.active_version,
        active,
        retained,
    )
    .expect("validated Runtime protection configuration");
    let provider = RestrictedOidcProviderClient::new(
        &config.provider_allowed_origins,
        config.provider_allow_http_loopback,
    )
    .expect("validated provider endpoint policy");
    Arc::new(RuntimeAuthService::new(
        Arc::new(PostgresAuthenticationRepository::new(database.clone())),
        Arc::new(PostgresSessionAuthorityRepository::new(database.clone())),
        Arc::new(PostgresRuntimeAuthorityRepository::new(database)),
        Arc::new(protector),
        Arc::new(EncryptedFileRuntimeSigner::new(signer_store)),
        Arc::new(EncryptedFileProviderSecretResolver::new(secret_store)),
        Arc::new(provider),
        Arc::new(SystemClock),
        config.runtime.external_base.clone(),
    ))
}

fn runtime_router(listener: &ListenerConfig, state: RuntimeState, config: &ServerConfig) -> Router {
    let public = Router::new()
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
        .route_layer(middleware::from_fn(reject_runtime_authorization));
    let router = if FEDERATED_PROJECT_AUTH_AVAILABLE {
        public.merge(federated_project_auth_router())
    } else {
        public
    };
    mount_and_bound(
        listener,
        router.with_state(state),
        HttpPlane::Runtime,
        config.request_timeout,
        config.max_request_bytes,
        256,
    )
}

fn federated_project_auth_router() -> Router<RuntimeState> {
    let public = Router::new()
        .route(
            "/v1/projects/{project_public_id}/auth/login/start",
            post(start_login).options(runtime_preflight),
        )
        .route(
            "/v1/projects/{project_public_id}/auth/handoff/exchange",
            post(exchange_handoff).options(runtime_preflight),
        )
        .route(
            "/v1/projects/{project_public_id}/auth/sessions/refresh",
            post(refresh_session).options(runtime_preflight),
        )
        .route(
            "/projects/{project_public_id}/auth/callback/{provider_key}",
            get(provider_callback),
        )
        .route_layer(middleware::from_fn(reject_runtime_authorization));
    let hosted = Router::new()
        .route(
            "/auth/interactions/{interaction}",
            get(hosted_interaction_shell),
        )
        .route(
            "/auth/browser-logout/{preparation}",
            get(browser_logout_shell),
        )
        .route(
            "/v1/projects/{project_public_id}/auth/interactions/{interaction}/method",
            post(select_provider_method),
        )
        .route(
            "/v1/projects/{project_public_id}/auth/interactions/{interaction}/session/reuse",
            post(reuse_browser_session),
        )
        .route(
            "/v1/projects/{project_public_id}/auth/browser-logout/{preparation}/confirm",
            post(confirm_browser_logout),
        )
        .route_layer(middleware::from_fn(reject_runtime_authorization));
    let bearer = Router::new()
        .route(
            "/v1/projects/{project_public_id}/auth/users/me",
            get(current_user).options(runtime_preflight),
        )
        .route(
            "/v1/projects/{project_public_id}/auth/sessions/logout",
            post(logout_application_session).options(runtime_preflight),
        )
        .route(
            "/v1/projects/{project_public_id}/auth/browser-logout/prepare",
            post(prepare_browser_logout).options(runtime_preflight),
        );
    public.merge(hosted).merge(bearer)
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
            "/projects/{project_id}/signing-keys/{key_id}/reconcile",
            post(reconcile_signing_key),
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
            "/projects/{project_id}/providers/{provider_id}/reconcile",
            post(reconcile_provider),
        )
        .route(
            "/projects/{project_id}/providers/{provider_id}/disable",
            post(disable_provider),
        )
        .route(
            "/projects/{project_id}/providers/{provider_id}/assignments/{application_id}",
            put(assign_provider).delete(unassign_provider),
        )
        .merge(control_lifecycle_router())
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

fn control_lifecycle_router() -> Router<ControlState> {
    Router::new()
        .route("/projects/{project_id}/users", get(list_project_users))
        .route(
            "/projects/{project_id}/users/{user_id}",
            get(get_project_user),
        )
        .route(
            "/projects/{project_id}/users/{user_id}/disable",
            post(disable_project_user),
        )
        .route(
            "/projects/{project_id}/users/{user_id}/sessions",
            get(list_project_user_sessions),
        )
        .route(
            "/projects/{project_id}/users/{user_id}/application-sessions/{session_id}/revoke",
            post(revoke_application_session),
        )
        .route(
            "/projects/{project_id}/users/{user_id}/browser-sessions/{session_id}/revoke",
            post(revoke_browser_session),
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

fn runtime_document_error(state: &RuntimeState, title: &str, message: &str) -> Response {
    let serialized = serde_json::json!({ "title": title, "message": message }).to_string();
    web_assets::shell_with_context(
        WebPlane::Runtime,
        &state.probe.base_path,
        &[
            ("owlauth-runtime-flow", "error"),
            ("owlauth-runtime-bootstrap", &serialized),
        ],
    )
}

async fn runtime_asset(Path(path): Path<String>, headers: HeaderMap) -> Response {
    web_assets::asset(WebPlane::Runtime, &format!("assets/{path}"), &headers)
}

async fn runtime_preflight(
    State(state): State<RuntimeState>,
    Extension(request_id): Extension<String>,
    Path(project_public_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Ok(Some(origin)) = request_origin(&headers) else {
        return runtime_error_response(
            StatusCode::FORBIDDEN,
            "origin_not_allowed",
            "The request Origin is not allowed for this Project.",
            &request_id,
        );
    };
    let method = exact_header(&headers, "access-control-request-method");
    if !matches!(method, Some("GET" | "POST"))
        || !valid_preflight_headers(exact_header(&headers, "access-control-request-headers"))
    {
        return runtime_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_preflight",
            "The CORS preflight request is invalid.",
            &request_id,
        );
    }
    let allowed = match runtime_auth(&state) {
        Ok(service) => {
            service
                .project_origin_allowed(&project_public_id, &origin)
                .await
        }
        Err(error) => Err(error),
    };
    match allowed {
        Ok(true) => {
            let mut response = StatusCode::NO_CONTENT.into_response();
            apply_cors(&mut response, &origin, true);
            response
        }
        Ok(false) | Err(ApplicationError::NotFound | ApplicationError::Disabled) => {
            runtime_error_response(
                StatusCode::FORBIDDEN,
                "origin_not_allowed",
                "The request Origin is not allowed for this Project.",
                &request_id,
            )
        }
        Err(error) => runtime_problem(error, &request_id),
    }
}

async fn start_login(
    State(state): State<RuntimeState>,
    Extension(request_id): Extension<String>,
    Path(project_public_id): Path<String>,
    headers: HeaderMap,
    RuntimeJson(request): RuntimeJson<runtime_types::LoginStartRequest>,
) -> Response {
    let cors_origin = match application_cors_origin(
        &state,
        &headers,
        &project_public_id,
        &request.application_id,
        &request.publishable_key,
        &request_id,
    )
    .await
    {
        Ok(origin) => origin,
        Err(response) => return response,
    };
    let result = match runtime_auth(&state) {
        Ok(service) => service
            .begin_login(BeginLogin {
                project_public_id,
                application_public_id: request.application_id,
                publishable_key: request.publishable_key,
                redirect_uri: request.redirect_uri,
                pkce_challenge: request.pkce_challenge,
                application_state: request.state,
                presentation_hint: request.presentation_hint,
            })
            .await
            .map(|pending| runtime_types::LoginStartResponse {
                hosted_url: pending.hosted_url,
                expires_at: timestamp(pending.expires_at),
            }),
        Err(error) => Err(error),
    };
    let mut response = runtime_status_json(StatusCode::CREATED, result, &request_id);
    if let Some(origin) = cors_origin {
        apply_cors(&mut response, &origin, false);
    }
    response
}

async fn hosted_interaction_shell(
    State(state): State<RuntimeState>,
    Extension(request_id): Extension<String>,
    Path(interaction): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !is_top_level_navigation(&headers) {
        return runtime_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_navigation",
            "Hosted authentication must start from a top-level document navigation.",
            &request_id,
        );
    }
    let Ok(interaction_cookie) = interaction_cookie_name(&interaction) else {
        return runtime_document_error(
            &state,
            "Request unavailable",
            "Return to your Application and start sign-in again.",
        );
    };
    let Ok(binding) = cookie_value(&headers, &interaction_cookie) else {
        return runtime_document_error(
            &state,
            "Request unavailable",
            "Return to your Application and start sign-in again.",
        );
    };
    let bootstrap = match runtime_auth(&state) {
        Ok(service) => {
            service
                .bootstrap_interaction(&interaction, binding.as_deref())
                .await
        }
        Err(error) => Err(error),
    };
    let Ok(bootstrap) = bootstrap else {
        return runtime_document_error(
            &state,
            "Sign-in unavailable",
            "Return to your Application and start sign-in again.",
        );
    };
    let reuse_available = match cookie_value(
        &headers,
        &project_session_cookie_name(&bootstrap.interaction.project_public_id),
    ) {
        Ok(Some(browser_session)) => match runtime_auth(&state) {
            Ok(service) => match service
                .browser_session_reuse_available(bootstrap.interaction.project_id, &browser_session)
                .await
            {
                Ok(available) => available,
                Err(ApplicationError::InvalidInput | ApplicationError::NotFound) => false,
                Err(error) => return runtime_problem(error, &request_id),
            },
            Err(error) => return runtime_problem(error, &request_id),
        },
        Ok(None) | Err(()) => false,
    };
    let Ok(body) = hosted_interaction_response(&bootstrap, reuse_available) else {
        return runtime_document_error(
            &state,
            "Sign-in unavailable",
            "Return to your Application and start sign-in again.",
        );
    };
    let Ok(serialized) = serde_json::to_string(&body) else {
        return runtime_document_error(
            &state,
            "Sign-in unavailable",
            "Return to your Application and start sign-in again.",
        );
    };
    let mut response = web_assets::shell_with_context(
        WebPlane::Runtime,
        &state.probe.base_path,
        &[
            ("owlauth-runtime-flow", "interaction"),
            ("owlauth-runtime-bootstrap", &serialized),
        ],
    );
    append_cookie(
        &mut response,
        &interaction_cookie,
        &bootstrap.browser_binding,
        &state.cookie_path,
        600,
    );
    response
}

async fn select_provider_method(
    State(state): State<RuntimeState>,
    Extension(request_id): Extension<String>,
    Path((project_public_id, interaction)): Path<(String, String)>,
    headers: HeaderMap,
    RuntimeJson(request): RuntimeJson<runtime_types::SelectProviderRequest>,
) -> Response {
    if !is_same_origin_mutation(&headers, &state.external_origin) {
        return forbidden_hosted_request(&request_id);
    }
    let Ok(binding) = required_interaction_cookie(&headers, &interaction) else {
        return invalid_cookie(&request_id);
    };
    let result = match runtime_auth(&state) {
        Ok(service) => service
            .select_provider(SelectProvider {
                project_public_id,
                interaction,
                browser_binding: binding,
                csrf: request.csrf,
                expected_revision: request.expected_revision,
                provider_key: request.provider_key,
            })
            .await
            .map(|url| runtime_types::NavigationResponse { url }),
        Err(error) => Err(error),
    };
    runtime_json(result, &request_id)
}

async fn reuse_browser_session(
    State(state): State<RuntimeState>,
    Extension(request_id): Extension<String>,
    Path((project_public_id, interaction)): Path<(String, String)>,
    headers: HeaderMap,
    RuntimeJson(request): RuntimeJson<runtime_types::ConfirmSessionReuseRequest>,
) -> Response {
    if !is_same_origin_mutation(&headers, &state.external_origin) {
        return forbidden_hosted_request(&request_id);
    }
    let Ok(binding) = required_interaction_cookie(&headers, &interaction) else {
        return invalid_cookie(&request_id);
    };
    let Ok(Some(browser_session)) =
        cookie_value(&headers, &project_session_cookie_name(&project_public_id))
    else {
        return invalid_cookie(&request_id);
    };
    let interaction_cookie = interaction_cookie_name(&interaction).ok();
    let result = match runtime_auth(&state) {
        Ok(service) => service
            .confirm_session_reuse(ConfirmSessionReuse {
                project_public_id,
                interaction,
                browser_binding: binding,
                csrf: request.csrf,
                browser_session,
                expected_revision: request.expected_revision,
            })
            .await
            .map(|completion| runtime_types::NavigationResponse {
                url: completion.redirect_url,
            }),
        Err(error) => Err(error),
    };
    let succeeded = result.is_ok();
    let mut response = runtime_json(result, &request_id);
    if succeeded && let Some(name) = interaction_cookie {
        clear_cookie(&mut response, &name, &state.cookie_path);
    }
    response
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderCallbackQuery {
    code: String,
    state: String,
}

async fn provider_callback(
    State(state): State<RuntimeState>,
    Path((project_public_id, provider_key)): Path<(String, String)>,
    Query(query): Query<ProviderCallbackQuery>,
    headers: HeaderMap,
) -> Response {
    let Ok(interaction_cookie) = interaction_cookie_name(&query.state) else {
        return runtime_document_error(
            &state,
            "Sign-in unavailable",
            "Return to your Application and start sign-in again.",
        );
    };
    let Ok(Some(browser_binding)) = cookie_value(&headers, &interaction_cookie) else {
        return runtime_document_error(
            &state,
            "Sign-in unavailable",
            "Return to your Application and start sign-in again.",
        );
    };
    let project_cookie = project_session_cookie_name(&project_public_id);
    let Ok(existing_browser_session) = cookie_value(&headers, &project_cookie) else {
        return runtime_document_error(
            &state,
            "Sign-in unavailable",
            "Return to your Application and start sign-in again.",
        );
    };
    let completion = match runtime_auth(&state) {
        Ok(service) => {
            service
                .complete_provider_callback(ProviderCallback {
                    project_public_id: project_public_id.clone(),
                    provider_key,
                    state: query.state,
                    code: query.code,
                    browser_binding,
                    existing_browser_session,
                })
                .await
        }
        Err(error) => Err(error),
    };
    let Ok(completion) = completion else {
        return runtime_document_error(
            &state,
            "Sign-in could not be completed",
            "Return to your Application and start sign-in again.",
        );
    };
    if completion.project_public_id != project_public_id {
        return runtime_document_error(
            &state,
            "Sign-in could not be completed",
            "Return to your Application and start sign-in again.",
        );
    }
    let mut response = Redirect::to(&completion.redirect_url).into_response();
    append_cookie(
        &mut response,
        &project_cookie,
        &completion.browser_session,
        &state.cookie_path,
        86_400,
    );
    clear_cookie(&mut response, &interaction_cookie, &state.cookie_path);
    response
}

async fn exchange_handoff(
    State(state): State<RuntimeState>,
    Extension(request_id): Extension<String>,
    Path(project_public_id): Path<String>,
    headers: HeaderMap,
    RuntimeJson(request): RuntimeJson<runtime_types::HandoffExchangeRequest>,
) -> Response {
    let cors_origin = match application_cors_origin(
        &state,
        &headers,
        &project_public_id,
        &request.application_id,
        &request.publishable_key,
        &request_id,
    )
    .await
    {
        Ok(origin) => origin,
        Err(response) => return response,
    };
    let result = match runtime_auth(&state) {
        Ok(service) => service
            .exchange_handoff(ExchangeHandoff {
                project_public_id,
                application_public_id: request.application_id,
                publishable_key: request.publishable_key,
                handoff: request.handoff,
                pkce_verifier: request.pkce_verifier,
            })
            .await
            .and_then(credential_pair_response),
        Err(error) => Err(error),
    };
    let mut response = runtime_json(result, &request_id);
    if let Some(origin) = cors_origin {
        apply_cors(&mut response, &origin, false);
    }
    response
}

async fn refresh_session(
    State(state): State<RuntimeState>,
    Extension(request_id): Extension<String>,
    Path(project_public_id): Path<String>,
    headers: HeaderMap,
    RuntimeJson(request): RuntimeJson<runtime_types::RefreshRequest>,
) -> Response {
    let cors_origin = match application_cors_origin(
        &state,
        &headers,
        &project_public_id,
        &request.application_id,
        &request.publishable_key,
        &request_id,
    )
    .await
    {
        Ok(origin) => origin,
        Err(response) => return response,
    };
    let result = match runtime_auth(&state) {
        Ok(service) => service
            .refresh(RefreshSession {
                project_public_id,
                application_public_id: request.application_id,
                publishable_key: request.publishable_key,
                refresh_token: request.refresh_token,
            })
            .await
            .and_then(credential_pair_response),
        Err(error) => Err(error),
    };
    let mut response = runtime_json(result, &request_id);
    if let Some(origin) = cors_origin {
        apply_cors(&mut response, &origin, false);
    }
    response
}

async fn current_user(
    State(state): State<RuntimeState>,
    Extension(request_id): Extension<String>,
    Path(project_public_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let cors_origin =
        match project_cors_origin(&state, &headers, &project_public_id, &request_id).await {
            Ok(origin) => origin,
            Err(response) => return response,
        };
    let Ok(token) = bearer_token(&headers) else {
        return unauthorized_runtime(&request_id);
    };
    let result = match runtime_auth(&state) {
        Ok(service) => match service.current_user(&token).await {
            Ok(current) => {
                let origin_allowed = match cors_origin.as_deref() {
                    Some(origin) => {
                        service
                            .application_session_origin_allowed(
                                current.project_id,
                                current.application_id,
                                origin,
                            )
                            .await
                    }
                    None => Ok(true),
                };
                if current.project_public_id != project_public_id || origin_allowed != Ok(true) {
                    Err(ApplicationError::NotFound)
                } else {
                    user_projection(current.projection_document).map(|projection| {
                        runtime_types::CurrentUserResponse {
                            project_id: current.project_public_id,
                            application_id: current.application_public_id,
                            user_id: current.user_public_id,
                            projection,
                            projection_revision: current.projection_revision,
                            authenticated_at: timestamp(current.authenticated_at),
                            session_expires_at: timestamp(current.absolute_expires_at),
                        }
                    })
                }
            }
            Err(error) => Err(error),
        },
        Err(error) => Err(error),
    };
    let mut response = runtime_auth_json(StatusCode::OK, result, &request_id);
    if let Some(origin) = cors_origin {
        apply_cors(&mut response, &origin, false);
    }
    response
}

async fn logout_application_session(
    State(state): State<RuntimeState>,
    Extension(request_id): Extension<String>,
    Path(project_public_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let cors_origin =
        match project_cors_origin(&state, &headers, &project_public_id, &request_id).await {
            Ok(origin) => origin,
            Err(response) => return response,
        };
    let Ok(token) = bearer_token(&headers) else {
        return unauthorized_runtime(&request_id);
    };
    let result = match runtime_auth(&state) {
        Ok(service) => match service.application_logout_target(&token).await {
            Ok(current) => {
                let origin_allowed = match cors_origin.as_deref() {
                    Some(origin) => {
                        service
                            .application_session_origin_allowed(
                                current.project_id,
                                current.application_id,
                                origin,
                            )
                            .await
                    }
                    None => Ok(true),
                };
                if current.project_public_id != project_public_id || origin_allowed != Ok(true) {
                    Err(ApplicationError::NotFound)
                } else {
                    service
                        .logout_application(current)
                        .await
                        .map(|()| runtime_types::CompletionResponse { completed: true })
                }
            }
            Err(error) => Err(error),
        },
        Err(error) => Err(error),
    };
    let mut response = runtime_auth_json(StatusCode::OK, result, &request_id);
    if let Some(origin) = cors_origin {
        apply_cors(&mut response, &origin, false);
    }
    response
}

async fn prepare_browser_logout(
    State(state): State<RuntimeState>,
    Extension(request_id): Extension<String>,
    Path(project_public_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let cors_origin =
        match project_cors_origin(&state, &headers, &project_public_id, &request_id).await {
            Ok(origin) => origin,
            Err(response) => return response,
        };
    let Ok(token) = bearer_token(&headers) else {
        return unauthorized_runtime(&request_id);
    };
    let result = match runtime_auth(&state) {
        Ok(service) => match service.current_user(&token).await {
            Ok(current) => {
                let origin_allowed = match cors_origin.as_deref() {
                    Some(origin) => {
                        service
                            .application_session_origin_allowed(
                                current.project_id,
                                current.application_id,
                                origin,
                            )
                            .await
                    }
                    None => Ok(true),
                };
                if current.project_public_id != project_public_id || origin_allowed != Ok(true) {
                    Err(ApplicationError::NotFound)
                } else {
                    service.prepare_browser_logout(&token).await.map(|target| {
                        runtime_types::BrowserLogoutPreparationResponse {
                            hosted_url: target.hosted_url,
                            expires_at: timestamp(target.expires_at),
                        }
                    })
                }
            }
            Err(error) => Err(error),
        },
        Err(error) => Err(error),
    };
    let mut response = runtime_auth_json(StatusCode::CREATED, result, &request_id);
    if let Some(origin) = cors_origin {
        apply_cors(&mut response, &origin, false);
    }
    response
}

async fn browser_logout_shell(
    State(state): State<RuntimeState>,
    Extension(request_id): Extension<String>,
    Path(preparation): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !is_top_level_navigation(&headers) {
        return runtime_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_navigation",
            "Browser logout confirmation requires a top-level document navigation.",
            &request_id,
        );
    }
    let Ok(service) = runtime_auth(&state) else {
        return runtime_document_error(
            &state,
            "Sign-out unavailable",
            "Close this page and return to your Application.",
        );
    };
    let Ok(project_public_id) = service.browser_logout_project(&preparation).await else {
        return runtime_document_error(
            &state,
            "Sign-out unavailable",
            "Close this page and return to your Application.",
        );
    };
    let Ok(Some(browser_session)) =
        cookie_value(&headers, &project_session_cookie_name(&project_public_id))
    else {
        return runtime_document_error(
            &state,
            "Sign-out unavailable",
            "Close this page and return to your Application.",
        );
    };
    let Ok(bound) = service
        .bind_browser_logout(&preparation, &browser_session)
        .await
    else {
        return runtime_document_error(
            &state,
            "Sign-out unavailable",
            "Close this page and return to your Application.",
        );
    };
    let bootstrap = runtime_types::BrowserLogoutResponse {
        project_id: bound.project_public_id,
        revision: bound.revision,
        csrf: bound.csrf.to_string(),
        expires_at: timestamp(bound.expires_at),
    };
    let Ok(serialized) = serde_json::to_string(&bootstrap) else {
        return runtime_document_error(
            &state,
            "Sign-out unavailable",
            "Close this page and return to your Application.",
        );
    };
    web_assets::shell_with_context(
        WebPlane::Runtime,
        &state.probe.base_path,
        &[
            ("owlauth-runtime-flow", "browser-logout"),
            ("owlauth-runtime-bootstrap", &serialized),
        ],
    )
}

async fn confirm_browser_logout(
    State(state): State<RuntimeState>,
    Extension(request_id): Extension<String>,
    Path((project_public_id, preparation)): Path<(String, String)>,
    headers: HeaderMap,
    RuntimeJson(request): RuntimeJson<runtime_types::ConfirmBrowserLogoutRequest>,
) -> Response {
    if !is_same_origin_mutation(&headers, &state.external_origin) {
        return forbidden_hosted_request(&request_id);
    }
    let cookie_name = project_session_cookie_name(&project_public_id);
    let Ok(Some(browser_session)) = cookie_value(&headers, &cookie_name) else {
        return invalid_cookie(&request_id);
    };
    let result = match runtime_auth(&state) {
        Ok(service) => service
            .confirm_browser_logout(ConfirmProjectBrowserLogout {
                project_public_id,
                preparation,
                browser_session,
                csrf: request.csrf,
                expected_revision: request.expected_revision,
            })
            .await
            .map(|_| runtime_types::CompletionResponse { completed: true }),
        Err(error) => Err(error),
    };
    let mut response = runtime_json(result, &request_id);
    if response.status().is_success() {
        clear_cookie(&mut response, &cookie_name, &state.cookie_path);
    }
    response
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
    Json(control_types::get_system())
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

struct RuntimeJson<T>(T);

impl<S, T> FromRequest<S> for RuntimeJson<T>
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
                runtime_error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_json",
                    "The request body must be bounded JSON matching the operation schema.",
                    &request_id,
                )
            })
    }
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

fn control_lifecycle(state: &ControlState) -> Result<&ControlLifecycleService, ApplicationError> {
    state
        .lifecycle
        .as_deref()
        .ok_or(ApplicationError::Persistence)
}

fn readiness(state: &RuntimeState) -> Result<&ReadinessService, ApplicationError> {
    state
        .readiness
        .as_deref()
        .ok_or(ApplicationError::Persistence)
}

fn runtime_auth(state: &RuntimeState) -> Result<&RuntimeAuthService, ApplicationError> {
    state.auth.as_deref().ok_or(ApplicationError::Persistence)
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

async fn list_project_users(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path(project_id): Path<String>,
) -> Response {
    let project_id = match resource_uuid(&project_id, &request_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    match control_lifecycle(&state) {
        Ok(service) => match service.list_project_users(project_id).await {
            Ok(users) => Json(control_types::ProjectUserList {
                items: users.into_iter().map(control_project_user).collect(),
            })
            .into_response(),
            Err(error) => application_problem(error, &request_id),
        },
        Err(error) => application_problem(error, &request_id),
    }
}

async fn get_project_user(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, user_id)): Path<(String, String)>,
) -> Response {
    let project_id = match resource_uuid(&project_id, &request_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    let user_id = match resource_uuid(&user_id, &request_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    match control_lifecycle(&state) {
        Ok(service) => match service.get_project_user(project_id, user_id).await {
            Ok(user) => Json(control_project_user(user)).into_response(),
            Err(error) => application_problem(error, &request_id),
        },
        Err(error) => application_problem(error, &request_id),
    }
}

async fn disable_project_user(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, user_id)): Path<(String, String)>,
    ControlJson(body): ControlJson<control_types::ExpectedSecurityRevision>,
) -> Response {
    let project_id = match resource_uuid(&project_id, &request_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    let user_id = match resource_uuid(&user_id, &request_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    match control_lifecycle(&state) {
        Ok(service) => match service
            .disable_project_user(
                project_id,
                user_id,
                body.expected_security_revision,
                request_uuid(&request_id),
            )
            .await
        {
            Ok(user) => Json(control_project_user(user)).into_response(),
            Err(error) => application_problem(error, &request_id),
        },
        Err(error) => application_problem(error, &request_id),
    }
}

async fn list_project_user_sessions(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, user_id)): Path<(String, String)>,
) -> Response {
    let project_id = match resource_uuid(&project_id, &request_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    let user_id = match resource_uuid(&user_id, &request_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    match control_lifecycle(&state) {
        Ok(service) => match service
            .list_project_user_sessions(project_id, user_id)
            .await
        {
            Ok(sessions) => Json(control_types::ProjectUserSessions {
                application_sessions: sessions
                    .application_sessions
                    .into_iter()
                    .map(control_application_session)
                    .collect(),
                browser_sessions: sessions
                    .browser_sessions
                    .iter()
                    .map(control_browser_session)
                    .collect(),
            })
            .into_response(),
            Err(error) => application_problem(error, &request_id),
        },
        Err(error) => application_problem(error, &request_id),
    }
}

async fn revoke_application_session(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, user_id, session_id)): Path<(String, String, String)>,
    ControlJson(body): ControlJson<control_types::ExpectedSessionRevision>,
) -> Response {
    let project_id = match resource_uuid(&project_id, &request_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    let user_id = match resource_uuid(&user_id, &request_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    let session_id = match resource_uuid(&session_id, &request_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    match control_lifecycle(&state) {
        Ok(service) => match service
            .revoke_application_session(
                project_id,
                user_id,
                session_id,
                body.expected_session_revision,
                request_uuid(&request_id),
            )
            .await
        {
            Ok(session) => Json(control_application_session(session)).into_response(),
            Err(error) => application_problem(error, &request_id),
        },
        Err(error) => application_problem(error, &request_id),
    }
}

async fn revoke_browser_session(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, user_id, session_id)): Path<(String, String, String)>,
    ControlJson(body): ControlJson<control_types::ExpectedSessionRevision>,
) -> Response {
    let project_id = match resource_uuid(&project_id, &request_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    let user_id = match resource_uuid(&user_id, &request_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    let session_id = match resource_uuid(&session_id, &request_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    match control_lifecycle(&state) {
        Ok(service) => match service
            .revoke_browser_session(
                project_id,
                user_id,
                session_id,
                body.expected_session_revision,
                request_uuid(&request_id),
            )
            .await
        {
            Ok(session) => Json(control_browser_session(&session)).into_response(),
            Err(error) => application_problem(error, &request_id),
        },
        Err(error) => application_problem(error, &request_id),
    }
}

fn timestamp(value: OffsetDateTime) -> String {
    value
        .format(&Rfc3339)
        .expect("application timestamps must be representable as RFC 3339")
}

fn control_project_user(user: application::ProjectUserRecord) -> control_types::ProjectUser {
    control_types::ProjectUser {
        id: user.id.to_string(),
        project_id: user.project_id.to_string(),
        public_id: user.public_id,
        status: match user.status {
            application::ProjectUserStatus::Active => control_types::ProjectUserStatus::Active,
            application::ProjectUserStatus::Disabled => control_types::ProjectUserStatus::Disabled,
        },
        user_revision: user.user_revision,
        security_revision: user.security_revision,
        display_name: user.display_name,
        picture_url: user.picture_url,
        created_at: timestamp(user.created_at),
        updated_at: timestamp(user.updated_at),
    }
}

fn control_session_status(
    status: application::ManagedSessionStatus,
) -> control_types::ManagedSessionStatus {
    match status {
        application::ManagedSessionStatus::Active => control_types::ManagedSessionStatus::Active,
        application::ManagedSessionStatus::Revoked => control_types::ManagedSessionStatus::Revoked,
        application::ManagedSessionStatus::Expired => control_types::ManagedSessionStatus::Expired,
    }
}

fn control_application_session(
    session: application::ApplicationSessionRecord,
) -> control_types::ApplicationSession {
    control_types::ApplicationSession {
        id: session.id.to_string(),
        project_id: session.project_id.to_string(),
        user_id: session.user_id.to_string(),
        application_id: session.application_id.to_string(),
        application_public_id: session.application_public_id,
        application_display_name: session.application_display_name,
        browser_session_id: session.browser_session_id.map(|id| id.to_string()),
        status: control_session_status(session.status),
        session_revision: session.session_revision,
        authenticated_at: timestamp(session.authenticated_at),
        absolute_expires_at: timestamp(session.absolute_expires_at),
        revoked_at: session.revoked_at.map(timestamp),
        created_at: timestamp(session.created_at),
        updated_at: timestamp(session.updated_at),
    }
}

fn control_browser_session(
    session: &application::BrowserSessionRecord,
) -> control_types::BrowserSession {
    control_types::BrowserSession {
        id: session.id.to_string(),
        project_id: session.project_id.to_string(),
        user_id: session.user_id.to_string(),
        status: control_session_status(session.status),
        session_revision: session.session_revision,
        authenticated_at: timestamp(session.authenticated_at),
        last_activity_at: timestamp(session.last_activity_at),
        idle_expires_at: timestamp(session.idle_expires_at),
        absolute_expires_at: timestamp(session.absolute_expires_at),
        terminated_at: session.terminated_at.map(timestamp),
        created_at: timestamp(session.created_at),
        updated_at: timestamp(session.updated_at),
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

async fn reconcile_signing_key(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, key_id)): Path<(String, String)>,
    ControlJson(body): ControlJson<control_types::ReconcileSigningKeyRequest>,
) -> Response {
    let (project_id, key_id) = match resource_pair(&project_id, &key_id, &request_id) {
        Ok(ids) => ids,
        Err(response) => return response,
    };
    match provisioning(&state) {
        Ok(service) => match service
            .reconcile_signing_key(
                project_id,
                key_id,
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

async fn reconcile_provider(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, provider_id)): Path<(String, String)>,
    ControlJson(body): ControlJson<control_types::ReconcileProviderRequest>,
) -> Response {
    let (project_id, provider_id) = match resource_pair(&project_id, &provider_id, &request_id) {
        Ok(ids) => ids,
        Err(response) => return response,
    };
    match provisioning(&state) {
        Ok(service) => match service
            .reconcile_provider(
                project_id,
                provider_id,
                zeroize::Zeroizing::new(body.client_secret),
                body.expected_project_revision,
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
    headers: HeaderMap,
    query: Result<Query<PublicConfigQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let Ok(Query(query)) = query else {
        return runtime_problem(ApplicationError::InvalidInput, &request_id);
    };
    let cors_origin = match public_application_cors_origin(
        &state,
        &headers,
        &project_public_id,
        &query.application_id,
        &request_id,
    )
    .await
    {
        Ok(origin) => origin,
        Err(response) => return response,
    };
    let result = match (readiness(&state), runtime_auth(&state)) {
        (Ok(readiness), Ok(auth)) => match readiness
            .public_application_config(&project_public_id, &query.application_id)
            .await
        {
            Ok(config) => {
                let structurally_available = config.login_available;
                let providers = config
                    .providers
                    .into_iter()
                    .filter(|provider| auth.provider_issuer_allowed(&provider.issuer))
                    .map(runtime_provider)
                    .collect::<Result<Vec<_>, _>>();
                providers.map(|providers| runtime_types::PublicApplicationConfig {
                    project_public_id: config.project_public_id,
                    project_display_name: config.project_display_name,
                    application_public_id: config.application_public_id,
                    application_display_name: config.application_display_name,
                    publishable_keys: config.publishable_keys,
                    login_available: FEDERATED_PROJECT_AUTH_AVAILABLE
                        && structurally_available
                        && !providers.is_empty(),
                    providers,
                })
            }
            Err(error) => Err(error),
        },
        (Err(error), _) | (_, Err(error)) => Err(error),
    };
    let mut response = runtime_json(result, &request_id);
    if let Some(origin) = cors_origin {
        apply_cors(&mut response, &origin, false);
    }
    response
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

fn runtime_status_json<T>(
    status: StatusCode,
    result: Result<T, ApplicationError>,
    request_id: &str,
) -> Response
where
    T: Serialize,
{
    match result {
        Ok(value) => (status, Json(value)).into_response(),
        Err(error) => runtime_problem(error, request_id),
    }
}

fn runtime_auth_json<T>(
    success_status: StatusCode,
    result: Result<T, ApplicationError>,
    request_id: &str,
) -> Response
where
    T: Serialize,
{
    match result {
        Ok(value) => (success_status, Json(value)).into_response(),
        Err(
            ApplicationError::Integrity
            | ApplicationError::Persistence
            | ApplicationError::ExternalStore,
        ) => runtime_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "authority_unavailable",
            "The Runtime authority is temporarily unavailable.",
            request_id,
        ),
        Err(_) => unauthorized_runtime(request_id),
    }
}

fn credential_pair_response(
    pair: application::CredentialPair,
) -> Result<runtime_types::CredentialPairResponse, ApplicationError> {
    Ok(runtime_types::CredentialPairResponse {
        project_id: pair.project_public_id,
        application_id: pair.application_public_id,
        user_id: pair.user_public_id,
        session_id: pair.application_session_id.to_string(),
        refresh_generation: pair.refresh_generation,
        access_token: pair.access_token.to_string(),
        refresh_token: pair.refresh_token.to_string(),
        token_type: pair.token_type,
        expires_in: pair.expires_in,
        projection: user_projection(pair.projection)?,
        projection_revision: pair.projection_revision,
        session_expires_at: timestamp(pair.session_expires_at),
    })
}

fn user_projection(
    document: serde_json::Value,
) -> Result<runtime_types::UserProjection, ApplicationError> {
    serde_json::from_value(document).map_err(|_| ApplicationError::Integrity)
}

fn hosted_interaction_response(
    bootstrap: &application::HostedBootstrap,
    session_reuse_available: bool,
) -> Result<runtime_types::HostedInteractionResponse, ApplicationError> {
    let status = match bootstrap.interaction.status.as_str() {
        "awaiting_method_selection" => {
            runtime_types::HostedInteractionStatus::AwaitingMethodSelection
        }
        "provider_authorization_started" => {
            runtime_types::HostedInteractionStatus::ProviderAuthorizationStarted
        }
        "provider_exchange_in_progress" => {
            runtime_types::HostedInteractionStatus::ProviderExchangeInProgress
        }
        "provider_exchange_failed" | "cancelled" => runtime_types::HostedInteractionStatus::Failed,
        "authenticated" => runtime_types::HostedInteractionStatus::Authenticated,
        "handoff_issued" => runtime_types::HostedInteractionStatus::HandoffIssued,
        "completed" => runtime_types::HostedInteractionStatus::Completed,
        "expired" => runtime_types::HostedInteractionStatus::Expired,
        _ => return Err(ApplicationError::Integrity),
    };
    Ok(runtime_types::HostedInteractionResponse {
        project_id: bootstrap.interaction.project_public_id.clone(),
        project_display_name: bootstrap.interaction.project_display_name.clone(),
        application_id: bootstrap.interaction.application_public_id.clone(),
        application_display_name: bootstrap.interaction.application_display_name.clone(),
        application_type: match bootstrap.interaction.application_type {
            ApplicationType::Web => runtime_types::HostedApplicationType::Web,
            ApplicationType::Native => runtime_types::HostedApplicationType::Native,
        },
        status,
        revision: bootstrap.interaction.transaction_revision,
        session_reuse_available,
        presentation_hint: bootstrap.interaction.presentation_hint.clone(),
        providers: bootstrap
            .interaction
            .providers
            .iter()
            .map(|provider| runtime_types::HostedProvider {
                key: provider.key.clone(),
                display_name: provider.display_name.clone(),
            })
            .collect(),
        csrf: bootstrap.csrf.to_string(),
        expires_at: timestamp(bootstrap.interaction.expires_at),
    })
}

fn validate_interaction_credential(credential: &str) -> Result<Uuid, ()> {
    let id = credential.split('.').next().ok_or(())?;
    let parsed = Uuid::parse_str(id).map_err(|_| ())?;
    if parsed.to_string() != id {
        return Err(());
    }
    Ok(parsed)
}

fn interaction_cookie_name(credential: &str) -> Result<String, ()> {
    let id = validate_interaction_credential(credential)?;
    let digest = Sha256::digest(id.as_bytes());
    Ok(format!(
        "owl_runtime_{}",
        URL_SAFE_NO_PAD.encode(&digest[..18])
    ))
}

fn project_session_cookie_name(project_public_id: &str) -> String {
    let digest = Sha256::digest(project_public_id.as_bytes());
    format!("owl_project_{}", URL_SAFE_NO_PAD.encode(&digest[..18]))
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Result<Option<String>, ()> {
    let values = headers.get_all(header::COOKIE);
    let mut iter = values.iter();
    let Some(header_value) = iter.next() else {
        return Ok(None);
    };
    if iter.next().is_some() {
        return Err(());
    }
    let value = header_value.to_str().map_err(|_| ())?;
    let mut found = None;
    for pair in value.split(';') {
        let (candidate, value) = pair.trim().split_once('=').ok_or(())?;
        if candidate == name {
            if found.is_some()
                || value.is_empty()
                || value.len() > 512
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            {
                return Err(());
            }
            found = Some(value.to_owned());
        }
    }
    Ok(found)
}

fn required_interaction_cookie(headers: &HeaderMap, interaction: &str) -> Result<String, ()> {
    cookie_value(headers, &interaction_cookie_name(interaction)?)?.ok_or(())
}

fn append_cookie(response: &mut Response, name: &str, value: &str, path: &str, max_age: i64) {
    let value =
        format!("{name}={value}; Path={path}; Max-Age={max_age}; Secure; HttpOnly; SameSite=Lax");
    if let Ok(value) = HeaderValue::from_str(&value) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

fn clear_cookie(response: &mut Response, name: &str, path: &str) {
    let value = format!("{name}=deleted; Path={path}; Max-Age=0; Secure; HttpOnly; SameSite=Lax");
    if let Ok(value) = HeaderValue::from_str(&value) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

async fn application_cors_origin(
    state: &RuntimeState,
    headers: &HeaderMap,
    project_public_id: &str,
    application_public_id: &str,
    publishable_key: &str,
    request_id: &str,
) -> Result<Option<String>, Response> {
    let origin = request_origin(headers).map_err(|()| {
        runtime_error_response(
            StatusCode::FORBIDDEN,
            "origin_not_allowed",
            "The request Origin is not allowed for this Application.",
            request_id,
        )
    })?;
    let Some(origin) = origin else {
        return Ok(None);
    };
    let allowed = runtime_auth(state)
        .map_err(|error| runtime_problem(error, request_id))?
        .application_origin_allowed(
            project_public_id,
            application_public_id,
            publishable_key,
            &origin,
        )
        .await
        .map_err(|error| runtime_problem(error, request_id))?;
    if !allowed {
        return Err(runtime_error_response(
            StatusCode::FORBIDDEN,
            "origin_not_allowed",
            "The request Origin is not allowed for this Application.",
            request_id,
        ));
    }
    Ok(Some(origin))
}

async fn public_application_cors_origin(
    state: &RuntimeState,
    headers: &HeaderMap,
    project_public_id: &str,
    application_public_id: &str,
    request_id: &str,
) -> Result<Option<String>, Response> {
    let origin = request_origin(headers).map_err(|()| {
        runtime_error_response(
            StatusCode::FORBIDDEN,
            "origin_not_allowed",
            "The request Origin is not allowed for this Application.",
            request_id,
        )
    })?;
    let Some(origin) = origin else {
        return Ok(None);
    };
    let allowed = runtime_auth(state)
        .map_err(|error| runtime_problem(error, request_id))?
        .public_application_origin_allowed(project_public_id, application_public_id, &origin)
        .await
        .map_err(|error| runtime_problem(error, request_id))?;
    if !allowed {
        return Err(runtime_error_response(
            StatusCode::FORBIDDEN,
            "origin_not_allowed",
            "The request Origin is not allowed for this Application.",
            request_id,
        ));
    }
    Ok(Some(origin))
}

async fn project_cors_origin(
    state: &RuntimeState,
    headers: &HeaderMap,
    project_public_id: &str,
    request_id: &str,
) -> Result<Option<String>, Response> {
    let origin = request_origin(headers).map_err(|()| {
        runtime_error_response(
            StatusCode::FORBIDDEN,
            "origin_not_allowed",
            "The request Origin is not allowed for this Project.",
            request_id,
        )
    })?;
    let Some(origin) = origin else {
        return Ok(None);
    };
    let allowed = runtime_auth(state)
        .map_err(|error| runtime_problem(error, request_id))?
        .project_origin_allowed(project_public_id, &origin)
        .await
        .map_err(|error| runtime_problem(error, request_id))?;
    if !allowed {
        return Err(runtime_error_response(
            StatusCode::FORBIDDEN,
            "origin_not_allowed",
            "The request Origin is not allowed for this Project.",
            request_id,
        ));
    }
    Ok(Some(origin))
}

fn request_origin(headers: &HeaderMap) -> Result<Option<String>, ()> {
    if !headers.contains_key(header::ORIGIN) {
        return Ok(None);
    }
    let origin = exact_header(headers, "origin").ok_or(())?;
    let parsed = url::Url::parse(origin).map_err(|_| ())?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.username() != ""
        || parsed.password().is_some()
        || parsed.host_str().is_none()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.origin().ascii_serialization() != origin
    {
        return Err(());
    }
    Ok(Some(origin.to_owned()))
}

fn valid_preflight_headers(value: Option<&str>) -> bool {
    value.is_none_or(|value| {
        let mut count = 0;
        let valid = value.split(',').all(|header| {
            count += 1;
            matches!(
                header.trim().to_ascii_lowercase().as_str(),
                "authorization" | "content-type"
            )
        });
        valid && count <= 2
    })
}

fn apply_cors(response: &mut Response, origin: &str, preflight: bool) {
    let Ok(origin) = HeaderValue::from_str(origin) else {
        return;
    };
    response
        .headers_mut()
        .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    response
        .headers_mut()
        .append(header::VARY, HeaderValue::from_static("Origin"));
    if preflight {
        response.headers_mut().insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, POST"),
        );
        response.headers_mut().insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("Authorization, Content-Type"),
        );
        response.headers_mut().insert(
            header::ACCESS_CONTROL_MAX_AGE,
            HeaderValue::from_static("600"),
        );
    }
}

fn exact_header<'a>(headers: &'a HeaderMap, name: &'static str) -> Option<&'a str> {
    let values = headers.get_all(HeaderName::from_static(name));
    let mut iter = values.iter();
    let value = iter.next()?.to_str().ok()?;
    if iter.next().is_some() {
        return None;
    }
    Some(value)
}

fn is_top_level_navigation(headers: &HeaderMap) -> bool {
    exact_header(headers, "sec-fetch-dest") == Some("document")
        && exact_header(headers, "sec-fetch-mode") == Some("navigate")
}

fn is_same_origin_mutation(headers: &HeaderMap, expected_origin: &str) -> bool {
    exact_header(headers, "origin") == Some(expected_origin)
        && exact_header(headers, "sec-fetch-site") == Some("same-origin")
        && matches!(
            exact_header(headers, "sec-fetch-mode"),
            Some("cors" | "same-origin")
        )
        && exact_header(headers, "sec-fetch-dest") == Some("empty")
}

fn bearer_token(headers: &HeaderMap) -> Result<String, ()> {
    let values = headers.get_all(header::AUTHORIZATION);
    let mut iter = values.iter();
    let value = iter.next().ok_or(())?.to_str().map_err(|_| ())?;
    if iter.next().is_some() {
        return Err(());
    }
    let token = value.strip_prefix("Bearer ").ok_or(())?;
    if token.is_empty()
        || token.len() > 16_384
        || token
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || !byte.is_ascii())
    {
        return Err(());
    }
    Ok(token.to_owned())
}

fn invalid_cookie(request_id: &str) -> Response {
    runtime_error_response(
        StatusCode::NOT_FOUND,
        "invalid_browser_context",
        "The browser context is missing or no longer valid.",
        request_id,
    )
}

fn forbidden_hosted_request(request_id: &str) -> Response {
    runtime_error_response(
        StatusCode::FORBIDDEN,
        "forbidden_browser_request",
        "The Hosted request failed same-origin browser checks.",
        request_id,
    )
}

fn unauthorized_runtime(request_id: &str) -> Response {
    runtime_error_response(
        StatusCode::UNAUTHORIZED,
        "unauthorized",
        "A single valid Project Bearer token is required.",
        request_id,
    )
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
    let public_jwk = match (state, key.public_jwk == serde_json::json!({})) {
        (
            control_types::SigningKeyState::Provisioning
            | control_types::SigningKeyState::Abandoned,
            true,
        ) => None,
        (_, true) => return Err(ApplicationError::Integrity),
        (_, false) => {
            Some(serde_json::from_value(key.public_jwk).map_err(|_| ApplicationError::Integrity)?)
        }
    };
    Ok(control_types::SigningKey {
        id: key.id.to_string(),
        project_id: key.project_id.to_string(),
        kid: key.kid,
        algorithm,
        state,
        ring_revision: key.ring_revision,
        signing_epoch: key.signing_epoch,
        sign_not_before: key.sign_not_before.map(timestamp),
        verify_not_after: key.verify_not_after.map(timestamp),
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
            "The requested Runtime resource was not found or is no longer available.",
        ),
        ApplicationError::InvalidInput => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "The Runtime request is invalid.",
        ),
        ApplicationError::RevisionConflict
        | ApplicationError::InvalidTransition
        | ApplicationError::IdempotencyConflict
        | ApplicationError::OperationInProgress
        | ApplicationError::PublicationPending => (
            StatusCode::CONFLICT,
            "invalid_state",
            "The Runtime operation is no longer valid in the current state.",
        ),
        ApplicationError::Integrity
        | ApplicationError::Persistence
        | ApplicationError::ExternalStore => (
            StatusCode::SERVICE_UNAVAILABLE,
            "authority_unavailable",
            "The Runtime authority is temporarily unavailable.",
        ),
    };
    runtime_error_response(status, code, message, request_id)
}

fn runtime_error_response(
    status: StatusCode,
    code: &str,
    message: &str,
    request_id: &str,
) -> Response {
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

    #[test]
    fn interaction_binding_cookies_are_partitioned_by_canonical_transaction_id() {
        let first_id = Uuid::new_v4();
        let second_id = Uuid::new_v4();
        let first = format!("{first_id}.1.first");
        let same_transaction_state = format!("{first_id}.1.upstream");
        let second = format!("{second_id}.1.second");
        let first_name = interaction_cookie_name(&first).expect("first credential is canonical");
        let second_name = interaction_cookie_name(&second).expect("second credential is canonical");
        assert_eq!(
            first_name,
            interaction_cookie_name(&same_transaction_state)
                .expect("provider state uses the same transaction ID")
        );
        assert_ne!(first_name, second_name);
        assert!(interaction_cookie_name("not-a-canonical-credential").is_err());

        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!(
                "{first_name}=binding-one; {second_name}=binding-two"
            ))
            .expect("cookie fixture is valid"),
        );
        assert_eq!(
            required_interaction_cookie(&headers, &first).as_deref(),
            Ok("binding-one")
        );
        assert_eq!(
            required_interaction_cookie(&headers, &second).as_deref(),
            Ok("binding-two")
        );
    }

    #[test]
    fn control_signing_key_represents_only_valid_pre_material_states_without_a_jwk() {
        let pre_material = application::SigningKeyRecord {
            id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            kid: "kid_recovery".to_owned(),
            algorithm: "EdDSA".to_owned(),
            state: "provisioning".to_owned(),
            ring_revision: 1,
            signing_epoch: 1,
            sign_not_before: None,
            verify_not_after: None,
            public_jwk: serde_json::json!({}),
        };
        assert_eq!(
            control_signing_key(pre_material.clone())
                .expect("a provisioning key may not have material yet")
                .public_jwk,
            None
        );

        let mut abandoned = pre_material.clone();
        abandoned.state = "abandoned".to_owned();
        assert_eq!(
            control_signing_key(abandoned)
                .expect("an abandoned pre-material key remains listable")
                .public_jwk,
            None
        );

        let mut invalid = pre_material;
        invalid.state = "published".to_owned();
        assert_eq!(
            control_signing_key(invalid),
            Err(ApplicationError::Integrity)
        );
    }

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
            ("OWLAUTH_RUNTIME_KEY_VERSION".to_owned(), "1".to_owned()),
            (
                "OWLAUTH_RUNTIME_DIGEST_KEY".to_owned(),
                "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM".to_owned(),
            ),
            (
                "OWLAUTH_RUNTIME_PROTECTION_KEY".to_owned(),
                "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ".to_owned(),
            ),
            (
                "OWLAUTH_PROVIDER_ALLOWED_ORIGINS".to_owned(),
                "https://accounts.example/".to_owned(),
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
        if mode.has_control() || (mode.has_runtime() && FEDERATED_PROJECT_AUTH_AVAILABLE) {
            values.extend([
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
            ]);
        }
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
    async fn runtime_composes_federated_auth_without_control_plane() {
        const { assert!(FEDERATED_PROJECT_AUTH_AVAILABLE) };
        let config = test_config(PlaneMode::Runtime);
        assert!(config.provisioning.is_some());
        let pools = DatabasePools {
            runtime: Some(DatabaseConnection::default()),
            control: None,
        };
        let mut routers = build_routers(&config, Some(&pools));
        assert!(
            routers.runtime_auth.is_some(),
            "Runtime mode must compose the federated authentication service"
        );
        assert!(routers.control.is_none());

        routers.mark_ready();
        let runtime = routers.runtime.take().expect("Runtime router should exist");
        let ready = runtime
            .clone()
            .oneshot(Request::get("/ready").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(ready.status(), StatusCode::OK);

        let jwks = runtime
            .oneshot(
                Request::get("/projects/example/.well-known/jwks.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            jwks.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "JWKS must remain routed to its composed readiness service"
        );
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
    async fn federated_auth_routes_are_mounted() {
        const { assert!(FEDERATED_PROJECT_AUTH_AVAILABLE) };
        let config = test_config(PlaneMode::Runtime);
        let mut routers = build_routers(&config, None);
        routers.mark_ready();
        let runtime = routers.runtime.take().expect("Runtime router should exist");

        for (method, path) in [
            ("POST", "/v1/projects/example/auth/login/start"),
            ("GET", "/auth/interactions/interaction"),
            (
                "POST",
                "/v1/projects/example/auth/interactions/interaction/method",
            ),
            (
                "POST",
                "/v1/projects/example/auth/interactions/interaction/session/reuse",
            ),
            ("GET", "/projects/example/auth/callback/provider"),
            ("POST", "/v1/projects/example/auth/handoff/exchange"),
            ("POST", "/v1/projects/example/auth/sessions/refresh"),
            ("GET", "/v1/projects/example/auth/users/me"),
            ("POST", "/v1/projects/example/auth/sessions/logout"),
            ("POST", "/v1/projects/example/auth/browser-logout/prepare"),
            ("GET", "/auth/browser-logout/preparation"),
            (
                "POST",
                "/v1/projects/example/auth/browser-logout/preparation/confirm",
            ),
        ] {
            let response = runtime
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_ne!(
                response.status(),
                StatusCode::NOT_FOUND,
                "federated authentication route is not mounted: {method} {path}"
            );
        }
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
            br#"{"product":"owlauth-server","provisioning":true,"login_readiness":true,"federated_project_auth":true}"#
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

    #[test]
    fn hosted_mutations_require_standard_same_origin_fetch_metadata() {
        let headers = HeaderMap::from_iter([
            (
                header::ORIGIN,
                HeaderValue::from_static("https://runtime.example"),
            ),
            (
                HeaderName::from_static("sec-fetch-site"),
                HeaderValue::from_static("same-origin"),
            ),
            (
                HeaderName::from_static("sec-fetch-mode"),
                HeaderValue::from_static("cors"),
            ),
            (
                HeaderName::from_static("sec-fetch-dest"),
                HeaderValue::from_static("empty"),
            ),
        ]);
        assert!(is_same_origin_mutation(&headers, "https://runtime.example"));

        let mut nonstandard = headers.clone();
        nonstandard.insert(
            HeaderName::from_static("sec-fetch-dest"),
            HeaderValue::from_static(""),
        );
        assert!(!is_same_origin_mutation(
            &nonstandard,
            "https://runtime.example"
        ));
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
