mod mcp;

use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[cfg(test)]
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

use axum::{
    Extension, Json, Router,
    extract::{
        ConnectInfo, DefaultBodyLimit, FromRequest, OriginalUri, Path, Query, Request, State,
    },
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post, put},
};
use owlauth_types::{
    FEDERATED_PROJECT_AUTH_AVAILABLE, HealthResponse, client as client_types,
    control::{self as control_types, ServiceDescriptor, SystemCapabilities},
    runtime as runtime_types,
};
#[cfg(test)]
use sea_orm::DatabaseConnection;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tower::limit::ConcurrencyLimitLayer;
use tower_http::{
    catch_panic::CatchPanicLayer, compression::CompressionLayer, timeout::TimeoutLayer,
};
use tracing::info;
use uuid::Uuid;

use crate::{
    application::{
        self, AdmissionDecision, AdmissionDimension, AdmissionDimensionKind, AdmissionEndpoint,
        AdmissionService, ApplicationError, BeginEmailChallenge, BeginLogin, Clock,
        ConfirmProjectBrowserLogout, ConfirmSessionReuse, ControlLifecycleService,
        CreateApplication, CreateManagedReauthorization, CreateProject, CreateProvider,
        CreateSmtpConfiguration, EmailControlService, ExchangeHandoff,
        IdentityMutationControlService, IdentityMutationRuntimePort, ManagedConnectionMetadata,
        ManagedConnectionRepository, ManagedConnectionService, ManagedReauthorizationCallback,
        ManagedReauthorizationCallbackOutcome, ManagedReauthorizationControlService,
        ManagedReauthorizationDenial, ManagedReauthorizationRuntimeService, ProviderCallback,
        ProviderCallbackDenial, ProviderCallbackOwner, ProviderCallbackOwnerResolver,
        ProviderOnboardingService, ProvisioningService, ReadinessService, RefreshSession,
        ReplaceApplicationConfiguration, RuntimeAuthService, SelectEmail, SelectProvider,
        SubmitEmailProof, UpdateApplication, UpdateProject, UpdateProjectPolicy,
        UpdateProviderEgressPolicy, WebhookControlService, WebhookWorker,
    },
    config::{DeploymentSmtpConfig, ListenerConfig, OperatorApiKey, ServerConfig},
    domain::{ApplicationType, ProviderEgressMode},
    web_assets::{self, WebPlane},
};

#[cfg(test)]
use crate::application::IdentityMutationRuntimeService;
#[cfg(test)]
use crate::{
    adapters::postgres::DatabasePools,
    composition::{
        build_managed_reauthorization_service, build_managed_reauthorization_target_issuer,
        build_managed_reauthorization_target_verifier,
    },
};

#[derive(Clone, Copy, Debug)]
enum HttpPlane {
    Runtime,
    Client,
    Control,
}

impl HttpPlane {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Runtime => "runtime",
            Self::Client => "client",
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
    admission: Arc<AdmissionService>,
    verified_origins: Arc<VerifiedApplicationOrigins>,
    readiness: Option<Arc<ReadinessService>>,
    auth: Option<Arc<RuntimeAuthService>>,
    callback_owners: Option<Arc<dyn ProviderCallbackOwnerResolver>>,
    managed_reauthorization: Option<Arc<ManagedReauthorizationRuntimeService>>,
    cookie_path: Arc<str>,
    external_origin: Arc<str>,
    identity_mutations: Option<Arc<dyn IdentityMutationRuntimePort>>,
}

#[derive(Clone)]
struct ClientState {
    probe: ProbeState,
    admission: Arc<AdmissionService>,
    api: Option<Arc<application::ClientApiService>>,
    readiness: Option<Arc<application::ClientDigestReadinessService>>,
}

#[derive(Clone)]
struct ControlState {
    probe: ProbeState,
    clock: Arc<dyn Clock>,
    operator_key: Arc<OperatorApiKey>,
    descriptor: Arc<ServiceDescriptor>,
    provisioning: Option<Arc<ProvisioningService>>,
    lifecycle: Option<Arc<ControlLifecycleService>>,
    email_control: Option<Arc<EmailControlService>>,
    deployment_smtp: Option<Arc<DeploymentSmtpConfig>>,
    managed_connections: Option<Arc<dyn ManagedConnectionRepository>>,
    managed_reauthorization: Option<Arc<ManagedReauthorizationControlService>>,
    identity_mutations: Option<Arc<IdentityMutationControlService>>,
    webhooks: Option<Arc<WebhookControlService>>,
    provider_onboarding: Option<Arc<ProviderOnboardingService>>,
    client_keys: Option<Arc<application::ClientKeyLifecycleService>>,
}

pub(crate) struct PlaneRouters {
    pub runtime: Option<Router>,
    pub client: Option<Router>,
    pub control: Option<Router>,
    pub runtime_auth: Option<Arc<RuntimeAuthService>>,
    pub managed_sync: Option<Arc<ManagedConnectionService>>,
    pub webhook_delivery: Option<Arc<WebhookWorker>>,
    #[cfg(test)]
    pub(crate) runtime_identity_mutations: Option<Arc<IdentityMutationRuntimeService>>,
    #[cfg(test)]
    pub(crate) control_identity_mutations: Option<Arc<IdentityMutationControlService>>,
    runtime_ready: Arc<AtomicBool>,
    client_ready: Arc<AtomicBool>,
    control_ready: Arc<AtomicBool>,
}

impl PlaneRouters {
    pub fn mark_ready(&self) {
        if self.runtime.is_some() {
            self.runtime_ready.store(true, Ordering::Release);
        }
        if self.client.is_some() {
            self.client_ready.store(true, Ordering::Release);
        }
        if self.control.is_some() {
            self.control_ready.store(true, Ordering::Release);
        }
    }

    pub fn mark_unready(&self) {
        self.runtime_ready.store(false, Ordering::Release);
        self.client_ready.store(false, Ordering::Release);
        self.control_ready.store(false, Ordering::Release);
    }
}

#[cfg(test)]
pub(crate) fn build_routers(config: &ServerConfig, pools: Option<&DatabasePools>) -> PlaneRouters {
    build_routers_with_runtime_incarnation(config, pools, Uuid::nil())
}

#[cfg(test)]
pub(crate) fn build_routers_with_runtime_incarnation(
    config: &ServerConfig,
    pools: Option<&DatabasePools>,
    runtime_incarnation: Uuid,
) -> PlaneRouters {
    let providers = crate::composition::bundled_software_providers(config)
        .expect("validated bundled provider configuration");
    let capabilities = crate::composition::build_http_capabilities(
        config,
        pools,
        runtime_incarnation,
        runtime_incarnation,
        &providers,
    );
    build_routers_with_capabilities(config, capabilities)
}

pub(crate) fn build_routers_with_capabilities(
    config: &ServerConfig,
    capabilities: crate::composition::HttpCapabilities,
) -> PlaneRouters {
    let runtime_ready = Arc::new(AtomicBool::new(false));
    let client_ready = Arc::new(AtomicBool::new(false));
    let control_ready = Arc::new(AtomicBool::new(false));

    let runtime_auth = capabilities
        .runtime
        .as_ref()
        .and_then(|runtime| runtime.auth.clone());
    let managed_sync = capabilities
        .runtime
        .as_ref()
        .and_then(|runtime| runtime.managed_sync.clone());
    let webhook_delivery = capabilities
        .runtime
        .as_ref()
        .and_then(|runtime| runtime.webhook_delivery.clone());
    #[cfg(test)]
    let runtime_identity_mutations = capabilities
        .runtime
        .as_ref()
        .and_then(|runtime| runtime.identity_mutations.clone());
    #[cfg(test)]
    let control_identity_mutations = capabilities
        .control
        .as_ref()
        .and_then(|control| control.identity_mutations.clone());

    let runtime = capabilities
        .runtime
        .map(|capabilities| build_runtime_plane(config, capabilities, Arc::clone(&runtime_ready)));
    let client = capabilities
        .client
        .map(|capabilities| build_client_plane(config, capabilities, Arc::clone(&client_ready)));
    let control = capabilities
        .control
        .map(|capabilities| build_control_plane(config, capabilities, Arc::clone(&control_ready)));

    PlaneRouters {
        runtime,
        client,
        control,
        runtime_auth,
        managed_sync,
        webhook_delivery,
        #[cfg(test)]
        runtime_identity_mutations,
        #[cfg(test)]
        control_identity_mutations,
        runtime_ready,
        client_ready,
        control_ready,
    }
}

fn build_runtime_plane(
    config: &ServerConfig,
    capabilities: crate::composition::RuntimeHttpCapabilities,
    ready: Arc<AtomicBool>,
) -> Router {
    runtime_router(
        &config.runtime,
        RuntimeState {
            probe: ProbeState {
                ready,
                base_path: Arc::from(config.runtime.external_base.path()),
            },
            readiness: capabilities.readiness,
            admission: capabilities.admission,
            verified_origins: Arc::new(VerifiedApplicationOrigins::default()),
            auth: capabilities.auth,
            callback_owners: capabilities.callback_owners,
            managed_reauthorization: capabilities.managed_reauthorization,
            cookie_path: Arc::from(config.runtime.external_base.path()),
            external_origin: Arc::from(config.runtime.external_base.origin().ascii_serialization()),
            identity_mutations: capabilities
                .identity_mutations
                .map(|service| service as Arc<dyn IdentityMutationRuntimePort>),
        },
        config,
    )
}

fn build_client_plane(
    config: &ServerConfig,
    capabilities: crate::composition::ClientHttpCapabilities,
    ready: Arc<AtomicBool>,
) -> Router {
    client_router(
        &config.client,
        ClientState {
            probe: ProbeState {
                ready,
                base_path: Arc::from(config.client.external_base.path()),
            },
            admission: capabilities.admission,
            api: capabilities.api,
            readiness: capabilities.readiness,
        },
        config,
    )
}

fn build_control_plane(
    config: &ServerConfig,
    capabilities: crate::composition::ControlHttpCapabilities,
    ready: Arc<AtomicBool>,
) -> Router {
    control_router(
        &config.control,
        ControlState {
            probe: ProbeState {
                ready,
                base_path: Arc::from(config.control.external_base.path()),
            },
            clock: capabilities.clock,
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
                mcp_url: config.control_mcp.enabled.then(|| {
                    config
                        .control
                        .external_base
                        .join("mcp")
                        .expect("validated Control base accepts the MCP path")
                        .to_string()
                }),
            }),
            provisioning: capabilities.provisioning,
            lifecycle: capabilities.lifecycle,
            email_control: capabilities.email_control,
            deployment_smtp: config.deployment_smtp.clone().map(Arc::new),
            managed_connections: capabilities.managed_connections,
            managed_reauthorization: capabilities.managed_reauthorization,
            identity_mutations: capabilities.identity_mutations,
            webhooks: capabilities.webhooks,
            provider_onboarding: capabilities.provider_onboarding,
            client_keys: capabilities.client_keys,
        },
        config,
    )
}

fn runtime_router(listener: &ListenerConfig, state: RuntimeState, config: &ServerConfig) -> Router {
    let public = Router::new()
        .route("/", get(runtime_root))
        .route("/auth", get(runtime_not_found))
        .route("/auth/", get(runtime_shell))
        .route(
            "/auth/assets/{*path}",
            get(runtime_asset).layer(CompressionLayer::new().br(true).gzip(true)),
        )
        .route("/auth/{*path}", get(runtime_not_found))
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

fn client_router(listener: &ListenerConfig, state: ClientState, config: &ServerConfig) -> Router {
    let protected = Router::new()
        .route(
            "/projects/{project_id}/users",
            get(client_list_project_users),
        )
        .route(
            "/projects/{project_id}/users/lookup",
            post(client_lookup_project_user),
        )
        .route(
            "/projects/{project_id}/users/{user_id}",
            get(client_get_project_user),
        )
        .route(
            "/projects/{project_id}/applications/{application_id}/users/{user_id}",
            get(client_get_application_user_projection),
        )
        .route(
            "/projects/{project_id}/tokens/introspect",
            post(client_introspect_project_token),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_client_key,
        ));
    let router = Router::new()
        .route("/health", get(liveness))
        .route("/ready", get(client_readiness))
        .nest("/v1", protected)
        .with_state(state);
    mount_and_bound(
        listener,
        router,
        HttpPlane::Client,
        config.request_timeout,
        config.max_request_bytes,
        256,
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "the Runtime route inventory stays explicit and plane-local"
)]
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
            "/auth/managed-reauthorizations/{interaction}",
            get(managed_reauthorization_shell),
        )
        .route(
            "/auth/identity-mutations/{interaction}",
            get(identity_mutation_shell),
        )
        .route(
            "/auth/identity-mutations/email/confirm/{challenge_id}",
            get(identity_mutation_magic_shell),
        )
        .route(
            "/v1/projects/{project_public_id}/auth/managed-reauthorizations/{interaction}/start",
            post(start_managed_reauthorization),
        )
        .route(
            "/v1/projects/{project_public_id}/auth/identity-mutations/{interaction}/proofs/{proof_slot}/method",
            post(select_identity_mutation_method),
        )
        .route(
            "/v1/projects/{project_public_id}/auth/identity-mutations/{interaction}/proofs/{proof_slot}/email/challenges",
            post(begin_identity_mutation_email_challenge),
        )
        .route(
            "/v1/projects/{project_public_id}/auth/identity-mutations/{interaction}/proofs/{proof_slot}/email/otp/verify",
            post(verify_identity_mutation_email_otp),
        )
        .route(
            "/v1/projects/{project_public_id}/auth/identity-mutations/{interaction}/proofs/{proof_slot}/email/link/verify",
            post(verify_identity_mutation_email_link),
        )
        .route(
            "/v1/projects/{project_public_id}/auth/identity-mutations/{interaction}/confirm",
            post(confirm_identity_mutation_ready),
        )
        .route(
            "/auth/browser-logout/{preparation}",
            get(browser_logout_shell),
        )
        .route(
            "/auth/email/confirm/{challenge_id}",
            get(email_magic_confirmation_shell),
        )
        .route(
            "/v1/projects/{project_public_id}/auth/interactions/{interaction}/method",
            post(select_provider_method),
        )
        .route(
            "/v1/projects/{project_public_id}/auth/interactions/{interaction}/email/select",
            post(select_email_method),
        )
        .route(
            "/v1/projects/{project_public_id}/auth/interactions/{interaction}/email/challenges",
            post(begin_email_challenge),
        )
        .route(
            "/v1/projects/{project_public_id}/auth/interactions/{interaction}/email/resend",
            post(resend_email_challenge),
        )
        .route(
            "/v1/projects/{project_public_id}/auth/interactions/{interaction}/email/otp/verify",
            post(verify_email_otp),
        )
        .route(
            "/v1/projects/{project_public_id}/auth/email/magic/confirm",
            post(confirm_email_magic),
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

#[allow(
    clippy::too_many_lines,
    reason = "the Control route inventory is intentionally explicit and plane-local"
)]
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
            "/projects/{project_id}/applications/{application_id}/webhook-endpoints",
            get(list_webhook_endpoints).post(create_webhook_endpoint),
        )
        .route(
            "/projects/{project_id}/applications/{application_id}/webhook-endpoints/{endpoint_id}",
            get(get_webhook_endpoint).put(update_webhook_endpoint),
        )
        .route(
            "/projects/{project_id}/applications/{application_id}/webhook-endpoints/{endpoint_id}/test",
            post(test_webhook_endpoint),
        )
        .route(
            "/projects/{project_id}/applications/{application_id}/webhook-endpoints/{endpoint_id}/activate",
            post(activate_webhook_endpoint),
        )
        .route(
            "/projects/{project_id}/applications/{application_id}/webhook-endpoints/{endpoint_id}/disable",
            post(disable_webhook_endpoint),
        )
        .route(
            "/projects/{project_id}/applications/{application_id}/webhook-endpoints/{endpoint_id}/secret-rotations",
            post(prepare_webhook_secret_rotation),
        )
        .route(
            "/projects/{project_id}/applications/{application_id}/webhook-endpoints/{endpoint_id}/secret-rotations/{generation}/activate",
            post(activate_webhook_secret_rotation),
        )
        .route(
            "/projects/{project_id}/applications/{application_id}/user-events",
            get(list_application_user_events),
        )
        .route(
            "/projects/{project_id}/applications/{application_id}/webhook-deliveries",
            get(list_webhook_deliveries),
        )
        .route(
            "/projects/{project_id}/applications/{application_id}/webhook-deliveries/{delivery_id}/replay",
            post(replay_webhook_delivery),
        )
        .route(
            "/projects/{project_id}/signing-keys",
            get(list_signing_keys),
        )
        .route(
            "/projects/{project_id}/signing-keys/rotate",
            post(rotate_signing_key),
        )
        .route(
            "/projects/{project_id}/signing-keys/{key_id}/revoke",
            post(revoke_signing_key),
        )
        .route(
            "/projects/{project_id}/provider-egress-policy",
            get(get_provider_egress_policy).put(update_provider_egress_policy),
        )
        .route(
            "/projects/{project_id}/providers/oidc/preflight",
            post(preflight_oidc_provider),
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
        .route(
            "/projects/{project_id}/email-method",
            get(get_email_method_policy).put(update_email_method_policy),
        )
        .route(
            "/projects/{project_id}/email-method/assignments",
            get(list_email_assignments),
        )
        .route(
            "/projects/{project_id}/applications/{application_id}/email-method",
            put(assign_email_method),
        )
        .route(
            "/projects/{project_id}/smtp-configurations",
            get(list_smtp_configurations).post(create_smtp_configuration),
        )
        .route(
            "/system/smtp-default-generations",
            get(list_deployment_smtp_generations).post(reconcile_deployment_smtp_generation),
        )
        .route(
            "/system/smtp-default-generations/{generation}/disable",
            post(disable_deployment_smtp_generation),
        )
        .route(
            "/system/smtp-default-generations/{generation}/compromise",
            post(compromise_deployment_smtp_generation),
        )
        .route(
            "/projects/{project_id}/smtp-configurations/{smtp_id}/test",
            post(test_smtp_configuration),
        )
        .route(
            "/projects/{project_id}/smtp-configurations/{smtp_id}/tests/{operation_id}",
            get(get_smtp_test_operation),
        )
        .route(
            "/projects/{project_id}/smtp-configurations/{smtp_id}/activate",
            post(activate_smtp_configuration),
        )
        .route(
            "/projects/{project_id}/smtp-configurations/{smtp_id}/disable",
            post(disable_smtp_configuration),
        )
        .route(
            "/projects/{project_id}/smtp-configurations/{smtp_id}/compromise",
            post(compromise_smtp_configuration),
        )
        .merge(control_lifecycle_router())
        .route(
            "/projects/{project_id}/identity-mutation-intents",
            post(create_identity_mutation_intent),
        )
        .route(
            "/projects/{project_id}/identity-mutation-intents/{intent_id}",
            get(get_identity_mutation_intent),
        )
        .route(
            "/projects/{project_id}/identity-mutation-intents/{intent_id}/cancel",
            post(cancel_identity_mutation_intent),
        )
        .route(
            "/projects/{project_id}/identity-mutation-intents/{intent_id}/confirm",
            post(confirm_identity_mutation_intent),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_operator,
        ));
    let mut application = Router::new()
        .route("/", get(control_root))
        .route("/console", get(control_shell))
        .route("/console/", get(control_shell))
        .route(
            "/console/assets/{*path}",
            get(control_asset).layer(CompressionLayer::new().br(true).gzip(true)),
        )
        .route("/console/{*path}", get(control_shell))
        .route("/health", get(liveness))
        .route("/ready", get(control_readiness))
        .nest("/v1", protected)
        .with_state(state.clone());
    if config.control_mcp.enabled {
        application = application.merge(mcp::router(
            &state,
            listener,
            &config.control_mcp,
            config.max_request_bytes,
        ));
    }
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
        .route(
            "/projects/{project_id}/client-keys",
            get(list_project_client_keys).post(create_project_client_key),
        )
        .route(
            "/projects/{project_id}/client-keys/{key_id}",
            get(get_project_client_key),
        )
        .route(
            "/projects/{project_id}/client-keys/{key_id}/acknowledge",
            post(acknowledge_project_client_key_delivery),
        )
        .route(
            "/projects/{project_id}/client-keys/{key_id}/revoke",
            post(revoke_project_client_key),
        )
        .route("/projects/{project_id}/users", get(list_project_users))
        .route(
            "/projects/{project_id}/users/{user_id}",
            get(get_project_user),
        )
        .route(
            "/projects/{project_id}/users/{user_id}/identities",
            get(list_project_user_identities),
        )
        .route(
            "/projects/{project_id}/users/{user_id}/disable",
            post(disable_project_user),
        )
        .route(
            "/projects/{project_id}/users/{user_id}/enable",
            post(enable_project_user),
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
        .route(
            "/projects/{project_id}/users/{user_id}/managed-provider-connections",
            get(list_managed_provider_connections),
        )
        .route(
            "/projects/{project_id}/users/{user_id}/managed-provider-connections/{connection_id}/synchronize",
            post(synchronize_managed_provider_connection),
        )
        .route(
            "/projects/{project_id}/users/{user_id}/managed-provider-connections/{connection_id}/reauthorizations",
            post(create_managed_reauthorization),
        )
        .route(
            "/projects/{project_id}/users/{user_id}/managed-provider-connections/{connection_id}/reauthorizations/{interaction_id}",
            get(get_managed_reauthorization),
        )
        .route(
            "/projects/{project_id}/users/{user_id}/managed-provider-connections/{connection_id}/reauthorizations/{interaction_id}/cancel",
            post(cancel_managed_reauthorization),
        )
        .route(
            "/projects/{project_id}/users/{user_id}/managed-provider-connections/{connection_id}/revoke",
            post(revoke_managed_provider_connection),
        )
        .route(
            "/projects/{project_id}/users/{user_id}/managed-provider-connections/{connection_id}/disconnect",
            post(disconnect_managed_provider_connection),
        )
}

#[derive(Clone)]
struct ClientAddress(String);

async fn attach_client_address(mut request: Request, next: Next) -> Response {
    let address = request
        .extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .map_or_else(|| "127.0.0.1".to_owned(), |peer| peer.0.ip().to_string());
    request.extensions_mut().insert(ClientAddress(address));
    next.run(request).await
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
        .layer(middleware::from_fn(attach_client_address))
}

async fn runtime_root(State(state): State<RuntimeState>) -> Redirect {
    Redirect::temporary(&format!("{}auth/", state.probe.base_path))
}

async fn runtime_shell(State(state): State<RuntimeState>) -> Response {
    web_assets::shell(WebPlane::Runtime, &state.probe.base_path)
}

async fn runtime_not_found(State(state): State<RuntimeState>) -> Response {
    let mut response = runtime_document_error(
        &state,
        "Page not found",
        "Return to your Application and start sign-in again.",
    );
    *response.status_mut() = StatusCode::NOT_FOUND;
    response
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

async fn admit_runtime(
    state: &RuntimeState,
    client: &ClientAddress,
    endpoint: AdmissionEndpoint,
    dimensions: &[AdmissionDimension<'_>],
    request_id: &str,
) -> Result<(), Response> {
    match state.admission.admit(endpoint, &client.0, dimensions).await {
        AdmissionDecision::Allowed => Ok(()),
        AdmissionDecision::Rejected {
            retry_after_seconds,
            ..
        } => Err(runtime_rate_limited_response(
            retry_after_seconds,
            request_id,
        )),
    }
}

fn runtime_rate_limited_response(retry_after_seconds: u64, request_id: &str) -> Response {
    let mut response = runtime_error_response(
        StatusCode::TOO_MANY_REQUESTS,
        "rate_limited",
        "The Runtime request rate limit was exceeded.",
        request_id,
    );
    if let Ok(value) = HeaderValue::from_str(&retry_after_seconds.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

const VERIFIED_ORIGIN_CAPACITY: usize = 1024;
const VERIFIED_ORIGIN_TTL: Duration = Duration::from_mins(5);

#[derive(Clone, Copy)]
enum VerifiedOriginSubject<'a> {
    Application {
        project_public_id: &'a str,
        application_public_id: &'a str,
    },
    Credential {
        project_public_id: &'a str,
        credential: &'a str,
    },
}

struct VerifiedOriginEntry {
    fingerprint: [u8; 32],
    expires_at: Instant,
}

#[derive(Default)]
struct VerifiedApplicationOrigins {
    entries: Mutex<VecDeque<VerifiedOriginEntry>>,
}

impl VerifiedApplicationOrigins {
    fn remember(&self, subject: VerifiedOriginSubject<'_>, origin: &str) {
        let fingerprint = verified_origin_fingerprint(subject, origin);
        let now = Instant::now();
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        entries.retain(|entry| entry.expires_at > now && entry.fingerprint != fingerprint);
        while entries.len() >= VERIFIED_ORIGIN_CAPACITY {
            entries.pop_front();
        }
        entries.push_back(VerifiedOriginEntry {
            fingerprint,
            expires_at: now + VERIFIED_ORIGIN_TTL,
        });
    }

    fn contains(&self, subject: VerifiedOriginSubject<'_>, origin: &str) -> bool {
        let fingerprint = verified_origin_fingerprint(subject, origin);
        let now = Instant::now();
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        entries.retain(|entry| entry.expires_at > now);
        entries.iter().any(|entry| entry.fingerprint == fingerprint)
    }
}

fn verified_origin_fingerprint(subject: VerifiedOriginSubject<'_>, origin: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    match subject {
        VerifiedOriginSubject::Application {
            project_public_id,
            application_public_id,
        } => {
            digest.update(b"application\0");
            update_length_prefixed(&mut digest, project_public_id);
            update_length_prefixed(&mut digest, application_public_id);
        }
        VerifiedOriginSubject::Credential {
            project_public_id,
            credential,
        } => {
            digest.update(b"credential\0");
            update_length_prefixed(&mut digest, project_public_id);
            update_length_prefixed(&mut digest, credential);
        }
    }
    update_length_prefixed(&mut digest, origin);
    digest.finalize().into()
}

fn update_length_prefixed(digest: &mut Sha256, value: &str) {
    digest.update(value.len().to_be_bytes());
    digest.update(value.as_bytes());
}

async fn admit_runtime_with_verified_cors(
    state: &RuntimeState,
    client: &ClientAddress,
    endpoint: AdmissionEndpoint,
    dimensions: &[AdmissionDimension<'_>],
    headers: &HeaderMap,
    subject: VerifiedOriginSubject<'_>,
    request_id: &str,
) -> Result<(), Response> {
    admit_runtime(state, client, endpoint, dimensions, request_id)
        .await
        .map_err(|response| {
            apply_verified_admission_cors(&state.verified_origins, headers, subject, response)
        })
}

fn apply_verified_admission_cors(
    verified_origins: &VerifiedApplicationOrigins,
    headers: &HeaderMap,
    subject: VerifiedOriginSubject<'_>,
    mut response: Response,
) -> Response {
    append_vary_origin(&mut response);
    if let Ok(Some(origin)) = request_origin(headers)
        && verified_origins.contains(subject, &origin)
    {
        apply_cors(&mut response, &origin, false);
        response.headers_mut().insert(
            header::ACCESS_CONTROL_EXPOSE_HEADERS,
            HeaderValue::from_static("Retry-After"),
        );
    }
    response
}

fn admission_dimension(kind: AdmissionDimensionKind, value: &str) -> AdmissionDimension<'_> {
    AdmissionDimension {
        kind,
        value,
        email_scope: None,
    }
}

fn scoped_email_admission_dimension<'a>(
    value: &'a str,
    project_id: &'a str,
    application_id: &'a str,
) -> AdmissionDimension<'a> {
    AdmissionDimension {
        kind: AdmissionDimensionKind::Email,
        value,
        email_scope: Some((project_id, application_id)),
    }
}

async fn runtime_asset(Path(path): Path<String>) -> Response {
    web_assets::asset(WebPlane::Runtime, &format!("assets/{path}"))
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
    Extension(client): Extension<ClientAddress>,
    Path(project_public_id): Path<String>,
    headers: HeaderMap,
    RuntimeJson(request): RuntimeJson<runtime_types::LoginStartRequest>,
) -> Response {
    if let Err(response) = admit_runtime_with_verified_cors(
        &state,
        &client,
        AdmissionEndpoint::LoginStart,
        &[
            admission_dimension(AdmissionDimensionKind::Project, &project_public_id),
            admission_dimension(AdmissionDimensionKind::Application, &request.application_id),
            admission_dimension(AdmissionDimensionKind::Credential, &request.publishable_key),
        ],
        &headers,
        VerifiedOriginSubject::Application {
            project_public_id: &project_public_id,
            application_public_id: &request.application_id,
        },
        &request_id,
    )
    .await
    {
        return response;
    }
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
    Extension(client): Extension<ClientAddress>,
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
    if let Err(response) = admit_runtime(
        &state,
        &client,
        AdmissionEndpoint::HostedInteraction,
        &[admission_dimension(
            AdmissionDimensionKind::Credential,
            &interaction,
        )],
        &request_id,
    )
    .await
    {
        return response;
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

#[derive(Serialize)]
struct IdentityMutationHostedBootstrap {
    project_public_id: String,
    operation_kind: &'static str,
    status: &'static str,
    revision: i64,
    csrf: String,
    expires_at: String,
    slots: Vec<IdentityMutationHostedSlot>,
}

#[derive(Serialize)]
struct IdentityMutationHostedSlot {
    id: String,
    role: &'static str,
    identity_kind: &'static str,
    method_kind: &'static str,
    state: &'static str,
    next_action: Option<&'static str>,
    proved: bool,
}

#[allow(
    clippy::too_many_lines,
    reason = "Hosted bootstrap maps only the reviewed safe intent and slot fields explicitly"
)]
async fn identity_mutation_shell(
    State(state): State<RuntimeState>,
    Extension(request_id): Extension<String>,
    Extension(client): Extension<ClientAddress>,
    Path(interaction): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !is_top_level_navigation(&headers) {
        return runtime_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_navigation",
            "Identity verification must start from a top-level document navigation.",
            &request_id,
        );
    }
    if let Err(response) = admit_runtime(
        &state,
        &client,
        AdmissionEndpoint::HostedInteraction,
        &[admission_dimension(
            AdmissionDimensionKind::Credential,
            &interaction,
        )],
        &request_id,
    )
    .await
    {
        return response;
    }
    let Ok(cookie_name) = interaction_cookie_name(&interaction) else {
        return runtime_document_error(
            &state,
            "Request unavailable",
            "Ask the operator to create a new identity-management request.",
        );
    };
    let Ok(binding) = cookie_value(&headers, &cookie_name) else {
        return runtime_document_error(
            &state,
            "Request unavailable",
            "Ask the operator to create a new identity-management request.",
        );
    };
    let Some(service) = state.identity_mutations.as_deref() else {
        return runtime_document_error(
            &state,
            "Request unavailable",
            "Identity management is unavailable.",
        );
    };
    let Ok(bootstrap) = service.bootstrap(&interaction, binding.as_deref()).await else {
        return runtime_document_error(
            &state,
            "Request unavailable",
            "Ask the operator to create a new identity-management request.",
        );
    };
    let body = IdentityMutationHostedBootstrap {
        project_public_id: bootstrap.intent.project_public_id,
        operation_kind: identity_mutation_kind_str(bootstrap.intent.kind),
        status: identity_mutation_status_str(bootstrap.intent.status),
        revision: bootstrap.intent.revision,
        csrf: bootstrap.csrf.to_string(),
        expires_at: timestamp(bootstrap.intent.expires_at),
        slots: bootstrap
            .intent
            .slots
            .into_iter()
            .map(|slot| IdentityMutationHostedSlot {
                id: slot.id.to_string(),
                role: match slot.role {
                    crate::domain::IdentityMutationSlotRole::DestinationOwner => {
                        "destination_owner"
                    }
                    crate::domain::IdentityMutationSlotRole::CandidateIdentity => {
                        "candidate_identity"
                    }
                    crate::domain::IdentityMutationSlotRole::IdentityOwner => "identity_owner",
                    crate::domain::IdentityMutationSlotRole::WinnerOwner => "winner_owner",
                    crate::domain::IdentityMutationSlotRole::LoserOwner => "loser_owner",
                },
                identity_kind: match slot.identity_kind {
                    crate::domain::IdentityKind::Provider => "provider",
                    crate::domain::IdentityKind::Email => "email",
                },
                method_kind: match slot.method_kind {
                    application::IdentityMutationProofMethodKind::Provider => "provider",
                    application::IdentityMutationProofMethodKind::Email => "email",
                },
                state: identity_mutation_slot_state_str(slot.state),
                next_action: identity_mutation_slot_next_action(slot.state),
                proved: slot.proved,
            })
            .collect(),
    };
    let Ok(serialized) = serde_json::to_string(&body) else {
        return runtime_document_error(
            &state,
            "Request unavailable",
            "Identity management is unavailable.",
        );
    };
    let mut response = web_assets::shell_with_context(
        WebPlane::Runtime,
        &state.probe.base_path,
        &[
            ("owlauth-runtime-flow", "identity_mutation"),
            ("owlauth-runtime-bootstrap", &serialized),
        ],
    );
    append_cookie(
        &mut response,
        &cookie_name,
        &bootstrap.browser_binding,
        &state.cookie_path,
        600,
    );
    response
}

async fn identity_mutation_magic_shell(
    State(state): State<RuntimeState>,
    Extension(request_id): Extension<String>,
    Extension(client): Extension<ClientAddress>,
    Path(challenge_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !is_top_level_navigation(&headers) {
        return runtime_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_navigation",
            "Open the verification link in a top-level browser window.",
            &request_id,
        );
    }
    if let Err(response) = admit_runtime(
        &state,
        &client,
        AdmissionEndpoint::EmailMagicRead,
        &[admission_dimension(
            AdmissionDimensionKind::Credential,
            &challenge_id,
        )],
        &request_id,
    )
    .await
    {
        return response;
    }
    let Ok(challenge_id) = Uuid::parse_str(&challenge_id) else {
        return runtime_document_error(
            &state,
            "Link unavailable",
            "Return to the originating identity verification and request a new link.",
        );
    };
    // This call creates only a challenge-scoped transfer gate. It never receives, validates, or
    // consumes the fragment proof, so scanners and GET navigation cannot win proof authority.
    let gate = match state.identity_mutations.as_deref() {
        Some(service) => service
            .establish_magic_transfer_context(challenge_id)
            .await
            .ok(),
        None => None,
    };
    let mut response = if let Some(gate) = gate.as_ref() {
        let generation = gate.generation.to_string();
        let revision = gate.expected_revision.to_string();
        let slot = gate.proof_slot_id.to_string();
        web_assets::shell_with_context(
            WebPlane::Runtime,
            &state.probe.base_path,
            &[
                ("owlauth-runtime-flow", "identity_mutation_magic"),
                ("owlauth-identity-magic-csrf", gate.csrf.as_str()),
                ("owlauth-identity-magic-project", &gate.project_public_id),
                ("owlauth-identity-magic-slot", &slot),
                ("owlauth-identity-magic-generation", &generation),
                ("owlauth-identity-magic-revision", &revision),
            ],
        )
    } else {
        web_assets::shell_with_context(
            WebPlane::Runtime,
            &state.probe.base_path,
            &[("owlauth-runtime-flow", "identity_mutation_magic")],
        )
    };
    if let Some(gate) = gate {
        append_cookie(
            &mut response,
            &identity_mutation_magic_transfer_cookie_name(challenge_id),
            gate.context.as_str(),
            &state.cookie_path,
            300,
        );
    }
    response
}

async fn select_identity_mutation_method(
    State(state): State<RuntimeState>,
    Extension(request_id): Extension<String>,
    Extension(client): Extension<ClientAddress>,
    Path((project_public_id, interaction, proof_slot)): Path<(String, String, String)>,
    headers: HeaderMap,
    RuntimeJson(request): RuntimeJson<runtime_types::SelectIdentityMutationMethodRequest>,
) -> Response {
    if !is_same_origin_mutation(&headers, &state.external_origin) {
        return forbidden_hosted_request(&request_id);
    }
    if let Err(response) = admit_runtime(
        &state,
        &client,
        AdmissionEndpoint::ProviderSelection,
        &[
            admission_dimension(AdmissionDimensionKind::Project, &project_public_id),
            admission_dimension(AdmissionDimensionKind::Credential, &interaction),
            admission_dimension(AdmissionDimensionKind::Credential, &proof_slot),
        ],
        &request_id,
    )
    .await
    {
        return response;
    }
    let Ok(binding) = required_interaction_cookie(&headers, &interaction) else {
        return invalid_cookie(&request_id);
    };
    let Ok(proof_slot_id) = Uuid::parse_str(&proof_slot) else {
        return runtime_problem(ApplicationError::InvalidInput, &request_id);
    };
    let asserted_method = match request.method_kind {
        runtime_types::IdentityMutationMethodKind::Provider => {
            application::IdentityMutationProofMethodKind::Provider
        }
        runtime_types::IdentityMutationMethodKind::Email => {
            application::IdentityMutationProofMethodKind::Email
        }
    };
    let Some(service) = state.identity_mutations.as_deref() else {
        return runtime_problem(ApplicationError::Persistence, &request_id);
    };
    match service
        .start_method(application::StartIdentityMutationMethod {
            project_public_id,
            interaction,
            proof_slot_id,
            asserted_method,
            browser_binding: binding.clone(),
            csrf: request.csrf,
            expected_revision: request.expected_revision,
        })
        .await
    {
        Ok(application::StartedIdentityMutationMethod::ProviderNavigation {
            url,
            proof_slot_id,
        }) => {
            let mut response = runtime_json(
                Ok(runtime_types::IdentityMutationMethodResponse::Provider(
                    runtime_types::NavigationResponse { url },
                )),
                &request_id,
            );
            append_cookie(
                &mut response,
                &identity_proof_slot_cookie_name(proof_slot_id),
                &binding,
                &state.cookie_path,
                600,
            );
            response
        }
        Ok(application::StartedIdentityMutationMethod::EmailAddressEntry(intent)) => runtime_json(
            Ok(runtime_types::IdentityMutationMethodResponse::Email(
                runtime_types::IdentityMutationProofStateResponse {
                    revision: intent.revision,
                    state: runtime_types::IdentityMutationProofState::EmailAddressEntry,
                },
            )),
            &request_id,
        ),
        Err(error) => runtime_problem(error, &request_id),
    }
}

async fn begin_identity_mutation_email_challenge(
    State(state): State<RuntimeState>,
    Extension(request_id): Extension<String>,
    Extension(client): Extension<ClientAddress>,
    Path((project_public_id, interaction, proof_slot)): Path<(String, String, String)>,
    headers: HeaderMap,
    RuntimeJson(request): RuntimeJson<runtime_types::BeginIdentityMutationEmailChallengeRequest>,
) -> Response {
    if !is_same_origin_mutation(&headers, &state.external_origin) {
        return forbidden_hosted_request(&request_id);
    }
    if let Err(response) = admit_runtime(
        &state,
        &client,
        AdmissionEndpoint::EmailChallenge,
        &[
            admission_dimension(AdmissionDimensionKind::Project, &project_public_id),
            admission_dimension(AdmissionDimensionKind::Credential, &interaction),
        ],
        &request_id,
    )
    .await
    {
        return response;
    }
    let Ok(binding) = required_interaction_cookie(&headers, &interaction) else {
        return invalid_cookie(&request_id);
    };
    let Ok(proof_slot_id) = Uuid::parse_str(&proof_slot) else {
        return runtime_problem(ApplicationError::InvalidInput, &request_id);
    };
    let Some(service) = state.identity_mutations.as_deref() else {
        return runtime_problem(ApplicationError::Persistence, &request_id);
    };
    runtime_status_json(
        StatusCode::ACCEPTED,
        service
            .begin_email_challenge(application::BeginIdentityMutationEmailChallenge {
                project_public_id,
                interaction,
                proof_slot_id,
                browser_binding: binding,
                csrf: request.csrf,
                expected_revision: request.expected_revision,
                email: request.email,
            })
            .await
            .map(
                |accepted| runtime_types::IdentityMutationEmailChallengeResponse {
                    accepted: true,
                    revision: accepted.revision,
                    challenge_id: accepted.challenge_id.to_string(),
                    generation: accepted.generation,
                    proof_modes: email_proof_modes(
                        accepted.otp_enabled,
                        accepted.magic_link_enabled,
                    ),
                    expires_at: timestamp(accepted.expires_at),
                },
            ),
        &request_id,
    )
}

async fn verify_identity_mutation_email_otp(
    state: State<RuntimeState>,
    request_id: Extension<String>,
    client: Extension<ClientAddress>,
    path: Path<(String, String, String)>,
    headers: HeaderMap,
    RuntimeJson(request): RuntimeJson<runtime_types::VerifyIdentityMutationEmailOtpRequest>,
) -> Response {
    verify_identity_mutation_email(
        state.0,
        request_id.0,
        client.0,
        path.0,
        headers,
        request.expected_revision,
        request.csrf,
        request.challenge_id,
        request.generation,
        application::EmailProofKind::Otp,
        request.otp,
    )
    .await
}

async fn verify_identity_mutation_email_link(
    state: State<RuntimeState>,
    request_id: Extension<String>,
    client: Extension<ClientAddress>,
    path: Path<(String, String, String)>,
    headers: HeaderMap,
    RuntimeJson(request): RuntimeJson<runtime_types::VerifyIdentityMutationEmailLinkRequest>,
) -> Response {
    verify_identity_mutation_email(
        state.0,
        request_id.0,
        client.0,
        path.0,
        headers,
        request.expected_revision,
        request.csrf,
        request.challenge_id,
        request.generation,
        application::EmailProofKind::MagicLink,
        request.token,
    )
    .await
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the shared OTP/magic handler keeps admission, same-browser, and transfer-cookie authority explicit"
)]
async fn verify_identity_mutation_email(
    state: RuntimeState,
    request_id: String,
    client: ClientAddress,
    (project_public_id, interaction, proof_slot): (String, String, String),
    headers: HeaderMap,
    expected_revision: i64,
    csrf: String,
    challenge_id: String,
    generation: i16,
    proof_kind: application::EmailProofKind,
    proof: String,
) -> Response {
    if !is_same_origin_mutation(&headers, &state.external_origin) {
        return forbidden_hosted_request(&request_id);
    }
    let endpoint = match proof_kind {
        application::EmailProofKind::Otp => AdmissionEndpoint::EmailOtpVerify,
        application::EmailProofKind::MagicLink => AdmissionEndpoint::EmailMagicConfirm,
    };
    if let Err(response) = admit_runtime(
        &state,
        &client,
        endpoint,
        &[
            admission_dimension(AdmissionDimensionKind::Project, &project_public_id),
            admission_dimension(AdmissionDimensionKind::Credential, &interaction),
        ],
        &request_id,
    )
    .await
    {
        return response;
    }
    let binding = required_interaction_cookie(&headers, &interaction).ok();
    let (Ok(proof_slot_id), Ok(challenge_id)) =
        (Uuid::parse_str(&proof_slot), Uuid::parse_str(&challenge_id))
    else {
        return runtime_problem(ApplicationError::InvalidInput, &request_id);
    };
    let transfer_cookie = (proof_kind == application::EmailProofKind::MagicLink)
        .then(|| {
            cookie_value(
                &headers,
                &identity_mutation_magic_transfer_cookie_name(challenge_id),
            )
            .ok()
            .flatten()
        })
        .flatten();
    let Some(service) = state.identity_mutations.as_deref() else {
        return runtime_problem(ApplicationError::Persistence, &request_id);
    };
    let transferred =
        proof_kind == application::EmailProofKind::MagicLink && transfer_cookie.is_some();
    let result = if let Some(transfer_context) = transfer_cookie {
        service
            .verify_magic_transfer(application::VerifyIdentityMutationMagicTransferProof {
                project_public_id,
                interaction,
                proof_slot_id,
                challenge_id,
                generation,
                csrf,
                expected_revision,
                proof: zeroize::Zeroizing::new(proof),
                transfer_context,
                browser_binding: binding,
            })
            .await
    } else {
        let Some(binding) = binding else {
            return invalid_cookie(&request_id);
        };
        service
            .verify_email_proof(application::VerifyRawIdentityMutationEmailProof {
                project_public_id,
                interaction,
                proof_slot_id,
                browser_binding: binding,
                csrf,
                expected_revision,
                challenge_id,
                generation,
                proof_kind,
                proof: zeroize::Zeroizing::new(proof),
            })
            .await
    };
    let clear_transfer = transferred && result.is_ok();
    let mut response = match result {
        Ok(application::IdentityMutationEmailCompletionDecision::Completed(intent)) => {
            runtime_json(
                Ok(runtime_types::IdentityMutationProofStateResponse {
                    revision: intent.revision,
                    state: runtime_types::IdentityMutationProofState::Proved,
                }),
                &request_id,
            )
        }
        Ok(application::IdentityMutationEmailCompletionDecision::Invalid) => {
            runtime_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_proof",
                "The proof could not be verified.",
                &request_id,
            )
        }
        Err(error) => runtime_problem(error, &request_id),
    };
    if clear_transfer {
        clear_cookie(
            &mut response,
            &identity_mutation_magic_transfer_cookie_name(challenge_id),
            &state.cookie_path,
        );
    }
    response
}

async fn confirm_identity_mutation_ready(
    State(state): State<RuntimeState>,
    Extension(request_id): Extension<String>,
    Extension(client): Extension<ClientAddress>,
    Path((project_public_id, interaction)): Path<(String, String)>,
    headers: HeaderMap,
    RuntimeJson(request): RuntimeJson<runtime_types::ConfirmHostedIdentityMutationRequest>,
) -> Response {
    if !is_same_origin_mutation(&headers, &state.external_origin) {
        return forbidden_hosted_request(&request_id);
    }
    if let Err(response) = admit_runtime(
        &state,
        &client,
        AdmissionEndpoint::HostedInteraction,
        &[
            admission_dimension(AdmissionDimensionKind::Project, &project_public_id),
            admission_dimension(AdmissionDimensionKind::Credential, &interaction),
        ],
        &request_id,
    )
    .await
    {
        return response;
    }
    let Ok(binding) = required_interaction_cookie(&headers, &interaction) else {
        return invalid_cookie(&request_id);
    };
    let Some(service) = state.identity_mutations.as_deref() else {
        return runtime_problem(ApplicationError::Persistence, &request_id);
    };
    runtime_json(
        service
            .confirm_ready(application::ConfirmIdentityMutationReady {
                project_public_id,
                interaction,
                browser_binding: binding,
                csrf: request.csrf,
                expected_revision: request.expected_revision,
            })
            .await
            .map(|intent| runtime_types::HostedIdentityMutationResponse {
                revision: intent.revision,
                status: match intent.status {
                    crate::domain::IdentityMutationStatus::PendingProof => {
                        runtime_types::HostedIdentityMutationStatus::PendingProof
                    }
                    crate::domain::IdentityMutationStatus::Ready
                    | crate::domain::IdentityMutationStatus::Completed => {
                        runtime_types::HostedIdentityMutationStatus::Ready
                    }
                    crate::domain::IdentityMutationStatus::Expired => {
                        runtime_types::HostedIdentityMutationStatus::Expired
                    }
                    crate::domain::IdentityMutationStatus::Cancelled => {
                        runtime_types::HostedIdentityMutationStatus::Cancelled
                    }
                },
            }),
        &request_id,
    )
}

const fn identity_mutation_kind_str(kind: crate::domain::IdentityMutationKind) -> &'static str {
    match kind {
        crate::domain::IdentityMutationKind::Link => "link",
        crate::domain::IdentityMutationKind::Unlink => "unlink",
        crate::domain::IdentityMutationKind::Merge => "merge",
    }
}

const fn identity_mutation_slot_state_str(
    state: crate::domain::IdentityMutationSlotState,
) -> &'static str {
    match state {
        crate::domain::IdentityMutationSlotState::Pending => "unselected",
        crate::domain::IdentityMutationSlotState::ProviderAuthorizationStarted => {
            "provider_started"
        }
        crate::domain::IdentityMutationSlotState::ProviderExchangeInProgress => "provider_exchange",
        crate::domain::IdentityMutationSlotState::ProviderExchangeFailed => "provider_failed",
        crate::domain::IdentityMutationSlotState::EmailAddressEntry => "email_address_entry",
        crate::domain::IdentityMutationSlotState::EmailChallengePending => {
            "email_challenge_pending"
        }
        crate::domain::IdentityMutationSlotState::Proved => "proved",
        crate::domain::IdentityMutationSlotState::Expired => "expired",
    }
}

const fn identity_mutation_slot_next_action(
    state: crate::domain::IdentityMutationSlotState,
) -> Option<&'static str> {
    match state {
        crate::domain::IdentityMutationSlotState::Pending => Some("select_method"),
        crate::domain::IdentityMutationSlotState::EmailAddressEntry => Some("enter_email"),
        crate::domain::IdentityMutationSlotState::EmailChallengePending => Some("verify_email"),
        crate::domain::IdentityMutationSlotState::ProviderAuthorizationStarted
        | crate::domain::IdentityMutationSlotState::ProviderExchangeInProgress => {
            Some("await_provider")
        }
        crate::domain::IdentityMutationSlotState::ProviderExchangeFailed => {
            Some("restart_provider")
        }
        crate::domain::IdentityMutationSlotState::Proved
        | crate::domain::IdentityMutationSlotState::Expired => None,
    }
}

const fn identity_mutation_status_str(
    status: crate::domain::IdentityMutationStatus,
) -> &'static str {
    match status {
        crate::domain::IdentityMutationStatus::PendingProof => "pending_proof",
        crate::domain::IdentityMutationStatus::Ready => "ready",
        crate::domain::IdentityMutationStatus::Completed => "completed",
        crate::domain::IdentityMutationStatus::Expired => "expired",
        crate::domain::IdentityMutationStatus::Cancelled => "cancelled",
    }
}

#[derive(Serialize)]
struct ManagedReauthorizationHostedBootstrap {
    project_public_id: String,
    provider_key: String,
    provider_display_name: String,
    provider_kind: String,
    status: String,
    revision: i64,
    csrf: String,
    expires_at: String,
}

async fn managed_reauthorization_shell(
    State(state): State<RuntimeState>,
    Extension(request_id): Extension<String>,
    Extension(client): Extension<ClientAddress>,
    Path(interaction): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !is_top_level_navigation(&headers) {
        return runtime_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_navigation",
            "Managed reauthorization must start from a top-level document navigation.",
            &request_id,
        );
    }
    if let Err(response) = admit_runtime(
        &state,
        &client,
        AdmissionEndpoint::HostedInteraction,
        &[admission_dimension(
            AdmissionDimensionKind::Credential,
            &interaction,
        )],
        &request_id,
    )
    .await
    {
        return response;
    }
    let Ok(cookie_name) = interaction_cookie_name(&interaction) else {
        return runtime_document_error(
            &state,
            "Request unavailable",
            "Ask the operator to create a new reauthorization.",
        );
    };
    let Ok(binding) = cookie_value(&headers, &cookie_name) else {
        return runtime_document_error(
            &state,
            "Request unavailable",
            "Ask the operator to create a new reauthorization.",
        );
    };
    let Some(service) = state.managed_reauthorization.as_deref() else {
        return runtime_document_error(
            &state,
            "Request unavailable",
            "Managed reauthorization is unavailable.",
        );
    };
    let Ok(bootstrap) = service.bootstrap(&interaction, binding.as_deref()).await else {
        return runtime_document_error(
            &state,
            "Request unavailable",
            "Ask the operator to create a new reauthorization.",
        );
    };
    let body = ManagedReauthorizationHostedBootstrap {
        project_public_id: bootstrap.interaction.project_public_id,
        provider_key: bootstrap.interaction.provider_key,
        provider_display_name: bootstrap.interaction.provider_display_name,
        provider_kind: bootstrap.interaction.provider_kind.as_str().to_owned(),
        status: bootstrap.interaction.status.as_str().to_owned(),
        revision: bootstrap.interaction.revision,
        csrf: bootstrap.csrf.to_string(),
        expires_at: timestamp(bootstrap.interaction.expires_at),
    };
    let Ok(serialized) = serde_json::to_string(&body) else {
        return runtime_document_error(
            &state,
            "Request unavailable",
            "Managed reauthorization is unavailable.",
        );
    };
    let mut response = web_assets::shell_with_context(
        WebPlane::Runtime,
        &state.probe.base_path,
        &[
            ("owlauth-runtime-flow", "managed_reauthorization"),
            ("owlauth-runtime-bootstrap", &serialized),
        ],
    );
    append_cookie(
        &mut response,
        &cookie_name,
        &bootstrap.browser_binding,
        &state.cookie_path,
        600,
    );
    response
}

async fn start_managed_reauthorization(
    State(state): State<RuntimeState>,
    Extension(request_id): Extension<String>,
    Extension(client): Extension<ClientAddress>,
    Path((project_public_id, interaction)): Path<(String, String)>,
    headers: HeaderMap,
    RuntimeJson(request): RuntimeJson<runtime_types::StartManagedReauthorizationRequest>,
) -> Response {
    if !is_same_origin_mutation(&headers, &state.external_origin) {
        return forbidden_hosted_request(&request_id);
    }
    if let Err(response) = admit_runtime(
        &state,
        &client,
        AdmissionEndpoint::ManagedReauthorizationStart,
        &[
            admission_dimension(AdmissionDimensionKind::Project, &project_public_id),
            admission_dimension(AdmissionDimensionKind::Credential, &interaction),
        ],
        &request_id,
    )
    .await
    {
        return response;
    }
    let Ok(binding) = required_interaction_cookie(&headers, &interaction) else {
        return invalid_cookie(&request_id);
    };
    let Some(service) = state.managed_reauthorization.as_deref() else {
        return runtime_problem(ApplicationError::Persistence, &request_id);
    };
    runtime_json(
        service
            .start(application::StartManagedReauthorization {
                project_public_id,
                interaction,
                browser_binding: binding,
                csrf: request.csrf,
                expected_revision: request.expected_revision,
            })
            .await
            .map(|url| runtime_types::NavigationResponse { url }),
        &request_id,
    )
}

async fn select_provider_method(
    State(state): State<RuntimeState>,
    Extension(request_id): Extension<String>,
    Extension(client): Extension<ClientAddress>,
    Path((project_public_id, interaction)): Path<(String, String)>,
    headers: HeaderMap,
    RuntimeJson(request): RuntimeJson<runtime_types::SelectProviderRequest>,
) -> Response {
    if !is_same_origin_mutation(&headers, &state.external_origin) {
        return forbidden_hosted_request(&request_id);
    }
    if let Err(response) = admit_runtime(
        &state,
        &client,
        AdmissionEndpoint::ProviderSelection,
        &[
            admission_dimension(AdmissionDimensionKind::Project, &project_public_id),
            admission_dimension(AdmissionDimensionKind::Credential, &interaction),
            admission_dimension(AdmissionDimensionKind::Provider, &request.provider_key),
        ],
        &request_id,
    )
    .await
    {
        return response;
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

async fn select_email_method(
    State(state): State<RuntimeState>,
    Extension(request_id): Extension<String>,
    Extension(client): Extension<ClientAddress>,
    Path((project_public_id, interaction)): Path<(String, String)>,
    headers: HeaderMap,
    RuntimeJson(request): RuntimeJson<runtime_types::SelectEmailRequest>,
) -> Response {
    if !is_same_origin_mutation(&headers, &state.external_origin) {
        return forbidden_hosted_request(&request_id);
    }
    if let Err(response) = admit_runtime(
        &state,
        &client,
        AdmissionEndpoint::EmailSelection,
        &[
            admission_dimension(AdmissionDimensionKind::Project, &project_public_id),
            admission_dimension(AdmissionDimensionKind::Credential, &interaction),
        ],
        &request_id,
    )
    .await
    {
        return response;
    }
    let Ok(binding) = required_interaction_cookie(&headers, &interaction) else {
        return invalid_cookie(&request_id);
    };
    let result = match runtime_auth(&state) {
        Ok(service) => service
            .select_email(SelectEmail {
                project_public_id,
                interaction,
                browser_binding: binding,
                csrf: request.csrf,
                expected_revision: request.expected_revision,
            })
            .await
            .map(|()| runtime_types::CompletionResponse { completed: true }),
        Err(error) => Err(error),
    };
    runtime_json(result, &request_id)
}

async fn begin_email_challenge(
    state: State<RuntimeState>,
    request_id: Extension<String>,
    client: Extension<ClientAddress>,
    path: Path<(String, String)>,
    headers: HeaderMap,
    request: RuntimeJson<runtime_types::BeginEmailChallengeRequest>,
) -> Response {
    email_challenge(state, request_id, client, path, headers, request, false).await
}

async fn resend_email_challenge(
    state: State<RuntimeState>,
    request_id: Extension<String>,
    client: Extension<ClientAddress>,
    path: Path<(String, String)>,
    headers: HeaderMap,
    request: RuntimeJson<runtime_types::BeginEmailChallengeRequest>,
) -> Response {
    email_challenge(state, request_id, client, path, headers, request, true).await
}

async fn after_email_pre_authority<T, E, F, Fut>(
    admission: &AdmissionService,
    endpoint: AdmissionEndpoint,
    client_address: &str,
    interaction: &str,
    authority: F,
) -> Result<Result<T, E>, u64>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    match admission
        .admit_email_pre_authority(endpoint, client_address, interaction)
        .await
    {
        AdmissionDecision::Allowed => Ok(authority().await),
        AdmissionDecision::Rejected {
            retry_after_seconds,
            ..
        } => Err(retry_after_seconds),
    }
}

async fn email_challenge(
    State(state): State<RuntimeState>,
    Extension(request_id): Extension<String>,
    Extension(client): Extension<ClientAddress>,
    Path((project_public_id, interaction)): Path<(String, String)>,
    headers: HeaderMap,
    RuntimeJson(request): RuntimeJson<runtime_types::BeginEmailChallengeRequest>,
    resend: bool,
) -> Response {
    if !is_same_origin_mutation(&headers, &state.external_origin) {
        return forbidden_hosted_request(&request_id);
    }
    let Ok(canonical_email) = crate::domain::CanonicalEmail::parse_v1(&request.email) else {
        return runtime_problem(ApplicationError::InvalidInput, &request_id);
    };
    let endpoint = if resend {
        AdmissionEndpoint::EmailResend
    } else {
        AdmissionEndpoint::EmailChallenge
    };
    let Ok(binding) = required_interaction_cookie(&headers, &interaction) else {
        return invalid_cookie(&request_id);
    };
    let service = match runtime_auth(&state) {
        Ok(service) => service,
        Err(error) => return runtime_problem(error, &request_id),
    };
    // This hard gate uses only request-derived, purpose-separated digests. The authority closure
    // cannot run until it passes, making the no-PostgreSQL-on-rejection invariant testable.
    let scope =
        match after_email_pre_authority(&state.admission, endpoint, &client.0, &interaction, || {
            service.email_admission_scope(&project_public_id, &interaction, &binding)
        })
        .await
        {
            Ok(Ok(scope)) => scope,
            Ok(Err(error)) => return runtime_problem(error, &request_id),
            Err(retry_after_seconds) => {
                return runtime_rate_limited_response(retry_after_seconds, &request_id);
            }
        };
    // Project and Application scope come from persisted interaction authority, never request
    // dimensions. This second stage consumes only authoritative owner/address buckets: request
    // client and opaque interaction quota were consumed exactly once by the hard pre-gate.
    let authoritative_project = scope.project_id.to_string();
    let authoritative_application = scope.application_id.to_string();
    let dimensions = [
        admission_dimension(AdmissionDimensionKind::Project, &authoritative_project),
        admission_dimension(
            AdmissionDimensionKind::Application,
            &authoritative_application,
        ),
        scoped_email_admission_dimension(
            canonical_email.expose(),
            &authoritative_project,
            &authoritative_application,
        ),
    ];
    let suppress_delivery = match state
        .admission
        .admit_email_authoritative(endpoint, &dimensions)
        .await
    {
        AdmissionDecision::Allowed => false,
        AdmissionDecision::Rejected {
            reason: application::AdmissionRejectionReason::Quota,
            suppression_eligible: true,
            ..
        } => true,
        AdmissionDecision::Rejected {
            retry_after_seconds,
            ..
        } => return runtime_rate_limited_response(retry_after_seconds, &request_id),
    };
    let result = service
        .begin_email_challenge(BeginEmailChallenge {
            project_public_id,
            interaction,
            browser_binding: binding,
            csrf: request.csrf,
            expected_revision: request.expected_revision,
            email: request.email,
            suppress_delivery,
        })
        .await
        .map(|accepted| runtime_types::EmailChallengeAcceptedResponse {
            accepted: accepted.accepted,
            revision: accepted.revision,
            challenge_id: accepted.challenge_id.to_string(),
            generation: accepted.generation,
            proof_modes: email_proof_modes(accepted.otp_enabled, accepted.magic_link_enabled),
            expires_at: timestamp(accepted.expires_at),
        });
    runtime_status_json(StatusCode::ACCEPTED, result, &request_id)
}

async fn verify_email_otp(
    State(state): State<RuntimeState>,
    Extension(request_id): Extension<String>,
    Extension(client): Extension<ClientAddress>,
    Path((project_public_id, interaction)): Path<(String, String)>,
    headers: HeaderMap,
    RuntimeJson(request): RuntimeJson<runtime_types::VerifyEmailOtpRequest>,
) -> Response {
    if !is_same_origin_mutation(&headers, &state.external_origin) {
        return forbidden_hosted_request(&request_id);
    }
    if !(6..=10).contains(&request.otp.len())
        || !request.otp.bytes().all(|byte| byte.is_ascii_digit())
    {
        return runtime_problem(ApplicationError::InvalidInput, &request_id);
    }
    if let Err(response) = admit_runtime(
        &state,
        &client,
        AdmissionEndpoint::EmailOtpVerify,
        &[
            admission_dimension(AdmissionDimensionKind::Project, &project_public_id),
            admission_dimension(AdmissionDimensionKind::Credential, &interaction),
        ],
        &request_id,
    )
    .await
    {
        return response;
    }
    let Ok(binding) = required_interaction_cookie(&headers, &interaction) else {
        return invalid_cookie(&request_id);
    };
    let Ok(challenge_id) = Uuid::parse_str(&request.challenge_id) else {
        return runtime_problem(ApplicationError::InvalidInput, &request_id);
    };
    let existing_browser_session =
        cookie_value(&headers, &project_session_cookie_name(&project_public_id))
            .ok()
            .flatten();
    let result = match runtime_auth(&state) {
        Ok(service) => {
            service
                .verify_email_proof(SubmitEmailProof {
                    project_public_id,
                    interaction,
                    challenge_id,
                    generation: request.generation,
                    browser_binding: Some(binding),
                    existing_browser_session,
                    csrf: request.csrf,
                    expected_revision: request.expected_revision,
                    kind: application::EmailProofKind::Otp,
                    proof: zeroize::Zeroizing::new(request.otp),
                })
                .await
        }
        Err(error) => Err(error),
    };
    email_completion_response(&state, result, &request_id)
}

async fn confirm_email_magic(
    State(state): State<RuntimeState>,
    Extension(request_id): Extension<String>,
    Extension(client): Extension<ClientAddress>,
    Path(project_public_id): Path<String>,
    headers: HeaderMap,
    RuntimeJson(request): RuntimeJson<runtime_types::ConfirmEmailMagicRequest>,
) -> Response {
    if !is_same_origin_mutation(&headers, &state.external_origin) {
        return forbidden_hosted_request(&request_id);
    }
    let canonical_magic_proof = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&request.proof)
        .is_ok_and(|decoded| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(decoded) == request.proof
        });
    if !(22..=128).contains(&request.proof.len()) || !canonical_magic_proof {
        return runtime_problem(ApplicationError::InvalidInput, &request_id);
    }
    if let Err(response) = admit_runtime(
        &state,
        &client,
        AdmissionEndpoint::EmailMagicConfirm,
        &[
            admission_dimension(AdmissionDimensionKind::Project, &project_public_id),
            admission_dimension(AdmissionDimensionKind::Credential, &request.challenge_id),
        ],
        &request_id,
    )
    .await
    {
        return response;
    }
    let Ok(challenge_id) = Uuid::parse_str(&request.challenge_id) else {
        return runtime_problem(ApplicationError::InvalidInput, &request_id);
    };
    let Ok(transaction_id) = Uuid::parse_str(&request.transaction_id) else {
        return runtime_problem(ApplicationError::InvalidInput, &request_id);
    };
    let Ok(Some(transfer_context)) =
        cookie_value(&headers, &magic_transfer_cookie_name(challenge_id))
    else {
        return invalid_cookie(&request_id);
    };
    let browser_binding = cookie_value(&headers, &interaction_cookie_name_from_id(transaction_id))
        .ok()
        .flatten();
    let existing_browser_session =
        cookie_value(&headers, &project_session_cookie_name(&project_public_id))
            .ok()
            .flatten();
    let result = match runtime_auth(&state) {
        Ok(service) => {
            service
                .verify_magic_transfer(application::SubmitMagicTransferProof {
                    project_public_id,
                    transaction_id,
                    challenge_id,
                    generation: request.generation,
                    browser_binding,
                    existing_browser_session,
                    transfer_context: zeroize::Zeroizing::new(transfer_context),
                    csrf: zeroize::Zeroizing::new(request.csrf),
                    expected_revision: request.expected_revision,
                    proof: zeroize::Zeroizing::new(request.proof),
                })
                .await
        }
        Err(error) => Err(error),
    };
    // A purpose-bound transfer context may have been established while another browser won the
    // one-use parent. Its later explicit POST is indistinguishable from any other invalid proof;
    // absence of the now-terminal authority must not become a resource oracle.
    let result = match result {
        Err(ApplicationError::NotFound) => Ok(application::EmailCompletion::Invalid),
        result => result,
    };
    email_completion_response(&state, result, &request_id)
}

fn email_completion_response(
    state: &RuntimeState,
    result: Result<application::EmailCompletion, ApplicationError>,
    request_id: &str,
) -> Response {
    match result {
        Ok(application::EmailCompletion::Invalid) => runtime_json(
            Ok(runtime_types::EmailProofResponse {
                completed: false,
                redirect_url: None,
                application_type: None,
            }),
            request_id,
        ),
        Ok(application::EmailCompletion::Completed(completion)) => {
            let project_cookie = project_session_cookie_name(&completion.project_public_id);
            let mut response = runtime_json(
                Ok(runtime_types::EmailProofResponse {
                    completed: true,
                    redirect_url: Some(completion.redirect_url),
                    application_type: completion.application_type.map(|application_type| {
                        match application_type {
                            ApplicationType::Web => runtime_types::HostedApplicationType::Web,
                            ApplicationType::Native => runtime_types::HostedApplicationType::Native,
                        }
                    }),
                }),
                request_id,
            );
            append_cookie(
                &mut response,
                &project_cookie,
                &completion.browser_session,
                &state.cookie_path,
                86_400,
            );
            response
        }
        Err(error) => runtime_problem(error, request_id),
    }
}

async fn email_magic_confirmation_shell(
    State(state): State<RuntimeState>,
    Extension(request_id): Extension<String>,
    Extension(client): Extension<ClientAddress>,
    Path(challenge_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !is_top_level_navigation(&headers) {
        return runtime_document_error(
            &state,
            "Link unavailable",
            "Open this link in a browser to continue.",
        );
    }
    if let Err(response) = admit_runtime(
        &state,
        &client,
        AdmissionEndpoint::EmailMagicRead,
        &[],
        &request_id,
    )
    .await
    {
        return response;
    }
    let Ok(challenge_id) = Uuid::parse_str(&challenge_id) else {
        return runtime_document_error(
            &state,
            "Link unavailable",
            "Return to your Application and start sign-in again.",
        );
    };
    let gate = match runtime_auth(&state) {
        Ok(service) => service
            .establish_magic_transfer_context(challenge_id)
            .await
            .ok(),
        Err(_) => None,
    };
    let mut response = if let Some(gate) = gate.as_ref() {
        web_assets::shell_with_context(
            WebPlane::Runtime,
            &state.probe.base_path,
            &[
                ("owlauth-runtime-flow", "email-magic"),
                ("owlauth-magic-csrf", gate.csrf.as_str()),
            ],
        )
    } else {
        web_assets::shell_with_context(
            WebPlane::Runtime,
            &state.probe.base_path,
            &[("owlauth-runtime-flow", "email-magic")],
        )
    };
    if let Some(gate) = gate {
        append_cookie(
            &mut response,
            &magic_transfer_cookie_name(challenge_id),
            gate.context.as_str(),
            &state.cookie_path,
            300,
        );
    }
    response
}

async fn reuse_browser_session(
    State(state): State<RuntimeState>,
    Extension(request_id): Extension<String>,
    Extension(client): Extension<ClientAddress>,
    Path((project_public_id, interaction)): Path<(String, String)>,
    headers: HeaderMap,
    RuntimeJson(request): RuntimeJson<runtime_types::ConfirmSessionReuseRequest>,
) -> Response {
    if !is_same_origin_mutation(&headers, &state.external_origin) {
        return forbidden_hosted_request(&request_id);
    }
    if let Err(response) = admit_runtime(
        &state,
        &client,
        AdmissionEndpoint::SessionReuse,
        &[
            admission_dimension(AdmissionDimensionKind::Project, &project_public_id),
            admission_dimension(AdmissionDimensionKind::Credential, &interaction),
        ],
        &request_id,
    )
    .await
    {
        return response;
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
    code: Option<String>,
    state: String,
    error: Option<String>,
    error_description: Option<String>,
    error_uri: Option<String>,
}

enum ProviderCallbackPayload {
    Success {
        state: String,
        code: String,
    },
    Denial {
        state: String,
        safe_outcome: &'static str,
    },
}

fn classify_provider_callback(
    query: ProviderCallbackQuery,
) -> Result<ProviderCallbackPayload, ApplicationError> {
    if query.state.is_empty()
        || query.state.len() > 256
        || query
            .code
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > 4_096)
        || query
            .error
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > 128)
        || query
            .error_description
            .as_ref()
            .is_some_and(|value| value.len() > 1_024)
        || query
            .error_uri
            .as_ref()
            .is_some_and(|value| value.len() > 2_048)
    {
        return Err(ApplicationError::InvalidInput);
    }
    match (query.code, query.error) {
        (Some(code), None) if query.error_description.is_none() && query.error_uri.is_none() => {
            Ok(ProviderCallbackPayload::Success {
                state: query.state,
                code,
            })
        }
        (None, Some(error)) => Ok(ProviderCallbackPayload::Denial {
            state: query.state,
            safe_outcome: safe_provider_denial_outcome(&error),
        }),
        _ => Err(ApplicationError::InvalidInput),
    }
}

fn safe_provider_denial_outcome(error: &str) -> &'static str {
    match error {
        "access_denied" => "auth.callback.denied_access",
        "interaction_required" | "login_required" | "consent_required" => {
            "auth.callback.denied_interaction"
        }
        "server_error" | "temporarily_unavailable" => "auth.callback.denied_unavailable",
        _ => "auth.callback.denied_other",
    }
}

fn should_clear_identity_callback_alias<T>(result: &Result<T, ApplicationError>) -> bool {
    result.is_ok()
}

#[allow(
    clippy::too_many_lines,
    reason = "the shared callback keeps typed success/denial ownership and cookie effects explicit"
)]
async fn provider_callback(
    State(state): State<RuntimeState>,
    Extension(request_id): Extension<String>,
    Extension(client): Extension<ClientAddress>,
    Path((project_public_id, provider_key)): Path<(String, String)>,
    Query(query): Query<ProviderCallbackQuery>,
    headers: HeaderMap,
) -> Response {
    let callback = match classify_provider_callback(query) {
        Ok(callback) => callback,
        Err(error) => return runtime_problem(error, &request_id),
    };
    let callback_state = match &callback {
        ProviderCallbackPayload::Success { state, .. }
        | ProviderCallbackPayload::Denial { state, .. } => state,
    };
    if let Err(response) = admit_runtime(
        &state,
        &client,
        AdmissionEndpoint::ProviderCallback,
        &[
            admission_dimension(AdmissionDimensionKind::Project, &project_public_id),
            admission_dimension(AdmissionDimensionKind::Provider, &provider_key),
            admission_dimension(AdmissionDimensionKind::Credential, callback_state),
        ],
        &request_id,
    )
    .await
    {
        return response;
    }
    // Classify exactly one typed owner before reading any class-specific cookie. There is no
    // probing or fallback after this authority decision, and no provider transport has run yet.
    let Ok(state_id) = validate_interaction_credential(callback_state) else {
        return runtime_document_error(
            &state,
            "Sign-in unavailable",
            "Return to the originating interaction and start again.",
        );
    };
    let callback_owner = match state.callback_owners.as_deref() {
        Some(resolver) => {
            resolver
                .resolve(state_id, &project_public_id, &provider_key)
                .await
        }
        None => Err(ApplicationError::NotFound),
    };
    let Ok(callback_owner) = callback_owner else {
        return runtime_document_error(
            &state,
            "Sign-in unavailable",
            "Return to the originating interaction and start again.",
        );
    };
    let interaction_cookie = match callback_owner {
        ProviderCallbackOwner::Login { .. }
        | ProviderCallbackOwner::ManagedReauthorization { .. } => {
            interaction_cookie_name_from_id(state_id)
        }
        ProviderCallbackOwner::IdentityMutation { proof_slot_id, .. } => {
            if proof_slot_id != state_id {
                return runtime_document_error(
                    &state,
                    "Identity proof could not be completed",
                    "Return to the identity-management interaction and start this proof again.",
                );
            }
            identity_proof_slot_cookie_name(proof_slot_id)
        }
    };
    let Ok(Some(browser_binding)) = cookie_value(&headers, &interaction_cookie) else {
        return runtime_document_error(
            &state,
            "Sign-in unavailable",
            "Return to the originating interaction and start again.",
        );
    };

    if let ProviderCallbackOwner::IdentityMutation {
        intent_id,
        proof_slot_id,
    } = callback_owner
    {
        let Some(service) = state.identity_mutations.as_deref() else {
            return runtime_document_error(
                &state,
                "Identity proof could not be completed",
                "Return to the identity-management interaction and start this proof again.",
            );
        };
        let result = match callback {
            ProviderCallbackPayload::Denial {
                state: callback_state,
                safe_outcome,
            } => service
                .deny_provider_callback(application::IdentityMutationProviderDenial {
                    intent_id,
                    proof_slot_id,
                    project_public_id: project_public_id.clone(),
                    provider_key: provider_key.clone(),
                    state: callback_state,
                    browser_binding,
                    safe_outcome,
                })
                .await
                .map(|_| None),
            ProviderCallbackPayload::Success {
                state: callback_state,
                code,
            } => service
                .complete_provider_callback(application::IdentityMutationProviderCallback {
                    intent_id,
                    proof_slot_id,
                    project_public_id: project_public_id.clone(),
                    provider_key: provider_key.clone(),
                    state: callback_state,
                    code,
                    browser_binding,
                })
                .await
                .map(|outcome| match outcome {
                    application::IdentityMutationCallbackOutcome::Proved {
                        continuation, ..
                    } => Some(continuation.to_string()),
                    application::IdentityMutationCallbackOutcome::Duplicate
                    | application::IdentityMutationCallbackOutcome::TerminalizedFailure
                    | application::IdentityMutationCallbackOutcome::TerminalizedStaleAuthority => {
                        None
                    }
                }),
        };
        let clear_alias = should_clear_identity_callback_alias(&result);
        let mut response = match result {
            Ok(Some(continuation)) => {
                // Continuation is the original opaque intent handle. It is kept out of response
                // metadata and used only to reconstruct the local same-origin Hosted path.
                Redirect::to(&format!(
                    "{}auth/identity-mutations/{continuation}",
                    state.probe.base_path
                ))
                .into_response()
            }
            Ok(None) => runtime_document_error(
                &state,
                "Identity proof was not completed",
                "Return to the identity-management interaction and continue or start this proof again.",
            ),
            Err(_) => runtime_document_error(
                &state,
                "Identity proof could not be completed",
                "Return to the identity-management interaction and start this proof again.",
            ),
        };
        // Clear only terminal/consumed state-to-slot aliases. Infrastructure failures retain the
        // alias because the authoritative slot may still be retryable. The intent binding cookie
        // remains until Hosted or Control reaches its final transition.
        if clear_alias {
            clear_cookie(&mut response, &interaction_cookie, &state.cookie_path);
        }
        return response;
    }

    if let ProviderCallbackPayload::Denial {
        state: callback_state,
        safe_outcome,
    } = &callback
    {
        if matches!(
            callback_owner,
            ProviderCallbackOwner::ManagedReauthorization { .. }
        ) {
            let Some(service) = state.managed_reauthorization.as_deref() else {
                return runtime_document_error(
                    &state,
                    "Reauthorization could not be completed",
                    "Ask the operator to inspect this interaction or create a new one.",
                );
            };
            match service
                .deny_callback(ManagedReauthorizationDenial {
                    project_public_id: project_public_id.clone(),
                    provider_key: provider_key.clone(),
                    state: callback_state.clone(),
                    browser_binding: browser_binding.clone(),
                    safe_outcome,
                })
                .await
            {
                Ok(_) => {
                    let mut response = runtime_document_error(
                        &state,
                        "Provider authorization was not approved",
                        "Ask the operator to create a new managed reauthorization interaction if access is still required.",
                    );
                    clear_cookie(&mut response, &interaction_cookie, &state.cookie_path);
                    return response;
                }
                Err(_) => {
                    return runtime_document_error(
                        &state,
                        "Reauthorization could not be completed",
                        "Ask the operator to inspect this interaction or create a new one.",
                    );
                }
            }
        }
        let denied = match runtime_auth(&state) {
            Ok(service) => {
                service
                    .deny_provider_callback(ProviderCallbackDenial {
                        project_public_id: project_public_id.clone(),
                        provider_key,
                        state: callback_state.clone(),
                        browser_binding,
                        safe_outcome,
                    })
                    .await
            }
            Err(error) => Err(error),
        };
        if denied.is_err() {
            return runtime_document_error(
                &state,
                "Sign-in could not be completed",
                "Return to your Application and start sign-in again.",
            );
        }
        let mut response = runtime_document_error(
            &state,
            "Provider authorization was not approved",
            "Return to your Application and start sign-in again if access is still required.",
        );
        clear_cookie(&mut response, &interaction_cookie, &state.cookie_path);
        return response;
    }

    let ProviderCallbackPayload::Success {
        state: callback_state,
        code,
    } = callback
    else {
        unreachable!()
    };
    if matches!(
        callback_owner,
        ProviderCallbackOwner::ManagedReauthorization { .. }
    ) {
        let Some(service) = state.managed_reauthorization.as_deref() else {
            return runtime_document_error(
                &state,
                "Reauthorization could not be completed",
                "Ask the operator to inspect this interaction or create a new one.",
            );
        };
        match service
            .complete_callback(ManagedReauthorizationCallback {
                project_public_id: project_public_id.clone(),
                provider_key: provider_key.clone(),
                state: callback_state.clone(),
                code: code.clone(),
                browser_binding: browser_binding.clone(),
            })
            .await
        {
            Ok(ManagedReauthorizationCallbackOutcome::TerminalizedFailure(interaction)) => {
                if !interaction.status.terminal() {
                    return runtime_document_error(
                        &state,
                        "Reauthorization could not be completed",
                        "Ask the operator to inspect this interaction or create a new one.",
                    );
                }
                let mut response = runtime_document_error(
                    &state,
                    "Reauthorization could not be completed",
                    "Ask the operator to inspect this interaction or create a new one.",
                );
                clear_cookie(&mut response, &interaction_cookie, &state.cookie_path);
                return response;
            }
            Ok(ManagedReauthorizationCallbackOutcome::TerminalizedStaleAuthority) => {
                let mut response = runtime_document_error(
                    &state,
                    "Reauthorization could not be completed",
                    "Ask the operator to inspect this interaction or create a new one.",
                );
                clear_cookie(&mut response, &interaction_cookie, &state.cookie_path);
                return response;
            }
            Ok(outcome) => {
                let interaction = match outcome {
                    ManagedReauthorizationCallbackOutcome::Completed(value)
                    | ManagedReauthorizationCallbackOutcome::Duplicate(value) => value,
                    ManagedReauthorizationCallbackOutcome::TerminalizedFailure(_)
                    | ManagedReauthorizationCallbackOutcome::TerminalizedStaleAuthority => {
                        unreachable!()
                    }
                };
                if interaction.status.terminal()
                    && interaction.status != application::ManagedReauthorizationStatus::Completed
                {
                    let mut response = runtime_document_error(
                        &state,
                        "Reauthorization could not be completed",
                        "Ask the operator to inspect this interaction or create a new one.",
                    );
                    clear_cookie(&mut response, &interaction_cookie, &state.cookie_path);
                    return response;
                }
                let payload = serde_json::json!({
                    "project_public_id": interaction.project_public_id,
                    "provider_key": interaction.provider_key,
                    "provider_display_name": interaction.provider_display_name,
                    "provider_kind": interaction.provider_kind.as_str(),
                    "status": interaction.status.as_str(),
                    "revision": interaction.revision,
                    "expires_at": timestamp(interaction.expires_at),
                });
                let serialized = payload.to_string();
                let mut response = web_assets::shell_with_context(
                    WebPlane::Runtime,
                    &state.probe.base_path,
                    &[
                        ("owlauth-runtime-flow", "managed_reauthorization"),
                        ("owlauth-runtime-bootstrap", &serialized),
                    ],
                );
                if interaction.status.terminal() {
                    clear_cookie(&mut response, &interaction_cookie, &state.cookie_path);
                }
                return response;
            }
            Err(_) => {
                return runtime_document_error(
                    &state,
                    "Reauthorization could not be completed",
                    "Ask the operator to inspect this interaction or create a new one.",
                );
            }
        }
    }
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
                    state: callback_state,
                    code,
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
    Extension(client): Extension<ClientAddress>,
    Path(project_public_id): Path<String>,
    headers: HeaderMap,
    RuntimeJson(request): RuntimeJson<runtime_types::HandoffExchangeRequest>,
) -> Response {
    if let Err(response) = admit_runtime_with_verified_cors(
        &state,
        &client,
        AdmissionEndpoint::HandoffExchange,
        &[
            admission_dimension(AdmissionDimensionKind::Project, &project_public_id),
            admission_dimension(AdmissionDimensionKind::Application, &request.application_id),
            admission_dimension(AdmissionDimensionKind::Credential, &request.handoff),
        ],
        &headers,
        VerifiedOriginSubject::Application {
            project_public_id: &project_public_id,
            application_public_id: &request.application_id,
        },
        &request_id,
    )
    .await
    {
        return response;
    }
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
    Extension(client): Extension<ClientAddress>,
    Path(project_public_id): Path<String>,
    headers: HeaderMap,
    RuntimeJson(request): RuntimeJson<runtime_types::RefreshRequest>,
) -> Response {
    if let Err(response) = admit_runtime_with_verified_cors(
        &state,
        &client,
        AdmissionEndpoint::Refresh,
        &[
            admission_dimension(AdmissionDimensionKind::Project, &project_public_id),
            admission_dimension(AdmissionDimensionKind::Application, &request.application_id),
            admission_dimension(AdmissionDimensionKind::Credential, &request.refresh_token),
        ],
        &headers,
        VerifiedOriginSubject::Application {
            project_public_id: &project_public_id,
            application_public_id: &request.application_id,
        },
        &request_id,
    )
    .await
    {
        return response;
    }
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
    Extension(client): Extension<ClientAddress>,
    Path(project_public_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Ok(token) = bearer_token(&headers) else {
        return unauthorized_runtime(&request_id);
    };
    if let Err(response) = admit_runtime_with_verified_cors(
        &state,
        &client,
        AdmissionEndpoint::CurrentUser,
        &[
            admission_dimension(AdmissionDimensionKind::Project, &project_public_id),
            admission_dimension(AdmissionDimensionKind::Credential, &token),
        ],
        &headers,
        VerifiedOriginSubject::Credential {
            project_public_id: &project_public_id,
            credential: &token,
        },
        &request_id,
    )
    .await
    {
        return response;
    }
    let cors_origin =
        match project_cors_origin(&state, &headers, &project_public_id, &request_id).await {
            Ok(origin) => origin,
            Err(response) => return response,
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
                    remember_verified_credential_origin(
                        &state,
                        &project_public_id,
                        &token,
                        cors_origin.as_deref(),
                    );
                    user_projection(current.projection_document).and_then(|projection| {
                        let projection_revision = projection.projection_revision;
                        if current.projection_revision != projection_revision {
                            return Err(ApplicationError::Integrity);
                        }
                        Ok(runtime_types::CurrentUserResponse {
                            project_id: current.project_public_id,
                            application_id: current.application_public_id,
                            user_id: current.user_public_id,
                            projection,
                            projection_revision,
                            authenticated_at: timestamp(current.authenticated_at),
                            session_expires_at: timestamp(current.absolute_expires_at),
                        })
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
    Extension(client): Extension<ClientAddress>,
    Path(project_public_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Ok(token) = bearer_token(&headers) else {
        return unauthorized_runtime(&request_id);
    };
    if let Err(response) = admit_runtime_with_verified_cors(
        &state,
        &client,
        AdmissionEndpoint::ApplicationLogout,
        &[
            admission_dimension(AdmissionDimensionKind::Project, &project_public_id),
            admission_dimension(AdmissionDimensionKind::Credential, &token),
        ],
        &headers,
        VerifiedOriginSubject::Credential {
            project_public_id: &project_public_id,
            credential: &token,
        },
        &request_id,
    )
    .await
    {
        return response;
    }
    let cors_origin =
        match project_cors_origin(&state, &headers, &project_public_id, &request_id).await {
            Ok(origin) => origin,
            Err(response) => return response,
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
                    remember_verified_credential_origin(
                        &state,
                        &project_public_id,
                        &token,
                        cors_origin.as_deref(),
                    );
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
    Extension(client): Extension<ClientAddress>,
    Path(project_public_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Ok(token) = bearer_token(&headers) else {
        return unauthorized_runtime(&request_id);
    };
    if let Err(response) = admit_runtime_with_verified_cors(
        &state,
        &client,
        AdmissionEndpoint::BrowserLogoutPrepare,
        &[
            admission_dimension(AdmissionDimensionKind::Project, &project_public_id),
            admission_dimension(AdmissionDimensionKind::Credential, &token),
        ],
        &headers,
        VerifiedOriginSubject::Credential {
            project_public_id: &project_public_id,
            credential: &token,
        },
        &request_id,
    )
    .await
    {
        return response;
    }
    let cors_origin =
        match project_cors_origin(&state, &headers, &project_public_id, &request_id).await {
            Ok(origin) => origin,
            Err(response) => return response,
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
                    remember_verified_credential_origin(
                        &state,
                        &project_public_id,
                        &token,
                        cors_origin.as_deref(),
                    );
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
    Extension(client): Extension<ClientAddress>,
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
    if let Err(response) = admit_runtime(
        &state,
        &client,
        AdmissionEndpoint::BrowserLogoutRead,
        &[admission_dimension(
            AdmissionDimensionKind::Credential,
            &preparation,
        )],
        &request_id,
    )
    .await
    {
        return response;
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
    Extension(client): Extension<ClientAddress>,
    Path((project_public_id, preparation)): Path<(String, String)>,
    headers: HeaderMap,
    RuntimeJson(request): RuntimeJson<runtime_types::ConfirmBrowserLogoutRequest>,
) -> Response {
    if !is_same_origin_mutation(&headers, &state.external_origin) {
        return forbidden_hosted_request(&request_id);
    }
    if let Err(response) = admit_runtime(
        &state,
        &client,
        AdmissionEndpoint::BrowserLogoutConfirm,
        &[
            admission_dimension(AdmissionDimensionKind::Project, &project_public_id),
            admission_dimension(AdmissionDimensionKind::Credential, &preparation),
        ],
        &request_id,
    )
    .await
    {
        return response;
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

async fn control_asset(Path(path): Path<String>) -> Response {
    web_assets::asset(WebPlane::Control, &format!("assets/{path}"))
}

async fn liveness() -> Json<HealthResponse> {
    Json(HealthResponse::ok())
}

async fn runtime_readiness(State(state): State<RuntimeState>) -> Response {
    readiness_response(state.probe.ready.load(Ordering::Acquire))
}

async fn client_readiness(State(state): State<ClientState>) -> Response {
    if !state.probe.ready.load(Ordering::Acquire) {
        return readiness_response(false);
    }
    let ready = match state.readiness.as_deref() {
        Some(readiness) => readiness
            .readiness()
            .await
            .is_ok_and(|snapshot| snapshot.is_ready()),
        None => true,
    };
    readiness_response(ready)
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientUserListQuery {
    cursor: Option<String>,
    limit: Option<usize>,
}

async fn client_list_project_users(
    State(state): State<ClientState>,
    Extension(request_id): Extension<String>,
    Extension(principal): Extension<application::ClientPrincipal>,
    OriginalUri(uri): OriginalUri,
) -> Response {
    let Ok(Query(query)) = Query::<ClientUserListQuery>::try_from_uri(&uri) else {
        return client_problem(ApplicationError::InvalidInput, &request_id);
    };
    let result = client_api(&state)
        .map(|service| service.list_users(&principal, query.cursor.as_deref(), query.limit));
    let result = match result {
        Ok(future) => future.await.and_then(client_user_list),
        Err(error) => Err(error),
    };
    client_json(result, &request_id)
}

async fn client_get_project_user(
    State(state): State<ClientState>,
    Extension(request_id): Extension<String>,
    Extension(principal): Extension<application::ClientPrincipal>,
    Path((_project_id, user_id)): Path<(String, String)>,
) -> Response {
    let result = match client_api(&state) {
        Ok(service) => service.user(&principal, &user_id).await.map(client_user),
        Err(error) => Err(error),
    };
    client_json(result, &request_id)
}

async fn client_lookup_project_user(
    State(state): State<ClientState>,
    Extension(request_id): Extension<String>,
    Extension(principal): Extension<application::ClientPrincipal>,
    ClientJson(request): ClientJson<client_types::LookupClientUserRequest>,
) -> Response {
    let result = match client_api(&state) {
        Ok(service) => service
            .lookup_user_by_email(&principal, &request.email)
            .await
            .map(|user| client_types::LookupClientUserResponse {
                user: user.map(client_user),
            }),
        Err(error) => Err(error),
    };
    client_json(result, &request_id)
}

async fn client_get_application_user_projection(
    State(state): State<ClientState>,
    Extension(request_id): Extension<String>,
    Extension(principal): Extension<application::ClientPrincipal>,
    Path((_project_id, application_id, user_id)): Path<(String, String, String)>,
) -> Response {
    let result = match client_api(&state) {
        Ok(service) => service
            .application_projection(&principal, &application_id, &user_id)
            .await
            .and_then(client_application_projection),
        Err(error) => Err(error),
    };
    client_json(result, &request_id)
}

async fn client_introspect_project_token(
    State(state): State<ClientState>,
    Extension(request_id): Extension<String>,
    Extension(principal): Extension<application::ClientPrincipal>,
    ClientJson(request): ClientJson<client_types::IntrospectProjectTokenRequest>,
) -> Response {
    let result = match client_api(&state) {
        Ok(service) => service
            .introspect(
                &principal,
                &request.token,
                request.expected_application_id.as_deref(),
            )
            .await
            .and_then(client_token_introspection),
        Err(error) => Err(error),
    };
    client_json(result, &request_id)
}

fn client_api(state: &ClientState) -> Result<&application::ClientApiService, ApplicationError> {
    state.api.as_deref().ok_or(ApplicationError::Persistence)
}

fn client_user(user: application::ClientUser) -> client_types::ClientUser {
    client_types::ClientUser {
        user_id: user.user_public_id,
        project_id: user.project_public_id,
        status: match user.status {
            application::ClientUserStatus::Active => client_types::ClientUserStatus::Active,
            application::ClientUserStatus::Disabled => client_types::ClientUserStatus::Disabled,
            application::ClientUserStatus::Merged => client_types::ClientUserStatus::Merged,
        },
        display_name: user.display_name,
        picture_url: user.picture_url,
        verified_email: user.primary_verified_email,
        user_revision: user.user_revision,
        created_at: timestamp(user.created_at),
        updated_at: timestamp(user.updated_at),
    }
}

fn client_user_list(
    page: application::ClientUserPage,
) -> Result<client_types::ClientUserList, ApplicationError> {
    if page.users.len() > application::MAX_CLIENT_USER_PAGE_LIMIT {
        return Err(ApplicationError::Integrity);
    }
    Ok(client_types::ClientUserList {
        items: page.users.into_iter().map(client_user).collect(),
        next_cursor: page.next_cursor,
    })
}

fn client_application_projection(
    projection: application::ClientApplicationProjection,
) -> Result<client_types::ClientApplicationUserProjection, ApplicationError> {
    // The document's updated_at is the projected Project-user timestamp. The projection row's
    // updated_at is storage/materialization metadata and may legitimately be later after first
    // materialization or repair, so it must not redefine or invalidate the public document field.
    client_projection_document(
        projection.project_public_id,
        projection.application_public_id,
        projection.user_public_id,
        projection.projection_revision,
        projection.document,
    )
}

fn client_projection_document(
    project_public_id: String,
    application_public_id: String,
    user_public_id: String,
    projection_revision: i64,
    document: serde_json::Value,
) -> Result<client_types::ClientApplicationUserProjection, ApplicationError> {
    let document = user_projection(document)?;
    if document.user_id != user_public_id || document.projection_revision != projection_revision {
        return Err(ApplicationError::Integrity);
    }
    Ok(client_types::ClientApplicationUserProjection {
        project_id: project_public_id,
        application_id: application_public_id,
        user_id: user_public_id,
        projection_schema: document.projection_schema,
        user_revision: document.user_revision,
        projection_revision: document.projection_revision,
        display_name: document.display_name,
        picture_url: document.picture_url,
        locale: document.locale,
        verified_email: document.verified_email,
        status: document.status,
        created_at: document.created_at,
        updated_at: document.updated_at,
    })
}

fn client_token_introspection(
    result: application::ClientTokenIntrospection,
) -> Result<client_types::ProjectTokenIntrospectionResponse, ApplicationError> {
    match result {
        application::ClientTokenIntrospection::Inactive => {
            Ok(client_types::ProjectTokenIntrospectionResponse::Inactive(
                client_types::InactiveProjectToken { active: false },
            ))
        }
        application::ClientTokenIntrospection::Active(active) => {
            let projection = client_projection_document(
                active.project_public_id.clone(),
                active.application_public_id.clone(),
                active.user_public_id.clone(),
                active.projection_revision,
                active.projection_document,
            )?;
            Ok(client_types::ProjectTokenIntrospectionResponse::Active(
                client_types::ActiveProjectToken {
                    active: true,
                    project_id: active.project_public_id,
                    application_id: active.application_public_id,
                    user_id: active.user_public_id,
                    session_id: active.application_session_id.to_string(),
                    token_type: active.token_type,
                    issued_at: timestamp(active.issued_at),
                    expires_at: timestamp(active.expires_at),
                    user_revision: active.user_revision,
                    session_revision: active.session_revision,
                    application_revision: active.application_revision,
                    projection,
                },
            ))
        }
    }
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

struct ClientJson<T>(T);

impl<S, T> FromRequest<S> for ClientJson<T>
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
                client_error_response(
                    StatusCode::BAD_REQUEST,
                    client_types::ClientErrorCode::InvalidRequest,
                    "The Client request body must be bounded JSON matching the operation schema.",
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

async fn require_client_key(
    State(state): State<ClientState>,
    Extension(client): Extension<ClientAddress>,
    Path(parameters): Path<HashMap<String, String>>,
    mut request: Request,
    next: Next,
) -> Response {
    let request_id = request
        .extensions()
        .get::<String>()
        .cloned()
        .unwrap_or_else(|| "unavailable".to_owned());
    if let AdmissionDecision::Rejected {
        retry_after_seconds,
        ..
    } = state.admission.admit_client_pre_authority(&client.0).await
    {
        return client_rate_limited_response(retry_after_seconds, &request_id);
    }
    let Some(project_public_id) = parameters.get("project_id") else {
        return client_problem(ApplicationError::InvalidInput, &request_id);
    };
    let Some(credential) = client_bearer_credential(request.headers()) else {
        return client_credential_denial(&state, &client, &request_id).await;
    };
    let service = match client_api(&state) {
        Ok(service) => service,
        Err(error) => return client_problem(error, &request_id),
    };
    let principal = service.authenticate(project_public_id, credential).await;
    match principal {
        Ok(principal) => {
            let project_id = principal.project_id.to_string();
            let key_id = principal.key_id.to_string();
            if let AdmissionDecision::Rejected {
                retry_after_seconds,
                ..
            } = state
                .admission
                .admit_client_authoritative(&client.0, &project_id, &key_id)
                .await
            {
                return client_rate_limited_response(retry_after_seconds, &request_id);
            }
            service.observe_client_key_usage(&principal);
            request.headers_mut().remove(header::AUTHORIZATION);
            request.extensions_mut().insert(principal);
            next.run(request).await
        }
        Err(
            ApplicationError::Integrity
            | ApplicationError::Persistence
            | ApplicationError::ExternalStore,
        ) => client_problem(ApplicationError::Persistence, &request_id),
        Err(_) => client_credential_denial(&state, &client, &request_id).await,
    }
}

async fn client_credential_denial(
    state: &ClientState,
    client: &ClientAddress,
    request_id: &str,
) -> Response {
    match state
        .admission
        .admit_client_credential_failure(&client.0)
        .await
    {
        AdmissionDecision::Allowed => unauthorized_client(request_id),
        AdmissionDecision::Rejected {
            retry_after_seconds,
            ..
        } => client_rate_limited_response(retry_after_seconds, request_id),
    }
}

fn client_bearer_credential(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let value = value.to_str().ok()?;
    let credential = value.strip_prefix("Bearer ")?;
    (!credential.is_empty() && !credential.bytes().any(|byte| byte.is_ascii_whitespace()))
        .then_some(credential)
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

fn provider_onboarding(
    state: &ControlState,
) -> Result<&ProviderOnboardingService, ApplicationError> {
    state
        .provider_onboarding
        .as_deref()
        .ok_or(ApplicationError::Persistence)
}

fn webhook_control(state: &ControlState) -> Result<&WebhookControlService, ApplicationError> {
    state
        .webhooks
        .as_deref()
        .ok_or(ApplicationError::Persistence)
}

async fn list_managed_provider_connections(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, user_id)): Path<(String, String)>,
) -> Response {
    let (project_id, user_id) = match (
        resource_uuid(&project_id, &request_id),
        resource_uuid(&user_id, &request_id),
    ) {
        (Ok(project_id), Ok(user_id)) => (project_id, user_id),
        (Err(response), _) | (_, Err(response)) => return response,
    };
    let Some(repository) = state.managed_connections.as_deref() else {
        return application_problem(ApplicationError::Persistence, &request_id);
    };
    let result = repository
        .list_metadata(project_id, user_id, 100)
        .await
        .and_then(|items| {
            items
                .into_iter()
                .map(managed_connection_response)
                .collect::<Result<Vec<_>, _>>()
        })
        .map(|items| control_types::ManagedProviderConnectionList { items });
    control_json(result, &request_id)
}

#[derive(Clone, Copy)]
enum ManagedControlAction {
    Synchronize,
    Revoke,
    Disconnect,
}

fn managed_owner_preflight(result: Result<(), ApplicationError>) -> Result<(), ApplicationError> {
    result
}

async fn managed_provider_connection_action(
    state: &ControlState,
    request_id: &str,
    project_id: String,
    user_id: String,
    connection_id: String,
    body: control_types::ManagedProviderConnectionActionRequest,
    action: ManagedControlAction,
) -> Response {
    let (project_id, user_id, connection_id) = match (
        resource_uuid(&project_id, request_id),
        resource_uuid(&user_id, request_id),
        resource_uuid(&connection_id, request_id),
    ) {
        (Ok(project_id), Ok(user_id), Ok(connection_id)) => (project_id, user_id, connection_id),
        (Err(response), _, _) | (_, Err(response), _) | (_, _, Err(response)) => return response,
    };
    if body.expected_revision <= 0
        || body.expected_generation <= 0
        || (matches!(
            action,
            ManagedControlAction::Disconnect | ManagedControlAction::Revoke
        ) && !body.confirm)
    {
        return application_problem(ApplicationError::InvalidInput, request_id);
    }
    let Some(repository) = state.managed_connections.as_deref() else {
        return application_problem(ApplicationError::Persistence, request_id);
    };
    if let Err(error) = managed_owner_preflight(
        repository
            .metadata_for_owner(project_id, user_id, connection_id)
            .await
            .map(drop),
    ) {
        return application_problem(error, request_id);
    }
    let now = state.clock.now();
    let result = match action {
        ManagedControlAction::Synchronize => {
            repository
                .request_synchronize(
                    project_id,
                    user_id,
                    connection_id,
                    body.expected_revision,
                    body.expected_generation,
                    now,
                )
                .await
        }
        ManagedControlAction::Revoke => {
            repository
                .request_revocation(
                    project_id,
                    user_id,
                    connection_id,
                    body.expected_revision,
                    body.expected_generation,
                    request_uuid(request_id),
                    now,
                )
                .await
        }
        ManagedControlAction::Disconnect => {
            repository
                .disconnect(
                    project_id,
                    user_id,
                    connection_id,
                    body.expected_revision,
                    body.expected_generation,
                    now,
                )
                .await
        }
    }
    .and_then(managed_connection_response);
    control_json(result, request_id)
}

async fn synchronize_managed_provider_connection(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, user_id, connection_id)): Path<(String, String, String)>,
    ControlJson(body): ControlJson<control_types::ManagedProviderConnectionActionRequest>,
) -> Response {
    managed_provider_connection_action(
        &state,
        &request_id,
        project_id,
        user_id,
        connection_id,
        body,
        ManagedControlAction::Synchronize,
    )
    .await
}

async fn create_managed_reauthorization(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, user_id, connection_id)): Path<(String, String, String)>,
    headers: HeaderMap,
    ControlJson(body): ControlJson<control_types::CreateManagedReauthorizationRequest>,
) -> Response {
    let (project_id, user_id, connection_id, application_id) = match (
        resource_uuid(&project_id, &request_id),
        resource_uuid(&user_id, &request_id),
        resource_uuid(&connection_id, &request_id),
        resource_uuid(&body.application_id, &request_id),
    ) {
        (Ok(project), Ok(user), Ok(connection), Ok(application)) => {
            (project, user, connection, application)
        }
        (Err(response), _, _, _)
        | (_, Err(response), _, _)
        | (_, _, Err(response), _)
        | (_, _, _, Err(response)) => return response,
    };
    let Ok(idempotency_key) = idempotency_key(&headers) else {
        return invalid_idempotency(&request_id);
    };
    let Some(repository) = state.managed_connections.as_deref() else {
        return application_problem(ApplicationError::Persistence, &request_id);
    };
    let metadata = match repository
        .metadata_for_owner(project_id, user_id, connection_id)
        .await
    {
        Ok(metadata) => metadata,
        Err(error) => return application_problem(error, &request_id),
    };
    let Some(service) = state.managed_reauthorization.as_deref() else {
        return application_problem(ApplicationError::Persistence, &request_id);
    };
    let result = service
        .create_for_adapter_key(
            CreateManagedReauthorization {
                project_id,
                user_id,
                connection_id,
                application_id,
                expected_connection_revision: body.expected_connection_revision,
                expected_connection_generation: body.expected_connection_generation,
                expected_credential_generation: body.expected_credential_generation,
                idempotency_key,
                correlation_id: request_uuid(&request_id),
            },
            &metadata.capability_key,
        )
        .await
        .map(
            |created| control_types::CreateManagedReauthorizationResponse {
                interaction: managed_reauthorization_response(created.interaction),
                hosted_target: created.hosted_target,
            },
        );
    control_json(result, &request_id)
}

async fn get_managed_reauthorization(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, user_id, connection_id, interaction_id)): Path<(
        String,
        String,
        String,
        String,
    )>,
) -> Response {
    let ids = (
        resource_uuid(&project_id, &request_id),
        resource_uuid(&user_id, &request_id),
        resource_uuid(&connection_id, &request_id),
        resource_uuid(&interaction_id, &request_id),
    );
    let (Ok(project_id), Ok(user_id), Ok(connection_id), Ok(interaction_id)) = ids else {
        return application_problem(ApplicationError::InvalidInput, &request_id);
    };
    let Some(service) = state.managed_reauthorization.as_deref() else {
        return application_problem(ApplicationError::Persistence, &request_id);
    };
    control_json(
        service
            .read(project_id, user_id, connection_id, interaction_id)
            .await
            .map(managed_reauthorization_response),
        &request_id,
    )
}

async fn cancel_managed_reauthorization(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, user_id, connection_id, interaction_id)): Path<(
        String,
        String,
        String,
        String,
    )>,
    ControlJson(body): ControlJson<control_types::CancelManagedReauthorizationRequest>,
) -> Response {
    let ids = (
        resource_uuid(&project_id, &request_id),
        resource_uuid(&user_id, &request_id),
        resource_uuid(&connection_id, &request_id),
        resource_uuid(&interaction_id, &request_id),
    );
    let (Ok(project_id), Ok(user_id), Ok(connection_id), Ok(interaction_id)) = ids else {
        return application_problem(ApplicationError::InvalidInput, &request_id);
    };
    let Some(service) = state.managed_reauthorization.as_deref() else {
        return application_problem(ApplicationError::Persistence, &request_id);
    };
    control_json(
        service
            .cancel(
                project_id,
                user_id,
                connection_id,
                interaction_id,
                body.expected_revision,
                request_uuid(&request_id),
            )
            .await
            .map(managed_reauthorization_response),
        &request_id,
    )
}

fn managed_reauthorization_response(
    value: application::ManagedReauthorizationView,
) -> control_types::ManagedReauthorization {
    use application::ManagedReauthorizationStatus as Source;
    let status = match value.status {
        Source::AwaitingBrowserBinding => {
            control_types::ManagedReauthorizationStatus::AwaitingBrowserBinding
        }
        Source::AwaitingProviderStart => {
            control_types::ManagedReauthorizationStatus::AwaitingProviderStart
        }
        Source::ProviderAuthorizationStarted => {
            control_types::ManagedReauthorizationStatus::ProviderAuthorizationStarted
        }
        Source::ProviderExchangeInProgress => {
            control_types::ManagedReauthorizationStatus::ProviderExchangeInProgress
        }
        Source::Completed => control_types::ManagedReauthorizationStatus::Completed,
        Source::ProviderExchangeFailed => {
            control_types::ManagedReauthorizationStatus::ProviderExchangeFailed
        }
        Source::Expired => control_types::ManagedReauthorizationStatus::Expired,
        Source::Cancelled => control_types::ManagedReauthorizationStatus::Cancelled,
    };
    control_types::ManagedReauthorization {
        id: value.id.to_string(),
        project_id: value.project_id.to_string(),
        user_id: value.user_id.to_string(),
        connection_id: value.connection_id.to_string(),
        provider_key: value.provider_key,
        application_id: value.application_id.to_string(),
        status,
        revision: value.revision,
        expires_at: timestamp(value.expires_at),
    }
}

async fn disconnect_managed_provider_connection(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, user_id, connection_id)): Path<(String, String, String)>,
    ControlJson(body): ControlJson<control_types::ManagedProviderConnectionActionRequest>,
) -> Response {
    managed_provider_connection_action(
        &state,
        &request_id,
        project_id,
        user_id,
        connection_id,
        body,
        ManagedControlAction::Disconnect,
    )
    .await
}

async fn revoke_managed_provider_connection(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, user_id, connection_id)): Path<(String, String, String)>,
    ControlJson(body): ControlJson<control_types::ManagedProviderConnectionActionRequest>,
) -> Response {
    managed_provider_connection_action(
        &state,
        &request_id,
        project_id,
        user_id,
        connection_id,
        body,
        ManagedControlAction::Revoke,
    )
    .await
}

fn managed_connection_response(
    connection: ManagedConnectionMetadata,
) -> Result<control_types::ManagedProviderConnection, ApplicationError> {
    let state = match connection.state.as_str() {
        "active" => control_types::ManagedProviderConnectionState::Active,
        "reauth_required" => control_types::ManagedProviderConnectionState::ReauthRequired,
        "revoked" => control_types::ManagedProviderConnectionState::Revoked,
        "disconnected" => control_types::ManagedProviderConnectionState::Disconnected,
        _ => return Err(ApplicationError::Integrity),
    };
    Ok(control_types::ManagedProviderConnection {
        id: connection.id.to_string(),
        project_id: connection.project_id.to_string(),
        provider_id: connection.provider_configuration_id.to_string(),
        identity_id: connection.linked_identity_id.to_string(),
        user_id: connection.user_id.to_string(),
        state,
        revision: connection.revision,
        generation: connection.generation,
        credential_generation: connection.credential_generation,
        capability_key: connection.capability_key,
        required_scopes: connection.required_scopes,
        source_schema: connection.source_schema,
        supports_revocation: connection.supports_revocation,
        reauthorization_application_ids: connection
            .reauthorization_application_ids
            .into_iter()
            .map(|id| id.to_string())
            .collect(),
        last_safe_outcome: connection.last_safe_outcome,
        last_synchronized_at: connection.last_synchronized_at.map(timestamp),
        next_synchronize_at: connection.next_synchronize_at.map(timestamp),
        next_renewal_at: connection.next_renewal_at.map(timestamp),
        consecutive_failures: connection.consecutive_failures,
    })
}

fn control_lifecycle(state: &ControlState) -> Result<&ControlLifecycleService, ApplicationError> {
    state
        .lifecycle
        .as_deref()
        .ok_or(ApplicationError::Persistence)
}

fn client_key_lifecycle(
    state: &ControlState,
) -> Result<&application::ClientKeyLifecycleService, ApplicationError> {
    state
        .client_keys
        .as_deref()
        .ok_or(ApplicationError::Persistence)
}

fn email_control(state: &ControlState) -> Result<&EmailControlService, ApplicationError> {
    state
        .email_control
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

async fn get_email_method_policy(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path(project_id): Path<String>,
) -> Response {
    let project_id = match resource_uuid(&project_id, &request_id) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let result = match email_control(&state) {
        Ok(service) => service
            .get_policy(project_id)
            .await
            .map(control_email_policy),
        Err(error) => Err(error),
    };
    control_json(result, &request_id)
}

async fn update_email_method_policy(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path(project_id): Path<String>,
    ControlJson(body): ControlJson<control_types::UpdateEmailMethodPolicyRequest>,
) -> Response {
    let project_id = match resource_uuid(&project_id, &request_id) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let result = match email_control(&state) {
        Ok(service) => service
            .update_policy(
                project_id,
                application::UpdateEmailPolicy {
                    enabled: body.enabled,
                    otp_enabled: body.otp_enabled,
                    magic_link_enabled: body.magic_link_enabled,
                    otp_digits: body.otp_digits,
                    otp_validity_seconds: body.otp_validity_seconds,
                    otp_max_attempts: body.otp_max_attempts,
                    resend_after_seconds: body.resend_after_seconds,
                    max_generations: body.max_generations,
                    magic_validity_seconds: body.magic_validity_seconds,
                    signup_enabled: body.signup_enabled,
                    transferred_magic_link_enabled: body.transferred_magic_link_enabled,
                    allow_deployment_default: body.allow_deployment_default,
                    expected_policy_revision: body.expected_policy_revision,
                    expected_security_revision: body.expected_security_revision,
                },
                request_uuid(&request_id),
            )
            .await
            .map(control_email_policy),
        Err(error) => Err(error),
    };
    control_json(result, &request_id)
}

async fn list_email_assignments(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path(project_id): Path<String>,
) -> Response {
    let project_id = match resource_uuid(&project_id, &request_id) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let result = match email_control(&state) {
        Ok(service) => service.list_assignments(project_id).await.map(|items| {
            control_types::EmailAssignmentList {
                items: items
                    .into_iter()
                    .map(|assignment| control_types::EmailAssignment {
                        project_id: assignment.project_id.to_string(),
                        application_id: assignment.application_id.to_string(),
                        enabled: assignment.enabled,
                        security_revision: assignment.security_revision,
                    })
                    .collect(),
            }
        }),
        Err(error) => Err(error),
    };
    control_json(result, &request_id)
}

async fn assign_email_method(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, application_id)): Path<(String, String)>,
    ControlJson(body): ControlJson<control_types::EmailAssignmentRequest>,
) -> Response {
    let (project_id, application_id) =
        match resource_pair(&project_id, &application_id, &request_id) {
            Ok(value) => value,
            Err(response) => return response,
        };
    let result = match email_control(&state) {
        Ok(service) => match service
            .assign(
                project_id,
                application_id,
                body.enabled,
                body.expected_application_security_revision,
                request_uuid(&request_id),
            )
            .await
        {
            Ok(()) => service
                .get_policy(project_id)
                .await
                .map(control_email_policy),
            Err(error) => Err(error),
        },
        Err(error) => Err(error),
    };
    control_json(result, &request_id)
}

async fn list_smtp_configurations(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path(project_id): Path<String>,
) -> Response {
    let project_id = match resource_uuid(&project_id, &request_id) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let result =
        match email_control(&state) {
            Ok(service) => service.list_smtp(project_id).await.map(|items| {
                control_types::SmtpConfigurationList {
                    items: items.into_iter().map(control_smtp).collect(),
                }
            }),
            Err(error) => Err(error),
        };
    control_json(result, &request_id)
}

async fn reconcile_deployment_smtp_generation(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    headers: HeaderMap,
    ControlJson(body): ControlJson<control_types::ReconcileDeploymentSmtpRequest>,
) -> Response {
    let Ok(idempotency_key) = idempotency_key(&headers) else {
        return invalid_idempotency(&request_id);
    };
    let Some(configured) = state.deployment_smtp.as_deref() else {
        return control_json::<control_types::DeploymentSmtpGeneration>(
            Err(ApplicationError::InvalidTransition),
            &request_id,
        );
    };
    let tls_mode = match configured.tls_mode.as_str() {
        "implicit_tls" => application::SmtpControlTlsMode::ImplicitTls,
        "starttls_required" => application::SmtpControlTlsMode::StarttlsRequired,
        _ => {
            return control_json::<control_types::DeploymentSmtpGeneration>(
                Err(ApplicationError::Integrity),
                &request_id,
            );
        }
    };
    let result = match email_control(&state) {
        Ok(service) => service
            .reconcile_deployment_smtp(application::ReconcileDeploymentSmtpGeneration {
                generation: configured.generation,
                host: configured.host.clone(),
                port: configured.port,
                tls_mode,
                sender_address: configured.sender_address.clone(),
                expected_safe_fingerprint: configured.safe_fingerprint,
                explicitly_allowed_private_ips: configured.explicitly_allowed_private_ips.clone(),
                credential: zeroize::Zeroizing::new(body.credential),
                idempotency_key,
                correlation_id: request_uuid(&request_id),
            })
            .await
            .map(control_deployment_smtp),
        Err(error) => Err(error),
    };
    control_json(result, &request_id)
}

async fn list_deployment_smtp_generations(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
) -> Response {
    let result = match email_control(&state) {
        Ok(service) => service.list_deployment_smtp().await.map(|items| {
            control_types::DeploymentSmtpGenerationList {
                items: items.into_iter().map(control_deployment_smtp).collect(),
            }
        }),
        Err(error) => Err(error),
    };
    control_json(result, &request_id)
}

async fn disable_deployment_smtp_generation(
    state: State<ControlState>,
    request_id: Extension<String>,
    path: Path<String>,
    body: ControlJson<control_types::SmtpRevisionRequest>,
) -> Response {
    mutate_deployment_smtp(state, request_id, path, body, false).await
}

async fn compromise_deployment_smtp_generation(
    state: State<ControlState>,
    request_id: Extension<String>,
    path: Path<String>,
    body: ControlJson<control_types::SmtpRevisionRequest>,
) -> Response {
    mutate_deployment_smtp(state, request_id, path, body, true).await
}

async fn mutate_deployment_smtp(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path(generation): Path<String>,
    ControlJson(body): ControlJson<control_types::SmtpRevisionRequest>,
    compromised: bool,
) -> Response {
    let Ok(generation) = generation.parse::<i32>() else {
        return control_json::<control_types::DeploymentSmtpGeneration>(
            Err(ApplicationError::InvalidInput),
            &request_id,
        );
    };
    let result = match email_control(&state) {
        Ok(service) => service
            .terminate_deployment_smtp(
                generation,
                body.expected_revision,
                compromised,
                request_uuid(&request_id),
            )
            .await
            .map(control_deployment_smtp),
        Err(error) => Err(error),
    };
    control_json(result, &request_id)
}

async fn create_smtp_configuration(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path(project_id): Path<String>,
    headers: HeaderMap,
    ControlJson(body): ControlJson<control_types::CreateSmtpConfigurationRequest>,
) -> Response {
    let project_id = match resource_uuid(&project_id, &request_id) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let Ok(idempotency_key) = idempotency_key(&headers) else {
        return invalid_idempotency(&request_id);
    };
    let tls_mode = match body.tls_mode {
        control_types::SmtpTlsMode::ImplicitTls => application::SmtpControlTlsMode::ImplicitTls,
        control_types::SmtpTlsMode::StarttlsRequired => {
            application::SmtpControlTlsMode::StarttlsRequired
        }
    };
    let result = match email_control(&state) {
        Ok(service) => service
            .create_smtp(
                project_id,
                CreateSmtpConfiguration {
                    host: body.host,
                    port: body.port,
                    tls_mode,
                    sender_address: body.sender_address,
                    sender_name: body.sender_name,
                    reply_to: body.reply_to,
                    credential: zeroize::Zeroizing::new(body.credential),
                    idempotency_key,
                    expected_project_security_revision: body.expected_project_security_revision,
                    correlation_id: request_uuid(&request_id),
                },
            )
            .await
            .map(control_smtp),
        Err(error) => Err(error),
    };
    control_json(result, &request_id)
}

async fn test_smtp_configuration(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, smtp_id)): Path<(String, String)>,
    headers: HeaderMap,
    ControlJson(body): ControlJson<control_types::TestSmtpConfigurationRequest>,
) -> Response {
    let (project_id, smtp_id) = match resource_pair(&project_id, &smtp_id, &request_id) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let Ok(idempotency_key) = idempotency_key(&headers) else {
        return invalid_idempotency(&request_id);
    };
    let result = match email_control(&state) {
        Ok(service) => service
            .test_smtp(
                project_id,
                smtp_id,
                &body.recipient,
                body.expected_revision,
                idempotency_key,
                request_uuid(&request_id),
            )
            .await
            .map(|record| control_smtp_test(&record)),
        Err(error) => Err(error),
    };
    let operation_id = result.as_ref().ok().map(|operation| operation.id.clone());
    let mut response = control_json(result, &request_id);
    if let Some(operation_id) = operation_id {
        *response.status_mut() = StatusCode::ACCEPTED;
        if let Ok(value) = HeaderValue::from_str(&format!(
            "/v1/projects/{project_id}/smtp-configurations/{smtp_id}/tests/{operation_id}"
        )) {
            response.headers_mut().insert(header::LOCATION, value);
        }
    }
    response
}

async fn get_smtp_test_operation(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, smtp_id, operation_id)): Path<(String, String, String)>,
) -> Response {
    let Ok(project_id) = Uuid::parse_str(&project_id) else {
        return control_json::<()>(Err(ApplicationError::InvalidInput), &request_id);
    };
    let Ok(smtp_id) = Uuid::parse_str(&smtp_id) else {
        return control_json::<()>(Err(ApplicationError::InvalidInput), &request_id);
    };
    let Ok(operation_id) = Uuid::parse_str(&operation_id) else {
        return control_json::<()>(Err(ApplicationError::InvalidInput), &request_id);
    };
    let result = match email_control(&state) {
        Ok(service) => service
            .get_smtp_test(project_id, operation_id)
            .await
            .and_then(|record| {
                if record.configuration_id == smtp_id {
                    Ok(control_smtp_test(&record))
                } else {
                    Err(ApplicationError::NotFound)
                }
            }),
        Err(error) => Err(error),
    };
    control_json(result, &request_id)
}

async fn activate_smtp_configuration(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, smtp_id)): Path<(String, String)>,
    ControlJson(body): ControlJson<control_types::SmtpRevisionRequest>,
) -> Response {
    mutate_smtp(
        state,
        request_id,
        project_id,
        smtp_id,
        body.expected_revision,
        0,
    )
    .await
}

async fn disable_smtp_configuration(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, smtp_id)): Path<(String, String)>,
    ControlJson(body): ControlJson<control_types::SmtpRevisionRequest>,
) -> Response {
    mutate_smtp(
        state,
        request_id,
        project_id,
        smtp_id,
        body.expected_revision,
        1,
    )
    .await
}

async fn compromise_smtp_configuration(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, smtp_id)): Path<(String, String)>,
    ControlJson(body): ControlJson<control_types::SmtpRevisionRequest>,
) -> Response {
    mutate_smtp(
        state,
        request_id,
        project_id,
        smtp_id,
        body.expected_revision,
        2,
    )
    .await
}

async fn mutate_smtp(
    state: ControlState,
    request_id: String,
    project_id: String,
    smtp_id: String,
    expected_revision: i64,
    action: u8,
) -> Response {
    let (project_id, smtp_id) = match resource_pair(&project_id, &smtp_id, &request_id) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let result = match email_control(&state) {
        Ok(service) => match action {
            0 => {
                service
                    .activate_smtp(
                        project_id,
                        smtp_id,
                        expected_revision,
                        request_uuid(&request_id),
                    )
                    .await
            }
            1 => {
                service
                    .terminate_smtp(
                        project_id,
                        smtp_id,
                        expected_revision,
                        false,
                        request_uuid(&request_id),
                    )
                    .await
            }
            _ => {
                service
                    .terminate_smtp(
                        project_id,
                        smtp_id,
                        expected_revision,
                        true,
                        request_uuid(&request_id),
                    )
                    .await
            }
        }
        .map(control_smtp),
        Err(error) => Err(error),
    };
    control_json(result, &request_id)
}

fn control_email_policy(
    record: application::EmailPolicyRecord,
) -> control_types::EmailMethodPolicy {
    control_types::EmailMethodPolicy {
        project_id: record.project_id.to_string(),
        enabled: record.enabled,
        policy_revision: record.policy_revision,
        security_revision: record.security_revision,
        otp_enabled: record.otp_enabled,
        magic_link_enabled: record.magic_link_enabled,
        otp_digits: record.otp_digits,
        otp_validity_seconds: record.otp_validity_seconds,
        otp_max_attempts: record.otp_max_attempts,
        resend_after_seconds: record.resend_after_seconds,
        max_generations: record.max_generations,
        magic_validity_seconds: record.magic_validity_seconds,
        signup_enabled: record.signup_enabled,
        transferred_magic_link_enabled: record.transferred_magic_link_enabled,
        allow_deployment_default: record.allow_deployment_default,
    }
}

fn control_smtp_test(
    record: &application::SmtpTestOperationRecord,
) -> control_types::SmtpTestOperation {
    control_types::SmtpTestOperation {
        id: record.id.to_string(),
        project_id: record.project_id.to_string(),
        smtp_configuration_id: record.configuration_id.to_string(),
        status: match record.state {
            application::SmtpTestState::Preparing => "preparing",
            application::SmtpTestState::Pending => "pending",
            application::SmtpTestState::Submitting => "submitting",
            application::SmtpTestState::Delivered => "delivered",
            application::SmtpTestState::Failed => "failed",
            application::SmtpTestState::Ambiguous => "ambiguous",
        }
        .to_owned(),
        outcome: record.outcome.map(|outcome| {
            match outcome {
                application::MailTransportOutcome::Delivered => "delivered",
                application::MailTransportOutcome::Transient => "transient",
                application::MailTransportOutcome::Permanent => "permanent",
                application::MailTransportOutcome::Ambiguous => "ambiguous",
                application::MailTransportOutcome::PolicyDenied => "policy_denied",
            }
            .to_owned()
        }),
        created_at: record.created_at.format(&Rfc3339).unwrap_or_default(),
        completed_at: record
            .completed_at
            .map(|value| value.format(&Rfc3339).unwrap_or_default()),
    }
}

fn control_smtp(record: application::SmtpConfigurationRecord) -> control_types::SmtpConfiguration {
    let status = match record.status {
        application::SmtpControlStatus::Reconciled => {
            control_types::SmtpGenerationStatus::Reconciled
        }
        application::SmtpControlStatus::Pending => control_types::SmtpGenerationStatus::Pending,
        application::SmtpControlStatus::Active => control_types::SmtpGenerationStatus::Active,
        application::SmtpControlStatus::Retained => control_types::SmtpGenerationStatus::Retained,
        application::SmtpControlStatus::Disabled => control_types::SmtpGenerationStatus::Disabled,
        application::SmtpControlStatus::Compromised => {
            control_types::SmtpGenerationStatus::Compromised
        }
        application::SmtpControlStatus::Retired => control_types::SmtpGenerationStatus::Retired,
    };
    let tls_mode = match record.tls_mode {
        application::SmtpControlTlsMode::ImplicitTls => control_types::SmtpTlsMode::ImplicitTls,
        application::SmtpControlTlsMode::StarttlsRequired => {
            control_types::SmtpTlsMode::StarttlsRequired
        }
    };
    control_types::SmtpConfiguration {
        id: record.id.to_string(),
        project_id: record.project_id.to_string(),
        generation: record.generation,
        revision: record.revision,
        security_eligibility_revision: record.security_eligibility_revision,
        status,
        host: record.host,
        port: record.port,
        tls_mode,
        sender_address: record.sender_address,
        sender_name: record.sender_name,
        reply_to: record.reply_to,
        retained_until: record.retained_until.map(timestamp),
        safe_fingerprint: record
            .safe_fingerprint
            .map(|fingerprint| URL_SAFE_NO_PAD.encode(fingerprint)),
    }
}

fn control_deployment_smtp(
    record: application::DeploymentSmtpGenerationRecord,
) -> control_types::DeploymentSmtpGeneration {
    let status = match record.status {
        application::SmtpControlStatus::Reconciled => {
            control_types::SmtpGenerationStatus::Reconciled
        }
        application::SmtpControlStatus::Pending => control_types::SmtpGenerationStatus::Pending,
        application::SmtpControlStatus::Active => control_types::SmtpGenerationStatus::Active,
        application::SmtpControlStatus::Retained => control_types::SmtpGenerationStatus::Retained,
        application::SmtpControlStatus::Disabled => control_types::SmtpGenerationStatus::Disabled,
        application::SmtpControlStatus::Compromised => {
            control_types::SmtpGenerationStatus::Compromised
        }
        application::SmtpControlStatus::Retired => control_types::SmtpGenerationStatus::Retired,
    };
    let tls_mode = match record.tls_mode {
        application::SmtpControlTlsMode::ImplicitTls => control_types::SmtpTlsMode::ImplicitTls,
        application::SmtpControlTlsMode::StarttlsRequired => {
            control_types::SmtpTlsMode::StarttlsRequired
        }
    };
    control_types::DeploymentSmtpGeneration {
        generation: record.generation,
        revision: record.revision,
        security_eligibility_revision: record.security_eligibility_revision,
        status,
        host: record.host,
        port: record.port,
        tls_mode,
        sender_address: record.sender_address,
        retained_until: record.retained_until.map(timestamp),
        safe_fingerprint: URL_SAFE_NO_PAD.encode(record.safe_fingerprint),
        explicitly_allowed_private_ips: record
            .explicitly_allowed_private_ips
            .into_iter()
            .map(|address| address.to_string())
            .collect(),
    }
}

fn parse_identity_user_target(
    target: &control_types::IdentityMutationUserTarget,
) -> Result<application::ExpectedUser, ApplicationError> {
    Ok(application::ExpectedUser {
        user_id: Uuid::parse_str(&target.user_id).map_err(|_| ApplicationError::InvalidInput)?,
        expected_user_revision: target.expected_user_revision,
        expected_user_security_revision: target.expected_user_security_revision,
    })
}

fn parse_identity_reference(
    reference: control_types::ExistingIdentityReference,
) -> Result<application::ExpectedIdentity, ApplicationError> {
    let (identity_kind, identity_id, expected_identity_revision) = match reference {
        control_types::ExistingIdentityReference::Provider {
            identity_id,
            expected_identity_revision,
        } => (
            crate::domain::IdentityKind::Provider,
            identity_id,
            expected_identity_revision,
        ),
        control_types::ExistingIdentityReference::Email {
            identity_id,
            expected_identity_revision,
        } => (
            crate::domain::IdentityKind::Email,
            identity_id,
            expected_identity_revision,
        ),
    };
    Ok(application::ExpectedIdentity {
        identity_kind,
        identity_id: Uuid::parse_str(&identity_id).map_err(|_| ApplicationError::InvalidInput)?,
        expected_identity_revision,
    })
}

fn parse_identity_authority(
    authority: control_types::IdentityMutationProofAuthority,
) -> Result<application::IdentityMutationProofAuthoritySelection, ApplicationError> {
    match authority {
        control_types::IdentityMutationProofAuthority::Provider {
            application_id,
            provider_id,
        } => Ok(
            application::IdentityMutationProofAuthoritySelection::Provider {
                application_id: Uuid::parse_str(&application_id)
                    .map_err(|_| ApplicationError::InvalidInput)?,
                provider_configuration_id: Uuid::parse_str(&provider_id)
                    .map_err(|_| ApplicationError::InvalidInput)?,
            },
        ),
        control_types::IdentityMutationProofAuthority::Email { application_id } => Ok(
            application::IdentityMutationProofAuthoritySelection::Email {
                application_id: Uuid::parse_str(&application_id)
                    .map_err(|_| ApplicationError::InvalidInput)?,
            },
        ),
    }
}

fn parse_unlink_primary(
    disposition: control_types::UnlinkPrimarySourceDisposition,
) -> Result<application::IdentityMutationPrimarySourceDisposition, ApplicationError> {
    match disposition {
        control_types::UnlinkPrimarySourceDisposition::Preserve => {
            Ok(application::IdentityMutationPrimarySourceDisposition::Preserve)
        }
        control_types::UnlinkPrimarySourceDisposition::Clear => {
            Ok(application::IdentityMutationPrimarySourceDisposition::Clear)
        }
        control_types::UnlinkPrimarySourceDisposition::Provider {
            identity_id,
            expected_identity_revision,
        } => Ok(
            application::IdentityMutationPrimarySourceDisposition::Provider(
                application::ExpectedIdentity {
                    identity_kind: crate::domain::IdentityKind::Provider,
                    identity_id: Uuid::parse_str(&identity_id)
                        .map_err(|_| ApplicationError::InvalidInput)?,
                    expected_identity_revision,
                },
            ),
        ),
        control_types::UnlinkPrimarySourceDisposition::Email {
            identity_id,
            expected_identity_revision,
        } => Ok(
            application::IdentityMutationPrimarySourceDisposition::Email(
                application::ExpectedIdentity {
                    identity_kind: crate::domain::IdentityKind::Email,
                    identity_id: Uuid::parse_str(&identity_id)
                        .map_err(|_| ApplicationError::InvalidInput)?,
                    expected_identity_revision,
                },
            ),
        ),
    }
}

fn parse_merge_primary(
    source: control_types::MergePrimarySource,
) -> Result<application::IdentityMutationPrimarySourceDisposition, ApplicationError> {
    match source {
        control_types::MergePrimarySource::Provider {
            identity_id,
            expected_identity_revision,
        } => Ok(
            application::IdentityMutationPrimarySourceDisposition::Provider(
                application::ExpectedIdentity {
                    identity_kind: crate::domain::IdentityKind::Provider,
                    identity_id: Uuid::parse_str(&identity_id)
                        .map_err(|_| ApplicationError::InvalidInput)?,
                    expected_identity_revision,
                },
            ),
        ),
        control_types::MergePrimarySource::Email {
            identity_id,
            expected_identity_revision,
        } => Ok(
            application::IdentityMutationPrimarySourceDisposition::Email(
                application::ExpectedIdentity {
                    identity_kind: crate::domain::IdentityKind::Email,
                    identity_id: Uuid::parse_str(&identity_id)
                        .map_err(|_| ApplicationError::InvalidInput)?,
                    expected_identity_revision,
                },
            ),
        ),
    }
}

fn parse_identity_operation(
    request: control_types::CreateIdentityMutationIntentRequest,
) -> Result<application::IdentityMutationCreateOperation, ApplicationError> {
    match request {
        control_types::CreateIdentityMutationIntentRequest::Link {
            destination,
            destination_identity,
            candidate_identity_kind,
            destination_proof_authority,
            candidate_proof_authority,
        } => Ok(application::IdentityMutationCreateOperation::Link {
            destination: parse_identity_user_target(&destination)?,
            destination_identity: parse_identity_reference(destination_identity)?,
            candidate_kind: match candidate_identity_kind {
                runtime_types::IdentityKind::Provider => crate::domain::IdentityKind::Provider,
                runtime_types::IdentityKind::Email => crate::domain::IdentityKind::Email,
            },
            destination_authority: parse_identity_authority(destination_proof_authority)?,
            candidate_authority: parse_identity_authority(candidate_proof_authority)?,
        }),
        control_types::CreateIdentityMutationIntentRequest::Unlink {
            owner,
            identity,
            proof_authority,
            primary_source_disposition,
        } => Ok(application::IdentityMutationCreateOperation::Unlink {
            owner: parse_identity_user_target(&owner)?,
            identity: parse_identity_reference(identity)?,
            authority: parse_identity_authority(proof_authority)?,
            primary_source: parse_unlink_primary(primary_source_disposition)?,
        }),
        control_types::CreateIdentityMutationIntentRequest::Merge {
            winner,
            winner_identity,
            winner_proof_authority,
            loser,
            loser_identity,
            loser_proof_authority,
            primary_source,
            sessions_disposition: _,
            bindings_disposition: _,
        } => Ok(application::IdentityMutationCreateOperation::Merge {
            winner: parse_identity_user_target(&winner)?,
            winner_identity: parse_identity_reference(winner_identity)?,
            loser: parse_identity_user_target(&loser)?,
            loser_identity: parse_identity_reference(loser_identity)?,
            winner_authority: parse_identity_authority(winner_proof_authority)?,
            loser_authority: parse_identity_authority(loser_proof_authority)?,
            primary_source: parse_merge_primary(primary_source)?,
            sessions: application::IdentityMutationSessionsDisposition::LoserRevoked,
            bindings: application::IdentityMutationBindingsDisposition::WinnerPreferred,
        }),
    }
}

async fn create_identity_mutation_intent(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path(project_id): Path<String>,
    headers: HeaderMap,
    ControlJson(body): ControlJson<control_types::CreateIdentityMutationIntentRequest>,
) -> Response {
    let project_id = match resource_uuid(&project_id, &request_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    let Ok(idempotency_key) = idempotency_key(&headers) else {
        return invalid_idempotency(&request_id);
    };
    let operation = match parse_identity_operation(body) {
        Ok(operation) => operation,
        Err(error) => return application_problem(error, &request_id),
    };
    let Some(service) = state.identity_mutations.as_deref() else {
        return application_problem(ApplicationError::Persistence, &request_id);
    };
    match service
        .create(application::CreateIdentityMutation {
            project_id,
            operation,
            idempotency_key,
            correlation_id: request_uuid(&request_id),
        })
        .await
    {
        Ok(created) => (
            StatusCode::CREATED,
            Json(control_types::CreateIdentityMutationIntentResponse {
                intent: control_identity_mutation_view(created.intent),
                hosted_target: created.hosted_target,
            }),
        )
            .into_response(),
        Err(error) => application_problem(error, &request_id),
    }
}

async fn get_identity_mutation_intent(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, intent_id)): Path<(String, String)>,
) -> Response {
    let (project_id, intent_id) = match resource_pair(&project_id, &intent_id, &request_id) {
        Ok(ids) => ids,
        Err(response) => return response,
    };
    let Some(service) = state.identity_mutations.as_deref() else {
        return application_problem(ApplicationError::Persistence, &request_id);
    };
    control_json(
        service
            .read(project_id, intent_id)
            .await
            .map(control_identity_mutation_view),
        &request_id,
    )
}

async fn cancel_identity_mutation_intent(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, intent_id)): Path<(String, String)>,
    ControlJson(body): ControlJson<control_types::CancelIdentityMutationIntentRequest>,
) -> Response {
    let (project_id, intent_id) = match resource_pair(&project_id, &intent_id, &request_id) {
        Ok(ids) => ids,
        Err(response) => return response,
    };
    let Some(service) = state.identity_mutations.as_deref() else {
        return application_problem(ApplicationError::Persistence, &request_id);
    };
    control_json(
        service
            .cancel(
                project_id,
                intent_id,
                body.expected_revision,
                request_uuid(&request_id),
            )
            .await
            .map(control_identity_mutation_view),
        &request_id,
    )
}

async fn confirm_identity_mutation_intent(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, intent_id)): Path<(String, String)>,
    ControlJson(body): ControlJson<control_types::ConfirmIdentityMutationIntentRequest>,
) -> Response {
    let (project_id, intent_id) = match resource_pair(&project_id, &intent_id, &request_id) {
        Ok(ids) => ids,
        Err(response) => return response,
    };
    let (expected_revision, expected_kind) = match body {
        control_types::ConfirmIdentityMutationIntentRequest::Link {
            expected_revision, ..
        } => (expected_revision, crate::domain::IdentityMutationKind::Link),
        control_types::ConfirmIdentityMutationIntentRequest::Unlink {
            expected_revision, ..
        } => (
            expected_revision,
            crate::domain::IdentityMutationKind::Unlink,
        ),
        control_types::ConfirmIdentityMutationIntentRequest::Merge {
            expected_revision, ..
        } => (
            expected_revision,
            crate::domain::IdentityMutationKind::Merge,
        ),
    };
    let Some(service) = state.identity_mutations.as_deref() else {
        return application_problem(ApplicationError::Persistence, &request_id);
    };
    control_json(
        service
            .confirm(
                project_id,
                intent_id,
                expected_revision,
                expected_kind,
                request_uuid(&request_id),
            )
            .await
            .map(control_identity_mutation_view),
        &request_id,
    )
}

fn control_identity_mutation_view(
    view: application::IdentityMutationView,
) -> control_types::IdentityMutationIntent {
    control_types::IdentityMutationIntent {
        id: view.id.to_string(),
        project_id: view.project_id.to_string(),
        operation_kind: match view.kind {
            crate::domain::IdentityMutationKind::Link => {
                control_types::IdentityMutationOperationKind::Link
            }
            crate::domain::IdentityMutationKind::Unlink => {
                control_types::IdentityMutationOperationKind::Unlink
            }
            crate::domain::IdentityMutationKind::Merge => {
                control_types::IdentityMutationOperationKind::Merge
            }
        },
        status: match view.status {
            crate::domain::IdentityMutationStatus::PendingProof => {
                control_types::IdentityMutationIntentStatus::PendingProof
            }
            crate::domain::IdentityMutationStatus::Ready => {
                control_types::IdentityMutationIntentStatus::Ready
            }
            crate::domain::IdentityMutationStatus::Completed => {
                control_types::IdentityMutationIntentStatus::Completed
            }
            crate::domain::IdentityMutationStatus::Expired => {
                control_types::IdentityMutationIntentStatus::Expired
            }
            crate::domain::IdentityMutationStatus::Cancelled => {
                control_types::IdentityMutationIntentStatus::Cancelled
            }
        },
        revision: view.revision,
        effective_expires_at: timestamp(view.expires_at),
        slots: view
            .slots
            .into_iter()
            .map(|slot| control_types::IdentityMutationProofSlot {
                id: slot.id.to_string(),
                role: match slot.role {
                    crate::domain::IdentityMutationSlotRole::DestinationOwner => {
                        control_types::IdentityMutationProofRole::DestinationOwner
                    }
                    crate::domain::IdentityMutationSlotRole::CandidateIdentity => {
                        control_types::IdentityMutationProofRole::CandidateIdentity
                    }
                    crate::domain::IdentityMutationSlotRole::IdentityOwner => {
                        control_types::IdentityMutationProofRole::IdentityOwner
                    }
                    crate::domain::IdentityMutationSlotRole::WinnerOwner => {
                        control_types::IdentityMutationProofRole::WinnerOwner
                    }
                    crate::domain::IdentityMutationSlotRole::LoserOwner => {
                        control_types::IdentityMutationProofRole::LoserOwner
                    }
                },
                identity_kind: match slot.identity_kind {
                    crate::domain::IdentityKind::Provider => runtime_types::IdentityKind::Provider,
                    crate::domain::IdentityKind::Email => runtime_types::IdentityKind::Email,
                },
                method_kind: match slot.method_kind {
                    application::IdentityMutationProofMethodKind::Provider => {
                        runtime_types::IdentityMutationMethodKind::Provider
                    }
                    application::IdentityMutationProofMethodKind::Email => {
                        runtime_types::IdentityMutationMethodKind::Email
                    }
                },
                proved: slot.proved,
            })
            .collect(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListProjectClientKeysQuery {
    cursor: Option<String>,
    limit: Option<usize>,
}

async fn list_project_client_keys(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path(project_id): Path<String>,
    query: Result<Query<ListProjectClientKeysQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let project_id = match resource_uuid(&project_id, &request_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    let Ok(Query(query)) = query else {
        return application_problem(ApplicationError::InvalidInput, &request_id);
    };
    match client_key_lifecycle(&state) {
        Ok(service) => match service
            .list_project_client_keys(project_id, query.cursor.as_deref(), query.limit)
            .await
        {
            Ok((keys, next_cursor, active_unacknowledged_key)) => {
                Json(control_types::ProjectClientKeyList {
                    items: keys.into_iter().map(control_project_client_key).collect(),
                    next_cursor,
                    active_unacknowledged_key: active_unacknowledged_key
                        .map(control_project_client_key),
                })
                .into_response()
            }
            Err(error) => application_problem(error, &request_id),
        },
        Err(error) => application_problem(error, &request_id),
    }
}

async fn get_project_client_key(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, key_id)): Path<(String, String)>,
) -> Response {
    let project_id = match resource_uuid(&project_id, &request_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    let key_id = match resource_uuid(&key_id, &request_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    match client_key_lifecycle(&state) {
        Ok(service) => match service.get_project_client_key(project_id, key_id).await {
            Ok(key) => Json(control_project_client_key(key)).into_response(),
            Err(error) => application_problem(error, &request_id),
        },
        Err(error) => application_problem(error, &request_id),
    }
}

async fn create_project_client_key(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path(project_id): Path<String>,
    headers: HeaderMap,
    ControlJson(body): ControlJson<control_types::CreateProjectClientKeyRequest>,
) -> Response {
    let project_id = match resource_uuid(&project_id, &request_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    let Ok(idempotency_key) = idempotency_key(&headers) else {
        return invalid_idempotency(&request_id);
    };
    let result = match client_key_lifecycle(&state) {
        Ok(service) => {
            service
                .create_project_client_key(application::CreateProjectClientKey {
                    project_id,
                    label: body.label,
                    idempotency_key,
                    correlation_id: request_uuid(&request_id),
                })
                .await
        }
        Err(error) => Err(error),
    };
    match result {
        Ok(application::CreateProjectClientKeyResult::Created {
            metadata,
            credential,
        }) => (
            StatusCode::CREATED,
            Json(control_types::CreateProjectClientKeyResponse {
                key: control_project_client_key(metadata),
                credential: credential.expose().to_owned(),
            }),
        )
            .into_response(),
        Ok(application::CreateProjectClientKeyResult::ReplayWithoutSecret { metadata }) => {
            let detail = format!(
                "This idempotent create already completed for public key ID {}; its one-time credential cannot be shown again. Revoke that key and create another.",
                metadata.public_key_id
            );
            control_problem(
                StatusCode::CONFLICT,
                "secret_unavailable",
                "Credential unavailable",
                &detail,
                &request_id,
            )
        }
        Err(error) => application_problem(error, &request_id),
    }
}

async fn acknowledge_project_client_key_delivery(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, key_id)): Path<(String, String)>,
    headers: HeaderMap,
    ControlJson(body): ControlJson<control_types::AcknowledgeProjectClientKeyDeliveryRequest>,
) -> Response {
    if !body.confirm_stored {
        return application_problem(ApplicationError::InvalidInput, &request_id);
    }
    let (project_id, key_id) = match resource_pair(&project_id, &key_id, &request_id) {
        Ok(ids) => ids,
        Err(response) => return response,
    };
    let Ok(idempotency_key) = idempotency_key(&headers) else {
        return invalid_idempotency(&request_id);
    };
    match client_key_lifecycle(&state) {
        Ok(service) => match service
            .acknowledge_project_client_key_delivery(
                application::AcknowledgeProjectClientKeyDelivery {
                    project_id,
                    key_id,
                    expected_revision: body.expected_revision,
                    idempotency_key,
                    correlation_id: request_uuid(&request_id),
                },
            )
            .await
        {
            Ok(key) => Json(control_project_client_key(key)).into_response(),
            Err(error) => application_problem(error, &request_id),
        },
        Err(error) => application_problem(error, &request_id),
    }
}

async fn revoke_project_client_key(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, key_id)): Path<(String, String)>,
    headers: HeaderMap,
    ControlJson(body): ControlJson<control_types::RevokeProjectClientKeyRequest>,
) -> Response {
    if !body.confirm {
        return application_problem(ApplicationError::InvalidInput, &request_id);
    }
    let (project_id, key_id) = match resource_pair(&project_id, &key_id, &request_id) {
        Ok(ids) => ids,
        Err(response) => return response,
    };
    let Ok(idempotency_key) = idempotency_key(&headers) else {
        return invalid_idempotency(&request_id);
    };
    match client_key_lifecycle(&state) {
        Ok(service) => match service
            .revoke_project_client_key(application::RevokeProjectClientKey {
                project_id,
                key_id,
                expected_revision: body.expected_revision,
                idempotency_key,
                correlation_id: request_uuid(&request_id),
            })
            .await
        {
            Ok(key) => Json(control_project_client_key(key)).into_response(),
            Err(error) => application_problem(error, &request_id),
        },
        Err(error) => application_problem(error, &request_id),
    }
}

#[derive(Debug, Deserialize)]
struct ListProjectUsersQuery {
    status: Option<control_types::ProjectUserStatus>,
    cursor: Option<String>,
    limit: Option<usize>,
}

async fn list_project_users(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path(project_id): Path<String>,
    Query(query): Query<ListProjectUsersQuery>,
) -> Response {
    let project_id = match resource_uuid(&project_id, &request_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    let cursor = match query.cursor.as_deref() {
        Some(value) => match resource_uuid(value, &request_id) {
            Ok(cursor) => Some(cursor),
            Err(response) => return response,
        },
        None => None,
    };
    let status = query.status.map(application_project_user_status);
    match control_lifecycle(&state) {
        Ok(service) => match service
            .list_project_users(project_id, status, cursor, query.limit)
            .await
        {
            Ok(page) => Json(control_types::ProjectUserList {
                items: page.items.into_iter().map(control_project_user).collect(),
                next_cursor: page.next_cursor.map(|cursor| cursor.to_string()),
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

async fn list_project_user_identities(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, user_id)): Path<(String, String)>,
) -> Response {
    let (project_id, user_id) = match resource_pair(&project_id, &user_id, &request_id) {
        Ok(ids) => ids,
        Err(response) => return response,
    };
    match control_lifecycle(&state) {
        Ok(service) => match service
            .list_project_user_identities(project_id, user_id)
            .await
        {
            Ok(identities) => Json(control_types::ProjectUserIdentityList {
                items: identities
                    .into_iter()
                    .map(control_project_user_identity)
                    .collect(),
            })
            .into_response(),
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

async fn enable_project_user(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, user_id)): Path<(String, String)>,
    ControlJson(body): ControlJson<control_types::ExpectedSecurityRevision>,
) -> Response {
    let (project_id, user_id) = match resource_pair(&project_id, &user_id, &request_id) {
        Ok(ids) => ids,
        Err(response) => return response,
    };
    match control_lifecycle(&state) {
        Ok(service) => match service
            .enable_project_user(
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

fn control_project_client_key(
    key: application::ProjectClientKeyRecord,
) -> control_types::ProjectClientKey {
    control_types::ProjectClientKey {
        id: key.id.to_string(),
        project_id: key.project_id.to_string(),
        public_key_id: key.public_key_id,
        label: key.label,
        status: match key.status {
            application::ProjectClientKeyStatus::Active => {
                control_types::ProjectClientKeyStatus::Active
            }
            application::ProjectClientKeyStatus::Revoked => {
                control_types::ProjectClientKeyStatus::Revoked
            }
        },
        digest_key_version: key.digest_key_version,
        display_prefix: key.display_prefix,
        revision: key.revision,
        created_at: timestamp(key.created_at),
        credential_acknowledged_at: key.credential_acknowledged_at.map(timestamp),
        last_used_at: key.last_used_at.map(timestamp),
        revoked_at: key.revoked_at.map(timestamp),
    }
}

fn timestamp(value: OffsetDateTime) -> String {
    value
        .format(&Rfc3339)
        .expect("application timestamps must be representable as RFC 3339")
}

fn control_project_user_identity(
    identity: application::ProjectUserIdentityRecord,
) -> control_types::ProjectUserIdentity {
    let presentation = match identity.kind {
        application::ProjectUserIdentityKind::Provider => {
            control_types::ProjectUserIdentityPresentation::Provider {
                provider_key: identity
                    .provider_key
                    .expect("validated provider inventory has creation provenance"),
            }
        }
        application::ProjectUserIdentityKind::Email => {
            control_types::ProjectUserIdentityPresentation::Email {
                address: control_types::RedactedEmailMarker::Redacted,
            }
        }
    };
    control_types::ProjectUserIdentity {
        id: identity.id.to_string(),
        project_id: identity.project_id.to_string(),
        user_id: identity.user_id.to_string(),
        status: match identity.status {
            application::ProjectUserIdentityStatus::Active => {
                control_types::ProjectUserIdentityStatus::Active
            }
            application::ProjectUserIdentityStatus::Disabled => {
                control_types::ProjectUserIdentityStatus::Disabled
            }
        },
        identity_revision: identity.identity_revision,
        is_primary_source: identity.is_primary_source,
        presentation,
        verified_or_observed_at: timestamp(identity.verified_or_observed_at),
        created_at: timestamp(identity.created_at),
        updated_at: timestamp(identity.updated_at),
    }
}

const fn application_project_user_status(
    status: control_types::ProjectUserStatus,
) -> application::ProjectUserStatus {
    match status {
        control_types::ProjectUserStatus::Active => application::ProjectUserStatus::Active,
        control_types::ProjectUserStatus::Disabled => application::ProjectUserStatus::Disabled,
        control_types::ProjectUserStatus::Merged => application::ProjectUserStatus::Merged,
    }
}

fn control_project_user(user: application::ProjectUserRecord) -> control_types::ProjectUser {
    control_types::ProjectUser {
        id: user.id.to_string(),
        project_id: user.project_id.to_string(),
        public_id: user.public_id,
        status: match user.status {
            application::ProjectUserStatus::Active => control_types::ProjectUserStatus::Active,
            application::ProjectUserStatus::Disabled => control_types::ProjectUserStatus::Disabled,
            application::ProjectUserStatus::Merged => control_types::ProjectUserStatus::Merged,
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

fn webhook_event_type(value: control_types::ApplicationUserEventType) -> String {
    match value {
        control_types::ApplicationUserEventType::Created => "user.projection.created",
        control_types::ApplicationUserEventType::Updated => "user.projection.updated",
        control_types::ApplicationUserEventType::Disabled => "user.projection.disabled",
    }
    .to_owned()
}

fn control_webhook_event_type(
    value: &str,
) -> Result<control_types::ApplicationUserEventType, ApplicationError> {
    match value {
        "user.projection.created" => Ok(control_types::ApplicationUserEventType::Created),
        "user.projection.updated" => Ok(control_types::ApplicationUserEventType::Updated),
        "user.projection.disabled" => Ok(control_types::ApplicationUserEventType::Disabled),
        _ => Err(ApplicationError::Integrity),
    }
}

fn control_webhook_endpoint(
    endpoint: application::WebhookEndpointRecord,
) -> Result<control_types::WebhookEndpoint, ApplicationError> {
    let status = match endpoint.status.as_str() {
        "pending" => control_types::WebhookEndpointStatus::Pending,
        "active" => control_types::WebhookEndpointStatus::Active,
        "disabled" => control_types::WebhookEndpointStatus::Disabled,
        _ => return Err(ApplicationError::Integrity),
    };
    Ok(control_types::WebhookEndpoint {
        id: endpoint.id.to_string(),
        public_id: endpoint.public_id,
        project_id: endpoint.project_id.to_string(),
        application_id: endpoint.application_id.to_string(),
        url: endpoint.url,
        subscribed_event_types: endpoint
            .subscribed_event_types
            .iter()
            .map(|value| control_webhook_event_type(value))
            .collect::<Result<Vec<_>, _>>()?,
        status,
        revision: endpoint.revision,
        current_secret_generation: endpoint.current_secret_generation,
        overlap_secret_generation: endpoint.overlap_secret_generation,
        overlap_expires_at: endpoint.overlap_expires_at.map(timestamp),
        consecutive_failure_count: endpoint.consecutive_failure_count,
        last_delivery_at: endpoint.last_delivery_at.map(timestamp),
        last_success_at: endpoint.last_success_at.map(timestamp),
        last_failure_class: endpoint.last_failure_class,
        last_tested_at: endpoint.last_tested_at.map(timestamp),
        last_test_succeeded_at: endpoint.last_test_succeeded_at.map(timestamp),
        created_at: timestamp(endpoint.created_at),
        updated_at: timestamp(endpoint.updated_at),
    })
}

fn control_application_user_event(
    event: application::ApplicationUserEventRecord,
) -> Result<control_types::ApplicationUserEvent, ApplicationError> {
    Ok(control_types::ApplicationUserEvent {
        event_id: event.event_id,
        project_id: event.project_id.to_string(),
        application_id: event.application_id.to_string(),
        user_id: event.user_id.to_string(),
        event_type: control_webhook_event_type(&event.event_type)?,
        user_revision: event.user_revision,
        projection_revision: event.projection_revision,
        projection_schema: event.projection_schema,
        safe_body: event.safe_body,
        occurred_at: timestamp(event.occurred_at),
    })
}

fn control_webhook_delivery(
    delivery: application::WebhookDeliveryRecord,
) -> Result<control_types::WebhookDelivery, ApplicationError> {
    let state = match delivery.state.as_str() {
        "pending" => control_types::WebhookDeliveryState::Pending,
        "leased" => control_types::WebhookDeliveryState::Leased,
        "delivered" => control_types::WebhookDeliveryState::Delivered,
        "terminal" => control_types::WebhookDeliveryState::Terminal,
        "cancelled" => control_types::WebhookDeliveryState::Cancelled,
        _ => return Err(ApplicationError::Integrity),
    };
    let last_outcome_class = delivery
        .last_outcome_class
        .as_deref()
        .map(|value| match value {
            "accepted" => Ok(control_types::WebhookDeliveryOutcomeClass::Accepted),
            "transient" => Ok(control_types::WebhookDeliveryOutcomeClass::Transient),
            "ambiguous" => Ok(control_types::WebhookDeliveryOutcomeClass::Ambiguous),
            "permanent" => Ok(control_types::WebhookDeliveryOutcomeClass::Permanent),
            _ => Err(ApplicationError::Integrity),
        })
        .transpose()?;
    Ok(control_types::WebhookDelivery {
        id: delivery.id.to_string(),
        endpoint_id: delivery.endpoint_id.to_string(),
        event_id: delivery.event_id,
        replay_sequence: delivery.replay_sequence,
        replay_of_delivery_id: delivery
            .replay_of_delivery_id
            .map(|value| value.to_string()),
        state,
        attempt_count: delivery.attempt_count,
        next_attempt_at: timestamp(delivery.next_attempt_at),
        last_outcome_class,
        last_http_status: delivery.last_http_status,
        delivered_at: delivery.delivered_at.map(timestamp),
        terminal_at: delivery.terminal_at.map(timestamp),
        created_at: timestamp(delivery.created_at),
    })
}

#[allow(
    clippy::result_large_err,
    reason = "Axum handler parsing returns the complete bounded HTTP problem response directly"
)]
fn three_resource_ids(
    first: &str,
    second: &str,
    third: &str,
    request_id: &str,
) -> Result<(Uuid, Uuid, Uuid), Response> {
    match (
        resource_uuid(first, request_id),
        resource_uuid(second, request_id),
        resource_uuid(third, request_id),
    ) {
        (Ok(first), Ok(second), Ok(third)) => Ok((first, second, third)),
        (Err(response), _, _) | (_, Err(response), _) | (_, _, Err(response)) => Err(response),
    }
}

async fn list_webhook_endpoints(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, application_id)): Path<(String, String)>,
) -> Response {
    let (project_id, application_id) =
        match resource_pair(&project_id, &application_id, &request_id) {
            Ok(value) => value,
            Err(response) => return response,
        };
    let result = match webhook_control(&state) {
        Ok(service) => service
            .list_endpoints(project_id, application_id)
            .await
            .and_then(|records| {
                records
                    .into_iter()
                    .map(control_webhook_endpoint)
                    .collect::<Result<Vec<_>, _>>()
            })
            .map(|items| control_types::WebhookEndpointList { items }),
        Err(error) => Err(error),
    };
    control_json(result, &request_id)
}

async fn create_webhook_endpoint(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, application_id)): Path<(String, String)>,
    headers: HeaderMap,
    ControlJson(body): ControlJson<control_types::CreateWebhookEndpointRequest>,
) -> Response {
    let (project_id, application_id) =
        match resource_pair(&project_id, &application_id, &request_id) {
            Ok(value) => value,
            Err(response) => return response,
        };
    let Ok(idempotency_key) = idempotency_key(&headers) else {
        return invalid_idempotency(&request_id);
    };
    let result = match webhook_control(&state) {
        Ok(service) => service
            .create_endpoint(
                project_id,
                application_id,
                application::CreateWebhookEndpoint {
                    url: body.url,
                    subscribed_event_types: body
                        .subscribed_event_types
                        .into_iter()
                        .map(webhook_event_type)
                        .collect(),
                    secret: zeroize::Zeroizing::new(body.secret.into_bytes()),
                    idempotency_key,
                },
                request_uuid(&request_id),
            )
            .await
            .and_then(control_webhook_endpoint),
        Err(error) => Err(error),
    };
    control_json(result, &request_id)
}

async fn get_webhook_endpoint(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, application_id, endpoint_id)): Path<(String, String, String)>,
) -> Response {
    let (project_id, application_id, endpoint_id) =
        match three_resource_ids(&project_id, &application_id, &endpoint_id, &request_id) {
            Ok(value) => value,
            Err(response) => return response,
        };
    let result = match webhook_control(&state) {
        Ok(service) => service
            .get_endpoint(project_id, application_id, endpoint_id)
            .await
            .and_then(control_webhook_endpoint),
        Err(error) => Err(error),
    };
    control_json(result, &request_id)
}

async fn update_webhook_endpoint(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, application_id, endpoint_id)): Path<(String, String, String)>,
    ControlJson(body): ControlJson<control_types::UpdateWebhookEndpointRequest>,
) -> Response {
    let (project_id, application_id, endpoint_id) =
        match three_resource_ids(&project_id, &application_id, &endpoint_id, &request_id) {
            Ok(value) => value,
            Err(response) => return response,
        };
    let result = match webhook_control(&state) {
        Ok(service) => service
            .update_endpoint(
                project_id,
                application_id,
                endpoint_id,
                application::UpdateWebhookEndpoint {
                    subscribed_event_types: body
                        .subscribed_event_types
                        .into_iter()
                        .map(webhook_event_type)
                        .collect(),
                    expected_revision: body.expected_revision,
                },
                request_uuid(&request_id),
            )
            .await
            .and_then(control_webhook_endpoint),
        Err(error) => Err(error),
    };
    control_json(result, &request_id)
}

async fn test_webhook_endpoint(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, application_id, endpoint_id)): Path<(String, String, String)>,
    ControlJson(body): ControlJson<control_types::ExpectedWebhookEndpointRevision>,
) -> Response {
    let (project_id, application_id, endpoint_id) =
        match three_resource_ids(&project_id, &application_id, &endpoint_id, &request_id) {
            Ok(value) => value,
            Err(response) => return response,
        };
    let result = match webhook_control(&state) {
        Ok(service) => service
            .test_endpoint(
                project_id,
                application_id,
                endpoint_id,
                body.expected_revision,
                request_uuid(&request_id),
            )
            .await
            .and_then(control_webhook_endpoint),
        Err(error) => Err(error),
    };
    control_json(result, &request_id)
}

async fn activate_webhook_endpoint(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, application_id, endpoint_id)): Path<(String, String, String)>,
    ControlJson(body): ControlJson<control_types::ExpectedWebhookEndpointRevision>,
) -> Response {
    let (project_id, application_id, endpoint_id) =
        match three_resource_ids(&project_id, &application_id, &endpoint_id, &request_id) {
            Ok(value) => value,
            Err(response) => return response,
        };
    let result = match webhook_control(&state) {
        Ok(service) => service
            .activate_endpoint(
                project_id,
                application_id,
                endpoint_id,
                body.expected_revision,
                request_uuid(&request_id),
            )
            .await
            .and_then(control_webhook_endpoint),
        Err(error) => Err(error),
    };
    control_json(result, &request_id)
}

async fn disable_webhook_endpoint(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, application_id, endpoint_id)): Path<(String, String, String)>,
    ControlJson(body): ControlJson<control_types::ExpectedWebhookEndpointRevision>,
) -> Response {
    let (project_id, application_id, endpoint_id) =
        match three_resource_ids(&project_id, &application_id, &endpoint_id, &request_id) {
            Ok(value) => value,
            Err(response) => return response,
        };
    let result = match webhook_control(&state) {
        Ok(service) => service
            .disable_endpoint(
                project_id,
                application_id,
                endpoint_id,
                body.expected_revision,
                request_uuid(&request_id),
            )
            .await
            .and_then(control_webhook_endpoint),
        Err(error) => Err(error),
    };
    control_json(result, &request_id)
}

async fn prepare_webhook_secret_rotation(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, application_id, endpoint_id)): Path<(String, String, String)>,
    headers: HeaderMap,
    ControlJson(body): ControlJson<control_types::PrepareWebhookSecretRotationRequest>,
) -> Response {
    let (project_id, application_id, endpoint_id) =
        match three_resource_ids(&project_id, &application_id, &endpoint_id, &request_id) {
            Ok(value) => value,
            Err(response) => return response,
        };
    let Ok(idempotency_key) = idempotency_key(&headers) else {
        return invalid_idempotency(&request_id);
    };
    let result = match webhook_control(&state) {
        Ok(service) => service
            .prepare_secret_rotation(
                project_id,
                application_id,
                endpoint_id,
                application::PrepareWebhookSecretRotation {
                    secret: zeroize::Zeroizing::new(body.secret.into_bytes()),
                    idempotency_key,
                    expected_revision: body.expected_revision,
                },
                request_uuid(&request_id),
            )
            .await
            .and_then(|prepared| {
                let preparation_status = match prepared.preparation_state {
                    application::WebhookSecretPreparationState::Pending => {
                        control_types::WebhookSecretPreparationStatus::Pending
                    }
                    application::WebhookSecretPreparationState::Provisioned => {
                        control_types::WebhookSecretPreparationStatus::Provisioned
                    }
                    application::WebhookSecretPreparationState::Terminal => {
                        control_types::WebhookSecretPreparationStatus::Terminal
                    }
                };
                Ok(control_types::PreparedWebhookSecretRotation {
                    endpoint: control_webhook_endpoint(prepared.endpoint)?,
                    generation: prepared.generation,
                    preparation_status,
                    already_active: prepared.already_active,
                })
            }),
        Err(error) => Err(error),
    };
    control_json(result, &request_id)
}

async fn activate_webhook_secret_rotation(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, application_id, endpoint_id, generation)): Path<(
        String,
        String,
        String,
        i32,
    )>,
    ControlJson(body): ControlJson<control_types::ActivateWebhookSecretRotationRequest>,
) -> Response {
    let (project_id, application_id, endpoint_id) =
        match three_resource_ids(&project_id, &application_id, &endpoint_id, &request_id) {
            Ok(value) => value,
            Err(response) => return response,
        };
    let result = match webhook_control(&state) {
        Ok(service) => service
            .activate_secret_rotation(
                project_id,
                application_id,
                endpoint_id,
                generation,
                body.expected_revision,
                body.overlap_seconds,
                request_uuid(&request_id),
            )
            .await
            .and_then(control_webhook_endpoint),
        Err(error) => Err(error),
    };
    control_json(result, &request_id)
}

#[derive(Deserialize)]
struct ListHistoryQuery {
    cursor: Option<String>,
    limit: Option<usize>,
}

async fn list_application_user_events(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, application_id)): Path<(String, String)>,
    Query(query): Query<ListHistoryQuery>,
) -> Response {
    let (project_id, application_id) =
        match resource_pair(&project_id, &application_id, &request_id) {
            Ok(value) => value,
            Err(response) => return response,
        };
    let result = match webhook_control(&state) {
        Ok(service) => service
            .list_events(
                project_id,
                application_id,
                query.cursor.as_deref(),
                query.limit,
            )
            .await
            .and_then(|page| {
                page.items
                    .into_iter()
                    .map(control_application_user_event)
                    .collect::<Result<Vec<_>, _>>()
                    .map(|items| control_types::ApplicationUserEventList {
                        items,
                        next_cursor: page.next_cursor,
                    })
            }),
        Err(error) => Err(error),
    };
    control_json(result, &request_id)
}

#[derive(Deserialize)]
struct ListWebhookDeliveriesQuery {
    endpoint_id: Option<String>,
    cursor: Option<String>,
    limit: Option<usize>,
}

async fn list_webhook_deliveries(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, application_id)): Path<(String, String)>,
    Query(query): Query<ListWebhookDeliveriesQuery>,
) -> Response {
    let (project_id, application_id) =
        match resource_pair(&project_id, &application_id, &request_id) {
            Ok(value) => value,
            Err(response) => return response,
        };
    let endpoint_id = match query.endpoint_id.as_deref() {
        Some(value) => match resource_uuid(value, &request_id) {
            Ok(value) => Some(value),
            Err(response) => return response,
        },
        None => None,
    };
    let result = match webhook_control(&state) {
        Ok(service) => service
            .list_deliveries(
                project_id,
                application_id,
                endpoint_id,
                query.cursor.as_deref(),
                query.limit,
            )
            .await
            .and_then(|page| {
                page.items
                    .into_iter()
                    .map(control_webhook_delivery)
                    .collect::<Result<Vec<_>, _>>()
                    .map(|items| control_types::WebhookDeliveryList {
                        items,
                        next_cursor: page.next_cursor,
                    })
            }),
        Err(error) => Err(error),
    };
    control_json(result, &request_id)
}

async fn replay_webhook_delivery(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, application_id, delivery_id)): Path<(String, String, String)>,
    ControlJson(body): ControlJson<control_types::ReplayWebhookDeliveryRequest>,
) -> Response {
    if !body.confirm {
        return application_problem(ApplicationError::InvalidInput, &request_id);
    }
    let (project_id, application_id, delivery_id) =
        match three_resource_ids(&project_id, &application_id, &delivery_id, &request_id) {
            Ok(value) => value,
            Err(response) => return response,
        };
    let result = match webhook_control(&state) {
        Ok(service) => service
            .replay_delivery(
                project_id,
                application_id,
                delivery_id,
                request_uuid(&request_id),
            )
            .await
            .and_then(control_webhook_delivery),
        Err(error) => Err(error),
    };
    control_json(result, &request_id)
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

async fn rotate_signing_key(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path(project_id): Path<String>,
    headers: HeaderMap,
    ControlJson(body): ControlJson<control_types::RotateSigningKeyRequest>,
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
            .request_signing_key_rotation(
                project_id,
                operation_alias,
                body.expected_project_revision,
            )
            .await
        {
            Ok(key) => control_json(control_signing_key(key), &request_id),
            Err(error) => application_problem(error, &request_id),
        },
        Err(error) => application_problem(error, &request_id),
    }
}

async fn revoke_signing_key(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path((project_id, key_id)): Path<(String, String)>,
    ControlJson(body): ControlJson<control_types::KeyTransitionRequest>,
) -> Response {
    let (project_id, key_id) = match resource_pair(&project_id, &key_id, &request_id) {
        Ok(ids) => ids,
        Err(response) => return response,
    };
    let result = match provisioning(&state) {
        Ok(service) => {
            service
                .revoke_signing_key(
                    project_id,
                    key_id,
                    body.expected_ring_revision,
                    request_uuid(&request_id),
                )
                .await
        }
        Err(error) => Err(error),
    };
    match result {
        Ok(key) => control_json(control_signing_key(key), &request_id),
        Err(error) => application_problem(error, &request_id),
    }
}

fn control_provider_egress_mode(mode: ProviderEgressMode) -> control_types::ProviderEgressMode {
    match mode {
        ProviderEgressMode::AllowAll => control_types::ProviderEgressMode::AllowAll,
        ProviderEgressMode::ExactOrigins => control_types::ProviderEgressMode::ExactOrigins,
    }
}

fn domain_provider_egress_mode(mode: control_types::ProviderEgressMode) -> ProviderEgressMode {
    match mode {
        control_types::ProviderEgressMode::AllowAll => ProviderEgressMode::AllowAll,
        control_types::ProviderEgressMode::ExactOrigins => ProviderEgressMode::ExactOrigins,
    }
}

fn control_provider_egress_policy(
    policy: application::ProviderEgressPolicyRecord,
) -> control_types::ProviderEgressPolicy {
    control_types::ProviderEgressPolicy {
        project_id: policy.project_id.to_string(),
        mode: control_provider_egress_mode(policy.mode),
        exact_origins: policy.exact_origins,
        revision: policy.revision,
    }
}

async fn get_provider_egress_policy(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path(project_id): Path<String>,
) -> Response {
    let project_id = match resource_uuid(&project_id, &request_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    match provider_onboarding(&state) {
        Ok(service) => match service.get_policy(project_id).await {
            Ok(policy) => Json(control_provider_egress_policy(policy)).into_response(),
            Err(error) => application_problem(error, &request_id),
        },
        Err(error) => application_problem(error, &request_id),
    }
}

async fn update_provider_egress_policy(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path(project_id): Path<String>,
    ControlJson(body): ControlJson<control_types::UpdateProviderEgressPolicyRequest>,
) -> Response {
    let project_id = match resource_uuid(&project_id, &request_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    match provider_onboarding(&state) {
        Ok(service) => match service
            .update_policy(
                project_id,
                UpdateProviderEgressPolicy {
                    mode: domain_provider_egress_mode(body.mode),
                    exact_origins: body.exact_origins,
                    expected_revision: body.expected_revision,
                },
                request_uuid(&request_id),
            )
            .await
        {
            Ok(policy) => Json(control_provider_egress_policy(policy)).into_response(),
            Err(error) => application_problem(error, &request_id),
        },
        Err(error) => application_problem(error, &request_id),
    }
}

async fn preflight_oidc_provider(
    State(state): State<ControlState>,
    Extension(request_id): Extension<String>,
    Path(project_id): Path<String>,
    ControlJson(body): ControlJson<control_types::OidcPreflightRequest>,
) -> Response {
    let project_id = match resource_uuid(&project_id, &request_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    match provider_onboarding(&state) {
        Ok(service) => match service
            .preflight(project_id, body.issuer, request_uuid(&request_id))
            .await
        {
            Ok((summary, policy)) => Json(control_types::OidcPreflightResult {
                canonical_issuer: summary.canonical_issuer,
                admitted_endpoint_origins: summary.admitted_endpoint_origins,
                exact_scopes: summary.exact_scopes,
                authorization_code_supported: summary.authorization_code_supported,
                pkce_s256_supported: summary.pkce_s256_supported,
                rs256_id_tokens_supported: summary.rs256_id_tokens_supported,
                managed_profile_supported: summary.managed_profile_supported,
                policy_mode: control_provider_egress_mode(policy.mode),
                policy_revision: policy.revision,
            })
            .into_response(),
            Err(error) => application_problem(error, &request_id),
        },
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
    let (provider_kind, issuer) = match control_provider_create_variant(body.kind, body.issuer) {
        Ok(provider) => provider,
        Err(error) => return application_problem(error, &request_id),
    };
    let egress_policy_revision = if provider_kind == crate::domain::ProviderKind::Oidc {
        match provider_onboarding(&state) {
            Ok(service) => match service
                .preflight_for_create(
                    project_id,
                    issuer.clone(),
                    body.managed_profile_enabled,
                    request_uuid(&request_id),
                )
                .await
            {
                Ok(policy) => Some(policy.revision),
                Err(error) => return application_problem(error, &request_id),
            },
            Err(error) => return application_problem(error, &request_id),
        }
    } else {
        None
    };
    match provisioning(&state) {
        Ok(service) => match service
            .create_provider(
                project_id,
                CreateProvider {
                    kind: provider_kind,
                    provider_key: body.provider_key,
                    display_name: body.display_name,
                    issuer,
                    client_id: body.client_id,
                    client_secret: zeroize::Zeroizing::new(body.client_secret),
                    managed_profile_enabled: body.managed_profile_enabled,
                    idempotency_key,
                    expected_project_revision: body.expected_project_revision,
                    egress_policy_revision,
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
    Extension(client): Extension<ClientAddress>,
    Path(project_public_id): Path<String>,
    headers: HeaderMap,
    query: Result<Query<PublicConfigQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let Ok(Query(query)) = query else {
        return runtime_problem(ApplicationError::InvalidInput, &request_id);
    };
    if let Err(response) = admit_runtime_with_verified_cors(
        &state,
        &client,
        AdmissionEndpoint::PublicConfig,
        &[
            admission_dimension(AdmissionDimensionKind::Project, &project_public_id),
            admission_dimension(AdmissionDimensionKind::Application, &query.application_id),
        ],
        &headers,
        VerifiedOriginSubject::Application {
            project_public_id: &project_public_id,
            application_public_id: &query.application_id,
        },
        &request_id,
    )
    .await
    {
        return response;
    }
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
                    .filter(|provider| {
                        auth.provider_issuer_allowed(&provider.kind, &provider.issuer)
                    })
                    .map(runtime_provider)
                    .collect::<Result<Vec<_>, _>>();
                providers.map(|providers| runtime_types::PublicApplicationConfig {
                    project_public_id: config.project_public_id,
                    project_display_name: config.project_display_name,
                    application_public_id: config.application_public_id,
                    application_display_name: config.application_display_name,
                    publishable_keys: config.publishable_keys,
                    email_available: config.email_available,
                    email_otp_enabled: config.email_otp_enabled,
                    email_magic_link_enabled: config.email_magic_link_enabled,
                    login_available: FEDERATED_PROJECT_AUTH_AVAILABLE
                        && structurally_available
                        && (!providers.is_empty() || config.email_available),
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
    Extension(client): Extension<ClientAddress>,
    Path(project_public_id): Path<String>,
) -> Response {
    if let Err(response) = admit_runtime(
        &state,
        &client,
        AdmissionEndpoint::ProjectJwks,
        &[admission_dimension(
            AdmissionDimensionKind::Project,
            &project_public_id,
        )],
        &request_id,
    )
    .await
    {
        return response;
    }
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

fn control_provider_create_variant(
    kind: runtime_types::ProviderKind,
    issuer: Option<String>,
) -> Result<(crate::domain::ProviderKind, String), ApplicationError> {
    match (kind, issuer) {
        (runtime_types::ProviderKind::Oidc, Some(issuer)) => {
            Ok((crate::domain::ProviderKind::Oidc, issuer))
        }
        (runtime_types::ProviderKind::Google, None) => Ok((
            crate::domain::ProviderKind::Google,
            crate::domain::GOOGLE_ISSUER.to_owned(),
        )),
        (runtime_types::ProviderKind::Github, None) => Ok((
            crate::domain::ProviderKind::Github,
            crate::domain::GITHUB_ISSUER.to_owned(),
        )),
        _ => Err(ApplicationError::InvalidInput),
    }
}

fn runtime_provider_kind(value: &str) -> Result<runtime_types::ProviderKind, ApplicationError> {
    match value {
        "oidc" => Ok(runtime_types::ProviderKind::Oidc),
        "google" => Ok(runtime_types::ProviderKind::Google),
        "github" => Ok(runtime_types::ProviderKind::Github),
        _ => Err(ApplicationError::Integrity),
    }
}

fn runtime_provider(
    provider: application::PublicProvider,
) -> Result<runtime_types::PublicProvider, ApplicationError> {
    let kind = runtime_provider_kind(&provider.kind)?;
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
    let projection = user_projection(pair.projection)?;
    let projection_revision = projection.projection_revision;
    if pair.projection_revision != projection_revision {
        return Err(ApplicationError::Integrity);
    }
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
        projection,
        projection_revision,
        session_expires_at: timestamp(pair.session_expires_at),
    })
}

fn user_projection(
    document: serde_json::Value,
) -> Result<runtime_types::UserProjection, ApplicationError> {
    let projection: runtime_types::UserProjection =
        serde_json::from_value(document).map_err(|_| ApplicationError::Integrity)?;
    if projection.projection_schema != crate::domain::USER_PROJECTION_SCHEMA_V1 {
        return Err(ApplicationError::Integrity);
    }
    Ok(projection)
}

fn hosted_interaction_response(
    bootstrap: &application::HostedBootstrap,
    session_reuse_available: bool,
) -> Result<runtime_types::HostedInteractionResponse, ApplicationError> {
    let status = match bootstrap.interaction.status.as_str() {
        "awaiting_method_selection" => {
            runtime_types::HostedInteractionStatus::AwaitingMethodSelection
        }
        "email_address_entry" => runtime_types::HostedInteractionStatus::EmailAddressEntry,
        "email_challenge_pending" => runtime_types::HostedInteractionStatus::EmailChallengePending,
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
                kind: match provider.kind {
                    crate::domain::ProviderKind::Oidc => runtime_types::ProviderKind::Oidc,
                    crate::domain::ProviderKind::Google => runtime_types::ProviderKind::Google,
                    crate::domain::ProviderKind::Github => runtime_types::ProviderKind::Github,
                },
            })
            .collect(),
        email_available: bootstrap.interaction.email_available,
        email_proof_modes: email_proof_modes(
            bootstrap.interaction.email_otp_enabled,
            bootstrap.interaction.email_magic_link_enabled,
        ),
        csrf: bootstrap.csrf.to_string(),
        expires_at: timestamp(bootstrap.interaction.expires_at),
    })
}

fn email_proof_modes(otp: bool, magic_link: bool) -> Vec<runtime_types::EmailProofMode> {
    [
        otp.then_some(runtime_types::EmailProofMode::Otp),
        magic_link.then_some(runtime_types::EmailProofMode::MagicLink),
    ]
    .into_iter()
    .flatten()
    .collect()
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
    Ok(interaction_cookie_name_from_id(id))
}

fn interaction_cookie_name_from_id(id: Uuid) -> String {
    let digest = Sha256::digest(id.as_bytes());
    format!("owl_runtime_{}", URL_SAFE_NO_PAD.encode(&digest[..18]))
}

fn identity_proof_slot_cookie_name(proof_slot_id: Uuid) -> String {
    let mut context = b"owlauth-identity-proof-slot-cookie-v1\0".to_vec();
    context.extend_from_slice(proof_slot_id.as_bytes());
    let digest = Sha256::digest(context);
    format!(
        "owl_identity_slot_{}",
        URL_SAFE_NO_PAD.encode(&digest[..18])
    )
}

fn magic_transfer_cookie_name(challenge_id: Uuid) -> String {
    let digest = Sha256::digest(challenge_id.as_bytes());
    format!("owl_magic_{}", URL_SAFE_NO_PAD.encode(&digest[..18]))
}

fn identity_mutation_magic_transfer_cookie_name(challenge_id: Uuid) -> String {
    let digest = Sha256::digest(challenge_id.as_bytes());
    format!(
        "owl_identity_magic_{}",
        URL_SAFE_NO_PAD.encode(&digest[..18])
    )
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
    state.verified_origins.remember(
        VerifiedOriginSubject::Application {
            project_public_id,
            application_public_id,
        },
        &origin,
    );
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
    state.verified_origins.remember(
        VerifiedOriginSubject::Application {
            project_public_id,
            application_public_id,
        },
        &origin,
    );
    Ok(Some(origin))
}

fn remember_verified_credential_origin(
    state: &RuntimeState,
    project_public_id: &str,
    credential: &str,
    origin: Option<&str>,
) {
    if let Some(origin) = origin {
        state.verified_origins.remember(
            VerifiedOriginSubject::Credential {
                project_public_id,
                credential,
            },
            origin,
        );
    }
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

fn append_vary_origin(response: &mut Response) {
    let already_varies = response
        .headers()
        .get_all(header::VARY)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|value| value.trim().eq_ignore_ascii_case("origin"));
    if !already_varies {
        response
            .headers_mut()
            .append(header::VARY, HeaderValue::from_static("Origin"));
    }
}

fn apply_cors(response: &mut Response, origin: &str, preflight: bool) {
    let Ok(origin) = HeaderValue::from_str(origin) else {
        return;
    };
    response
        .headers_mut()
        .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    append_vary_origin(response);
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
    let domain_kind = crate::domain::ProviderKind::parse(&provider.kind)
        .map_err(|_| ApplicationError::Integrity)?;
    let kind = runtime_provider_kind(&provider.kind)?;
    let status = match provider.status.as_str() {
        "provisioning" => control_types::ProviderStatus::Provisioning,
        "active" => control_types::ProviderStatus::Active,
        "disabled" => control_types::ProviderStatus::Disabled,
        _ => return Err(ApplicationError::Integrity),
    };
    let managed = crate::adapters::oidc::managed_profile_capabilities()
        .for_kind(domain_kind)
        .unwrap_or_else(crate::adapters::oidc::controlled_oidc_managed_capability);
    let managed_supported = domain_kind.capabilities().managed_profile;
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
        login_supported: domain_kind.capabilities().login,
        identity_proof_supported: domain_kind.capabilities().identity_proof,
        managed_profile: control_types::ProviderManagedProfileCapability {
            supported: managed_supported,
            enabled: provider.managed_profile_enabled,
            exact_scopes: if managed_supported {
                managed
                    .exact_scopes
                    .iter()
                    .map(ToString::to_string)
                    .collect()
            } else {
                Vec::new()
            },
            profile_schema: if managed_supported {
                managed.profile_schema.to_owned()
            } else {
                String::new()
            },
            read_retry_safe: managed_supported && managed.read_retry_safe,
            renewal_idempotent_replay: managed_supported
                && matches!(
                    managed.renewal_replay,
                    crate::domain::RenewalReplay::StableAttemptId
                ),
            supports_revocation: managed_supported && managed.supports_revocation,
        },
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
        ApplicationError::ClientVerifierUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "client_verifier_unavailable",
            "Client verifier fleet unavailable",
            "The required Client verifier fleet is not ready for this credential version.",
        ),
        ApplicationError::InvalidTransition => (
            StatusCode::CONFLICT,
            "invalid_transition",
            "Invalid state transition",
            "The requested lifecycle transition is not allowed.",
        ),
        ApplicationError::ProviderPreflightRejected => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "provider_preflight_rejected",
            "Provider preflight rejected",
            "The issuer or discovered provider metadata does not satisfy the OwlAuth OIDC profile or current Project egress policy.",
        ),
        ApplicationError::ProviderPreflightUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "provider_preflight_unavailable",
            "Provider preflight unavailable",
            "The provider discovery endpoint could not be reached or safely validated.",
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

fn client_json<T>(result: Result<T, ApplicationError>, request_id: &str) -> Response
where
    T: Serialize,
{
    match result {
        Ok(value) => Json(value).into_response(),
        Err(error) => client_problem(error, request_id),
    }
}

fn client_problem(error: ApplicationError, request_id: &str) -> Response {
    let (status, code, message) = match error {
        ApplicationError::InvalidInput => (
            StatusCode::BAD_REQUEST,
            client_types::ClientErrorCode::InvalidRequest,
            "The Client request is invalid.",
        ),
        ApplicationError::NotFound | ApplicationError::Disabled => (
            StatusCode::NOT_FOUND,
            client_types::ClientErrorCode::NotFound,
            "The requested Client resource was not found or is no longer available.",
        ),
        ApplicationError::RevisionConflict
        | ApplicationError::InvalidTransition
        | ApplicationError::IdempotencyConflict
        | ApplicationError::OperationInProgress
        | ApplicationError::PublicationPending => (
            StatusCode::CONFLICT,
            client_types::ClientErrorCode::Conflict,
            "The Client request is no longer valid in the current state.",
        ),
        ApplicationError::Integrity
        | ApplicationError::Persistence
        | ApplicationError::ClientVerifierUnavailable
        | ApplicationError::ProviderPreflightRejected
        | ApplicationError::ProviderPreflightUnavailable
        | ApplicationError::ExternalStore => (
            StatusCode::SERVICE_UNAVAILABLE,
            client_types::ClientErrorCode::TemporarilyUnavailable,
            "The Client authority is temporarily unavailable.",
        ),
    };
    client_error_response(status, code, message, request_id)
}

fn client_rate_limited_response(retry_after_seconds: u64, request_id: &str) -> Response {
    let retry_after_seconds = retry_after_seconds.clamp(1, 60);
    let mut response = client_error_response(
        StatusCode::TOO_MANY_REQUESTS,
        client_types::ClientErrorCode::RateLimited,
        "The Client request rate limit was exceeded.",
        request_id,
    );
    if let Ok(value) = HeaderValue::from_str(&retry_after_seconds.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

fn unauthorized_client(request_id: &str) -> Response {
    let mut response = client_error_response(
        StatusCode::UNAUTHORIZED,
        client_types::ClientErrorCode::InvalidCredential,
        "A single valid Project client Bearer credential is required.",
        request_id,
    );
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

fn client_error_response(
    status: StatusCode,
    code: client_types::ClientErrorCode,
    message: &str,
    request_id: &str,
) -> Response {
    (
        status,
        Json(client_types::ClientError {
            code,
            message: message.to_owned(),
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
        | ApplicationError::ClientVerifierUnavailable
        | ApplicationError::ProviderPreflightRejected
        | ApplicationError::ProviderPreflightUnavailable
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
pub(crate) mod tests {
    use std::{
        collections::BTreeMap,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use tower::ServiceExt;

    use super::*;
    use crate::config::PlaneMode;

    const TEST_PROJECT: &str = "prj_http_identity";
    const TEST_BINDING: &str = "browser-binding";
    const TEST_CSRF: &str = "csrf-value";

    #[derive(Clone, Copy)]
    enum CallbackBehavior {
        Proved,
        Denied,
        PersistenceFailure,
    }

    struct TestIdentityMutationAuthority {
        calls: AtomicUsize,
        callback_behavior: CallbackBehavior,
    }

    impl TestIdentityMutationAuthority {
        fn posts() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                callback_behavior: CallbackBehavior::Proved,
            }
        }

        fn callback(callback_behavior: CallbackBehavior) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                callback_behavior,
            }
        }

        fn call_count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }

        fn record_call(&self) {
            self.calls.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn test_identity_view(
        revision: i64,
        status: crate::domain::IdentityMutationStatus,
    ) -> application::IdentityMutationView {
        application::IdentityMutationView {
            id: Uuid::from_u128(0x125),
            project_id: Uuid::from_u128(0x126),
            project_public_id: TEST_PROJECT.to_owned(),
            kind: crate::domain::IdentityMutationKind::Link,
            status,
            revision,
            expires_at: OffsetDateTime::from_unix_timestamp(1_900_000_000).expect("test timestamp"),
            slots: Vec::new(),
        }
    }

    #[async_trait]
    impl IdentityMutationRuntimePort for TestIdentityMutationAuthority {
        async fn bootstrap(
            &self,
            _interaction: &str,
            _browser_binding: Option<&str>,
        ) -> Result<application::IdentityMutationBootstrap, ApplicationError> {
            unreachable!("POST/callback fixture does not bootstrap Hosted")
        }

        async fn establish_magic_transfer_context(
            &self,
            _challenge_id: Uuid,
        ) -> Result<application::IdentityMutationMagicTransferGate, ApplicationError> {
            unreachable!("POST/callback fixture does not stage a magic GET")
        }

        async fn start_method(
            &self,
            command: application::StartIdentityMutationMethod,
        ) -> Result<application::StartedIdentityMutationMethod, ApplicationError> {
            self.record_call();
            assert_eq!(command.project_public_id, TEST_PROJECT);
            assert_eq!(command.interaction, test_identity_interaction());
            assert_eq!(command.proof_slot_id, test_proof_slot());
            assert_eq!(
                command.asserted_method,
                application::IdentityMutationProofMethodKind::Provider
            );
            assert_eq!(command.browser_binding, TEST_BINDING);
            assert_eq!(command.csrf, TEST_CSRF);
            assert_eq!(command.expected_revision, 7);
            Ok(
                application::StartedIdentityMutationMethod::ProviderNavigation {
                    url: "https://accounts.example/authorize".to_owned(),
                    proof_slot_id: command.proof_slot_id,
                },
            )
        }

        async fn begin_email_challenge(
            &self,
            request: application::BeginIdentityMutationEmailChallenge,
        ) -> Result<application::IdentityMutationEmailChallengeAccepted, ApplicationError> {
            self.record_call();
            assert_eq!(request.project_public_id, TEST_PROJECT);
            assert_eq!(request.interaction, test_identity_interaction());
            assert_eq!(request.proof_slot_id, test_proof_slot());
            assert_eq!(request.browser_binding, TEST_BINDING);
            assert_eq!(request.csrf, TEST_CSRF);
            assert_eq!(request.expected_revision, 8);
            assert_eq!(request.email, "person@example.com");
            Ok(application::IdentityMutationEmailChallengeAccepted {
                revision: 9,
                challenge_id: test_challenge(),
                generation: 2,
                otp_enabled: true,
                magic_link_enabled: true,
                expires_at: OffsetDateTime::from_unix_timestamp(1_900_000_000)
                    .expect("test timestamp"),
            })
        }

        async fn verify_email_proof(
            &self,
            request: application::VerifyRawIdentityMutationEmailProof,
        ) -> Result<application::IdentityMutationEmailCompletionDecision, ApplicationError>
        {
            self.record_call();
            assert_eq!(request.project_public_id, TEST_PROJECT);
            assert_eq!(request.interaction, test_identity_interaction());
            assert_eq!(request.proof_slot_id, test_proof_slot());
            assert_eq!(request.browser_binding, TEST_BINDING);
            assert_eq!(request.csrf, TEST_CSRF);
            assert_eq!(request.expected_revision, 9);
            assert_eq!(request.challenge_id, test_challenge());
            assert_eq!(request.generation, 2);
            assert_eq!(request.proof_kind, application::EmailProofKind::Otp);
            assert_eq!(request.proof.as_str(), "12345678");
            Ok(
                application::IdentityMutationEmailCompletionDecision::Completed(
                    test_identity_view(10, crate::domain::IdentityMutationStatus::Ready),
                ),
            )
        }

        async fn verify_magic_transfer(
            &self,
            request: application::VerifyIdentityMutationMagicTransferProof,
        ) -> Result<application::IdentityMutationEmailCompletionDecision, ApplicationError>
        {
            self.record_call();
            assert_eq!(request.project_public_id, TEST_PROJECT);
            assert_eq!(request.interaction, test_identity_interaction());
            assert_eq!(request.proof_slot_id, test_proof_slot());
            assert_eq!(request.challenge_id, test_challenge());
            assert_eq!(request.generation, 2);
            assert_eq!(request.csrf, "transfer-csrf");
            assert_eq!(request.expected_revision, 9);
            assert_eq!(request.proof.as_str(), "abcdefghijklmnopqrstuv");
            assert_eq!(request.transfer_context, "transfer-context");
            assert_eq!(request.browser_binding, None);
            Ok(
                application::IdentityMutationEmailCompletionDecision::Completed(
                    test_identity_view(10, crate::domain::IdentityMutationStatus::Ready),
                ),
            )
        }

        async fn confirm_ready(
            &self,
            command: application::ConfirmIdentityMutationReady,
        ) -> Result<application::IdentityMutationView, ApplicationError> {
            self.record_call();
            assert_eq!(command.project_public_id, TEST_PROJECT);
            assert_eq!(command.interaction, test_identity_interaction());
            assert_eq!(command.browser_binding, TEST_BINDING);
            assert_eq!(command.csrf, TEST_CSRF);
            assert_eq!(command.expected_revision, 10);
            Ok(test_identity_view(
                11,
                crate::domain::IdentityMutationStatus::Ready,
            ))
        }

        async fn deny_provider_callback(
            &self,
            denial: application::IdentityMutationProviderDenial,
        ) -> Result<application::IdentityMutationView, ApplicationError> {
            self.record_call();
            assert_identity_callback_fields(
                denial.intent_id,
                denial.proof_slot_id,
                &denial.project_public_id,
                &denial.provider_key,
                &denial.state,
                &denial.browser_binding,
            );
            assert_eq!(denial.safe_outcome, "auth.callback.denied_access");
            match self.callback_behavior {
                CallbackBehavior::Denied => Ok(test_identity_view(
                    8,
                    crate::domain::IdentityMutationStatus::PendingProof,
                )),
                CallbackBehavior::PersistenceFailure => Err(ApplicationError::Persistence),
                CallbackBehavior::Proved => {
                    unreachable!("proved fixture receives success callback")
                }
            }
        }

        async fn complete_provider_callback(
            &self,
            callback: application::IdentityMutationProviderCallback,
        ) -> Result<application::IdentityMutationCallbackOutcome, ApplicationError> {
            self.record_call();
            assert_identity_callback_fields(
                callback.intent_id,
                callback.proof_slot_id,
                &callback.project_public_id,
                &callback.provider_key,
                &callback.state,
                &callback.browser_binding,
            );
            assert_eq!(callback.code, "authorization-code");
            match self.callback_behavior {
                CallbackBehavior::Proved => {
                    Ok(application::IdentityMutationCallbackOutcome::Proved {
                        continuation: zeroize::Zeroizing::new(test_identity_interaction()),
                    })
                }
                CallbackBehavior::PersistenceFailure => Err(ApplicationError::Persistence),
                CallbackBehavior::Denied => unreachable!("denial fixture receives denial callback"),
            }
        }
    }

    fn test_identity_interaction() -> String {
        format!("{}.opaque-interaction", Uuid::from_u128(0x125))
    }

    fn test_proof_slot() -> Uuid {
        Uuid::from_u128(0x127)
    }

    fn test_challenge() -> Uuid {
        Uuid::from_u128(0x128)
    }

    fn assert_identity_callback_fields(
        intent_id: Uuid,
        proof_slot_id: Uuid,
        project_public_id: &str,
        provider_key: &str,
        state: &str,
        browser_binding: &str,
    ) {
        assert_eq!(intent_id, Uuid::from_u128(0x125));
        assert_eq!(proof_slot_id, test_proof_slot());
        assert_eq!(project_public_id, TEST_PROJECT);
        assert_eq!(provider_key, "workforce");
        assert_eq!(state, test_callback_state());
        assert_eq!(browser_binding, TEST_BINDING);
    }

    fn test_callback_state() -> String {
        format!("{}.1.state-secret", test_proof_slot())
    }

    struct TestIdentityCallbackOwnerResolver {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl ProviderCallbackOwnerResolver for TestIdentityCallbackOwnerResolver {
        async fn resolve(
            &self,
            state_id: Uuid,
            project_public_id: &str,
            provider_key: &str,
        ) -> Result<ProviderCallbackOwner, ApplicationError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(state_id, test_proof_slot());
            assert_eq!(project_public_id, TEST_PROJECT);
            assert_eq!(provider_key, "workforce");
            Ok(ProviderCallbackOwner::IdentityMutation {
                intent_id: Uuid::from_u128(0x125),
                proof_slot_id: test_proof_slot(),
            })
        }
    }

    fn test_identity_runtime_state(
        authority: Arc<dyn IdentityMutationRuntimePort>,
        callback_owners: Option<Arc<dyn ProviderCallbackOwnerResolver>>,
    ) -> RuntimeState {
        RuntimeState {
            probe: ProbeState {
                ready: Arc::new(AtomicBool::new(true)),
                base_path: Arc::from("/runtime/"),
            },
            admission: Arc::new(AdmissionService::new(
                format!("identity-http-{}", Uuid::new_v4()),
                [77; 32],
                1,
                None,
            )),
            verified_origins: Arc::new(VerifiedApplicationOrigins::default()),
            readiness: None,
            auth: None,
            callback_owners,
            managed_reauthorization: None,
            cookie_path: Arc::from("/runtime/"),
            external_origin: Arc::from("https://identity.example"),
            identity_mutations: Some(authority),
        }
    }

    fn same_origin_headers(cookie: Option<String>) -> HeaderMap {
        let mut headers = HeaderMap::from_iter([
            (
                header::ORIGIN,
                HeaderValue::from_static("https://identity.example"),
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
        if let Some(cookie) = cookie {
            headers.insert(
                header::COOKIE,
                HeaderValue::from_str(&cookie).expect("valid test cookie"),
            );
        }
        headers
    }

    fn interaction_cookie() -> String {
        format!(
            "{}={TEST_BINDING}",
            interaction_cookie_name(&test_identity_interaction()).expect("valid interaction")
        )
    }

    fn response_cookies(response: &Response) -> Vec<String> {
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| value.to_str().expect("ASCII cookie").to_owned())
            .collect()
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn identity_mutation_post_handlers_forward_exact_authority_and_cookie_context() {
        let authority = Arc::new(TestIdentityMutationAuthority::posts());
        let state = test_identity_runtime_state(authority.clone(), None);
        let request_id = || Extension("identity-handler-test".to_owned());
        let client = || Extension(ClientAddress("203.0.113.125".to_owned()));
        let proof_path = || {
            Path((
                TEST_PROJECT.to_owned(),
                test_identity_interaction(),
                test_proof_slot().to_string(),
            ))
        };

        let response = select_identity_mutation_method(
            State(state.clone()),
            request_id(),
            client(),
            proof_path(),
            same_origin_headers(Some(interaction_cookie())),
            RuntimeJson(runtime_types::SelectIdentityMutationMethodRequest {
                expected_revision: 7,
                csrf: TEST_CSRF.to_owned(),
                method_kind: runtime_types::IdentityMutationMethodKind::Provider,
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let cookies = response_cookies(&response);
        assert_eq!(cookies.len(), 1);
        assert_eq!(
            cookies[0],
            format!(
                "{}={TEST_BINDING}; Path=/runtime/; Max-Age=600; Secure; HttpOnly; SameSite=Lax",
                identity_proof_slot_cookie_name(test_proof_slot())
            )
        );

        let response = begin_identity_mutation_email_challenge(
            State(state.clone()),
            request_id(),
            client(),
            proof_path(),
            same_origin_headers(Some(interaction_cookie())),
            RuntimeJson(runtime_types::BeginIdentityMutationEmailChallengeRequest {
                expected_revision: 8,
                csrf: TEST_CSRF.to_owned(),
                email: "person@example.com".to_owned(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        let response = verify_identity_mutation_email_otp(
            State(state.clone()),
            request_id(),
            client(),
            proof_path(),
            same_origin_headers(Some(interaction_cookie())),
            RuntimeJson(runtime_types::VerifyIdentityMutationEmailOtpRequest {
                expected_revision: 9,
                csrf: TEST_CSRF.to_owned(),
                challenge_id: test_challenge().to_string(),
                generation: 2,
                otp: "12345678".to_owned(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response_cookies(&response).is_empty());

        let transfer_cookie_name = identity_mutation_magic_transfer_cookie_name(test_challenge());
        let response = verify_identity_mutation_email_link(
            State(state.clone()),
            request_id(),
            client(),
            proof_path(),
            same_origin_headers(Some(format!("{transfer_cookie_name}=transfer-context"))),
            RuntimeJson(runtime_types::VerifyIdentityMutationEmailLinkRequest {
                expected_revision: 9,
                csrf: "transfer-csrf".to_owned(),
                challenge_id: test_challenge().to_string(),
                generation: 2,
                token: "abcdefghijklmnopqrstuv".to_owned(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response_cookies(&response),
            vec![format!(
                "{transfer_cookie_name}=deleted; Path=/runtime/; Max-Age=0; Secure; HttpOnly; SameSite=Lax"
            )]
        );

        let response = confirm_identity_mutation_ready(
            State(state),
            request_id(),
            client(),
            Path((TEST_PROJECT.to_owned(), test_identity_interaction())),
            same_origin_headers(Some(interaction_cookie())),
            RuntimeJson(runtime_types::ConfirmHostedIdentityMutationRequest {
                expected_revision: 10,
                csrf: TEST_CSRF.to_owned(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(authority.call_count(), 5);
    }

    #[tokio::test]
    async fn identity_callback_dispatch_clears_only_terminal_slot_alias() {
        for (behavior, denial, clears_alias) in [
            (CallbackBehavior::Proved, false, true),
            (CallbackBehavior::Denied, true, true),
            (CallbackBehavior::PersistenceFailure, true, false),
        ] {
            let authority = Arc::new(TestIdentityMutationAuthority::callback(behavior));
            let owners = Arc::new(TestIdentityCallbackOwnerResolver {
                calls: AtomicUsize::new(0),
            });
            let state = test_identity_runtime_state(authority.clone(), Some(owners.clone()));
            let query = if denial {
                ProviderCallbackQuery {
                    code: None,
                    state: test_callback_state(),
                    error: Some("access_denied".to_owned()),
                    error_description: None,
                    error_uri: None,
                }
            } else {
                ProviderCallbackQuery {
                    code: Some("authorization-code".to_owned()),
                    state: test_callback_state(),
                    error: None,
                    error_description: None,
                    error_uri: None,
                }
            };
            let alias = identity_proof_slot_cookie_name(test_proof_slot());
            let response = provider_callback(
                State(state),
                Extension("identity-callback-test".to_owned()),
                Extension(ClientAddress("203.0.113.126".to_owned())),
                Path((TEST_PROJECT.to_owned(), "workforce".to_owned())),
                Query(query),
                HeaderMap::from_iter([(
                    header::COOKIE,
                    HeaderValue::from_str(&format!("{alias}={TEST_BINDING}"))
                        .expect("valid callback cookie"),
                )]),
            )
            .await;
            assert_eq!(owners.calls.load(Ordering::SeqCst), 1);
            assert_eq!(authority.call_count(), 1);
            let cookies = response_cookies(&response);
            if clears_alias {
                assert_eq!(
                    cookies,
                    vec![format!(
                        "{alias}=deleted; Path=/runtime/; Max-Age=0; Secure; HttpOnly; SameSite=Lax"
                    )]
                );
            } else {
                assert!(cookies.is_empty(), "retryable failure must retain alias");
            }
            assert!(
                cookies
                    .iter()
                    .all(|cookie| !cookie.starts_with("owl_runtime_")),
                "callback must leave the intent browser binding untouched"
            );
        }
    }

    #[tokio::test]
    async fn rejected_email_pre_gate_never_invokes_authority_for_challenge_or_resend() {
        for endpoint in [
            AdmissionEndpoint::EmailChallenge,
            AdmissionEndpoint::EmailResend,
        ] {
            let admission =
                AdmissionService::new(format!("pre-gate-{endpoint:?}"), [19; 32], 1, None);
            let authority_calls = AtomicUsize::new(0);
            for _ in 0..256 {
                assert!(
                    after_email_pre_authority(
                        &admission,
                        endpoint,
                        "203.0.113.44",
                        "opaque-interaction",
                        || async {
                            authority_calls.fetch_add(1, Ordering::SeqCst);
                            Ok::<_, ()>(())
                        },
                    )
                    .await
                    .expect("pre-gate allows reviewed quota")
                    .is_ok()
                );
            }
            let before = authority_calls.load(Ordering::SeqCst);
            assert!(
                after_email_pre_authority(
                    &admission,
                    endpoint,
                    "203.0.113.44",
                    "opaque-interaction",
                    || async {
                        authority_calls.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, ()>(())
                    },
                )
                .await
                .is_err()
            );
            assert_eq!(
                authority_calls.load(Ordering::SeqCst),
                before,
                "an exhausted pre-gate must not invoke PostgreSQL authority"
            );
        }
    }

    #[test]
    fn email_proof_mode_contract_is_truthful_for_every_admitted_set() {
        assert_eq!(
            email_proof_modes(true, false),
            vec![runtime_types::EmailProofMode::Otp]
        );
        assert_eq!(
            email_proof_modes(false, true),
            vec![runtime_types::EmailProofMode::MagicLink]
        );
        assert_eq!(
            email_proof_modes(true, true),
            vec![
                runtime_types::EmailProofMode::Otp,
                runtime_types::EmailProofMode::MagicLink,
            ]
        );
        assert!(email_proof_modes(false, false).is_empty());
    }

    #[test]
    fn managed_target_composition_uses_distinct_control_and_runtime_facades() {
        let config = test_config(PlaneMode::All);
        let issuer = build_managed_reauthorization_target_issuer(&config);
        let verifier = build_managed_reauthorization_target_verifier(&config);
        let interaction_id = Uuid::new_v4();
        let handle =
            application::ManagedReauthorizationTargetIssuer::random_handle(issuer.as_ref(), 32)
                .expect("Control issuer generates a target handle");
        let digest = application::ManagedReauthorizationTargetIssuer::digest_handle(
            issuer.as_ref(),
            interaction_id,
            handle.as_bytes(),
        )
        .expect("Control issuer digests with the active target key");
        assert_eq!(
            application::ManagedReauthorizationTargetVerifier::digest_handle_at(
                verifier.as_ref(),
                interaction_id,
                handle.as_bytes(),
                digest.key_version,
            )
            .expect("Runtime verifier accepts the frozen target key version"),
            digest
        );
        assert!(
            application::ManagedReauthorizationTargetVerifier::readable_key_versions(
                verifier.as_ref(),
            )
            .contains(&digest.key_version)
        );
        let _: Arc<ManagedReauthorizationControlService> =
            build_managed_reauthorization_service(DatabaseConnection::default(), &config);
    }

    #[test]
    fn managed_owner_preflight_preserves_typed_failures() {
        let not_found = managed_owner_preflight(Err(ApplicationError::NotFound))
            .expect_err("wrong owner is hidden as NotFound");
        assert_eq!(
            application_problem(not_found, "request").status(),
            StatusCode::NOT_FOUND
        );
        for error in [ApplicationError::Persistence, ApplicationError::Integrity] {
            let error = managed_owner_preflight(Err(error))
                .expect_err("infrastructure or integrity preflight must fail");
            let response = application_problem(error, "request");
            assert_ne!(
                response.status(),
                StatusCode::NOT_FOUND,
                "non-ownership failures must not be collapsed into 404"
            );
        }
        assert!(managed_owner_preflight(Ok(())).is_ok());
    }

    #[test]
    fn identity_callback_alias_is_retained_only_for_retryable_failures() {
        assert!(should_clear_identity_callback_alias(&Ok::<
            _,
            ApplicationError,
        >(())));
        assert!(!should_clear_identity_callback_alias(&Err::<(), _>(
            ApplicationError::ExternalStore
        )));
        assert!(!should_clear_identity_callback_alias(&Err::<(), _>(
            ApplicationError::Persistence
        )));
    }

    #[test]
    fn provider_callback_parser_is_bounded_and_tags_success_or_safe_denial() {
        let state = format!("{}.1.state-secret", Uuid::new_v4());
        assert!(matches!(
            classify_provider_callback(ProviderCallbackQuery {
                code: Some("authorization-code".to_owned()),
                state: state.clone(),
                error: None,
                error_description: None,
                error_uri: None,
            }),
            Ok(ProviderCallbackPayload::Success { .. })
        ));
        let denial = classify_provider_callback(ProviderCallbackQuery {
            code: None,
            state: state.clone(),
            error: Some("access_denied".to_owned()),
            // Accepted only to interoperate with the standard callback; neither raw value is
            // carried into the tagged payload, logs, persistence, or rendered output.
            error_description: Some("raw upstream prose must disappear".to_owned()),
            error_uri: Some("https://upstream.example/private-error".to_owned()),
        })
        .expect("tag bounded denial");
        assert!(matches!(
            denial,
            ProviderCallbackPayload::Denial {
                safe_outcome: "auth.callback.denied_access",
                ..
            }
        ));
        assert!(
            classify_provider_callback(ProviderCallbackQuery {
                code: Some("code".to_owned()),
                state: state.clone(),
                error: Some("access_denied".to_owned()),
                error_description: None,
                error_uri: None,
            })
            .is_err()
        );
        assert!(
            classify_provider_callback(ProviderCallbackQuery {
                code: None,
                state,
                error: Some("x".repeat(129)),
                error_description: None,
                error_uri: None,
            })
            .is_err()
        );
        assert_eq!(
            safe_provider_denial_outcome("provider-specific-raw-value"),
            "auth.callback.denied_other"
        );
    }

    #[test]
    fn control_provider_create_variants_derive_only_named_issuers() {
        assert_eq!(
            control_provider_create_variant(runtime_types::ProviderKind::Google, None),
            Ok((
                crate::domain::ProviderKind::Google,
                crate::domain::GOOGLE_ISSUER.to_owned(),
            ))
        );
        assert_eq!(
            control_provider_create_variant(
                runtime_types::ProviderKind::Oidc,
                Some("https://issuer.example".to_owned()),
            ),
            Ok((
                crate::domain::ProviderKind::Oidc,
                "https://issuer.example".to_owned(),
            ))
        );
        assert_eq!(
            control_provider_create_variant(
                runtime_types::ProviderKind::Google,
                Some(crate::domain::GOOGLE_ISSUER.to_owned()),
            ),
            Err(ApplicationError::InvalidInput)
        );
        assert_eq!(
            control_provider_create_variant(runtime_types::ProviderKind::Oidc, None),
            Err(ApplicationError::InvalidInput)
        );
    }

    #[tokio::test]
    async fn provider_preflight_problem_codes_are_stable_and_safely_bounded() {
        for (error, status, code) in [
            (
                ApplicationError::ProviderPreflightRejected,
                StatusCode::UNPROCESSABLE_ENTITY,
                "provider_preflight_rejected",
            ),
            (
                ApplicationError::ProviderPreflightUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "provider_preflight_unavailable",
            ),
        ] {
            let response = application_problem(error, "request-safe-id");
            assert_eq!(response.status(), status);
            let body: serde_json::Value = serde_json::from_slice(
                &to_bytes(response.into_body(), 16_384)
                    .await
                    .expect("problem response should be bounded"),
            )
            .expect("problem response should be JSON");
            assert_eq!(body["code"], code);
            assert_eq!(body["request_id"], "request-safe-id");
            assert_eq!(body["status"], status.as_u16());
            let serialized = body.to_string();
            assert!(!serialized.contains("issuer.example"));
            assert!(!serialized.contains("upstream"));
        }
    }

    #[test]
    fn control_provider_managed_capability_matches_the_reviewed_adapter() {
        let record = application::ProviderRecord {
            id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            provider_key: "workforce".to_owned(),
            kind: "oidc".to_owned(),
            display_name: "Workforce".to_owned(),
            issuer: "https://issuer.example".to_owned(),
            client_id: "client".to_owned(),
            callback_url: "https://runtime.example/callback".to_owned(),
            status: "active".to_owned(),
            revision: 1,
            managed_profile_enabled: true,
            managed_profile_revision: 1,
            assigned_application_ids: Vec::new(),
        };
        let public = control_provider(record.clone()).expect("map reviewed OIDC capability");
        assert!(public.login_supported);
        assert!(public.identity_proof_supported);
        let reviewed = crate::adapters::oidc::controlled_oidc_managed_capability();
        assert_eq!(
            public.managed_profile.exact_scopes,
            reviewed
                .exact_scopes
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            public.managed_profile.profile_schema,
            reviewed.profile_schema
        );
        assert_eq!(
            public.managed_profile.read_retry_safe,
            reviewed.read_retry_safe
        );
        assert_eq!(
            public.managed_profile.renewal_idempotent_replay,
            matches!(
                reviewed.renewal_replay,
                crate::domain::RenewalReplay::StableAttemptId
            )
        );
        assert_eq!(
            public.managed_profile.supports_revocation,
            reviewed.supports_revocation
        );
        assert!(public.managed_profile.supports_revocation);

        let mut google_record = record.clone();
        google_record.kind = "google".to_owned();
        google_record.provider_key = "google".to_owned();
        google_record.issuer = crate::domain::GOOGLE_ISSUER.to_owned();
        let google = control_provider(google_record).expect("map reviewed Google capability");
        assert_eq!(google.kind, owlauth_types::runtime::ProviderKind::Google);
        assert_eq!(
            google.managed_profile.exact_scopes,
            ["openid", "profile"].map(str::to_owned)
        );

        let mut github_record = record;
        github_record.kind = "github".to_owned();
        github_record.provider_key = "github".to_owned();
        github_record.issuer = crate::domain::GITHUB_ISSUER.to_owned();
        github_record.managed_profile_enabled = false;
        let github = control_provider(github_record).expect("map reviewed GitHub capability");
        assert_eq!(github.kind, owlauth_types::runtime::ProviderKind::Github);
        assert!(github.login_supported);
        assert!(!github.identity_proof_supported);
        assert!(!github.managed_profile.supported);
        assert!(!github.managed_profile.enabled);
        assert!(github.managed_profile.exact_scopes.is_empty());
        assert!(github.managed_profile.profile_schema.is_empty());
        assert!(!github.managed_profile.read_retry_safe);
        assert!(!github.managed_profile.renewal_idempotent_replay);
        assert!(!github.managed_profile.supports_revocation);
    }

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

    #[allow(
        clippy::too_many_lines,
        reason = "HTTP fixture enumerates complete Runtime and Control security configuration"
    )]
    pub(crate) fn test_config(mode: PlaneMode) -> ServerConfig {
        test_config_with_identity_material(
            mode,
            "http-test-runtime",
            "test-deployment",
            "PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0",
            "Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4",
            "R0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0c",
        )
    }

    pub(crate) fn identity_mutation_composition_config(mode: PlaneMode) -> ServerConfig {
        test_config_with_identity_material(
            mode,
            "identity-mutation-test",
            "identity-mutation-test",
            "CwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCws",
            "DAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw",
            "Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4",
        )
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the real-composition fixture injects the complete physically distinct identity key configuration"
    )]
    fn test_config_with_identity_material(
        mode: PlaneMode,
        runtime_process_id: &str,
        instance_id: &str,
        email_digest_key: &str,
        email_protection_key: &str,
        projection_protection_key: &str,
    ) -> ServerConfig {
        let key = format!("owl_ctrl_v1_{}", "A".repeat(43));
        let mut values = BTreeMap::from([
            (
                "OWLAUTH_POSTGRES_URL".to_owned(),
                "postgres://owlauth:test@127.0.0.1/owlauth".to_owned(),
            ),
            (
                "OWLAUTH_RUNTIME_PROCESS_ID".to_owned(),
                runtime_process_id.to_owned(),
            ),
            (
                "OWLAUTH_REQUIRED_RUNTIME_PROCESS_IDS".to_owned(),
                runtime_process_id.to_owned(),
            ),
            ("OWLAUTH_RUNTIME_MAX_PROCESSES".to_owned(), "64".to_owned()),
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
                "OWLAUTH_EMAIL_IDENTITY_KEY_VERSION".to_owned(),
                "1".to_owned(),
            ),
            (
                "OWLAUTH_EMAIL_IDENTITY_DIGEST_KEY".to_owned(),
                email_digest_key.to_owned(),
            ),
            (
                "OWLAUTH_EMAIL_IDENTITY_PROTECTION_KEY".to_owned(),
                email_protection_key.to_owned(),
            ),
            (
                "OWLAUTH_PROJECTION_EMAIL_KEY_VERSION".to_owned(),
                "1".to_owned(),
            ),
            (
                "OWLAUTH_PROJECTION_EMAIL_PROTECTION_KEY".to_owned(),
                projection_protection_key.to_owned(),
            ),
            (
                "OWLAUTH_MANAGED_REAUTHORIZATION_KEY_VERSION".to_owned(),
                "1".to_owned(),
            ),
            (
                "OWLAUTH_MANAGED_REAUTHORIZATION_DIGEST_KEY".to_owned(),
                "DQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0".to_owned(),
            ),
            (
                "OWLAUTH_MANAGED_REAUTHORIZATION_PROTECTION_KEY".to_owned(),
                "Dg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4".to_owned(),
            ),
            (
                "OWLAUTH_IDENTITY_MUTATION_EVIDENCE_KEY_VERSION".to_owned(),
                "1".to_owned(),
            ),
            (
                "OWLAUTH_IDENTITY_MUTATION_EVIDENCE_DIGEST_KEY".to_owned(),
                "EBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBA".to_owned(),
            ),
            (
                "OWLAUTH_IDENTITY_MUTATION_EVIDENCE_PROTECTION_KEY".to_owned(),
                "ERERERERERERERERERERERERERERERERERERERERERE".to_owned(),
            ),
            (
                "OWLAUTH_ADMISSION_DIGEST_KEY".to_owned(),
                "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU".to_owned(),
            ),
            ("OWLAUTH_CONTROL_API_KEY".to_owned(), key),
            ("OWLAUTH_INSTANCE_ID".to_owned(), instance_id.to_owned()),
            (
                "OWLAUTH_CLIENT_PROCESS_ID".to_owned(),
                "client-1".to_owned(),
            ),
            (
                "OWLAUTH_REQUIRED_CLIENT_PROCESS_IDS".to_owned(),
                "client-1".to_owned(),
            ),
            (
                "OWLAUTH_CLIENT_KEY_DIGEST_KEY_VERSION".to_owned(),
                "1".to_owned(),
            ),
            (
                "OWLAUTH_CLIENT_KEY_DIGEST_KEY".to_owned(),
                "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo".to_owned(),
            ),
            (
                "OWLAUTH_SOFTWARE_CUSTODY_KEY".to_owned(),
                "Hh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4".to_owned(),
            ),
            (
                "OWLAUTH_MODE".to_owned(),
                match mode {
                    PlaneMode::All => "all",
                    PlaneMode::Runtime => "runtime",
                    PlaneMode::Client => "client",
                    PlaneMode::Control => "control",
                }
                .to_owned(),
            ),
        ]);
        if mode.has_runtime() && FEDERATED_PROJECT_AUTH_AVAILABLE {
            values.extend([
                (
                    "OWLAUTH_MANAGED_CREDENTIAL_KEY_VERSION".to_owned(),
                    "1".to_owned(),
                ),
                (
                    "OWLAUTH_MANAGED_CREDENTIAL_KEY".to_owned(),
                    "BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgY".to_owned(),
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
    async fn runtime_admission_returns_bounded_429_before_downstream_authority() {
        let config = test_config(PlaneMode::Runtime);
        let mut routers = build_routers(&config, None);
        let router = routers.runtime.take().expect("Runtime router exists");
        let uri = "/v1/projects/project/auth/config?application_id=application";

        for _ in 0..9 {
            let response = router
                .clone()
                .oneshot(
                    Request::get(uri)
                        .header(header::ORIGIN, "https://unverified.example")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_ne!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        }
        let response = router
            .oneshot(
                Request::get(uri)
                    .header(header::ORIGIN, "https://unverified.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry_after = response
            .headers()
            .get(header::RETRY_AFTER)
            .unwrap()
            .to_str()
            .unwrap()
            .parse::<u64>()
            .unwrap();
        assert!((1..=60).contains(&retry_after));
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert!(
            !response
                .headers()
                .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN),
            "an unverified Origin must never be reflected"
        );
        assert!(
            response
                .headers()
                .get_all(header::VARY)
                .iter()
                .any(|value| value == "Origin"),
            "admission responses must vary by Origin even when it is not reflected"
        );
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let problem: runtime_types::RuntimeError = serde_json::from_slice(&body).unwrap();
        assert_eq!(problem.code, "rate_limited");
        assert_eq!(
            problem.message,
            "The Runtime request rate limit was exceeded."
        );
        assert!(!problem.request_id.is_empty());
        assert!(problem.request_id.len() <= 128);
    }

    #[tokio::test]
    async fn managed_reauthorization_start_rejects_concurrency_before_runtime_services() {
        let config = test_config(PlaneMode::Runtime);
        let origin = config.runtime.external_base.origin().ascii_serialization();
        // Compose the real PostgreSQL repository and OIDC discovery client around a disconnected
        // database sentinel. Touching either downstream path would fail instead of yielding 429.
        let pools = DatabasePools {
            runtime: Some(DatabaseConnection::default()),
            client: None,
            control: None,
        };
        let mut routers = build_routers(&config, Some(&pools));
        assert!(routers.runtime_auth.is_some());
        let router = routers.runtime.take().expect("Runtime router exists");
        let interaction = "opaque-interaction".to_owned();
        let base_path = config.runtime.external_base.path().trim_end_matches('/');
        let uri = format!(
            "{base_path}/v1/projects/project/auth/managed-reauthorizations/{interaction}/start"
        );
        let request = || {
            Request::post(&uri)
                .header(header::ORIGIN, &origin)
                .header("sec-fetch-site", "same-origin")
                .header("sec-fetch-mode", "cors")
                .header("sec-fetch-dest", "empty")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"expected_revision":1,"csrf":"opaque"}"#))
                .unwrap()
        };

        // This endpoint's reviewed local policy permits one request per process/window when the
        // deployment is configured for its maximum process count. The admitted probe stops at the
        // missing opaque cookie before touching the composed PostgreSQL/provider services.
        let admitted = router.clone().oneshot(request()).await.unwrap();
        assert_eq!(admitted.status(), StatusCode::NOT_FOUND);

        // Every concurrent retry must be rejected by admission. If admission moved below cookie
        // validation, PostgreSQL, or provider discovery, these requests would not return bounded
        // 429 responses with the disconnected PostgreSQL sentinel.
        let mut attempts = tokio::task::JoinSet::new();
        for _ in 0..16 {
            let router = router.clone();
            let request = request();
            attempts.spawn(async move { router.oneshot(request).await.unwrap() });
        }
        while let Some(response) = attempts.join_next().await {
            let response = response.unwrap();
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
            let retry_after = response
                .headers()
                .get(header::RETRY_AFTER)
                .expect("admission rejection carries Retry-After")
                .to_str()
                .unwrap()
                .parse::<u64>()
                .unwrap();
            assert!((1..=60).contains(&retry_after));
            let problem: runtime_types::RuntimeError =
                serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap())
                    .unwrap();
            assert_eq!(problem.code, "rate_limited");
            assert_eq!(
                problem.message,
                "The Runtime request rate limit was exceeded."
            );
        }
    }

    #[test]
    fn admission_cors_reflects_only_a_previously_verified_exact_application_origin() {
        let verified = VerifiedApplicationOrigins::default();
        let allowed = "https://app.example";
        let application = VerifiedOriginSubject::Application {
            project_public_id: "project-a",
            application_public_id: "application-a",
        };
        verified.remember(application, allowed);

        let response_for = |subject, origin: &'static str| {
            let headers =
                HeaderMap::from_iter([(header::ORIGIN, HeaderValue::from_static(origin))]);
            let mut response = runtime_error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "The Runtime request rate limit was exceeded.",
                "request-id",
            );
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("7"));
            apply_verified_admission_cors(&verified, &headers, subject, response)
        };

        let readable = response_for(application, allowed);
        assert_eq!(readable.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            readable.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
            allowed
        );
        assert_eq!(readable.headers()[header::RETRY_AFTER], "7");
        assert_eq!(
            readable.headers()[header::ACCESS_CONTROL_EXPOSE_HEADERS],
            "Retry-After"
        );
        assert!(
            readable
                .headers()
                .get_all(header::VARY)
                .iter()
                .any(|value| value == "Origin")
        );

        for rejected in [
            response_for(application, "https://unknown.example"),
            response_for(
                VerifiedOriginSubject::Application {
                    project_public_id: "project-a",
                    application_public_id: "application-b",
                },
                allowed,
            ),
            response_for(
                VerifiedOriginSubject::Application {
                    project_public_id: "project-b",
                    application_public_id: "application-a",
                },
                allowed,
            ),
        ] {
            assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);
            assert!(
                !rejected
                    .headers()
                    .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            );
            assert!(
                !rejected
                    .headers()
                    .contains_key(header::ACCESS_CONTROL_EXPOSE_HEADERS)
            );
            assert_eq!(rejected.headers()[header::RETRY_AFTER], "7");
            assert!(
                rejected
                    .headers()
                    .get_all(header::VARY)
                    .iter()
                    .any(|value| value == "Origin")
            );
        }
    }

    #[test]
    fn admission_cors_credential_verification_is_not_reusable_by_another_token() {
        let verified = VerifiedApplicationOrigins::default();
        let origin = "https://app.example";
        let verified_subject = VerifiedOriginSubject::Credential {
            project_public_id: "project-a",
            credential: "token-a",
        };
        verified.remember(verified_subject, origin);
        assert!(verified.contains(verified_subject, origin));
        assert!(!verified.contains(
            VerifiedOriginSubject::Credential {
                project_public_id: "project-a",
                credential: "token-b",
            },
            origin,
        ));
        assert!(!verified.contains(
            VerifiedOriginSubject::Credential {
                project_public_id: "project-b",
                credential: "token-a",
            },
            origin,
        ));
    }

    #[test]
    fn identity_mutation_facades_and_key_custody_follow_plane_mode() {
        let control_config = test_config(PlaneMode::Control);
        assert!(control_config.runtime_protection.is_none());
        assert!(control_config.email_identity_protection.is_some());
        let control_pools = DatabasePools {
            runtime: None,
            client: None,
            control: Some(DatabaseConnection::default()),
        };
        let control = build_routers(&control_config, Some(&control_pools));
        assert!(control.control_identity_mutations.is_some());
        assert!(control.runtime_identity_mutations.is_none());
        assert!(control.runtime_auth.is_none());

        let runtime_config = test_config(PlaneMode::Runtime);
        assert!(runtime_config.runtime_protection.is_some());
        assert!(runtime_config.control_api_key.is_none());
        let runtime_pools = DatabasePools {
            runtime: Some(DatabaseConnection::default()),
            client: None,
            control: None,
        };
        let runtime = build_routers(&runtime_config, Some(&runtime_pools));
        assert!(runtime.runtime_identity_mutations.is_some());
        assert!(runtime.control_identity_mutations.is_none());

        let all_config = test_config(PlaneMode::All);
        let all_pools = DatabasePools {
            runtime: Some(DatabaseConnection::default()),
            client: None,
            control: Some(DatabaseConnection::default()),
        };
        let all = build_routers(&all_config, Some(&all_pools));
        assert!(all.runtime_identity_mutations.is_some());
        assert!(all.control_identity_mutations.is_some());
    }

    #[tokio::test]
    async fn runtime_composes_federated_auth_without_control_plane() {
        const { assert!(FEDERATED_PROJECT_AUTH_AVAILABLE) };
        let config = test_config(PlaneMode::Runtime);
        assert!(config.provisioning.is_some());
        let pools = DatabasePools {
            runtime: Some(DatabaseConnection::default()),
            client: None,
            control: None,
        };
        let mut routers = build_routers(&config, Some(&pools));
        assert!(
            routers.runtime_auth.is_some(),
            "Runtime mode must compose the federated authentication service"
        );
        assert!(routers.control.is_none());
        assert!(
            !routers
                .managed_sync
                .as_ref()
                .expect("Runtime managed capability should be composed")
                .managed_claims_ready(),
            "managed credential readiness starts degraded independently of the listener"
        );

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
        assert_eq!(descriptor.mcp_url, None);

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

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "one protocol journey proves MCP discovery, admission, negotiation, catalog, dispatch, and plane isolation"
    )]
    async fn mcp_is_explicit_control_only_authenticated_and_tools_only() {
        let mut config = test_config(PlaneMode::All);
        config.control_mcp.enabled = true;
        config.max_request_bytes = 1024;
        let mut routers = build_routers(&config, None);
        routers.mark_ready();
        let control = routers.control.take().expect("Control router should exist");
        let authorization = format!("Bearer owl_ctrl_v1_{}", "A".repeat(43));
        let initialize = r#"{
            "jsonrpc":"2.0",
            "id":1,
            "method":"initialize",
            "params":{
                "protocolVersion":"2025-06-18",
                "capabilities":{},
                "clientInfo":{"name":"owlauth-test","version":"1.0.0"}
            }
        }"#;

        let discovery = control
            .clone()
            .oneshot(
                Request::get("/.well-known/owlauth")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let descriptor: ServiceDescriptor =
            serde_json::from_slice(&to_bytes(discovery.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(
            descriptor.mcp_url.as_deref(),
            Some("https://identity.example/control/mcp")
        );

        let denied = control
            .clone()
            .oneshot(
                Request::post("/control/mcp")
                    .header(header::HOST, "identity.example")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::ACCEPT, "application/json, text/event-stream")
                    .body(Body::from("not-json"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
        for unauthenticated in [
            Request::get("/control/mcp")
                .header(header::HOST, "identity.example")
                .body(Body::empty())
                .unwrap(),
            Request::delete("/control/mcp")
                .header(header::HOST, "identity.example")
                .body(Body::empty())
                .unwrap(),
        ] {
            let response = control.clone().oneshot(unauthenticated).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        let mut duplicate_credential = Request::post("/control/mcp")
            .header(header::HOST, "identity.example")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .body(Body::from(initialize))
            .unwrap();
        duplicate_credential.headers_mut().append(
            header::AUTHORIZATION,
            HeaderValue::from_str(&authorization).unwrap(),
        );
        duplicate_credential.headers_mut().append(
            header::AUTHORIZATION,
            HeaderValue::from_str(&authorization).unwrap(),
        );
        let duplicate_credential = control.clone().oneshot(duplicate_credential).await.unwrap();
        assert_eq!(duplicate_credential.status(), StatusCode::UNAUTHORIZED);

        let oversized = control
            .clone()
            .oneshot(
                Request::post("/control/mcp")
                    .header(header::HOST, "identity.example")
                    .header(header::AUTHORIZATION, &authorization)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::ACCEPT, "application/json, text/event-stream")
                    .body(Body::from("x".repeat(1025)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let wrong_origin = control
            .clone()
            .oneshot(
                Request::post("/control/mcp")
                    .header(header::HOST, "identity.example")
                    .header(header::ORIGIN, "https://attacker.example")
                    .header(header::AUTHORIZATION, &authorization)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::ACCEPT, "application/json, text/event-stream")
                    .body(Body::from(initialize))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong_origin.status(), StatusCode::BAD_REQUEST);

        let wrong_host = control
            .clone()
            .oneshot(
                Request::post("/control/mcp")
                    .header(header::HOST, "attacker.example")
                    .header(header::AUTHORIZATION, &authorization)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::ACCEPT, "application/json, text/event-stream")
                    .body(Body::from(initialize))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong_host.status(), StatusCode::BAD_REQUEST);

        for wrong_authority in [
            Request::post("/control/mcp")
                .header(header::HOST, "identity.example:8443")
                .header(header::AUTHORIZATION, &authorization)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, "application/json, text/event-stream")
                .body(Body::from(initialize))
                .unwrap(),
            Request::post("/control/mcp")
                .header(header::HOST, "identity.example")
                .header(header::ORIGIN, "https://identity.example:8443")
                .header(header::AUTHORIZATION, &authorization)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, "application/json, text/event-stream")
                .body(Body::from(initialize))
                .unwrap(),
        ] {
            let response = control.clone().oneshot(wrong_authority).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        let initialized = control
            .clone()
            .oneshot(
                Request::post("/control/mcp")
                    .header(header::HOST, "identity.example")
                    .header(header::ORIGIN, "https://identity.example")
                    .header(header::AUTHORIZATION, &authorization)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::ACCEPT, "application/json, text/event-stream")
                    .body(Body::from(initialize))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(initialized.status(), StatusCode::OK);
        assert!(initialized.headers().get("mcp-session-id").is_none());
        let initialized: serde_json::Value =
            serde_json::from_slice(&to_bytes(initialized.into_body(), 65_536).await.unwrap())
                .unwrap();
        assert_eq!(
            initialized["result"]["serverInfo"]["name"],
            "owlauth-server"
        );
        assert!(initialized["result"]["capabilities"]["tools"].is_object());
        assert!(
            initialized["result"]["capabilities"]
                .get("prompts")
                .is_none()
        );
        assert!(
            initialized["result"]["capabilities"]
                .get("resources")
                .is_none()
        );

        let unsupported_protocol = control
            .clone()
            .oneshot(
                Request::post("/control/mcp")
                    .header(header::HOST, "identity.example")
                    .header(header::AUTHORIZATION, &authorization)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::ACCEPT, "application/json, text/event-stream")
                    .header("mcp-protocol-version", "2099-01-01")
                    .body(Body::from(
                        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unsupported_protocol.status(), StatusCode::BAD_REQUEST);

        let tools = control
            .clone()
            .oneshot(
                Request::post("/control/mcp")
                    .header(header::HOST, "identity.example")
                    .header(header::AUTHORIZATION, &authorization)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::ACCEPT, "application/json, text/event-stream")
                    .header("mcp-protocol-version", "2025-06-18")
                    .body(Body::from(
                        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(tools.status(), StatusCode::OK);
        let tools: serde_json::Value =
            serde_json::from_slice(&to_bytes(tools.into_body(), 65_536).await.unwrap()).unwrap();
        let tools = tools["result"]["tools"]
            .as_array()
            .expect("tools/list returns a bounded catalog");
        assert_eq!(tools.len(), 7);
        assert!(
            tools
                .iter()
                .any(|tool| tool["name"] == "owlauth_system_get")
        );
        assert!(tools.iter().all(|tool| {
            tool["inputSchema"]["additionalProperties"] == false
                && tool["outputSchema"]["type"] == "object"
                && tool["outputSchema"]["additionalProperties"] == false
        }));
        assert!(
            tools
                .iter()
                .all(|tool| tool["annotations"]["readOnlyHint"] == true),
            "the initial MCP catalog is read-only"
        );

        let called = control
            .clone()
            .oneshot(
                Request::post("/control/mcp")
                    .header(header::HOST, "identity.example")
                    .header(header::AUTHORIZATION, &authorization)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::ACCEPT, "application/json, text/event-stream")
                    .header("mcp-protocol-version", "2025-06-18")
                    .body(Body::from(
                        r#"{"jsonrpc":"2.0","id":"call-1","method":"tools/call","params":{"name":"owlauth_system_get","arguments":{}}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(called.status(), StatusCode::OK);
        let called: serde_json::Value =
            serde_json::from_slice(&to_bytes(called.into_body(), 65_536).await.unwrap()).unwrap();
        assert_eq!(
            called["result"]["structuredContent"]["product"],
            "owlauth-server"
        );
        assert_eq!(called["result"]["isError"], false);
        assert!(!called.to_string().contains("owl_ctrl_v1_"));

        let rejected_arguments = control
            .clone()
            .oneshot(
                Request::post("/control/mcp")
                    .header(header::HOST, "identity.example")
                    .header(header::AUTHORIZATION, &authorization)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::ACCEPT, "application/json, text/event-stream")
                    .header("mcp-protocol-version", "2025-06-18")
                    .body(Body::from(
                        r#"{"jsonrpc":"2.0","id":"call-2","method":"tools/call","params":{"name":"owlauth_system_get","arguments":{"injected":"value"}}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rejected_arguments.status(), StatusCode::OK);
        let rejected_arguments: serde_json::Value = serde_json::from_slice(
            &to_bytes(rejected_arguments.into_body(), 65_536)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(
            rejected_arguments["error"]["code"] == -32602
                || rejected_arguments["result"]["isError"] == true,
            "closed tool input must reject unknown fields: {rejected_arguments}"
        );
        assert!(!rejected_arguments.to_string().contains("owl_ctrl_v1_"));

        let runtime = routers.runtime.take().expect("Runtime router should exist");
        let runtime_mcp = runtime
            .oneshot(
                Request::post("/runtime/mcp")
                    .header(header::AUTHORIZATION, authorization)
                    .body(Body::from(initialize))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(runtime_mcp.status(), StatusCode::NOT_FOUND);
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
    #[allow(
        clippy::too_many_lines,
        reason = "one end-to-end asset test must compare both planes, encodings, HEAD semantics, and cross-plane isolation"
    )]
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

        for path in ["/runtime/auth", "/runtime/auth/unknown"] {
            let runtime_not_found = runtime
                .clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(runtime_not_found.status(), StatusCode::NOT_FOUND);
            assert_eq!(
                runtime_not_found.headers()[header::CACHE_CONTROL],
                HeaderValue::from_static("no-store")
            );
            let not_found_document = String::from_utf8(
                to_bytes(runtime_not_found.into_body(), 1_000_000)
                    .await
                    .unwrap()
                    .to_vec(),
            )
            .unwrap();
            assert!(not_found_document.contains("Page not found"));
            assert!(not_found_document.contains("owlauth-runtime-flow\" content=\"error"));
        }

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
        assert_eq!(compressed.headers()[header::VARY], "accept-encoding");
        assert_eq!(
            compressed.headers()[header::CACHE_CONTROL],
            "public, max-age=31536000, immutable"
        );
        assert!(!compressed.headers().contains_key(header::ETAG));
        let identity = runtime
            .clone()
            .oneshot(
                Request::get(&runtime_asset_path)
                    .header(header::ACCEPT_ENCODING, "identity")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(identity.status(), StatusCode::OK);
        assert!(!identity.headers().contains_key(header::CONTENT_ENCODING));
        assert_eq!(identity.headers()[header::VARY], "accept-encoding");
        let head = runtime
            .clone()
            .oneshot(
                Request::head(&runtime_asset_path)
                    .header(header::ACCEPT_ENCODING, "gzip")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(head.status(), StatusCode::OK);
        assert_eq!(head.headers()[header::CONTENT_ENCODING], "gzip");
        assert!(to_bytes(head.into_body(), 1).await.unwrap().is_empty());

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

        let slashless_control_shell = control
            .clone()
            .oneshot(
                Request::get("/control/console")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(slashless_control_shell.status(), StatusCode::OK);

        let control_shell = control
            .clone()
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
        let control_asset_path = attribute(&control_document, "src");
        assert!(control_asset_path.starts_with("/control/console/assets/control-"));

        let control_compressed = control
            .clone()
            .oneshot(
                Request::get(&control_asset_path)
                    .header(header::ACCEPT_ENCODING, "gzip;q=0.8, br")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(control_compressed.status(), StatusCode::OK);
        assert_eq!(control_compressed.headers()[header::CONTENT_ENCODING], "br");
        assert_eq!(
            control_compressed.headers()[header::VARY],
            "accept-encoding"
        );
        assert_eq!(
            control_compressed.headers()[header::CACHE_CONTROL],
            "public, max-age=31536000, immutable"
        );
        assert!(!control_compressed.headers().contains_key(header::ETAG));

        let control_identity = control
            .clone()
            .oneshot(
                Request::get(&control_asset_path)
                    .header(header::ACCEPT_ENCODING, "identity")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(control_identity.status(), StatusCode::OK);
        assert!(
            !control_identity
                .headers()
                .contains_key(header::CONTENT_ENCODING)
        );
        assert_eq!(control_identity.headers()[header::VARY], "accept-encoding");

        let control_head = control
            .clone()
            .oneshot(
                Request::head(&control_asset_path)
                    .header(header::ACCEPT_ENCODING, "gzip")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(control_head.status(), StatusCode::OK);
        assert_eq!(control_head.headers()[header::CONTENT_ENCODING], "gzip");
        assert!(
            to_bytes(control_head.into_body(), 1)
                .await
                .unwrap()
                .is_empty()
        );

        let control_filename = control_asset_path
            .rsplit('/')
            .next()
            .expect("asset path should have a filename");
        let reverse_cross_plane = runtime
            .oneshot(
                Request::get(format!("/runtime/auth/assets/{control_filename}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(reverse_cross_plane.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn identity_public_routes_are_plane_local_authenticated_and_hosted_guarded() {
        let config = test_config(PlaneMode::All);
        let routers = build_routers(&config, None);
        let control = routers.control.expect("Control router");
        let runtime = routers.runtime.expect("Runtime router");
        let project = Uuid::new_v4();
        let user = Uuid::new_v4();
        let inventory = format!("/control/v1/projects/{project}/users/{user}/identities");
        let unauthenticated = control
            .clone()
            .oneshot(Request::get(&inventory).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
        let authenticated = control
            .clone()
            .oneshot(
                Request::get(&inventory)
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer owl_ctrl_v1_{}", "A".repeat(43)),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(authenticated.status(), StatusCode::NOT_FOUND);

        let interaction = format!("{}.{}", Uuid::new_v4(), "A".repeat(43));
        let shell = runtime
            .clone()
            .oneshot(
                Request::get(format!("/runtime/auth/identity-mutations/{interaction}"))
                    .header("sec-fetch-site", "same-origin")
                    .header("sec-fetch-mode", "navigate")
                    .header("sec-fetch-dest", "document")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(shell.status(), StatusCode::OK);

        let mutation_path =
            format!("/runtime/v1/projects/project/auth/identity-mutations/{interaction}/confirm");
        let authorization_rejected = runtime
            .clone()
            .oneshot(
                Request::post(&mutation_path)
                    .header(header::AUTHORIZATION, "Bearer forbidden")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"expected_revision":1,"csrf":"csrf"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authorization_rejected.status(), StatusCode::BAD_REQUEST);
        let cross_site_rejected = runtime
            .oneshot(
                Request::post(&mutation_path)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("sec-fetch-site", "cross-site")
                    .header("sec-fetch-mode", "cors")
                    .header("sec-fetch-dest", "empty")
                    .body(Body::from(r#"{"expected_revision":1,"csrf":"csrf"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cross_site_rejected.status(), StatusCode::FORBIDDEN);
    }

    const CLIENT_TEST_PROJECT: &str = "project-a";
    const CLIENT_TEST_PUBLIC_KEY_ID: &str = "AAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn client_projection_preserves_materialized_user_and_projection_revisions() {
        let converted = client_projection_document(
            "project-a".to_owned(),
            "application-a".to_owned(),
            "user-a".to_owned(),
            13,
            serde_json::json!({
                "user_id": "user-a",
                "user_revision": 7,
                "projection_schema": "owlauth.user.v1",
                "projection_revision": 13,
                "display_name": null,
                "picture_url": null,
                "locale": null,
                "verified_email": null,
                "status": "active",
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:01Z"
            }),
        )
        .expect("valid materialized projection");
        assert_eq!(converted.user_revision, 7);
        assert_eq!(converted.projection_revision, 13);
    }

    struct TestClientRepository {
        authority_calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl application::ClientApiRepository for TestClientRepository {
        async fn client_key_authority(
            &self,
            public_key_id: &str,
        ) -> Result<application::ClientKeyAuthority, ApplicationError> {
            self.authority_calls.fetch_add(1, Ordering::SeqCst);
            if public_key_id != CLIENT_TEST_PUBLIC_KEY_ID {
                return Err(ApplicationError::NotFound);
            }
            Ok(application::ClientKeyAuthority {
                key_id: Uuid::from_u128(0xc11e_0002),
                project_id: Uuid::from_u128(0xc11e_0001),
                project_public_id: CLIENT_TEST_PROJECT.to_owned(),
                public_key_id: CLIENT_TEST_PUBLIC_KEY_ID.to_owned(),
                digest_key_version: 1,
                credential_digest: [7; 32],
            })
        }

        async fn confirm_active(
            &self,
            project_id: Uuid,
            key_id: Uuid,
        ) -> Result<(), ApplicationError> {
            assert_eq!(project_id, Uuid::from_u128(0xc11e_0001));
            assert_eq!(key_id, Uuid::from_u128(0xc11e_0002));
            Ok(())
        }

        async fn record_usage_if_older(
            &self,
            project_id: Uuid,
            key_id: Uuid,
            _usage_bucket: OffsetDateTime,
        ) -> Result<(), ApplicationError> {
            assert_eq!(project_id, Uuid::from_u128(0xc11e_0001));
            assert_eq!(key_id, Uuid::from_u128(0xc11e_0002));
            Ok(())
        }

        async fn list_users(
            &self,
            project_id: Uuid,
            project_public_id: &str,
            after: Option<application::ClientUserCursor>,
            limit_plus_one: usize,
        ) -> Result<Vec<(application::ClientUserCursor, application::ClientUser)>, ApplicationError>
        {
            assert_eq!(project_id, Uuid::from_u128(0xc11e_0001));
            assert_eq!(project_public_id, CLIENT_TEST_PROJECT);
            assert!(after.is_none());
            assert_eq!(limit_plus_one, 51);
            Ok(Vec::new())
        }

        async fn user_by_public_id(
            &self,
            _project_id: Uuid,
            _project_public_id: &str,
            _user_public_id: &str,
        ) -> Result<application::ClientUser, ApplicationError> {
            Err(ApplicationError::NotFound)
        }

        async fn user_by_email_digests(
            &self,
            _project_id: Uuid,
            _project_public_id: &str,
            _candidates: &[application::VersionedDigest],
        ) -> Result<Option<application::ClientUser>, ApplicationError> {
            Ok(None)
        }

        async fn application_projection(
            &self,
            _project_id: Uuid,
            _project_public_id: &str,
            _application_public_id: &str,
            _user_public_id: &str,
        ) -> Result<application::ClientApplicationProjection, ApplicationError> {
            Err(ApplicationError::NotFound)
        }

        async fn verification_key(
            &self,
            _project_id: Uuid,
            _kid: &str,
            _now: OffsetDateTime,
        ) -> Result<application::ClientVerificationKey, ApplicationError> {
            Err(ApplicationError::NotFound)
        }

        async fn introspect_session(
            &self,
            _lookup: application::ClientTokenSessionLookup,
        ) -> Result<application::ActiveClientToken, ApplicationError> {
            Err(ApplicationError::Disabled)
        }
    }

    struct TestClientKeyVerifier;

    impl application::ClientKeyVerifier for TestClientKeyVerifier {
        fn readable_versions(&self) -> std::collections::BTreeSet<i32> {
            std::collections::BTreeSet::from([1])
        }

        fn digest_candidate(
            &self,
            project_id: Uuid,
            key_id: Uuid,
            public_key_id: &str,
            secret: &[u8; application::CLIENT_KEY_SECRET_BYTES],
            digest_key_version: i32,
        ) -> Result<[u8; 32], ApplicationError> {
            let expected = project_id == Uuid::from_u128(0xc11e_0001)
                && key_id == Uuid::from_u128(0xc11e_0002)
                && public_key_id == CLIENT_TEST_PUBLIC_KEY_ID
                && digest_key_version == 1
                && secret == &[0; application::CLIENT_KEY_SECRET_BYTES];
            Ok(if expected { [7; 32] } else { [8; 32] })
        }
    }

    struct TestClientEmailDigester;

    impl application::ClientEmailLookupDigester for TestClientEmailDigester {
        fn digest_candidates(
            &self,
            _project_id: Uuid,
            _canonical_email: &str,
        ) -> Result<Vec<application::VersionedDigest>, ApplicationError> {
            Ok(vec![application::VersionedDigest {
                value: [1; 32],
                key_version: 1,
            }])
        }
    }

    struct TestClientTokenVerifier;

    impl application::ClientTokenSignatureVerifier for TestClientTokenVerifier {
        fn verify(
            &self,
            _public_jwk: &serde_json::Value,
            _signing_input: &[u8],
            _signature: &[u8],
        ) -> Result<(), ApplicationError> {
            Ok(())
        }
    }

    struct TestClientClock;

    impl application::Clock for TestClientClock {
        fn now(&self) -> OffsetDateTime {
            OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("test timestamp")
        }
    }

    fn canonical_test_client_credential() -> String {
        format!(
            "owl_client_v1.{CLIENT_TEST_PUBLIC_KEY_ID}.{}",
            "A".repeat(43)
        )
    }

    fn isolated_test_client_router_with_authority_calls() -> (Router, Arc<AtomicUsize>) {
        let config = test_config(PlaneMode::Client);
        let authority_calls = Arc::new(AtomicUsize::new(0));
        let api = Arc::new(application::ClientApiService::new(
            Arc::new(TestClientRepository {
                authority_calls: Arc::clone(&authority_calls),
            }),
            Arc::new(TestClientKeyVerifier),
            Arc::new(TestClientEmailDigester),
            Arc::new(TestClientTokenVerifier),
            Arc::new(TestClientClock),
        ));
        let mut routers = build_routers_with_capabilities(
            &config,
            crate::composition::HttpCapabilities {
                runtime: None,
                client: Some(crate::composition::ClientHttpCapabilities {
                    admission: Arc::new(AdmissionService::new(
                        format!("client-http-{}", Uuid::new_v4()),
                        [83; 32],
                        1,
                        None,
                    )),
                    api: Some(api),
                    readiness: None,
                }),
                control: None,
            },
        );
        routers.mark_ready();
        (
            routers.client.take().expect("Client router"),
            authority_calls,
        )
    }

    fn isolated_test_client_router() -> Router {
        isolated_test_client_router_with_authority_calls().0
    }

    async fn assert_client_error(
        response: Response,
        expected_status: StatusCode,
        expected_code: client_types::ClientErrorCode,
    ) {
        assert_eq!(response.status(), expected_status);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let error: client_types::ClientError = serde_json::from_slice(
            &to_bytes(response.into_body(), 4096)
                .await
                .expect("bounded Client error body"),
        )
        .expect("Client JSON error envelope");
        assert_eq!(error.code, expected_code);
        assert!(!error.request_id.is_empty());
    }

    fn assert_no_browser_authority_headers(response: &Response) {
        for name in [
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            header::ACCESS_CONTROL_ALLOW_METHODS,
            header::SET_COOKIE,
            header::LOCATION,
        ] {
            assert!(
                !response.headers().contains_key(&name),
                "Client response unexpectedly contains {name}"
            );
        }
        assert!(!response.status().is_redirection());
    }

    #[tokio::test]
    async fn client_authentication_failures_collapse_to_one_bearer_error() {
        let router = isolated_test_client_router();
        let path = "/v1/projects/project-a/users";
        let valid = canonical_test_client_credential();
        let requests = [
            Request::get(path).body(Body::empty()).unwrap(),
            Request::get(path)
                .header(header::AUTHORIZATION, format!("Bearer {valid}"))
                .header(header::AUTHORIZATION, format!("Bearer {valid}"))
                .body(Body::empty())
                .unwrap(),
            Request::get(path)
                .header(header::AUTHORIZATION, "Bearer owl_client_v1.not-canonical")
                .body(Body::empty())
                .unwrap(),
            Request::get(path)
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer owl_ctrl_v1_{}", "A".repeat(43)),
                )
                .body(Body::empty())
                .unwrap(),
        ];
        for request in requests {
            let response = router.clone().oneshot(request).await.unwrap();
            assert_eq!(response.headers()[header::WWW_AUTHENTICATE], "Bearer");
            assert_no_browser_authority_headers(&response);
            assert_client_error(
                response,
                StatusCode::UNAUTHORIZED,
                client_types::ClientErrorCode::InvalidCredential,
            )
            .await;
        }
    }

    #[tokio::test]
    async fn client_pre_authority_admission_stops_unknown_credentials_before_authority() {
        let router = isolated_test_client_router();
        let path = "/v1/projects/project-a/users";
        for _ in 0..120 {
            let response = router
                .clone()
                .oneshot(
                    Request::get(path)
                        .header(header::AUTHORIZATION, "Bearer malformed")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        let response = router
            .oneshot(
                Request::get(path)
                    .header(header::AUTHORIZATION, "Bearer malformed")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry_after = response.headers()[header::RETRY_AFTER]
            .to_str()
            .expect("integer Retry-After")
            .parse::<u64>()
            .expect("numeric Retry-After");
        assert!((1..=60).contains(&retry_after));
        assert_no_browser_authority_headers(&response);
        assert_client_error(
            response,
            StatusCode::TOO_MANY_REQUESTS,
            client_types::ClientErrorCode::RateLimited,
        )
        .await;
    }

    #[tokio::test]
    async fn failure_block_stops_canonical_unknown_credentials_before_another_repository_lookup() {
        let (router, authority_calls) = isolated_test_client_router_with_authority_calls();
        let unknown = format!(
            "Bearer owl_client_v1.{}.{}",
            URL_SAFE_NO_PAD.encode([1_u8; application::CLIENT_KEY_PUBLIC_ID_BYTES]),
            "A".repeat(43)
        );
        let request = || {
            Request::get("/v1/projects/project-a/users")
                .header(header::AUTHORIZATION, &unknown)
                .body(Body::empty())
                .unwrap()
        };

        for request_number in 1..=120 {
            let response = router.clone().oneshot(request()).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "unknown canonical request {request_number}"
            );
        }
        assert_eq!(authority_calls.load(Ordering::SeqCst), 120);

        let threshold_response = router.clone().oneshot(request()).await.unwrap();
        assert_eq!(threshold_response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(authority_calls.load(Ordering::SeqCst), 121);

        let preblocked_response = router.oneshot(request()).await.unwrap();
        assert_eq!(preblocked_response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            authority_calls.load(Ordering::SeqCst),
            121,
            "an active source block must reject before another authority lookup"
        );
    }

    #[tokio::test]
    async fn valid_client_traffic_does_not_consume_the_strict_failure_budget() {
        let router = isolated_test_client_router();
        let authorization = format!("Bearer {}", canonical_test_client_credential());
        for request_number in 1..=130 {
            let response = router
                .clone()
                .oneshot(
                    Request::get("/v1/projects/project-a/users")
                        .header(header::AUTHORIZATION, &authorization)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "valid request {request_number} was incorrectly charged to failure admission"
            );
        }
    }

    #[tokio::test]
    async fn canonical_client_key_is_project_bound_and_reads_the_directory() {
        let router = isolated_test_client_router();
        let authorization = format!("Bearer {}", canonical_test_client_credential());
        let response = router
            .clone()
            .oneshot(
                Request::get("/v1/projects/project-a/users")
                    .header(header::AUTHORIZATION, &authorization)
                    .header(header::ORIGIN, "https://browser.example")
                    .header(header::ACCEPT, "text/html,application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            HeaderValue::from_static("application/json")
        );
        assert_no_browser_authority_headers(&response);
        let page: client_types::ClientUserList = serde_json::from_slice(
            &to_bytes(response.into_body(), 4096)
                .await
                .expect("bounded list body"),
        )
        .expect("Client list JSON");
        assert!(page.items.is_empty());
        assert_eq!(page.next_cursor, None);

        let wrong_project = router
            .oneshot(
                Request::get("/v1/projects/project-b/users")
                    .header(header::AUTHORIZATION, authorization)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong_project.headers()[header::WWW_AUTHENTICATE], "Bearer");
        assert_client_error(
            wrong_project,
            StatusCode::UNAUTHORIZED,
            client_types::ClientErrorCode::InvalidCredential,
        )
        .await;
    }

    #[tokio::test]
    async fn authenticated_client_parse_failures_use_the_client_json_envelope() {
        let router = isolated_test_client_router();
        let authorization = format!("Bearer {}", canonical_test_client_credential());
        let malformed_query = router
            .clone()
            .oneshot(
                Request::get("/v1/projects/project-a/users?limit=not-a-number")
                    .header(header::AUTHORIZATION, &authorization)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_client_error(
            malformed_query,
            StatusCode::BAD_REQUEST,
            client_types::ClientErrorCode::InvalidRequest,
        )
        .await;

        let malformed_body = router
            .oneshot(
                Request::post("/v1/projects/project-a/users/lookup")
                    .header(header::AUTHORIZATION, authorization)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_client_error(
            malformed_body,
            StatusCode::BAD_REQUEST,
            client_types::ClientErrorCode::InvalidRequest,
        )
        .await;
    }

    #[tokio::test]
    async fn client_router_exposes_only_json_client_and_probe_routes() {
        let router = isolated_test_client_router();
        for path in [
            "/",
            "/auth/",
            "/console",
            "/mcp",
            "/v1/projects/project-a/auth/config",
            "/v1/projects/project-a/client-keys",
            "/.well-known/owlauth",
        ] {
            let response = router
                .clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
            assert_no_browser_authority_headers(&response);
        }
        let preflight = router
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/v1/projects/project-a/users")
                    .header(header::ORIGIN, "https://browser.example")
                    .header("access-control-request-method", "GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(preflight.headers()[header::WWW_AUTHENTICATE], "Bearer");
        assert_no_browser_authority_headers(&preflight);
        assert_client_error(
            preflight,
            StatusCode::UNAUTHORIZED,
            client_types::ClientErrorCode::InvalidCredential,
        )
        .await;
    }

    #[tokio::test]
    async fn application_sync_routes_are_control_authenticated_and_runtime_absent() {
        let config = test_config(PlaneMode::All);
        let routers = build_routers(&config, None);
        let control = routers.control.expect("Control router");
        let runtime = routers.runtime.expect("Runtime router");
        let project = Uuid::new_v4();
        let application = Uuid::new_v4();
        let endpoint = Uuid::new_v4();
        let paths = [
            format!("/control/v1/projects/{project}/applications/{application}/webhook-endpoints"),
            format!(
                "/control/v1/projects/{project}/applications/{application}/webhook-endpoints/{endpoint}"
            ),
            format!("/control/v1/projects/{project}/applications/{application}/user-events"),
            format!("/control/v1/projects/{project}/applications/{application}/webhook-deliveries"),
        ];
        for path in paths {
            let unauthenticated = control
                .clone()
                .oneshot(Request::get(&path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED, "{path}");

            let authenticated = control
                .clone()
                .oneshot(
                    Request::get(&path)
                        .header(
                            header::AUTHORIZATION,
                            format!("Bearer owl_ctrl_v1_{}", "A".repeat(43)),
                        )
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_ne!(authenticated.status(), StatusCode::NOT_FOUND, "{path}");

            let runtime_response = runtime
                .clone()
                .oneshot(Request::get(&path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(runtime_response.status(), StatusCode::NOT_FOUND, "{path}");
        }
    }
}
