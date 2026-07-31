use serde::{Deserialize, Serialize};
use utoipa::openapi::security::{Http, HttpAuthScheme, SecurityScheme};
use utoipa::{Modify, OpenApi, ToSchema};

pub use crate::control_resources::*;
use crate::health::HealthResponse;

/// Side-effect-free origin-root descriptor used before credential selection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct ServiceDescriptor {
    /// Descriptor schema version.
    pub schema_version: String,
    /// Exact product identity.
    pub product: String,
    /// Stable public deployment identity.
    pub instance_id: String,
    /// Canonical same-origin Control API base with a trailing slash.
    pub api_base_url: String,
    /// Supported API versions.
    pub api_versions: Vec<String>,
    /// Credential class accepted by the selected product.
    pub credential_class: String,
    /// Canonical same-origin remote MCP URL when enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_url: Option<String>,
}

#[utoipa::path(
    get,
    path = "/.well-known/owlauth",
    responses(
        (status = 200, description = "Public OwlAuth endpoint descriptor", body = ServiceDescriptor)
    )
)]
#[doc(hidden)]
#[must_use]
pub fn get_service_descriptor() -> ServiceDescriptor {
    ServiceDescriptor {
        schema_version: "1".to_owned(),
        product: "owlauth-server".to_owned(),
        instance_id: "deployment-public-id".to_owned(),
        api_base_url: "https://admin.example.com/v1/".to_owned(),
        api_versions: vec!["v1".to_owned()],
        credential_class: "operator-api-key".to_owned(),
        mcp_url: None,
    }
}

/// Bounded capabilities returned after Control operator authentication.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, ToSchema)]
pub struct SystemCapabilities {
    /// Product identifier for this Control endpoint.
    pub product: String,
    /// Whether Project, Application, key, and provider provisioning is implemented.
    pub provisioning: bool,
    /// Whether Runtime configuration and signing-key publication readiness is implemented.
    pub login_readiness: bool,
    /// Whether end-user federated login, handoff, and session operations are implemented.
    pub federated_project_auth: bool,
}

#[utoipa::path(
    get,
    path = "/v1/system",
    responses(
        (status = 200, description = "Authenticated deployment capabilities", body = SystemCapabilities),
        (status = 401, description = "Missing or invalid operator API key")
    ),
    security(("operator_api_key" = []))
)]
#[doc(hidden)]
#[must_use]
pub fn get_system() -> SystemCapabilities {
    SystemCapabilities {
        product: "owlauth-server".to_owned(),
        provisioning: true,
        login_readiness: true,
        federated_project_auth: crate::FEDERATED_PROJECT_AUTH_AVAILABLE,
    }
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "OwlAuth Control API",
        description = "Deployment Control API"
    ),
    paths(
        crate::health::get_liveness,
        crate::health::get_readiness,
        get_service_descriptor,
        get_system,
        crate::control_resources::list_projects,
        crate::control_resources::create_project,
        crate::control_resources::get_project,
        crate::control_resources::update_project,
        crate::control_resources::get_project_policy,
        crate::control_resources::update_project_policy,
        crate::control_resources::disable_project,
        crate::control_resources::list_applications,
        crate::control_resources::create_application,
        crate::control_resources::get_application,
        crate::control_resources::update_application,
        crate::control_resources::replace_application_configuration,
        crate::control_resources::disable_application,
        crate::control_resources::list_signing_keys,
        crate::control_resources::create_signing_key,
        crate::control_resources::reconcile_signing_key,
        crate::control_resources::activate_signing_key,
        crate::control_resources::retire_signing_key,
        crate::control_resources::revoke_signing_key,
        crate::control_resources::list_providers,
        crate::control_resources::create_provider,
        crate::control_resources::reconcile_provider,
        crate::control_resources::disable_provider,
        crate::control_resources::assign_provider,
        crate::control_resources::unassign_provider
    ),
    components(schemas(
        HealthResponse,
        ServiceDescriptor,
        SystemCapabilities,
        ProblemDetails,
        ProjectStatus,
        ApplicationType,
        ApplicationStatus,
        SigningKeyState,
        ProviderStatus,
        crate::runtime::ProviderKind,
        crate::runtime::JwkKeyType,
        crate::runtime::JwkCurve,
        crate::runtime::SigningAlgorithm,
        crate::runtime::JwkUse,
        crate::runtime::PublicJwk,
        Project,
        ProjectList,
        CreateProjectRequest,
        UpdateProjectRequest,
        ProjectPolicy,
        UpdateProjectPolicyRequest,
        ExpectedSecurityRevision,
        ApplicationConfiguration,
        Application,
        ApplicationList,
        CreateApplicationRequest,
        UpdateApplicationRequest,
        ReplaceApplicationConfigurationRequest,
        SigningKey,
        SigningKeyList,
        CreateSigningKeyRequest,
        ReconcileSigningKeyRequest,
        KeyTransitionRequest,
        Provider,
        ProviderList,
        CreateProviderRequest,
        ReconcileProviderRequest,
        ProviderRevisionRequest,
        ProviderAssignmentRequest
    )),
    modifiers(&ControlSecurity)
)]
struct ControlApiDoc;

struct ControlSecurity;

impl Modify for ControlSecurity {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        openapi
            .components
            .get_or_insert_default()
            .add_security_scheme(
                "operator_api_key",
                SecurityScheme::Http(Http::new(HttpAuthScheme::Bearer)),
            );
    }
}

/// Generates the complete Control-plane `OpenAPI` document.
#[must_use]
pub fn openapi() -> utoipa::openapi::OpenApi {
    ControlApiDoc::openapi()
}
