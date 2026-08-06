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
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
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
        crate::control_resources::list_project_client_keys,
        crate::control_resources::get_project_client_key,
        crate::control_resources::create_project_client_key,
        crate::control_resources::acknowledge_project_client_key_delivery,
        crate::control_resources::revoke_project_client_key,
        crate::control_resources::list_applications,
        crate::control_resources::create_application,
        crate::control_resources::get_application,
        crate::control_resources::update_application,
        crate::control_resources::replace_application_configuration,
        crate::control_resources::disable_application,
        crate::control_resources::get_project_projection_policy,
        crate::control_resources::update_project_projection_policy,
        crate::control_resources::get_application_projection_policy,
        crate::control_resources::update_application_projection_policy,
        crate::control_resources::list_webhook_endpoints,
        crate::control_resources::create_webhook_endpoint,
        crate::control_resources::get_webhook_endpoint,
        crate::control_resources::update_webhook_endpoint,
        crate::control_resources::test_webhook_endpoint,
        crate::control_resources::activate_webhook_endpoint,
        crate::control_resources::disable_webhook_endpoint,
        crate::control_resources::prepare_webhook_secret_rotation,
        crate::control_resources::activate_webhook_secret_rotation,
        crate::control_resources::list_application_user_events,
        crate::control_resources::list_webhook_deliveries,
        crate::control_resources::replay_webhook_delivery,
        crate::control_resources::list_signing_keys,
        crate::control_resources::create_signing_key,
        crate::control_resources::reconcile_signing_key,
        crate::control_resources::activate_signing_key,
        crate::control_resources::retire_signing_key,
        crate::control_resources::revoke_signing_key,
        crate::control_resources::get_provider_egress_policy,
        crate::control_resources::update_provider_egress_policy,
        crate::control_resources::preflight_oidc_provider,
        crate::control_resources::list_providers,
        crate::control_resources::create_provider,
        crate::control_resources::reconcile_provider,
        crate::control_resources::disable_provider,
        crate::control_resources::assign_provider,
        crate::control_resources::unassign_provider,
        crate::control_resources::get_email_method_policy,
        crate::control_resources::update_email_method_policy,
        crate::control_resources::list_email_assignments,
        crate::control_resources::assign_email_method,
        crate::control_resources::list_deployment_smtp_generations,
        crate::control_resources::disable_deployment_smtp_generation,
        crate::control_resources::compromise_deployment_smtp_generation,
        crate::control_resources::list_smtp_configurations,
        crate::control_resources::create_smtp_configuration,
        crate::control_resources::test_smtp_configuration,
        crate::control_resources::get_smtp_test_operation,
        crate::control_resources::activate_smtp_configuration,
        crate::control_resources::disable_smtp_configuration,
        crate::control_resources::compromise_smtp_configuration,
        crate::control_resources::list_project_users,
        crate::control_resources::get_project_user,
        crate::control_resources::list_project_user_identities,
        crate::control_resources::disable_project_user,
        crate::control_resources::list_project_user_sessions,
        crate::control_resources::revoke_application_session,
        crate::control_resources::revoke_browser_session,
        crate::control_resources::list_managed_provider_connections,
        crate::control_resources::synchronize_managed_provider_connection,
        crate::control_resources::create_managed_reauthorization,
        crate::control_resources::get_managed_reauthorization,
        crate::control_resources::cancel_managed_reauthorization,
        crate::control_resources::revoke_managed_provider_connection,
        crate::control_resources::disconnect_managed_provider_connection,
        crate::control_resources::create_identity_mutation_intent,
        crate::control_resources::get_identity_mutation_intent,
        crate::control_resources::cancel_identity_mutation_intent,
        crate::control_resources::confirm_identity_mutation_intent
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
        ProjectionPolicy,
        UpdateProjectionPolicyRequest,
        WebhookEndpointStatus,
        ApplicationUserEventType,
        WebhookDeliveryState,
        WebhookDeliveryOutcomeClass,
        WebhookEndpoint,
        WebhookEndpointList,
        CreateWebhookEndpointRequest,
        UpdateWebhookEndpointRequest,
        ExpectedWebhookEndpointRevision,
        PrepareWebhookSecretRotationRequest,
        WebhookSecretPreparationStatus,
        PreparedWebhookSecretRotation,
        ActivateWebhookSecretRotationRequest,
        ApplicationUserEvent,
        ApplicationUserEventList,
        WebhookDelivery,
        WebhookDeliveryList,
        ReplayWebhookDeliveryRequest,
        SigningKey,
        SigningKeyList,
        ProjectClientKeyStatus,
        ProjectClientKey,
        ProjectClientKeyList,
        CreateProjectClientKeyRequest,
        CreateProjectClientKeyResponse,
        AcknowledgeProjectClientKeyDeliveryRequest,
        RevokeProjectClientKeyRequest,
        CreateSigningKeyRequest,
        ReconcileSigningKeyRequest,
        KeyTransitionRequest,
        Provider,
        ProviderManagedProfileCapability,
        ProviderList,
        ProviderEgressMode,
        ProviderEgressPolicy,
        UpdateProviderEgressPolicyRequest,
        OidcPreflightRequest,
        OidcPreflightResult,
        CreateProviderRequest,
        ReconcileProviderRequest,
        ProviderRevisionRequest,
        ProviderAssignmentRequest,
        SmtpTlsMode,
        SmtpGenerationStatus,
        EmailMethodPolicy,
        UpdateEmailMethodPolicyRequest,
        EmailAssignmentRequest,
        EmailAssignment,
        EmailAssignmentList,
        SmtpConfiguration,
        SmtpConfigurationList,
        DeploymentSmtpGeneration,
        DeploymentSmtpGenerationList,
        ReconcileDeploymentSmtpRequest,
        CreateSmtpConfigurationRequest,
        SmtpRevisionRequest,
        TestSmtpConfigurationRequest,
        ManagedProviderConnectionState,
        ManagedProviderConnection,
        ManagedProviderConnectionList,
        ManagedProviderConnectionActionRequest,
        ManagedReauthorizationStatus,
        ManagedReauthorization,
        CreateManagedReauthorizationRequest,
        CreateManagedReauthorizationResponse,
        CancelManagedReauthorizationRequest,
        crate::runtime::IdentityKind,
        crate::runtime::IdentityMutationMethodKind,
        IdentityMutationUserTarget,
        ExistingIdentityReference,
        IdentityMutationProofAuthority,
        UnlinkPrimarySourceDisposition,
        MergePrimarySource,
        MergeSessionsDisposition,
        MergeBindingsDisposition,
        CreateIdentityMutationIntentRequest,
        IdentityMutationOperationKind,
        IdentityMutationIntentStatus,
        IdentityMutationProofRole,
        IdentityMutationProofSlot,
        IdentityMutationIntent,
        CreateIdentityMutationIntentResponse,
        CancelIdentityMutationIntentRequest,
        LinkIdentityMutationConfirmation,
        UnlinkIdentityMutationConfirmation,
        MergeIdentityMutationConfirmation,
        ConfirmIdentityMutationIntentRequest,
        ProjectUserStatus,
        ManagedSessionStatus,
        ProjectUser,
        ProjectUserList,
        ProjectUserIdentityStatus,
        RedactedEmailMarker,
        ProjectUserIdentityPresentation,
        ProjectUserIdentity,
        ProjectUserIdentityList,
        ApplicationSession,
        BrowserSession,
        ProjectUserSessions,
        ExpectedSessionRevision
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

#[cfg(test)]
mod identity_inventory_tests {
    use super::*;

    #[test]
    fn application_sync_contract_is_typed_bounded_and_control_only() {
        let document = serde_json::to_value(openapi()).expect("serialize Control OpenAPI");
        for path in [
            "/v1/projects/{project_id}/projection-policy",
            "/v1/projects/{project_id}/applications/{application_id}/projection-policy",
            "/v1/projects/{project_id}/applications/{application_id}/webhook-endpoints",
            "/v1/projects/{project_id}/applications/{application_id}/webhook-endpoints/{endpoint_id}",
            "/v1/projects/{project_id}/applications/{application_id}/webhook-endpoints/{endpoint_id}/test",
            "/v1/projects/{project_id}/applications/{application_id}/webhook-endpoints/{endpoint_id}/activate",
            "/v1/projects/{project_id}/applications/{application_id}/webhook-endpoints/{endpoint_id}/secret-rotations",
            "/v1/projects/{project_id}/applications/{application_id}/user-events",
            "/v1/projects/{project_id}/applications/{application_id}/webhook-deliveries",
            "/v1/projects/{project_id}/applications/{application_id}/webhook-deliveries/{delivery_id}/replay",
        ] {
            assert!(document["paths"][path].is_object(), "missing path: {path}");
        }
        assert_eq!(
            document["components"]["schemas"]["CreateWebhookEndpointRequest"]["properties"]["secret"]
                ["writeOnly"],
            true
        );
        assert_eq!(
            document["components"]["schemas"]["WebhookEndpointList"]["properties"]["items"]["maxItems"],
            100
        );
        let endpoint = document["components"]["schemas"]["WebhookEndpoint"].to_string();
        assert!(!endpoint.contains("secret_ref"));
        assert!(!endpoint.contains("request_fingerprint"));
        let runtime =
            serde_json::to_value(crate::runtime::openapi()).expect("serialize Runtime OpenAPI");
        assert!(
            runtime["paths"]
                ["/v1/projects/{project_id}/applications/{application_id}/webhook-endpoints"]
                .is_null()
        );
    }

    #[test]
    fn email_assignment_read_model_is_bounded_and_control_only() {
        let document = serde_json::to_value(openapi()).expect("serialize Control OpenAPI");
        let path = "/v1/projects/{project_id}/email-method/assignments";
        assert!(document["paths"][path]["get"].is_object());
        assert_eq!(
            document["components"]["schemas"]["EmailAssignmentList"]["properties"]["items"]["maxItems"],
            100
        );
        assert_eq!(
            document["components"]["schemas"]["EmailAssignment"]["properties"]["security_revision"]
                ["minimum"],
            1
        );
        let runtime =
            serde_json::to_value(crate::runtime::openapi()).expect("serialize Runtime OpenAPI");
        assert!(runtime["paths"].get(path).is_none());
    }

    #[test]
    fn identity_inventory_contract_is_bounded_redacted_and_control_only() {
        let document = serde_json::to_value(openapi()).expect("serialize Control OpenAPI");
        assert!(
            document["paths"]
                .get("/v1/projects/{project_id}/users/{user_id}/identities")
                .is_some()
        );
        assert_eq!(
            document["components"]["schemas"]["ProjectUserIdentityList"]["properties"]["items"]["maxItems"],
            100
        );
        let identity = document["components"]["schemas"]["ProjectUserIdentity"].to_string();
        for forbidden in [
            "issuer",
            "subject",
            "ciphertext",
            "digest",
            "alias",
            "client_id",
            "secret",
            "credential",
            "receipt",
            "evidence",
            "raw_email",
        ] {
            assert!(
                !identity.contains(forbidden),
                "safe inventory schema exposed forbidden field {forbidden}"
            );
        }
        let runtime =
            serde_json::to_value(crate::runtime::openapi()).expect("serialize Runtime OpenAPI");
        assert!(
            runtime["paths"]
                .get("/v1/projects/{project_id}/users/{user_id}/identities")
                .is_none()
        );
    }
}
