use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::runtime::{ProviderKind, PublicJwk, SigningAlgorithm};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProjectStatus {
    Active,
    Disabled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationType {
    Web,
    Native,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationStatus {
    Active,
    Disabled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SigningKeyState {
    Provisioning,
    Published,
    Active,
    Retiring,
    Retired,
    Revoked,
    Abandoned,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStatus {
    Provisioning,
    Active,
    Disabled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct ProblemDetails {
    #[serde(rename = "type")]
    pub type_uri: String,
    pub code: String,
    pub title: String,
    pub status: u16,
    pub detail: String,
    pub request_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct Project {
    pub id: String,
    pub public_id: String,
    #[schema(max_length = 128)]
    pub display_name: String,
    #[schema(max_length = 256)]
    pub belongs_to: Option<String>,
    pub status: ProjectStatus,
    pub metadata_revision: i64,
    pub security_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct ProjectList {
    #[schema(max_items = 100)]
    pub items: Vec<Project>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct CreateProjectRequest {
    #[schema(min_length = 1, max_length = 128)]
    pub display_name: String,
    #[schema(max_length = 256)]
    pub belongs_to: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct UpdateProjectRequest {
    #[schema(min_length = 1, max_length = 128)]
    pub display_name: String,
    #[schema(max_length = 256)]
    pub belongs_to: Option<String>,
    #[schema(minimum = 1)]
    pub expected_metadata_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct ProjectPolicy {
    pub project_id: String,
    #[schema(minimum = 60, maximum = 3600)]
    pub access_token_lifetime_seconds: i32,
    pub browser_session_reuse: bool,
    #[schema(minimum = 1)]
    pub claims_revision: i64,
    #[schema(minimum = 1)]
    pub session_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct UpdateProjectPolicyRequest {
    #[schema(minimum = 60, maximum = 3600)]
    pub access_token_lifetime_seconds: i32,
    pub browser_session_reuse: bool,
    #[schema(minimum = 1)]
    pub expected_claims_revision: i64,
    #[schema(minimum = 1)]
    pub expected_session_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct ExpectedSecurityRevision {
    #[schema(minimum = 1)]
    pub expected_security_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct ApplicationConfiguration {
    #[schema(max_items = 50)]
    pub redirect_uris: Vec<String>,
    #[schema(max_items = 50)]
    pub allowed_origins: Vec<String>,
    #[schema(max_items = 50)]
    pub publishable_keys: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct Application {
    pub id: String,
    pub project_id: String,
    pub public_id: String,
    #[schema(max_length = 128)]
    pub display_name: String,
    pub application_type: ApplicationType,
    pub status: ApplicationStatus,
    pub metadata_revision: i64,
    pub security_revision: i64,
    pub configuration: ApplicationConfiguration,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct ApplicationList {
    #[schema(max_items = 100)]
    pub items: Vec<Application>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct CreateApplicationRequest {
    #[schema(min_length = 1, max_length = 128)]
    pub display_name: String,
    pub application_type: ApplicationType,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct UpdateApplicationRequest {
    #[schema(min_length = 1, max_length = 128)]
    pub display_name: String,
    #[schema(minimum = 1)]
    pub expected_metadata_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct ReplaceApplicationConfigurationRequest {
    #[schema(max_items = 50)]
    pub redirect_uris: Vec<String>,
    #[schema(max_items = 50)]
    pub allowed_origins: Vec<String>,
    #[schema(minimum = 1)]
    pub expected_security_revision: i64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct SigningKey {
    pub id: String,
    pub project_id: String,
    pub kid: String,
    pub algorithm: SigningAlgorithm,
    pub state: SigningKeyState,
    pub ring_revision: i64,
    pub signing_epoch: i64,
    pub sign_not_before: Option<String>,
    pub verify_not_after: Option<String>,
    /// Absent until the external signer material has been reconciled.
    pub public_jwk: Option<PublicJwk>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct SigningKeyList {
    #[schema(max_items = 100)]
    pub items: Vec<SigningKey>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct CreateSigningKeyRequest {
    #[schema(minimum = 1)]
    pub expected_project_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct KeyTransitionRequest {
    #[schema(minimum = 1)]
    pub expected_ring_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct Provider {
    pub id: String,
    pub project_id: String,
    #[schema(max_length = 64)]
    pub provider_key: String,
    pub kind: ProviderKind,
    #[schema(max_length = 128)]
    pub display_name: String,
    pub issuer: String,
    pub client_id: String,
    pub callback_url: String,
    pub status: ProviderStatus,
    pub revision: i64,
    #[schema(max_items = 100)]
    pub assigned_application_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct ProviderList {
    #[schema(max_items = 100)]
    pub items: Vec<Provider>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct CreateProviderRequest {
    #[schema(min_length = 1, max_length = 64)]
    pub provider_key: String,
    #[schema(min_length = 1, max_length = 128)]
    pub display_name: String,
    #[schema(min_length = 8, max_length = 2048)]
    pub issuer: String,
    #[schema(min_length = 1, max_length = 512)]
    pub client_id: String,
    #[schema(write_only, min_length = 1, max_length = 4096)]
    pub client_secret: String,
    #[schema(minimum = 1)]
    pub expected_project_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct ReconcileSigningKeyRequest {
    #[schema(minimum = 1)]
    pub expected_project_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct ReconcileProviderRequest {
    #[schema(write_only, min_length = 1, max_length = 4096)]
    pub client_secret: String,
    #[schema(minimum = 1)]
    pub expected_project_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct ProviderRevisionRequest {
    #[schema(minimum = 1)]
    pub expected_provider_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct ProviderAssignmentRequest {
    #[schema(minimum = 1)]
    pub expected_application_revision: i64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProjectUserStatus {
    Active,
    Disabled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ManagedSessionStatus {
    Active,
    Revoked,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct ProjectUser {
    pub id: String,
    pub project_id: String,
    #[schema(max_length = 96)]
    pub public_id: String,
    pub status: ProjectUserStatus,
    #[schema(minimum = 1)]
    pub user_revision: i64,
    #[schema(minimum = 1)]
    pub security_revision: i64,
    #[schema(max_length = 256)]
    pub display_name: Option<String>,
    #[schema(max_length = 2048)]
    pub picture_url: Option<String>,
    #[schema(max_length = 64)]
    pub created_at: String,
    #[schema(max_length = 64)]
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct ProjectUserList {
    #[schema(max_items = 100)]
    pub items: Vec<ProjectUser>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct ApplicationSession {
    pub id: String,
    pub project_id: String,
    pub user_id: String,
    pub application_id: String,
    #[schema(max_length = 96)]
    pub application_public_id: String,
    #[schema(max_length = 128)]
    pub application_display_name: String,
    pub browser_session_id: Option<String>,
    pub status: ManagedSessionStatus,
    #[schema(minimum = 1)]
    pub session_revision: i64,
    #[schema(max_length = 64)]
    pub authenticated_at: String,
    #[schema(max_length = 64)]
    pub absolute_expires_at: String,
    #[schema(max_length = 64)]
    pub revoked_at: Option<String>,
    #[schema(max_length = 64)]
    pub created_at: String,
    #[schema(max_length = 64)]
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct BrowserSession {
    pub id: String,
    pub project_id: String,
    pub user_id: String,
    pub status: ManagedSessionStatus,
    #[schema(minimum = 1)]
    pub session_revision: i64,
    #[schema(max_length = 64)]
    pub authenticated_at: String,
    #[schema(max_length = 64)]
    pub last_activity_at: String,
    #[schema(max_length = 64)]
    pub idle_expires_at: String,
    #[schema(max_length = 64)]
    pub absolute_expires_at: String,
    #[schema(max_length = 64)]
    pub terminated_at: Option<String>,
    #[schema(max_length = 64)]
    pub created_at: String,
    #[schema(max_length = 64)]
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct ProjectUserSessions {
    #[schema(max_items = 100)]
    pub application_sessions: Vec<ApplicationSession>,
    #[schema(max_items = 100)]
    pub browser_sessions: Vec<BrowserSession>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct ExpectedSessionRevision {
    /// Exact current revision. A terminal session with this revision is returned unchanged;
    /// a stale revision conflicts.
    #[schema(minimum = 1)]
    pub expected_session_revision: i64,
}

macro_rules! control_path {
    ($name:ident, $method:ident, $path:literal, $response:ty, $summary:literal $(, body = $body:ty)? $(, params($($params:tt)*))?) => {
        #[utoipa::path(
            $method,
            path = $path,
            $(request_body = $body,)?
            responses(
                (status = 200, description = $summary, body = $response),
                (status = 400, description = "Invalid request", body = ProblemDetails),
                (status = 401, description = "Missing or invalid operator API key", body = ProblemDetails),
                (status = 404, description = "Resource not found", body = ProblemDetails),
                (status = 409, description = "Revision, state, or idempotency conflict", body = ProblemDetails),
                (status = 500, description = "Stored authority data violated an invariant", body = ProblemDetails),
                (status = 503, description = "Required authority unavailable", body = ProblemDetails)
            ),
            $(params($($params)*),)?
            security(("operator_api_key" = []))
        )]
        #[doc(hidden)]
        pub fn $name() {}
    };
}

control_path!(
    list_projects,
    get,
    "/v1/projects",
    ProjectList,
    "Projects",
    params(("belongs_to" = Option<String>, Query))
);
control_path!(
    create_project,
    post,
    "/v1/projects",
    Project,
    "Created project",
    body = CreateProjectRequest,
    params(("Idempotency-Key" = String, Header))
);
control_path!(
    get_project,
    get,
    "/v1/projects/{project_id}",
    Project,
    "Project",
    params(("project_id" = String, Path))
);
control_path!(
    update_project,
    patch,
    "/v1/projects/{project_id}",
    Project,
    "Updated project",
    body = UpdateProjectRequest,
    params(("project_id" = String, Path))
);
control_path!(
    get_project_policy,
    get,
    "/v1/projects/{project_id}/policy",
    ProjectPolicy,
    "Project policy",
    params(("project_id" = String, Path))
);
control_path!(
    update_project_policy,
    put,
    "/v1/projects/{project_id}/policy",
    ProjectPolicy,
    "Updated Project policy",
    body = UpdateProjectPolicyRequest,
    params(("project_id" = String, Path))
);
control_path!(
    disable_project,
    post,
    "/v1/projects/{project_id}/disable",
    Project,
    "Disabled project",
    body = ExpectedSecurityRevision,
    params(("project_id" = String, Path))
);
control_path!(
    list_applications,
    get,
    "/v1/projects/{project_id}/applications",
    ApplicationList,
    "Applications",
    params(("project_id" = String, Path))
);
control_path!(
    create_application,
    post,
    "/v1/projects/{project_id}/applications",
    Application,
    "Created application",
    body = CreateApplicationRequest,
    params(
        ("project_id" = String, Path),
        ("Idempotency-Key" = String, Header)
    )
);
control_path!(
    get_application,
    get,
    "/v1/projects/{project_id}/applications/{application_id}",
    Application,
    "Application",
    params(
        ("project_id" = String, Path),
        ("application_id" = String, Path)
    )
);
control_path!(
    update_application,
    patch,
    "/v1/projects/{project_id}/applications/{application_id}",
    Application,
    "Updated application",
    body = UpdateApplicationRequest,
    params(
        ("project_id" = String, Path),
        ("application_id" = String, Path)
    )
);
control_path!(
    replace_application_configuration,
    put,
    "/v1/projects/{project_id}/applications/{application_id}/configuration",
    Application,
    "Replaced exact application configuration",
    body = ReplaceApplicationConfigurationRequest,
    params(
        ("project_id" = String, Path),
        ("application_id" = String, Path)
    )
);
control_path!(
    disable_application,
    post,
    "/v1/projects/{project_id}/applications/{application_id}/disable",
    Application,
    "Disabled application",
    body = ExpectedSecurityRevision,
    params(
        ("project_id" = String, Path),
        ("application_id" = String, Path)
    )
);
control_path!(
    list_signing_keys,
    get,
    "/v1/projects/{project_id}/signing-keys",
    SigningKeyList,
    "Signing keys",
    params(("project_id" = String, Path))
);
control_path!(
    create_signing_key,
    post,
    "/v1/projects/{project_id}/signing-keys",
    SigningKey,
    "Provisioned and published signing key",
    body = CreateSigningKeyRequest,
    params(
        ("project_id" = String, Path),
        ("Idempotency-Key" = String, Header)
    )
);
control_path!(
    reconcile_signing_key,
    post,
    "/v1/projects/{project_id}/signing-keys/{key_id}/reconcile",
    SigningKey,
    "Reconciled signing key provisioning",
    body = ReconcileSigningKeyRequest,
    params(("project_id" = String, Path), ("key_id" = String, Path))
);
control_path!(
    activate_signing_key,
    post,
    "/v1/projects/{project_id}/signing-keys/{key_id}/activate",
    SigningKey,
    "Activated signing key",
    body = KeyTransitionRequest,
    params(("project_id" = String, Path), ("key_id" = String, Path))
);
control_path!(
    retire_signing_key,
    post,
    "/v1/projects/{project_id}/signing-keys/{key_id}/retire",
    SigningKey,
    "Retired signing key",
    body = KeyTransitionRequest,
    params(("project_id" = String, Path), ("key_id" = String, Path))
);
control_path!(
    revoke_signing_key,
    post,
    "/v1/projects/{project_id}/signing-keys/{key_id}/revoke",
    SigningKey,
    "Emergency-revoked signing key",
    body = KeyTransitionRequest,
    params(("project_id" = String, Path), ("key_id" = String, Path))
);
control_path!(
    list_providers,
    get,
    "/v1/projects/{project_id}/providers",
    ProviderList,
    "Providers",
    params(("project_id" = String, Path))
);
control_path!(
    create_provider,
    post,
    "/v1/projects/{project_id}/providers",
    Provider,
    "Configured provider",
    body = CreateProviderRequest,
    params(
        ("project_id" = String, Path),
        ("Idempotency-Key" = String, Header)
    )
);
control_path!(
    reconcile_provider,
    post,
    "/v1/projects/{project_id}/providers/{provider_id}/reconcile",
    Provider,
    "Reconciled provider secret provisioning",
    body = ReconcileProviderRequest,
    params(
        ("project_id" = String, Path),
        ("provider_id" = String, Path)
    )
);
control_path!(
    disable_provider,
    post,
    "/v1/projects/{project_id}/providers/{provider_id}/disable",
    Provider,
    "Disabled provider",
    body = ProviderRevisionRequest,
    params(
        ("project_id" = String, Path),
        ("provider_id" = String, Path)
    )
);
control_path!(
    assign_provider,
    put,
    "/v1/projects/{project_id}/providers/{provider_id}/assignments/{application_id}",
    Provider,
    "Assigned provider",
    body = ProviderAssignmentRequest,
    params(
        ("project_id" = String, Path),
        ("provider_id" = String, Path),
        ("application_id" = String, Path)
    )
);
control_path!(
    unassign_provider,
    delete,
    "/v1/projects/{project_id}/providers/{provider_id}/assignments/{application_id}",
    Provider,
    "Unassigned provider",
    body = ProviderAssignmentRequest,
    params(
        ("project_id" = String, Path),
        ("provider_id" = String, Path),
        ("application_id" = String, Path)
    )
);

control_path!(
    list_project_users,
    get,
    "/v1/projects/{project_id}/users",
    ProjectUserList,
    "Project users",
    params(("project_id" = String, Path))
);
control_path!(
    get_project_user,
    get,
    "/v1/projects/{project_id}/users/{user_id}",
    ProjectUser,
    "Project user",
    params(("project_id" = String, Path), ("user_id" = String, Path))
);
control_path!(
    disable_project_user,
    post,
    "/v1/projects/{project_id}/users/{user_id}/disable",
    ProjectUser,
    "Disabled Project user",
    body = ExpectedSecurityRevision,
    params(("project_id" = String, Path), ("user_id" = String, Path))
);
control_path!(
    list_project_user_sessions,
    get,
    "/v1/projects/{project_id}/users/{user_id}/sessions",
    ProjectUserSessions,
    "Project user sessions",
    params(("project_id" = String, Path), ("user_id" = String, Path))
);
control_path!(
    revoke_application_session,
    post,
    "/v1/projects/{project_id}/users/{user_id}/application-sessions/{session_id}/revoke",
    ApplicationSession,
    "Revoked Application session",
    body = ExpectedSessionRevision,
    params(
        ("project_id" = String, Path),
        ("user_id" = String, Path),
        ("session_id" = String, Path)
    )
);
control_path!(
    revoke_browser_session,
    post,
    "/v1/projects/{project_id}/users/{user_id}/browser-sessions/{session_id}/revoke",
    BrowserSession,
    "Revoked Project browser session",
    body = ExpectedSessionRevision,
    params(
        ("project_id" = String, Path),
        ("user_id" = String, Path),
        ("session_id" = String, Path)
    )
);

#[cfg(test)]
mod tests {
    #[test]
    fn user_and_session_lifecycle_contract_is_bounded_and_control_only() {
        let document = serde_json::to_value(crate::control::openapi())
            .expect("Control OpenAPI should serialize");
        for path in [
            "/v1/projects/{project_id}/users",
            "/v1/projects/{project_id}/users/{user_id}",
            "/v1/projects/{project_id}/users/{user_id}/disable",
            "/v1/projects/{project_id}/users/{user_id}/sessions",
            "/v1/projects/{project_id}/users/{user_id}/application-sessions/{session_id}/revoke",
            "/v1/projects/{project_id}/users/{user_id}/browser-sessions/{session_id}/revoke",
        ] {
            assert!(document["paths"][path].is_object(), "missing path: {path}");
        }
        let user = &document["components"]["schemas"]["ProjectUser"]["properties"];
        assert!(user.get("provider_credentials").is_none());
        assert!(user.get("source_payload").is_none());
        assert_eq!(
            document["components"]["schemas"]["ProjectUserList"]["properties"]["items"]["maxItems"],
            100
        );
    }
}
