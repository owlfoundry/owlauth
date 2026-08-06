use std::io::Write as _;

use clap::{Args, Subcommand, ValueEnum};
use owlauth_types::{
    control::{
        AcknowledgeProjectClientKeyDeliveryRequest, ActivateWebhookSecretRotationRequest,
        Application, ApplicationList, ApplicationSession, ApplicationType, ApplicationUserEvent,
        ApplicationUserEventList, ApplicationUserEventType, BrowserSession,
        CreateApplicationRequest, CreateProjectClientKeyRequest, CreateProjectClientKeyResponse,
        CreateProjectRequest, CreateProviderRequest, CreateWebhookEndpointRequest,
        ExpectedSecurityRevision, ExpectedSessionRevision, ExpectedWebhookEndpointRevision,
        KeyTransitionRequest, OidcPreflightRequest, OidcPreflightResult,
        PrepareWebhookSecretRotationRequest, PreparedWebhookSecretRotation, Project,
        ProjectClientKey, ProjectClientKeyList, ProjectList, ProjectPolicy, ProjectUser,
        ProjectUserIdentityList, ProjectUserList, ProjectUserSessions, ProjectUserStatus, Provider,
        ProviderAssignmentRequest, ProviderEgressMode, ProviderEgressPolicy, ProviderList,
        ProviderRevisionRequest, ReplayWebhookDeliveryRequest, RevokeProjectClientKeyRequest,
        RotateSigningKeyRequest, SigningKey, SigningKeyList, UpdateProjectPolicyRequest,
        UpdateProviderEgressPolicyRequest, UpdateWebhookEndpointRequest, WebhookDelivery,
        WebhookDeliveryList, WebhookEndpoint, WebhookEndpointList,
    },
    runtime::ProviderKind,
};
use reqwest::Method;
use serde::Serialize;
use zeroize::Zeroize;

use crate::remote::{
    AuthenticatedServerClient, RemoteError, StoredProfile, authenticated_server,
    authenticated_server_snapshot, print_json, require_confirmation, validate_idempotency_key,
    validate_resource_id,
};

#[derive(Debug, Serialize)]
struct ProjectUserOutput {
    id: String,
    project_id: String,
    public_id: String,
    status: ProjectUserStatus,
    user_revision: i64,
    security_revision: i64,
    created_at: String,
    updated_at: String,
}

impl From<ProjectUser> for ProjectUserOutput {
    fn from(value: ProjectUser) -> Self {
        Self {
            id: value.id,
            project_id: value.project_id,
            public_id: value.public_id,
            status: value.status,
            user_revision: value.user_revision,
            security_revision: value.security_revision,
            created_at: value.created_at,
            updated_at: value.updated_at,
        }
    }
}

#[derive(Debug, Serialize)]
struct ProjectUserListOutput {
    items: Vec<ProjectUserOutput>,
    next_cursor: Option<String>,
}

impl From<ProjectUserList> for ProjectUserListOutput {
    fn from(value: ProjectUserList) -> Self {
        Self {
            items: value.items.into_iter().map(Into::into).collect(),
            next_cursor: value.next_cursor,
        }
    }
}

#[derive(Debug, Serialize)]
struct ApplicationUserEventOutput {
    event_id: String,
    project_id: String,
    application_id: String,
    user_id: String,
    event_type: ApplicationUserEventType,
    user_revision: i64,
    projection_revision: i64,
    projection_schema: String,
    occurred_at: String,
}

impl From<ApplicationUserEvent> for ApplicationUserEventOutput {
    fn from(value: ApplicationUserEvent) -> Self {
        Self {
            event_id: value.event_id,
            project_id: value.project_id,
            application_id: value.application_id,
            user_id: value.user_id,
            event_type: value.event_type,
            user_revision: value.user_revision,
            projection_revision: value.projection_revision,
            projection_schema: value.projection_schema,
            occurred_at: value.occurred_at,
        }
    }
}

#[derive(Debug, Serialize)]
struct ApplicationUserEventListOutput {
    items: Vec<ApplicationUserEventOutput>,
    next_cursor: Option<String>,
}

impl From<ApplicationUserEventList> for ApplicationUserEventListOutput {
    fn from(value: ApplicationUserEventList) -> Self {
        Self {
            items: value.items.into_iter().map(Into::into).collect(),
            next_cursor: value.next_cursor,
        }
    }
}

#[derive(Debug, Args)]
pub(crate) struct ProjectArgs {
    #[command(subcommand)]
    command: ProjectCommand,
}

#[derive(Debug, Subcommand)]
enum ProjectCommand {
    /// List the bounded Project inventory.
    List {
        #[arg(long)]
        belongs_to: Option<String>,
    },
    /// Get one Project by its Control UUID.
    Get { project_id: String },
    /// Create a Project with a caller-retained idempotency key.
    Create {
        #[arg(long)]
        display_name: String,
        #[arg(long)]
        belongs_to: Option<String>,
        #[arg(long)]
        idempotency_key: String,
    },
    /// Monotonically disable a Project.
    Disable {
        project_id: String,
        #[arg(long)]
        expected_security_revision: i64,
        #[arg(long)]
        yes: bool,
    },
    /// Read or replace Project token/session policy.
    Policy(ProjectPolicyArgs),
    /// Inspect and administer Project users and their sessions.
    User(ProjectUserArgs),
}

#[derive(Debug, Args)]
struct ProjectUserArgs {
    #[command(subcommand)]
    command: ProjectUserCommand,
}

#[derive(Debug, Subcommand)]
enum ProjectUserCommand {
    List {
        project_id: String,
    },
    Get {
        project_id: String,
        user_id: String,
    },
    Identities {
        project_id: String,
        user_id: String,
    },
    Disable {
        project_id: String,
        user_id: String,
        #[arg(long)]
        expected_security_revision: i64,
        #[arg(long)]
        yes: bool,
    },
    Enable {
        project_id: String,
        user_id: String,
        #[arg(long)]
        expected_security_revision: i64,
        #[arg(long)]
        yes: bool,
    },
    Sessions {
        project_id: String,
        user_id: String,
    },
    RevokeApplicationSession {
        project_id: String,
        user_id: String,
        session_id: String,
        #[arg(long)]
        expected_session_revision: i64,
        #[arg(long)]
        yes: bool,
    },
    RevokeBrowserSession {
        project_id: String,
        user_id: String,
        session_id: String,
        #[arg(long)]
        expected_session_revision: i64,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Args)]
struct ProjectPolicyArgs {
    #[command(subcommand)]
    command: ProjectPolicyCommand,
}

#[derive(Debug, Subcommand)]
enum ProjectPolicyCommand {
    Get {
        project_id: String,
    },
    Set {
        project_id: String,
        #[arg(long)]
        access_token_lifetime_seconds: i32,
        #[arg(long, required = true, action = clap::ArgAction::Set)]
        browser_session_reuse: bool,
        #[arg(long)]
        expected_claims_revision: i64,
        #[arg(long)]
        expected_session_revision: i64,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ApplicationTypeArg {
    Web,
    Native,
}

impl From<ApplicationTypeArg> for ApplicationType {
    fn from(value: ApplicationTypeArg) -> Self {
        match value {
            ApplicationTypeArg::Web => Self::Web,
            ApplicationTypeArg::Native => Self::Native,
        }
    }
}

#[derive(Debug, Args)]
pub(crate) struct ClientKeyArgs {
    #[command(subcommand)]
    command: ClientKeyCommand,
}

#[derive(Debug, Subcommand)]
enum ClientKeyCommand {
    /// List secret-free Project client-key metadata.
    List { project_id: String },
    /// Create a Project client key and reveal its credential exactly once.
    Create {
        project_id: String,
        #[arg(long)]
        label: String,
        #[arg(long)]
        idempotency_key: String,
    },
    /// Confirm that a revealed credential is durably stored outside `OwlAuth`.
    Acknowledge {
        project_id: String,
        key_id: String,
        #[arg(long, value_parser = clap::value_parser!(i64).range(1..))]
        expected_revision: i64,
        #[arg(long)]
        idempotency_key: String,
        #[arg(long)]
        yes: bool,
    },
    /// Immediately and irreversibly revoke one Project client key.
    Revoke {
        project_id: String,
        key_id: String,
        #[arg(long, value_parser = clap::value_parser!(i64).range(1..))]
        expected_revision: i64,
        #[arg(long)]
        idempotency_key: String,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Args)]
pub(crate) struct ApplicationArgs {
    #[command(subcommand)]
    command: ApplicationCommand,
}

#[derive(Debug, Subcommand)]
enum ApplicationCommand {
    List {
        project_id: String,
    },
    Get {
        project_id: String,
        application_id: String,
    },
    Create {
        project_id: String,
        #[arg(long)]
        display_name: String,
        #[arg(long, value_enum)]
        application_type: ApplicationTypeArg,
        #[arg(long)]
        idempotency_key: String,
    },
    Disable {
        project_id: String,
        application_id: String,
        #[arg(long)]
        expected_security_revision: i64,
        #[arg(long)]
        yes: bool,
    },
    /// Inspect immutable Application user-event history.
    UserEvent(ApplicationUserEventArgs),
}

#[derive(Debug, Args)]
struct ApplicationUserEventArgs {
    #[command(subcommand)]
    command: ApplicationUserEventCommand,
}

#[derive(Debug, Subcommand)]
enum ApplicationUserEventCommand {
    List {
        project_id: String,
        application_id: String,
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long)]
        limit: Option<usize>,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ProviderKindArg {
    Oidc,
    Google,
    Github,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ProviderEgressModeArg {
    AllowAll,
    ExactOrigins,
}

impl From<ProviderEgressModeArg> for ProviderEgressMode {
    fn from(value: ProviderEgressModeArg) -> Self {
        match value {
            ProviderEgressModeArg::AllowAll => Self::AllowAll,
            ProviderEgressModeArg::ExactOrigins => Self::ExactOrigins,
        }
    }
}

impl From<ProviderKindArg> for ProviderKind {
    fn from(value: ProviderKindArg) -> Self {
        match value {
            ProviderKindArg::Oidc => Self::Oidc,
            ProviderKindArg::Google => Self::Google,
            ProviderKindArg::Github => Self::Github,
        }
    }
}

#[derive(Debug, Args)]
pub(crate) struct ProviderArgs {
    #[command(subcommand)]
    command: ProviderCommand,
}

#[derive(Debug, Subcommand)]
enum ProviderCommand {
    EgressGet {
        project_id: String,
    },
    EgressSet {
        project_id: String,
        #[arg(long, value_enum)]
        mode: ProviderEgressModeArg,
        #[arg(long, value_delimiter = ',')]
        exact_origin: Vec<String>,
        #[arg(long)]
        expected_revision: i64,
    },
    Preflight {
        project_id: String,
        #[arg(long)]
        provider_key: String,
        #[arg(long)]
        issuer: String,
    },
    List {
        project_id: String,
    },
    Create {
        project_id: String,
        #[arg(long, value_enum)]
        kind: ProviderKindArg,
        #[arg(long)]
        provider_key: String,
        #[arg(long)]
        display_name: String,
        #[arg(long)]
        issuer: Option<String>,
        #[arg(long)]
        client_id: String,
        /// Environment variable containing the write-only provider client secret.
        #[arg(long)]
        client_secret_env: String,
        #[arg(long)]
        managed_profile_enabled: bool,
        #[arg(long)]
        expected_project_revision: i64,
        #[arg(long)]
        idempotency_key: String,
    },
    Disable {
        project_id: String,
        provider_id: String,
        #[arg(long)]
        expected_provider_revision: i64,
        #[arg(long)]
        yes: bool,
    },
    Assign {
        project_id: String,
        provider_id: String,
        application_id: String,
        #[arg(long)]
        expected_application_revision: i64,
        #[arg(long)]
        yes: bool,
    },
    Unassign {
        project_id: String,
        provider_id: String,
        application_id: String,
        #[arg(long)]
        expected_application_revision: i64,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Args)]
pub(crate) struct SigningKeyArgs {
    #[command(subcommand)]
    command: SigningKeyCommand,
}

#[derive(Debug, Subcommand)]
enum SigningKeyCommand {
    List {
        project_id: String,
    },
    Rotate {
        project_id: String,
        #[arg(long)]
        expected_project_revision: i64,
        #[arg(long)]
        idempotency_key: String,
    },
    Revoke(KeyTransitionArgs),
}

#[derive(Debug, Args)]
struct KeyTransitionArgs {
    project_id: String,
    key_id: String,
    #[arg(long)]
    expected_ring_revision: i64,
    #[arg(long)]
    yes: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum WebhookEventArg {
    Created,
    Updated,
    Disabled,
}

impl From<WebhookEventArg> for owlauth_types::control::ApplicationUserEventType {
    fn from(value: WebhookEventArg) -> Self {
        match value {
            WebhookEventArg::Created => Self::Created,
            WebhookEventArg::Updated => Self::Updated,
            WebhookEventArg::Disabled => Self::Disabled,
        }
    }
}

#[derive(Debug, Args)]
pub(crate) struct WebhookArgs {
    #[command(subcommand)]
    command: WebhookCommand,
}

#[derive(Debug, Subcommand)]
enum WebhookCommand {
    /// Manage immutable-destination webhook endpoints.
    Endpoint(WebhookEndpointArgs),
    /// Inspect bounded webhook delivery state; event bodies are intentionally absent.
    Delivery(WebhookDeliveryArgs),
}

#[derive(Debug, Args)]
struct WebhookEndpointArgs {
    #[command(subcommand)]
    command: WebhookEndpointCommand,
}

#[derive(Debug, Subcommand)]
enum WebhookEndpointCommand {
    List {
        project_id: String,
        application_id: String,
    },
    Get {
        project_id: String,
        application_id: String,
        endpoint_id: String,
    },
    Create {
        project_id: String,
        application_id: String,
        #[arg(long)]
        url: String,
        #[arg(long = "event", value_enum, required = true)]
        events: Vec<WebhookEventArg>,
        /// Environment variable containing the write-only signing secret.
        #[arg(long)]
        secret_env: String,
        #[arg(long)]
        idempotency_key: String,
    },
    /// Replace the complete event subscription at an exact endpoint revision.
    Update {
        project_id: String,
        application_id: String,
        endpoint_id: String,
        #[arg(long = "event", value_enum, required = true)]
        events: Vec<WebhookEventArg>,
        #[arg(long)]
        expected_revision: i64,
        #[arg(long)]
        yes: bool,
    },
    /// Provision a write-only candidate secret generation.
    PrepareSecretRotation {
        project_id: String,
        application_id: String,
        endpoint_id: String,
        /// Environment variable containing the write-only signing secret.
        #[arg(long)]
        secret_env: String,
        #[arg(long)]
        expected_revision: i64,
        #[arg(long)]
        idempotency_key: String,
    },
    /// Activate a prepared secret generation with bounded verification overlap.
    ActivateSecretRotation {
        project_id: String,
        application_id: String,
        endpoint_id: String,
        generation: i32,
        #[arg(long)]
        expected_revision: i64,
        #[arg(long)]
        overlap_seconds: i64,
        #[arg(long)]
        yes: bool,
    },
    Test(WebhookEndpointTransitionArgs),
    Activate(WebhookEndpointTransitionArgs),
    Disable(WebhookEndpointTransitionArgs),
}

#[derive(Debug, Args)]
struct WebhookEndpointTransitionArgs {
    project_id: String,
    application_id: String,
    endpoint_id: String,
    #[arg(long)]
    expected_revision: i64,
    #[arg(long)]
    yes: bool,
}

#[derive(Debug, Args)]
struct WebhookDeliveryArgs {
    #[command(subcommand)]
    command: WebhookDeliveryCommand,
}

#[derive(Debug, Subcommand)]
enum WebhookDeliveryCommand {
    List {
        project_id: String,
        application_id: String,
        #[arg(long)]
        endpoint_id: Option<String>,
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long)]
        limit: Option<usize>,
    },
    Replay {
        project_id: String,
        application_id: String,
        delivery_id: String,
        #[arg(long)]
        yes: bool,
    },
}

pub(crate) fn run_project(profile: Option<&str>, args: ProjectArgs) -> Result<(), RemoteError> {
    match args.command {
        ProjectCommand::List { belongs_to } => {
            let client = authenticated_server(profile)?;
            let value: ProjectList = match belongs_to {
                Some(value) => client.get_with_query("projects", &[("belongs_to", value)])?,
                None => client.get("projects")?,
            };
            print_json(&value)
        }
        ProjectCommand::Get { project_id } => {
            resource(&project_id)?;
            let value: Project =
                authenticated_server(profile)?.get(&format!("projects/{project_id}"))?;
            print_json(&value)
        }
        ProjectCommand::Create {
            display_name,
            belongs_to,
            idempotency_key,
        } => {
            idem(&idempotency_key)?;
            let value: Project = authenticated_server(profile)?.send(
                Method::POST,
                "projects",
                &CreateProjectRequest {
                    display_name,
                    belongs_to,
                },
                Some(&idempotency_key),
            )?;
            print_json(&value)
        }
        ProjectCommand::Disable {
            project_id,
            expected_security_revision,
            yes,
        } => {
            resource(&project_id)?;
            let target = format!("projects/{project_id}/disable");
            let stored = require_confirmation(
                yes,
                profile,
                "project.disable",
                &target,
                &serde_json::json!({
                    "effect": "monotonically disable the Project",
                    "expected_security_revision": expected_security_revision,
                }),
            )?;
            let value: Project = authenticated_server_snapshot(stored)?.send(
                Method::POST,
                &target,
                &ExpectedSecurityRevision {
                    expected_security_revision,
                },
                None,
            )?;
            print_json(&value)
        }
        ProjectCommand::Policy(args) => run_project_policy(profile, args),
        ProjectCommand::User(args) => run_project_user(profile, args),
    }
}

pub(crate) fn run_client_key(
    profile: Option<&str>,
    args: ClientKeyArgs,
) -> Result<(), RemoteError> {
    match args.command {
        ClientKeyCommand::List { project_id } => {
            resource(&project_id)?;
            let value: ProjectClientKeyList = authenticated_server(profile)?
                .get(&format!("projects/{project_id}/client-keys"))?;
            print_json(&value)
        }
        ClientKeyCommand::Create {
            project_id,
            label,
            idempotency_key,
        } => {
            resource(&project_id)?;
            idem(&idempotency_key)?;
            let mut value: CreateProjectClientKeyResponse = authenticated_server(profile)?.send(
                Method::POST,
                &format!("projects/{project_id}/client-keys"),
                &CreateProjectClientKeyRequest { label },
                Some(&idempotency_key),
            )?;
            // Stream directly to stdout so no additional heap String retains the one-time secret.
            // Zeroize the deserialized response on both successful and failed output.
            let result = print_one_time_client_key(&value);
            value.credential.zeroize();
            result
        }
        ClientKeyCommand::Acknowledge {
            project_id,
            key_id,
            expected_revision,
            idempotency_key,
            yes,
        } => {
            resources(&[&project_id, &key_id])?;
            idem(&idempotency_key)?;
            let target = format!("projects/{project_id}/client-keys/{key_id}/acknowledge");
            let stored = require_confirmation(
                yes,
                profile,
                "project-client-key.acknowledge-delivery",
                &target,
                &serde_json::json!({
                    "effect": "assert that the one-time credential is durably stored outside OwlAuth and unblock replacement creation",
                    "expected_revision": expected_revision,
                    "confirm_stored": true,
                }),
            )?;
            let value: ProjectClientKey = authenticated_server_snapshot(stored)?.send(
                Method::POST,
                &target,
                &AcknowledgeProjectClientKeyDeliveryRequest {
                    expected_revision,
                    confirm_stored: true,
                },
                Some(&idempotency_key),
            )?;
            print_json(&value)
        }
        ClientKeyCommand::Revoke {
            project_id,
            key_id,
            expected_revision,
            idempotency_key,
            yes,
        } => {
            resources(&[&project_id, &key_id])?;
            idem(&idempotency_key)?;
            let target = format!("projects/{project_id}/client-keys/{key_id}/revoke");
            let stored = require_confirmation(
                yes,
                profile,
                "project-client-key.revoke",
                &target,
                &serde_json::json!({
                    "effect": "immediately and irreversibly revoke the Project client key",
                    "expected_revision": expected_revision,
                    "confirm": true,
                }),
            )?;
            let value: ProjectClientKey = authenticated_server_snapshot(stored)?.send(
                Method::POST,
                &target,
                &RevokeProjectClientKeyRequest {
                    expected_revision,
                    confirm: true,
                },
                Some(&idempotency_key),
            )?;
            print_json(&value)
        }
    }
}

fn print_one_time_client_key(value: &CreateProjectClientKeyResponse) -> Result<(), RemoteError> {
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer_pretty(&mut output, value).map_err(|_| RemoteError::ProfileStorage)?;
    output
        .write_all(b"\n")
        .and_then(|()| output.flush())
        .map_err(|_| RemoteError::ProfileStorage)
}

#[allow(
    clippy::too_many_lines,
    reason = "typed user lifecycle dispatch keeps confirmation and exact session targets visible"
)]
fn run_project_user(profile: Option<&str>, args: ProjectUserArgs) -> Result<(), RemoteError> {
    match args.command {
        ProjectUserCommand::List { project_id } => {
            resource(&project_id)?;
            let value: ProjectUserList =
                authenticated_server(profile)?.get(&format!("projects/{project_id}/users"))?;
            print_json(&ProjectUserListOutput::from(value))
        }
        ProjectUserCommand::Get {
            project_id,
            user_id,
        } => {
            resources(&[&project_id, &user_id])?;
            let value: ProjectUser = authenticated_server(profile)?
                .get(&format!("projects/{project_id}/users/{user_id}"))?;
            print_json(&ProjectUserOutput::from(value))
        }
        ProjectUserCommand::Identities {
            project_id,
            user_id,
        } => {
            resources(&[&project_id, &user_id])?;
            let value: ProjectUserIdentityList = authenticated_server(profile)?
                .get(&format!("projects/{project_id}/users/{user_id}/identities"))?;
            print_json(&value)
        }
        ProjectUserCommand::Disable {
            project_id,
            user_id,
            expected_security_revision,
            yes,
        } => {
            resources(&[&project_id, &user_id])?;
            let target = format!("projects/{project_id}/users/{user_id}/disable");
            let stored = require_confirmation(
                yes,
                profile,
                "project-user.disable",
                &target,
                &serde_json::json!({
                    "effect": "disable the Project user and revoke its authority",
                    "expected_security_revision": expected_security_revision,
                }),
            )?;
            let value: ProjectUser = authenticated_server_snapshot(stored)?.send(
                Method::POST,
                &target,
                &ExpectedSecurityRevision {
                    expected_security_revision,
                },
                None,
            )?;
            print_json(&ProjectUserOutput::from(value))
        }
        ProjectUserCommand::Enable {
            project_id,
            user_id,
            expected_security_revision,
            yes,
        } => {
            resources(&[&project_id, &user_id])?;
            let target = format!("projects/{project_id}/users/{user_id}/enable");
            let stored = require_confirmation(
                yes,
                profile,
                "project-user.enable",
                &target,
                &serde_json::json!({
                    "effect": "enable fresh authentication without reviving prior credentials",
                    "expected_security_revision": expected_security_revision,
                }),
            )?;
            let value: ProjectUser = authenticated_server_snapshot(stored)?.send(
                Method::POST,
                &target,
                &ExpectedSecurityRevision {
                    expected_security_revision,
                },
                None,
            )?;
            print_json(&ProjectUserOutput::from(value))
        }
        ProjectUserCommand::Sessions {
            project_id,
            user_id,
        } => {
            resources(&[&project_id, &user_id])?;
            let value: ProjectUserSessions = authenticated_server(profile)?
                .get(&format!("projects/{project_id}/users/{user_id}/sessions"))?;
            print_json(&value)
        }
        ProjectUserCommand::RevokeApplicationSession {
            project_id,
            user_id,
            session_id,
            expected_session_revision,
            yes,
        } => revoke_project_user_session(
            profile,
            "application",
            &project_id,
            &user_id,
            &session_id,
            expected_session_revision,
            yes,
        ),
        ProjectUserCommand::RevokeBrowserSession {
            project_id,
            user_id,
            session_id,
            expected_session_revision,
            yes,
        } => revoke_project_user_session(
            profile,
            "browser",
            &project_id,
            &user_id,
            &session_id,
            expected_session_revision,
            yes,
        ),
    }
}

fn revoke_project_user_session(
    profile: Option<&str>,
    session_kind: &str,
    project_id: &str,
    user_id: &str,
    session_id: &str,
    expected_session_revision: i64,
    yes: bool,
) -> Result<(), RemoteError> {
    resources(&[project_id, user_id, session_id])?;
    let collection = match session_kind {
        "application" => "application-sessions",
        "browser" => "browser-sessions",
        _ => return Err(RemoteError::InvalidApiResponse),
    };
    let target = format!("projects/{project_id}/users/{user_id}/{collection}/{session_id}/revoke");
    let stored = require_confirmation(
        yes,
        profile,
        &format!("project-user.{session_kind}-session.revoke"),
        &target,
        &serde_json::json!({
            "effect": "revoke the exact session",
            "expected_session_revision": expected_session_revision,
        }),
    )?;
    let client = authenticated_server_snapshot(stored)?;
    let request = ExpectedSessionRevision {
        expected_session_revision,
    };
    match session_kind {
        "application" => {
            let value: ApplicationSession = client.send(Method::POST, &target, &request, None)?;
            print_json(&value)
        }
        "browser" => {
            let value: BrowserSession = client.send(Method::POST, &target, &request, None)?;
            print_json(&value)
        }
        _ => Err(RemoteError::InvalidApiResponse),
    }
}

fn run_project_policy(profile: Option<&str>, args: ProjectPolicyArgs) -> Result<(), RemoteError> {
    match args.command {
        ProjectPolicyCommand::Get { project_id } => {
            resource(&project_id)?;
            let value: ProjectPolicy =
                authenticated_server(profile)?.get(&format!("projects/{project_id}/policy"))?;
            print_json(&value)
        }
        ProjectPolicyCommand::Set {
            project_id,
            access_token_lifetime_seconds,
            browser_session_reuse,
            expected_claims_revision,
            expected_session_revision,
            yes,
        } => {
            resource(&project_id)?;
            let target = format!("projects/{project_id}/policy");
            let stored = require_confirmation(
                yes,
                profile,
                "project.policy.replace",
                &target,
                &serde_json::json!({
                    "effect": "replace the complete token and browser-session policy",
                    "access_token_lifetime_seconds": access_token_lifetime_seconds,
                    "browser_session_reuse": browser_session_reuse,
                    "expected_claims_revision": expected_claims_revision,
                    "expected_session_revision": expected_session_revision,
                }),
            )?;
            let value: ProjectPolicy = authenticated_server_snapshot(stored)?.send(
                Method::PUT,
                &target,
                &UpdateProjectPolicyRequest {
                    access_token_lifetime_seconds,
                    browser_session_reuse,
                    expected_claims_revision,
                    expected_session_revision,
                },
                None,
            )?;
            print_json(&value)
        }
    }
}

pub(crate) fn run_application(
    profile: Option<&str>,
    args: ApplicationArgs,
) -> Result<(), RemoteError> {
    match args.command {
        ApplicationCommand::List { project_id } => {
            resource(&project_id)?;
            let value: ApplicationList = authenticated_server(profile)?
                .get(&format!("projects/{project_id}/applications"))?;
            print_json(&value)
        }
        ApplicationCommand::Get {
            project_id,
            application_id,
        } => {
            resources(&[&project_id, &application_id])?;
            let value: Application = authenticated_server(profile)?.get(&format!(
                "projects/{project_id}/applications/{application_id}"
            ))?;
            print_json(&value)
        }
        ApplicationCommand::Create {
            project_id,
            display_name,
            application_type,
            idempotency_key,
        } => {
            resource(&project_id)?;
            idem(&idempotency_key)?;
            let value: Application = authenticated_server(profile)?.send(
                Method::POST,
                &format!("projects/{project_id}/applications"),
                &CreateApplicationRequest {
                    display_name,
                    application_type: application_type.into(),
                },
                Some(&idempotency_key),
            )?;
            print_json(&value)
        }
        ApplicationCommand::Disable {
            project_id,
            application_id,
            expected_security_revision,
            yes,
        } => {
            resources(&[&project_id, &application_id])?;
            let target = format!("projects/{project_id}/applications/{application_id}/disable");
            let stored = require_confirmation(
                yes,
                profile,
                "application.disable",
                &target,
                &serde_json::json!({
                    "effect": "monotonically disable the Application",
                    "expected_security_revision": expected_security_revision,
                }),
            )?;
            let value: Application = authenticated_server_snapshot(stored)?.send(
                Method::POST,
                &target,
                &ExpectedSecurityRevision {
                    expected_security_revision,
                },
                None,
            )?;
            print_json(&value)
        }
        ApplicationCommand::UserEvent(args) => run_application_user_event(profile, args),
    }
}

fn run_application_user_event(
    profile: Option<&str>,
    args: ApplicationUserEventArgs,
) -> Result<(), RemoteError> {
    match args.command {
        ApplicationUserEventCommand::List {
            project_id,
            application_id,
            cursor,
            limit,
        } => {
            resources(&[&project_id, &application_id])?;
            let query = history_query(cursor, limit)?;
            let value: ApplicationUserEventList = authenticated_server(profile)?.get_with_query(
                &format!("projects/{project_id}/applications/{application_id}/user-events"),
                &query,
            )?;
            print_json(&ApplicationUserEventListOutput::from(value))
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "typed provider dispatch keeps each reviewed command and trust transition visible"
)]
pub(crate) fn run_provider(profile: Option<&str>, args: ProviderArgs) -> Result<(), RemoteError> {
    match args.command {
        ProviderCommand::EgressGet { project_id } => {
            resource(&project_id)?;
            let value: ProviderEgressPolicy = authenticated_server(profile)?
                .get(&format!("projects/{project_id}/provider-egress-policy"))?;
            print_json(&value)
        }
        ProviderCommand::EgressSet {
            project_id,
            mode,
            exact_origin,
            expected_revision,
        } => {
            resource(&project_id)?;
            let value: ProviderEgressPolicy = authenticated_server(profile)?.send(
                Method::PUT,
                &format!("projects/{project_id}/provider-egress-policy"),
                &UpdateProviderEgressPolicyRequest {
                    mode: mode.into(),
                    exact_origins: exact_origin,
                    expected_revision,
                },
                None,
            )?;
            print_json(&value)
        }
        ProviderCommand::Preflight {
            project_id,
            provider_key,
            issuer,
        } => {
            resource(&project_id)?;
            let value: OidcPreflightResult = authenticated_server(profile)?.send(
                Method::POST,
                &format!("projects/{project_id}/providers/oidc/preflight"),
                &OidcPreflightRequest {
                    provider_key,
                    issuer,
                },
                None,
            )?;
            print_json(&value)
        }
        ProviderCommand::List { project_id } => {
            resource(&project_id)?;
            let value: ProviderList =
                authenticated_server(profile)?.get(&format!("projects/{project_id}/providers"))?;
            print_json(&value)
        }
        ProviderCommand::Create {
            project_id,
            kind,
            provider_key,
            display_name,
            issuer,
            client_id,
            client_secret_env,
            managed_profile_enabled,
            expected_project_revision,
            idempotency_key,
        } => {
            resource(&project_id)?;
            idem(&idempotency_key)?;
            let kind: ProviderKind = kind.into();
            if matches!(kind, ProviderKind::Oidc) != issuer.is_some() {
                return Err(RemoteError::InvalidProviderVariant);
            }
            let client = authenticated_server(profile)?;
            let mut request = CreateProviderRequest {
                kind,
                provider_key,
                display_name,
                issuer,
                client_id,
                client_secret: client.read_write_only_secret(&client_secret_env)?,
                managed_profile_enabled,
                expected_project_revision,
            };
            let result: Result<Provider, RemoteError> = client.send(
                Method::POST,
                &format!("projects/{project_id}/providers"),
                &request,
                Some(&idempotency_key),
            );
            request.client_secret.zeroize();
            print_json(&result?)
        }
        ProviderCommand::Disable {
            project_id,
            provider_id,
            expected_provider_revision,
            yes,
        } => {
            resources(&[&project_id, &provider_id])?;
            let target = format!("projects/{project_id}/providers/{provider_id}/disable");
            let stored = require_confirmation(
                yes,
                profile,
                "provider.disable",
                &target,
                &serde_json::json!({
                    "effect": "monotonically disable the provider",
                    "expected_provider_revision": expected_provider_revision,
                }),
            )?;
            let value: Provider = authenticated_server_snapshot(stored)?.send(
                Method::POST,
                &target,
                &ProviderRevisionRequest {
                    expected_provider_revision,
                },
                None,
            )?;
            print_json(&value)
        }
        ProviderCommand::Assign {
            project_id,
            provider_id,
            application_id,
            expected_application_revision,
            yes,
        } => {
            resources(&[&project_id, &provider_id, &application_id])?;
            let target = format!(
                "projects/{project_id}/providers/{provider_id}/assignments/{application_id}"
            );
            let stored = require_confirmation(
                yes,
                profile,
                "provider.assign",
                &target,
                &serde_json::json!({
                    "effect": "enable this provider for the exact Application",
                    "expected_application_revision": expected_application_revision,
                }),
            )?;
            let client = authenticated_server_snapshot(stored)?;
            provider_assignment(
                &client,
                Method::PUT,
                &project_id,
                &provider_id,
                &application_id,
                expected_application_revision,
            )
        }
        ProviderCommand::Unassign {
            project_id,
            provider_id,
            application_id,
            expected_application_revision,
            yes,
        } => {
            resources(&[&project_id, &provider_id, &application_id])?;
            let target = format!(
                "projects/{project_id}/providers/{provider_id}/assignments/{application_id}"
            );
            let stored = require_confirmation(
                yes,
                profile,
                "provider.unassign",
                &target,
                &serde_json::json!({
                    "effect": "disable this provider for the exact Application",
                    "expected_application_revision": expected_application_revision,
                }),
            )?;
            let client = authenticated_server_snapshot(stored)?;
            provider_assignment(
                &client,
                Method::DELETE,
                &project_id,
                &provider_id,
                &application_id,
                expected_application_revision,
            )
        }
    }
}

fn provider_assignment(
    client: &AuthenticatedServerClient,
    method: Method,
    project_id: &str,
    provider_id: &str,
    application_id: &str,
    expected_application_revision: i64,
) -> Result<(), RemoteError> {
    resources(&[project_id, provider_id, application_id])?;
    let value: Provider = client.send(
        method,
        &format!("projects/{project_id}/providers/{provider_id}/assignments/{application_id}"),
        &ProviderAssignmentRequest {
            expected_application_revision,
        },
        None,
    )?;
    print_json(&value)
}

pub(crate) fn run_signing_key(
    profile: Option<&str>,
    args: SigningKeyArgs,
) -> Result<(), RemoteError> {
    match args.command {
        SigningKeyCommand::List { project_id } => {
            resource(&project_id)?;
            let value: SigningKeyList = authenticated_server(profile)?
                .get(&format!("projects/{project_id}/signing-keys"))?;
            print_json(&value)
        }
        SigningKeyCommand::Rotate {
            project_id,
            expected_project_revision,
            idempotency_key,
        } => {
            resource(&project_id)?;
            idem(&idempotency_key)?;
            let value: SigningKey = authenticated_server(profile)?.send(
                Method::POST,
                &format!("projects/{project_id}/signing-keys/rotate"),
                &RotateSigningKeyRequest {
                    expected_project_revision,
                },
                Some(&idempotency_key),
            )?;
            print_json(&value)
        }
        SigningKeyCommand::Revoke(args) => revoke_signing_key(profile, &args),
    }
}

fn revoke_signing_key(profile: Option<&str>, args: &KeyTransitionArgs) -> Result<(), RemoteError> {
    resources(&[&args.project_id, &args.key_id])?;
    let target = format!(
        "projects/{}/signing-keys/{}/revoke",
        args.project_id, args.key_id
    );
    let stored = require_confirmation(
        args.yes,
        profile,
        "signing-key.revoke",
        &target,
        &serde_json::json!({
            "effect": "immediately revoke the signing key",
            "expected_ring_revision": args.expected_ring_revision,
        }),
    )?;
    let value: SigningKey = authenticated_server_snapshot(stored)?.send(
        Method::POST,
        &target,
        &KeyTransitionRequest {
            expected_ring_revision: args.expected_ring_revision,
        },
        None,
    )?;
    print_json(&value)
}

pub(crate) fn run_webhook(profile: Option<&str>, args: WebhookArgs) -> Result<(), RemoteError> {
    match args.command {
        WebhookCommand::Endpoint(args) => run_webhook_endpoint(profile, args),
        WebhookCommand::Delivery(args) => run_webhook_delivery(profile, args),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "typed endpoint lifecycle dispatch keeps write-only secret and confirmation boundaries visible"
)]
fn run_webhook_endpoint(
    profile: Option<&str>,
    args: WebhookEndpointArgs,
) -> Result<(), RemoteError> {
    match args.command {
        WebhookEndpointCommand::List {
            project_id,
            application_id,
        } => {
            let base = webhook_base(&project_id, &application_id)?;
            let value: WebhookEndpointList = authenticated_server(profile)?.get(&base)?;
            print_json(&value)
        }
        WebhookEndpointCommand::Get {
            project_id,
            application_id,
            endpoint_id,
        } => {
            let base = webhook_base(&project_id, &application_id)?;
            resource(&endpoint_id)?;
            let value: WebhookEndpoint =
                authenticated_server(profile)?.get(&format!("{base}/{endpoint_id}"))?;
            print_json(&value)
        }
        WebhookEndpointCommand::Create {
            project_id,
            application_id,
            url,
            events,
            secret_env,
            idempotency_key,
        } => {
            let base = webhook_base(&project_id, &application_id)?;
            idem(&idempotency_key)?;
            let client = authenticated_server(profile)?;
            let mut request = CreateWebhookEndpointRequest {
                url,
                subscribed_event_types: events.into_iter().map(Into::into).collect(),
                secret: client.read_write_only_secret(&secret_env)?,
            };
            let result: Result<WebhookEndpoint, RemoteError> =
                client.send(Method::POST, &base, &request, Some(&idempotency_key));
            request.secret.zeroize();
            print_json(&result?)
        }
        WebhookEndpointCommand::Update {
            project_id,
            application_id,
            endpoint_id,
            events,
            expected_revision,
            yes,
        } => {
            let base = webhook_base(&project_id, &application_id)?;
            resource(&endpoint_id)?;
            let target = format!("{base}/{endpoint_id}");
            let subscribed_event_types = events
                .into_iter()
                .map(Into::into)
                .collect::<Vec<owlauth_types::control::ApplicationUserEventType>>();
            let stored = require_confirmation(
                yes,
                profile,
                "webhook-endpoint.subscription.replace",
                &target,
                &serde_json::json!({
                    "effect": "replace the complete webhook event subscription",
                    "subscribed_event_types": subscribed_event_types,
                    "expected_revision": expected_revision,
                }),
            )?;
            let value: WebhookEndpoint = authenticated_server_snapshot(stored)?.send(
                Method::PUT,
                &target,
                &UpdateWebhookEndpointRequest {
                    subscribed_event_types,
                    expected_revision,
                },
                None,
            )?;
            print_json(&value)
        }
        WebhookEndpointCommand::PrepareSecretRotation {
            project_id,
            application_id,
            endpoint_id,
            secret_env,
            expected_revision,
            idempotency_key,
        } => {
            let base = webhook_base(&project_id, &application_id)?;
            resource(&endpoint_id)?;
            idem(&idempotency_key)?;
            let client = authenticated_server(profile)?;
            let mut request = PrepareWebhookSecretRotationRequest {
                secret: client.read_write_only_secret(&secret_env)?,
                expected_revision,
            };
            let result: Result<PreparedWebhookSecretRotation, RemoteError> = client.send(
                Method::POST,
                &format!("{base}/{endpoint_id}/secret-rotations"),
                &request,
                Some(&idempotency_key),
            );
            request.secret.zeroize();
            print_json(&result?)
        }
        WebhookEndpointCommand::ActivateSecretRotation {
            project_id,
            application_id,
            endpoint_id,
            generation,
            expected_revision,
            overlap_seconds,
            yes,
        } => {
            let base = webhook_base(&project_id, &application_id)?;
            resource(&endpoint_id)?;
            let target = format!("{base}/{endpoint_id}/secret-rotations/{generation}/activate");
            let stored = require_confirmation(
                yes,
                profile,
                "webhook-endpoint.secret-rotation.activate",
                &target,
                &serde_json::json!({
                    "effect": "activate the prepared signing-secret generation",
                    "generation": generation,
                    "overlap_seconds": overlap_seconds,
                    "expected_revision": expected_revision,
                }),
            )?;
            let value: WebhookEndpoint = authenticated_server_snapshot(stored)?.send(
                Method::POST,
                &target,
                &ActivateWebhookSecretRotationRequest {
                    expected_revision,
                    overlap_seconds,
                },
                None,
            )?;
            print_json(&value)
        }
        WebhookEndpointCommand::Test(args) => {
            let stored = confirm_webhook_transition(profile, "test", &args)?;
            webhook_endpoint_transition(stored, "test", &args)
        }
        WebhookEndpointCommand::Activate(args) => {
            let stored = confirm_webhook_transition(profile, "activate", &args)?;
            webhook_endpoint_transition(stored, "activate", &args)
        }
        WebhookEndpointCommand::Disable(args) => {
            let stored = confirm_webhook_transition(profile, "disable", &args)?;
            webhook_endpoint_transition(stored, "disable", &args)
        }
    }
}

fn confirm_webhook_transition(
    profile: Option<&str>,
    transition: &str,
    args: &WebhookEndpointTransitionArgs,
) -> Result<StoredProfile, RemoteError> {
    let base = webhook_base(&args.project_id, &args.application_id)?;
    resource(&args.endpoint_id)?;
    let target = format!("{base}/{}/{transition}", args.endpoint_id);
    require_confirmation(
        args.yes,
        profile,
        &format!("webhook-endpoint.{transition}"),
        &target,
        &serde_json::json!({
            "effect": "dispatch or change the webhook endpoint",
            "expected_revision": args.expected_revision,
        }),
    )
}

fn webhook_endpoint_transition(
    stored: StoredProfile,
    transition: &str,
    args: &WebhookEndpointTransitionArgs,
) -> Result<(), RemoteError> {
    let base = webhook_base(&args.project_id, &args.application_id)?;
    resource(&args.endpoint_id)?;
    let value: WebhookEndpoint = authenticated_server_snapshot(stored)?.send(
        Method::POST,
        &format!("{base}/{}/{transition}", args.endpoint_id),
        &ExpectedWebhookEndpointRevision {
            expected_revision: args.expected_revision,
        },
        None,
    )?;
    print_json(&value)
}

fn run_webhook_delivery(
    profile: Option<&str>,
    args: WebhookDeliveryArgs,
) -> Result<(), RemoteError> {
    match args.command {
        WebhookDeliveryCommand::List {
            project_id,
            application_id,
            endpoint_id,
            cursor,
            limit,
        } => {
            resources(&[&project_id, &application_id])?;
            let path =
                format!("projects/{project_id}/applications/{application_id}/webhook-deliveries");
            let mut query = Vec::new();
            if let Some(endpoint_id) = endpoint_id {
                resource(&endpoint_id)?;
                query.push(("endpoint_id", endpoint_id));
            }
            query.extend(history_query(cursor, limit)?);
            let value: WebhookDeliveryList =
                authenticated_server(profile)?.get_with_query(&path, &query)?;
            print_json(&value)
        }
        WebhookDeliveryCommand::Replay {
            project_id,
            application_id,
            delivery_id,
            yes,
        } => {
            resources(&[&project_id, &application_id, &delivery_id])?;
            let target = format!(
                "projects/{project_id}/applications/{application_id}/webhook-deliveries/{delivery_id}/replay"
            );
            let stored = require_confirmation(
                yes,
                profile,
                "webhook-delivery.replay",
                &target,
                &serde_json::json!({
                    "effect": "create one new delivery for the same immutable event and endpoint",
                    "confirm": true,
                }),
            )?;
            let value: WebhookDelivery = authenticated_server_snapshot(stored)?.send(
                Method::POST,
                &target,
                &ReplayWebhookDeliveryRequest { confirm: true },
                None,
            )?;
            print_json(&value)
        }
    }
}

fn history_query(
    cursor: Option<String>,
    limit: Option<usize>,
) -> Result<Vec<(&'static str, String)>, RemoteError> {
    if limit.is_some_and(|value| !(1..=100).contains(&value)) {
        return Err(RemoteError::InvalidHistoryLimit);
    }
    let mut query = Vec::new();
    if let Some(cursor) = cursor {
        query.push(("cursor", cursor));
    }
    if let Some(limit) = limit {
        query.push(("limit", limit.to_string()));
    }
    Ok(query)
}

fn webhook_base(project_id: &str, application_id: &str) -> Result<String, RemoteError> {
    resources(&[project_id, application_id])?;
    Ok(format!(
        "projects/{project_id}/applications/{application_id}/webhook-endpoints"
    ))
}

fn resource(value: &str) -> Result<(), RemoteError> {
    validate_resource_id(value)
}

fn resources(values: &[&str]) -> Result<(), RemoteError> {
    values.iter().try_for_each(|value| resource(value))
}

fn idem(value: &str) -> Result<(), RemoteError> {
    validate_idempotency_key(value)
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
        time::Duration,
    };

    use serde::Serialize;
    use serde_json::{Value, json};
    use url::Url;

    use super::*;
    use crate::remote::AuthenticatedServerClient;

    struct CapturedRequest {
        head: String,
        body: Vec<u8>,
    }

    fn capture_server() -> (String, thread::JoinHandle<CapturedRequest>) {
        capture_server_with_response(json!({}))
    }

    fn capture_server_with_response(
        response: Value,
    ) -> (String, thread::JoinHandle<CapturedRequest>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}/", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];
            let header_end = loop {
                let read = stream.read(&mut buffer).unwrap();
                assert!(read > 0, "request closed before headers completed");
                request.extend_from_slice(&buffer[..read]);
                if let Some(index) = request.windows(4).position(|value| value == b"\r\n\r\n") {
                    break index + 4;
                }
            };
            let head = String::from_utf8(request[..header_end].to_vec()).unwrap();
            let content_length = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            while request.len() < header_end + content_length {
                let read = stream.read(&mut buffer).unwrap();
                assert!(read > 0, "request closed before body completed");
                request.extend_from_slice(&buffer[..read]);
            }
            let response = serde_json::to_vec(&response).unwrap();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.len()
            )
            .unwrap();
            stream.write_all(&response).unwrap();
            CapturedRequest {
                head,
                body: request[header_end..header_end + content_length].to_vec(),
            }
        });
        (origin, server)
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "owned table entries keep each transport case compact and independent"
    )]
    fn assert_send<B: Serialize>(
        method: Method,
        path: &str,
        body: &B,
        idempotency_key: Option<&str>,
        expected_body: Value,
    ) {
        let (origin, server) = capture_server();
        let client = AuthenticatedServerClient::for_transport_test(
            Url::parse(&format!("{origin}v1/")).unwrap(),
        );
        let _: Value = client
            .send(method.clone(), path, body, idempotency_key)
            .unwrap();
        let captured = server.join().unwrap();
        assert!(
            captured
                .head
                .starts_with(&format!("{} /v1/{path} HTTP/1.1", method.as_str()))
        );
        let lower = captured.head.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer owl_ctrl_v1_"));
        match idempotency_key {
            Some(key) => assert!(lower.contains(&format!("idempotency-key: {key}"))),
            None => assert!(!lower.contains("idempotency-key:")),
        }
        assert_eq!(
            serde_json::from_slice::<Value>(&captured.body).unwrap(),
            expected_body
        );
    }

    fn assert_get<T: serde::de::DeserializeOwned>(path: &str, response: Value) {
        let (origin, server) = capture_server_with_response(response);
        let client = AuthenticatedServerClient::for_transport_test(
            Url::parse(&format!("{origin}v1/")).unwrap(),
        );
        let _: T = client.get(path).unwrap();
        let captured = server.join().unwrap();
        assert!(
            captured
                .head
                .starts_with(&format!("GET /v1/{path} HTTP/1.1"))
        );
        assert!(captured.body.is_empty());
    }

    fn assert_get_query(path: &str, query: &[(&str, &str)], expected_target: &str) {
        let (origin, server) = capture_server();
        let client = AuthenticatedServerClient::for_transport_test(
            Url::parse(&format!("{origin}v1/")).unwrap(),
        );
        let query = query
            .iter()
            .map(|(name, value)| (*name, (*value).to_owned()))
            .collect::<Vec<_>>();
        let _: Value = client.get_with_query(path, &query).unwrap();
        let captured = server.join().unwrap();
        assert!(
            captured
                .head
                .starts_with(&format!("GET {expected_target} HTTP/1.1"))
        );
        assert!(captured.body.is_empty());
    }

    #[test]
    fn project_user_output_omits_profile_fields_from_single_and_list_responses() {
        const DISPLAY_SENTINEL: &str = "PROFILE-DISPLAY-SENTINEL-MUST-NOT-LEAK";
        const PICTURE_SENTINEL: &str = "https://profile.invalid/PICTURE-SENTINEL-MUST-NOT-LEAK";
        let source_user = json!({
            "id": "11111111-1111-4111-8111-111111111111",
            "project_id": "22222222-2222-4222-8222-222222222222",
            "public_id": "usr_public",
            "status": "active",
            "user_revision": 7,
            "security_revision": 11,
            "display_name": DISPLAY_SENTINEL,
            "picture_url": PICTURE_SENTINEL,
            "created_at": "2026-08-01T10:20:30Z",
            "updated_at": "2026-08-02T11:22:33Z"
        });
        let expected = json!({
            "id": "11111111-1111-4111-8111-111111111111",
            "project_id": "22222222-2222-4222-8222-222222222222",
            "public_id": "usr_public",
            "status": "active",
            "user_revision": 7,
            "security_revision": 11,
            "created_at": "2026-08-01T10:20:30Z",
            "updated_at": "2026-08-02T11:22:33Z"
        });

        let single_source: ProjectUser = serde_json::from_value(source_user.clone()).unwrap();
        let single_output = serde_json::to_value(ProjectUserOutput::from(single_source)).unwrap();
        assert_eq!(single_output, expected);

        let list_source: ProjectUserList =
            serde_json::from_value(json!({ "items": [source_user] })).unwrap();
        let list_output = serde_json::to_value(ProjectUserListOutput::from(list_source)).unwrap();
        assert_eq!(
            list_output,
            json!({ "items": [expected], "next_cursor": null })
        );

        let serialized = serde_json::to_string(&list_output).unwrap();
        assert!(!serialized.contains(DISPLAY_SENTINEL));
        assert!(!serialized.contains(PICTURE_SENTINEL));
        assert!(!serialized.contains("display_name"));
        assert!(!serialized.contains("picture_url"));
    }

    #[test]
    fn application_user_event_output_omits_body_from_source_response() {
        const BODY_SENTINEL: &str = "EVENT-BODY-SENTINEL-MUST-NOT-LEAK";
        let source: ApplicationUserEventList = serde_json::from_value(json!({
            "items": [{
                "event_id": "evt_123",
                "project_id": "11111111-1111-4111-8111-111111111111",
                "application_id": "22222222-2222-4222-8222-222222222222",
                "user_id": "33333333-3333-4333-8333-333333333333",
                "event_type": "user.projection.updated",
                "user_revision": 13,
                "projection_revision": 17,
                "projection_schema": "projection.v1",
                "safe_body": { "unmistakable_secret": BODY_SENTINEL },
                "occurred_at": "2026-08-03T12:34:56Z"
            }],
            "next_cursor": "cursor_456"
        }))
        .unwrap();

        let output = serde_json::to_value(ApplicationUserEventListOutput::from(source)).unwrap();
        assert_eq!(
            output,
            json!({
                "items": [{
                    "event_id": "evt_123",
                    "project_id": "11111111-1111-4111-8111-111111111111",
                    "application_id": "22222222-2222-4222-8222-222222222222",
                    "user_id": "33333333-3333-4333-8333-333333333333",
                    "event_type": "user.projection.updated",
                    "user_revision": 13,
                    "projection_revision": 17,
                    "projection_schema": "projection.v1",
                    "occurred_at": "2026-08-03T12:34:56Z"
                }],
                "next_cursor": "cursor_456"
            })
        );
        let serialized = serde_json::to_string(&output).unwrap();
        assert!(!serialized.contains(BODY_SENTINEL));
        assert!(!serialized.contains("safe_body"));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one table-like transport test keeps every typed Control command family auditable"
    )]
    fn typed_transport_conformance_covers_exposed_command_families() {
        const PROJECT: &str = "11111111-1111-4111-8111-111111111111";
        const APPLICATION: &str = "22222222-2222-4222-8222-222222222222";
        const PROVIDER: &str = "33333333-3333-4333-8333-333333333333";
        const KEY: &str = "44444444-4444-4444-8444-444444444444";
        const ENDPOINT: &str = "55555555-5555-4555-8555-555555555555";
        const USER: &str = "66666666-6666-4666-8666-666666666666";
        const SESSION: &str = "77777777-7777-4777-8777-777777777777";
        const DELIVERY: &str = "88888888-8888-4888-8888-888888888888";

        assert_get::<owlauth_types::control::SystemCapabilities>(
            "system",
            serde_json::to_value(owlauth_types::control::get_system()).unwrap(),
        );
        for path in [
            "projects".to_owned(),
            format!("projects/{PROJECT}"),
            format!("projects/{PROJECT}/policy"),
            format!("projects/{PROJECT}/applications"),
            format!("projects/{PROJECT}/applications/{APPLICATION}"),
            format!("projects/{PROJECT}/providers"),
            format!("projects/{PROJECT}/provider-egress-policy"),
            format!("projects/{PROJECT}/signing-keys"),
            format!("projects/{PROJECT}/applications/{APPLICATION}/webhook-endpoints"),
            format!("projects/{PROJECT}/applications/{APPLICATION}/user-events"),
            format!("projects/{PROJECT}/applications/{APPLICATION}/webhook-deliveries"),
            format!("projects/{PROJECT}/users"),
            format!("projects/{PROJECT}/users/{USER}"),
            format!("projects/{PROJECT}/users/{USER}/identities"),
            format!("projects/{PROJECT}/users/{USER}/sessions"),
        ] {
            assert_get::<Value>(&path, json!({}));
        }
        assert_get::<ProjectList>("projects", json!({"items":[]}));
        assert_get::<ApplicationList>(
            &format!("projects/{PROJECT}/applications"),
            json!({"items":[]}),
        );
        assert_get::<ProviderList>(
            &format!("projects/{PROJECT}/providers"),
            json!({"items":[]}),
        );
        assert_get::<ProviderEgressPolicy>(
            &format!("projects/{PROJECT}/provider-egress-policy"),
            json!({
                "project_id": PROJECT,
                "mode": "allow_all",
                "exact_origins": [],
                "revision": 1
            }),
        );
        assert_get::<SigningKeyList>(
            &format!("projects/{PROJECT}/signing-keys"),
            json!({"items":[]}),
        );
        assert_get::<WebhookEndpointList>(
            &format!("projects/{PROJECT}/applications/{APPLICATION}/webhook-endpoints"),
            json!({"items":[]}),
        );
        assert_get::<ApplicationUserEventList>(
            &format!("projects/{PROJECT}/applications/{APPLICATION}/user-events"),
            json!({"items":[],"next_cursor":null}),
        );
        assert_get::<WebhookDeliveryList>(
            &format!("projects/{PROJECT}/applications/{APPLICATION}/webhook-deliveries"),
            json!({"items":[],"next_cursor":null}),
        );
        assert_get::<ProjectUserList>(&format!("projects/{PROJECT}/users"), json!({"items":[]}));
        assert_get::<ProjectUserIdentityList>(
            &format!("projects/{PROJECT}/users/{USER}/identities"),
            json!({"items":[]}),
        );
        assert_get::<ProjectUserSessions>(
            &format!("projects/{PROJECT}/users/{USER}/sessions"),
            json!({"application_sessions":[],"browser_sessions":[]}),
        );
        assert_get::<ProjectClientKeyList>(
            &format!("projects/{PROJECT}/client-keys"),
            json!({"items":[],"active_unacknowledged_key":null}),
        );
        assert_send(
            Method::POST,
            &format!("projects/{PROJECT}/client-keys"),
            &CreateProjectClientKeyRequest {
                label: "customer-backend".to_owned(),
            },
            Some("client_key_create_1"),
            json!({"label":"customer-backend"}),
        );
        assert_send(
            Method::POST,
            &format!("projects/{PROJECT}/client-keys/{KEY}/acknowledge"),
            &AcknowledgeProjectClientKeyDeliveryRequest {
                expected_revision: 1,
                confirm_stored: true,
            },
            Some("client_key_acknowledge_1"),
            json!({"expected_revision":1,"confirm_stored":true}),
        );
        assert_send(
            Method::POST,
            &format!("projects/{PROJECT}/client-keys/{KEY}/revoke"),
            &RevokeProjectClientKeyRequest {
                expected_revision: 2,
                confirm: true,
            },
            Some("client_key_revoke_1"),
            json!({"expected_revision":2,"confirm":true}),
        );

        let project = CreateProjectRequest {
            display_name: "Production".to_owned(),
            belongs_to: Some("tenant-a".to_owned()),
        };
        assert_send(
            Method::POST,
            "projects",
            &project,
            Some("project_create_1"),
            json!({"display_name":"Production","belongs_to":"tenant-a"}),
        );
        let project_policy = UpdateProjectPolicyRequest {
            access_token_lifetime_seconds: 900,
            browser_session_reuse: false,
            expected_claims_revision: 2,
            expected_session_revision: 3,
        };
        assert_send(
            Method::PUT,
            &format!("projects/{PROJECT}/policy"),
            &project_policy,
            None,
            json!({
                "access_token_lifetime_seconds":900,
                "browser_session_reuse":false,
                "expected_claims_revision":2,
                "expected_session_revision":3
            }),
        );

        let application = CreateApplicationRequest {
            display_name: "Console".to_owned(),
            application_type: ApplicationType::Web,
        };
        assert_send(
            Method::POST,
            &format!("projects/{PROJECT}/applications"),
            &application,
            Some("application_create_1"),
            json!({"display_name":"Console","application_type":"web"}),
        );
        let security_revision = ExpectedSecurityRevision {
            expected_security_revision: 4,
        };
        assert_send(
            Method::POST,
            &format!("projects/{PROJECT}/applications/{APPLICATION}/disable"),
            &security_revision,
            None,
            json!({"expected_security_revision":4}),
        );

        assert_send(
            Method::PUT,
            &format!("projects/{PROJECT}/provider-egress-policy"),
            &UpdateProviderEgressPolicyRequest {
                mode: ProviderEgressMode::ExactOrigins,
                exact_origins: vec!["https://identity.example".to_owned()],
                expected_revision: 1,
            },
            None,
            json!({
                "mode":"exact_origins",
                "exact_origins":["https://identity.example"],
                "expected_revision":1
            }),
        );
        assert_send(
            Method::POST,
            &format!("projects/{PROJECT}/providers/oidc/preflight"),
            &OidcPreflightRequest {
                provider_key: "workforce".to_owned(),
                issuer: "https://identity.example".to_owned(),
            },
            None,
            json!({
                "provider_key":"workforce",
                "issuer":"https://identity.example"
            }),
        );

        let provider = CreateProviderRequest {
            kind: ProviderKind::Google,
            provider_key: "google".to_owned(),
            display_name: "Google".to_owned(),
            issuer: None,
            client_id: "client".to_owned(),
            client_secret: "write-only-test-secret".to_owned(),
            managed_profile_enabled: true,
            expected_project_revision: 5,
        };
        assert_send(
            Method::POST,
            &format!("projects/{PROJECT}/providers"),
            &provider,
            Some("provider_create_1"),
            json!({
                "kind":"google",
                "provider_key":"google",
                "display_name":"Google",
                "issuer":null,
                "client_id":"client",
                "client_secret":"write-only-test-secret",
                "managed_profile_enabled":true,
                "expected_project_revision":5
            }),
        );
        let custom_oidc = CreateProviderRequest {
            kind: ProviderKind::Oidc,
            provider_key: "workforce".to_owned(),
            display_name: "Workforce".to_owned(),
            issuer: Some("https://identity.example".to_owned()),
            client_id: "client".to_owned(),
            client_secret: "write-only-test-secret".to_owned(),
            managed_profile_enabled: false,
            expected_project_revision: 6,
        };
        assert_send(
            Method::POST,
            &format!("projects/{PROJECT}/providers"),
            &custom_oidc,
            Some("provider_create_2"),
            json!({
                "kind":"oidc",
                "provider_key":"workforce",
                "display_name":"Workforce",
                "issuer":"https://identity.example",
                "client_id":"client",
                "client_secret":"write-only-test-secret",
                "managed_profile_enabled":false,
                "expected_project_revision":6
            }),
        );
        let assignment = ProviderAssignmentRequest {
            expected_application_revision: 6,
        };
        let assignment_path =
            format!("projects/{PROJECT}/providers/{PROVIDER}/assignments/{APPLICATION}");
        for method in [Method::PUT, Method::DELETE] {
            assert_send(
                method,
                &assignment_path,
                &assignment,
                None,
                json!({"expected_application_revision":6}),
            );
        }
        assert_send(
            Method::POST,
            &format!("projects/{PROJECT}/providers/{PROVIDER}/disable"),
            &ProviderRevisionRequest {
                expected_provider_revision: 7,
            },
            None,
            json!({"expected_provider_revision":7}),
        );

        assert_send(
            Method::POST,
            &format!("projects/{PROJECT}/signing-keys/rotate"),
            &RotateSigningKeyRequest {
                expected_project_revision: 8,
            },
            Some("signing_key_rotate_1"),
            json!({"expected_project_revision":8}),
        );
        assert_send(
            Method::POST,
            &format!("projects/{PROJECT}/signing-keys/{KEY}/revoke"),
            &KeyTransitionRequest {
                expected_ring_revision: 9,
            },
            None,
            json!({"expected_ring_revision":9}),
        );

        let webhook = CreateWebhookEndpointRequest {
            url: "https://hooks.example/events".to_owned(),
            subscribed_event_types: vec![owlauth_types::control::ApplicationUserEventType::Created],
            secret: "write-only-test-secret".to_owned(),
        };
        let webhook_base =
            format!("projects/{PROJECT}/applications/{APPLICATION}/webhook-endpoints");
        assert_send(
            Method::POST,
            &webhook_base,
            &webhook,
            Some("webhook_create_1"),
            json!({
                "url":"https://hooks.example/events",
                "subscribed_event_types":["user.projection.created"],
                "secret":"write-only-test-secret"
            }),
        );
        let webhook_revision = ExpectedWebhookEndpointRevision {
            expected_revision: 11,
        };
        for action in ["test", "activate", "disable"] {
            assert_send(
                Method::POST,
                &format!("{webhook_base}/{ENDPOINT}/{action}"),
                &webhook_revision,
                None,
                json!({"expected_revision":11}),
            );
        }
        assert_send(
            Method::PUT,
            &format!("{webhook_base}/{ENDPOINT}"),
            &UpdateWebhookEndpointRequest {
                subscribed_event_types: vec![
                    owlauth_types::control::ApplicationUserEventType::Created,
                    owlauth_types::control::ApplicationUserEventType::Updated,
                ],
                expected_revision: 12,
            },
            None,
            json!({
                "subscribed_event_types":[
                    "user.projection.created",
                    "user.projection.updated"
                ],
                "expected_revision":12
            }),
        );
        assert_send(
            Method::POST,
            &format!("{webhook_base}/{ENDPOINT}/secret-rotations"),
            &PrepareWebhookSecretRotationRequest {
                secret: "new-write-only-test-secret".to_owned(),
                expected_revision: 13,
            },
            Some("webhook_rotate_1"),
            json!({"secret":"new-write-only-test-secret","expected_revision":13}),
        );
        assert_send(
            Method::POST,
            &format!("{webhook_base}/{ENDPOINT}/secret-rotations/2/activate"),
            &ActivateWebhookSecretRotationRequest {
                expected_revision: 14,
                overlap_seconds: 600,
            },
            None,
            json!({"expected_revision":14,"overlap_seconds":600}),
        );

        let user_base = format!("projects/{PROJECT}/users/{USER}");
        assert_send(
            Method::POST,
            &format!("{user_base}/disable"),
            &ExpectedSecurityRevision {
                expected_security_revision: 15,
            },
            None,
            json!({"expected_security_revision":15}),
        );
        for collection in ["application-sessions", "browser-sessions"] {
            assert_send(
                Method::POST,
                &format!("{user_base}/{collection}/{SESSION}/revoke"),
                &ExpectedSessionRevision {
                    expected_session_revision: 16,
                },
                None,
                json!({"expected_session_revision":16}),
            );
        }

        let event_path = format!("projects/{PROJECT}/applications/{APPLICATION}/user-events");
        assert_get_query(
            &event_path,
            &[("cursor", "event+cursor=="), ("limit", "25")],
            &format!("/v1/{event_path}?cursor=event%2Bcursor%3D%3D&limit=25"),
        );
        let delivery_path =
            format!("projects/{PROJECT}/applications/{APPLICATION}/webhook-deliveries");
        assert_get_query(
            &delivery_path,
            &[
                ("endpoint_id", ENDPOINT),
                ("cursor", "delivery/cursor"),
                ("limit", "50"),
            ],
            &format!(
                "/v1/{delivery_path}?endpoint_id={ENDPOINT}&cursor=delivery%2Fcursor&limit=50"
            ),
        );
        assert_send(
            Method::POST,
            &format!("{delivery_path}/{DELIVERY}/replay"),
            &ReplayWebhookDeliveryRequest { confirm: true },
            None,
            json!({"confirm":true}),
        );
    }
}
