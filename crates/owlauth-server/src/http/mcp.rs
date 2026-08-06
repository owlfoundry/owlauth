use std::{
    str::FromStr as _,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    Router,
    extract::{DefaultBodyLimit, Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::Response,
};
use rmcp::{
    ErrorData, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, Implementation, ServerCapabilities, ServerInfo},
    schemars, tool, tool_handler, tool_router,
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::never::NeverSessionManager,
    },
};
use serde::{Deserialize, Serialize};
use tower_http::{catch_panic::CatchPanicLayer, timeout::TimeoutLayer};
use url::{Host, Url};
use uuid::Uuid;

use super::{ControlState, control_problem, timestamp, valid_control_authorization};
use crate::{
    application::{ApplicationError, ProvisioningService, WebhookControlService},
    config::{ListenerConfig, McpHttpConfig, OperatorApiKey},
};

#[derive(Clone)]
struct McpApplicationServices {
    provisioning: Option<Arc<ProvisioningService>>,
    webhooks: Option<Arc<WebhookControlService>>,
}

impl From<&ControlState> for McpApplicationServices {
    fn from(state: &ControlState) -> Self {
        Self {
            provisioning: state.provisioning.clone(),
            webhooks: state.webhooks.clone(),
        }
    }
}

#[derive(Clone)]
struct McpAdmission {
    operator_key: Arc<OperatorApiKey>,
    external_origin: McpExternalOrigin,
    concurrency: Arc<tokio::sync::Semaphore>,
    rate: Arc<Mutex<McpRateWindow>>,
    max_requests_per_second: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct McpExternalOrigin {
    scheme: String,
    host: String,
    effective_port: u16,
}

impl McpExternalOrigin {
    fn from_url(url: &Url) -> Self {
        Self {
            scheme: url.scheme().to_owned(),
            host: normalized_url_host(url),
            effective_port: url
                .port_or_known_default()
                .expect("validated HTTP external URL has an effective port"),
        }
    }

    fn matches_authority(&self, value: &str) -> bool {
        let Ok(authority) = axum::http::uri::Authority::from_str(value) else {
            return false;
        };
        let host = normalized_authority_host(authority.host());
        let default_port = match self.scheme.as_str() {
            "https" => 443,
            "http" => 80,
            _ => return false,
        };
        let port = authority.port_u16().unwrap_or(default_port);
        host == self.host && port == self.effective_port
    }

    fn matches_origin(&self, value: &str) -> bool {
        let Ok(url) = Url::parse(value) else {
            return false;
        };
        url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none()
            && url.username().is_empty()
            && url.password().is_none()
            && url.scheme() == self.scheme
            && normalized_url_host(&url) == self.host
            && url.port_or_known_default() == Some(self.effective_port)
    }
}

#[derive(Debug)]
struct McpRateWindow {
    started_at: Instant,
    accepted: usize,
}

#[derive(Clone, Copy, Debug)]
struct AuthenticatedDeploymentOperator;

#[derive(Clone, Debug)]
struct OwlAuthMcpServer {
    services: McpApplicationServices,
    max_result_bytes: usize,
    tool_router: ToolRouter<Self>,
}

impl std::fmt::Debug for McpApplicationServices {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("McpApplicationServices([REDACTED])")
    }
}

impl OwlAuthMcpServer {
    fn new(services: McpApplicationServices, max_result_bytes: usize) -> Self {
        Self {
            services,
            max_result_bytes,
            tool_router: Self::tool_router(),
        }
    }

    fn provisioning(&self) -> Result<&ProvisioningService, ApplicationError> {
        self.services
            .provisioning
            .as_deref()
            .ok_or(ApplicationError::Persistence)
    }

    fn webhooks(&self) -> Result<&WebhookControlService, ApplicationError> {
        self.services
            .webhooks
            .as_deref()
            .ok_or(ApplicationError::Persistence)
    }

    fn result<T: Serialize>(
        &self,
        result: Result<T, ApplicationError>,
    ) -> Result<CallToolResult, ErrorData> {
        match result {
            Ok(value) => {
                let value = serde_json::to_value(value).map_err(|_| {
                    ErrorData::internal_error("tool result serialization failed", None)
                })?;
                let encoded = serde_json::to_vec(&value).map_err(|_| {
                    ErrorData::internal_error("tool result serialization failed", None)
                })?;
                if encoded.len() > self.max_result_bytes {
                    return Ok(CallToolResult::structured_error(serde_json::json!({
                        "error": {
                            "code": "result_too_large",
                            "message": "The bounded tool result exceeds the configured limit."
                        }
                    })));
                }
                Ok(CallToolResult::structured(value))
            }
            Err(error) => Ok(application_error_result(error)),
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
enum McpResourceStatus {
    Active,
    Disabled,
}

#[derive(Clone, Copy, Debug, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
enum McpWebhookEndpointStatus {
    Pending,
    Active,
    Disabled,
}

#[derive(Clone, Copy, Debug, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
enum McpWebhookDeliveryStatus {
    Pending,
    Leased,
    Delivered,
    Terminal,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Serialize, schemars::JsonSchema)]
enum McpWebhookEventType {
    #[serde(rename = "user.projection.created")]
    Created,
    #[serde(rename = "user.projection.updated")]
    Updated,
    #[serde(rename = "user.projection.disabled")]
    Disabled,
}

#[derive(Clone, Copy, Debug, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
enum McpWebhookOutcomeClass {
    Accepted,
    Transient,
    Ambiguous,
    Permanent,
}

#[derive(Clone, Copy, Debug, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
enum McpApplicationKind {
    Web,
    Native,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct McpSystemOutput {
    product: String,
    provisioning: bool,
    login_readiness: bool,
    federated_project_auth: bool,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct McpProjectOutput {
    id: String,
    public_id: String,
    display_name: String,
    status: McpResourceStatus,
    metadata_revision: i64,
    security_revision: i64,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct McpProjectListOutput {
    items: Vec<McpProjectOutput>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct McpApplicationOutput {
    id: String,
    project_id: String,
    public_id: String,
    display_name: String,
    application_type: McpApplicationKind,
    status: McpResourceStatus,
    metadata_revision: i64,
    security_revision: i64,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct McpApplicationListOutput {
    items: Vec<McpApplicationOutput>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct McpWebhookEndpointOutput {
    id: String,
    public_id: String,
    project_id: String,
    application_id: String,
    subscribed_event_types: Vec<McpWebhookEventType>,
    status: McpWebhookEndpointStatus,
    revision: i64,
    current_secret_generation: Option<i32>,
    overlap_secret_generation: Option<i32>,
    consecutive_failure_count: i32,
    last_failure_class: Option<McpWebhookOutcomeClass>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct McpWebhookEndpointListOutput {
    items: Vec<McpWebhookEndpointOutput>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct McpWebhookDeliveryOutput {
    id: String,
    endpoint_id: String,
    event_id: String,
    replay_sequence: i32,
    replay_of_delivery_id: Option<String>,
    state: McpWebhookDeliveryStatus,
    attempt_count: i32,
    next_attempt_at: String,
    last_outcome_class: Option<McpWebhookOutcomeClass>,
    last_http_status: Option<i32>,
    delivered_at: Option<String>,
    terminal_at: Option<String>,
    created_at: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct McpWebhookDeliveryListOutput {
    items: Vec<McpWebhookDeliveryOutput>,
    next_cursor: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct EmptyInput {}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct ListProjectsInput {
    /// Optional exact opaque Project ownership metadata filter.
    belongs_to: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct ProjectInput {
    /// Exact Project UUID returned by `OwlAuth` Control.
    project_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct ApplicationInput {
    /// Exact Project UUID returned by `OwlAuth` Control.
    project_id: String,
    /// Exact Application UUID owned by the Project.
    application_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[allow(
    clippy::struct_field_names,
    reason = "closed MCP input uses explicit protocol resource ID names"
)]
struct WebhookDeliveriesInput {
    /// Exact Project UUID returned by `OwlAuth` Control.
    project_id: String,
    /// Exact Application UUID owned by the Project.
    application_id: String,
    /// Optional exact webhook endpoint UUID.
    endpoint_id: Option<String>,
    /// Opaque cursor returned by the previous call.
    cursor: Option<String>,
    /// Page size from 1 through 100; defaults to 50.
    limit: Option<usize>,
}

fn mcp_resource_status(value: &str) -> Result<McpResourceStatus, ApplicationError> {
    match value {
        "active" => Ok(McpResourceStatus::Active),
        "disabled" => Ok(McpResourceStatus::Disabled),
        _ => Err(ApplicationError::Integrity),
    }
}

fn mcp_endpoint_status(value: &str) -> Result<McpWebhookEndpointStatus, ApplicationError> {
    match value {
        "pending" => Ok(McpWebhookEndpointStatus::Pending),
        "active" => Ok(McpWebhookEndpointStatus::Active),
        "disabled" => Ok(McpWebhookEndpointStatus::Disabled),
        _ => Err(ApplicationError::Integrity),
    }
}

fn mcp_delivery_status(value: &str) -> Result<McpWebhookDeliveryStatus, ApplicationError> {
    match value {
        "pending" => Ok(McpWebhookDeliveryStatus::Pending),
        "leased" => Ok(McpWebhookDeliveryStatus::Leased),
        "delivered" => Ok(McpWebhookDeliveryStatus::Delivered),
        "terminal" => Ok(McpWebhookDeliveryStatus::Terminal),
        "cancelled" => Ok(McpWebhookDeliveryStatus::Cancelled),
        _ => Err(ApplicationError::Integrity),
    }
}

fn mcp_event_type(value: &str) -> Result<McpWebhookEventType, ApplicationError> {
    match value {
        "user.projection.created" => Ok(McpWebhookEventType::Created),
        "user.projection.updated" => Ok(McpWebhookEventType::Updated),
        "user.projection.disabled" => Ok(McpWebhookEventType::Disabled),
        _ => Err(ApplicationError::Integrity),
    }
}

fn mcp_outcome_class(value: &str) -> Result<McpWebhookOutcomeClass, ApplicationError> {
    match value {
        "accepted" => Ok(McpWebhookOutcomeClass::Accepted),
        "transient" => Ok(McpWebhookOutcomeClass::Transient),
        "ambiguous" => Ok(McpWebhookOutcomeClass::Ambiguous),
        "permanent" => Ok(McpWebhookOutcomeClass::Permanent),
        _ => Err(ApplicationError::Integrity),
    }
}

fn mcp_project(
    record: crate::application::ProjectRecord,
) -> Result<McpProjectOutput, ApplicationError> {
    Ok(McpProjectOutput {
        id: record.id.to_string(),
        public_id: record.public_id,
        display_name: record.display_name,
        status: mcp_resource_status(&record.status)?,
        metadata_revision: record.metadata_revision,
        security_revision: record.security_revision,
    })
}

fn mcp_application(
    record: crate::application::ApplicationRecord,
) -> Result<McpApplicationOutput, ApplicationError> {
    let application_type = match record.application_type.as_str() {
        "web" => McpApplicationKind::Web,
        "native" => McpApplicationKind::Native,
        _ => return Err(ApplicationError::Integrity),
    };
    Ok(McpApplicationOutput {
        id: record.id.to_string(),
        project_id: record.project_id.to_string(),
        public_id: record.public_id,
        display_name: record.display_name,
        application_type,
        status: mcp_resource_status(&record.status)?,
        metadata_revision: record.metadata_revision,
        security_revision: record.security_revision,
    })
}

fn mcp_webhook_endpoint(
    record: crate::application::WebhookEndpointRecord,
) -> Result<McpWebhookEndpointOutput, ApplicationError> {
    let subscribed_event_types = record
        .subscribed_event_types
        .iter()
        .map(|value| mcp_event_type(value))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(McpWebhookEndpointOutput {
        id: record.id.to_string(),
        public_id: record.public_id,
        project_id: record.project_id.to_string(),
        application_id: record.application_id.to_string(),
        subscribed_event_types,
        status: mcp_endpoint_status(&record.status)?,
        revision: record.revision,
        current_secret_generation: record.current_secret_generation,
        overlap_secret_generation: record.overlap_secret_generation,
        consecutive_failure_count: record.consecutive_failure_count,
        last_failure_class: record
            .last_failure_class
            .as_deref()
            .map(mcp_outcome_class)
            .transpose()?,
    })
}

fn mcp_webhook_delivery(
    record: crate::application::WebhookDeliveryRecord,
) -> Result<McpWebhookDeliveryOutput, ApplicationError> {
    let last_outcome_class = record
        .last_outcome_class
        .as_deref()
        .map(mcp_outcome_class)
        .transpose()?;
    Ok(McpWebhookDeliveryOutput {
        id: record.id.to_string(),
        endpoint_id: record.endpoint_id.to_string(),
        event_id: record.event_id,
        replay_sequence: record.replay_sequence,
        replay_of_delivery_id: record.replay_of_delivery_id.map(|value| value.to_string()),
        state: mcp_delivery_status(&record.state)?,
        attempt_count: record.attempt_count,
        next_attempt_at: timestamp(record.next_attempt_at),
        last_outcome_class,
        last_http_status: record.last_http_status,
        delivered_at: record.delivered_at.map(timestamp),
        terminal_at: record.terminal_at.map(timestamp),
        created_at: timestamp(record.created_at),
    })
}

#[tool_router]
impl OwlAuthMcpServer {
    /// Return the bounded public `OwlAuth` server capability summary.
    #[tool(
        name = "owlauth_system_get",
        output_schema = rmcp::handler::server::tool::schema_for_type::<McpSystemOutput>(),
        annotations(
            title = "Get OwlAuth system capabilities",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn system_get(
        &self,
        Parameters(EmptyInput {}): Parameters<EmptyInput>,
    ) -> Result<CallToolResult, ErrorData> {
        self.result(Ok::<_, ApplicationError>(McpSystemOutput {
            product: "owlauth-server".to_owned(),
            provisioning: true,
            login_readiness: true,
            federated_project_auth: owlauth_types::FEDERATED_PROJECT_AUTH_AVAILABLE,
        }))
    }

    /// List at most the server-defined bounded number of Projects.
    #[tool(
        name = "owlauth_projects_list",
        output_schema = rmcp::handler::server::tool::schema_for_type::<McpProjectListOutput>(),
        annotations(
            title = "List OwlAuth Projects",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn projects_list(
        &self,
        Parameters(input): Parameters<ListProjectsInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let result = match self.provisioning() {
            Ok(service) => service
                .list_projects(input.belongs_to)
                .await
                .and_then(|records| {
                    records
                        .into_iter()
                        .map(mcp_project)
                        .collect::<Result<Vec<_>, _>>()
                        .map(|items| McpProjectListOutput { items })
                }),
            Err(error) => Err(error),
        };
        self.result(result)
    }

    /// Get one exact Project's safe metadata and revisions.
    #[tool(
        name = "owlauth_project_get",
        output_schema = rmcp::handler::server::tool::schema_for_type::<McpProjectOutput>(),
        annotations(
            title = "Get an OwlAuth Project",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn project_get(
        &self,
        Parameters(input): Parameters<ProjectInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let project_id = parse_uuid("project_id", &input.project_id)?;
        let result = match self.provisioning() {
            Ok(service) => service.get_project(project_id).await.and_then(mcp_project),
            Err(error) => Err(error),
        };
        self.result(result)
    }

    /// List the bounded Application inventory owned by one exact Project.
    #[tool(
        name = "owlauth_applications_list",
        output_schema = rmcp::handler::server::tool::schema_for_type::<McpApplicationListOutput>(),
        annotations(
            title = "List OwlAuth Applications",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn applications_list(
        &self,
        Parameters(input): Parameters<ProjectInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let project_id = parse_uuid("project_id", &input.project_id)?;
        let result = match self.provisioning() {
            Ok(service) => service
                .list_applications(project_id)
                .await
                .and_then(|records| {
                    records
                        .into_iter()
                        .map(mcp_application)
                        .collect::<Result<Vec<_>, _>>()
                        .map(|items| McpApplicationListOutput { items })
                }),
            Err(error) => Err(error),
        };
        self.result(result)
    }

    /// Get one exact Project-owned Application's safe configuration metadata.
    #[tool(
        name = "owlauth_application_get",
        output_schema = rmcp::handler::server::tool::schema_for_type::<McpApplicationOutput>(),
        annotations(
            title = "Get an OwlAuth Application",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn application_get(
        &self,
        Parameters(input): Parameters<ApplicationInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let project_id = parse_uuid("project_id", &input.project_id)?;
        let application_id = parse_uuid("application_id", &input.application_id)?;
        let result = match self.provisioning() {
            Ok(service) => service
                .get_application(project_id, application_id)
                .await
                .and_then(mcp_application),
            Err(error) => Err(error),
        };
        self.result(result)
    }

    /// List safe webhook endpoint lifecycle and secret-generation metadata.
    #[tool(
        name = "owlauth_webhook_endpoints_list",
        output_schema = rmcp::handler::server::tool::schema_for_type::<McpWebhookEndpointListOutput>(),
        annotations(
            title = "List OwlAuth webhook endpoints",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn webhook_endpoints_list(
        &self,
        Parameters(input): Parameters<ApplicationInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let project_id = parse_uuid("project_id", &input.project_id)?;
        let application_id = parse_uuid("application_id", &input.application_id)?;
        let result = match self.webhooks() {
            Ok(service) => service
                .list_endpoints(project_id, application_id)
                .await
                .and_then(|records| {
                    records
                        .into_iter()
                        .map(mcp_webhook_endpoint)
                        .collect::<Result<Vec<_>, _>>()
                })
                .map(|items| McpWebhookEndpointListOutput { items }),
            Err(error) => Err(error),
        };
        self.result(result)
    }

    /// List bounded safe webhook delivery state, optionally for one endpoint.
    #[tool(
        name = "owlauth_webhook_deliveries_list",
        output_schema = rmcp::handler::server::tool::schema_for_type::<McpWebhookDeliveryListOutput>(),
        annotations(
            title = "List OwlAuth webhook deliveries",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn webhook_deliveries_list(
        &self,
        Parameters(input): Parameters<WebhookDeliveriesInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let project_id = parse_uuid("project_id", &input.project_id)?;
        let application_id = parse_uuid("application_id", &input.application_id)?;
        let endpoint_id = input
            .endpoint_id
            .as_deref()
            .map(|value| parse_uuid("endpoint_id", value))
            .transpose()?;
        let result = match self.webhooks() {
            Ok(service) => service
                .list_deliveries(
                    project_id,
                    application_id,
                    endpoint_id,
                    input.cursor.as_deref(),
                    input.limit,
                )
                .await
                .and_then(|page| {
                    page.items
                        .into_iter()
                        .map(mcp_webhook_delivery)
                        .collect::<Result<Vec<_>, _>>()
                        .map(|items| McpWebhookDeliveryListOutput {
                            items,
                            next_cursor: page.next_cursor,
                        })
                }),
            Err(error) => Err(error),
        };
        self.result(result)
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for OwlAuthMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("owlauth-server", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "Seven bounded, read-only deployment-operator inspection tools over OwlAuth Control application services.",
            )
    }
}

fn parse_uuid(field: &'static str, value: &str) -> Result<Uuid, ErrorData> {
    let parsed = Uuid::parse_str(value).map_err(|_| {
        ErrorData::invalid_params(format!("{field} must be an exact canonical UUID"), None)
    })?;
    if parsed.to_string() != value {
        return Err(ErrorData::invalid_params(
            format!("{field} must be an exact canonical UUID"),
            None,
        ));
    }
    Ok(parsed)
}

fn application_error_result(error: ApplicationError) -> CallToolResult {
    let (code, message) = match error {
        ApplicationError::InvalidInput => ("invalid_input", "The request value is invalid."),
        ApplicationError::NotFound => ("not_found", "The requested resource was not found."),
        ApplicationError::Disabled => ("disabled", "The requested resource is disabled."),
        ApplicationError::RevisionConflict => (
            "revision_conflict",
            "The requested resource revision is stale.",
        ),
        ApplicationError::IdempotencyConflict => (
            "idempotency_conflict",
            "The idempotency key conflicts with another request.",
        ),
        ApplicationError::OperationInProgress => (
            "operation_in_progress",
            "The requested operation is already in progress.",
        ),
        ApplicationError::PublicationPending => (
            "publication_pending",
            "The requested publication has not propagated.",
        ),
        ApplicationError::InvalidTransition => (
            "invalid_transition",
            "The requested state transition is not allowed.",
        ),
        ApplicationError::Integrity
        | ApplicationError::Persistence
        | ApplicationError::ClientVerifierUnavailable
        | ApplicationError::ProviderPreflightRejected
        | ApplicationError::ProviderPreflightUnavailable
        | ApplicationError::ExternalStore => (
            "temporarily_unavailable",
            "The Control capability is temporarily unavailable.",
        ),
    };
    CallToolResult::structured_error(serde_json::json!({
        "error": { "code": code, "message": message }
    }))
}

fn has_exact_external_authority(
    headers: &axum::http::HeaderMap,
    uri: &axum::http::Uri,
    expected: &McpExternalOrigin,
) -> bool {
    let mut hosts = headers.get_all(header::HOST).iter();
    let host = match (hosts.next(), hosts.next()) {
        (None, None) => None,
        (Some(value), None) => value.to_str().ok(),
        _ => return false,
    };
    let uri_authority = uri.authority().map(axum::http::uri::Authority::as_str);
    let exact_authority = match (host, uri_authority) {
        (None, None) => false,
        (Some(host), None) => expected.matches_authority(host),
        (None, Some(authority)) => expected.matches_authority(authority),
        (Some(host), Some(authority)) => {
            expected.matches_authority(host)
                && expected.matches_authority(authority)
                && normalized_request_authority(host, &expected.scheme)
                    == normalized_request_authority(authority, &expected.scheme)
        }
    };
    let mut origins = headers.get_all(header::ORIGIN).iter();
    let exact_origin = match (origins.next(), origins.next()) {
        (None, None) => true,
        (Some(value), None) => value
            .to_str()
            .is_ok_and(|value| expected.matches_origin(value)),
        _ => false,
    };
    exact_authority && exact_origin
}

async fn require_mcp_operator(
    State(admission): State<McpAdmission>,
    mut request: Request,
    next: Next,
) -> Response {
    if !valid_control_authorization(request.headers(), &admission.operator_key) {
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
    if !has_exact_external_authority(request.headers(), request.uri(), &admission.external_origin) {
        let request_id = request
            .extensions()
            .get::<String>()
            .cloned()
            .unwrap_or_else(|| "unavailable".to_owned());
        return control_problem(
            StatusCode::BAD_REQUEST,
            "invalid_external_authority",
            "Invalid MCP external authority",
            "Host and optional Origin must exactly match the configured Control external authority.",
            &request_id,
        );
    }
    request.headers_mut().remove(header::AUTHORIZATION);
    request
        .extensions_mut()
        .insert(AuthenticatedDeploymentOperator);
    let rate_limited = {
        let mut window = admission
            .rate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if window.started_at.elapsed() >= Duration::from_secs(1) {
            window.started_at = Instant::now();
            window.accepted = 0;
        }
        if window.accepted >= admission.max_requests_per_second {
            true
        } else {
            window.accepted += 1;
            false
        }
    };
    if rate_limited {
        let request_id = request
            .extensions()
            .get::<String>()
            .cloned()
            .unwrap_or_else(|| "unavailable".to_owned());
        let mut response = control_problem(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "MCP request rate exceeded",
            "The bounded MCP request rate has been exceeded.",
            &request_id,
        );
        response.headers_mut().insert(
            header::RETRY_AFTER,
            "1".parse().expect("static header value"),
        );
        return response;
    }
    let Ok(permit) = Arc::clone(&admission.concurrency).try_acquire_owned() else {
        let request_id = request
            .extensions()
            .get::<String>()
            .cloned()
            .unwrap_or_else(|| "unavailable".to_owned());
        return control_problem(
            StatusCode::TOO_MANY_REQUESTS,
            "concurrency_limited",
            "MCP concurrency exceeded",
            "The bounded MCP concurrency budget is exhausted.",
            &request_id,
        );
    };
    let response = next.run(request).await;
    drop(permit);
    response
}

fn normalized_url_host(url: &Url) -> String {
    match url.host().expect("validated external URL has a host") {
        Host::Domain(value) => value.to_ascii_lowercase(),
        Host::Ipv4(value) => value.to_string(),
        Host::Ipv6(value) => value.to_string(),
    }
}

fn normalized_request_authority(value: &str, scheme: &str) -> Option<(String, u16)> {
    let authority = axum::http::uri::Authority::from_str(value).ok()?;
    let port = authority.port_u16().unwrap_or(match scheme {
        "https" => 443,
        "http" => 80,
        _ => return None,
    });
    Some((normalized_authority_host(authority.host()), port))
}

fn normalized_authority_host(value: &str) -> String {
    value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(value)
        .to_ascii_lowercase()
}

fn external_authority(url: &Url) -> String {
    let host = match url.host().expect("validated external URL has a host") {
        Host::Domain(value) => value.to_owned(),
        Host::Ipv4(value) => value.to_string(),
        Host::Ipv6(value) => format!("[{value}]"),
    };
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    }
}

pub(super) fn router(
    state: &ControlState,
    listener: &ListenerConfig,
    config: &McpHttpConfig,
    control_max_request_bytes: usize,
) -> Router {
    let services = McpApplicationServices::from(state);
    let max_result_bytes = config.max_result_bytes;
    let max_request_bytes = config.max_request_bytes.min(control_max_request_bytes);
    let transport = StreamableHttpService::new(
        move || Ok(OwlAuthMcpServer::new(services.clone(), max_result_bytes)),
        Arc::new(NeverSessionManager::default()),
        StreamableHttpServerConfig::default()
            .with_legacy_session_mode(false)
            .with_json_response(true)
            .with_sse_keep_alive(None)
            .with_allowed_hosts([external_authority(&listener.external_base)])
            .with_allowed_origins([listener.external_base.origin().ascii_serialization()])
            .with_max_request_body_bytes(max_request_bytes),
    );
    Router::new()
        .nest_service("/mcp", transport)
        .route_layer(middleware::from_fn_with_state(
            McpAdmission {
                operator_key: Arc::clone(&state.operator_key),
                external_origin: McpExternalOrigin::from_url(&listener.external_base),
                concurrency: Arc::new(tokio::sync::Semaphore::new(config.max_concurrent_requests)),
                rate: Arc::new(Mutex::new(McpRateWindow {
                    started_at: Instant::now(),
                    accepted: 0,
                })),
                max_requests_per_second: config.max_requests_per_second,
            },
            require_mcp_operator,
        ))
        .layer(DefaultBodyLimit::max(max_request_bytes))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            config.request_timeout,
        ))
        .layer(CatchPanicLayer::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_ids_are_exact_canonical_uuids() {
        let canonical = "550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(
            parse_uuid("project_id", canonical).unwrap().to_string(),
            canonical
        );
        assert!(parse_uuid("project_id", "550E8400-E29B-41D4-A716-446655440000").is_err());
        assert!(parse_uuid("project_id", "550e8400e29b41d4a716446655440000").is_err());
    }

    #[test]
    fn external_authority_matches_only_the_normalized_configured_origin() {
        let https = McpExternalOrigin::from_url(&Url::parse("https://Identity.Example/").unwrap());
        assert!(https.matches_authority("identity.example"));
        assert!(https.matches_authority("IDENTITY.EXAMPLE:443"));
        assert!(!https.matches_authority("identity.example:8443"));
        assert!(https.matches_origin("https://identity.example"));
        assert!(https.matches_origin("https://identity.example:443"));
        assert!(!https.matches_origin("https://identity.example:8443"));
        assert!(!https.matches_origin("https://identity.example/path"));

        let ipv6 = McpExternalOrigin::from_url(&Url::parse("http://[::1]:8081/").unwrap());
        assert!(ipv6.matches_authority("[::1]:8081"));
        assert!(ipv6.matches_origin("http://[::1]:8081"));
        assert!(!ipv6.matches_authority("[::1]"));
        assert!(!ipv6.matches_authority("[::1]:8082"));

        let nondefault =
            McpExternalOrigin::from_url(&Url::parse("https://identity.example:8443/").unwrap());
        assert!(nondefault.matches_authority("identity.example:8443"));
        assert!(!nondefault.matches_authority("identity.example"));
    }

    #[test]
    fn uri_authority_is_accepted_and_must_agree_with_host() {
        let expected =
            McpExternalOrigin::from_url(&Url::parse("https://identity.example:8443/").unwrap());
        let empty = axum::http::HeaderMap::new();
        let uri = axum::http::Uri::from_static("https://identity.example:8443/control/mcp");
        assert!(has_exact_external_authority(&empty, &uri, &expected));

        let matching = axum::http::HeaderMap::from_iter([(
            header::HOST,
            "identity.example:8443".parse().unwrap(),
        )]);
        assert!(has_exact_external_authority(&matching, &uri, &expected));
        let conflicting =
            axum::http::HeaderMap::from_iter([(header::HOST, "identity.example".parse().unwrap())]);
        assert!(!has_exact_external_authority(&conflicting, &uri, &expected));
    }

    #[test]
    fn every_tool_has_a_closed_mcp_owned_output_schema() {
        let server = OwlAuthMcpServer::new(
            McpApplicationServices {
                provisioning: None,
                webhooks: None,
            },
            1024,
        );
        let tools = server.tool_router.list_all();
        assert_eq!(tools.len(), 7);
        for tool in tools {
            let schema = tool
                .output_schema
                .expect("every MCP tool declares outputSchema");
            assert_eq!(schema.get("type"), Some(&serde_json::json!("object")));
            assert_eq!(
                schema.get("additionalProperties"),
                Some(&serde_json::json!(false))
            );
        }
    }

    #[test]
    fn resource_specific_output_values_fail_closed() {
        assert!(mcp_resource_status("pending").is_err());
        assert!(mcp_endpoint_status("leased").is_err());
        assert!(mcp_delivery_status("active").is_err());
        assert!(mcp_event_type("user.projection.unknown").is_err());
        assert!(mcp_outcome_class("other").is_err());
        assert!(mcp_resource_status("active").is_ok());
        assert!(mcp_endpoint_status("pending").is_ok());
        assert!(mcp_delivery_status("delivered").is_ok());
    }

    #[test]
    fn webhook_endpoint_output_never_discloses_the_destination_url() {
        let now = time::OffsetDateTime::UNIX_EPOCH;
        let output = mcp_webhook_endpoint(crate::application::WebhookEndpointRecord {
            id: Uuid::nil(),
            public_id: "whe_test".to_owned(),
            project_id: Uuid::nil(),
            application_id: Uuid::nil(),
            url: "https://hooks.example/deliver?token=secret".to_owned(),
            subscribed_event_types: vec!["user.projection.updated".to_owned()],
            status: "active".to_owned(),
            revision: 1,
            current_secret_generation: Some(1),
            overlap_secret_generation: None,
            overlap_expires_at: None,
            consecutive_failure_count: 0,
            last_delivery_at: None,
            last_success_at: None,
            last_failure_class: None,
            last_tested_at: None,
            last_test_succeeded_at: None,
            created_at: now,
            updated_at: now,
        })
        .unwrap();
        let serialized = serde_json::to_value(output).unwrap();
        assert!(serialized.get("url").is_none());
        assert!(!serialized.to_string().contains("token=secret"));
    }
}
