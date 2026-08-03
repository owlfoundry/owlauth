use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{ApplicationError, ProjectionPolicyRecord};

pub(crate) const PROJECTION_POLICY_COMMIT_TOOL: &str = "owlauth_projection_policy_update_commit";
const CAPABILITY_PREFIX: &str = "owl_mcp_confirm_v1_";
const CAPABILITY_BYTES: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct ConfirmedProjectionPolicyUpdate {
    pub project_id: Uuid,
    pub application_id: Option<Uuid>,
    pub verified_email_enabled: bool,
    pub expected_revision: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct McpConfirmationContext {
    pub instance_id: String,
    pub control_endpoint: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PreparedProjectionPolicyConfirmation {
    pub policy: ProjectionPolicyRecord,
    pub expires_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProjectionPolicyConfirmationPreview {
    pub policy: ProjectionPolicyRecord,
    pub capability: String,
    pub expires_at: OffsetDateTime,
}

#[async_trait]
pub(crate) trait McpConfirmationPort: Send + Sync {
    async fn prepare_projection_policy_update(
        &self,
        context: &McpConfirmationContext,
        command: ConfirmedProjectionPolicyUpdate,
        capability_digest: Vec<u8>,
        command_digest: Vec<u8>,
    ) -> Result<PreparedProjectionPolicyConfirmation, ApplicationError>;

    async fn commit_projection_policy_update(
        &self,
        context: &McpConfirmationContext,
        command: ConfirmedProjectionPolicyUpdate,
        capability_digest: Vec<u8>,
        command_digest: Vec<u8>,
        correlation_id: Uuid,
    ) -> Result<ProjectionPolicyRecord, ApplicationError>;
}

#[derive(Clone)]
pub(crate) struct McpConfirmationService {
    port: std::sync::Arc<dyn McpConfirmationPort>,
    context: McpConfirmationContext,
}

impl McpConfirmationService {
    pub(crate) fn new(
        port: std::sync::Arc<dyn McpConfirmationPort>,
        context: McpConfirmationContext,
    ) -> Result<Self, ApplicationError> {
        if context.instance_id.is_empty()
            || context.instance_id.len() > 128
            || context.control_endpoint.is_empty()
            || context.control_endpoint.len() > 2048
        {
            return Err(ApplicationError::InvalidInput);
        }
        Ok(Self { port, context })
    }

    pub(crate) async fn preview_projection_policy_update(
        &self,
        command: ConfirmedProjectionPolicyUpdate,
    ) -> Result<ProjectionPolicyConfirmationPreview, ApplicationError> {
        validate_command(&command)?;
        let mut random = Zeroizing::new([0_u8; CAPABILITY_BYTES]);
        getrandom::fill(random.as_mut()).map_err(|_| ApplicationError::Persistence)?;
        let capability = format!(
            "{CAPABILITY_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(random.as_ref())
        );
        let capability_digest = Sha256::digest(capability.as_bytes()).to_vec();
        let command_digest = command_digest(&command)?;
        let prepared = self
            .port
            .prepare_projection_policy_update(
                &self.context,
                command,
                capability_digest,
                command_digest,
            )
            .await?;
        Ok(ProjectionPolicyConfirmationPreview {
            policy: prepared.policy,
            capability,
            expires_at: prepared.expires_at,
        })
    }

    pub(crate) async fn commit_projection_policy_update(
        &self,
        command: ConfirmedProjectionPolicyUpdate,
        capability: &str,
        correlation_id: Uuid,
    ) -> Result<ProjectionPolicyRecord, ApplicationError> {
        validate_command(&command)?;
        validate_capability(capability)?;
        let capability_digest = Sha256::digest(capability.as_bytes()).to_vec();
        let command_digest = command_digest(&command)?;
        self.port
            .commit_projection_policy_update(
                &self.context,
                command,
                capability_digest,
                command_digest,
                correlation_id,
            )
            .await
    }
}

fn validate_command(command: &ConfirmedProjectionPolicyUpdate) -> Result<(), ApplicationError> {
    if command.expected_revision <= 0 {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(())
}

fn command_digest(command: &ConfirmedProjectionPolicyUpdate) -> Result<Vec<u8>, ApplicationError> {
    #[derive(Serialize)]
    struct CanonicalCommand<'a> {
        schema: &'static str,
        tool: &'static str,
        command: &'a ConfirmedProjectionPolicyUpdate,
    }
    let encoded = serde_json::to_vec(&CanonicalCommand {
        schema: "owlauth.mcp.confirmation.v1",
        tool: PROJECTION_POLICY_COMMIT_TOOL,
        command,
    })
    .map_err(|_| ApplicationError::Integrity)?;
    Ok(Sha256::digest(encoded).to_vec())
}

fn validate_capability(capability: &str) -> Result<(), ApplicationError> {
    let encoded = capability
        .strip_prefix(CAPABILITY_PREFIX)
        .ok_or(ApplicationError::InvalidInput)?;
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .map_err(|_| ApplicationError::InvalidInput)?;
    if decoded.len() != CAPABILITY_BYTES || URL_SAFE_NO_PAD.encode(decoded) != encoded {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(())
}
