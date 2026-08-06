use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::ApplicationError;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct PublicProvider {
    pub key: String,
    pub display_name: String,
    pub kind: String,
    pub issuer: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the internal snapshot mirrors orthogonal public capability facts"
)]
pub(crate) struct PublicApplicationConfig {
    pub project_public_id: String,
    pub project_display_name: String,
    pub application_public_id: String,
    pub application_display_name: String,
    pub publishable_keys: Vec<String>,
    pub providers: Vec<PublicProvider>,
    pub email_available: bool,
    pub email_otp_enabled: bool,
    pub email_magic_link_enabled: bool,
    pub login_available: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct JwksDocument {
    pub keys: Vec<Value>,
    pub revision: i64,
    pub signing_epoch: i64,
}

#[async_trait]
pub(crate) trait ReadinessPort: Send + Sync {
    async fn public_application_config(
        &self,
        project_public_id: &str,
        application_public_id: &str,
    ) -> Result<PublicApplicationConfig, ApplicationError>;

    async fn project_jwks(&self, project_public_id: &str)
    -> Result<JwksDocument, ApplicationError>;

    async fn observe_signing_revisions(&self, limit: usize) -> Result<usize, ApplicationError>;
}

#[derive(Clone)]
pub(crate) struct ReadinessService {
    port: Arc<dyn ReadinessPort>,
}

impl ReadinessService {
    pub(crate) fn new(port: Arc<dyn ReadinessPort>) -> Self {
        Self { port }
    }

    pub(crate) async fn public_application_config(
        &self,
        project_public_id: &str,
        application_public_id: &str,
    ) -> Result<PublicApplicationConfig, ApplicationError> {
        self.port
            .public_application_config(project_public_id, application_public_id)
            .await
    }

    pub(crate) async fn project_jwks(
        &self,
        project_public_id: &str,
    ) -> Result<JwksDocument, ApplicationError> {
        self.port.project_jwks(project_public_id).await
    }

    pub(crate) async fn observe_signing_revisions(
        &self,
        limit: usize,
    ) -> Result<usize, ApplicationError> {
        if !(1..=100).contains(&limit) {
            return Err(ApplicationError::InvalidInput);
        }
        self.port.observe_signing_revisions(limit).await
    }
}
