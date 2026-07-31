use async_trait::async_trait;
use serde_json::Value;
use uuid::Uuid;

use super::ApplicationError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NewProject {
    pub id: Uuid,
    pub public_id: String,
    pub display_name: String,
    pub belongs_to: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CompleteIdempotency {
    Completed,
    AlreadyCompleted,
}

/// A transaction-bound, application-owned port for one Project command.
///
/// Implementations keep transaction handles and ORM types private. Every repository mutation and
/// durable audit append participating in the command uses the same implementation instance.
#[allow(
    dead_code,
    reason = "the application-owned port is exercised by the retained PostgreSQL Unit-of-Work validation"
)]
#[async_trait]
pub(crate) trait ProjectUnitOfWork: Send {
    async fn insert_project_with_audit(
        &self,
        project: NewProject,
        correlation_id: Uuid,
    ) -> Result<(), ApplicationError>;

    async fn insert_pending_idempotency(
        &self,
        key: String,
        project_id: Uuid,
        request_digest: Vec<u8>,
    ) -> Result<(), ApplicationError>;

    async fn complete_idempotency_once(
        &self,
        key: &str,
        response: Value,
    ) -> Result<CompleteIdempotency, ApplicationError>;

    async fn commit(self) -> Result<(), ApplicationError>;

    async fn rollback(self) -> Result<(), ApplicationError>;
}
