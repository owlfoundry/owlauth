use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, DatabaseConnection, DatabaseTransaction,
    EntityTrait, QueryFilter, TransactionTrait,
};
use serde_json::{Map, Value};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

use super::entity::{audit_event, control_idempotency_record, project};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NewProject {
    pub id: Uuid,
    pub public_id: String,
    pub belongs_to: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CompleteIdempotency {
    Completed,
    AlreadyCompleted,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum RepositoryError {
    #[error("repository transaction could not begin")]
    Begin,
    #[error("repository mutation failed")]
    Mutation,
    #[error("repository transaction could not commit")]
    Commit,
    #[error("repository transaction could not roll back")]
    Rollback,
}

/// Transaction-bound Unit of Work for Project and deployment-audit mutations.
///
/// Its API contains semantic values only; `SeaORM` entities and transaction handles stay
/// inside the `PostgreSQL` adapter.
pub(crate) struct ProjectUnitOfWork {
    transaction: DatabaseTransaction,
}

impl ProjectUnitOfWork {
    pub async fn begin(database: &DatabaseConnection) -> Result<Self, RepositoryError> {
        let transaction = database.begin().await.map_err(|_| RepositoryError::Begin)?;
        Ok(Self { transaction })
    }

    pub async fn insert_project_with_audit(
        &self,
        project: NewProject,
        correlation_id: Uuid,
    ) -> Result<(), RepositoryError> {
        project::ActiveModel {
            id: Set(project.id),
            public_id: Set(project.public_id),
            belongs_to: Set(project.belongs_to),
            status: Set("active".to_owned()),
            metadata_revision: Set(1),
            security_revision: Set(1),
        }
        .insert(&self.transaction)
        .await
        .map_err(|_| RepositoryError::Mutation)?;

        audit_event::ActiveModel {
            id: Set(Uuid::new_v4()),
            project_id: Set(Some(project.id)),
            actor_kind: Set("deployment_operator".to_owned()),
            action: Set("project.created".to_owned()),
            target_kind: Set("project".to_owned()),
            target_id: Set(Some(project.id)),
            outcome: Set("succeeded".to_owned()),
            correlation_id: Set(correlation_id),
            safe_context: Set(Value::Object(Map::default())),
        }
        .insert(&self.transaction)
        .await
        .map_err(|_| RepositoryError::Mutation)?;
        Ok(())
    }

    pub async fn insert_pending_idempotency(
        &self,
        key: String,
        project_id: Uuid,
        request_digest: Vec<u8>,
    ) -> Result<(), RepositoryError> {
        control_idempotency_record::ActiveModel {
            idempotency_key: Set(key),
            project_id: Set(Some(project_id)),
            request_digest: Set(request_digest),
            state: Set("pending".to_owned()),
            result_resource_id: Set(None),
            response: Set(None),
            completed_at: Set(None),
        }
        .insert(&self.transaction)
        .await
        .map_err(|_| RepositoryError::Mutation)?;
        Ok(())
    }

    pub async fn complete_idempotency_once(
        &self,
        key: &str,
        response: Value,
    ) -> Result<CompleteIdempotency, RepositoryError> {
        let result = control_idempotency_record::Entity::update_many()
            .col_expr(
                control_idempotency_record::Column::State,
                sea_orm::sea_query::Expr::value("completed"),
            )
            .col_expr(
                control_idempotency_record::Column::Response,
                sea_orm::sea_query::Expr::value(response),
            )
            .col_expr(
                control_idempotency_record::Column::CompletedAt,
                sea_orm::sea_query::Expr::value(OffsetDateTime::now_utc()),
            )
            .filter(control_idempotency_record::Column::IdempotencyKey.eq(key))
            .filter(control_idempotency_record::Column::State.eq("pending"))
            .exec(&self.transaction)
            .await
            .map_err(|_| RepositoryError::Mutation)?;
        Ok(if result.rows_affected == 1 {
            CompleteIdempotency::Completed
        } else {
            CompleteIdempotency::AlreadyCompleted
        })
    }

    pub async fn commit(self) -> Result<(), RepositoryError> {
        self.transaction
            .commit()
            .await
            .map_err(|_| RepositoryError::Commit)
    }

    pub async fn rollback(self) -> Result<(), RepositoryError> {
        self.transaction
            .rollback()
            .await
            .map_err(|_| RepositoryError::Rollback)
    }
}
