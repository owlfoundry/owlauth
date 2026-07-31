use sea_orm::{ActiveModelTrait, Set};
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::application::ApplicationError;

use super::{authentication::persistence, entity::audit_event};

pub(super) async fn append_runtime_audit(
    transaction: &sea_orm::DatabaseTransaction,
    project_id: Uuid,
    actor_kind: &str,
    action: &str,
    target_kind: &str,
    target_id: Option<Uuid>,
    correlation_id: Uuid,
) -> Result<(), ApplicationError> {
    audit_event::ActiveModel {
        id: Set(Uuid::new_v4()),
        project_id: Set(Some(project_id)),
        actor_kind: Set(actor_kind.to_owned()),
        action: Set(action.to_owned()),
        target_kind: Set(target_kind.to_owned()),
        target_id: Set(target_id),
        outcome: Set("succeeded".to_owned()),
        correlation_id: Set(correlation_id),
        safe_context: Set(Value::Object(Map::new())),
    }
    .insert(transaction)
    .await
    .map_err(persistence)?;
    Ok(())
}
