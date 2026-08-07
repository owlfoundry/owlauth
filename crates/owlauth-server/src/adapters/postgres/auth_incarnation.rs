use sea_orm::{ConnectionTrait, DbBackend, Statement};
use uuid::Uuid;

use crate::application::ApplicationError;

#[derive(Clone, Debug)]
pub(super) struct AuthIncarnationFence {
    process_id: String,
    incarnation: Uuid,
}

impl AuthIncarnationFence {
    pub(super) fn new(process_id: String, incarnation: Uuid) -> Self {
        Self {
            process_id,
            incarnation,
        }
    }

    #[cfg(test)]
    pub(super) fn test_default() -> Self {
        Self::new("auth-1".to_owned(), Uuid::nil())
    }

    pub(super) fn process_id(&self) -> &str {
        &self.process_id
    }

    pub(super) const fn incarnation(&self) -> Uuid {
        self.incarnation
    }

    /// Acquires the Auth incarnation row before any business lock and holds it for the
    /// caller's transaction lifetime. Replacement takes the conflicting row lock, so either the
    /// operation finishes first or the predecessor observes `Disabled` before business mutation.
    pub(super) async fn lock<C: ConnectionTrait>(
        &self,
        connection: &C,
    ) -> Result<(), ApplicationError> {
        let current = connection
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT 1 FROM auth_process_incarnations
                 WHERE process_id=$1 AND process_incarnation=$2 FOR SHARE",
                vec![self.process_id.clone().into(), self.incarnation.into()],
            ))
            .await
            .map_err(|_| ApplicationError::Persistence)?
            .is_some();
        if current {
            Ok(())
        } else {
            Err(ApplicationError::Disabled)
        }
    }
}
