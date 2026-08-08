use std::collections::BTreeSet;

use sea_orm::{ConnectionTrait, DbBackend, QueryResult, Statement};
use uuid::Uuid;

use crate::application::{ApplicationError, VersionedDigest};

use super::authentication::persistence;

/// Resolves one canonical email lookup against the process-local active and retained key ring.
/// The result is a Project user ID only; no address or digest escapes.
pub(super) async fn resolve_active_email_user_id<C: ConnectionTrait>(
    connection: &C,
    project_id: Uuid,
    candidates: &[VersionedDigest],
) -> Result<Option<Uuid>, ApplicationError> {
    if candidates.is_empty() || candidates.len() > 32 {
        return Err(ApplicationError::InvalidInput);
    }
    if candidates
        .iter()
        .any(|candidate| candidate.key_version <= 0)
        || candidates
            .iter()
            .map(|candidate| candidate.key_version)
            .collect::<BTreeSet<_>>()
            .len()
            != candidates.len()
    {
        return Err(ApplicationError::InvalidInput);
    }

    let mut user_ids = BTreeSet::new();
    for candidate in candidates {
        if candidate.key_version <= 0 {
            return Err(ApplicationError::InvalidInput);
        }
        let row = connection
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT identity.user_id
                   FROM email_identity_aliases alias
                   JOIN email_identities identity
                     ON identity.project_id=alias.project_id
                    AND identity.id=alias.identity_id
                  WHERE alias.project_id=$1 AND alias.canonicalization_version=1
                    AND alias.digest_key_version=$2 AND alias.lookup_digest=$3
                    AND identity.status='active'",
                [
                    project_id.into(),
                    candidate.key_version.into(),
                    candidate.value.to_vec().into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        if let Some(row) = row {
            user_ids.insert(user_id(&row)?);
        }
    }
    if user_ids.len() > 1 {
        return Err(ApplicationError::Integrity);
    }
    Ok(user_ids.into_iter().next())
}

fn user_id(row: &QueryResult) -> Result<Uuid, ApplicationError> {
    row.try_get("", "user_id").map_err(persistence)
}
