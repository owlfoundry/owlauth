use std::collections::BTreeSet;

use sea_orm::{ConnectionTrait, DbBackend, QueryResult, Statement};
use uuid::Uuid;

use crate::application::{ApplicationError, VersionedDigest};

use super::authentication::persistence;

/// Resolves one exact canonical email lookup inside the caller's authoritative snapshot.
/// Durable alias authority, rather than the process key inventory, decides which candidate
/// versions remain accepted. The result is a Project user ID only; no address or digest escapes.
pub(super) async fn resolve_active_email_user_id<C: ConnectionTrait>(
    connection: &C,
    project_id: Uuid,
    candidates: &[VersionedDigest],
) -> Result<Option<Uuid>, ApplicationError> {
    if candidates.is_empty() || candidates.len() > 32 {
        return Err(ApplicationError::InvalidInput);
    }
    let authority = connection
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT accepted_versions FROM email_identity_alias_authority WHERE singleton=TRUE"
                .to_owned(),
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?;
    let accepted: serde_json::Value = authority
        .try_get("", "accepted_versions")
        .map_err(persistence)?;
    let accepted =
        serde_json::from_value::<Vec<i32>>(accepted).map_err(|_| ApplicationError::Integrity)?;
    let accepted_set = accepted.iter().copied().collect::<BTreeSet<_>>();
    if accepted.is_empty()
        || accepted.len() > 16
        || accepted_set.len() != accepted.len()
        || accepted_set.iter().any(|version| *version <= 0)
        || accepted_set.iter().any(|version| {
            !candidates
                .iter()
                .any(|candidate| candidate.key_version == *version)
        })
    {
        return Err(ApplicationError::Integrity);
    }

    let mut user_ids = BTreeSet::new();
    for candidate in candidates
        .iter()
        .filter(|candidate| accepted_set.contains(&candidate.key_version))
    {
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
