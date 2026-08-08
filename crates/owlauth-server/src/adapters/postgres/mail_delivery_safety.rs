use std::collections::BTreeSet;

use sea_orm::{ConnectionTrait, DatabaseTransaction, DbBackend, Statement};
use uuid::Uuid;

use crate::application::{ApplicationError, VersionedDigest};

/// A protocol-safety bound, not a tenant quota or a generic request rate limit.
/// It prevents one Project from growing an unclaimable active mail backlog without bound.
pub(super) const MAX_ACTIVE_MAIL_OUTBOX_PER_PROJECT: i64 = 1_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum MailDeliveryAuthorization {
    Dispatch,
    RecipientSuppressed,
    ProjectBacklogFull,
}

pub(super) async fn authorize_mail_delivery(
    transaction: &DatabaseTransaction,
    project_id: Uuid,
    canonicalization_version: i32,
    recipient_digests: &[VersionedDigest],
    suppression_seconds: i32,
) -> Result<MailDeliveryAuthorization, ApplicationError> {
    authorize_mail_delivery_with_limit(
        transaction,
        project_id,
        canonicalization_version,
        recipient_digests,
        suppression_seconds,
        MAX_ACTIVE_MAIL_OUTBOX_PER_PROJECT,
    )
    .await
}

pub(super) async fn authorize_mail_delivery_with_limit(
    transaction: &DatabaseTransaction,
    project_id: Uuid,
    canonicalization_version: i32,
    recipient_digests: &[VersionedDigest],
    suppression_seconds: i32,
    active_outbox_limit: i64,
) -> Result<MailDeliveryAuthorization, ApplicationError> {
    validate_inputs(
        canonicalization_version,
        recipient_digests,
        suppression_seconds,
    )?;
    if active_outbox_limit <= 0 || active_outbox_limit > MAX_ACTIVE_MAIL_OUTBOX_PER_PROJECT {
        return Err(ApplicationError::InvalidInput);
    }

    // Every generation path takes this short transaction-scoped Project lock after locking its
    // own protocol owner. It serializes only the side-effect decision, so the backlog count and
    // recent-recipient check are authoritative across Runtime replicas.
    transaction
        .query_one_raw(statement(
            "SELECT pg_advisory_xact_lock(\
                 hashtextextended('owlauth-project-mail-delivery:' || $1::TEXT, 0))",
            vec![project_id.into()],
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?;

    let active_outbox = transaction
        .query_one_raw(statement(
            "SELECT COUNT(*)::BIGINT AS count FROM mail_outbox
             WHERE project_id=$1 AND status IN ('pending','leased','retry','ambiguous')",
            vec![project_id.into()],
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?
        .try_get::<i64>("", "count")
        .map_err(persistence)?;
    if active_outbox >= active_outbox_limit {
        return Ok(MailDeliveryAuthorization::ProjectBacklogFull);
    }

    if recipient_was_recently_enqueued(
        transaction,
        project_id,
        canonicalization_version,
        recipient_digests,
        suppression_seconds,
    )
    .await?
    {
        return Ok(MailDeliveryAuthorization::RecipientSuppressed);
    }
    Ok(MailDeliveryAuthorization::Dispatch)
}

async fn recipient_was_recently_enqueued(
    transaction: &DatabaseTransaction,
    project_id: Uuid,
    canonicalization_version: i32,
    recipient_digests: &[VersionedDigest],
    suppression_seconds: i32,
) -> Result<bool, ApplicationError> {
    let mut values = vec![
        project_id.into(),
        canonicalization_version.into(),
        suppression_seconds.into(),
    ];
    let mut candidates = Vec::with_capacity(recipient_digests.len());
    for digest in recipient_digests {
        let version_parameter = values.len() + 1;
        values.push(digest.key_version.into());
        let digest_parameter = values.len() + 1;
        values.push(digest.value.to_vec().into());
        candidates.push(format!(
            "(challenge.lookup_digest_key_version=${version_parameter} \
             AND challenge.lookup_digest=${digest_parameter})"
        ));
    }
    let sql = format!(
        "SELECT 1 FROM email_challenges challenge
         JOIN mail_outbox outbox ON outbox.project_id=challenge.project_id
           AND outbox.challenge_id=challenge.id
           AND outbox.challenge_generation=challenge.generation
         WHERE challenge.project_id=$1 AND challenge.canonicalization_version=$2
           AND outbox.created_at > clock_timestamp() - make_interval(secs => $3)
           AND ({}) LIMIT 1",
        candidates.join(" OR ")
    );
    transaction
        .query_one_raw(statement(&sql, values))
        .await
        .map(|row| row.is_some())
        .map_err(persistence)
}

fn validate_inputs(
    canonicalization_version: i32,
    recipient_digests: &[VersionedDigest],
    suppression_seconds: i32,
) -> Result<(), ApplicationError> {
    if canonicalization_version <= 0
        || recipient_digests.is_empty()
        || recipient_digests.len() > 16
        || !(30..=600).contains(&suppression_seconds)
    {
        return Err(ApplicationError::InvalidInput);
    }
    let mut versions = BTreeSet::new();
    for digest in recipient_digests {
        if digest.key_version <= 0 || !versions.insert(digest.key_version) {
            return Err(ApplicationError::InvalidInput);
        }
    }
    Ok(())
}

fn statement(sql: &str, values: Vec<sea_orm::Value>) -> Statement {
    Statement::from_sql_and_values(DbBackend::Postgres, sql, values)
}

fn persistence(_: sea_orm::DbErr) -> ApplicationError {
    ApplicationError::Persistence
}
