//! Explicit, bounded `PostgreSQL` retention maintenance for operator-run jobs.

use std::{fmt, time::Duration};

use serde::Serialize;
use sqlx::{PgPool, postgres::PgPoolOptions};
use thiserror::Error;

use crate::adapters::migrations::verify_url;

const DEFAULT_BATCH_SIZE: u32 = 1_000;
const MAX_BATCH_SIZE: u32 = 10_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PruneOptions {
    pub batch_size: u32,
}

impl Default for PruneOptions {
    fn default() -> Self {
        Self {
            batch_size: DEFAULT_BATCH_SIZE,
        }
    }
}

impl PruneOptions {
    fn validate(self) -> Result<Self, MaintenanceError> {
        if !(1..=MAX_BATCH_SIZE).contains(&self.batch_size) {
            return Err(MaintenanceError::InvalidBatchSize);
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct PruneReport {
    pub login_aggregates: u64,
    pub browser_logout_interactions: u64,
    pub refresh_token_generations: u64,
    pub application_session_aggregates: u64,
    pub browser_session_aggregates: u64,
    pub smtp_test_operations: u64,
    pub webhook_records: u64,
    pub total: u64,
}

impl PruneReport {
    fn finish(mut self) -> Result<Self, MaintenanceError> {
        self.total = [
            self.login_aggregates,
            self.browser_logout_interactions,
            self.refresh_token_generations,
            self.application_session_aggregates,
            self.browser_session_aggregates,
            self.smtp_test_operations,
            self.webhook_records,
        ]
        .into_iter()
        .try_fold(0_u64, u64::checked_add)
        .ok_or(MaintenanceError::CountOverflow)?;
        Ok(self)
    }
}

#[derive(Error)]
pub enum MaintenanceError {
    #[error("maintenance batch size must be between 1 and 10000")]
    InvalidBatchSize,
    #[error("database schema verification failed")]
    SchemaVerification,
    #[error("database maintenance failed")]
    Database(#[source] sqlx::Error),
    #[error("database maintenance count overflowed")]
    CountOverflow,
}

impl fmt::Debug for MaintenanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl From<sqlx::Error> for MaintenanceError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

/// Prunes one bounded batch from every safe retention class.
///
/// This command intentionally excludes append-only audit/key history, durable-resource
/// idempotency tombstones, merge authority, and live durable resources. All eligibility cutoffs
/// are authored and evaluated by `PostgreSQL`. Running it repeatedly is safe.
///
/// # Errors
///
/// Returns an error when the batch size is invalid, schema verification fails, a database
/// operation fails, or a deleted-row count cannot be represented safely.
pub async fn prune(
    database_url: &str,
    options: PruneOptions,
) -> Result<PruneReport, MaintenanceError> {
    let options = options.validate()?;
    verify_url(database_url, Duration::from_secs(5))
        .await
        .map_err(|_| MaintenanceError::SchemaVerification)?;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect(database_url)
        .await
        .map_err(MaintenanceError::Database)?;
    let result = prune_pool(&pool, options).await;
    pool.close().await;
    result
}

async fn prune_pool(pool: &PgPool, options: PruneOptions) -> Result<PruneReport, MaintenanceError> {
    let batch_size = i64::from(options.batch_size);
    let report = PruneReport {
        login_aggregates: delete_count(pool, PRUNE_LOGIN_AGGREGATES, batch_size).await?,
        browser_logout_interactions: delete_count(
            pool,
            PRUNE_BROWSER_LOGOUT_INTERACTIONS,
            batch_size,
        )
        .await?,
        refresh_token_generations: delete_count(pool, PRUNE_REFRESH_TOKEN_GENERATIONS, batch_size)
            .await?,
        application_session_aggregates: delete_count(
            pool,
            PRUNE_APPLICATION_SESSION_AGGREGATES,
            batch_size,
        )
        .await?,
        browser_session_aggregates: delete_count(
            pool,
            PRUNE_BROWSER_SESSION_AGGREGATES,
            batch_size,
        )
        .await?,
        smtp_test_operations: delete_count(pool, PRUNE_SMTP_TEST_OPERATIONS, batch_size).await?,
        webhook_records: prune_webhook_records(pool, batch_size).await?,
        ..PruneReport::default()
    };
    report.finish()
}

async fn begin_bounded_transaction(
    pool: &PgPool,
) -> Result<sqlx::Transaction<'_, sqlx::Postgres>, MaintenanceError> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET LOCAL lock_timeout = '250ms'")
        .execute(&mut *transaction)
        .await?;
    sqlx::query("SET LOCAL statement_timeout = '5s'")
        .execute(&mut *transaction)
        .await?;
    Ok(transaction)
}

async fn delete_count(
    pool: &PgPool,
    sql: &'static str,
    batch_size: i64,
) -> Result<u64, MaintenanceError> {
    let mut transaction = begin_bounded_transaction(pool).await?;
    let deleted = sqlx::query_scalar::<_, i64>(sql)
        .bind(batch_size)
        .fetch_one(&mut *transaction)
        .await?;
    transaction.commit().await?;
    u64::try_from(deleted).map_err(|_| MaintenanceError::CountOverflow)
}

const PRUNE_LOGIN_AGGREGATES: &str = r"
WITH candidates AS (
    SELECT id
      FROM login_transactions
     WHERE expires_at <= transaction_timestamp() - interval '24 hours'
     ORDER BY expires_at,id
     LIMIT $1 FOR UPDATE SKIP LOCKED
), deleted AS (
    DELETE FROM login_transactions login
     USING candidates
     WHERE login.id=candidates.id
     RETURNING login.id
)
SELECT COUNT(*)::bigint FROM deleted
";

const PRUNE_BROWSER_LOGOUT_INTERACTIONS: &str = r"
WITH candidates AS (
    SELECT id
      FROM project_browser_logout_interactions
     WHERE expires_at <= transaction_timestamp() - interval '24 hours'
     ORDER BY expires_at,id
     LIMIT $1 FOR UPDATE SKIP LOCKED
), deleted AS (
    DELETE FROM project_browser_logout_interactions interaction
     USING candidates
     WHERE interaction.id=candidates.id
     RETURNING interaction.id
)
SELECT COUNT(*)::bigint FROM deleted
";

const PRUNE_REFRESH_TOKEN_GENERATIONS: &str = r"
WITH candidates AS (
    SELECT generation.id
      FROM refresh_token_generations generation
      JOIN refresh_families family ON family.id=generation.family_id
      JOIN application_sessions session ON session.id=family.application_session_id
     WHERE generation.retain_until <= transaction_timestamp()
       AND session.absolute_expires_at <= transaction_timestamp() - interval '24 hours'
       AND NOT EXISTS (
           SELECT 1 FROM project_browser_logout_interactions interaction
            WHERE interaction.application_session_id=session.id)
     ORDER BY generation.retain_until,generation.id
     LIMIT $1 FOR UPDATE OF generation SKIP LOCKED
), deleted AS (
    DELETE FROM refresh_token_generations generation
     USING candidates
     WHERE generation.id=candidates.id
     RETURNING generation.id
)
SELECT COUNT(*)::bigint FROM deleted
";

const PRUNE_APPLICATION_SESSION_AGGREGATES: &str = r"
WITH candidates AS (
    SELECT session.id
      FROM application_sessions session
     WHERE session.absolute_expires_at <= transaction_timestamp() - interval '24 hours'
       AND NOT EXISTS (
           SELECT 1 FROM project_browser_logout_interactions interaction
            WHERE interaction.application_session_id=session.id)
       AND NOT EXISTS (
           SELECT 1
             FROM refresh_families family
             JOIN refresh_token_generations generation ON generation.family_id=family.id
            WHERE family.application_session_id=session.id)
     ORDER BY session.absolute_expires_at,session.id
     LIMIT $1 FOR UPDATE OF session SKIP LOCKED
), deleted AS (
    DELETE FROM application_sessions session
     USING candidates
     WHERE session.id=candidates.id
     RETURNING session.id
)
SELECT COUNT(*)::bigint FROM deleted
";

const PRUNE_BROWSER_SESSION_AGGREGATES: &str = r"
WITH candidates AS (
    SELECT session.id
      FROM project_browser_sessions session
     WHERE session.absolute_expires_at <= transaction_timestamp() - interval '24 hours'
       AND NOT EXISTS (
           SELECT 1 FROM application_sessions application_session
            WHERE application_session.browser_session_id=session.id)
       AND NOT EXISTS (
           SELECT 1 FROM project_browser_logout_interactions interaction
            WHERE interaction.browser_session_id=session.id)
       AND NOT EXISTS (
           SELECT 1 FROM handoff_tickets ticket
            WHERE ticket.browser_session_id=session.id)
     ORDER BY session.absolute_expires_at,session.id
     LIMIT $1 FOR UPDATE OF session SKIP LOCKED
), deleted AS (
    DELETE FROM project_browser_sessions session
     USING candidates
     WHERE session.id=candidates.id
     RETURNING session.id
)
SELECT COUNT(*)::bigint FROM deleted
";

const PRUNE_SMTP_TEST_OPERATIONS: &str = r"
WITH candidates AS (
    SELECT test.id,test.recipient_material_id
      FROM project_smtp_test_operations test
     WHERE test.state IN ('delivered','failed','ambiguous')
       AND test.recipient_erased_at IS NOT NULL
       AND test.completed_at <= transaction_timestamp() - interval '24 hours'
     ORDER BY test.completed_at,test.id
     LIMIT $1 FOR UPDATE OF test SKIP LOCKED
), deleted_operations AS (
    DELETE FROM project_smtp_test_operations test
     USING candidates
     WHERE test.id=candidates.id
     RETURNING test.recipient_material_id
), deleted_materials AS (
    DELETE FROM protected_materials material
     USING deleted_operations operation
     WHERE material.id=operation.recipient_material_id
       AND material.owner_kind='smtp_test_recipient'
       AND material.state='erased'
     RETURNING material.id
)
SELECT COUNT(*)::bigint FROM deleted_operations
";

async fn prune_webhook_records(pool: &PgPool, batch_size: i64) -> Result<u64, MaintenanceError> {
    let mut transaction = begin_bounded_transaction(pool).await?;
    let mut affected = 0_u64;

    for sql in [
        CANCEL_EXPIRED_WEBHOOK_DELIVERIES,
        PRUNE_WEBHOOK_DELIVERY_ATTEMPTS,
        PRUNE_WEBHOOK_DELIVERIES,
        PRUNE_APPLICATION_USER_EVENTS,
    ] {
        let remaining = batch_size
            .saturating_sub(i64::try_from(affected).map_err(|_| MaintenanceError::CountOverflow)?);
        if remaining == 0 {
            break;
        }
        let rows = sqlx::query_scalar::<_, i64>(sql)
            .bind(remaining)
            .fetch_one(&mut *transaction)
            .await?;
        affected = affected
            .checked_add(u64::try_from(rows).map_err(|_| MaintenanceError::CountOverflow)?)
            .ok_or(MaintenanceError::CountOverflow)?;
    }

    transaction.commit().await?;
    Ok(affected)
}

const CANCEL_EXPIRED_WEBHOOK_DELIVERIES: &str = r"
WITH candidates AS (
    SELECT delivery.id
      FROM webhook_deliveries delivery
      JOIN application_user_events event ON event.id=delivery.event_id
     WHERE delivery.state='pending'
       AND event.retain_until <= transaction_timestamp()
     ORDER BY event.retain_until,delivery.created_at,delivery.id
     LIMIT $1 FOR UPDATE OF delivery SKIP LOCKED
), updated AS (
    UPDATE webhook_deliveries delivery
       SET state='cancelled',terminal_at=transaction_timestamp(),
           updated_at=transaction_timestamp()
      FROM candidates
     WHERE delivery.id=candidates.id
     RETURNING delivery.id
)
SELECT COUNT(*)::bigint FROM updated
";

const PRUNE_WEBHOOK_DELIVERY_ATTEMPTS: &str = r"
WITH candidates AS (
    SELECT attempt.ctid
      FROM webhook_delivery_attempts attempt
      JOIN webhook_deliveries delivery ON delivery.id=attempt.delivery_id
      JOIN application_user_events event ON event.id=delivery.event_id
     WHERE delivery.state IN ('delivered','terminal','cancelled')
       AND event.retain_until <= transaction_timestamp()
     ORDER BY event.retain_until,attempt.delivery_id,attempt.attempt_number
     LIMIT $1 FOR UPDATE OF attempt SKIP LOCKED
), deleted AS (
    DELETE FROM webhook_delivery_attempts attempt
     USING candidates
     WHERE attempt.ctid=candidates.ctid
     RETURNING attempt.ctid
)
SELECT COUNT(*)::bigint FROM deleted
";

const PRUNE_WEBHOOK_DELIVERIES: &str = r"
WITH candidates AS (
    SELECT delivery.id
      FROM webhook_deliveries delivery
      JOIN application_user_events event ON event.id=delivery.event_id
     WHERE delivery.state IN ('delivered','terminal','cancelled')
       AND event.retain_until <= transaction_timestamp()
       AND NOT EXISTS (
           SELECT 1 FROM webhook_delivery_attempts attempt
            WHERE attempt.delivery_id=delivery.id)
       AND NOT EXISTS (
           SELECT 1 FROM webhook_deliveries replay
            WHERE replay.replay_of_delivery_id=delivery.id)
     ORDER BY event.retain_until,delivery.replay_sequence DESC,delivery.id
     LIMIT $1 FOR UPDATE OF delivery SKIP LOCKED
), deleted AS (
    DELETE FROM webhook_deliveries delivery
     USING candidates
     WHERE delivery.id=candidates.id
     RETURNING delivery.id
)
SELECT COUNT(*)::bigint FROM deleted
";

const PRUNE_APPLICATION_USER_EVENTS: &str = r"
WITH candidates AS (
    SELECT event.id
      FROM application_user_events event
     WHERE event.retain_until <= transaction_timestamp()
       AND NOT EXISTS (
           SELECT 1 FROM webhook_deliveries delivery
            WHERE delivery.event_id=event.id)
     ORDER BY event.retain_until,event.id
     LIMIT $1 FOR UPDATE OF event SKIP LOCKED
), deleted AS (
    DELETE FROM application_user_events event
     USING candidates
     WHERE event.id=candidates.id
     RETURNING event.id
)
SELECT COUNT(*)::bigint FROM deleted
";

#[cfg(test)]
mod tests {
    use super::{MaintenanceError, PruneOptions, PruneReport};

    #[test]
    fn options_reject_zero_and_unbounded_batches() {
        assert!(matches!(
            PruneOptions { batch_size: 0 }.validate(),
            Err(MaintenanceError::InvalidBatchSize)
        ));
        assert!(matches!(
            PruneOptions { batch_size: 10_001 }.validate(),
            Err(MaintenanceError::InvalidBatchSize)
        ));
        assert_eq!(
            PruneOptions { batch_size: 10_000 }
                .validate()
                .expect("maximum batch is valid")
                .batch_size,
            10_000
        );
    }

    #[test]
    fn report_total_covers_every_cleanup_class() {
        let report = PruneReport {
            login_aggregates: 1,
            browser_logout_interactions: 2,
            refresh_token_generations: 3,
            application_session_aggregates: 4,
            browser_session_aggregates: 5,
            smtp_test_operations: 6,
            webhook_records: 7,
            total: 0,
        }
        .finish()
        .expect("small report sums exactly");
        assert_eq!(report.total, 28);
    }

    #[test]
    fn debug_output_redacts_database_diagnostics() {
        let error = MaintenanceError::Database(sqlx::Error::Io(std::io::Error::other(
            "sensitive database diagnostic",
        )));
        assert_eq!(format!("{error:?}"), "database maintenance failed");
        let boxed: Box<dyn std::error::Error + Send + Sync> = Box::new(error);
        assert_eq!(format!("{boxed:?}"), "database maintenance failed");
    }
}

#[cfg(test)]
#[path = "maintenance_integration_tests.rs"]
mod integration_tests;
