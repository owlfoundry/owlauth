use std::time::Duration;

use sqlx::{Connection, PgConnection};
use thiserror::Error;
use tokio::time::timeout;

use crate::config::{MigrationMode, PostgresConfig};

#[cfg(test)]
#[path = "migration_contention_tests.rs"]
mod contention_tests;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum SchemaError {
    #[error("PostgreSQL connection failed")]
    Connection,
    #[error("PostgreSQL migration failed")]
    Migration,
    #[error("PostgreSQL migration lock deadline elapsed")]
    LockTimeout,
    #[error("PostgreSQL migration statement deadline elapsed")]
    StatementTimeout,
    #[error("PostgreSQL migration process deadline elapsed")]
    Deadline,
    #[error("PostgreSQL migration history is absent or unreadable")]
    HistoryUnavailable,
    #[error("PostgreSQL migration history contains an unsuccessful migration")]
    DirtyHistory,
    #[error("PostgreSQL migration history differs from this binary")]
    IncompatibleHistory,
}

pub(crate) async fn prepare_schema(config: &PostgresConfig) -> Result<(), SchemaError> {
    match config.migration_mode {
        MigrationMode::Auto => migrate(config).await,
        MigrationMode::Verify => {
            verify_url(config.serving_url.expose(), config.connect_timeout).await
        }
    }
}

async fn connect(url: &str, deadline: Duration) -> Result<PgConnection, SchemaError> {
    timeout(deadline, PgConnection::connect(url))
        .await
        .map_err(|_| SchemaError::Connection)?
        .map_err(|_| SchemaError::Connection)
}

async fn migrate(config: &PostgresConfig) -> Result<(), SchemaError> {
    let mut connection = connect(config.migration_url.expose(), config.connect_timeout).await?;
    configure_migration_session(&mut connection, config).await?;

    let result = run_migrator(&mut connection, &MIGRATOR, config.migration_deadline).await;

    // Closing the dedicated backend is part of migration completion. It releases a cancelled
    // transaction and SQLx's session advisory migration lock before any serving pool is built.
    let close_result = close_migration_connection(connection, config.connect_timeout).await;
    result?;
    close_result?;
    verify_url(config.migration_url.expose(), config.connect_timeout).await
}

async fn close_migration_connection(
    connection: PgConnection,
    deadline: Duration,
) -> Result<(), SchemaError> {
    timeout(deadline, connection.close())
        .await
        .map_err(|_| SchemaError::Connection)?
        .map_err(|_| SchemaError::Migration)
}

async fn configure_migration_session(
    connection: &mut PgConnection,
    config: &PostgresConfig,
) -> Result<(), SchemaError> {
    if let Some(role) = &config.migration_owner_role {
        // `set_config` accepts the validated role as a value rather than SQL syntax.
        sqlx::query("SELECT set_config('role', $1, false)")
            .bind(role)
            .execute(&mut *connection)
            .await
            .map_err(|_| SchemaError::Migration)?;
    }
    configure_migration_timeouts(
        connection,
        config.migration_lock_timeout,
        config.migration_statement_timeout,
    )
    .await
}

async fn configure_migration_timeouts(
    connection: &mut PgConnection,
    lock_timeout: Duration,
    statement_timeout: Duration,
) -> Result<(), SchemaError> {
    for (setting, value) in [
        ("lock_timeout", format!("{}ms", lock_timeout.as_millis())),
        (
            "statement_timeout",
            format!("{}ms", statement_timeout.as_millis()),
        ),
    ] {
        sqlx::query("SELECT set_config($1, $2, false)")
            .bind(setting)
            .bind(value)
            .execute(&mut *connection)
            .await
            .map_err(|_| SchemaError::Migration)?;
    }
    Ok(())
}

async fn run_migrator(
    connection: &mut PgConnection,
    migrator: &sqlx::migrate::Migrator,
    deadline: Duration,
) -> Result<(), SchemaError> {
    match timeout(deadline, migrator.run(connection)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(classify_migration_error(&error)),
        Err(_) => Err(SchemaError::Deadline),
    }
}

fn classify_migration_error(error: &sqlx::migrate::MigrateError) -> SchemaError {
    let code = match error {
        sqlx::migrate::MigrateError::Execute(sqlx::Error::Database(error))
        | sqlx::migrate::MigrateError::ExecuteMigration(sqlx::Error::Database(error), _) => {
            error.code()
        }
        _ => None,
    };
    match code.as_deref() {
        Some("55P03") => SchemaError::LockTimeout,
        Some("57014") => SchemaError::StatementTimeout,
        _ => SchemaError::Migration,
    }
}

pub(crate) async fn verify_url(url: &str, deadline: Duration) -> Result<(), SchemaError> {
    let mut connection = connect(url, deadline).await?;
    let rows = timeout(
        deadline,
        sqlx::query_as::<_, (i64, bool, Vec<u8>)>(
            "SELECT version, success, checksum FROM _sqlx_migrations ORDER BY version",
        )
        .fetch_all(&mut connection),
    )
    .await
    .map_err(|_| SchemaError::HistoryUnavailable)?
    .map_err(|_| SchemaError::HistoryUnavailable)?;

    let expected: Vec<_> = MIGRATOR
        .iter()
        .filter(|migration| !migration.migration_type.is_down_migration())
        .collect();
    if rows.iter().any(|(_, success, _)| !success) {
        return Err(SchemaError::DirtyHistory);
    }
    if rows.len() != expected.len()
        || rows.iter().zip(&expected).any(|(actual, expected)| {
            actual.0 != expected.version || actual.2.as_slice() != expected.checksum.as_ref()
        })
    {
        return Err(SchemaError::IncompatibleHistory);
    }

    connection
        .close()
        .await
        .map_err(|_| SchemaError::HistoryUnavailable)?;
    Ok(())
}
