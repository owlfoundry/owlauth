use std::time::Duration;

use sqlx::{Connection, PgConnection};
use thiserror::Error;
use tokio::time::timeout;

use crate::config::{MigrationMode, PostgresConfig};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum SchemaError {
    #[error("PostgreSQL connection failed")]
    Connection,
    #[error("PostgreSQL migration failed")]
    Migration,
    #[error("PostgreSQL migration lock deadline elapsed")]
    LockTimeout,
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
    let timeout_value = format!("{}ms", config.migration_lock_timeout.as_millis());
    sqlx::query("SELECT set_config('lock_timeout', $1, false)")
        .bind(timeout_value)
        .execute(&mut connection)
        .await
        .map_err(|_| SchemaError::Migration)?;

    if let Some(role) = &config.migration_owner_role {
        // `set_config` accepts the validated role as a value rather than SQL syntax.
        sqlx::query("SELECT set_config('role', $1, false)")
            .bind(role)
            .execute(&mut connection)
            .await
            .map_err(|_| SchemaError::Migration)?;
    }

    let migration_result =
        timeout(config.migration_lock_timeout, MIGRATOR.run(&mut connection)).await;
    match migration_result {
        Ok(Ok(())) => {
            connection
                .close()
                .await
                .map_err(|_| SchemaError::Migration)?;
            Ok(())
        }
        Ok(Err(error)) if is_database_lock_timeout(&error) => Err(SchemaError::LockTimeout),
        Ok(Err(_)) => Err(SchemaError::Migration),
        Err(_) => Err(SchemaError::LockTimeout),
    }
}

fn is_database_lock_timeout(error: &sqlx::migrate::MigrateError) -> bool {
    let database_error = match error {
        sqlx::migrate::MigrateError::Execute(sqlx::Error::Database(error))
        | sqlx::migrate::MigrateError::ExecuteMigration(sqlx::Error::Database(error), _) => {
            Some(error)
        }
        _ => None,
    };
    database_error.is_some_and(|error| error.code().as_deref() == Some("55P03"))
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
        || rows.iter().zip(expected).any(|(actual, expected)| {
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
