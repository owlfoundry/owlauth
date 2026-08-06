#[cfg(test)]
mod application_sync_tests;
mod audit;
pub(crate) mod authentication;
pub(crate) mod client_api;
pub(crate) mod client_key;
#[cfg(test)]
mod client_key_migration_tests;
pub(crate) mod client_readiness;
pub(crate) mod control_lifecycle;
pub(crate) mod custody;
pub(crate) mod custody_import;
pub(crate) mod email;
pub(crate) mod email_control;
#[cfg(test)]
mod email_tests;
pub(crate) mod entity;
#[cfg(test)]
mod identity_lifecycle_migration_tests;
pub(crate) mod identity_mutation;
#[cfg(test)]
mod identity_mutation_test_support;
#[cfg(test)]
mod identity_mutation_tests;
pub(crate) mod managed_connection;
pub(crate) mod managed_reauthorization;
pub(crate) mod projection;
pub(crate) mod projection_expansion;
pub(crate) mod provider_callback;
pub(crate) mod provider_egress;
mod provider_row;
pub(crate) mod provisioning;
pub(crate) mod readiness;
pub(crate) mod runtime_authority;
mod runtime_incarnation;
pub(crate) mod session_authority;
#[cfg(test)]
mod session_authority_tests;
#[cfg(test)]
mod unit_of_work;
pub(crate) mod webhook;

use std::time::Duration;

use sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement,
};
use thiserror::Error;

use crate::{
    adapters::migrations::{SchemaError, verify_url},
    config::ServerConfig,
};

#[derive(Debug)]
pub(crate) struct DatabasePools {
    pub runtime: Option<DatabaseConnection>,
    pub client: Option<DatabaseConnection>,
    pub control: Option<DatabaseConnection>,
}

impl DatabasePools {
    pub async fn close(self) {
        if let Some(pool) = self.runtime {
            let _ = pool.close().await;
        }
        if let Some(pool) = self.client {
            let _ = pool.close().await;
        }
        if let Some(pool) = self.control {
            let _ = pool.close().await;
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum PoolError {
    #[error("a serving PostgreSQL pool has incompatible migration history")]
    Schema,
    #[error("a serving PostgreSQL pool could not be created")]
    Connection,
}

pub(crate) async fn create_pools(config: &ServerConfig) -> Result<DatabasePools, PoolError> {
    let runtime = if config.mode.has_runtime() {
        Some(
            create_pool(
                config.postgres.runtime_url.expose(),
                config.runtime.database_max_connections.get(),
                config.postgres.connect_timeout,
                config.postgres.database_lock_timeout,
            )
            .await?,
        )
    } else {
        None
    };

    let client = if config.mode.has_client() {
        match create_pool(
            config.postgres.client_url.expose(),
            config.client.database_max_connections.get(),
            config.postgres.connect_timeout,
            config.postgres.database_lock_timeout,
        )
        .await
        {
            Ok(pool) => Some(pool),
            Err(error) => {
                if let Some(runtime) = runtime {
                    let _ = runtime.close().await;
                }
                return Err(error);
            }
        }
    } else {
        None
    };

    let control = if config.mode.has_control() {
        match create_pool(
            config.postgres.control_url.expose(),
            config.control.database_max_connections.get(),
            config.postgres.connect_timeout,
            config.postgres.database_lock_timeout,
        )
        .await
        {
            Ok(pool) => Some(pool),
            Err(error) => {
                if let Some(runtime) = runtime {
                    let _ = runtime.close().await;
                }
                if let Some(client) = client {
                    let _ = client.close().await;
                }
                return Err(error);
            }
        }
    } else {
        None
    };

    Ok(DatabasePools {
        runtime,
        client,
        control,
    })
}

async fn create_pool(
    url: &str,
    max_connections: u32,
    timeout: Duration,
    lock_timeout: Duration,
) -> Result<DatabaseConnection, PoolError> {
    verify_url(url, timeout).await.map_err(map_schema_error)?;

    let lock_timeout_value = lock_timeout.as_millis().to_string();
    let mut options = ConnectOptions::new(url.to_owned());
    options
        .max_connections(max_connections)
        .min_connections(0)
        .connect_timeout(timeout)
        .acquire_timeout(timeout)
        .idle_timeout(Duration::from_mins(5))
        .max_lifetime(Duration::from_mins(30))
        .map_sqlx_postgres_opts(move |postgres| {
            postgres.options([("lock_timeout", lock_timeout_value.clone())])
        })
        .sqlx_logging(false);
    let pool = Database::connect(options)
        .await
        .map_err(|_| PoolError::Connection)?;
    let configured = pool
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT current_setting('lock_timeout')::interval = $1::interval AS configured",
            [format!("{}ms", lock_timeout.as_millis()).into()],
        ))
        .await
        .map_err(|_| PoolError::Connection)?
        .ok_or(PoolError::Connection)?
        .try_get::<bool>("", "configured")
        .map_err(|_| PoolError::Connection)?;
    if !configured {
        let _ = pool.close().await;
        return Err(PoolError::Connection);
    }
    Ok(pool)
}

const fn map_schema_error(_: SchemaError) -> PoolError {
    PoolError::Schema
}

#[cfg(test)]
mod capability_journeys;
