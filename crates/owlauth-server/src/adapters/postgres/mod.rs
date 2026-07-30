#[allow(
    dead_code,
    reason = "private entities back the next application services"
)]
mod entity;
#[allow(
    dead_code,
    reason = "the transaction boundary is validated before HTTP mutation exposure"
)]
mod unit_of_work;

use std::time::Duration;

use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use thiserror::Error;

use crate::{
    adapters::migrations::{SchemaError, verify_url},
    config::ServerConfig,
};

#[derive(Debug)]
pub(crate) struct DatabasePools {
    pub runtime: Option<DatabaseConnection>,
    pub control: Option<DatabaseConnection>,
}

impl DatabasePools {
    pub async fn close(self) {
        if let Some(pool) = self.runtime {
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
            )
            .await?,
        )
    } else {
        None
    };

    let control = if config.mode.has_control() {
        match create_pool(
            config.postgres.control_url.expose(),
            config.control.database_max_connections.get(),
            config.postgres.connect_timeout,
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

    Ok(DatabasePools { runtime, control })
}

async fn create_pool(
    url: &str,
    max_connections: u32,
    timeout: Duration,
) -> Result<DatabaseConnection, PoolError> {
    verify_url(url, timeout).await.map_err(map_schema_error)?;

    let mut options = ConnectOptions::new(url.to_owned());
    options
        .max_connections(max_connections)
        .min_connections(0)
        .connect_timeout(timeout)
        .acquire_timeout(timeout)
        .idle_timeout(Duration::from_mins(5))
        .max_lifetime(Duration::from_mins(30))
        .sqlx_logging(false);
    Database::connect(options)
        .await
        .map_err(|_| PoolError::Connection)
}

const fn map_schema_error(_: SchemaError) -> PoolError {
    PoolError::Schema
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, env, time::Duration};

    use crc::{CRC_32_ISO_HDLC, Crc};
    use sea_orm::{EntityTrait, TransactionTrait};
    use sqlx::{Connection, PgConnection};
    use testcontainers::{
        GenericImage, ImageExt,
        core::{IntoContainerPort, WaitFor, wait::LogWaitStrategy},
        runners::AsyncRunner,
    };
    use tokio::time::timeout;
    use uuid::Uuid;

    use super::*;
    use crate::{
        adapters::{
            migrations::{SchemaError, prepare_schema, verify_url},
            postgres::{
                entity::{audit_event, project},
                unit_of_work::{CompleteIdempotency, NewProject, ProjectUnitOfWork},
            },
        },
        config::{MigrationMode, PlaneMode, ServerConfig},
    };

    const POSTGRES_PORT: u16 = 5432;

    fn docker_is_required() -> bool {
        env::var("OWLAUTH_REQUIRE_DOCKER").is_ok_and(|value| value == "1")
    }

    fn unavailable_or_fail(error: impl std::fmt::Display) -> bool {
        assert!(
            !docker_is_required(),
            "PostgreSQL test container is required but failed to start: {error}"
        );
        eprintln!("skipping PostgreSQL adapter test: Docker unavailable: {error}");
        false
    }

    fn server_config(migration_url: &str, runtime_url: &str, control_url: &str) -> ServerConfig {
        let values = BTreeMap::from([
            ("OWLAUTH_MODE".to_owned(), "all".to_owned()),
            (
                "OWLAUTH_CONTROL_API_KEY".to_owned(),
                format!("owl_ctrl_v1_{}", "A".repeat(43)),
            ),
            (
                "OWLAUTH_INSTANCE_ID".to_owned(),
                "test-deployment".to_owned(),
            ),
            (
                "OWLAUTH_MIGRATION_OWNER_ROLE".to_owned(),
                "owlauth_owner".to_owned(),
            ),
            ("OWLAUTH_POSTGRES_URL".to_owned(), runtime_url.to_owned()),
            (
                "OWLAUTH_RUNTIME_POSTGRES_URL".to_owned(),
                runtime_url.to_owned(),
            ),
            (
                "OWLAUTH_CONTROL_POSTGRES_URL".to_owned(),
                control_url.to_owned(),
            ),
            (
                "OWLAUTH_MIGRATION_POSTGRES_URL".to_owned(),
                migration_url.to_owned(),
            ),
            (
                "OWLAUTH_RUNTIME_DATABASE_MAX_CONNECTIONS".to_owned(),
                "1".to_owned(),
            ),
            (
                "OWLAUTH_CONTROL_DATABASE_MAX_CONNECTIONS".to_owned(),
                "1".to_owned(),
            ),
        ]);
        ServerConfig::from_values_for_test(&values).expect("database test config should parse")
    }

    async fn complete_once(database: DatabaseConnection, key: String) -> CompleteIdempotency {
        let unit = ProjectUnitOfWork::begin(&database)
            .await
            .expect("claim Unit of Work should begin");
        let outcome = unit
            .complete_idempotency_once(&key, serde_json::json!({"accepted": true}))
            .await
            .expect("conditional completion should execute");
        unit.commit().await.expect("claim should commit");
        outcome
    }

    #[test]
    fn plane_modes_select_separate_pool_sets() {
        assert!(PlaneMode::Runtime.has_runtime());
        assert!(!PlaneMode::Runtime.has_control());
        assert!(!PlaneMode::Control.has_runtime());
        assert!(PlaneMode::Control.has_control());
        assert!(PlaneMode::All.has_runtime());
        assert!(PlaneMode::All.has_control());
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one container covers the related PostgreSQL startup and transaction invariants"
    )]
    #[tokio::test]
    async fn migrations_pools_unit_of_work_and_one_use_mutation_are_real() {
        let wait = WaitFor::log(LogWaitStrategy::stderr(
            "database system is ready to accept connections",
        ));
        let container = match GenericImage::new("postgres", "17-bookworm")
            .with_exposed_port(POSTGRES_PORT.tcp())
            .with_wait_for(wait)
            .with_env_var("POSTGRES_DB", "owlauth_test")
            .with_env_var("POSTGRES_USER", "owlauth")
            .with_env_var("POSTGRES_PASSWORD", "owlauth_test")
            .start()
            .await
        {
            Ok(container) => container,
            Err(error) => {
                if !unavailable_or_fail(error) {
                    return;
                }
                unreachable!();
            }
        };
        let host = container
            .get_host()
            .await
            .expect("host should be available");
        let port = container
            .get_host_port_ipv4(POSTGRES_PORT)
            .await
            .expect("mapped port should be available");
        let url = format!("postgres://owlauth:owlauth_test@{host}:{port}/owlauth_test");
        let mut owner_setup = PgConnection::connect(&url)
            .await
            .expect("owner setup connection should open");
        for statement in [
            "CREATE ROLE owlauth_owner NOLOGIN",
            "CREATE ROLE owlauth_runtime LOGIN PASSWORD 'runtime_test'",
            "CREATE ROLE owlauth_control LOGIN PASSWORD 'control_test'",
            "GRANT owlauth_owner TO owlauth",
            "ALTER SCHEMA public OWNER TO owlauth_owner",
            "GRANT USAGE ON SCHEMA public TO owlauth_runtime, owlauth_control",
            "ALTER DEFAULT PRIVILEGES FOR ROLE owlauth_owner IN SCHEMA public \
             GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO owlauth_runtime, owlauth_control",
            "ALTER DEFAULT PRIVILEGES FOR ROLE owlauth_owner IN SCHEMA public \
             GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO owlauth_runtime, owlauth_control",
        ] {
            sqlx::query(statement)
                .execute(&mut owner_setup)
                .await
                .expect("owner and serving-role setup should succeed");
        }
        owner_setup
            .close()
            .await
            .expect("owner setup connection should close");

        let runtime_url =
            format!("postgres://owlauth_runtime:runtime_test@{host}:{port}/owlauth_test");
        let control_url =
            format!("postgres://owlauth_control:control_test@{host}:{port}/owlauth_test");
        let mut config = server_config(&url, &runtime_url, &control_url);

        config.postgres.migration_mode = MigrationMode::Verify;
        assert_eq!(
            prepare_schema(&config.postgres)
                .await
                .expect_err("verify must not create absent history"),
            SchemaError::HistoryUnavailable
        );

        config.postgres.migration_mode = MigrationMode::Auto;
        config.postgres.migration_lock_timeout = Duration::from_millis(100);
        let mut lock_connection = PgConnection::connect(&url)
            .await
            .expect("lock connection should open");
        let checksum = Crc::<u32>::new(&CRC_32_ISO_HDLC).checksum(b"owlauth_test");
        let lock_id = 0x3d32_ad9e_i64 * i64::from(checksum);
        sqlx::query("SELECT pg_advisory_lock($1)")
            .bind(lock_id)
            .execute(&mut lock_connection)
            .await
            .expect("migration advisory lock should be held");
        assert_eq!(
            prepare_schema(&config.postgres)
                .await
                .expect_err("bounded migration lock wait must fail"),
            SchemaError::LockTimeout
        );
        lock_connection
            .close()
            .await
            .expect("lock connection should close and release its lock");

        config.postgres.migration_lock_timeout = Duration::from_secs(5);
        let (first, second) = tokio::join!(
            prepare_schema(&config.postgres),
            prepare_schema(&config.postgres)
        );
        first.expect("first concurrent migrator should succeed");
        second.expect("second concurrent migrator should serialize and succeed");

        let mut ownership_connection = PgConnection::connect(&url)
            .await
            .expect("ownership query connection should open");
        let schema_owner: String = sqlx::query_scalar(
            "SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = 'public'",
        )
        .fetch_one(&mut ownership_connection)
        .await
        .expect("schema owner should be queryable");
        assert_eq!(schema_owner, "owlauth_owner");
        let table_owners: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT tableowner FROM pg_tables \
             WHERE schemaname = 'public' AND tablename IN (\
                 '_sqlx_migrations', 'projects', 'applications', \
                 'control_idempotency_records', 'audit_events'\
             )",
        )
        .fetch_all(&mut ownership_connection)
        .await
        .expect("migration-created table owners should be queryable");
        assert_eq!(table_owners, vec!["owlauth_owner".to_owned()]);
        sqlx::query(
            "REVOKE INSERT, UPDATE, DELETE ON _sqlx_migrations \
             FROM owlauth_runtime, owlauth_control",
        )
        .execute(&mut ownership_connection)
        .await
        .expect("serving roles should retain read-only migration history access");
        let history_privileges: (bool, bool) = sqlx::query_as(
            "SELECT \
                 has_table_privilege('owlauth_runtime', '_sqlx_migrations', 'SELECT'), \
                 has_table_privilege('owlauth_runtime', '_sqlx_migrations', 'INSERT,UPDATE,DELETE')",
        )
        .fetch_one(&mut ownership_connection)
        .await
        .expect("serving history grants should be queryable");
        assert_eq!(history_privileges, (true, false));
        ownership_connection
            .close()
            .await
            .expect("ownership query connection should close");

        verify_url(&url, Duration::from_secs(5))
            .await
            .expect("exact serving history should verify without DDL");

        let pools = create_pools(&config)
            .await
            .expect("separate serving pools should open");
        let runtime = pools.runtime.as_ref().expect("Runtime pool should exist");
        let control = pools.control.as_ref().expect("Control pool should exist");
        let runtime_transaction = runtime.begin().await.expect("Runtime slot should acquire");
        let control_transaction = timeout(Duration::from_millis(500), control.begin())
            .await
            .expect("Control must not wait for the exhausted Runtime pool")
            .expect("Control slot should acquire");
        assert!(
            timeout(Duration::from_millis(100), runtime.begin())
                .await
                .is_err()
        );
        runtime_transaction
            .rollback()
            .await
            .expect("Runtime transaction should roll back");
        control_transaction
            .rollback()
            .await
            .expect("Control transaction should roll back");

        let rolled_back_project = Uuid::new_v4();
        let unit = ProjectUnitOfWork::begin(control)
            .await
            .expect("Unit of Work should begin");
        unit.insert_project_with_audit(
            NewProject {
                id: rolled_back_project,
                public_id: "project_rollback".to_owned(),
                belongs_to: None,
            },
            Uuid::new_v4(),
        )
        .await
        .expect("representative cross-repository mutation should stage");
        unit.rollback()
            .await
            .expect("Unit of Work should roll back");
        assert!(
            project::Entity::find_by_id(rolled_back_project)
                .one(control)
                .await
                .expect("rollback query should work")
                .is_none()
        );

        let project_id = Uuid::new_v4();
        let key = "create-project-once".to_owned();
        let unit = ProjectUnitOfWork::begin(control)
            .await
            .expect("Unit of Work should begin");
        unit.insert_project_with_audit(
            NewProject {
                id: project_id,
                public_id: "project_committed".to_owned(),
                belongs_to: Some("external-owner".to_owned()),
            },
            Uuid::new_v4(),
        )
        .await
        .expect("Project and audit should stage");
        unit.insert_pending_idempotency(key.clone(), project_id, vec![7; 32])
            .await
            .expect("one-use record should stage");
        unit.commit()
            .await
            .expect("Unit of Work should commit atomically");
        assert_eq!(
            audit_event::Entity::find()
                .all(control)
                .await
                .expect("audit query should work")
                .len(),
            1
        );

        let (left, right) = tokio::join!(
            complete_once(control.clone(), key.clone()),
            complete_once(control.clone(), key)
        );
        assert!(matches!(
            (left, right),
            (
                CompleteIdempotency::Completed,
                CompleteIdempotency::AlreadyCompleted
            ) | (
                CompleteIdempotency::AlreadyCompleted,
                CompleteIdempotency::Completed
            )
        ));

        pools.close().await;
    }
}
