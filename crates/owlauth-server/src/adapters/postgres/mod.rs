mod audit;
#[allow(
    dead_code,
    reason = "the Runtime composition follows the HTTP-free authentication repository slice"
)]
pub(crate) mod authentication;
pub(crate) mod control_lifecycle;
pub(crate) mod entity;
pub(crate) mod provisioning;
pub(crate) mod readiness;
pub(crate) mod runtime_authority;
#[allow(
    dead_code,
    reason = "the Runtime composition follows the HTTP-free session authority slice"
)]
pub(crate) mod session_authority;
#[cfg(test)]
mod session_authority_tests;
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
    use std::{
        collections::BTreeMap,
        env,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use async_trait::async_trait;
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode, header},
    };
    use crc::{CRC_32_ISO_HDLC, Crc};
    use sea_orm::{
        ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter,
        QuerySelect, TransactionTrait,
    };
    use sqlx::{Connection, PgConnection};
    use testcontainers::{
        GenericImage, ImageExt,
        core::{IntoContainerPort, WaitFor, wait::LogWaitStrategy},
        runners::AsyncRunner,
    };
    use tokio::time::timeout;
    use tower::ServiceExt;
    use uuid::Uuid;

    use super::*;
    use crate::{
        adapters::{
            migrations::{SchemaError, prepare_schema, verify_url},
            postgres::{
                entity::{
                    application, application_provider_assignment, application_publishable_key,
                    audit_event, control_idempotency_record, key_provisioning_operation,
                    key_state_event, project, project_signing_key, provider_configuration,
                    provider_secret_operation, runtime_publication_lease,
                },
                provisioning::PostgresProvisioningAdapter,
                readiness::PostgresReadinessAdapter,
                unit_of_work::ProjectUnitOfWork,
            },
            software_store::EncryptedFileStore,
            system::{Sha256RequestDigester, SystemClock, SystemEntropy},
        },
        application::{
            ApplicationError, CompleteIdempotency, ConfigurationSecretStore, CreateApplication,
            CreateProject, CreateProvider, NewProject, PrepareProvider, PreparedProvider,
            PreparedSigningKey, ProviderProvisioningPort, ProvisioningInfrastructure,
            ProvisioningOperationState, ProvisioningService, ReadinessService,
            ReplaceApplicationConfiguration, SignerStore, SigningKeyProvisioningPort,
            UpdateProject, UpdateProjectPolicy,
        },
        config::{MigrationMode, PlaneMode, ServerConfig},
        domain::ApplicationType,
        http::build_routers,
    };

    const POSTGRES_PORT: u16 = 5432;

    async fn bump_project_metadata_revision(
        database: &DatabaseConnection,
        project_id: Uuid,
    ) -> Result<(), ApplicationError> {
        let project = project::Entity::find_by_id(project_id)
            .one(database)
            .await
            .map_err(|_| ApplicationError::Persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let next_revision = project.metadata_revision + 1;
        let mut active = project.into_active_model();
        active.metadata_revision = Set(next_revision);
        active
            .update(database)
            .await
            .map(|_| ())
            .map_err(|_| ApplicationError::Persistence)
    }

    #[derive(Clone)]
    struct RevisionBumpingSignerStore {
        inner: EncryptedFileStore,
        database: DatabaseConnection,
        project_id: Uuid,
        bumped: Arc<AtomicBool>,
        put_calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl SignerStore for RevisionBumpingSignerStore {
        async fn put_if_absent(
            &self,
            alias: String,
            seed: zeroize::Zeroizing<[u8; 32]>,
        ) -> Result<(), ApplicationError> {
            self.put_calls.fetch_add(1, Ordering::SeqCst);
            SignerStore::put_if_absent(&self.inner, alias, seed).await?;
            if !self.bumped.swap(true, Ordering::SeqCst) {
                bump_project_metadata_revision(&self.database, self.project_id).await?;
            }
            Ok(())
        }

        async fn public_jwk(
            &self,
            alias: String,
            kid: &str,
        ) -> Result<serde_json::Value, ApplicationError> {
            SignerStore::public_jwk(&self.inner, alias, kid).await
        }

        async fn verify(
            &self,
            alias: String,
            kid: &str,
            public_jwk: &serde_json::Value,
        ) -> Result<(), ApplicationError> {
            SignerStore::verify(&self.inner, alias, kid, public_jwk).await
        }
    }

    #[derive(Clone)]
    struct RevisionBumpingSecretStore {
        inner: EncryptedFileStore,
        database: DatabaseConnection,
        project_id: Uuid,
        bumped: Arc<AtomicBool>,
        put_calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl ConfigurationSecretStore for RevisionBumpingSecretStore {
        fn request_fingerprint(&self, value: &[u8]) -> [u8; 32] {
            ConfigurationSecretStore::request_fingerprint(&self.inner, value)
        }

        async fn put_if_absent(
            &self,
            alias: String,
            value: zeroize::Zeroizing<Vec<u8>>,
        ) -> Result<(), ApplicationError> {
            self.put_calls.fetch_add(1, Ordering::SeqCst);
            ConfigurationSecretStore::put_if_absent(&self.inner, alias, value).await?;
            if !self.bumped.swap(true, Ordering::SeqCst) {
                bump_project_metadata_revision(&self.database, self.project_id).await?;
            }
            Ok(())
        }

        async fn ensure_readable(&self, alias: String) -> Result<(), ApplicationError> {
            ConfigurationSecretStore::ensure_readable(&self.inner, alias).await
        }
    }

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
                "OWLAUTH_SIGNER_STORE_ROOT".to_owned(),
                "/tmp/owlauth-postgres-test-signers".to_owned(),
            ),
            (
                "OWLAUTH_SIGNER_STORE_KEY".to_owned(),
                "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE".to_owned(),
            ),
            (
                "OWLAUTH_CONFIGURATION_SECRET_STORE_ROOT".to_owned(),
                "/tmp/owlauth-postgres-test-secrets".to_owned(),
            ),
            (
                "OWLAUTH_CONFIGURATION_SECRET_STORE_KEY".to_owned(),
                "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI".to_owned(),
            ),
            (
                "OWLAUTH_MIGRATION_OWNER_ROLE".to_owned(),
                "owlauth_owner".to_owned(),
            ),
            ("OWLAUTH_POSTGRES_URL".to_owned(), runtime_url.to_owned()),
            (
                "OWLAUTH_RUNTIME_PROCESS_ID".to_owned(),
                "runtime-test-process".to_owned(),
            ),
            ("OWLAUTH_RUNTIME_KEY_VERSION".to_owned(), "1".to_owned()),
            (
                "OWLAUTH_RUNTIME_DIGEST_KEY".to_owned(),
                "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM".to_owned(),
            ),
            (
                "OWLAUTH_RUNTIME_PROTECTION_KEY".to_owned(),
                "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ".to_owned(),
            ),
            (
                "OWLAUTH_PROVIDER_ALLOWED_ORIGINS".to_owned(),
                "https://accounts.example/".to_owned(),
            ),
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
                display_name: "Rollback project".to_owned(),
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
                display_name: "Committed project".to_owned(),
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

        let store_root =
            env::temp_dir().join(format!("owlauth-provisioning-test-{}", Uuid::new_v4()));
        let signer_root = store_root.join("signers");
        let secret_root = store_root.join("secrets");
        let signer_store = EncryptedFileStore::new(signer_root.clone(), [11; 32]).unwrap();
        let secret_store = EncryptedFileStore::new(secret_root, [12; 32]).unwrap();
        let provisioning = ProvisioningService::new(
            Arc::new(PostgresProvisioningAdapter::new(
                control.clone(),
                url::Url::parse("https://identity.example/runtime/").unwrap(),
                vec![
                    "runtime-test-process".to_owned(),
                    "runtime-secondary-process".to_owned(),
                ],
                Duration::from_millis(10),
                Duration::from_secs(1),
            )),
            ProvisioningInfrastructure::new(
                signer_store.clone(),
                secret_store.clone(),
                SystemClock,
                SystemEntropy,
                Sha256RequestDigester,
                false,
            ),
        );
        let readiness = ReadinessService::new(Arc::new(PostgresReadinessAdapter::new(
            runtime.clone(),
            "runtime-test-process".to_owned(),
            Duration::from_secs(1),
        )));
        let secondary_readiness = ReadinessService::new(Arc::new(PostgresReadinessAdapter::new(
            runtime.clone(),
            "runtime-secondary-process".to_owned(),
            Duration::from_secs(1),
        )));
        let unexpected_readiness = ReadinessService::new(Arc::new(PostgresReadinessAdapter::new(
            runtime.clone(),
            "runtime-unexpected-process".to_owned(),
            Duration::from_mins(1),
        )));

        let created_project = provisioning
            .create_project(
                CreateProject {
                    display_name: "Production project".to_owned(),
                    belongs_to: Some("customer-42".to_owned()),
                    idempotency_key: "project-create-12345678".to_owned(),
                },
                Uuid::new_v4(),
            )
            .await
            .expect("Project creation should commit");
        let replayed_project = provisioning
            .create_project(
                CreateProject {
                    display_name: "Production project".to_owned(),
                    belongs_to: Some("customer-42".to_owned()),
                    idempotency_key: "project-create-12345678".to_owned(),
                },
                Uuid::new_v4(),
            )
            .await
            .expect("same idempotent Project request should replay");
        assert_eq!(created_project, replayed_project);

        let concurrent_project = CreateProject {
            display_name: "Concurrent project".to_owned(),
            belongs_to: None,
            idempotency_key: "project-concurrent-same-12345678".to_owned(),
        };
        let (concurrent_project_left, concurrent_project_right) = tokio::join!(
            provisioning.create_project(concurrent_project.clone(), Uuid::new_v4()),
            provisioning.create_project(concurrent_project, Uuid::new_v4()),
        );
        assert_eq!(
            concurrent_project_left.expect("one concurrent Project create should commit"),
            concurrent_project_right.expect("same-key Project create should replay")
        );

        let (conflicting_project_left, conflicting_project_right) = tokio::join!(
            provisioning.create_project(
                CreateProject {
                    display_name: "Concurrent project left".to_owned(),
                    belongs_to: None,
                    idempotency_key: "project-concurrent-conflict-12345678".to_owned(),
                },
                Uuid::new_v4(),
            ),
            provisioning.create_project(
                CreateProject {
                    display_name: "Concurrent project right".to_owned(),
                    belongs_to: None,
                    idempotency_key: "project-concurrent-conflict-12345678".to_owned(),
                },
                Uuid::new_v4(),
            ),
        );
        assert!(matches!(
            (&conflicting_project_left, &conflicting_project_right),
            (Ok(_), Err(ApplicationError::IdempotencyConflict))
                | (Err(ApplicationError::IdempotencyConflict), Ok(_))
        ));

        let initial_policy = provisioning
            .get_project_policy(created_project.id)
            .await
            .expect("new Projects should have an atomic default policy");
        assert_eq!(initial_policy.access_token_lifetime_seconds, 900);
        assert!(!initial_policy.browser_session_reuse);
        assert_eq!(
            (
                initial_policy.claims_revision,
                initial_policy.session_revision
            ),
            (1, 1)
        );
        let updated_policy = provisioning
            .update_project_policy(
                created_project.id,
                UpdateProjectPolicy {
                    access_token_lifetime_seconds: 1_200,
                    browser_session_reuse: true,
                    expected_claims_revision: initial_policy.claims_revision,
                    expected_session_revision: initial_policy.session_revision,
                },
                Uuid::new_v4(),
            )
            .await
            .expect("policy revisions should advance atomically");
        assert_eq!(
            (
                updated_policy.claims_revision,
                updated_policy.session_revision
            ),
            (2, 2)
        );
        assert_eq!(
            provisioning
                .update_project_policy(
                    created_project.id,
                    UpdateProjectPolicy {
                        access_token_lifetime_seconds: 1_800,
                        browser_session_reuse: false,
                        expected_claims_revision: 1,
                        expected_session_revision: 2,
                    },
                    Uuid::new_v4(),
                )
                .await,
            Err(ApplicationError::RevisionConflict)
        );

        assert_eq!(
            provisioning
                .list_projects(Some("customer-42".to_owned()))
                .await
                .expect("owner filtering should succeed")
                .iter()
                .map(|project| project.id)
                .collect::<Vec<_>>(),
            [created_project.id]
        );
        assert!(
            provisioning
                .list_projects(Some("customer".to_owned()))
                .await
                .expect("owner filtering is exact")
                .is_empty()
        );
        let moved_project = provisioning
            .update_project(
                created_project.id,
                UpdateProject {
                    display_name: created_project.display_name.clone(),
                    belongs_to: Some("customer-84".to_owned()),
                    expected_metadata_revision: created_project.metadata_revision,
                },
                Uuid::new_v4(),
            )
            .await
            .expect("Project ownership metadata should be replaceable");
        assert!(
            provisioning
                .list_projects(Some("customer-42".to_owned()))
                .await
                .expect("old owner filter should succeed")
                .is_empty()
        );
        let created_project = provisioning
            .update_project(
                moved_project.id,
                UpdateProject {
                    display_name: moved_project.display_name.clone(),
                    belongs_to: None,
                    expected_metadata_revision: moved_project.metadata_revision,
                },
                Uuid::new_v4(),
            )
            .await
            .expect("Project ownership metadata should be clearable");
        assert_eq!(created_project.belongs_to, None);

        let key_fence_project = provisioning
            .create_project(
                CreateProject {
                    display_name: "Key fence project".to_owned(),
                    belongs_to: None,
                    idempotency_key: "key-fence-project-12345678".to_owned(),
                },
                Uuid::new_v4(),
            )
            .await
            .expect("key fence Project should be created");
        let key_fence_signer_root = store_root.join("key-fence-signers");
        let key_fence_signer = EncryptedFileStore::new(key_fence_signer_root.clone(), [21; 32])
            .expect("key fence signer store should initialize");
        let key_fence_secret =
            EncryptedFileStore::new(store_root.join("key-fence-secrets"), [22; 32])
                .expect("key fence secret store should initialize");
        let key_fence_put_calls = Arc::new(AtomicUsize::new(0));
        let key_revision_store = RevisionBumpingSignerStore {
            inner: key_fence_signer,
            database: control.clone(),
            project_id: key_fence_project.id,
            bumped: Arc::new(AtomicBool::new(false)),
            put_calls: key_fence_put_calls.clone(),
        };
        let key_fence_service = ProvisioningService::new(
            Arc::new(PostgresProvisioningAdapter::new(
                control.clone(),
                url::Url::parse("https://identity.example/runtime/").unwrap(),
                vec!["runtime-test-process".to_owned()],
                Duration::from_millis(10),
                Duration::from_secs(1),
            )),
            ProvisioningInfrastructure::new(
                key_revision_store.clone(),
                key_fence_secret.clone(),
                SystemClock,
                SystemEntropy,
                Sha256RequestDigester,
                false,
            ),
        );
        assert_eq!(
            key_fence_service
                .provision_signing_key(
                    key_fence_project.id,
                    "key-fence-operation-12345678".to_owned(),
                    key_fence_project.metadata_revision,
                    Uuid::new_v4(),
                )
                .await,
            Err(ApplicationError::RevisionConflict),
            "a Project metadata change after signer creation must fence material recording"
        );
        let key_fence_operation = key_provisioning_operation::Entity::find()
            .filter(
                key_provisioning_operation::Column::OperationAlias
                    .eq("key-fence-operation-12345678"),
            )
            .one(control)
            .await
            .expect("key fence operation should be queryable")
            .expect("key fence operation should remain durable");
        assert_eq!(key_fence_operation.state, "prepared");
        assert_eq!(
            key_fence_operation.expected_project_revision,
            key_fence_project.metadata_revision
        );
        let key_fence_resource_id = key_fence_operation.key_id;
        assert_eq!(
            std::fs::read_dir(&key_fence_signer_root)
                .expect("key fence signer directory should exist")
                .count(),
            1
        );
        assert_eq!(key_fence_put_calls.load(Ordering::SeqCst), 1);
        let restarted_key_fence_service = ProvisioningService::new(
            Arc::new(PostgresProvisioningAdapter::new(
                control.clone(),
                url::Url::parse("https://identity.example/runtime/").unwrap(),
                vec!["runtime-test-process".to_owned()],
                Duration::from_millis(10),
                Duration::from_secs(1),
            )),
            ProvisioningInfrastructure::new(
                key_revision_store,
                key_fence_secret,
                SystemClock,
                SystemEntropy,
                Sha256RequestDigester,
                false,
            ),
        );
        assert_eq!(
            restarted_key_fence_service
                .reconcile_signing_key(
                    key_fence_project.id,
                    key_fence_resource_id,
                    key_fence_project.metadata_revision,
                    Uuid::new_v4(),
                )
                .await,
            Err(ApplicationError::RevisionConflict),
            "restart and retry must preserve the captured stale fence rather than overwrite it"
        );
        let retried_key_fence_operation = key_provisioning_operation::Entity::find()
            .filter(
                key_provisioning_operation::Column::OperationAlias
                    .eq("key-fence-operation-12345678"),
            )
            .one(control)
            .await
            .expect("retried key fence operation should be queryable")
            .expect("retried key fence operation should remain durable");
        assert_eq!(retried_key_fence_operation.id, key_fence_operation.id);
        assert_eq!(retried_key_fence_operation.key_id, key_fence_resource_id);
        assert_eq!(
            std::fs::read_dir(&key_fence_signer_root)
                .expect("key fence signer directory should remain readable")
                .count(),
            1,
            "retry must not create a replacement signer"
        );
        assert_eq!(
            key_fence_put_calls.load(Ordering::SeqCst),
            1,
            "a stale prepared operation must fail before another signer call"
        );
        let mut stored_key_fence_operation = retried_key_fence_operation.into_active_model();
        stored_key_fence_operation.state = Set("stored".to_owned());
        stored_key_fence_operation
            .update(control)
            .await
            .expect("stored stale key operation fixture should persist");
        let reconciled_key = restarted_key_fence_service
            .reconcile_signing_key(
                key_fence_project.id,
                key_fence_resource_id,
                key_fence_project.metadata_revision + 1,
                Uuid::new_v4(),
            )
            .await
            .expect("current authorization should reconcile the same stored key operation");
        assert_eq!(reconciled_key.id, key_fence_resource_id);
        let reconciled_key_fence_operation = key_provisioning_operation::Entity::find()
            .filter(
                key_provisioning_operation::Column::OperationAlias
                    .eq("key-fence-operation-12345678"),
            )
            .one(control)
            .await
            .expect("reconciled key operation should be queryable")
            .expect("reconciled key operation should remain durable");
        assert_eq!(reconciled_key_fence_operation.id, key_fence_operation.id);
        assert_eq!(reconciled_key_fence_operation.state, "completed");
        assert_eq!(
            reconciled_key_fence_operation.expected_project_revision,
            key_fence_project.metadata_revision + 1
        );
        assert_eq!(
            std::fs::read_dir(&key_fence_signer_root)
                .expect("reconciled signer directory should remain readable")
                .count(),
            1,
            "reauthorization must reconcile the original signer alias"
        );
        assert_eq!(
            key_fence_put_calls.load(Ordering::SeqCst),
            2,
            "reauthorization should verify the original external signer alias once"
        );

        let abandon_adapter = PostgresProvisioningAdapter::new(
            control.clone(),
            url::Url::parse("https://identity.example/runtime/").unwrap(),
            vec!["runtime-test-process".to_owned()],
            Duration::from_millis(10),
            Duration::from_secs(1),
        );
        let incomplete = abandon_adapter
            .prepare_signing_key(
                key_fence_project.id,
                "key-abandon-operation-12345678".to_owned(),
                "signer/key-abandon-operation-12345678".to_owned(),
                key_fence_project.metadata_revision + 1,
                vec![7; 32],
            )
            .await
            .expect("a durable pre-material key should be prepared");
        let incomplete_record = abandon_adapter
            .get_signing_key(key_fence_project.id, incomplete.key_id)
            .await
            .expect("the pre-material key should remain listable");
        assert_eq!(incomplete_record.public_jwk, serde_json::json!({}));
        let abandoned = restarted_key_fence_service
            .revoke_signing_key(
                key_fence_project.id,
                incomplete.key_id,
                incomplete_record.ring_revision,
                Uuid::new_v4(),
            )
            .await
            .expect("revoking a pre-material key should atomically abandon it");
        assert_eq!(abandoned.state, "abandoned");
        assert_eq!(abandoned.public_jwk, serde_json::json!({}));
        let abandoned_operation =
            key_provisioning_operation::Entity::find_by_id(incomplete.operation_id)
                .one(control)
                .await
                .expect("abandoned key operation should be queryable")
                .expect("abandoned key operation should remain durable");
        assert_eq!(abandoned_operation.state, "abandoned");
        assert_eq!(
            restarted_key_fence_service
                .reconcile_signing_key(
                    key_fence_project.id,
                    incomplete.key_id,
                    key_fence_project.metadata_revision + 1,
                    Uuid::new_v4(),
                )
                .await,
            Err(ApplicationError::InvalidTransition),
            "an abandoned key operation must not be resumed"
        );

        let provider_fence_project = provisioning
            .create_project(
                CreateProject {
                    display_name: "Provider fence project".to_owned(),
                    belongs_to: None,
                    idempotency_key: "provider-fence-project-12345678".to_owned(),
                },
                Uuid::new_v4(),
            )
            .await
            .expect("provider fence Project should be created");
        let provider_fence_signer =
            EncryptedFileStore::new(store_root.join("provider-fence-signers"), [23; 32])
                .expect("provider fence signer store should initialize");
        let provider_fence_secret_root = store_root.join("provider-fence-secrets");
        let provider_fence_secret =
            EncryptedFileStore::new(provider_fence_secret_root.clone(), [24; 32])
                .expect("provider fence secret store should initialize");
        let provider_fence_put_calls = Arc::new(AtomicUsize::new(0));
        let provider_revision_store = RevisionBumpingSecretStore {
            inner: provider_fence_secret,
            database: control.clone(),
            project_id: provider_fence_project.id,
            bumped: Arc::new(AtomicBool::new(false)),
            put_calls: provider_fence_put_calls.clone(),
        };
        let provider_fence_service = ProvisioningService::new(
            Arc::new(PostgresProvisioningAdapter::new(
                control.clone(),
                url::Url::parse("https://identity.example/runtime/").unwrap(),
                vec!["runtime-test-process".to_owned()],
                Duration::from_millis(10),
                Duration::from_secs(1),
            )),
            ProvisioningInfrastructure::new(
                provider_fence_signer.clone(),
                provider_revision_store.clone(),
                SystemClock,
                SystemEntropy,
                Sha256RequestDigester,
                false,
            ),
        );
        let provider_fence_command = || CreateProvider {
            provider_key: "fenced-workforce".to_owned(),
            display_name: "Fenced Workforce".to_owned(),
            issuer: "https://fenced-accounts.example/".to_owned(),
            client_id: "owlauth-fence-test".to_owned(),
            client_secret: zeroize::Zeroizing::new("provider-fence-secret".to_owned()),
            idempotency_key: "provider-fence-operation-12345678".to_owned(),
            expected_project_revision: provider_fence_project.metadata_revision,
        };
        assert_eq!(
            provider_fence_service
                .create_provider(
                    provider_fence_project.id,
                    provider_fence_command(),
                    Uuid::new_v4(),
                )
                .await,
            Err(ApplicationError::RevisionConflict),
            "a Project metadata change after secret creation must fence stored-state recording"
        );
        let provider_fence_operation = provider_secret_operation::Entity::find()
            .filter(
                provider_secret_operation::Column::OperationAlias
                    .eq("provider-fence-operation-12345678"),
            )
            .one(control)
            .await
            .expect("provider fence operation should be queryable")
            .expect("provider fence operation should remain durable");
        assert_eq!(provider_fence_operation.state, "prepared");
        assert_eq!(
            provider_fence_operation.expected_project_revision,
            provider_fence_project.metadata_revision
        );
        let provider_fence_resource_id = provider_fence_operation.provider_id;
        assert_eq!(
            std::fs::read_dir(&provider_fence_secret_root)
                .expect("provider fence secret directory should exist")
                .count(),
            1
        );
        assert_eq!(provider_fence_put_calls.load(Ordering::SeqCst), 1);
        let restarted_provider_fence_service = ProvisioningService::new(
            Arc::new(PostgresProvisioningAdapter::new(
                control.clone(),
                url::Url::parse("https://identity.example/runtime/").unwrap(),
                vec!["runtime-test-process".to_owned()],
                Duration::from_millis(10),
                Duration::from_secs(1),
            )),
            ProvisioningInfrastructure::new(
                provider_fence_signer,
                provider_revision_store,
                SystemClock,
                SystemEntropy,
                Sha256RequestDigester,
                false,
            ),
        );
        assert_eq!(
            restarted_provider_fence_service
                .reconcile_provider(
                    provider_fence_project.id,
                    provider_fence_resource_id,
                    zeroize::Zeroizing::new("provider-fence-secret".to_owned()),
                    provider_fence_project.metadata_revision,
                    Uuid::new_v4(),
                )
                .await,
            Err(ApplicationError::RevisionConflict),
            "restart and retry must preserve the captured stale provider fence"
        );
        let retried_provider_fence_operation = provider_secret_operation::Entity::find()
            .filter(
                provider_secret_operation::Column::OperationAlias
                    .eq("provider-fence-operation-12345678"),
            )
            .one(control)
            .await
            .expect("retried provider fence operation should be queryable")
            .expect("retried provider fence operation should remain durable");
        assert_eq!(
            retried_provider_fence_operation.id,
            provider_fence_operation.id
        );
        assert_eq!(
            retried_provider_fence_operation.provider_id,
            provider_fence_resource_id
        );
        assert_eq!(
            std::fs::read_dir(&provider_fence_secret_root)
                .expect("provider fence secret directory should remain readable")
                .count(),
            1,
            "retry must not create a replacement secret"
        );
        assert_eq!(
            provider_fence_put_calls.load(Ordering::SeqCst),
            1,
            "a stale prepared operation must fail before another secret-store call"
        );
        let mut conflicting_provider_fence_command = provider_fence_command();
        conflicting_provider_fence_command.display_name = "Different Workforce".to_owned();
        assert_eq!(
            restarted_provider_fence_service
                .create_provider(
                    provider_fence_project.id,
                    conflicting_provider_fence_command,
                    Uuid::new_v4(),
                )
                .await,
            Err(ApplicationError::IdempotencyConflict),
            "digest conflict must take precedence over a stale captured revision"
        );
        assert_eq!(
            provider_fence_put_calls.load(Ordering::SeqCst),
            1,
            "digest conflict must fail before another secret-store call"
        );
        let mut stored_provider_fence_operation =
            retried_provider_fence_operation.into_active_model();
        stored_provider_fence_operation.state = Set("stored".to_owned());
        stored_provider_fence_operation
            .update(control)
            .await
            .expect("stored stale provider operation fixture should persist");
        assert_eq!(
            restarted_provider_fence_service
                .reconcile_provider(
                    provider_fence_project.id,
                    provider_fence_resource_id,
                    zeroize::Zeroizing::new("wrong-provider-fence-secret".to_owned()),
                    provider_fence_project.metadata_revision + 1,
                    Uuid::new_v4(),
                )
                .await,
            Err(ApplicationError::IdempotencyConflict),
            "resource-keyed reconciliation must reject a different re-entered secret"
        );
        assert_eq!(
            provider_fence_put_calls.load(Ordering::SeqCst),
            1,
            "wrong secret reconciliation must fail before another external write"
        );
        let reconciled_provider = restarted_provider_fence_service
            .reconcile_provider(
                provider_fence_project.id,
                provider_fence_resource_id,
                zeroize::Zeroizing::new("provider-fence-secret".to_owned()),
                provider_fence_project.metadata_revision + 1,
                Uuid::new_v4(),
            )
            .await
            .expect("current authorization should reconcile the same stored provider operation");
        assert_eq!(reconciled_provider.id, provider_fence_resource_id);
        let reconciled_provider_fence_operation = provider_secret_operation::Entity::find()
            .filter(
                provider_secret_operation::Column::OperationAlias
                    .eq("provider-fence-operation-12345678"),
            )
            .one(control)
            .await
            .expect("reconciled provider operation should be queryable")
            .expect("reconciled provider operation should remain durable");
        assert_eq!(
            reconciled_provider_fence_operation.id,
            provider_fence_operation.id
        );
        assert_eq!(reconciled_provider_fence_operation.state, "completed");
        assert_eq!(
            reconciled_provider_fence_operation.expected_project_revision,
            provider_fence_project.metadata_revision + 1
        );
        assert_eq!(
            std::fs::read_dir(&provider_fence_secret_root)
                .expect("reconciled provider secret directory should remain readable")
                .count(),
            1,
            "reauthorization must reconcile the original provider secret alias"
        );
        assert_eq!(
            provider_fence_put_calls.load(Ordering::SeqCst),
            2,
            "reauthorization should verify the original external secret alias once"
        );

        let created_application = provisioning
            .create_application(
                created_project.id,
                CreateApplication {
                    display_name: "Browser application".to_owned(),
                    application_type: ApplicationType::Web,
                    idempotency_key: "application-create-12345678".to_owned(),
                },
                Uuid::new_v4(),
            )
            .await
            .expect("Application creation should commit");

        let concurrent_application = CreateApplication {
            display_name: "Concurrent application".to_owned(),
            application_type: ApplicationType::Web,
            idempotency_key: "application-concurrent-same-12345678".to_owned(),
        };
        let (concurrent_application_left, concurrent_application_right) = tokio::join!(
            provisioning.create_application(
                created_project.id,
                concurrent_application.clone(),
                Uuid::new_v4(),
            ),
            provisioning.create_application(
                created_project.id,
                concurrent_application,
                Uuid::new_v4(),
            ),
        );
        assert_eq!(
            concurrent_application_left.expect("one concurrent Application create should commit"),
            concurrent_application_right.expect("same-key Application create should replay")
        );

        let (conflicting_application_left, conflicting_application_right) = tokio::join!(
            provisioning.create_application(
                created_project.id,
                CreateApplication {
                    display_name: "Concurrent application left".to_owned(),
                    application_type: ApplicationType::Web,
                    idempotency_key: "application-concurrent-conflict-12345678".to_owned(),
                },
                Uuid::new_v4(),
            ),
            provisioning.create_application(
                created_project.id,
                CreateApplication {
                    display_name: "Concurrent application right".to_owned(),
                    application_type: ApplicationType::Web,
                    idempotency_key: "application-concurrent-conflict-12345678".to_owned(),
                },
                Uuid::new_v4(),
            ),
        );
        assert!(matches!(
            (
                &conflicting_application_left,
                &conflicting_application_right
            ),
            (Ok(_), Err(ApplicationError::IdempotencyConflict))
                | (Err(ApplicationError::IdempotencyConflict), Ok(_))
        ));

        let application_idempotency =
            control_idempotency_record::Entity::find_by_id("application-create-12345678")
                .one(control)
                .await
                .expect("idempotency metadata should be queryable")
                .expect("Application creation should retain its replay record");
        assert_eq!(application_idempotency.project_id, Some(created_project.id));
        assert_eq!(
            application_idempotency.result_resource_id,
            Some(created_application.id)
        );
        assert_eq!(application_idempotency.operation_kind, "application.create");
        assert!(application_idempotency.expires_at.is_none());
        let configured_application = provisioning
            .replace_application_configuration(
                created_project.id,
                created_application.id,
                ReplaceApplicationConfiguration {
                    redirect_uris: vec!["https://app.example/callback".to_owned()],
                    allowed_origins: vec!["https://app.example".to_owned()],
                    expected_security_revision: created_application.security_revision,
                },
                Uuid::new_v4(),
            )
            .await
            .expect("exact Application configuration should commit");
        assert_eq!(configured_application.security_revision, 2);
        assert_eq!(
            configured_application.configuration.redirect_uris,
            ["https://app.example/callback"]
        );

        let mut direct_sql = PgConnection::connect(&control_url)
            .await
            .expect("direct constraint test connection should open");
        let duplicate_redirect = sqlx::query(
            "INSERT INTO application_redirects \
             (project_id, application_id, redirect_uri, redirect_type) \
             VALUES ($1, $2, $3, 'web')",
        )
        .bind(created_project.id)
        .bind(created_application.id)
        .bind("https://app.example/callback")
        .execute(&mut direct_sql)
        .await
        .expect_err("duplicate exact redirect must be rejected");
        assert_eq!(
            duplicate_redirect
                .as_database_error()
                .expect("duplicate redirect should be a database error")
                .code()
                .as_deref(),
            Some("23505")
        );
        let duplicate_origin = sqlx::query(
            "INSERT INTO application_origins (project_id, application_id, origin) \
             VALUES ($1, $2, $3)",
        )
        .bind(created_project.id)
        .bind(created_application.id)
        .bind("https://app.example")
        .execute(&mut direct_sql)
        .await
        .expect_err("duplicate exact origin must be rejected");
        assert_eq!(
            duplicate_origin
                .as_database_error()
                .expect("duplicate origin should be a database error")
                .code()
                .as_deref(),
            Some("23505")
        );
        let cross_project_redirect = sqlx::query(
            "INSERT INTO application_redirects \
             (project_id, application_id, redirect_uri, redirect_type) \
             VALUES ($1, $2, $3, 'web')",
        )
        .bind(key_fence_project.id)
        .bind(created_application.id)
        .bind("https://cross-project.example/callback")
        .execute(&mut direct_sql)
        .await
        .expect_err("cross-Project child must be rejected");
        assert_eq!(
            cross_project_redirect
                .as_database_error()
                .expect("cross-Project child should be a database error")
                .code()
                .as_deref(),
            Some("23503")
        );
        let malformed_public_id = sqlx::query(
            "INSERT INTO projects \
             (id, public_id, status, metadata_revision, security_revision) \
             VALUES ($1, 'invalid/public', 'active', 1, 1)",
        )
        .bind(Uuid::new_v4())
        .execute(&mut direct_sql)
        .await
        .expect_err("unsafe public ID characters must be rejected");
        assert_eq!(
            malformed_public_id
                .as_database_error()
                .expect("malformed public ID should be a database error")
                .code()
                .as_deref(),
            Some("23514")
        );
        let changed_public_id = sqlx::query("UPDATE projects SET public_id = $1 WHERE id = $2")
            .bind("prj_replaced_identity")
            .bind(created_project.id)
            .execute(&mut direct_sql)
            .await
            .expect_err("Project public identity must be immutable");
        assert_eq!(
            changed_public_id
                .as_database_error()
                .expect("immutable Project identity should be a database error")
                .code()
                .as_deref(),
            Some("23514")
        );
        let audit_id: Uuid = sqlx::query_scalar(
            "SELECT id FROM audit_events WHERE project_id = $1 ORDER BY occurred_at, id LIMIT 1",
        )
        .bind(created_project.id)
        .fetch_one(&mut direct_sql)
        .await
        .expect("audit fixture should exist");
        for statement in [
            "UPDATE audit_events SET safe_context = '{\"changed\":true}'::jsonb WHERE id = $1",
            "DELETE FROM audit_events WHERE id = $1",
        ] {
            let audit_mutation = sqlx::query(statement)
                .bind(audit_id)
                .execute(&mut direct_sql)
                .await
                .expect_err("audit mutation must be rejected");
            assert_eq!(
                audit_mutation
                    .as_database_error()
                    .expect("audit mutation should be a database error")
                    .code()
                    .as_deref(),
                Some("23514")
            );
        }
        direct_sql
            .close()
            .await
            .expect("direct constraint connection should close");

        let signing_key = provisioning
            .provision_signing_key(
                created_project.id,
                "signing-operation-12345678".to_owned(),
                created_project.metadata_revision,
                Uuid::new_v4(),
            )
            .await
            .expect("signing material should reconcile and publish");
        let operation = key_provisioning_operation::Entity::find()
            .filter(
                key_provisioning_operation::Column::OperationAlias.eq("signing-operation-12345678"),
            )
            .one(control)
            .await
            .expect("key operation should be queryable")
            .expect("key operation should be durable");
        let mut operation_active = operation.into_active_model();
        operation_active.state = Set("stored".to_owned());
        operation_active.completed_at = Set(None);
        operation_active
            .update(control)
            .await
            .expect("stored recovery fixture should persist");
        let key = project_signing_key::Entity::find_by_id(signing_key.id)
            .one(control)
            .await
            .expect("signing key should be queryable")
            .expect("signing key should exist");
        let mut key_active = key.into_active_model();
        key_active.state = Set("provisioning".to_owned());
        key_active
            .update(control)
            .await
            .expect("stored recovery fixture should persist");
        let restarted_provisioning = ProvisioningService::new(
            Arc::new(PostgresProvisioningAdapter::new(
                control.clone(),
                url::Url::parse("https://identity.example/runtime/").unwrap(),
                vec![
                    "runtime-test-process".to_owned(),
                    "runtime-secondary-process".to_owned(),
                ],
                Duration::from_millis(10),
                Duration::from_secs(1),
            )),
            ProvisioningInfrastructure::new(
                signer_store.clone(),
                secret_store.clone(),
                SystemClock,
                SystemEntropy,
                Sha256RequestDigester,
                false,
            ),
        );
        let signing_key = restarted_provisioning
            .provision_signing_key(
                created_project.id,
                "signing-operation-12345678".to_owned(),
                created_project.metadata_revision,
                Uuid::new_v4(),
            )
            .await
            .expect("a restarted adapter should finalize the same stored key operation");
        assert_eq!(signing_key.state, "published");
        assert_eq!(signing_key.ring_revision, 3);

        let mut jwk_constraint_sql = PgConnection::connect(&control_url)
            .await
            .expect("JWK constraint test connection should open");
        for (statement, expectation) in [
            (
                "UPDATE project_signing_keys \
                 SET public_jwk = public_jwk || '{\"d\":\"private\"}'::jsonb WHERE id = $1",
                "private JWK material must be rejected",
            ),
            (
                "UPDATE project_signing_keys \
                 SET public_jwk = jsonb_set(public_jwk, '{kid}', '\"kid_wrong_identity\"') \
                 WHERE id = $1",
                "JWK kid must equal the stable row kid",
            ),
        ] {
            let invalid_jwk = sqlx::query(statement)
                .bind(signing_key.id)
                .execute(&mut jwk_constraint_sql)
                .await
                .expect_err(expectation);
            assert_eq!(
                invalid_jwk
                    .as_database_error()
                    .expect("invalid JWK should be a database error")
                    .code()
                    .as_deref(),
                Some("23514")
            );
        }
        jwk_constraint_sql
            .close()
            .await
            .expect("JWK constraint test connection should close");

        assert_eq!(
            provisioning
                .activate_signing_key(
                    created_project.id,
                    signing_key.id,
                    signing_key.ring_revision,
                    Uuid::new_v4(),
                )
                .await,
            Err(crate::application::ApplicationError::PublicationPending)
        );

        let published_jwks = readiness
            .project_jwks(&created_project.public_id)
            .await
            .expect("Runtime should load and lease the published JWKS revision");
        assert_eq!(published_jwks.revision, signing_key.ring_revision);
        assert_eq!(published_jwks.keys.len(), 1);
        tokio::time::sleep(Duration::from_millis(15)).await;
        assert_eq!(
            provisioning
                .activate_signing_key(
                    created_project.id,
                    signing_key.id,
                    signing_key.ring_revision,
                    Uuid::new_v4(),
                )
                .await,
            Err(ApplicationError::PublicationPending)
        );
        secondary_readiness
            .project_jwks(&created_project.public_id)
            .await
            .expect("every required Runtime process should observe the revision");
        tokio::time::sleep(Duration::from_millis(15)).await;
        let active_key = provisioning
            .activate_signing_key(
                created_project.id,
                signing_key.id,
                signing_key.ring_revision,
                Uuid::new_v4(),
            )
            .await
            .expect("activation should succeed after the propagation interval");
        assert_eq!(active_key.state, "active");

        unexpected_readiness
            .project_jwks(&created_project.public_id)
            .await
            .expect("an additional live Runtime should lease its loaded revision");
        let policy_before_reduction = provisioning
            .get_project_policy(created_project.id)
            .await
            .expect("current policy should be queryable");
        provisioning
            .update_project_policy(
                created_project.id,
                UpdateProjectPolicy {
                    access_token_lifetime_seconds: 60,
                    browser_session_reuse: policy_before_reduction.browser_session_reuse,
                    expected_claims_revision: policy_before_reduction.claims_revision,
                    expected_session_revision: policy_before_reduction.session_revision,
                },
                Uuid::new_v4(),
            )
            .await
            .expect("lowering the Project token policy should commit");

        let rotating_key = provisioning
            .provision_signing_key(
                created_project.id,
                "signing-rotation-12345678".to_owned(),
                created_project.metadata_revision,
                Uuid::new_v4(),
            )
            .await
            .expect("a second key should publish for safe rotation");
        let rotation_jwks = readiness
            .project_jwks(&created_project.public_id)
            .await
            .expect("primary Runtime should observe the rotation revision");
        secondary_readiness
            .project_jwks(&created_project.public_id)
            .await
            .expect("secondary Runtime should observe the rotation revision");
        assert_eq!(rotation_jwks.keys.len(), 2);
        tokio::time::sleep(Duration::from_millis(15)).await;
        assert_eq!(
            provisioning
                .activate_signing_key(
                    created_project.id,
                    rotating_key.id,
                    rotating_key.ring_revision,
                    Uuid::new_v4(),
                )
                .await,
            Err(ApplicationError::PublicationPending),
            "an unexpected live Runtime with a stale revision must block activation"
        );
        let unexpected_lease = runtime_publication_lease::Entity::find()
            .filter(runtime_publication_lease::Column::ProjectId.eq(created_project.id))
            .filter(runtime_publication_lease::Column::ProcessId.eq("runtime-unexpected-process"))
            .one(control)
            .await
            .expect("unexpected Runtime lease should be queryable")
            .expect("unexpected Runtime lease should exist");
        let mut unexpected_lease_active = unexpected_lease.into_active_model();
        let expired_at = time::OffsetDateTime::now_utc() - time::Duration::seconds(1);
        unexpected_lease_active.first_observed_at = Set(expired_at - time::Duration::seconds(2));
        unexpected_lease_active.last_observed_at = Set(expired_at - time::Duration::seconds(1));
        unexpected_lease_active.expires_at = Set(expired_at);
        unexpected_lease_active
            .update(control)
            .await
            .expect("drained Runtime lease should expire");
        let (left_activation, right_activation) = tokio::join!(
            provisioning.activate_signing_key(
                created_project.id,
                rotating_key.id,
                rotating_key.ring_revision,
                Uuid::new_v4(),
            ),
            provisioning.activate_signing_key(
                created_project.id,
                rotating_key.id,
                rotating_key.ring_revision,
                Uuid::new_v4(),
            )
        );
        let rotated_active_key = match (left_activation, right_activation) {
            (
                Ok(active),
                Err(ApplicationError::RevisionConflict | ApplicationError::InvalidTransition),
            )
            | (
                Err(ApplicationError::RevisionConflict | ApplicationError::InvalidTransition),
                Ok(active),
            ) => active,
            outcomes => panic!("exactly one concurrent activation must commit: {outcomes:?}"),
        };
        let retiring_key = provisioning
            .list_signing_keys(created_project.id)
            .await
            .expect("rotated keys should be queryable")
            .into_iter()
            .find(|key| key.id == active_key.id)
            .expect("the former active key should remain in the ring");
        assert_eq!(retiring_key.state, "retiring");
        let rotation_time = rotated_active_key
            .sign_not_before
            .expect("the newly active key should record its activation time");
        assert_eq!(
            retiring_key.verify_not_after,
            Some(
                rotation_time
                    + time::Duration::seconds(i64::from(
                        crate::domain::MAX_ACCESS_TOKEN_LIFETIME_SECONDS,
                    ))
                    + time::Duration::seconds(1)
                    + time::Duration::milliseconds(10)
            ),
            "a reduced Project policy must not shorten the hard maximum verification overlap"
        );

        assert_eq!(
            provisioning
                .retire_signing_key(
                    created_project.id,
                    retiring_key.id,
                    rotated_active_key.ring_revision,
                    Uuid::new_v4(),
                )
                .await,
            Err(ApplicationError::InvalidTransition)
        );
        let retiring_model = project_signing_key::Entity::find_by_id(retiring_key.id)
            .one(control)
            .await
            .expect("retiring key should be queryable")
            .expect("retiring key should exist");
        let mut retiring_active = retiring_model.into_active_model();
        let elapsed_cutoff = time::OffsetDateTime::now_utc() - time::Duration::seconds(1);
        retiring_active.sign_not_before =
            Set(Some(elapsed_cutoff - time::Duration::microseconds(1)));
        retiring_active.verify_not_after = Set(Some(elapsed_cutoff));
        retiring_active
            .update(control)
            .await
            .expect("test cutoff should advance past the retention window");
        let post_cutoff_jwks = readiness
            .project_jwks(&created_project.public_id)
            .await
            .expect("expired retiring keys should leave Runtime JWKS");
        assert_eq!(post_cutoff_jwks.keys.len(), 1);
        let retired_key = provisioning
            .retire_signing_key(
                created_project.id,
                retiring_key.id,
                rotated_active_key.ring_revision,
                Uuid::new_v4(),
            )
            .await
            .expect("retirement should finalize only after verification cutoff");
        assert_eq!(retired_key.state, "retired");
        let active_key = provisioning
            .list_signing_keys(created_project.id)
            .await
            .expect("the active key should remain queryable")
            .into_iter()
            .find(|key| key.id == rotated_active_key.id)
            .expect("the rotated key should remain active");
        assert_eq!(active_key.state, "active");
        assert_eq!(active_key.ring_revision, retired_key.ring_revision);
        assert!(
            key_state_event::Entity::find()
                .filter(key_state_event::Column::ProjectId.eq(created_project.id))
                .all(control)
                .await
                .expect("key lifecycle events should be queryable")
                .len()
                >= 6
        );

        let provider = provisioning
            .create_provider(
                created_project.id,
                CreateProvider {
                    provider_key: "workforce".to_owned(),
                    display_name: "Workforce SSO".to_owned(),
                    issuer: "https://accounts.example/".to_owned(),
                    client_id: "owlauth-test".to_owned(),
                    client_secret: zeroize::Zeroizing::new("provider-secret".to_owned()),
                    idempotency_key: "provider-operation-12345678".to_owned(),
                    expected_project_revision: created_project.metadata_revision,
                },
                Uuid::new_v4(),
            )
            .await
            .expect("provider secret should reconcile without disclosure");
        let operation = provider_secret_operation::Entity::find()
            .filter(
                provider_secret_operation::Column::OperationAlias.eq("provider-operation-12345678"),
            )
            .one(control)
            .await
            .expect("provider operation should be queryable")
            .expect("provider operation should be durable");
        let mut operation_active = operation.into_active_model();
        operation_active.state = Set("stored".to_owned());
        operation_active.completed_at = Set(None);
        operation_active
            .update(control)
            .await
            .expect("stored provider recovery fixture should persist");
        let provider_model = provider_configuration::Entity::find_by_id(provider.id)
            .one(control)
            .await
            .expect("provider should be queryable")
            .expect("provider should exist");
        let mut provider_active = provider_model.into_active_model();
        provider_active.status = Set("provisioning".to_owned());
        provider_active.secret_ref = Set(None);
        provider_active.revision = Set(1);
        provider_active
            .update(control)
            .await
            .expect("stored provider recovery fixture should persist");
        let provider = restarted_provisioning
            .create_provider(
                created_project.id,
                CreateProvider {
                    provider_key: "workforce".to_owned(),
                    display_name: "Workforce SSO".to_owned(),
                    issuer: "https://accounts.example/".to_owned(),
                    client_id: "owlauth-test".to_owned(),
                    client_secret: zeroize::Zeroizing::new("provider-secret".to_owned()),
                    idempotency_key: "provider-operation-12345678".to_owned(),
                    expected_project_revision: created_project.metadata_revision,
                },
                Uuid::new_v4(),
            )
            .await
            .expect("a restarted adapter should finalize the same stored provider operation");
        assert_eq!(provider.status, "active");
        let mut callback_constraint_sql = PgConnection::connect(&control_url)
            .await
            .expect("callback constraint test connection should open");
        let changed_callback =
            sqlx::query("UPDATE provider_configurations SET callback_url = $1 WHERE id = $2")
                .bind("https://identity.example/runtime/projects/replaced/auth/callback/workforce")
                .bind(provider.id)
                .execute(&mut callback_constraint_sql)
                .await
                .expect_err("provider callback identity must be immutable");
        assert_eq!(
            changed_callback
                .as_database_error()
                .expect("immutable callback should be a database error")
                .code()
                .as_deref(),
            Some("23514")
        );
        callback_constraint_sql
            .close()
            .await
            .expect("callback constraint test connection should close");

        bump_project_metadata_revision(control, created_project.id)
            .await
            .expect("completed replay fence fixture should advance Project metadata");
        let completed_key_operation = key_provisioning_operation::Entity::find()
            .filter(
                key_provisioning_operation::Column::OperationAlias.eq("signing-operation-12345678"),
            )
            .one(control)
            .await
            .expect("completed key operation should be queryable")
            .expect("completed key operation should exist");
        let completed_key_model = project_signing_key::Entity::find_by_id(signing_key.id)
            .one(control)
            .await
            .expect("completed key should be queryable")
            .expect("completed key should exist");
        let prepared_key = PreparedSigningKey {
            operation_id: completed_key_operation.id,
            ring_id: completed_key_operation.ring_id,
            key_id: completed_key_operation.key_id,
            kid: completed_key_model.kid,
            signer_ref: completed_key_model.signer_ref,
            request_digest: completed_key_operation.request_digest,
            state: ProvisioningOperationState::Prepared,
        };
        let completed_provider_operation = provider_secret_operation::Entity::find()
            .filter(
                provider_secret_operation::Column::OperationAlias.eq("provider-operation-12345678"),
            )
            .one(control)
            .await
            .expect("completed provider operation should be queryable")
            .expect("completed provider operation should exist");
        let prepared_provider = PreparedProvider {
            operation_id: completed_provider_operation.id,
            provider_id: completed_provider_operation.provider_id,
            request_digest: completed_provider_operation.request_digest,
            state: ProvisioningOperationState::Prepared,
        };
        let completed_stage_adapter = PostgresProvisioningAdapter::new(
            control.clone(),
            url::Url::parse("https://identity.example/runtime/").unwrap(),
            vec!["runtime-test-process".to_owned()],
            Duration::from_millis(10),
            Duration::from_secs(1),
        );
        let replayed_at = time::OffsetDateTime::now_utc();
        completed_stage_adapter
            .record_signing_key_material(
                created_project.id,
                &prepared_key,
                created_project.metadata_revision,
                serde_json::json!({}),
                replayed_at,
            )
            .await
            .expect("an in-flight key record stage should observe concurrent completion");
        let stage_replayed_key = completed_stage_adapter
            .publish_signing_key(
                created_project.id,
                &prepared_key,
                created_project.metadata_revision,
                Uuid::new_v4(),
                replayed_at,
            )
            .await
            .expect("an in-flight key publish stage should observe concurrent completion");
        assert_eq!(stage_replayed_key.id, signing_key.id);
        completed_stage_adapter
            .mark_provider_secret_stored(
                created_project.id,
                &prepared_provider,
                created_project.metadata_revision,
                replayed_at,
            )
            .await
            .expect("an in-flight provider store stage should observe concurrent completion");
        let stage_replayed_provider = completed_stage_adapter
            .finalize_provider(
                created_project.id,
                &prepared_provider,
                created_project.metadata_revision,
                "unused-after-completion".to_owned(),
                Uuid::new_v4(),
                replayed_at,
            )
            .await
            .expect("an in-flight provider finalize stage should observe concurrent completion");
        assert_eq!(stage_replayed_provider.id, provider.id);

        let replayed_signing_key = restarted_provisioning
            .provision_signing_key(
                created_project.id,
                "signing-operation-12345678".to_owned(),
                created_project.metadata_revision,
                Uuid::new_v4(),
            )
            .await
            .expect("a completed key operation should replay across later Project revisions");
        assert_eq!(replayed_signing_key.id, signing_key.id);
        let replayed_provider = restarted_provisioning
            .create_provider(
                created_project.id,
                CreateProvider {
                    provider_key: "workforce".to_owned(),
                    display_name: "Workforce SSO".to_owned(),
                    issuer: "https://accounts.example/".to_owned(),
                    client_id: "owlauth-test".to_owned(),
                    client_secret: zeroize::Zeroizing::new("provider-secret".to_owned()),
                    idempotency_key: "provider-operation-12345678".to_owned(),
                    expected_project_revision: created_project.metadata_revision,
                },
                Uuid::new_v4(),
            )
            .await
            .expect("a completed provider operation should replay across later Project revisions");
        assert_eq!(replayed_provider.id, provider.id);

        let assigned = provisioning
            .assign_provider(
                created_project.id,
                provider.id,
                created_application.id,
                configured_application.security_revision,
                Uuid::new_v4(),
            )
            .await
            .expect("same-Project provider assignment should commit");
        assert_eq!(assigned.assigned_application_ids, [created_application.id]);

        let public_config = readiness
            .public_application_config(&created_project.public_id, &created_application.public_id)
            .await
            .expect("Runtime public configuration should resolve exact IDs");
        assert!(public_config.login_available);
        assert_eq!(public_config.providers.len(), 1);
        assert_eq!(public_config.providers[0].key, "workforce");
        assert_eq!(public_config.publishable_keys.len(), 1);
        assert_eq!(assigned.revision, provider.revision + 1);

        let mut blocked_egress_config = config.clone();
        blocked_egress_config.provider_allowed_origins =
            vec!["https://different-provider.example/".to_owned()];
        let mut blocked_egress_routers = build_routers(&blocked_egress_config, Some(&pools));
        blocked_egress_routers.mark_ready();
        let blocked_egress_response = blocked_egress_routers
            .runtime
            .take()
            .expect("Runtime router should be composed")
            .oneshot(
                Request::get(format!(
                    "/v1/projects/{}/auth/config?application_id={}",
                    created_project.public_id, created_application.public_id
                ))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(blocked_egress_response.status(), StatusCode::OK);
        let blocked_egress_json: serde_json::Value = serde_json::from_slice(
            &to_bytes(blocked_egress_response.into_body(), 1_000_000)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(blocked_egress_json["providers"], serde_json::json!([]));
        assert_eq!(blocked_egress_json["login_available"], false);

        let snapshot_mutation = control
            .begin()
            .await
            .expect("snapshot race transaction should begin");
        project::Entity::find_by_id(created_project.id)
            .lock_exclusive()
            .one(&snapshot_mutation)
            .await
            .expect("Project guard should be lockable")
            .expect("Project should exist");
        let assignment = application_provider_assignment::Entity::find_by_id((
            created_project.id,
            created_application.id,
            provider.id,
        ))
        .lock_exclusive()
        .one(&snapshot_mutation)
        .await
        .expect("assignment should be lockable")
        .expect("assignment should exist");
        let application = application::Entity::find_by_id(created_application.id)
            .lock_exclusive()
            .one(&snapshot_mutation)
            .await
            .expect("Application should be lockable")
            .expect("Application should exist");
        let provider_model = provider_configuration::Entity::find_by_id(provider.id)
            .lock_exclusive()
            .one(&snapshot_mutation)
            .await
            .expect("provider should be lockable")
            .expect("provider should exist");
        let next_application_revision = application.security_revision + 1;
        let mut assignment_active = assignment.into_active_model();
        assignment_active.status = Set("disabled".to_owned());
        assignment_active.security_revision = Set(next_application_revision);
        assignment_active
            .update(&snapshot_mutation)
            .await
            .expect("unassignment fixture should stage");
        let next_aggregate_revision = application.revision + 1;
        let mut application_active = application.into_active_model();
        application_active.security_revision = Set(next_application_revision);
        application_active.revision = Set(next_aggregate_revision);
        application_active
            .update(&snapshot_mutation)
            .await
            .expect("Application revision fixture should stage");
        let next_provider_revision = provider_model.revision + 1;
        let mut provider_active = provider_model.into_active_model();
        provider_active.revision = Set(next_provider_revision);
        provider_active
            .update(&snapshot_mutation)
            .await
            .expect("provider revision fixture should stage");

        let readiness_for_race = readiness.clone();
        let project_public_id = created_project.public_id.clone();
        let application_public_id = created_application.public_id.clone();
        let mut snapshot_read = tokio::spawn(async move {
            readiness_for_race
                .public_application_config(&project_public_id, &application_public_id)
                .await
        });
        assert!(
            timeout(Duration::from_millis(50), &mut snapshot_read)
                .await
                .is_err(),
            "Runtime snapshot must wait for the conflicting Project mutation"
        );
        snapshot_mutation
            .commit()
            .await
            .expect("unassignment fixture should commit");
        let raced_public_config = snapshot_read
            .await
            .expect("snapshot task should complete")
            .expect("post-commit public config should remain available");
        assert!(raced_public_config.providers.is_empty());

        let application_after_unassignment = provisioning
            .get_application(created_project.id, created_application.id)
            .await
            .expect("Application revision should reflect unassignment");
        let reassigned = provisioning
            .assign_provider(
                created_project.id,
                provider.id,
                created_application.id,
                application_after_unassignment.security_revision,
                Uuid::new_v4(),
            )
            .await
            .expect("a current command should reactivate the terminal assignment row");
        assert_eq!(reassigned.revision, next_provider_revision + 1);
        assert_eq!(
            provisioning
                .disable_provider(
                    created_project.id,
                    provider.id,
                    assigned.revision,
                    Uuid::new_v4(),
                )
                .await,
            Err(ApplicationError::RevisionConflict),
            "an assignment revision must fence a concurrent stale provider disable"
        );

        let application_before_configuration_race = provisioning
            .get_application(created_project.id, created_application.id)
            .await
            .expect("Application should be queryable before concurrent configuration");
        let (left_configuration, right_configuration) = tokio::join!(
            provisioning.replace_application_configuration(
                created_project.id,
                created_application.id,
                ReplaceApplicationConfiguration {
                    redirect_uris: vec!["https://app.example/callback-a".to_owned()],
                    allowed_origins: vec!["https://app.example".to_owned()],
                    expected_security_revision: application_before_configuration_race
                        .security_revision,
                },
                Uuid::new_v4(),
            ),
            provisioning.replace_application_configuration(
                created_project.id,
                created_application.id,
                ReplaceApplicationConfiguration {
                    redirect_uris: vec!["https://app.example/callback-b".to_owned()],
                    allowed_origins: vec!["https://app.example".to_owned()],
                    expected_security_revision: application_before_configuration_race
                        .security_revision,
                },
                Uuid::new_v4(),
            )
        );
        assert!(matches!(
            (&left_configuration, &right_configuration),
            (Ok(_), Err(ApplicationError::RevisionConflict))
                | (Err(ApplicationError::RevisionConflict), Ok(_))
        ));

        assert_eq!(
            provisioning
                .get_application(Uuid::new_v4(), created_application.id)
                .await,
            Err(crate::application::ApplicationError::NotFound)
        );

        let revoked = provisioning
            .revoke_signing_key(
                created_project.id,
                active_key.id,
                active_key.ring_revision,
                Uuid::new_v4(),
            )
            .await
            .expect("emergency revocation should commit");
        assert_eq!(revoked.state, "revoked");
        let revoked_jwks = readiness
            .project_jwks(&created_project.public_id)
            .await
            .expect("Runtime should publish the post-revocation revision");
        assert!(revoked_jwks.keys.is_empty());
        assert!(revoked_jwks.signing_epoch > published_jwks.signing_epoch);

        let mut routers = build_routers(&config, Some(&pools));
        routers.mark_ready();
        let control_router = routers.control.take().expect("Control router should exist");
        let denied = control_router
            .clone()
            .oneshot(
                Request::get(format!(
                    "/v1/projects/{}/applications/{}",
                    created_project.id,
                    Uuid::new_v4()
                ))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
        let listed = control_router
            .oneshot(
                Request::get("/v1/projects")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer owl_ctrl_v1_{}", "A".repeat(43)),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(listed.status(), StatusCode::OK);
        let listed_body = to_bytes(listed.into_body(), 1_000_000).await.unwrap();
        assert!(
            std::str::from_utf8(&listed_body)
                .unwrap()
                .contains(&created_project.public_id)
        );

        let runtime_router = routers.runtime.take().expect("Runtime router should exist");
        let runtime_config_uri = format!(
            "/v1/projects/{}/auth/config?application_id={}",
            created_project.public_id, created_application.public_id
        );
        let leaked_credential = runtime_router
            .clone()
            .oneshot(
                Request::get(&runtime_config_uri)
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer owl_ctrl_v1_{}", "A".repeat(43)),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(leaked_credential.status(), StatusCode::BAD_REQUEST);
        let public_response = runtime_router
            .clone()
            .oneshot(
                Request::get(&runtime_config_uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(public_response.status(), StatusCode::OK);
        assert_eq!(public_response.headers()[header::CACHE_CONTROL], "no-store");
        let runtime_body = to_bytes(public_response.into_body(), 1_000_000)
            .await
            .unwrap();
        let runtime_json: serde_json::Value = serde_json::from_slice(&runtime_body).unwrap();
        assert_eq!(runtime_json["login_available"], false);
        assert!(runtime_json.get("belongs_to").is_none());
        assert!(runtime_json.get("client_secret").is_none());

        let jwks_response = runtime_router
            .oneshot(
                Request::get(format!(
                    "/projects/{}/.well-known/jwks.json",
                    created_project.public_id
                ))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(jwks_response.status(), StatusCode::OK);
        let jwks_json: serde_json::Value = serde_json::from_slice(
            &to_bytes(jwks_response.into_body(), 1_000_000)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(jwks_json["keys"], serde_json::json!([]));

        let current_application = provisioning
            .get_application(created_project.id, created_application.id)
            .await
            .expect("Application should remain available before disablement");
        let disabled_application = provisioning
            .disable_application(
                created_project.id,
                created_application.id,
                current_application.security_revision,
                Uuid::new_v4(),
            )
            .await
            .expect("Application disablement should commit atomically");
        assert_eq!(disabled_application.status, "disabled");
        assert_eq!(
            application_provider_assignment::Entity::find_by_id((
                created_project.id,
                created_application.id,
                provider.id,
            ))
            .one(control)
            .await
            .expect("assignment should be queryable")
            .expect("assignment should remain as terminal history")
            .status,
            "disabled"
        );
        assert_eq!(
            application_publishable_key::Entity::find()
                .filter(application_publishable_key::Column::ProjectId.eq(created_project.id))
                .filter(
                    application_publishable_key::Column::ApplicationId.eq(created_application.id),
                )
                .one(control)
                .await
                .expect("publishable key should be queryable")
                .expect("publishable key should remain as terminal history")
                .status,
            "disabled"
        );
        assert_eq!(
            provider_configuration::Entity::find_by_id(provider.id)
                .one(control)
                .await
                .expect("provider should be queryable")
                .expect("provider should remain configured")
                .status,
            "active"
        );
        assert_eq!(
            readiness
                .public_application_config(
                    &created_project.public_id,
                    &created_application.public_id,
                )
                .await,
            Err(ApplicationError::NotFound)
        );

        let current_project = provisioning
            .get_project(created_project.id)
            .await
            .expect("current Project metadata revision should be queryable");
        let unavailable_signer_key = provisioning
            .provision_signing_key(
                created_project.id,
                "signing-missing-material-12345678".to_owned(),
                current_project.metadata_revision,
                Uuid::new_v4(),
            )
            .await
            .expect("a key should publish before signer validation");
        readiness
            .project_jwks(&created_project.public_id)
            .await
            .expect("primary Runtime should observe the new revision");
        secondary_readiness
            .project_jwks(&created_project.public_id)
            .await
            .expect("secondary Runtime should observe the new revision");
        tokio::time::sleep(Duration::from_millis(1_050)).await;
        let expired_primary_lease = runtime_publication_lease::Entity::find()
            .filter(runtime_publication_lease::Column::ProjectId.eq(created_project.id))
            .filter(runtime_publication_lease::Column::ProcessId.eq("runtime-test-process"))
            .one(control)
            .await
            .expect("expired primary lease should be queryable")
            .expect("primary lease should exist");
        assert!(expired_primary_lease.expires_at <= time::OffsetDateTime::now_utc());
        assert_eq!(
            provisioning
                .activate_signing_key(
                    created_project.id,
                    unavailable_signer_key.id,
                    unavailable_signer_key.ring_revision,
                    Uuid::new_v4(),
                )
                .await,
            Err(ApplicationError::PublicationPending)
        );
        readiness
            .project_jwks(&created_project.public_id)
            .await
            .expect("primary Runtime should renew its stale lease");
        secondary_readiness
            .project_jwks(&created_project.public_id)
            .await
            .expect("secondary Runtime should renew its stale lease");
        let renewed_primary_lease = runtime_publication_lease::Entity::find()
            .filter(runtime_publication_lease::Column::ProjectId.eq(created_project.id))
            .filter(runtime_publication_lease::Column::ProcessId.eq("runtime-test-process"))
            .one(control)
            .await
            .expect("renewed primary lease should be queryable")
            .expect("primary lease should still exist");
        assert!(
            renewed_primary_lease.first_observed_at > expired_primary_lease.first_observed_at,
            "an expired same-revision lease starts a new propagation observation"
        );
        assert_eq!(
            renewed_primary_lease.first_observed_at,
            renewed_primary_lease.last_observed_at
        );
        tokio::time::sleep(Duration::from_millis(15)).await;
        let signer_model = project_signing_key::Entity::find_by_id(unavailable_signer_key.id)
            .one(control)
            .await
            .expect("signing key should be queryable")
            .expect("signing key should exist");
        std::fs::remove_file(signer_root.join(format!("{}.owls", signer_model.signer_ref)))
            .expect("signer material should be removable for the controlled failure");
        assert_eq!(
            provisioning
                .activate_signing_key(
                    created_project.id,
                    unavailable_signer_key.id,
                    unavailable_signer_key.ring_revision,
                    Uuid::new_v4(),
                )
                .await,
            Err(ApplicationError::Integrity)
        );

        let lease_before_disable = runtime_publication_lease::Entity::find()
            .filter(runtime_publication_lease::Column::ProjectId.eq(created_project.id))
            .filter(runtime_publication_lease::Column::ProcessId.eq("runtime-test-process"))
            .one(control)
            .await
            .expect("pre-disable lease should be queryable")
            .expect("pre-disable lease should exist");
        let disable_transaction = control
            .begin()
            .await
            .expect("disable race transaction should begin");
        let locked_project = project::Entity::find_by_id(created_project.id)
            .lock_exclusive()
            .one(&disable_transaction)
            .await
            .expect("Project should lock for disable race")
            .expect("Project should exist");
        let mut disabled = locked_project.into_active_model();
        disabled.status = Set("disabled".to_owned());
        disabled.security_revision = Set(created_project.security_revision + 1);
        disabled
            .update(&disable_transaction)
            .await
            .expect("uncommitted disable should update the locked Project");

        let raced_readiness = readiness.clone();
        let raced_project_public_id = created_project.public_id.clone();
        let jwks_read =
            tokio::spawn(
                async move { raced_readiness.project_jwks(&raced_project_public_id).await },
            );
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert!(
            !jwks_read.is_finished(),
            "JWKS read must serialize behind the Project disable lock"
        );
        disable_transaction
            .commit()
            .await
            .expect("Project disable race should commit");
        assert_eq!(
            jwks_read.await.expect("JWKS race task should join"),
            Err(ApplicationError::NotFound)
        );
        let lease_after_disable = runtime_publication_lease::Entity::find()
            .filter(runtime_publication_lease::Column::ProjectId.eq(created_project.id))
            .filter(runtime_publication_lease::Column::ProcessId.eq("runtime-test-process"))
            .one(control)
            .await
            .expect("post-disable lease should be queryable")
            .expect("post-disable lease should remain as history");
        assert_eq!(
            lease_after_disable.last_observed_at, lease_before_disable.last_observed_at,
            "a JWKS read that loses the disable race must not write a lease"
        );

        let mut capacity_sql = PgConnection::connect(&control_url)
            .await
            .expect("capacity fixture connection should open");
        let project_count: i64 = sqlx::query_scalar("SELECT count(*) FROM projects")
            .fetch_one(&mut capacity_sql)
            .await
            .expect("Project count should be queryable");
        assert!(project_count < 100, "capacity fixture needs room to fill");
        let filler_project_ids = (project_count..99)
            .map(|_| Uuid::new_v4())
            .collect::<Vec<_>>();
        let filler_project_public_ids = filler_project_ids
            .iter()
            .map(|id| format!("prj_capacity_{}", id.simple()))
            .collect::<Vec<_>>();
        sqlx::query(
            "INSERT INTO projects \
             (id, public_id, status, metadata_revision, security_revision) \
             SELECT seed.id, seed.public_id, 'active', 1, 1 \
             FROM UNNEST($1::uuid[], $2::text[]) AS seed(id, public_id)",
        )
        .bind(&filler_project_ids)
        .bind(&filler_project_public_ids)
        .execute(&mut capacity_sql)
        .await
        .expect("Project capacity fixtures should insert");

        let capacity_database = sea_orm::Database::connect(&control_url)
            .await
            .expect("capacity adapter pool should open");
        let capacity_adapter = PostgresProvisioningAdapter::new(
            capacity_database.clone(),
            url::Url::parse("https://identity.example/runtime/").unwrap(),
            Vec::new(),
            Duration::from_millis(10),
            Duration::from_secs(1),
        );
        let left_project_command = CreateProject {
            display_name: "Capacity winner left".to_owned(),
            belongs_to: None,
            idempotency_key: "project-capacity-left-12345678".to_owned(),
        };
        let right_project_command = CreateProject {
            display_name: "Capacity winner right".to_owned(),
            belongs_to: None,
            idempotency_key: "project-capacity-right-12345678".to_owned(),
        };
        let (left_project, right_project) = tokio::join!(
            capacity_adapter.create_project(left_project_command.clone(), Uuid::new_v4()),
            capacity_adapter.create_project(right_project_command.clone(), Uuid::new_v4()),
        );
        let (capacity_project, replay_project_command) = match (left_project, right_project) {
            (Ok(created), Err(ApplicationError::InvalidInput)) => (created, left_project_command),
            (Err(ApplicationError::InvalidInput), Ok(created)) => (created, right_project_command),
            outcomes => panic!("exactly one concurrent capacity create must commit: {outcomes:?}"),
        };
        assert_eq!(
            capacity_adapter
                .create_project(replay_project_command, Uuid::new_v4())
                .await
                .expect("completed Project replay must survive full capacity"),
            capacity_project
        );
        assert_eq!(
            capacity_adapter
                .create_project(
                    CreateProject {
                        display_name: "Over capacity".to_owned(),
                        belongs_to: None,
                        idempotency_key: "project-over-capacity-12345678".to_owned(),
                    },
                    Uuid::new_v4(),
                )
                .await,
            Err(ApplicationError::InvalidInput)
        );

        let first_application_command = CreateApplication {
            display_name: "Capacity replay application".to_owned(),
            application_type: ApplicationType::Web,
            idempotency_key: "application-capacity-replay-12345678".to_owned(),
        };
        let first_capacity_application = capacity_adapter
            .create_application(
                capacity_project.id,
                first_application_command.clone(),
                Uuid::new_v4(),
            )
            .await
            .expect("first capacity Application should commit");
        let filler_application_ids = (1..99).map(|_| Uuid::new_v4()).collect::<Vec<_>>();
        let filler_application_public_ids = filler_application_ids
            .iter()
            .map(|id| format!("app_capacity_{}", id.simple()))
            .collect::<Vec<_>>();
        sqlx::query(
            "INSERT INTO applications (id, project_id, public_id, status, revision) \
             SELECT seed.id, $3, seed.public_id, 'active', 1 \
             FROM UNNEST($1::uuid[], $2::text[]) AS seed(id, public_id)",
        )
        .bind(&filler_application_ids)
        .bind(&filler_application_public_ids)
        .bind(capacity_project.id)
        .execute(&mut capacity_sql)
        .await
        .expect("Application capacity fixtures should insert");
        let left_application_command = CreateApplication {
            display_name: "Capacity winner left".to_owned(),
            application_type: ApplicationType::Web,
            idempotency_key: "application-capacity-left-12345678".to_owned(),
        };
        let right_application_command = CreateApplication {
            display_name: "Capacity winner right".to_owned(),
            application_type: ApplicationType::Web,
            idempotency_key: "application-capacity-right-12345678".to_owned(),
        };
        let (left_application, right_application) = tokio::join!(
            capacity_adapter.create_application(
                capacity_project.id,
                left_application_command.clone(),
                Uuid::new_v4(),
            ),
            capacity_adapter.create_application(
                capacity_project.id,
                right_application_command.clone(),
                Uuid::new_v4(),
            ),
        );
        let (capacity_application, replay_application_command) = match (
            left_application,
            right_application,
        ) {
            (Ok(created), Err(ApplicationError::InvalidInput)) => {
                (created, left_application_command)
            }
            (Err(ApplicationError::InvalidInput), Ok(created)) => {
                (created, right_application_command)
            }
            outcomes => {
                panic!(
                    "exactly one concurrent Application capacity create must commit: {outcomes:?}"
                )
            }
        };
        assert_eq!(
            capacity_adapter
                .create_application(
                    capacity_project.id,
                    replay_application_command,
                    Uuid::new_v4(),
                )
                .await
                .expect("capacity-winning Application should replay at full capacity"),
            capacity_application
        );
        assert_eq!(
            capacity_adapter
                .create_application(
                    capacity_project.id,
                    first_application_command,
                    Uuid::new_v4(),
                )
                .await
                .expect("completed Application replay must survive full capacity"),
            first_capacity_application
        );

        let first_provider_command = PrepareProvider {
            provider_key: "capacity_replay".to_owned(),
            display_name: "Capacity replay provider".to_owned(),
            issuer: "https://accounts.example/".to_owned(),
            client_id: "capacity-client".to_owned(),
            operation_alias: "provider-capacity-replay-12345678".to_owned(),
            expected_project_revision: capacity_project.metadata_revision,
            request_digest: vec![31; 32],
        };
        let first_capacity_provider = capacity_adapter
            .prepare_provider(capacity_project.id, first_provider_command.clone())
            .await
            .expect("first capacity provider should prepare");
        let filler_provider_ids = (1..100).map(|_| Uuid::new_v4()).collect::<Vec<_>>();
        let filler_provider_keys = (1..100)
            .map(|index| format!("capacity_{index}"))
            .collect::<Vec<_>>();
        sqlx::query(
            "INSERT INTO provider_configurations \
             (id, project_id, provider_key, kind, display_name, issuer, client_id, \
              callback_url, secret_ref, status, revision) \
             SELECT seed.id, $3, seed.provider_key, 'oidc', 'Capacity provider', \
                    'https://accounts.example/', 'capacity-client', \
                    'https://identity.example/runtime/capacity/' || seed.provider_key, \
                    NULL, 'provisioning', 1 \
             FROM UNNEST($1::uuid[], $2::text[]) AS seed(id, provider_key)",
        )
        .bind(&filler_provider_ids)
        .bind(&filler_provider_keys)
        .bind(capacity_project.id)
        .execute(&mut capacity_sql)
        .await
        .expect("provider capacity fixtures should insert");
        assert!(matches!(
            capacity_adapter
                .prepare_provider(
                    capacity_project.id,
                    PrepareProvider {
                        provider_key: "capacity_overflow".to_owned(),
                        display_name: "Over capacity".to_owned(),
                        issuer: "https://accounts.example/".to_owned(),
                        client_id: "capacity-client".to_owned(),
                        operation_alias: "provider-over-capacity-12345678".to_owned(),
                        expected_project_revision: capacity_project.metadata_revision,
                        request_digest: vec![32; 32],
                    },
                )
                .await,
            Err(ApplicationError::InvalidInput)
        ));
        let replayed_capacity_provider = capacity_adapter
            .prepare_provider(capacity_project.id, first_provider_command)
            .await
            .expect("prepared provider replay must survive full capacity");
        assert_eq!(
            replayed_capacity_provider.provider_id,
            first_capacity_provider.provider_id
        );
        assert_eq!(
            replayed_capacity_provider.operation_id,
            first_capacity_provider.operation_id
        );

        let first_capacity_key = capacity_adapter
            .prepare_signing_key(
                capacity_project.id,
                "key-capacity-replay-12345678".to_owned(),
                "signer-capacity-replay-12345678".to_owned(),
                capacity_project.metadata_revision,
                vec![41; 32],
            )
            .await
            .expect("first capacity key should prepare");
        let filler_key_ids = (1..100).map(|_| Uuid::new_v4()).collect::<Vec<_>>();
        let filler_kids = filler_key_ids
            .iter()
            .map(|id| format!("kid_capacity_{}", id.simple()))
            .collect::<Vec<_>>();
        let filler_signer_refs = filler_key_ids
            .iter()
            .map(|id| format!("signer_capacity_{}", id.simple()))
            .collect::<Vec<_>>();
        sqlx::query(
            "INSERT INTO project_signing_keys \
             (id, project_id, ring_id, kid, public_jwk, signer_ref, state, ring_revision) \
             SELECT seed.id, $4, $5, seed.kid, '{}'::jsonb, seed.signer_ref, \
                    'provisioning', 1 \
             FROM UNNEST($1::uuid[], $2::text[], $3::text[]) \
                  AS seed(id, kid, signer_ref)",
        )
        .bind(&filler_key_ids)
        .bind(&filler_kids)
        .bind(&filler_signer_refs)
        .bind(capacity_project.id)
        .bind(first_capacity_key.ring_id)
        .execute(&mut capacity_sql)
        .await
        .expect("signing-key capacity fixtures should insert");
        assert!(matches!(
            capacity_adapter
                .prepare_signing_key(
                    capacity_project.id,
                    "key-over-capacity-12345678".to_owned(),
                    "signer-over-capacity-12345678".to_owned(),
                    capacity_project.metadata_revision,
                    vec![42; 32],
                )
                .await,
            Err(ApplicationError::InvalidInput)
        ));
        let replayed_capacity_key = capacity_adapter
            .prepare_signing_key(
                capacity_project.id,
                "key-capacity-replay-12345678".to_owned(),
                "signer-capacity-replay-12345678".to_owned(),
                capacity_project.metadata_revision,
                vec![41; 32],
            )
            .await
            .expect("prepared key replay must survive full capacity");
        assert_eq!(replayed_capacity_key.key_id, first_capacity_key.key_id);
        assert_eq!(
            replayed_capacity_key.operation_id,
            first_capacity_key.operation_id
        );

        sqlx::query(
            "UPDATE provider_configurations \
             SET secret_ref = 'capacity-secret', status = 'active' \
             WHERE id = ANY($1::uuid[])",
        )
        .bind(&filler_provider_ids[..51])
        .execute(&mut capacity_sql)
        .await
        .expect("assignment provider fixtures should activate");
        sqlx::query(
            "INSERT INTO application_provider_assignments \
             (project_id, application_id, provider_id, status, security_revision) \
             SELECT $2, $3, provider_id, 'active', 1 \
             FROM UNNEST($1::uuid[]) AS seed(provider_id)",
        )
        .bind(&filler_provider_ids[..50])
        .bind(capacity_project.id)
        .bind(first_capacity_application.id)
        .execute(&mut capacity_sql)
        .await
        .expect("assignment capacity fixtures should insert");
        assert_eq!(
            capacity_adapter
                .assign_provider(
                    capacity_project.id,
                    filler_provider_ids[50],
                    first_capacity_application.id,
                    first_capacity_application.security_revision,
                    Uuid::new_v4(),
                )
                .await,
            Err(ApplicationError::InvalidTransition)
        );
        capacity_sql
            .close()
            .await
            .expect("capacity fixture connection should close");
        capacity_database
            .close()
            .await
            .expect("capacity pool should close");

        std::fs::remove_dir_all(store_root).expect("temporary encrypted stores should clean up");
        pools.close().await;
    }
}
