pub(crate) mod entity;
pub(crate) mod provisioning;
pub(crate) mod readiness;
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
    use std::{collections::BTreeMap, env, sync::Arc, time::Duration};

    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode, header},
    };
    use crc::{CRC_32_ISO_HDLC, Crc};
    use sea_orm::{
        ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter,
        TransactionTrait,
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
                    application_provider_assignment, application_publishable_key, audit_event,
                    control_idempotency_record, key_provisioning_operation, key_state_event,
                    project, project_signing_key, provider_configuration,
                    provider_secret_operation,
                },
                provisioning::PostgresProvisioningAdapter,
                readiness::PostgresReadinessAdapter,
                unit_of_work::{CompleteIdempotency, NewProject, ProjectUnitOfWork},
            },
            software_store::EncryptedFileStore,
        },
        application::{
            ApplicationError, CreateApplication, CreateProject, CreateProvider,
            ProvisioningService, ReadinessService, ReplaceApplicationConfiguration, UpdateProject,
            UpdateProjectPolicy,
        },
        config::{MigrationMode, PlaneMode, ServerConfig},
        domain::ApplicationType,
        http::build_routers,
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
        let provisioning = ProvisioningService::new(Arc::new(PostgresProvisioningAdapter::new(
            control.clone(),
            signer_store.clone(),
            secret_store.clone(),
            url::Url::parse("https://identity.example/runtime/").unwrap(),
            vec![
                "runtime-test-process".to_owned(),
                "runtime-secondary-process".to_owned(),
            ],
            Duration::from_millis(10),
            Duration::from_secs(1),
        )));
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
        let restarted_provisioning =
            ProvisioningService::new(Arc::new(PostgresProvisioningAdapter::new(
                control.clone(),
                signer_store.clone(),
                secret_store.clone(),
                url::Url::parse("https://identity.example/runtime/").unwrap(),
                vec![
                    "runtime-test-process".to_owned(),
                    "runtime-secondary-process".to_owned(),
                ],
                Duration::from_millis(10),
                Duration::from_secs(1),
            )));
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
        let rotated_active_key = provisioning
            .activate_signing_key(
                created_project.id,
                rotating_key.id,
                rotating_key.ring_revision,
                Uuid::new_v4(),
            )
            .await
            .expect("rotation should activate exactly one new key");
        let retiring_key = provisioning
            .list_signing_keys(created_project.id)
            .await
            .expect("rotated keys should be queryable")
            .into_iter()
            .find(|key| key.id == active_key.id)
            .expect("the former active key should remain in the ring");
        assert_eq!(retiring_key.state, "retiring");
        assert!(retiring_key.verify_not_after.is_some());
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
        tokio::time::sleep(Duration::from_millis(1_050)).await;
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
        assert!(!public_config.login_available);
        assert_eq!(public_config.providers.len(), 1);
        assert_eq!(public_config.providers[0].key, "workforce");
        assert_eq!(public_config.publishable_keys.len(), 1);
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

        let unavailable_signer_key = provisioning
            .provision_signing_key(
                created_project.id,
                "signing-missing-material-12345678".to_owned(),
                created_project.metadata_revision,
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

        std::fs::remove_dir_all(store_root).expect("temporary encrypted stores should clean up");
        pools.close().await;
    }
}
