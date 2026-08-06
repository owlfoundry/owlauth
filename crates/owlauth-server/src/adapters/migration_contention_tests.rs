use std::{env, fs, path::PathBuf, time::Duration};

use sqlx::{Connection, PgConnection, migrate::Migrator};
use testcontainers::{
    GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor, wait::LogWaitStrategy},
    runners::AsyncRunner,
};
use uuid::Uuid;

use super::{SchemaError, close_migration_connection, configure_migration_timeouts, run_migrator};

const POSTGRES_PORT: u16 = 5432;

struct MigrationDirectory(PathBuf);

impl MigrationDirectory {
    fn new() -> Self {
        let path = env::temp_dir().join(format!("owlauth-migration-contention-{}", Uuid::new_v4()));
        fs::create_dir_all(&path).expect("migration fixture directory should be created");
        Self(path)
    }

    fn write(&self, version: &str, description: &str, sql: &str) {
        fs::write(self.0.join(format!("{version}_{description}.sql")), sql)
            .expect("migration fixture should be written");
    }

    async fn migrator(&self) -> Migrator {
        Migrator::new(self.0.as_path())
            .await
            .expect("migration fixture should load")
    }
}

impl Drop for MigrationDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn docker_is_required() -> bool {
    env::var("OWLAUTH_REQUIRE_DOCKER").is_ok_and(|value| value == "1")
}

async fn connect(url: &str) -> PgConnection {
    PgConnection::connect(url)
        .await
        .expect("PostgreSQL test connection should open")
}

async fn backend_exists(observer: &mut PgConnection, process_id: i32) -> bool {
    sqlx::query_scalar::<_, bool>("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid=$1)")
        .bind(process_id)
        .fetch_one(observer)
        .await
        .expect("backend state should be observable")
}

async fn wait_for_backend_exit(observer: &mut PgConnection, process_id: i32) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while backend_exists(observer, process_id).await {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("closed migration backend should disappear");
}

#[allow(
    clippy::too_many_lines,
    reason = "one real backend preserves ordered DDL-lock, statement, cancellation, cleanup, and retry evidence"
)]
#[tokio::test]
async fn migration_timeouts_rollback_cleanup_and_retry_against_real_postgres() {
    let wait = WaitFor::log(LogWaitStrategy::stderr(
        "database system is ready to accept connections",
    ));
    let container = match GenericImage::new("postgres", "17-bookworm")
        .with_exposed_port(POSTGRES_PORT.tcp())
        .with_wait_for(wait)
        .with_env_var("POSTGRES_DB", "owlauth_migration_contention")
        .with_env_var("POSTGRES_USER", "owlauth")
        .with_env_var("POSTGRES_PASSWORD", "owlauth_test")
        .start()
        .await
    {
        Ok(container) => container,
        Err(error) => {
            assert!(
                !docker_is_required(),
                "PostgreSQL migration contention test is required but Docker failed: {error}"
            );
            eprintln!("skipping PostgreSQL migration contention test: {error}");
            return;
        }
    };
    let host = container.get_host().await.expect("container host");
    let port = container
        .get_host_port_ipv4(POSTGRES_PORT)
        .await
        .expect("container port");
    let url = format!("postgres://owlauth:owlauth_test@{host}:{port}/owlauth_migration_contention");
    let migrations = MigrationDirectory::new();
    migrations.write(
        "20260801000000",
        "create_lock_target",
        "CREATE TABLE migration_lock_target (id BIGINT PRIMARY KEY, value TEXT NOT NULL);\n\
         INSERT INTO migration_lock_target (id,value)\n\
         SELECT value, repeat('x', 128) FROM generate_series(1, 1000) AS value;",
    );

    let mut initial = connect(&url).await;
    configure_migration_timeouts(&mut initial, Duration::from_secs(5), Duration::from_secs(5))
        .await
        .expect("initial migration timeouts should configure");
    run_migrator(
        &mut initial,
        &migrations.migrator().await,
        Duration::from_secs(10),
    )
    .await
    .expect("initial migration should apply");
    initial.close().await.expect("initial backend should close");

    migrations.write(
        "20260801010000",
        "expand_lock_target",
        "ALTER TABLE migration_lock_target ADD COLUMN expanded_value BIGINT;",
    );
    let expanded = migrations.migrator().await;
    let mut blocker = connect(&url).await;
    sqlx::query("BEGIN")
        .execute(&mut blocker)
        .await
        .expect("blocker transaction should begin");
    sqlx::query("SELECT id FROM migration_lock_target WHERE id=1 FOR UPDATE")
        .execute(&mut blocker)
        .await
        .expect("blocker should hold a table-conflicting lock");

    let mut subject = connect(&url).await;
    let subject_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut subject)
        .await
        .expect("subject backend ID");
    configure_migration_timeouts(
        &mut subject,
        Duration::from_millis(100),
        Duration::from_secs(5),
    )
    .await
    .expect("DDL contention timeouts should configure");
    assert_eq!(
        run_migrator(&mut subject, &expanded, Duration::from_secs(10))
            .await
            .expect_err("database lock timeout must fail the blocked migration"),
        SchemaError::LockTimeout
    );

    let mut observer = connect(&url).await;
    let applied_versions: Vec<i64> =
        sqlx::query_scalar("SELECT version FROM _sqlx_migrations WHERE success ORDER BY version")
            .fetch_all(&mut observer)
            .await
            .expect("successful migration history should be readable");
    assert_eq!(applied_versions, vec![20_260_801_000_000]);
    let expanded_column_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1 FROM information_schema.columns
              WHERE table_schema='public' AND table_name='migration_lock_target'
                AND column_name='expanded_value'
         )",
    )
    .fetch_one(&mut observer)
    .await
    .expect("failed DDL state should be observable");
    assert!(!expanded_column_exists);
    assert!(backend_exists(&mut observer, subject_pid).await);
    subject
        .close()
        .await
        .expect("failed migration backend should close");
    wait_for_backend_exit(&mut observer, subject_pid).await;

    sqlx::query("ROLLBACK")
        .execute(&mut blocker)
        .await
        .expect("blocker should release its transaction");
    blocker.close().await.expect("blocker backend should close");
    let mut retry = connect(&url).await;
    configure_migration_timeouts(&mut retry, Duration::from_secs(5), Duration::from_secs(5))
        .await
        .expect("retry timeouts should configure");
    run_migrator(&mut retry, &expanded, Duration::from_secs(10))
        .await
        .expect("operator retry should apply the exact pending migration");
    retry.close().await.expect("retry backend should close");

    migrations.write(
        "20260801020000",
        "statement_deadline",
        "SELECT pg_sleep(1);",
    );
    let statement_timeout = migrations.migrator().await;
    let mut statement_subject = connect(&url).await;
    configure_migration_timeouts(
        &mut statement_subject,
        Duration::from_secs(5),
        Duration::from_millis(100),
    )
    .await
    .expect("statement timeout should configure");
    assert_eq!(
        run_migrator(
            &mut statement_subject,
            &statement_timeout,
            Duration::from_secs(10),
        )
        .await
        .expect_err("database statement timeout must cancel the migration"),
        SchemaError::StatementTimeout
    );
    statement_subject
        .close()
        .await
        .expect("statement-timeout backend should close");
    let timed_out_history: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version=20260801020000)",
    )
    .fetch_one(&mut observer)
    .await
    .expect("statement-timeout history should be observable");
    assert!(!timed_out_history);

    fs::write(
        migrations.0.join("20260801020000_statement_deadline.sql"),
        "SELECT 1;",
    )
    .expect("statement-timeout retry fixture should be replaced");
    let mut statement_retry = connect(&url).await;
    configure_migration_timeouts(
        &mut statement_retry,
        Duration::from_secs(5),
        Duration::from_secs(5),
    )
    .await
    .expect("statement retry timeouts should configure");
    run_migrator(
        &mut statement_retry,
        &migrations.migrator().await,
        Duration::from_secs(10),
    )
    .await
    .expect("explicit retry should apply after statement remediation");
    statement_retry
        .close()
        .await
        .expect("statement retry backend should close");

    migrations.write(
        "20260801030000",
        "outer_deadline",
        "SET LOCAL statement_timeout='0'; SELECT pg_sleep(2);",
    );
    let outer_deadline = migrations.migrator().await;
    let mut deadline_subject = connect(&url).await;
    let deadline_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut deadline_subject)
        .await
        .expect("deadline backend ID");
    configure_migration_timeouts(
        &mut deadline_subject,
        Duration::from_secs(5),
        Duration::from_secs(5),
    )
    .await
    .expect("outer deadline session should configure");
    assert_eq!(
        run_migrator(
            &mut deadline_subject,
            &outer_deadline,
            Duration::from_millis(100),
        )
        .await
        .expect_err("outer migration guard must cancel loss of control"),
        SchemaError::Deadline
    );
    close_migration_connection(deadline_subject, Duration::from_millis(500))
        .await
        .expect("outer-deadline backend should close within the cleanup bound");
    wait_for_backend_exit(&mut observer, deadline_pid).await;
    let deadline_history: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version=20260801030000)",
    )
    .fetch_one(&mut observer)
    .await
    .expect("outer-deadline history should be observable");
    assert!(!deadline_history);
    observer
        .close()
        .await
        .expect("observer backend should close");
}
