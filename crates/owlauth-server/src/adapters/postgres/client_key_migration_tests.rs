use std::env;

use sqlx::{PgPool, Row as _, postgres::PgPoolOptions};
use testcontainers::{
    GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor, wait::LogWaitStrategy},
    runners::AsyncRunner,
};
use uuid::Uuid;

const POSTGRES_PORT: u16 = 5432;
const CLIENT_KEY_SCHEMA_VERSION: i64 = 20_260_805_120_000;
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

fn docker_is_required() -> bool {
    env::var("OWLAUTH_REQUIRE_DOCKER").is_ok_and(|value| value == "1")
}

fn assert_check_violation(error: &sqlx::Error, expected_message: &str) {
    let database = error
        .as_database_error()
        .expect("expected PostgreSQL constraint error");
    assert_eq!(database.code().as_deref(), Some("23514"));
    assert!(
        database.message().contains(expected_message),
        "unexpected PostgreSQL error: {}",
        database.message()
    );
}

async fn pre_acknowledgement_pool() -> Option<(testcontainers::ContainerAsync<GenericImage>, PgPool)>
{
    let wait = WaitFor::log(LogWaitStrategy::stderr(
        "database system is ready to accept connections",
    ));
    let container = match GenericImage::new("postgres", "17-bookworm")
        .with_exposed_port(POSTGRES_PORT.tcp())
        .with_wait_for(wait)
        .with_env_var("POSTGRES_DB", "owlauth_client_key_migration_test")
        .with_env_var("POSTGRES_USER", "owlauth")
        .with_env_var("POSTGRES_PASSWORD", "owlauth_test")
        .start()
        .await
    {
        Ok(container) => container,
        Err(error) => {
            assert!(
                !docker_is_required(),
                "PostgreSQL client-key migration test container is required: {error}"
            );
            eprintln!("skipping client-key migration test: Docker unavailable: {error}");
            return None;
        }
    };
    let host = container.get_host().await.expect("container host");
    let port = container
        .get_host_port_ipv4(POSTGRES_PORT)
        .await
        .expect("container port");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&format!(
            "postgres://owlauth:owlauth_test@{host}:{port}/owlauth_client_key_migration_test"
        ))
        .await
        .expect("connect client-key migration test database");
    let pre_acknowledgement = sqlx::migrate::Migrator::with_migrations(
        MIGRATOR
            .iter()
            .filter(|migration| migration.version <= CLIENT_KEY_SCHEMA_VERSION)
            .cloned()
            .collect(),
    );
    pre_acknowledgement
        .run(&pool)
        .await
        .expect("apply migrations through initial client-key schema");
    Some((container, pool))
}

#[allow(
    clippy::too_many_arguments,
    reason = "upgrade rows expose every legacy lifecycle column at each auditable fixture call"
)]
async fn insert_key(
    pool: &PgPool,
    project_id: Uuid,
    key_id: Uuid,
    public_key_id: &str,
    label: &str,
    status: &str,
    revision: i64,
    created_at: &str,
    revoked_at: Option<&str>,
) {
    sqlx::query(
        "INSERT INTO project_client_keys
            (id,project_id,public_key_id,label,status,digest_key_version,credential_digest,
             display_prefix,revision,created_at,revoked_at)
         VALUES ($1,$2,$3,$4,$5,1,$6,'owl_client_v1.' || $3,$7,$8::timestamptz,$9::timestamptz)",
    )
    .bind(key_id)
    .bind(project_id)
    .bind(public_key_id)
    .bind(label)
    .bind(status)
    .bind(vec![7_u8; 32])
    .bind(revision)
    .bind(created_at)
    .bind(revoked_at)
    .execute(pool)
    .await
    .expect("insert pre-acknowledgement client key");
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one real upgrade fixture proves backfill and every database lifecycle transition together"
)]
async fn acknowledgement_upgrade_backfills_history_and_enforces_new_insert_and_update_protocol() {
    let Some((_container, pool)) = pre_acknowledgement_pool().await else {
        return;
    };
    let project_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO projects(id,public_id,display_name,status,metadata_revision,security_revision)
         VALUES ($1,'prj_client_key_migration','Client Key Migration','active',1,1)",
    )
    .bind(project_id)
    .execute(&pool)
    .await
    .expect("insert migration Project");

    let historical_active = Uuid::new_v4();
    let historical_revoked = Uuid::new_v4();
    insert_key(
        &pool,
        project_id,
        historical_active,
        "AAAAAAAAAAAAAAAAAAAAAA",
        "historical active",
        "active",
        1,
        "2026-08-05T12:00:00Z",
        None,
    )
    .await;
    insert_key(
        &pool,
        project_id,
        historical_revoked,
        "BBBBBBBBBBBBBBBBBBBBBB",
        "historical revoked",
        "revoked",
        2,
        "2026-08-05T12:00:00Z",
        Some("2026-08-05T12:01:00Z"),
    )
    .await;

    MIGRATOR
        .run(&pool)
        .await
        .expect("apply delivery-acknowledgement migration");

    let active = sqlx::query(
        "SELECT created_at,credential_acknowledged_at
           FROM project_client_keys WHERE id=$1",
    )
    .bind(historical_active)
    .fetch_one(&pool)
    .await
    .expect("read backfilled active key");
    assert_eq!(
        active
            .try_get::<time::OffsetDateTime, _>("created_at")
            .expect("created_at"),
        active
            .try_get::<time::OffsetDateTime, _>("credential_acknowledged_at")
            .expect("credential acknowledgement")
    );
    let revoked_acknowledgement = sqlx::query_scalar::<_, Option<time::OffsetDateTime>>(
        "SELECT credential_acknowledged_at FROM project_client_keys WHERE id=$1",
    )
    .bind(historical_revoked)
    .fetch_one(&pool)
    .await
    .expect("read historical revoked key");
    assert!(revoked_acknowledgement.is_none());

    let forged_insert = sqlx::query(
        "INSERT INTO project_client_keys
            (id,project_id,public_key_id,label,status,digest_key_version,credential_digest,
             display_prefix,revision,credential_acknowledged_at)
         VALUES ($1,$2,'CCCCCCCCCCCCCCCCCCCCCC','forged acknowledged','active',1,$3,
                 'owl_client_v1.' || 'CCCCCCCCCCCCCCCCCCCCCC',1,transaction_timestamp())",
    )
    .bind(Uuid::new_v4())
    .bind(project_id)
    .bind(vec![8_u8; 32])
    .execute(&pool)
    .await
    .expect_err("new key must not start acknowledged");
    assert_check_violation(
        &forged_insert,
        "new project client key delivery cannot start acknowledged",
    );

    let current_key = Uuid::new_v4();
    insert_key(
        &pool,
        project_id,
        current_key,
        "DDDDDDDDDDDDDDDDDDDDDD",
        "current key",
        "active",
        1,
        "2026-08-05T13:00:00Z",
        None,
    )
    .await;
    let initial_acknowledgement = sqlx::query_scalar::<_, Option<time::OffsetDateTime>>(
        "SELECT credential_acknowledged_at FROM project_client_keys WHERE id=$1",
    )
    .bind(current_key)
    .fetch_one(&pool)
    .await
    .expect("read current key");
    assert!(initial_acknowledgement.is_none());

    sqlx::query(
        "UPDATE project_client_keys
            SET credential_acknowledged_at='2026-08-05T13:01:00Z',revision=2
          WHERE id=$1",
    )
    .bind(current_key)
    .execute(&pool)
    .await
    .expect("acknowledge current key");

    let clear =
        sqlx::query("UPDATE project_client_keys SET credential_acknowledged_at=NULL WHERE id=$1")
            .bind(current_key)
            .execute(&pool)
            .await
            .expect_err("acknowledgement cannot be cleared");
    assert_check_violation(&clear, "invalid project client key usage update");
    let rewrite = sqlx::query(
        "UPDATE project_client_keys
            SET credential_acknowledged_at='2026-08-05T13:02:00Z'
          WHERE id=$1",
    )
    .bind(current_key)
    .execute(&pool)
    .await
    .expect_err("acknowledgement cannot be rewritten");
    assert_check_violation(&rewrite, "invalid project client key usage update");

    sqlx::query(
        "UPDATE project_client_keys
            SET status='revoked',revoked_at='2026-08-05T13:02:00Z',revision=3
          WHERE id=$1",
    )
    .bind(current_key)
    .execute(&pool)
    .await
    .expect("revoke acknowledged key");
    let mutate_revoked =
        sqlx::query("UPDATE project_client_keys SET label='mutated revoked' WHERE id=$1")
            .bind(current_key)
            .execute(&pool)
            .await
            .expect_err("revoked key must be terminal");
    assert_check_violation(&mutate_revoked, "revoked project client key is immutable");
}
