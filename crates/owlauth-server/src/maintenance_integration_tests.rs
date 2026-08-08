use std::env;

use sqlx::postgres::PgPoolOptions;
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
};

use super::{
    MaintenanceError, PRUNE_APPLICATION_SESSION_AGGREGATES, PRUNE_REFRESH_TOKEN_GENERATIONS,
    PruneOptions, delete_count, prune, prune_pool,
};

const POSTGRES_PORT: u16 = 5432;

fn docker_is_required() -> bool {
    env::var("OWLAUTH_REQUIRE_DOCKER").is_ok_and(|value| value == "1")
}

async fn start_postgres() -> Option<(ContainerAsync<GenericImage>, String)> {
    let container = match GenericImage::new("postgres", "17-bookworm")
        .with_exposed_port(POSTGRES_PORT.tcp())
        .with_wait_for(WaitFor::message_on_stderr(
            "database system is ready to accept connections",
        ))
        .with_env_var("POSTGRES_DB", "owlauth_maintenance_test")
        .with_env_var("POSTGRES_USER", "owlauth")
        .with_env_var("POSTGRES_PASSWORD", "owlauth_test")
        .start()
        .await
    {
        Ok(container) => container,
        Err(error) => {
            assert!(
                !docker_is_required(),
                "PostgreSQL maintenance test container is required: {error}"
            );
            eprintln!("skipping maintenance integration test: Docker unavailable: {error}");
            return None;
        }
    };
    let host = container.get_host().await.expect("container host");
    let port = container
        .get_host_port_ipv4(POSTGRES_PORT)
        .await
        .expect("container port");
    Some((
        container,
        format!("postgres://owlauth:owlauth_test@{host}:{port}/owlauth_maintenance_test"),
    ))
}

#[tokio::test]
async fn exact_released_schema_prunes_representative_production_graphs() {
    let Some((_container, database_url)) = start_postgres().await else {
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .expect("maintenance test database");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("install exact released schema");
    sqlx::raw_sql(include_str!("maintenance_production_fixture.sql"))
        .execute(&pool)
        .await
        .expect("seed production-schema retention graphs");

    let report = prune(&database_url, PruneOptions { batch_size: 100 })
        .await
        .expect("exact released schema should pass maintenance verification");
    assert_eq!(report.refresh_token_generations, 1);
    assert_eq!(report.application_session_aggregates, 1);
    assert_eq!(report.smtp_test_operations, 1);
    assert_eq!(report.webhook_records, 3);
    assert_eq!(report.total, 6);

    let retained_counts: (i64, i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT
           (SELECT COUNT(*) FROM application_sessions),
           (SELECT COUNT(*) FROM refresh_families),
           (SELECT COUNT(*) FROM refresh_token_generations),
           (SELECT COUNT(*) FROM project_smtp_test_operations),
           (SELECT COUNT(*) FROM protected_materials
             WHERE id='10000000-0000-0000-0000-000000000017'),
           (SELECT COUNT(*) FROM application_user_events),
           (SELECT COUNT(*) FROM webhook_deliveries),
           (SELECT COUNT(*) FROM webhook_delivery_attempts)",
    )
    .fetch_one(&pool)
    .await
    .expect("inspect production-schema retention results");
    assert_eq!(retained_counts, (0, 0, 0, 0, 0, 0, 0, 0));
}

#[tokio::test]
async fn refresh_generations_are_bounded_before_session_deletion() {
    let Some((_container, database_url)) = start_postgres().await else {
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .expect("maintenance test database");
    sqlx::raw_sql(
        r"
        CREATE TABLE application_sessions (
            id uuid PRIMARY KEY,
            absolute_expires_at timestamptz NOT NULL
        );
        CREATE TABLE project_browser_logout_interactions (
            id uuid PRIMARY KEY,
            application_session_id uuid NOT NULL REFERENCES application_sessions(id)
        );
        CREATE TABLE refresh_families (
            id uuid PRIMARY KEY,
            application_session_id uuid NOT NULL REFERENCES application_sessions(id) ON DELETE CASCADE
        );
        CREATE TABLE refresh_token_generations (
            id uuid PRIMARY KEY,
            family_id uuid NOT NULL REFERENCES refresh_families(id) ON DELETE CASCADE,
            retain_until timestamptz NOT NULL
        );
        INSERT INTO application_sessions VALUES
          ('00000000-0000-0000-0000-000000000060',transaction_timestamp()-interval '2 days');
        INSERT INTO refresh_families VALUES
          ('00000000-0000-0000-0000-000000000061','00000000-0000-0000-0000-000000000060');
        INSERT INTO refresh_token_generations VALUES
          ('00000000-0000-0000-0000-000000000062','00000000-0000-0000-0000-000000000061',transaction_timestamp()-interval '1 day'),
          ('00000000-0000-0000-0000-000000000063','00000000-0000-0000-0000-000000000061',transaction_timestamp()-interval '1 day');
        ",
    )
    .execute(&pool)
    .await
    .expect("create bounded refresh fixtures");

    assert_eq!(
        delete_count(&pool, PRUNE_REFRESH_TOKEN_GENERATIONS, 1)
            .await
            .expect("first bounded generation batch"),
        1
    );
    assert_eq!(
        delete_count(&pool, PRUNE_APPLICATION_SESSION_AGGREGATES, 1)
            .await
            .expect("session remains while one generation exists"),
        0
    );
    assert_eq!(
        delete_count(&pool, PRUNE_REFRESH_TOKEN_GENERATIONS, 1)
            .await
            .expect("second bounded generation batch"),
        1
    );
    assert_eq!(
        delete_count(&pool, PRUNE_APPLICATION_SESSION_AGGREGATES, 1)
            .await
            .expect("session becomes eligible after generations are empty"),
        1
    );
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the retention integration scenario keeps its related schema, fixtures, and assertions together"
)]
async fn prune_is_bounded_cascading_and_idempotent() {
    let Some((_container, database_url)) = start_postgres().await else {
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .expect("maintenance test database");

    sqlx::raw_sql(
        r"
        CREATE TABLE login_transactions (
            id uuid PRIMARY KEY,
            expires_at timestamptz NOT NULL
        );
        CREATE TABLE email_challenges (
            id uuid PRIMARY KEY,
            transaction_id uuid NOT NULL REFERENCES login_transactions(id) ON DELETE CASCADE
        );
        CREATE TABLE mail_outbox (
            id uuid PRIMARY KEY,
            challenge_id uuid NOT NULL REFERENCES email_challenges(id) ON DELETE CASCADE
        );

        CREATE TABLE identity_mutation_intents (
            id uuid PRIMARY KEY,
            expires_at timestamptz NOT NULL
        );
        CREATE TABLE identity_mutation_proof_slots (
            id uuid PRIMARY KEY,
            intent_id uuid NOT NULL REFERENCES identity_mutation_intents(id) ON DELETE CASCADE
        );
        CREATE TABLE project_user_merge_tombstones (
            identity_mutation_intent_id uuid NOT NULL REFERENCES identity_mutation_intents(id)
        );

        CREATE TABLE managed_provider_reauthorization_interactions (
            id uuid PRIMARY KEY,
            expires_at timestamptz NOT NULL
        );
        CREATE TABLE managed_reauthorization_create_results (
            id uuid PRIMARY KEY,
            interaction_id uuid NOT NULL REFERENCES managed_provider_reauthorization_interactions(id) ON DELETE CASCADE
        );

        CREATE TABLE project_browser_sessions (
            id uuid PRIMARY KEY,
            absolute_expires_at timestamptz NOT NULL
        );
        CREATE TABLE handoff_tickets (
            id uuid PRIMARY KEY,
            login_transaction_id uuid NOT NULL REFERENCES login_transactions(id) ON DELETE CASCADE,
            browser_session_id uuid NOT NULL REFERENCES project_browser_sessions(id)
        );
        CREATE TABLE application_sessions (
            id uuid PRIMARY KEY,
            browser_session_id uuid REFERENCES project_browser_sessions(id),
            absolute_expires_at timestamptz NOT NULL
        );
        CREATE TABLE project_browser_logout_interactions (
            id uuid PRIMARY KEY,
            application_session_id uuid NOT NULL REFERENCES application_sessions(id),
            browser_session_id uuid NOT NULL REFERENCES project_browser_sessions(id),
            expires_at timestamptz NOT NULL
        );
        CREATE TABLE refresh_families (
            id uuid PRIMARY KEY,
            application_session_id uuid NOT NULL REFERENCES application_sessions(id) ON DELETE CASCADE
        );
        CREATE TABLE refresh_token_generations (
            id uuid PRIMARY KEY,
            family_id uuid NOT NULL REFERENCES refresh_families(id) ON DELETE CASCADE,
            retain_until timestamptz NOT NULL
        );

        CREATE TABLE protected_materials (
            id uuid PRIMARY KEY,
            owner_kind text NOT NULL,
            state text NOT NULL
        );
        CREATE TABLE project_smtp_test_operations (
            id uuid PRIMARY KEY,
            state text NOT NULL,
            recipient_erased_at timestamptz,
            completed_at timestamptz,
            recipient_material_id uuid NOT NULL REFERENCES protected_materials(id)
        );

        CREATE TABLE application_user_events (
            id uuid PRIMARY KEY,
            retain_until timestamptz NOT NULL
        );
        CREATE TABLE webhook_deliveries (
            id uuid PRIMARY KEY,
            event_id uuid NOT NULL REFERENCES application_user_events(id),
            state text NOT NULL,
            terminal_at timestamptz,
            updated_at timestamptz NOT NULL,
            created_at timestamptz NOT NULL,
            replay_sequence integer NOT NULL DEFAULT 0,
            replay_of_delivery_id uuid REFERENCES webhook_deliveries(id)
        );
        CREATE TABLE webhook_delivery_attempts (
            delivery_id uuid NOT NULL REFERENCES webhook_deliveries(id),
            attempt_number integer NOT NULL,
            PRIMARY KEY (delivery_id,attempt_number)
        );

        INSERT INTO login_transactions VALUES
          ('00000000-0000-0000-0000-000000000001',transaction_timestamp()-interval '2 days'),
          ('00000000-0000-0000-0000-000000000002',transaction_timestamp()+interval '10 minutes');
        INSERT INTO email_challenges VALUES
          ('00000000-0000-0000-0000-000000000003','00000000-0000-0000-0000-000000000001');
        INSERT INTO mail_outbox VALUES
          ('00000000-0000-0000-0000-000000000004','00000000-0000-0000-0000-000000000003');

        INSERT INTO identity_mutation_intents VALUES
          ('00000000-0000-0000-0000-000000000010',transaction_timestamp()-interval '2 days'),
          ('00000000-0000-0000-0000-000000000011',transaction_timestamp()-interval '2 days'),
          ('00000000-0000-0000-0000-000000000012',transaction_timestamp()+interval '10 minutes');
        INSERT INTO identity_mutation_proof_slots VALUES
          ('00000000-0000-0000-0000-000000000013','00000000-0000-0000-0000-000000000010');
        INSERT INTO project_user_merge_tombstones VALUES
          ('00000000-0000-0000-0000-000000000011');

        INSERT INTO managed_provider_reauthorization_interactions VALUES
          ('00000000-0000-0000-0000-000000000020',transaction_timestamp()-interval '2 days'),
          ('00000000-0000-0000-0000-000000000021',transaction_timestamp()+interval '10 minutes');
        INSERT INTO managed_reauthorization_create_results VALUES
          ('00000000-0000-0000-0000-000000000022','00000000-0000-0000-0000-000000000020');

        INSERT INTO project_browser_sessions VALUES
          ('00000000-0000-0000-0000-000000000030',transaction_timestamp()-interval '2 days'),
          ('00000000-0000-0000-0000-000000000031',transaction_timestamp()+interval '1 day'),
          ('00000000-0000-0000-0000-000000000037',transaction_timestamp()-interval '2 days');
        INSERT INTO handoff_tickets VALUES
          ('00000000-0000-0000-0000-000000000038','00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000037');
        INSERT INTO application_sessions VALUES
          ('00000000-0000-0000-0000-000000000032','00000000-0000-0000-0000-000000000030',transaction_timestamp()-interval '2 days'),
          ('00000000-0000-0000-0000-000000000033','00000000-0000-0000-0000-000000000031',transaction_timestamp()+interval '30 days'),
          ('00000000-0000-0000-0000-000000000039',NULL,transaction_timestamp()-interval '2 days');
        INSERT INTO project_browser_logout_interactions VALUES
          ('00000000-0000-0000-0000-000000000034','00000000-0000-0000-0000-000000000032','00000000-0000-0000-0000-000000000030',transaction_timestamp()-interval '2 days');
        INSERT INTO refresh_families VALUES
          ('00000000-0000-0000-0000-000000000035','00000000-0000-0000-0000-000000000032'),
          ('00000000-0000-0000-0000-000000000045','00000000-0000-0000-0000-000000000039');
        INSERT INTO refresh_token_generations VALUES
          ('00000000-0000-0000-0000-000000000036','00000000-0000-0000-0000-000000000035',transaction_timestamp()-interval '1 day'),
          ('00000000-0000-0000-0000-000000000046','00000000-0000-0000-0000-000000000045',transaction_timestamp()+interval '1 day');

        INSERT INTO protected_materials VALUES
          ('00000000-0000-0000-0000-000000000040','smtp_test_recipient','erased'),
          ('00000000-0000-0000-0000-000000000041','smtp_test_recipient','erased');
        INSERT INTO project_smtp_test_operations VALUES
          ('00000000-0000-0000-0000-000000000042','delivered',transaction_timestamp()-interval '2 days',transaction_timestamp()-interval '2 days','00000000-0000-0000-0000-000000000040'),
          ('00000000-0000-0000-0000-000000000043','delivered',transaction_timestamp(),transaction_timestamp(),'00000000-0000-0000-0000-000000000041');

        INSERT INTO application_user_events VALUES
          ('00000000-0000-0000-0000-000000000050',transaction_timestamp()-interval '1 day'),
          ('00000000-0000-0000-0000-000000000051',transaction_timestamp()+interval '30 days');
        INSERT INTO webhook_deliveries
          (id,event_id,state,terminal_at,updated_at,created_at,replay_sequence)
        VALUES
          ('00000000-0000-0000-0000-000000000052','00000000-0000-0000-0000-000000000050','delivered',transaction_timestamp()-interval '1 day',transaction_timestamp()-interval '1 day',transaction_timestamp()-interval '31 days',0);
        INSERT INTO webhook_delivery_attempts VALUES
          ('00000000-0000-0000-0000-000000000052',1);
        ",
    )
    .execute(&pool)
    .await
    .expect("create retention fixtures");

    let verification_error = prune(&database_url, PruneOptions { batch_size: 100 })
        .await
        .expect_err("look-alike schema must fail before retention DML");
    assert!(matches!(
        verification_error,
        MaintenanceError::SchemaVerification
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM login_transactions")
            .fetch_one(&pool)
            .await
            .expect("schema rejection must leave eligible rows untouched"),
        2
    );

    let report = prune_pool(&pool, PruneOptions { batch_size: 100 })
        .await
        .expect("prune eligible fixtures through the verified core");
    assert_eq!(report.login_aggregates, 1);
    assert_eq!(report.browser_logout_interactions, 1);
    assert_eq!(report.refresh_token_generations, 1);
    assert_eq!(report.application_session_aggregates, 1);
    assert_eq!(report.browser_session_aggregates, 1);
    assert_eq!(report.smtp_test_operations, 1);
    assert_eq!(report.webhook_records, 3);
    assert_eq!(report.total, 9);

    let counts: (i64, i64, i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT
           (SELECT COUNT(*) FROM login_transactions),
           (SELECT COUNT(*) FROM email_challenges),
           (SELECT COUNT(*) FROM identity_mutation_intents),
           (SELECT COUNT(*) FROM managed_provider_reauthorization_interactions),
           (SELECT COUNT(*) FROM application_sessions),
           (SELECT COUNT(*) FROM project_browser_sessions),
           (SELECT COUNT(*) FROM handoff_tickets),
           (SELECT COUNT(*) FROM project_smtp_test_operations),
           (SELECT COUNT(*) FROM application_user_events)",
    )
    .fetch_one(&pool)
    .await
    .expect("inspect retained fixtures");
    assert_eq!(counts, (1, 0, 3, 2, 2, 2, 1, 1, 1));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM protected_materials WHERE id='00000000-0000-0000-0000-000000000040'",
        )
        .fetch_one(&pool)
        .await
        .expect("inspect erased SMTP recipient material"),
        0
    );

    let second = prune_pool(&pool, PruneOptions { batch_size: 100 })
        .await
        .expect("repeat maintenance safely");
    assert_eq!(second.total, 0);
}
