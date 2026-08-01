use std::env;

use sqlx::{Executor, PgPool, postgres::PgPoolOptions};
use testcontainers::{
    GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor, wait::LogWaitStrategy},
    runners::AsyncRunner,
};
use uuid::Uuid;

const POSTGRES_PORT: u16 = 5432;

fn docker_is_required() -> bool {
    env::var("OWLAUTH_REQUIRE_DOCKER").is_ok_and(|value| value == "1")
}

async fn prior_schema_pool() -> Option<(testcontainers::ContainerAsync<GenericImage>, PgPool)> {
    let wait = WaitFor::log(LogWaitStrategy::stderr(
        "database system is ready to accept connections",
    ));
    let container = match GenericImage::new("postgres", "17-bookworm")
        .with_exposed_port(POSTGRES_PORT.tcp())
        .with_wait_for(wait)
        .with_env_var("POSTGRES_DB", "owlauth_migration_test")
        .with_env_var("POSTGRES_USER", "owlauth")
        .with_env_var("POSTGRES_PASSWORD", "owlauth_test")
        .start()
        .await
    {
        Ok(container) => container,
        Err(error) => {
            assert!(
                !docker_is_required(),
                "PostgreSQL migration test container is required: {error}"
            );
            eprintln!("skipping identity projection migration test: Docker unavailable: {error}");
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
            "postgres://owlauth:owlauth_test@{host}:{port}/owlauth_migration_test"
        ))
        .await
        .expect("connect migration test database");
    for migration in [
        include_str!("../../../migrations/20260729000000_project_application_core.sql"),
        include_str!("../../../migrations/20260730000000_control_provisioning_readiness.sql"),
        include_str!("../../../migrations/20260730010000_policy_signing_safety.sql"),
        include_str!("../../../migrations/20260730020000_federated_auth_foundation.sql"),
        include_str!("../../../migrations/20260730030000_block_a_data_hardening.sql"),
    ] {
        pool.execute(sqlx::raw_sql(migration))
            .await
            .expect("apply prior released migration");
    }
    Some((container, pool))
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the upgrade fixture keeps one complete pre-migration authority graph visible"
)]
async fn provider_users_upgrade_without_revision_or_projection_churn() {
    let Some((_container, pool)) = prior_schema_pool().await else {
        return;
    };
    let project_id = Uuid::new_v4();
    let application_id = Uuid::new_v4();
    let provider_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let identity_id = Uuid::new_v4();
    let binding_id = Uuid::new_v4();
    let projection_id = Uuid::new_v4();
    let digest = vec![7_u8; 32];
    let projection = serde_json::json!({
        "created_at": "2026-08-01T00:00:00Z",
        "display_name": "Ada",
        "picture_url": null,
        "projection_revision": 3,
        "projection_schema": "owlauth.user.v1",
        "status": "active",
        "updated_at": "2026-08-01T00:00:00Z",
        "user_id": "usr_upgrade01",
        "user_revision": 4
    });

    sqlx::query(
        "INSERT INTO projects
            (id, public_id, display_name, status, metadata_revision, security_revision)
         VALUES ($1, 'prj_upgrade01', 'Upgrade', 'active', 1, 1)",
    )
    .bind(project_id)
    .execute(&pool)
    .await
    .expect("seed Project");
    sqlx::query(
        "INSERT INTO applications
            (id, project_id, public_id, display_name, application_type, status,
             revision, metadata_revision, security_revision)
         VALUES ($1, $2, 'app_upgrade01', 'Upgrade App', 'web', 'active', 1, 1, 1)",
    )
    .bind(application_id)
    .bind(project_id)
    .execute(&pool)
    .await
    .expect("seed Application");
    sqlx::query(
        "INSERT INTO project_policies
            (project_id, claims_revision, session_revision, claims_policy, session_policy)
         VALUES ($1, 1, 1, '{\"access_token_lifetime_seconds\":900}'::jsonb,
             '{\"browser_session_reuse\":false,\"browser_session_reuse_max_age_seconds\":28800}'::jsonb)",
    )
    .bind(project_id)
    .execute(&pool)
    .await
    .expect("seed policy");
    sqlx::query(
        "INSERT INTO provider_configurations
            (id, project_id, provider_key, kind, display_name, issuer, client_id,
             callback_url, secret_ref, status, revision)
         VALUES ($1, $2, 'oidc-main', 'oidc', 'OIDC', 'https://issuer.example', 'client',
             'https://runtime.example/callback', 'secret/ref/upgrade', 'active', 1)",
    )
    .bind(provider_id)
    .bind(project_id)
    .execute(&pool)
    .await
    .expect("seed provider");
    sqlx::query(
        "INSERT INTO project_users
            (id, project_id, public_id, status, user_revision, security_revision,
             base_profile_digest, display_name, created_at, updated_at)
         VALUES ($1, $2, 'usr_upgrade01', 'active', 4, 2, $3, 'Ada',
             '2026-08-01T00:00:00Z', '2026-08-01T00:00:00Z')",
    )
    .bind(user_id)
    .bind(project_id)
    .bind(&digest)
    .execute(&pool)
    .await
    .expect("seed user");
    sqlx::query(
        "INSERT INTO linked_identities
            (id, project_id, user_id, created_via_provider_configuration_id, issuer, subject,
             status, identity_revision, display_name, observed_at, created_at, updated_at)
         VALUES ($1, $2, $3, $4, 'https://issuer.example', 'subject', 'active', 2, 'Ada',
             '2026-08-01T00:00:00Z', '2026-08-01T00:00:00Z', '2026-08-01T00:00:00Z')",
    )
    .bind(identity_id)
    .bind(project_id)
    .bind(user_id)
    .bind(provider_id)
    .execute(&pool)
    .await
    .expect("seed identity");
    sqlx::query("UPDATE project_users SET primary_profile_identity_id = $2 WHERE id = $1")
        .bind(user_id)
        .bind(identity_id)
        .execute(&pool)
        .await
        .expect("select primary identity");
    sqlx::query(
        "INSERT INTO application_user_bindings
            (id, project_id, application_id, user_id, status, binding_revision,
             created_at, updated_at)
         VALUES ($1, $2, $3, $4, 'active', 1,
             '2026-08-01T00:00:00Z', '2026-08-01T00:00:00Z')",
    )
    .bind(binding_id)
    .bind(project_id)
    .bind(application_id)
    .bind(user_id)
    .execute(&pool)
    .await
    .expect("seed binding");
    sqlx::query(
        "INSERT INTO application_user_projections
            (id, project_id, binding_id, application_id, user_id, schema_name,
             projection_revision, source_user_revision, project_policy_revision,
             application_policy_revision, canonical_digest, document, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, 'owlauth.user.v1', 3, 4, 1, 1, $6, $7,
             '2026-08-01T00:00:00Z', '2026-08-01T00:00:00Z')",
    )
    .bind(projection_id)
    .bind(project_id)
    .bind(binding_id)
    .bind(application_id)
    .bind(user_id)
    .bind(&digest)
    .bind(&projection)
    .execute(&pool)
    .await
    .expect("seed projection");

    pool.execute(sqlx::raw_sql(include_str!(
        "../../../migrations/20260801000000_identity_projection_foundation.sql"
    )))
    .await
    .expect("apply identity projection migration");

    let unvalidated_expand_constraints: i64 = sqlx::query_scalar(
        "SELECT count(*)
         FROM pg_constraint
         WHERE conname = ANY($1)
           AND NOT convalidated",
    )
    .bind(vec![
        "project_users_local_profile_shape_check",
        "project_users_primary_source_kind_check",
        "project_users_primary_source_shape_check",
        "linked_identities_source_kind_check",
        "linked_identities_source_schema_check",
        "linked_identities_source_profile_shape_check",
        "application_user_projections_source_digest_check",
    ])
    .fetch_one(&pool)
    .await
    .expect("inspect expand-phase constraints");
    assert_eq!(unvalidated_expand_constraints, 7);
    let fanout_indexes: (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT to_regclass('application_bindings_user_idx')::TEXT,
                to_regclass('application_user_bindings_user_fanout_idx')::TEXT",
    )
    .fetch_one(&pool)
    .await
    .expect("inspect bounded fan-out indexes");
    assert_eq!(
        fanout_indexes,
        (Some("application_bindings_user_idx".to_owned()), None)
    );

    let upgraded: (i64, i64, String, Option<Vec<u8>>, Option<String>, bool) = sqlx::query_as(
        "SELECT users.user_revision, projections.projection_revision,
                users.primary_source_kind, identities.source_profile_digest,
                users.local_display_name, users.local_display_name_set
         FROM project_users AS users
         JOIN linked_identities AS identities
           ON identities.project_id = users.project_id AND identities.id = users.primary_profile_identity_id
         JOIN application_user_projections AS projections
           ON projections.project_id = users.project_id AND projections.user_id = users.id
         WHERE users.project_id = $1 AND users.id = $2",
    )
    .bind(project_id)
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .expect("load upgraded identity projection");
    assert_eq!(upgraded.0, 4);
    assert_eq!(upgraded.1, 3);
    assert_eq!(upgraded.2, "provider");
    assert_eq!(upgraded.3, None);
    assert_eq!(upgraded.4, None);
    assert!(!upgraded.5);

    let upgraded_projection: (serde_json::Value, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT document, source_base_profile_digest
         FROM application_user_projections WHERE id = $1",
    )
    .bind(projection_id)
    .fetch_one(&pool)
    .await
    .expect("load upgraded projection document");
    assert_eq!(upgraded_projection.0, projection);
    assert_eq!(upgraded_projection.1, None);

    let overlap_user_id = Uuid::new_v4();
    let overlap_identity_id = Uuid::new_v4();
    let overlap_binding_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO project_users
            (id, project_id, public_id, status, user_revision, security_revision,
             base_profile_digest, display_name)
         VALUES ($1, $2, 'usr_overlap01', 'active', 1, 1, $3, 'Grace')",
    )
    .bind(overlap_user_id)
    .bind(project_id)
    .bind(vec![9_u8; 32])
    .execute(&pool)
    .await
    .expect("release N-1 user insert remains compatible");
    sqlx::query(
        "INSERT INTO linked_identities
            (id, project_id, user_id, created_via_provider_configuration_id, issuer, subject,
             status, identity_revision, display_name, observed_at)
         VALUES ($1, $2, $3, $4, 'https://issuer.example', 'overlap-subject',
             'active', 1, 'Grace', transaction_timestamp())",
    )
    .bind(overlap_identity_id)
    .bind(project_id)
    .bind(overlap_user_id)
    .bind(provider_id)
    .execute(&pool)
    .await
    .expect("release N-1 identity insert remains compatible");
    sqlx::query("UPDATE project_users SET primary_profile_identity_id = $2 WHERE id = $1")
        .bind(overlap_user_id)
        .bind(overlap_identity_id)
        .execute(&pool)
        .await
        .expect("release N-1 primary-source update remains compatible");
    sqlx::query(
        "INSERT INTO application_user_bindings
            (id, project_id, application_id, user_id, status, binding_revision)
         VALUES ($1, $2, $3, $4, 'active', 1)",
    )
    .bind(overlap_binding_id)
    .bind(project_id)
    .bind(application_id)
    .bind(overlap_user_id)
    .execute(&pool)
    .await
    .expect("release N-1 binding insert remains compatible");
    sqlx::query(
        "INSERT INTO application_user_projections
            (id, project_id, binding_id, application_id, user_id, schema_name,
             projection_revision, source_user_revision, project_policy_revision,
             application_policy_revision, canonical_digest, document)
         VALUES ($1, $2, $3, $4, $5, 'owlauth.user.v1', 1, 1, 1, 1, $6,
             '{\"overlap\":true}'::jsonb)",
    )
    .bind(Uuid::new_v4())
    .bind(project_id)
    .bind(overlap_binding_id)
    .bind(application_id)
    .bind(overlap_user_id)
    .bind(vec![8_u8; 32])
    .execute(&pool)
    .await
    .expect("release N-1 projection insert remains compatible");

    let locale_digest =
        super::projection::base_profile_digest(Some("Grace"), None, Some("en-US"), None)
            .expect("canonical Rust locale digest");
    sqlx::query(
        "UPDATE linked_identities
         SET locale = 'en-US', source_profile_digest = $2
         WHERE id = $1",
    )
    .bind(overlap_identity_id)
    .bind(locale_digest)
    .execute(&pool)
    .await
    .expect("release N identity update writes canonical locale digest");
    sqlx::query("UPDATE linked_identities SET display_name = 'Grace Hopper' WHERE id = $1")
        .bind(overlap_identity_id)
        .execute(&pool)
        .await
        .expect("release N-1 profile update refreshes source digest");

    let overlap: (String, String, String, Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT users.primary_source_kind, identities.source_kind, identities.source_schema,
                identities.source_profile_digest, projections.source_base_profile_digest
         FROM project_users AS users
         JOIN linked_identities AS identities
           ON identities.project_id = users.project_id AND identities.user_id = users.id
         JOIN application_user_projections AS projections
           ON projections.project_id = users.project_id AND projections.user_id = users.id
         WHERE users.id = $1",
    )
    .bind(overlap_user_id)
    .fetch_one(&pool)
    .await
    .expect("load N-1 overlap defaults");
    assert_eq!(overlap.0, "provider");
    assert_eq!(overlap.1, "provider");
    assert_eq!(overlap.2, "owlauth.provider-profile.v1");
    assert_eq!(
        overlap.3,
        super::projection::base_profile_digest(Some("Grace Hopper"), None, Some("en-US"), None,)
            .expect("canonical Rust locale digest")
    );
    assert_eq!(overlap.4, vec![9_u8; 32]);
}
