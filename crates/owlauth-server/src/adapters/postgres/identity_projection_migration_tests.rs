use std::{collections::BTreeMap, env};

use sea_orm::{Database, EntityTrait, TransactionTrait};
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

async fn prior_schema_pool()
-> Option<(testcontainers::ContainerAsync<GenericImage>, PgPool, String)> {
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
    let database_url =
        format!("postgres://owlauth:owlauth_test@{host}:{port}/owlauth_migration_test");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
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
    Some((container, pool, database_url))
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the upgrade fixture keeps one complete pre-migration authority graph visible"
)]
async fn provider_users_upgrade_without_revision_or_projection_churn() {
    let Some((_container, pool, database_url)) = prior_schema_pool().await else {
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

    for migration in [
        include_str!("../../../migrations/20260801010000_passwordless_email.sql"),
        include_str!("../../../migrations/20260801020000_managed_provider_connections.sql"),
        include_str!("../../../migrations/20260801030000_identity_lifecycle_and_projection.sql"),
    ] {
        pool.execute(sqlx::raw_sql(migration))
            .await
            .expect("upgrade populated release N-1 schema");
    }

    let lifecycle_projection: serde_json::Value =
        sqlx::query_scalar("SELECT document FROM application_user_projections WHERE id=$1")
            .bind(projection_id)
            .fetch_one(&pool)
            .await
            .expect("load lifecycle-upgraded projection document");
    assert_eq!(
        lifecycle_projection, projection,
        "expand migration must not rewrite the populated projection directory"
    );
    let safe_document_constraint_validated: bool = sqlx::query_scalar(
        "SELECT convalidated FROM pg_constraint
          WHERE conrelid='application_user_projections'::regclass
            AND conname='application_user_projections_safe_document_check'",
    )
    .fetch_one(&pool)
    .await
    .expect("inspect safe-document expansion constraint");
    assert!(!safe_document_constraint_validated);

    let projection_email_authority: (i64, i32, Vec<i32>, Option<i32>) = sqlx::query_as(
        "SELECT authority_revision,write_version,accepted_versions,target_version
           FROM projection_email_key_authority WHERE singleton=TRUE",
    )
    .fetch_one(&pool)
    .await
    .expect("load populated-upgrade projection email key authority");
    assert_eq!(projection_email_authority, (1, 1, vec![1], None));
    let empty_acceptance = sqlx::query(
        "UPDATE projection_email_key_authority SET accepted_versions=ARRAY[]::INTEGER[]
          WHERE singleton=TRUE",
    )
    .execute(&pool)
    .await
    .expect_err("authority cannot lose its activated write version");
    assert_eq!(
        empty_acceptance
            .as_database_error()
            .and_then(|error| error.code().map(std::borrow::Cow::into_owned))
            .as_deref(),
        Some("23514")
    );
    let malformed_observation = sqlx::query(
        "INSERT INTO projection_email_runtime_observations
         (process_id,process_incarnation,authority_revision,readable_versions,observed_at,lease_expires_at)
         VALUES ('runtime-a',$1,1,ARRAY[]::INTEGER[],clock_timestamp(),clock_timestamp()+INTERVAL '1 minute')",
    )
    .bind(Uuid::new_v4())
    .execute(&pool)
    .await
    .expect_err("Runtime observation inventory cannot be empty");
    assert_eq!(
        malformed_observation
            .as_database_error()
            .and_then(|error| error.code().map(std::borrow::Cow::into_owned))
            .as_deref(),
        Some("23514")
    );

    // A release N-1 writer remains legal after schema N is installed. It may rewrite an existing
    // row to the exact old non-email shape or insert one for a newly observed Application.
    sqlx::query(
        "UPDATE application_user_projections
            SET document=$1,canonical_digest=$2,source_base_profile_digest=NULL
          WHERE id=$3",
    )
    .bind(&projection)
    .bind(&digest)
    .bind(projection_id)
    .execute(&pool)
    .await
    .expect("release N-1 projection update remains overlap-compatible after schema N");
    let overlap_application_id = Uuid::new_v4();
    let overlap_post_migration_binding_id = Uuid::new_v4();
    let overlap_post_migration_projection_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO applications
            (id,project_id,public_id,display_name,application_type,status,
             revision,metadata_revision,security_revision)
         VALUES ($1,$2,'app_overlap02','Overlap App','web','active',1,1,1)",
    )
    .bind(overlap_application_id)
    .bind(project_id)
    .execute(&pool)
    .await
    .expect("insert overlap Application after schema N");
    sqlx::query(
        "INSERT INTO application_user_bindings
            (id,project_id,application_id,user_id,status,binding_revision)
         VALUES ($1,$2,$3,$4,'active',1)",
    )
    .bind(overlap_post_migration_binding_id)
    .bind(project_id)
    .bind(overlap_application_id)
    .bind(user_id)
    .execute(&pool)
    .await
    .expect("insert overlap binding after schema N");
    sqlx::query(
        "INSERT INTO application_user_projections
            (id,project_id,binding_id,application_id,user_id,schema_name,
             projection_revision,source_user_revision,project_policy_revision,
             application_policy_revision,canonical_digest,document)
         VALUES ($1,$2,$3,$4,$5,'owlauth.user.v1',3,4,1,1,$6,$7)",
    )
    .bind(overlap_post_migration_projection_id)
    .bind(project_id)
    .bind(overlap_post_migration_binding_id)
    .bind(overlap_application_id)
    .bind(user_id)
    .bind(&digest)
    .bind(&projection)
    .execute(&pool)
    .await
    .expect("release N-1 projection insert remains overlap-compatible after schema N");

    let mut old_shape_with_null_schema = projection.clone();
    old_shape_with_null_schema["projection_schema"] = serde_json::Value::Null;
    let old_shape_error =
        sqlx::query("UPDATE application_user_projections SET document=$1 WHERE id=$2")
            .bind(&old_shape_with_null_schema)
            .bind(projection_id)
            .execute(&pool)
            .await
            .expect_err("old projection shape with null schema must fail");
    match old_shape_error {
        sqlx::Error::Database(database) => {
            assert_eq!(database.code().as_deref(), Some("23514"));
        }
        other => panic!("expected old-shape check violation, got {other:?}"),
    }

    let mut current_shape_with_null_schema = projection.clone();
    current_shape_with_null_schema["projection_schema"] = serde_json::Value::Null;
    current_shape_with_null_schema["locale"] = serde_json::Value::Null;
    current_shape_with_null_schema["verified_email"] = serde_json::Value::Null;
    let current_shape_error =
        sqlx::query("UPDATE application_user_projections SET document=$1 WHERE id=$2")
            .bind(&current_shape_with_null_schema)
            .bind(projection_id)
            .execute(&pool)
            .await
            .expect_err("current projection shape with null schema must fail");
    match current_shape_error {
        sqlx::Error::Database(database) => {
            assert_eq!(database.code().as_deref(), Some("23514"));
        }
        other => panic!("expected current-shape check violation, got {other:?}"),
    }

    // Exercise the production PostgreSQL lazy-repair operation. It must persist the canonical N
    // digest/document before delivery without treating storage normalization as a semantic change.
    let database = Database::connect(&database_url)
        .await
        .expect("connect SeaORM repair database");
    let transaction = database.begin().await.expect("begin projection repair");
    let user = super::entity::project_user::Entity::find_by_id(user_id)
        .one(&transaction)
        .await
        .expect("load repair user")
        .expect("repair user exists");
    let stored = super::entity::application_user_projection::Entity::find_by_id(projection_id)
        .one(&transaction)
        .await
        .expect("load stale overlap projection")
        .expect("stale overlap projection exists");
    let stale_digest = stored.canonical_digest.clone();
    let (repaired_model, repair) = super::projection::repair_projection(
        &transaction,
        stored,
        &user,
        1,
        1,
        time::OffsetDateTime::now_utc(),
    )
    .await
    .expect("repair N-1 projection through production repository path");
    transaction
        .commit()
        .await
        .expect("commit projection repair");
    assert!(repair.storage_repair_required);
    assert_eq!(repair.revision, 3);
    assert_ne!(repair.digest, stale_digest);
    assert_eq!(repaired_model.projection_revision, 3);
    assert_eq!(repaired_model.canonical_digest, repair.digest);
    assert_eq!(repaired_model.document, repair.storage_document);
    assert_eq!(
        repaired_model.source_base_profile_digest,
        Some(user.base_profile_digest)
    );

    // Exercise staged write authority, exact current-incarnation observations, stale-writer
    // rejection, referenced-version retirement, and restart-safe retirement authorization.
    let runtime_a = Uuid::new_v4();
    let runtime_b = Uuid::new_v4();
    for (process_id, incarnation) in [("runtime-a", runtime_a), ("runtime-b", runtime_b)] {
        sqlx::query(
            "INSERT INTO runtime_process_incarnations(process_id,process_incarnation,started_at)
             VALUES ($1,$2,clock_timestamp())",
        )
        .bind(process_id)
        .bind(incarnation)
        .execute(&pool)
        .await
        .expect("seed required Runtime incarnation");
    }
    let projection_protector =
        crate::adapters::runtime_security::SoftwareProjectionVerifiedEmailProtector::new(
            "migration-projection-authority".to_owned(),
            2,
            crate::adapters::runtime_security::RuntimeKeyMaterial::new([51; 32], [52; 32]),
            BTreeMap::from([(
                1,
                crate::adapters::runtime_security::RuntimeKeyMaterial::new([41; 32], [42; 32]),
            )]),
        )
        .expect("rotated projection protector");
    let authority = super::projection::PostgresProjectionEmailKeyAuthority::new(database.clone());
    let now = time::OffsetDateTime::now_utc();
    let required = vec!["runtime-a".to_owned(), "runtime-b".to_owned()];
    for invalid_retention in [
        time::Duration::microseconds(1),
        time::Duration::microseconds(1_500),
        time::Duration::milliseconds(86_400_001),
    ] {
        assert_eq!(
            authority
                .reconcile(
                    &required,
                    &projection_protector,
                    Some(2),
                    None,
                    invalid_retention,
                )
                .await,
            Err(crate::application::ApplicationError::InvalidInput),
            "retention must be a positive whole-millisecond duration bounded to one day"
        );
    }
    assert_eq!(
        authority
            .reconcile(
                &required,
                &projection_protector,
                Some(2),
                None,
                time::Duration::milliseconds(200),
            )
            .await,
        Err(crate::application::ApplicationError::Disabled),
        "first rollout stages but cannot cut over without observations"
    );
    for invalid_lease in [
        time::Duration::ZERO,
        time::Duration::microseconds(1_500),
        time::Duration::milliseconds(86_400_001),
    ] {
        assert_eq!(
            authority
                .observe_runtime("runtime-a", runtime_a, &projection_protector, invalid_lease,)
                .await,
            Err(crate::application::ApplicationError::InvalidInput),
            "authority leases must be positive whole-millisecond durations bounded to one day"
        );
    }
    let database_before_observation: time::OffsetDateTime =
        sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&pool)
            .await
            .expect("read PostgreSQL clock before observation");
    // There is deliberately no legacy observed-at/expiry argument to skew: the only temporal
    // input is a bounded duration, and PostgreSQL authors both absolute timestamps.
    authority
        .observe_runtime(
            "runtime-a",
            runtime_a,
            &projection_protector,
            time::Duration::minutes(1),
        )
        .await
        .expect("first Runtime observes staged authority");
    let database_after_observation: time::OffsetDateTime =
        sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&pool)
            .await
            .expect("read PostgreSQL clock after observation");
    let (observed_at, lease_expires_at): (time::OffsetDateTime, time::OffsetDateTime) =
        sqlx::query_as(
            "SELECT observed_at,lease_expires_at
               FROM projection_email_runtime_observations
              WHERE process_id='runtime-a' AND process_incarnation=$1",
        )
        .bind(runtime_a)
        .fetch_one(&pool)
        .await
        .expect("read database-authored observation timestamps");
    assert!(observed_at >= database_before_observation);
    assert!(observed_at <= database_after_observation);
    assert_eq!(
        lease_expires_at - observed_at,
        time::Duration::minutes(1),
        "PostgreSQL must derive expiry solely from the validated duration"
    );
    assert_eq!(
        authority
            .reconcile(
                &required,
                &projection_protector,
                Some(2),
                None,
                time::Duration::milliseconds(200),
            )
            .await,
        Err(crate::application::ApplicationError::Disabled),
        "one missing required Runtime blocks cutover"
    );
    authority
        .observe_runtime(
            "runtime-b",
            runtime_b,
            &projection_protector,
            time::Duration::minutes(1),
        )
        .await
        .expect("second Runtime observes staged authority");
    authority
        .reconcile(
            &required,
            &projection_protector,
            Some(2),
            None,
            time::Duration::milliseconds(200),
        )
        .await
        .expect("all required Runtime observations permit cutover");

    let stale_writer =
        crate::adapters::runtime_security::SoftwareProjectionVerifiedEmailProtector::new(
            "migration-projection-authority".to_owned(),
            1,
            crate::adapters::runtime_security::RuntimeKeyMaterial::new([41; 32], [42; 32]),
            BTreeMap::new(),
        )
        .expect("stale projection writer");
    let stale_transaction = database.begin().await.expect("begin stale writer check");
    assert_eq!(
        super::projection::assert_projection_write_authority(&stale_transaction, &stale_writer,)
            .await,
        Err(crate::application::ApplicationError::Disabled)
    );
    stale_transaction
        .rollback()
        .await
        .expect("rollback stale writer check");
    for (process_id, incarnation) in [("runtime-a", runtime_a), ("runtime-b", runtime_b)] {
        authority
            .observe_runtime(
                process_id,
                incarnation,
                &projection_protector,
                time::Duration::minutes(1),
            )
            .await
            .expect("Runtime observes activated write authority");
    }

    let retained_email_identity_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO email_identities
         (id,project_id,user_id,status,identity_revision,canonicalization_version,
          address_ciphertext,address_key_version,verified_at,created_at,updated_at)
         VALUES ($1,$2,$3,'active',1,1,$4,1,$5,$5,$5)",
    )
    .bind(retained_email_identity_id)
    .bind(project_id)
    .bind(user_id)
    .bind(vec![8_u8; 41])
    .bind(now)
    .execute(&pool)
    .await
    .expect("seed retained durable email source");
    sqlx::query(
        "UPDATE application_user_projections
            SET verified_email_source_identity_id=$1,
                verified_email_ciphertext=$2,verified_email_key_version=1
          WHERE id=$3",
    )
    .bind(retained_email_identity_id)
    .bind(vec![9_u8; 40])
    .bind(projection_id)
    .execute(&pool)
    .await
    .expect("seed retained-version projection reference");
    assert_eq!(
        authority
            .reconcile(
                &required,
                &projection_protector,
                None,
                Some(1),
                time::Duration::milliseconds(200),
            )
            .await,
        Err(crate::application::ApplicationError::Disabled),
        "referenced projection key cannot enter retirement"
    );
    sqlx::query(
        "UPDATE application_user_projections
            SET verified_email_source_identity_id=NULL,
                verified_email_ciphertext=NULL,verified_email_key_version=NULL
          WHERE id=$1",
    )
    .bind(projection_id)
    .execute(&pool)
    .await
    .expect("eliminate retained-version projection reference");
    assert_eq!(
        authority
            .reconcile(
                &required,
                &projection_protector,
                None,
                Some(1),
                time::Duration::milliseconds(200),
            )
            .await,
        Err(crate::application::ApplicationError::Disabled),
        "retirement authorization must survive its safety interval"
    );
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    authority
        .reconcile(
            &required,
            &projection_protector,
            None,
            Some(1),
            time::Duration::milliseconds(200),
        )
        .await
        .expect("unreferenced retained version retires after PostgreSQL-measured safety interval");
    let retired_authority: (i32, Vec<i32>) = sqlx::query_as(
        "SELECT write_version,accepted_versions FROM projection_email_key_authority
          WHERE singleton=TRUE",
    )
    .fetch_one(&pool)
    .await
    .expect("load retired projection authority");
    assert_eq!(retired_authority, (2, vec![2]));

    let post_migration_overlap_keys: i64 = sqlx::query_scalar(
        "SELECT count(*)
           FROM application_user_projections AS projection,
                LATERAL jsonb_object_keys(projection.document)
          WHERE projection.id=$1",
    )
    .bind(overlap_post_migration_projection_id)
    .fetch_one(&pool)
    .await
    .expect("load post-migration N-1 projection");
    assert_eq!(post_migration_overlap_keys, 9);
}
