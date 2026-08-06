use std::env;

use sqlx::{PgPool, Postgres, Transaction, postgres::PgPoolOptions};
use testcontainers::{
    GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor, wait::LogWaitStrategy},
    runners::AsyncRunner,
};
use uuid::Uuid;

const POSTGRES_PORT: u16 = 5432;
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[allow(
    clippy::struct_field_names,
    reason = "explicit relational role names keep migration fixture binds auditable"
)]
struct AuthorityFixture {
    project_id: Uuid,
    application_id: Uuid,
    provider_id: Uuid,
    winner_user_id: Uuid,
    winner_identity_id: Uuid,
    loser_user_id: Uuid,
}

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

async fn migrated_pool() -> Option<(testcontainers::ContainerAsync<GenericImage>, PgPool)> {
    let wait = WaitFor::log(LogWaitStrategy::stderr(
        "database system is ready to accept connections",
    ));
    let container = match GenericImage::new("postgres", "17-bookworm")
        .with_exposed_port(POSTGRES_PORT.tcp())
        .with_wait_for(wait)
        .with_env_var("POSTGRES_DB", "owlauth_identity_lifecycle_test")
        .with_env_var("POSTGRES_USER", "owlauth")
        .with_env_var("POSTGRES_PASSWORD", "owlauth_test")
        .start()
        .await
    {
        Ok(container) => container,
        Err(error) => {
            assert!(
                !docker_is_required(),
                "PostgreSQL identity lifecycle test container is required: {error}"
            );
            eprintln!("skipping identity lifecycle migration test: Docker unavailable: {error}");
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
            "postgres://owlauth:owlauth_test@{host}:{port}/owlauth_identity_lifecycle_test"
        ))
        .await
        .expect("connect identity lifecycle migration test database");
    MIGRATOR
        .run(&pool)
        .await
        .expect("apply complete migration set");
    Some((container, pool))
}

async fn seed_user_with_provider_identity(
    pool: &PgPool,
    project_id: Uuid,
    provider_id: Uuid,
    suffix: &str,
) -> (Uuid, Uuid) {
    let user_id = Uuid::new_v4();
    let identity_id = Uuid::new_v4();
    let mut transaction = pool.begin().await.expect("begin user seed");
    sqlx::query(
        "INSERT INTO project_users
            (id,project_id,public_id,status,user_revision,security_revision,
             base_profile_digest,display_name)
         VALUES ($1,$2,$3,'active',1,1,$4,$5)",
    )
    .bind(user_id)
    .bind(project_id)
    .bind(format!("usr_{suffix}"))
    .bind(vec![7_u8; 32])
    .bind(format!("User {suffix}"))
    .execute(&mut *transaction)
    .await
    .expect("insert Project user");
    sqlx::query(
        "INSERT INTO linked_identities
            (id,project_id,user_id,created_via_provider_configuration_id,issuer,subject,
             status,identity_revision,source_profile_digest,observed_at)
         VALUES ($1,$2,$3,$4,'https://issuer.example',$5,'active',1,public.owlauth_provider_source_profile_digest(NULL,NULL,NULL),
                 transaction_timestamp())",
    )
    .bind(identity_id)
    .bind(project_id)
    .bind(user_id)
    .bind(provider_id)
    .bind(format!("subject-{suffix}"))
    .execute(&mut *transaction)
    .await
    .expect("insert provider identity");
    sqlx::query("UPDATE project_users SET primary_profile_identity_id=$2 WHERE id=$1")
        .bind(user_id)
        .bind(identity_id)
        .execute(&mut *transaction)
        .await
        .expect("select primary provider identity");
    transaction.commit().await.expect("commit user seed");
    (user_id, identity_id)
}

async fn seed_authority(pool: &PgPool) -> AuthorityFixture {
    let project_id = Uuid::new_v4();
    let application_id = Uuid::new_v4();
    let provider_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO projects
            (id,public_id,status,metadata_revision,security_revision)
         VALUES ($1,$2,'active',1,1)",
    )
    .bind(project_id)
    .bind(format!("prj_{project_id}"))
    .execute(pool)
    .await
    .expect("insert Project");
    sqlx::query(
        "INSERT INTO applications
            (id,project_id,public_id,status,revision,metadata_revision,security_revision)
         VALUES ($1,$2,$3,'active',1,1,1)",
    )
    .bind(application_id)
    .bind(project_id)
    .bind(format!("app_{application_id}"))
    .execute(pool)
    .await
    .expect("insert Application");
    sqlx::query(
        "INSERT INTO project_policies
            (project_id,claims_revision,session_revision,claims_policy,session_policy)
         VALUES ($1,1,1,'{\"access_token_lifetime_seconds\":900}'::jsonb,
                 '{\"browser_session_reuse\":false,
                    \"browser_session_reuse_max_age_seconds\":28800}'::jsonb)",
    )
    .bind(project_id)
    .execute(pool)
    .await
    .expect("insert Project policy");
    sqlx::query(
        "WITH material AS (
             INSERT INTO protected_materials
                (id,scope_kind,project_id,owner_kind,owner_id,generation,material_kind,
                 provider_id,provider_format_version,context_version,context_digest,
                 opaque_value,safe_fingerprint,state)
             VALUES (gen_random_uuid(),'project',$2,'provider_secret',$1,1,
                     'configuration_secret','software',1,1,
                     decode(repeat('03',32),'hex'),decode('01','hex'),
                     decode(repeat('02',32),'hex'),'live')
             RETURNING id
         )
         INSERT INTO provider_configurations
            (id,project_id,provider_key,kind,display_name,issuer,client_id,callback_url,
             secret_material_id,status,revision)
         SELECT $1,$2,'oidc-main','oidc','OIDC','https://issuer.example','client',
                'https://runtime.example/callback',material.id,'active',1 FROM material",
    )
    .bind(provider_id)
    .bind(project_id)
    .execute(pool)
    .await
    .expect("insert provider");
    sqlx::query(
        "INSERT INTO application_provider_assignments
            (project_id,application_id,provider_id,status,security_revision)
         VALUES ($1,$2,$3,'active',1)",
    )
    .bind(project_id)
    .bind(application_id)
    .bind(provider_id)
    .execute(pool)
    .await
    .expect("assign provider");
    let (winner_user_id, winner_identity_id) =
        seed_user_with_provider_identity(pool, project_id, provider_id, "winner01").await;
    let (loser_user_id, _) =
        seed_user_with_provider_identity(pool, project_id, provider_id, "loser01").await;
    AuthorityFixture {
        project_id,
        application_id,
        provider_id,
        winner_user_id,
        winner_identity_id,
        loser_user_id,
    }
}

async fn insert_link_intent(
    transaction: &mut Transaction<'_, Postgres>,
    fixture: &AuthorityFixture,
    intent_id: Uuid,
) {
    insert_unbound_link_intent(transaction, fixture, intent_id).await;
    sqlx::query(
        "UPDATE identity_mutation_intents
            SET browser_binding_digest=$1,browser_binding_digest_key_version=1,
                csrf_digest=$2,csrf_digest_key_version=1,browser_binding_revision=1,
                intent_revision=2,updated_at=transaction_timestamp()
          WHERE id=$3 AND intent_revision=1",
    )
    .bind(vec![2_u8; 32])
    .bind(vec![3_u8; 32])
    .bind(intent_id)
    .execute(&mut **transaction)
    .await
    .expect("bind link intent once");
}

async fn insert_unbound_link_intent(
    transaction: &mut Transaction<'_, Postgres>,
    fixture: &AuthorityFixture,
    intent_id: Uuid,
) {
    let hosted_digest = intent_id
        .as_bytes()
        .iter()
        .copied()
        .cycle()
        .take(32)
        .collect::<Vec<_>>();
    sqlx::query(
        "INSERT INTO identity_mutation_intents
            (id,project_id,operation_kind,status,intent_revision,
             project_metadata_revision,project_security_revision,
             destination_user_id,destination_user_revision,
             destination_user_security_revision,primary_source_disposition,
             hosted_handle_digest,hosted_handle_digest_key_version,
             correlation_id,expires_at)
         VALUES ($1,$2,'link','pending_proof',1,1,1,$3,1,1,'preserve',
                 $4,1,$5,transaction_timestamp()+INTERVAL '10 minutes')",
    )
    .bind(intent_id)
    .bind(fixture.project_id)
    .bind(fixture.winner_user_id)
    .bind(hosted_digest)
    .bind(Uuid::new_v4())
    .execute(&mut **transaction)
    .await
    .expect("insert unbound link intent");
}

#[allow(
    clippy::too_many_arguments,
    reason = "migration helper exposes every constrained slot dimension at its call site"
)]
async fn insert_provider_slot(
    transaction: &mut Transaction<'_, Postgres>,
    fixture: &AuthorityFixture,
    intent_id: Uuid,
    slot_id: Uuid,
    ordinal: i16,
    role: &str,
    purpose: &str,
    existing_identity_id: Option<Uuid>,
) {
    insert_provider_slot_for_user(
        transaction,
        fixture,
        intent_id,
        slot_id,
        ordinal,
        role,
        purpose,
        fixture.winner_user_id,
        existing_identity_id,
    )
    .await;
}

#[allow(
    clippy::too_many_arguments,
    reason = "merge proof fixtures require the exact frozen winner or loser owner"
)]
async fn insert_provider_slot_for_user(
    transaction: &mut Transaction<'_, Postgres>,
    fixture: &AuthorityFixture,
    intent_id: Uuid,
    slot_id: Uuid,
    ordinal: i16,
    role: &str,
    purpose: &str,
    proof_user_id: Uuid,
    existing_identity_id: Option<Uuid>,
) {
    sqlx::query(
        "INSERT INTO identity_mutation_proof_slots
            (id,project_id,intent_id,slot_ordinal,slot_role,purpose,identity_kind,
             proof_user_id,expected_user_revision,expected_user_security_revision,
             existing_provider_identity_id,expected_identity_revision,
             application_id,application_security_revision,method_kind,
             provider_adapter_key,provider_adapter_capability_revision,
             provider_configuration_id,provider_revision,
             provider_assignment_security_revision,provider_scopes,callback_url,
             provider_pkce_required,oidc_nonce_required,state,slot_revision)
         VALUES ($1,$2,$3,$4,$5,$6,'provider',$7,1,1,$8,$9,$10,1,'provider',
                 'oidc',1,$11,1,1,ARRAY['openid','profile']::text[],
                 'https://runtime.example/callback',false,true,'pending',1)",
    )
    .bind(slot_id)
    .bind(fixture.project_id)
    .bind(intent_id)
    .bind(ordinal)
    .bind(role)
    .bind(purpose)
    .bind(proof_user_id)
    .bind(existing_identity_id)
    .bind(existing_identity_id.map(|_| 1_i64))
    .bind(fixture.application_id)
    .bind(fixture.provider_id)
    .execute(&mut **transaction)
    .await
    .expect("insert provider proof slot");
}

async fn stage_synthetic_project_user_merge(
    transaction: &mut Transaction<'_, Postgres>,
    project_id: Uuid,
    loser_user_id: Uuid,
    winner_user_id: Uuid,
    winner_primary_identity_id: Uuid,
) {
    let correlation_id = Uuid::new_v4();
    sqlx::query("SET LOCAL session_replication_role='replica'")
        .execute(&mut **transaction)
        .await
        .expect("suspend non-graph authority triggers for merge race fixture");
    sqlx::query(
        "UPDATE linked_identities
            SET user_id=$1,identity_revision=identity_revision+1,
                updated_at=transaction_timestamp()
          WHERE project_id=$2 AND user_id=$3",
    )
    .bind(winner_user_id)
    .bind(project_id)
    .bind(loser_user_id)
    .execute(&mut **transaction)
    .await
    .expect("stage loser identity movement");
    sqlx::query(
        "UPDATE project_users
            SET status='merged',merged_into_user_id=$1,
                primary_profile_identity_id=NULL,primary_email_identity_id=NULL,
                updated_at=transaction_timestamp()
          WHERE project_id=$2 AND id=$3",
    )
    .bind(winner_user_id)
    .bind(project_id)
    .bind(loser_user_id)
    .execute(&mut **transaction)
    .await
    .expect("stage merged loser shape");
    sqlx::query(
        "INSERT INTO project_user_merge_tombstones
            (project_id,loser_user_id,winner_user_id,loser_user_revision,
             winner_user_revision,primary_source_kind,primary_provider_identity_id,
             primary_email_identity_id,sessions_disposition,bindings_disposition,
             merged_at,correlation_id,identity_mutation_intent_id)
         VALUES ($1,$2,$3,1,1,'provider',$4,NULL,'loser_revoked','winner_preferred',
                 transaction_timestamp(),$5,$6)",
    )
    .bind(project_id)
    .bind(loser_user_id)
    .bind(winner_user_id)
    .bind(winner_primary_identity_id)
    .bind(correlation_id)
    .bind(Uuid::new_v4())
    .execute(&mut **transaction)
    .await
    .expect("stage synthetic merge tombstone");
    sqlx::query("SET LOCAL session_replication_role='origin'")
        .execute(&mut **transaction)
        .await
        .expect("restore merge graph authority triggers");
    sqlx::query(
        "UPDATE project_users SET status=status
          WHERE project_id=$1 AND id=$2",
    )
    .bind(project_id)
    .bind(loser_user_id)
    .execute(&mut **transaction)
    .await
    .expect("queue final merge graph validation");
}

async fn create_valid_link_intent(pool: &PgPool, fixture: &AuthorityFixture) -> (Uuid, Uuid) {
    let intent_id = Uuid::new_v4();
    let owner_slot_id = Uuid::new_v4();
    let candidate_slot_id = Uuid::new_v4();
    let mut transaction = pool.begin().await.expect("begin valid intent");
    insert_link_intent(&mut transaction, fixture, intent_id).await;
    insert_provider_slot(
        &mut transaction,
        fixture,
        intent_id,
        owner_slot_id,
        1,
        "destination_owner",
        "link.destination_owner",
        Some(fixture.winner_identity_id),
    )
    .await;
    insert_provider_slot(
        &mut transaction,
        fixture,
        intent_id,
        candidate_slot_id,
        2,
        "candidate_identity",
        "link.candidate_identity",
        None,
    )
    .await;
    transaction
        .commit()
        .await
        .expect("commit valid link intent");
    (intent_id, candidate_slot_id)
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one PostgreSQL fixture validates the joined migration invariants atomically"
)]
async fn identity_lifecycle_schema_enforces_roles_callbacks_and_merge_attribution() {
    let Some((_container, pool)) = migrated_pool().await else {
        return;
    };
    let fixture = seed_authority(&pool).await;

    let forbidden_candidate_columns: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.columns
          WHERE table_schema=current_schema()
            AND table_name='identity_mutation_candidate_evidence'
            AND column_name = ANY($1)",
    )
    .bind(vec![
        "issuer",
        "subject",
        "normalized_email",
        "email_aliases",
        "display_name",
        "picture_url",
    ])
    .fetch_one(&pool)
    .await
    .expect("inspect candidate PII columns");
    assert_eq!(forbidden_candidate_columns, 0);

    let missing_slot_intent_id = Uuid::new_v4();
    let mut incomplete = pool.begin().await.expect("begin incomplete intent");
    insert_link_intent(&mut incomplete, &fixture, missing_slot_intent_id).await;
    insert_provider_slot(
        &mut incomplete,
        &fixture,
        missing_slot_intent_id,
        Uuid::new_v4(),
        1,
        "destination_owner",
        "link.destination_owner",
        Some(fixture.winner_identity_id),
    )
    .await;
    assert!(
        incomplete.commit().await.is_err(),
        "a link intent missing candidate_identity must fail at the deferred boundary"
    );

    let (intent_id, candidate_slot_id) = create_valid_link_intent(&pool, &fixture).await;
    let mut ownerless_callback = pool.begin().await.expect("begin ownerless callback");
    sqlx::query(
        "UPDATE identity_mutation_proof_slots
            SET state='provider_authorization_started',slot_revision=2,
                upstream_state_digest=$1,upstream_state_digest_key_version=1,
                oidc_nonce_digest=$2,oidc_nonce_digest_key_version=1,
                callback_continuation_ciphertext=decode(repeat('aa',64),'hex'),
                callback_continuation_key_version=1,
                provider_started_at=transaction_timestamp(),updated_at=transaction_timestamp()
          WHERE id=$3 AND intent_id=$4",
    )
    .bind(vec![4_u8; 32])
    .bind(vec![5_u8; 32])
    .bind(candidate_slot_id)
    .bind(intent_id)
    .execute(&mut *ownerless_callback)
    .await
    .expect("start ownerless callback before deferred check");
    assert!(
        ownerless_callback.commit().await.is_err(),
        "provider start without a typed callback owner must fail"
    );

    let mut owned_callback = pool.begin().await.expect("begin owned callback");
    sqlx::query(
        "UPDATE identity_mutation_proof_slots
            SET state='provider_authorization_started',slot_revision=2,
                upstream_state_digest=$1,upstream_state_digest_key_version=1,
                oidc_nonce_digest=$2,oidc_nonce_digest_key_version=1,
                callback_continuation_ciphertext=decode(repeat('aa',64),'hex'),
                callback_continuation_key_version=1,
                provider_started_at=transaction_timestamp(),updated_at=transaction_timestamp()
          WHERE id=$3 AND intent_id=$4",
    )
    .bind(vec![4_u8; 32])
    .bind(vec![5_u8; 32])
    .bind(candidate_slot_id)
    .bind(intent_id)
    .execute(&mut *owned_callback)
    .await
    .expect("start owned callback");
    sqlx::query(
        "INSERT INTO provider_callback_owners
            (state_id,project_id,provider_configuration_id,owner_kind,
             identity_mutation_intent_id,identity_mutation_proof_slot_id)
         VALUES ($1,$2,$3,'identity_mutation',$4,$1)",
    )
    .bind(candidate_slot_id)
    .bind(fixture.project_id)
    .bind(fixture.provider_id)
    .bind(intent_id)
    .execute(&mut *owned_callback)
    .await
    .expect("insert typed callback owner");
    owned_callback
        .commit()
        .await
        .expect("commit typed provider start");

    let replace_started_continuation = sqlx::query(
        "UPDATE identity_mutation_proof_slots
            SET callback_continuation_ciphertext=decode(repeat('bb',64),'hex'),
                slot_revision=3,updated_at=transaction_timestamp()
          WHERE id=$1 AND intent_id=$2",
    )
    .bind(candidate_slot_id)
    .bind(intent_id)
    .execute(&pool)
    .await;
    assert!(
        replace_started_continuation.is_err(),
        "started provider proof authority cannot replace its Hosted continuation"
    );

    let mut delete_live_owner = pool.begin().await.expect("begin callback owner deletion");
    sqlx::query("DELETE FROM provider_callback_owners WHERE state_id=$1")
        .bind(candidate_slot_id)
        .execute(&mut *delete_live_owner)
        .await
        .expect("delete owner before deferred check");
    assert!(
        delete_live_owner.commit().await.is_err(),
        "a started callback cannot lose its typed owner"
    );

    let binding_id = Uuid::new_v4();
    let projection_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO application_user_bindings
            (id,project_id,application_id,user_id,status,binding_revision)
         VALUES ($1,$2,$3,$4,'active',1)",
    )
    .bind(binding_id)
    .bind(fixture.project_id)
    .bind(fixture.application_id)
    .bind(fixture.loser_user_id)
    .execute(&pool)
    .await
    .expect("insert losing binding");
    sqlx::query(
        "INSERT INTO application_user_projections
            (id,project_id,binding_id,application_id,user_id,schema_name,
             projection_revision,source_user_revision,canonical_digest,
             source_base_profile_digest,document)
         VALUES ($1,$2,$3,$4,$5,'owlauth.user.v1',1,1,$6,$7,
             jsonb_build_object(
               'user_id','usr_migration','user_revision',1,
               'projection_schema','owlauth.user.v1','projection_revision',1,
               'display_name',NULL,'picture_url',NULL,'locale',NULL,
               'verified_email',NULL,'status','active',
               'created_at','2026-08-02T00:00:00Z',
               'updated_at','2026-08-02T00:00:00Z'))",
    )
    .bind(projection_id)
    .bind(fixture.project_id)
    .bind(binding_id)
    .bind(fixture.application_id)
    .bind(fixture.loser_user_id)
    .bind(vec![6_u8; 32])
    .bind(vec![7_u8; 32])
    .execute(&pool)
    .await
    .expect("insert losing projection");
    let mismatched_session_owner = sqlx::query(
        "INSERT INTO application_sessions
            (id,project_id,application_id,user_id,binding_id,status,session_revision,
             project_security_revision,application_security_revision,
             user_security_revision,claims_revision,policy_session_revision,
             authenticated_at,absolute_expires_at)
         VALUES ($1,$2,$3,$4,$5,'active',1,1,1,1,1,1,
                 transaction_timestamp(),transaction_timestamp()+INTERVAL '30 days')",
    )
    .bind(Uuid::new_v4())
    .bind(fixture.project_id)
    .bind(fixture.application_id)
    .bind(fixture.winner_user_id)
    .bind(binding_id)
    .execute(&pool)
    .await;
    assert!(
        mismatched_session_owner.is_err(),
        "a session must capture its binding owner at insertion"
    );
    sqlx::query(
        "INSERT INTO application_sessions
            (id,project_id,application_id,user_id,binding_id,status,session_revision,
             project_security_revision,application_security_revision,
             user_security_revision,claims_revision,policy_session_revision,
             authenticated_at,absolute_expires_at)
         VALUES ($1,$2,$3,$4,$5,'active',1,1,1,1,1,1,
                 transaction_timestamp(),transaction_timestamp()+INTERVAL '30 days')",
    )
    .bind(session_id)
    .bind(fixture.project_id)
    .bind(fixture.application_id)
    .bind(fixture.loser_user_id)
    .bind(binding_id)
    .execute(&pool)
    .await
    .expect("insert historical Application session");
    let rewrite_session_owner =
        sqlx::query("UPDATE application_sessions SET user_id=$1 WHERE id=$2")
            .bind(fixture.winner_user_id)
            .bind(session_id)
            .execute(&pool)
            .await;
    assert!(
        rewrite_session_owner.is_err(),
        "historical Application-session credential ownership is immutable"
    );

    let rewrite_binding_created_at = sqlx::query(
        "UPDATE application_user_bindings
            SET created_at=created_at-INTERVAL '1 second'
          WHERE id=$1",
    )
    .bind(binding_id)
    .execute(&pool)
    .await;
    assert!(
        rewrite_binding_created_at.is_err(),
        "binding creation authority is immutable"
    );

    let mut move_binding = pool.begin().await.expect("begin binding move");
    sqlx::query(
        "UPDATE application_user_bindings
            SET user_id=$1,binding_revision=binding_revision+1,
                updated_at=transaction_timestamp()
          WHERE id=$2",
    )
    .bind(fixture.winner_user_id)
    .bind(binding_id)
    .execute(&mut *move_binding)
    .await
    .expect("move binding to winner");
    sqlx::query(
        "UPDATE application_user_projections
            SET user_id=$1,updated_at=transaction_timestamp()
          WHERE id=$2",
    )
    .bind(fixture.winner_user_id)
    .bind(projection_id)
    .execute(&mut *move_binding)
    .await
    .expect("move projection to winner");
    move_binding
        .commit()
        .await
        .expect("commit deferred binding move");

    let attribution: (Uuid, Uuid, Uuid) = sqlx::query_as(
        "SELECT binding.user_id,projection.user_id,session.user_id
           FROM application_user_bindings AS binding
           JOIN application_user_projections AS projection
             ON projection.binding_id=binding.id
           JOIN application_sessions AS session ON session.binding_id=binding.id
          WHERE binding.id=$1",
    )
    .bind(binding_id)
    .fetch_one(&pool)
    .await
    .expect("load merged attribution");
    assert_eq!(attribution.0, fixture.winner_user_id);
    assert_eq!(attribution.1, fixture.winner_user_id);
    assert_eq!(attribution.2, fixture.loser_user_id);
}

async fn prove_provider_slot(
    pool: &PgPool,
    fixture: &AuthorityFixture,
    intent_id: Uuid,
    slot_id: Uuid,
    existing_identity_id: Option<Uuid>,
    candidate_evidence_id: Option<Uuid>,
) {
    prove_provider_slot_for_user(
        pool,
        fixture,
        intent_id,
        slot_id,
        fixture.winner_user_id,
        existing_identity_id,
        candidate_evidence_id,
    )
    .await;
}

#[allow(
    clippy::too_many_lines,
    reason = "test helper keeps one complete provider proof transaction explicit"
)]
async fn prove_provider_slot_for_user(
    pool: &PgPool,
    fixture: &AuthorityFixture,
    intent_id: Uuid,
    slot_id: Uuid,
    proof_user_id: Uuid,
    existing_identity_id: Option<Uuid>,
    candidate_evidence_id: Option<Uuid>,
) {
    let mut transaction = pool.begin().await.expect("begin provider proof");
    let state_digest = slot_id
        .as_bytes()
        .iter()
        .copied()
        .cycle()
        .take(32)
        .collect::<Vec<_>>();
    sqlx::query(
        "UPDATE identity_mutation_proof_slots
            SET state='provider_authorization_started',slot_revision=2,
                upstream_state_digest=$1,upstream_state_digest_key_version=1,
                oidc_nonce_digest=$2,oidc_nonce_digest_key_version=1,
                callback_continuation_ciphertext=decode(repeat('aa',64),'hex'),
                callback_continuation_key_version=1,
                provider_started_at=transaction_timestamp(),updated_at=transaction_timestamp()
          WHERE id=$3 AND intent_id=$4",
    )
    .bind(&state_digest)
    .bind(vec![9_u8; 32])
    .bind(slot_id)
    .bind(intent_id)
    .execute(&mut *transaction)
    .await
    .expect("start provider proof");
    sqlx::query(
        "INSERT INTO provider_callback_owners
            (state_id,project_id,provider_configuration_id,owner_kind,
             identity_mutation_intent_id,identity_mutation_proof_slot_id)
         VALUES ($1,$2,$3,'identity_mutation',$4,$1)",
    )
    .bind(slot_id)
    .bind(fixture.project_id)
    .bind(fixture.provider_id)
    .bind(intent_id)
    .execute(&mut *transaction)
    .await
    .expect("insert mutation callback owner");
    sqlx::query(
        "UPDATE identity_mutation_proof_slots
            SET state='provider_exchange_in_progress',slot_revision=3,
                exchange_claimed_at=transaction_timestamp(),updated_at=transaction_timestamp()
          WHERE id=$1 AND intent_id=$2",
    )
    .bind(slot_id)
    .bind(intent_id)
    .execute(&mut *transaction)
    .await
    .expect("claim provider exchange");
    sqlx::query(
        "UPDATE identity_mutation_proof_slots
            SET state='proved',slot_revision=4,exchange_claimed_at=NULL,
                callback_continuation_ciphertext=NULL,
                callback_continuation_key_version=NULL,
                proved_at=transaction_timestamp(),updated_at=transaction_timestamp()
          WHERE id=$1 AND intent_id=$2",
    )
    .bind(slot_id)
    .bind(intent_id)
    .execute(&mut *transaction)
    .await
    .expect("prove provider slot");
    if let Some(evidence_id) = candidate_evidence_id {
        sqlx::query(
            "INSERT INTO identity_mutation_candidate_evidence
                (id,project_id,intent_id,slot_id,identity_kind,candidate_revision,
                 protector_key_version,evidence_ciphertext,evidence_digest,retain_until)
             SELECT $1,$2,$3,$4,'provider',1,1,$5,$6,
                    intent.expires_at+INTERVAL '15 minutes'
               FROM identity_mutation_intents AS intent
              WHERE intent.project_id=$2 AND intent.id=$3",
        )
        .bind(evidence_id)
        .bind(fixture.project_id)
        .bind(intent_id)
        .bind(slot_id)
        .bind(vec![7_u8; 64])
        .bind(vec![8_u8; 32])
        .execute(&mut *transaction)
        .await
        .expect("insert candidate evidence");
    }
    let receipt_digest = Uuid::new_v4()
        .as_bytes()
        .iter()
        .copied()
        .cycle()
        .take(32)
        .collect::<Vec<_>>();
    sqlx::query(
        "INSERT INTO identity_proof_receipts
            (id,project_id,intent_id,slot_id,evidence_kind,identity_kind,
             provider_identity_id,candidate_evidence_id,evidence_revision,
             proof_user_id,proof_user_revision,proof_user_security_revision,
             interaction_browser_binding_digest,
             interaction_browser_binding_digest_key_version,
             interaction_browser_binding_revision,captured_intent_revision,purpose,
             receipt_digest,receipt_digest_key_version,status,issued_at,expires_at)
         SELECT $1,$2,$3,$4,
                CASE WHEN $5::uuid IS NULL THEN 'candidate_evidence' ELSE 'existing_identity' END,
                'provider',$5,$6,1,$7,1,1,$8,1,1,intent.intent_revision,
                slot.purpose,$9,1,'issued',slot.proved_at,
                LEAST(slot.proved_at+INTERVAL '5 minutes',intent.expires_at)
           FROM identity_mutation_proof_slots AS slot
           JOIN identity_mutation_intents AS intent
             ON intent.project_id=slot.project_id AND intent.id=slot.intent_id
          WHERE slot.id=$4 AND slot.intent_id=$3",
    )
    .bind(Uuid::new_v4())
    .bind(fixture.project_id)
    .bind(intent_id)
    .bind(slot_id)
    .bind(existing_identity_id)
    .bind(candidate_evidence_id)
    .bind(proof_user_id)
    .bind(vec![2_u8; 32])
    .bind(receipt_digest)
    .execute(&mut *transaction)
    .await
    .expect("insert exact proof receipt");
    sqlx::query(
        "UPDATE identity_mutation_intents AS intent
            SET intent_revision=intent.intent_revision+1,
                updated_at=transaction_timestamp()
          WHERE intent.id=$1
            AND intent.intent_revision=(
                SELECT captured_intent_revision
                  FROM identity_proof_receipts
                 WHERE intent_id=$1 AND slot_id=$2
            )",
    )
    .bind(intent_id)
    .bind(slot_id)
    .execute(&mut *transaction)
    .await
    .expect("advance intent after receipt attachment");
    transaction.commit().await.expect("commit provider proof");
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one adversarial PostgreSQL test keeps lifecycle authority failures in one fixture"
)]
async fn identity_lifecycle_schema_rejects_stale_proofs_live_evidence_and_merge_cycles() {
    let Some((_container, pool)) = migrated_pool().await else {
        return;
    };
    let fixture = seed_authority(&pool).await;

    let invalid_initial_intent = sqlx::query(
        "INSERT INTO identity_mutation_intents
            (id,project_id,operation_kind,status,intent_revision,
             project_metadata_revision,project_security_revision,
             destination_user_id,destination_user_revision,
             destination_user_security_revision,primary_source_disposition,
             hosted_handle_digest,hosted_handle_digest_key_version,
             browser_binding_digest,browser_binding_digest_key_version,
             csrf_digest,csrf_digest_key_version,browser_binding_revision,
             correlation_id,expires_at,ready_at,terminal_at)
         VALUES ($1,$2,'link','completed',1,1,1,$3,1,1,'preserve',
                 $4,1,$5,1,$6,1,1,$7,transaction_timestamp()+INTERVAL '10 minutes',
                 transaction_timestamp(),transaction_timestamp())",
    )
    .bind(Uuid::new_v4())
    .bind(fixture.project_id)
    .bind(fixture.winner_user_id)
    .bind(vec![21_u8; 32])
    .bind(vec![22_u8; 32])
    .bind(vec![23_u8; 32])
    .bind(Uuid::new_v4())
    .execute(&pool)
    .await;
    assert!(
        invalid_initial_intent.is_err(),
        "an intent cannot be born completed"
    );

    let born_bound_intent = sqlx::query(
        "INSERT INTO identity_mutation_intents
            (id,project_id,operation_kind,status,intent_revision,
             project_metadata_revision,project_security_revision,
             destination_user_id,destination_user_revision,
             destination_user_security_revision,primary_source_disposition,
             hosted_handle_digest,hosted_handle_digest_key_version,
             browser_binding_digest,browser_binding_digest_key_version,
             csrf_digest,csrf_digest_key_version,browser_binding_revision,
             correlation_id,expires_at)
         VALUES ($1,$2,'link','pending_proof',1,1,1,$3,1,1,'preserve',
                 $4,1,$5,1,$6,1,1,$7,transaction_timestamp()+INTERVAL '10 minutes')",
    )
    .bind(Uuid::new_v4())
    .bind(fixture.project_id)
    .bind(fixture.winner_user_id)
    .bind(vec![24_u8; 32])
    .bind(vec![25_u8; 32])
    .bind(vec![26_u8; 32])
    .bind(Uuid::new_v4())
    .execute(&pool)
    .await;
    assert!(
        born_bound_intent.is_err(),
        "a Control-created intent must be born without browser authority"
    );

    let nullable_intent_authority = sqlx::query(
        "INSERT INTO identity_mutation_intents
            (id,project_id,operation_kind,status,intent_revision,
             project_metadata_revision,project_security_revision,
             destination_user_id,destination_user_revision,
             destination_user_security_revision,primary_source_disposition,
             hosted_handle_digest,hosted_handle_digest_key_version,
             correlation_id,expires_at)
         VALUES ($1,$2,'link','pending_proof',1,1,1,$3,NULL,1,'preserve',
                 $4,1,$5,transaction_timestamp()+INTERVAL '10 minutes')",
    )
    .bind(Uuid::new_v4())
    .bind(fixture.project_id)
    .bind(fixture.winner_user_id)
    .bind(vec![34_u8; 32])
    .bind(Uuid::new_v4())
    .execute(&pool)
    .await;
    assert!(
        nullable_intent_authority.is_err(),
        "nullable frozen user revisions cannot pass an operation discriminator"
    );

    let valid_scope_set: bool = sqlx::query_scalar(
        "SELECT owlauth_valid_identity_proof_scopes(ARRAY['openid','profile']::text[])",
    )
    .fetch_one(&pool)
    .await
    .expect("validate canonical proof scopes");
    assert!(valid_scope_set);
    for invalid_scopes in [
        vec![None],
        vec![Some("openid".to_owned()), Some("openid".to_owned())],
        vec![Some(String::new())],
        vec![Some("openid profile".to_owned())],
        vec![Some("offline_access".to_owned())],
    ] {
        let valid: bool =
            sqlx::query_scalar("SELECT owlauth_valid_identity_proof_scopes($1::text[])")
                .bind(invalid_scopes)
                .fetch_one(&pool)
                .await
                .expect("validate rejected proof scopes");
        assert!(!valid, "malformed proof scope set must be rejected");
    }

    let loser_identity_id: Uuid =
        sqlx::query_scalar("SELECT id FROM linked_identities WHERE project_id=$1 AND user_id=$2")
            .bind(fixture.project_id)
            .bind(fixture.loser_user_id)
            .fetch_one(&pool)
            .await
            .expect("load unrelated primary identity");
    let foreign_primary_source = sqlx::query(
        "INSERT INTO identity_mutation_intents
            (id,project_id,operation_kind,status,intent_revision,
             project_metadata_revision,project_security_revision,
             identity_owner_user_id,identity_owner_user_revision,
             identity_owner_user_security_revision,primary_source_disposition,
             primary_provider_identity_id,primary_source_identity_revision,
             hosted_handle_digest,hosted_handle_digest_key_version,correlation_id,expires_at)
         VALUES ($1,$2,'unlink','pending_proof',1,1,1,$3,1,1,'provider',$4,1,
                 $5,1,$6,transaction_timestamp()+INTERVAL '10 minutes')",
    )
    .bind(Uuid::new_v4())
    .bind(fixture.project_id)
    .bind(fixture.winner_user_id)
    .bind(loser_identity_id)
    .bind(vec![33_u8; 32])
    .bind(Uuid::new_v4())
    .execute(&pool)
    .await;
    assert!(
        foreign_primary_source.is_err(),
        "unlink replacement source must belong to the frozen identity owner"
    );

    let canonical_scopes: bool = sqlx::query_scalar(
        "SELECT owlauth_valid_identity_proof_scopes(ARRAY['openid','profile']::text[])",
    )
    .fetch_one(&pool)
    .await
    .expect("validate canonical provider scopes");
    let noncanonical_scopes: bool = sqlx::query_scalar(
        "SELECT owlauth_valid_identity_proof_scopes('[0:1]={openid,profile}'::text[])",
    )
    .fetch_one(&pool)
    .await
    .expect("validate noncanonical provider scopes");
    assert!(canonical_scopes);
    assert!(
        !noncanonical_scopes,
        "persisted scope arrays must remain decodable by the Rust Vec representation"
    );

    let nullable_slot_intent_id = Uuid::new_v4();
    let mut nullable_slot = pool.begin().await.expect("begin nullable slot intent");
    insert_unbound_link_intent(&mut nullable_slot, &fixture, nullable_slot_intent_id).await;
    let nullable_slot_authority = sqlx::query(
        "INSERT INTO identity_mutation_proof_slots
            (id,project_id,intent_id,slot_ordinal,slot_role,purpose,identity_kind,
             proof_user_id,expected_user_revision,expected_user_security_revision,
             existing_provider_identity_id,expected_identity_revision,
             application_id,application_security_revision,method_kind,
             provider_adapter_key,provider_adapter_capability_revision,
             provider_configuration_id,provider_revision,
             provider_assignment_security_revision,provider_scopes,callback_url,
             provider_pkce_required,oidc_nonce_required,state,slot_revision)
         VALUES ($1,$2,$3,1,'destination_owner','link.destination_owner','provider',
                 $4,1,1,$5,NULL,$6,1,'provider','oidc',1,$7,1,1,
                 ARRAY['openid','profile']::text[],'https://runtime.example/callback',
                 false,true,'pending',1)",
    )
    .bind(Uuid::new_v4())
    .bind(fixture.project_id)
    .bind(nullable_slot_intent_id)
    .bind(fixture.winner_user_id)
    .bind(fixture.winner_identity_id)
    .bind(fixture.application_id)
    .bind(fixture.provider_id)
    .execute(&mut *nullable_slot)
    .await;
    assert!(
        nullable_slot_authority.is_err(),
        "an existing-identity slot cannot omit its frozen identity revision"
    );
    nullable_slot
        .rollback()
        .await
        .expect("rollback rejected nullable slot intent");

    let unbound_intent_id = Uuid::new_v4();
    let unbound_owner_slot_id = Uuid::new_v4();
    let unbound_candidate_slot_id = Uuid::new_v4();
    let mut unbound = pool.begin().await.expect("begin unbound intent");
    insert_unbound_link_intent(&mut unbound, &fixture, unbound_intent_id).await;
    insert_provider_slot(
        &mut unbound,
        &fixture,
        unbound_intent_id,
        unbound_owner_slot_id,
        1,
        "destination_owner",
        "link.destination_owner",
        Some(fixture.winner_identity_id),
    )
    .await;
    insert_provider_slot(
        &mut unbound,
        &fixture,
        unbound_intent_id,
        unbound_candidate_slot_id,
        2,
        "candidate_identity",
        "link.candidate_identity",
        None,
    )
    .await;
    unbound.commit().await.expect("commit unbound intent");

    let mut premature_proof = pool.begin().await.expect("begin premature proof");
    sqlx::query(
        "UPDATE identity_mutation_proof_slots
            SET state='provider_authorization_started',slot_revision=2,
                upstream_state_digest=$1,upstream_state_digest_key_version=1,
                oidc_nonce_digest=$2,oidc_nonce_digest_key_version=1,
                callback_continuation_ciphertext=decode(repeat('aa',64),'hex'),
                callback_continuation_key_version=1,
                provider_started_at=transaction_timestamp(),updated_at=transaction_timestamp()
          WHERE id=$3 AND intent_id=$4",
    )
    .bind(vec![25_u8; 32])
    .bind(vec![26_u8; 32])
    .bind(unbound_candidate_slot_id)
    .bind(unbound_intent_id)
    .execute(&mut *premature_proof)
    .await
    .expect("stage proof before browser binding");
    assert!(
        premature_proof.commit().await.is_err(),
        "an unbound mutation intent cannot start a proof"
    );

    sqlx::query(
        "UPDATE identity_mutation_intents
            SET browser_binding_digest=$1,browser_binding_digest_key_version=1,
                csrf_digest=$2,csrf_digest_key_version=1,browser_binding_revision=1,
                intent_revision=2,updated_at=transaction_timestamp()
          WHERE id=$3",
    )
    .bind(vec![27_u8; 32])
    .bind(vec![28_u8; 32])
    .bind(unbound_intent_id)
    .execute(&pool)
    .await
    .expect("bind Control-created intent once");

    let unbound_rebind = sqlx::query(
        "UPDATE identity_mutation_intents
            SET browser_binding_digest=$1,csrf_digest=$2,browser_binding_revision=2,
                intent_revision=3,updated_at=transaction_timestamp()
          WHERE id=$3",
    )
    .bind(vec![29_u8; 32])
    .bind(vec![30_u8; 32])
    .bind(unbound_intent_id)
    .execute(&pool)
    .await;
    assert!(
        unbound_rebind.is_err(),
        "a Control-created mutation intent can bind only once"
    );

    let (bound_intent_id, _) = create_valid_link_intent(&pool, &fixture).await;
    let rebind = sqlx::query(
        "UPDATE identity_mutation_intents
            SET browser_binding_digest=$1,csrf_digest=$2,browser_binding_revision=2,
                intent_revision=3,updated_at=transaction_timestamp()
          WHERE id=$3",
    )
    .bind(vec![31_u8; 32])
    .bind(vec![32_u8; 32])
    .bind(bound_intent_id)
    .execute(&pool)
    .await;
    assert!(
        rebind.is_err(),
        "a bound mutation interaction cannot move browsers"
    );

    let mismatched_create_key = format!("mutation-create-mismatch-{bound_intent_id}");
    sqlx::query(
        "INSERT INTO control_idempotency_records
            (idempotency_key,project_id,request_digest,state,result_resource_id,response,
             operation_kind,request_scope,completed_at)
         VALUES ($1,$2,$3,'completed',$4,'{}'::jsonb,
                 'application.create',$5,transaction_timestamp())",
    )
    .bind(&mismatched_create_key)
    .bind(fixture.project_id)
    .bind(vec![35_u8; 32])
    .bind(bound_intent_id)
    .bind(fixture.project_id.to_string())
    .execute(&pool)
    .await
    .expect("insert mismatched create idempotency authority");
    let mismatched_create_result = sqlx::query(
        "INSERT INTO identity_mutation_create_results
            (idempotency_key,project_id,intent_id,request_digest,
             create_result_key_version,create_result_ciphertext,expires_at)
         SELECT $1,project_id,id,$2,1,$3,expires_at
           FROM identity_mutation_intents WHERE id=$4",
    )
    .bind(&mismatched_create_key)
    .bind(vec![35_u8; 32])
    .bind(vec![36_u8; 64])
    .bind(bound_intent_id)
    .execute(&pool)
    .await;
    assert!(
        mismatched_create_result.is_err(),
        "create result must match the completed identity-mutation idempotency authority"
    );

    let create_key = format!("mutation-create-{bound_intent_id}");
    sqlx::query(
        "INSERT INTO control_idempotency_records
            (idempotency_key,project_id,request_digest,state,result_resource_id,response,
             operation_kind,request_scope,completed_at)
         VALUES ($1,$2,$3,'completed',$4,'{}'::jsonb,
                 'identity_mutation.create',$5,transaction_timestamp())",
    )
    .bind(&create_key)
    .bind(fixture.project_id)
    .bind(vec![35_u8; 32])
    .bind(bound_intent_id)
    .bind(fixture.project_id.to_string())
    .execute(&pool)
    .await
    .expect("insert mutation create idempotency authority");
    let short_create_result = sqlx::query(
        "INSERT INTO identity_mutation_create_results
            (idempotency_key,project_id,intent_id,request_digest,
             create_result_key_version,create_result_ciphertext,expires_at)
         SELECT $1,project_id,id,$2,1,$3,expires_at-INTERVAL '1 second'
           FROM identity_mutation_intents WHERE id=$4",
    )
    .bind(&create_key)
    .bind(vec![35_u8; 32])
    .bind(vec![36_u8; 64])
    .bind(bound_intent_id)
    .execute(&pool)
    .await
    .expect_err("short create-result retention must fail");
    assert_check_violation(&short_create_result, "exact intent deadline");

    sqlx::query(
        "INSERT INTO identity_mutation_create_results
            (idempotency_key,project_id,intent_id,request_digest,
             create_result_key_version,create_result_ciphertext,expires_at)
         SELECT $1,project_id,id,$2,1,$3,expires_at
           FROM identity_mutation_intents WHERE id=$4",
    )
    .bind(&create_key)
    .bind(vec![35_u8; 32])
    .bind(vec![36_u8; 64])
    .bind(bound_intent_id)
    .execute(&pool)
    .await
    .expect("insert live mutation create result");
    let early_create_result_erasure = sqlx::query(
        "UPDATE identity_mutation_create_results
            SET create_result_ciphertext=NULL,erased_at=transaction_timestamp()
          WHERE idempotency_key=$1",
    )
    .bind(&create_key)
    .execute(&pool)
    .await;
    assert!(
        early_create_result_erasure.is_err(),
        "the exact Hosted target remains replayable through intent expiry"
    );
    let rewrite_create_result_authority = sqlx::query(
        "UPDATE identity_mutation_create_results SET request_digest=$1
          WHERE idempotency_key=$2",
    )
    .bind(vec![37_u8; 32])
    .bind(&create_key)
    .execute(&pool)
    .await;
    assert!(
        rewrite_create_result_authority.is_err(),
        "create-result request authority is immutable"
    );
    let future_dated_create_result_erasure = sqlx::query(
        "UPDATE identity_mutation_create_results
            SET create_result_ciphertext=NULL,erased_at=expires_at
          WHERE idempotency_key=$1",
    )
    .bind(&create_key)
    .execute(&pool)
    .await;
    assert!(
        future_dated_create_result_erasure.is_err(),
        "a caller-supplied future timestamp cannot erase a still-live Hosted target"
    );
    let rewrite_idempotency_authority = sqlx::query(
        "UPDATE control_idempotency_records SET request_scope='another-project'
          WHERE idempotency_key=$1",
    )
    .bind(&create_key)
    .execute(&pool)
    .await;
    assert!(
        rewrite_idempotency_authority.is_err(),
        "committed create-result idempotency authority is immutable"
    );

    let delete_live_result =
        sqlx::query("DELETE FROM identity_mutation_create_results WHERE idempotency_key=$1")
            .bind(&create_key)
            .execute(&pool)
            .await
            .expect_err("live create-result tombstone deletion must fail");
    assert_check_violation(&delete_live_result, "authority tombstone cannot be deleted");
    let delete_parent_intent = sqlx::query("DELETE FROM identity_mutation_intents WHERE id=$1")
        .bind(bound_intent_id)
        .execute(&pool)
        .await
        .expect_err("parent cascade cannot delete create-result authority");
    assert_check_violation(
        &delete_parent_intent,
        "durable create authority cannot be deleted",
    );

    let mut incomplete_result_erasure = pool
        .begin()
        .await
        .expect("begin cancellation without create-result erasure");
    sqlx::query(
        "UPDATE identity_mutation_proof_slots
            SET state='expired',slot_revision=slot_revision+1,
                terminal_at=transaction_timestamp(),updated_at=transaction_timestamp()
          WHERE intent_id=$1",
    )
    .bind(bound_intent_id)
    .execute(&mut *incomplete_result_erasure)
    .await
    .expect("expire slots before incomplete create-result cancellation");
    sqlx::query(
        "UPDATE identity_mutation_intents
            SET status='cancelled',intent_revision=intent_revision+1,
                terminal_at=transaction_timestamp(),updated_at=transaction_timestamp()
          WHERE id=$1",
    )
    .bind(bound_intent_id)
    .execute(&mut *incomplete_result_erasure)
    .await
    .expect("stage cancellation without result erasure");
    let incomplete_result_error = incomplete_result_erasure
        .commit()
        .await
        .expect_err("terminal intent cannot retain live create-result ciphertext");
    assert_check_violation(
        &incomplete_result_error,
        "terminal state requires exact create-result ciphertext erasure",
    );

    let mut cancel_and_erase = pool.begin().await.expect("begin cancellation erasure");
    sqlx::query(
        "UPDATE identity_mutation_proof_slots
            SET state='expired',slot_revision=slot_revision+1,
                terminal_at=transaction_timestamp(),updated_at=transaction_timestamp()
          WHERE intent_id=$1",
    )
    .bind(bound_intent_id)
    .execute(&mut *cancel_and_erase)
    .await
    .expect("expire cancelled intent slots");
    sqlx::query(
        "UPDATE identity_mutation_intents
            SET status='cancelled',intent_revision=intent_revision+1,
                terminal_at=transaction_timestamp(),updated_at=transaction_timestamp()
          WHERE id=$1",
    )
    .bind(bound_intent_id)
    .execute(&mut *cancel_and_erase)
    .await
    .expect("cancel create-result owner intent");
    sqlx::query(
        "UPDATE identity_mutation_create_results
            SET create_result_ciphertext=NULL,erased_at=transaction_timestamp()
          WHERE idempotency_key=$1",
    )
    .bind(&create_key)
    .execute(&mut *cancel_and_erase)
    .await
    .expect("erase terminal create-result ciphertext");
    cancel_and_erase
        .commit()
        .await
        .expect("commit cancellation with authority tombstone");
    let retained_result: (bool, bool) = sqlx::query_as(
        "SELECT create_result_ciphertext IS NULL,erased_at IS NOT NULL
           FROM identity_mutation_create_results WHERE idempotency_key=$1",
    )
    .bind(&create_key)
    .fetch_one(&pool)
    .await
    .expect("load erased create-result tombstone");
    assert_eq!(retained_result, (true, true));
    let rewrite_after_erasure = sqlx::query(
        "UPDATE control_idempotency_records SET request_scope='after-erasure'
          WHERE idempotency_key=$1",
    )
    .bind(&create_key)
    .execute(&pool)
    .await
    .expect_err("erasure must not release idempotency authority");
    assert_check_violation(&rewrite_after_erasure, "idempotency authority is immutable");

    let unlink_intent_id = Uuid::new_v4();
    let unlink_slot_id = Uuid::new_v4();
    let mut unlink = pool.begin().await.expect("begin unlink intent");
    sqlx::query(
        "INSERT INTO identity_mutation_intents
            (id,project_id,operation_kind,status,intent_revision,
             project_metadata_revision,project_security_revision,
             identity_owner_user_id,identity_owner_user_revision,
             identity_owner_user_security_revision,primary_source_disposition,
             hosted_handle_digest,hosted_handle_digest_key_version,
             correlation_id,expires_at)
         VALUES ($1,$2,'unlink','pending_proof',1,1,1,$3,1,1,'clear',
                 $4,1,$5,transaction_timestamp()+INTERVAL '10 minutes')",
    )
    .bind(unlink_intent_id)
    .bind(fixture.project_id)
    .bind(fixture.winner_user_id)
    .bind(vec![41_u8; 32])
    .bind(Uuid::new_v4())
    .execute(&mut *unlink)
    .await
    .expect("insert unlink intent");
    sqlx::query(
        "UPDATE identity_mutation_intents
            SET browser_binding_digest=$1,browser_binding_digest_key_version=1,
                csrf_digest=$2,csrf_digest_key_version=1,browser_binding_revision=1,
                intent_revision=2,updated_at=transaction_timestamp()
          WHERE id=$3 AND intent_revision=1",
    )
    .bind(vec![2_u8; 32])
    .bind(vec![42_u8; 32])
    .bind(unlink_intent_id)
    .execute(&mut *unlink)
    .await
    .expect("bind unlink intent once");
    insert_provider_slot(
        &mut unlink,
        &fixture,
        unlink_intent_id,
        unlink_slot_id,
        1,
        "identity_owner",
        "unlink.identity_owner",
        Some(fixture.winner_identity_id),
    )
    .await;
    unlink.commit().await.expect("commit unlink intent");
    prove_provider_slot(
        &pool,
        &fixture,
        unlink_intent_id,
        unlink_slot_id,
        Some(fixture.winner_identity_id),
        None,
    )
    .await;
    let orphaned_expired_receipt = sqlx::query(
        "UPDATE identity_proof_receipts SET status='expired'
          WHERE intent_id=$1 AND slot_id=$2",
    )
    .bind(unlink_intent_id)
    .bind(unlink_slot_id)
    .execute(&pool)
    .await;
    assert!(
        orphaned_expired_receipt.is_err(),
        "an expired receipt cannot commit below a live parent intent"
    );
    let mut stale_ready = pool.begin().await.expect("begin stale ready transition");
    sqlx::query(
        "UPDATE identity_mutation_intents
            SET status='ready',intent_revision=4,
                ready_at=transaction_timestamp()+INTERVAL '6 minutes',
                updated_at=transaction_timestamp()
          WHERE id=$1",
    )
    .bind(unlink_intent_id)
    .execute(&mut *stale_ready)
    .await
    .expect("stage stale ready transition");
    assert!(
        stale_ready.commit().await.is_err(),
        "a receipt that expires before ready_at cannot authorize a ready intent"
    );

    let mut incomplete_cancel = pool.begin().await.expect("begin incomplete cancellation");
    sqlx::query(
        "UPDATE identity_mutation_intents
            SET status='cancelled',intent_revision=intent_revision+1,
                terminal_at=transaction_timestamp(),updated_at=transaction_timestamp()
          WHERE id=$1",
    )
    .bind(unlink_intent_id)
    .execute(&mut *incomplete_cancel)
    .await
    .expect("stage parent-only cancellation");
    assert!(
        incomplete_cancel.commit().await.is_err(),
        "a terminal parent cannot retain a proved proof slot"
    );

    let mut complete_cancel = pool.begin().await.expect("begin complete cancellation");
    sqlx::query(
        "UPDATE identity_proof_receipts SET status='expired'
          WHERE intent_id=$1 AND slot_id=$2",
    )
    .bind(unlink_intent_id)
    .bind(unlink_slot_id)
    .execute(&mut *complete_cancel)
    .await
    .expect("expire receipt with its parent");
    sqlx::query(
        "UPDATE identity_mutation_proof_slots
            SET state='expired',slot_revision=slot_revision+1,proved_at=NULL,
                terminal_at=transaction_timestamp(),updated_at=transaction_timestamp()
          WHERE intent_id=$1 AND id=$2",
    )
    .bind(unlink_intent_id)
    .bind(unlink_slot_id)
    .execute(&mut *complete_cancel)
    .await
    .expect("expire the previously proved slot");
    sqlx::query(
        "UPDATE identity_mutation_intents
            SET status='cancelled',intent_revision=intent_revision+1,
                terminal_at=transaction_timestamp(),updated_at=transaction_timestamp()
          WHERE id=$1",
    )
    .bind(unlink_intent_id)
    .execute(&mut *complete_cancel)
    .await
    .expect("stage aggregate cancellation");
    complete_cancel
        .commit()
        .await
        .expect("terminalize every proof child with its parent");

    let (candidate_intent_id, candidate_slot_id) = create_valid_link_intent(&pool, &fixture).await;
    let evidence_id = Uuid::new_v4();
    prove_provider_slot(
        &pool,
        &fixture,
        candidate_intent_id,
        candidate_slot_id,
        None,
        Some(evidence_id),
    )
    .await;
    let rewrite_evidence_id =
        sqlx::query("UPDATE identity_mutation_candidate_evidence SET id=$1 WHERE id=$2")
            .bind(Uuid::new_v4())
            .bind(evidence_id)
            .execute(&pool)
            .await;
    assert!(
        rewrite_evidence_id.is_err(),
        "candidate evidence identity is immutable"
    );
    let extend_evidence_retention = sqlx::query(
        "UPDATE identity_mutation_candidate_evidence AS evidence
            SET retain_until=intent.expires_at+INTERVAL '15 minutes 1 second'
           FROM identity_mutation_intents AS intent
          WHERE evidence.id=$1 AND intent.id=evidence.intent_id",
    )
    .bind(evidence_id)
    .execute(&pool)
    .await;
    assert!(
        extend_evidence_retention.is_err(),
        "candidate evidence cannot outlive the bounded retention window"
    );
    let mut live_delete = pool.begin().await.expect("begin live evidence deletion");
    sqlx::query("DELETE FROM identity_mutation_candidate_evidence WHERE id=$1")
        .bind(evidence_id)
        .execute(&mut *live_delete)
        .await
        .expect("stage live evidence deletion");
    assert!(
        live_delete.commit().await.is_err(),
        "candidate evidence cannot disappear while its intent remains live"
    );

    let (ready_intent_id, ready_candidate_slot_id) =
        create_valid_link_intent(&pool, &fixture).await;
    let ready_owner_slot_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM identity_mutation_proof_slots
          WHERE intent_id=$1 AND slot_role='destination_owner'",
    )
    .bind(ready_intent_id)
    .fetch_one(&pool)
    .await
    .expect("load ready-intent owner slot");
    prove_provider_slot(
        &pool,
        &fixture,
        ready_intent_id,
        ready_owner_slot_id,
        Some(fixture.winner_identity_id),
        None,
    )
    .await;
    prove_provider_slot(
        &pool,
        &fixture,
        ready_intent_id,
        ready_candidate_slot_id,
        None,
        Some(Uuid::new_v4()),
    )
    .await;
    sqlx::query(
        "UPDATE identity_mutation_intents
            SET status='ready',intent_revision=5,ready_at=transaction_timestamp(),
                updated_at=transaction_timestamp()
          WHERE id=$1 AND intent_revision=4",
    )
    .bind(ready_intent_id)
    .execute(&pool)
    .await
    .expect("make fully proved intent ready");
    let rewrite_ready_timestamp = sqlx::query(
        "UPDATE identity_mutation_intents
            SET ready_at=ready_at+INTERVAL '1 second',intent_revision=6,
                updated_at=transaction_timestamp()
          WHERE id=$1",
    )
    .bind(ready_intent_id)
    .execute(&pool)
    .await;
    assert!(
        rewrite_ready_timestamp.is_err(),
        "ready timestamp is immutable after the ready transition"
    );

    let managed_connection_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO managed_provider_connections
            (id,project_id,provider_configuration_id,linked_identity_id,user_id,state,
             revision,generation,credential_generation,project_security_revision,
             provider_revision,user_security_revision,identity_revision,
             managed_profile_revision,adapter_key,adapter_capability_revision,
             required_scopes,supports_revocation,last_safe_outcome,created_at,updated_at)
         VALUES ($1,$2,$3,$4,$5,'reauth_required',1,1,1,1,1,1,1,1,'oidc',1,
                 ARRAY['openid','profile']::text[],true,'reauth_required',
                 transaction_timestamp(),transaction_timestamp())",
    )
    .bind(managed_connection_id)
    .bind(fixture.project_id)
    .bind(fixture.provider_id)
    .bind(fixture.winner_identity_id)
    .bind(fixture.winner_user_id)
    .execute(&pool)
    .await
    .expect("insert managed connection before merge");

    let reauthorization_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO managed_provider_reauthorization_interactions
            (id,project_id,project_public_id,connection_id,linked_identity_id,user_id,
             provider_configuration_id,provider_key,issuer,provider_kind,provider_display_name,subject,client_id,
             secret_material_id,provider_egress_policy_revision,application_id,
             expected_connection_generation,
             expected_credential_generation,
             expected_connection_revision,project_security_revision,user_security_revision,
             identity_revision,provider_revision,managed_profile_revision,application_revision,
             assignment_security_revision,callback_url,adapter_key,
             adapter_capability_revision,supports_revocation,required_scopes,
             provider_pkce_required,oidc_nonce_required,revision,status,expires_at,created_at)
         VALUES ($1,$2,(SELECT public_id FROM projects WHERE id=$2),$3,$4,$5,$6,
                 'oidc-main',
                 'https://issuer.example','oidc','Main','subject-winner01','client',
                 (SELECT secret_material_id FROM provider_configurations WHERE id=$6),
                 (SELECT revision FROM project_provider_egress_policies WHERE project_id=$2),$7,
                 1,1,1,1,1,1,1,1,1,1,'https://runtime.example/callback','oidc',1,true,
                 ARRAY['openid','profile']::text[],false,true,1,'awaiting_browser_binding',
                 transaction_timestamp()+INTERVAL '10 minutes',transaction_timestamp())",
    )
    .bind(reauthorization_id)
    .bind(fixture.project_id)
    .bind(managed_connection_id)
    .bind(fixture.winner_identity_id)
    .bind(fixture.winner_user_id)
    .bind(fixture.provider_id)
    .bind(fixture.application_id)
    .execute(&pool)
    .await
    .expect("insert historical managed reauthorization");
    let rewrite_reauthorization_owner = sqlx::query(
        "UPDATE managed_provider_reauthorization_interactions
            SET user_id=$1,revision=revision+1
          WHERE id=$2",
    )
    .bind(fixture.loser_user_id)
    .bind(reauthorization_id)
    .execute(&pool)
    .await;
    assert!(
        rewrite_reauthorization_owner.is_err(),
        "managed reauthorization freezes its insertion-time owner"
    );

    let replacement_identity_id = Uuid::new_v4();
    let mut move_identity = pool.begin().await.expect("begin identity owner move");
    sqlx::query(
        "INSERT INTO linked_identities
            (id,project_id,user_id,created_via_provider_configuration_id,issuer,subject,
             status,identity_revision,source_profile_digest,observed_at)
         VALUES ($1,$2,$3,$4,'https://issuer.example','subject-replacement01',
                 'active',1,public.owlauth_provider_source_profile_digest(NULL,NULL,NULL),transaction_timestamp())",
    )
    .bind(replacement_identity_id)
    .bind(fixture.project_id)
    .bind(fixture.winner_user_id)
    .bind(fixture.provider_id)
    .execute(&mut *move_identity)
    .await
    .expect("insert replacement primary identity");
    sqlx::query(
        "UPDATE project_users
            SET primary_profile_identity_id=$1,user_revision=user_revision+1,
                updated_at=transaction_timestamp()
          WHERE id=$2",
    )
    .bind(replacement_identity_id)
    .bind(fixture.winner_user_id)
    .execute(&mut *move_identity)
    .await
    .expect("replace losing user's primary identity");
    sqlx::query(
        "UPDATE linked_identities
            SET user_id=$1,identity_revision=identity_revision+1,
                updated_at=transaction_timestamp()
          WHERE id=$2",
    )
    .bind(fixture.loser_user_id)
    .bind(fixture.winner_identity_id)
    .execute(&mut *move_identity)
    .await
    .expect("move provider identity to merge winner");
    sqlx::query(
        "UPDATE managed_provider_connections
            SET user_id=$1,revision=revision+1,updated_at=transaction_timestamp()
          WHERE id=$2",
    )
    .bind(fixture.loser_user_id)
    .bind(managed_connection_id)
    .execute(&mut *move_identity)
    .await
    .expect("move live managed connection with identity");
    move_identity
        .commit()
        .await
        .expect("commit deferred identity and connection move");

    let merge_attribution: (Uuid, Uuid, Uuid, Uuid, Uuid) = sqlx::query_as(
        "SELECT slot.proof_user_id,receipt.proof_user_id,connection.user_id,
                reauthorization.user_id,identity.user_id
           FROM identity_mutation_proof_slots AS slot
           JOIN identity_proof_receipts AS receipt
             ON receipt.project_id=slot.project_id AND receipt.slot_id=slot.id
           JOIN managed_provider_connections AS connection
             ON connection.project_id=slot.project_id
            AND connection.linked_identity_id=slot.existing_provider_identity_id
           JOIN managed_provider_reauthorization_interactions AS reauthorization
             ON reauthorization.connection_id=connection.id
           JOIN linked_identities AS identity
             ON identity.id=slot.existing_provider_identity_id
          WHERE slot.id=$1",
    )
    .bind(unlink_slot_id)
    .fetch_one(&pool)
    .await
    .expect("load historical and live identity ownership after merge");
    assert_eq!(merge_attribution.0, fixture.winner_user_id);
    assert_eq!(merge_attribution.1, fixture.winner_user_id);
    assert_eq!(merge_attribution.2, fixture.loser_user_id);
    assert_eq!(merge_attribution.3, fixture.winner_user_id);
    assert_eq!(merge_attribution.4, fixture.loser_user_id);
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "email proof regression keeps the exact challenge, evidence, and receipt transaction visible"
)]
async fn identity_lifecycle_schema_requires_exact_mutation_email_challenges() {
    let Some((_container, pool)) = migrated_pool().await else {
        return;
    };
    let fixture = seed_authority(&pool).await;
    sqlx::query(
        "UPDATE project_email_policies
            SET status='enabled',allow_deployment_default=TRUE
          WHERE project_id=$1",
    )
    .bind(fixture.project_id)
    .execute(&pool)
    .await
    .expect("enable mutation email policy");
    sqlx::query(
        "INSERT INTO application_email_assignments
            (project_id,application_id,status,security_revision)
         VALUES ($1,$2,'active',1)",
    )
    .bind(fixture.project_id)
    .bind(fixture.application_id)
    .execute(&pool)
    .await
    .expect("assign mutation email method");

    let intent_id = Uuid::new_v4();
    let owner_slot_id = Uuid::new_v4();
    let email_slot_id = Uuid::new_v4();
    let mut setup = pool.begin().await.expect("begin email intent setup");
    insert_link_intent(&mut setup, &fixture, intent_id).await;
    insert_provider_slot(
        &mut setup,
        &fixture,
        intent_id,
        owner_slot_id,
        1,
        "destination_owner",
        "link.destination_owner",
        Some(fixture.winner_identity_id),
    )
    .await;
    sqlx::query(
        "INSERT INTO identity_mutation_proof_slots
            (id,project_id,intent_id,slot_ordinal,slot_role,purpose,identity_kind,
             proof_user_id,expected_user_revision,expected_user_security_revision,
             application_id,application_security_revision,method_kind,
             email_assignment_application_id,email_policy_revision,email_security_revision,
             email_assignment_security_revision,state,slot_revision)
         VALUES ($1,$2,$3,2,'candidate_identity','link.candidate_identity','email',
                 $4,1,1,$5,1,'email',$5,1,1,1,'pending',1)",
    )
    .bind(email_slot_id)
    .bind(fixture.project_id)
    .bind(intent_id)
    .bind(fixture.winner_user_id)
    .bind(fixture.application_id)
    .execute(&mut *setup)
    .await
    .expect("insert email candidate slot");
    sqlx::query(
        "UPDATE identity_mutation_proof_slots
            SET state='email_address_entry',slot_revision=2,
                updated_at=transaction_timestamp()
          WHERE id=$1",
    )
    .bind(email_slot_id)
    .execute(&mut *setup)
    .await
    .expect("select email proof method");
    setup.commit().await.expect("commit email intent setup");

    let mut missing_challenge = pool
        .begin()
        .await
        .expect("begin missing challenge transition");
    sqlx::query(
        "UPDATE identity_mutation_proof_slots
            SET state='email_challenge_pending',slot_revision=3,
                updated_at=transaction_timestamp()
          WHERE id=$1",
    )
    .bind(email_slot_id)
    .execute(&mut *missing_challenge)
    .await
    .expect("stage email pending without challenge");
    let missing_error = missing_challenge
        .commit()
        .await
        .expect_err("pending email slot without challenge must fail");
    assert_check_violation(&missing_error, "exact current challenge lifecycle");

    let challenge_id = Uuid::new_v4();
    let outbox_id = Uuid::new_v4();
    let mut pending = pool
        .begin()
        .await
        .expect("begin valid pending email challenge");
    sqlx::query(
        "UPDATE identity_mutation_proof_slots
            SET state='email_challenge_pending',slot_revision=3,
                updated_at=transaction_timestamp()
          WHERE id=$1",
    )
    .bind(email_slot_id)
    .execute(&mut *pending)
    .await
    .expect("stage valid email pending state");
    sqlx::query(
        "INSERT INTO email_challenges
            (id,project_id,application_id,owner_kind,identity_mutation_intent_id,
             identity_mutation_proof_slot_id,generation,status,canonicalization_version,
             lookup_digest,lookup_digest_key_version,address_ciphertext,address_key_version,
             otp_digest,otp_digest_key_version,otp_max_attempts,method_policy_revision,
             method_security_revision,assignment_security_revision,smtp_selection_kind,
             smtp_generation,smtp_security_eligibility_revision,browser_binding_required,
             issued_at,otp_expires_at,expires_at)
         VALUES ($1,$2,$3,'identity_mutation',$4,$5,1,'pending',1,$6,1,$7,1,
                 $8,1,5,1,1,1,'deployment_default',1,1,TRUE,
                 transaction_timestamp(),transaction_timestamp()+INTERVAL '2 minutes',
                 transaction_timestamp()+INTERVAL '5 minutes')",
    )
    .bind(challenge_id)
    .bind(fixture.project_id)
    .bind(fixture.application_id)
    .bind(intent_id)
    .bind(email_slot_id)
    .bind(vec![41_u8; 32])
    .bind(vec![42_u8; 64])
    .bind(vec![43_u8; 32])
    .execute(&mut *pending)
    .await
    .expect("insert exact mutation email challenge");
    sqlx::query(
        "INSERT INTO mail_outbox
            (id,project_id,transaction_id,challenge_id,challenge_generation,status,
             smtp_selection_kind,smtp_generation,smtp_security_eligibility_revision,
             message_id,envelope_ciphertext,envelope_key_version,body_ciphertext,
             body_key_version,next_attempt_at,useful_until)
         VALUES ($1,$2,NULL,$3,1,'pending','deployment_default',1,1,$4,$5,1,$6,1,
                 transaction_timestamp(),transaction_timestamp()+INTERVAL '5 minutes')",
    )
    .bind(outbox_id)
    .bind(fixture.project_id)
    .bind(challenge_id)
    .bind(format!("owlauth-test-{outbox_id}"))
    .bind(vec![54_u8; 64])
    .bind(vec![55_u8; 64])
    .execute(&mut *pending)
    .await
    .expect("insert exact mutation challenge outbox");
    pending
        .commit()
        .await
        .expect("commit exact pending mutation email challenge");

    let mismatched_outbox_id = Uuid::new_v4();
    let mut mismatched_outbox = pool
        .begin()
        .await
        .expect("begin mismatched SMTP outbox replacement");
    sqlx::query("DELETE FROM mail_outbox WHERE id=$1")
        .bind(outbox_id)
        .execute(&mut *mismatched_outbox)
        .await
        .expect("stage exact outbox replacement");
    sqlx::query(
        "INSERT INTO mail_outbox
            (id,project_id,transaction_id,challenge_id,challenge_generation,status,
             smtp_selection_kind,smtp_generation,smtp_security_eligibility_revision,
             message_id,envelope_ciphertext,envelope_key_version,body_ciphertext,
             body_key_version,next_attempt_at,useful_until)
         VALUES ($1,$2,NULL,$3,1,'pending','deployment_default',2,1,$4,$5,1,$6,1,
                 transaction_timestamp(),transaction_timestamp()+INTERVAL '5 minutes')",
    )
    .bind(mismatched_outbox_id)
    .bind(fixture.project_id)
    .bind(challenge_id)
    .bind(format!("owlauth-test-{mismatched_outbox_id}"))
    .bind(vec![56_u8; 64])
    .bind(vec![57_u8; 64])
    .execute(&mut *mismatched_outbox)
    .await
    .expect("stage outbox with mismatched SMTP generation");
    let mismatched_smtp_authority =
        sqlx::query("SET CONSTRAINTS mail_outbox_exact_challenge_owner IMMEDIATE")
            .execute(&mut *mismatched_outbox)
            .await
            .expect_err("outbox with mismatched SMTP generation must fail");
    assert_check_violation(
        &mismatched_smtp_authority,
        "mail outbox must match its exact challenge and SMTP authority",
    );
    mismatched_outbox
        .rollback()
        .await
        .expect("rollback mismatched SMTP outbox replacement");

    let mut missing_outbox = pool.begin().await.expect("begin pending outbox deletion");
    sqlx::query("DELETE FROM mail_outbox WHERE id=$1")
        .bind(outbox_id)
        .execute(&mut *missing_outbox)
        .await
        .expect("stage pending mutation outbox deletion");
    let missing_outbox_error = missing_outbox
        .commit()
        .await
        .expect_err("pending mutation challenge must retain its exact outbox");
    assert_check_violation(
        &missing_outbox_error,
        "pending mutation email challenge requires one exact mail outbox row",
    );

    let immutable_outbox_owner = sqlx::query(
        "UPDATE mail_outbox SET challenge_generation=challenge_generation+1 WHERE id=$1",
    )
    .bind(outbox_id)
    .execute(&pool)
    .await;
    assert!(
        immutable_outbox_owner.is_err(),
        "mail outbox cannot be rebound away from a pending mutation challenge"
    );
    let rewrite_outbox_smtp_authority =
        sqlx::query("UPDATE mail_outbox SET smtp_generation=smtp_generation+1 WHERE id=$1")
            .bind(outbox_id)
            .execute(&pool)
            .await;
    assert!(
        rewrite_outbox_smtp_authority.is_err(),
        "mail outbox cannot diverge from its challenge SMTP authority"
    );

    let evidence_id = Uuid::new_v4();
    let receipt_id = Uuid::new_v4();
    let mut unconsumed = pool.begin().await.expect("begin unconsumed email proof");
    sqlx::query(
        "UPDATE identity_mutation_proof_slots
            SET state='proved',slot_revision=4,proved_at=transaction_timestamp(),
                updated_at=transaction_timestamp()
          WHERE id=$1",
    )
    .bind(email_slot_id)
    .execute(&mut *unconsumed)
    .await
    .expect("stage proved email slot without challenge consumption");
    sqlx::query(
        "INSERT INTO identity_mutation_candidate_evidence
            (id,project_id,intent_id,slot_id,identity_kind,candidate_revision,
             protector_key_version,evidence_ciphertext,evidence_digest,retain_until)
         SELECT $1,$2,$3,$4,'email',1,1,$5,$6,
                intent.expires_at+INTERVAL '15 minutes'
           FROM identity_mutation_intents AS intent WHERE intent.id=$3",
    )
    .bind(evidence_id)
    .bind(fixture.project_id)
    .bind(intent_id)
    .bind(email_slot_id)
    .bind(vec![44_u8; 64])
    .bind(vec![45_u8; 32])
    .execute(&mut *unconsumed)
    .await
    .expect("insert email candidate evidence");
    sqlx::query(
        "INSERT INTO identity_proof_receipts
            (id,project_id,intent_id,slot_id,evidence_kind,identity_kind,
             candidate_evidence_id,evidence_revision,proof_user_id,proof_user_revision,
             proof_user_security_revision,interaction_browser_binding_digest,
             interaction_browser_binding_digest_key_version,
             interaction_browser_binding_revision,captured_intent_revision,purpose,
             receipt_digest,receipt_digest_key_version,status,issued_at,expires_at)
         SELECT $1,$2,$3,$4,'candidate_evidence','email',$5,1,$6,1,1,$7,1,1,
                intent.intent_revision,slot.purpose,$8,1,'issued',slot.proved_at,
                slot.proved_at+INTERVAL '5 minutes'
           FROM identity_mutation_proof_slots AS slot
           JOIN identity_mutation_intents AS intent ON intent.id=slot.intent_id
          WHERE slot.id=$4",
    )
    .bind(receipt_id)
    .bind(fixture.project_id)
    .bind(intent_id)
    .bind(email_slot_id)
    .bind(evidence_id)
    .bind(fixture.winner_user_id)
    .bind(vec![2_u8; 32])
    .bind(vec![46_u8; 32])
    .execute(&mut *unconsumed)
    .await
    .expect("insert unconsumed email receipt");
    sqlx::query(
        "UPDATE identity_mutation_intents
            SET intent_revision=intent_revision+1,updated_at=transaction_timestamp()
          WHERE id=$1",
    )
    .bind(intent_id)
    .execute(&mut *unconsumed)
    .await
    .expect("stage intent revision for unconsumed email proof");
    let unconsumed_error = unconsumed
        .commit()
        .await
        .expect_err("proved email slot requires consumed challenge");
    assert_check_violation(&unconsumed_error, "frozen proof authority");

    let mut proved = pool.begin().await.expect("begin valid email proof");
    sqlx::query(
        "UPDATE email_challenges
            SET status='consumed',consumed_at=transaction_timestamp(),
                terminal_at=transaction_timestamp(),updated_at=transaction_timestamp()
          WHERE id=$1",
    )
    .bind(challenge_id)
    .execute(&mut *proved)
    .await
    .expect("consume mutation email challenge");
    sqlx::query(
        "UPDATE identity_mutation_proof_slots
            SET state='proved',slot_revision=4,proved_at=transaction_timestamp(),
                updated_at=transaction_timestamp()
          WHERE id=$1",
    )
    .bind(email_slot_id)
    .execute(&mut *proved)
    .await
    .expect("prove mutation email slot");
    sqlx::query(
        "INSERT INTO identity_mutation_candidate_evidence
            (id,project_id,intent_id,slot_id,identity_kind,candidate_revision,
             protector_key_version,evidence_ciphertext,evidence_digest,retain_until)
         SELECT $1,$2,$3,$4,'email',1,1,$5,$6,
                intent.expires_at+INTERVAL '15 minutes'
           FROM identity_mutation_intents AS intent WHERE intent.id=$3",
    )
    .bind(evidence_id)
    .bind(fixture.project_id)
    .bind(intent_id)
    .bind(email_slot_id)
    .bind(vec![44_u8; 64])
    .bind(vec![45_u8; 32])
    .execute(&mut *proved)
    .await
    .expect("insert valid email candidate evidence");
    sqlx::query(
        "INSERT INTO identity_proof_receipts
            (id,project_id,intent_id,slot_id,evidence_kind,identity_kind,
             candidate_evidence_id,evidence_revision,proof_user_id,proof_user_revision,
             proof_user_security_revision,interaction_browser_binding_digest,
             interaction_browser_binding_digest_key_version,
             interaction_browser_binding_revision,captured_intent_revision,purpose,
             receipt_digest,receipt_digest_key_version,status,issued_at,expires_at)
         SELECT $1,$2,$3,$4,'candidate_evidence','email',$5,1,$6,1,1,$7,1,1,
                intent.intent_revision,slot.purpose,$8,1,'issued',slot.proved_at,
                slot.proved_at+INTERVAL '5 minutes'
           FROM identity_mutation_proof_slots AS slot
           JOIN identity_mutation_intents AS intent ON intent.id=slot.intent_id
          WHERE slot.id=$4",
    )
    .bind(receipt_id)
    .bind(fixture.project_id)
    .bind(intent_id)
    .bind(email_slot_id)
    .bind(evidence_id)
    .bind(fixture.winner_user_id)
    .bind(vec![2_u8; 32])
    .bind(vec![46_u8; 32])
    .execute(&mut *proved)
    .await
    .expect("insert valid email proof receipt");
    sqlx::query(
        "UPDATE identity_mutation_intents
            SET intent_revision=intent_revision+1,updated_at=transaction_timestamp()
          WHERE id=$1",
    )
    .bind(intent_id)
    .execute(&mut *proved)
    .await
    .expect("advance valid email intent revision");
    proved
        .commit()
        .await
        .expect("commit valid mutation email proof");

    let mut delete_challenge = pool.begin().await.expect("begin challenge deletion");
    sqlx::query("DELETE FROM email_challenges WHERE id=$1")
        .bind(challenge_id)
        .execute(&mut *delete_challenge)
        .await
        .expect("stage consumed challenge deletion");
    let delete_error = delete_challenge
        .commit()
        .await
        .expect_err("proved email slot must retain consumed challenge authority");
    assert_check_violation(&delete_error, "exact current challenge lifecycle");
}

#[tokio::test]
async fn identity_lifecycle_schema_rejects_future_proof_authority() {
    let Some((_container, pool)) = migrated_pool().await else {
        return;
    };
    let fixture = seed_authority(&pool).await;
    let (intent_id, candidate_slot_id) = create_valid_link_intent(&pool, &fixture).await;

    let future_proof = sqlx::query(
        "UPDATE identity_mutation_proof_slots
            SET state='proved',slot_revision=slot_revision+1,
                proved_at=clock_timestamp()+INTERVAL '1 minute',
                updated_at=transaction_timestamp()
          WHERE id=$1",
    )
    .bind(candidate_slot_id)
    .execute(&pool)
    .await
    .expect_err("future proof timestamp must fail before state acceptance");
    assert_check_violation(&future_proof, "proof timestamp must be current");

    let evidence_id = Uuid::new_v4();
    let mut future_receipt = pool.begin().await.expect("begin future receipt fixture");
    sqlx::query("SET LOCAL session_replication_role='replica'")
        .execute(&mut *future_receipt)
        .await
        .expect("suspend slot triggers for synthetic future proof");
    sqlx::query(
        "UPDATE identity_mutation_proof_slots
            SET state='proved',slot_revision=slot_revision+1,
                proved_at=clock_timestamp()+INTERVAL '1 minute',
                updated_at=transaction_timestamp()
          WHERE id=$1",
    )
    .bind(candidate_slot_id)
    .execute(&mut *future_receipt)
    .await
    .expect("seed synthetic future proof timestamp");
    sqlx::query("SET LOCAL session_replication_role='origin'")
        .execute(&mut *future_receipt)
        .await
        .expect("restore proof authority triggers");
    sqlx::query(
        "INSERT INTO identity_mutation_candidate_evidence
            (id,project_id,intent_id,slot_id,identity_kind,candidate_revision,
             protector_key_version,evidence_ciphertext,evidence_digest,retain_until)
         SELECT $1,$2,$3,$4,'provider',1,1,$5,$6,
                intent.expires_at+INTERVAL '15 minutes'
           FROM identity_mutation_intents AS intent WHERE intent.id=$3",
    )
    .bind(evidence_id)
    .bind(fixture.project_id)
    .bind(intent_id)
    .bind(candidate_slot_id)
    .bind(vec![61_u8; 64])
    .bind(vec![62_u8; 32])
    .execute(&mut *future_receipt)
    .await
    .expect("insert synthetic future proof evidence");
    let receipt_error = sqlx::query(
        "INSERT INTO identity_proof_receipts
            (id,project_id,intent_id,slot_id,evidence_kind,identity_kind,
             candidate_evidence_id,evidence_revision,proof_user_id,proof_user_revision,
             proof_user_security_revision,interaction_browser_binding_digest,
             interaction_browser_binding_digest_key_version,
             interaction_browser_binding_revision,captured_intent_revision,purpose,
             receipt_digest,receipt_digest_key_version,status,issued_at,expires_at)
         SELECT $1,$2,$3,$4,'candidate_evidence','provider',$5,1,$6,1,1,$7,1,1,
                intent.intent_revision,slot.purpose,$8,1,'issued',slot.proved_at,
                slot.proved_at+INTERVAL '5 minutes'
           FROM identity_mutation_proof_slots AS slot
           JOIN identity_mutation_intents AS intent ON intent.id=slot.intent_id
          WHERE slot.id=$4",
    )
    .bind(Uuid::new_v4())
    .bind(fixture.project_id)
    .bind(intent_id)
    .bind(candidate_slot_id)
    .bind(evidence_id)
    .bind(fixture.winner_user_id)
    .bind(vec![2_u8; 32])
    .bind(vec![63_u8; 32])
    .execute(&mut *future_receipt)
    .await
    .expect_err("future receipt issue timestamp must fail");
    assert_check_violation(&receipt_error, "receipt issue timestamp must be current");
    future_receipt
        .rollback()
        .await
        .expect("roll back synthetic future receipt fixture");
}

#[tokio::test]
async fn identity_lifecycle_schema_orders_completion_after_receipt_consumption() {
    let Some((_container, pool)) = migrated_pool().await else {
        return;
    };
    let fixture = seed_authority(&pool).await;
    let (intent_id, candidate_slot_id) = create_valid_link_intent(&pool, &fixture).await;
    let owner_slot_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM identity_mutation_proof_slots
          WHERE intent_id=$1 AND slot_role='destination_owner'",
    )
    .bind(intent_id)
    .fetch_one(&pool)
    .await
    .expect("load completion owner slot");
    prove_provider_slot(
        &pool,
        &fixture,
        intent_id,
        owner_slot_id,
        Some(fixture.winner_identity_id),
        None,
    )
    .await;
    let evidence_id = Uuid::new_v4();
    prove_provider_slot(
        &pool,
        &fixture,
        intent_id,
        candidate_slot_id,
        None,
        Some(evidence_id),
    )
    .await;
    sqlx::query(
        "UPDATE identity_mutation_intents
            SET status='ready',intent_revision=intent_revision+1,
                ready_at=transaction_timestamp(),updated_at=transaction_timestamp()
          WHERE id=$1",
    )
    .bind(intent_id)
    .execute(&pool)
    .await
    .expect("mark fully proved intent ready");

    let mut backdated_completion = pool.begin().await.expect("begin backdated completion");
    sqlx::query("SELECT pg_sleep(0.05)")
        .execute(&mut *backdated_completion)
        .await
        .expect("separate transaction start from receipt consumption");
    sqlx::query(
        "UPDATE identity_proof_receipts
            SET status='consumed',consumed_at=clock_timestamp()
          WHERE intent_id=$1",
    )
    .bind(intent_id)
    .execute(&mut *backdated_completion)
    .await
    .expect("consume completion receipts");
    sqlx::query("DELETE FROM identity_mutation_candidate_evidence WHERE id=$1")
        .bind(evidence_id)
        .execute(&mut *backdated_completion)
        .await
        .expect("erase consumed candidate evidence");
    sqlx::query(
        "UPDATE identity_mutation_intents
            SET status='completed',intent_revision=intent_revision+1,
                terminal_at=transaction_timestamp(),updated_at=transaction_timestamp()
          WHERE id=$1",
    )
    .bind(intent_id)
    .execute(&mut *backdated_completion)
    .await
    .expect("stage completion before receipt consumption");
    let error = backdated_completion
        .commit()
        .await
        .expect_err("completion timestamp must not predate receipt consumption");
    assert_check_violation(&error, "fresh consumed receipts");
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the regression carries a complete two-owner merge proof to the false terminal commit"
)]
async fn identity_lifecycle_schema_rejects_completed_merge_without_tombstone() {
    let Some((_container, pool)) = migrated_pool().await else {
        return;
    };
    let fixture = seed_authority(&pool).await;
    let loser_identity_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM linked_identities
          WHERE project_id=$1 AND user_id=$2",
    )
    .bind(fixture.project_id)
    .bind(fixture.loser_user_id)
    .fetch_one(&pool)
    .await
    .expect("load loser merge identity");
    let intent_id = Uuid::new_v4();
    let winner_slot_id = Uuid::new_v4();
    let loser_slot_id = Uuid::new_v4();
    let hosted_digest = intent_id
        .as_bytes()
        .iter()
        .copied()
        .cycle()
        .take(32)
        .collect::<Vec<_>>();
    let mut setup = pool
        .begin()
        .await
        .expect("begin complete merge proof setup");
    sqlx::query(
        "INSERT INTO identity_mutation_intents
            (id,project_id,operation_kind,status,intent_revision,
             project_metadata_revision,project_security_revision,
             winner_user_id,winner_user_revision,winner_user_security_revision,
             loser_user_id,loser_user_revision,loser_user_security_revision,
             primary_source_disposition,primary_provider_identity_id,
             primary_source_identity_revision,sessions_disposition,bindings_disposition,
             hosted_handle_digest,hosted_handle_digest_key_version,
             correlation_id,expires_at)
         VALUES ($1,$2,'merge','pending_proof',1,1,1,$3,1,1,$4,1,1,
                 'provider',$5,1,'loser_revoked','winner_preferred',$6,1,$7,
                 transaction_timestamp()+INTERVAL '10 minutes')",
    )
    .bind(intent_id)
    .bind(fixture.project_id)
    .bind(fixture.winner_user_id)
    .bind(fixture.loser_user_id)
    .bind(fixture.winner_identity_id)
    .bind(hosted_digest)
    .bind(Uuid::new_v4())
    .execute(&mut *setup)
    .await
    .expect("insert merge intent");
    sqlx::query(
        "UPDATE identity_mutation_intents
            SET browser_binding_digest=$1,browser_binding_digest_key_version=1,
                csrf_digest=$2,csrf_digest_key_version=1,browser_binding_revision=1,
                intent_revision=2,updated_at=transaction_timestamp()
          WHERE id=$3 AND intent_revision=1",
    )
    .bind(vec![2_u8; 32])
    .bind(vec![3_u8; 32])
    .bind(intent_id)
    .execute(&mut *setup)
    .await
    .expect("bind merge interaction");
    insert_provider_slot_for_user(
        &mut setup,
        &fixture,
        intent_id,
        winner_slot_id,
        1,
        "winner_owner",
        "merge.winner_owner",
        fixture.winner_user_id,
        Some(fixture.winner_identity_id),
    )
    .await;
    insert_provider_slot_for_user(
        &mut setup,
        &fixture,
        intent_id,
        loser_slot_id,
        2,
        "loser_owner",
        "merge.loser_owner",
        fixture.loser_user_id,
        Some(loser_identity_id),
    )
    .await;
    setup.commit().await.expect("commit merge proof setup");

    prove_provider_slot_for_user(
        &pool,
        &fixture,
        intent_id,
        winner_slot_id,
        fixture.winner_user_id,
        Some(fixture.winner_identity_id),
        None,
    )
    .await;
    prove_provider_slot_for_user(
        &pool,
        &fixture,
        intent_id,
        loser_slot_id,
        fixture.loser_user_id,
        Some(loser_identity_id),
        None,
    )
    .await;
    sqlx::query(
        "UPDATE identity_mutation_intents
            SET status='ready',intent_revision=intent_revision+1,
                ready_at=transaction_timestamp(),updated_at=transaction_timestamp()
          WHERE id=$1",
    )
    .bind(intent_id)
    .execute(&pool)
    .await
    .expect("mark merge proof ready");

    let mut false_completion = pool.begin().await.expect("begin false merge completion");
    sqlx::query(
        "UPDATE identity_proof_receipts
            SET status='consumed',consumed_at=transaction_timestamp()
          WHERE intent_id=$1",
    )
    .bind(intent_id)
    .execute(&mut *false_completion)
    .await
    .expect("consume exact merge receipts");
    sqlx::query(
        "UPDATE identity_mutation_intents
            SET status='completed',intent_revision=intent_revision+1,
                terminal_at=transaction_timestamp(),updated_at=transaction_timestamp()
          WHERE id=$1",
    )
    .bind(intent_id)
    .execute(&mut *false_completion)
    .await
    .expect("stage completed merge without graph transition");
    let error = false_completion
        .commit()
        .await
        .expect_err("completed merge without an exact tombstone must fail");
    assert_check_violation(&error, "one exact merge tombstone");
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the real-expiry regression keeps proof setup and the backdated transition explicit"
)]
async fn identity_lifecycle_schema_uses_actual_time_for_ready_transition() {
    let Some((_container, pool)) = migrated_pool().await else {
        return;
    };
    let fixture = seed_authority(&pool).await;
    let intent_id = Uuid::new_v4();
    let owner_slot_id = Uuid::new_v4();
    let candidate_slot_id = Uuid::new_v4();
    let candidate_evidence_id = Uuid::new_v4();
    let mut setup = pool.begin().await.expect("begin short-lived intent setup");
    sqlx::query(
        "INSERT INTO identity_mutation_intents
            (id,project_id,operation_kind,status,intent_revision,
             project_metadata_revision,project_security_revision,
             destination_user_id,destination_user_revision,
             destination_user_security_revision,primary_source_disposition,
             hosted_handle_digest,hosted_handle_digest_key_version,
             correlation_id,expires_at)
         VALUES ($1,$2,'link','pending_proof',1,1,1,$3,1,1,'preserve',
                 $4,1,$5,clock_timestamp()+INTERVAL '10 seconds')",
    )
    .bind(intent_id)
    .bind(fixture.project_id)
    .bind(fixture.winner_user_id)
    .bind(vec![51_u8; 32])
    .bind(Uuid::new_v4())
    .execute(&mut *setup)
    .await
    .expect("insert short-lived link intent");
    sqlx::query(
        "UPDATE identity_mutation_intents
            SET browser_binding_digest=$1,browser_binding_digest_key_version=1,
                csrf_digest=$2,csrf_digest_key_version=1,browser_binding_revision=1,
                intent_revision=2,updated_at=transaction_timestamp()
          WHERE id=$3",
    )
    .bind(vec![2_u8; 32])
    .bind(vec![53_u8; 32])
    .bind(intent_id)
    .execute(&mut *setup)
    .await
    .expect("bind short-lived intent");
    insert_provider_slot(
        &mut setup,
        &fixture,
        intent_id,
        owner_slot_id,
        1,
        "destination_owner",
        "link.destination_owner",
        Some(fixture.winner_identity_id),
    )
    .await;
    insert_provider_slot(
        &mut setup,
        &fixture,
        intent_id,
        candidate_slot_id,
        2,
        "candidate_identity",
        "link.candidate_identity",
        None,
    )
    .await;
    setup
        .commit()
        .await
        .expect("commit short-lived intent setup");

    prove_provider_slot(
        &pool,
        &fixture,
        intent_id,
        owner_slot_id,
        Some(fixture.winner_identity_id),
        None,
    )
    .await;
    prove_provider_slot(
        &pool,
        &fixture,
        intent_id,
        candidate_slot_id,
        None,
        Some(candidate_evidence_id),
    )
    .await;
    sqlx::query(
        "SELECT pg_sleep(GREATEST(
             EXTRACT(EPOCH FROM (expires_at-clock_timestamp()))+0.1,
             0
         )) FROM identity_mutation_intents WHERE id=$1",
    )
    .bind(intent_id)
    .execute(&pool)
    .await
    .expect("wait until the intent actually expires");

    let mut backdated_ready = pool
        .begin()
        .await
        .expect("begin backdated ready transition");
    sqlx::query(
        "UPDATE identity_mutation_intents
            SET status='ready',intent_revision=intent_revision+1,
                ready_at=created_at+INTERVAL '1 microsecond',
                updated_at=transaction_timestamp()
          WHERE id=$1",
    )
    .bind(intent_id)
    .execute(&mut *backdated_ready)
    .await
    .expect("stage a historically plausible ready timestamp");
    let error = backdated_ready
        .commit()
        .await
        .expect_err("actual expiry must reject a backdated ready timestamp");
    assert_check_violation(&error, "fresh issued receipts");
}

#[tokio::test]
async fn identity_lifecycle_schema_rejects_tombstone_without_merged_loser() {
    let Some((_container, pool)) = migrated_pool().await else {
        return;
    };
    let fixture = seed_authority(&pool).await;
    let intent_id = Uuid::new_v4();
    let correlation_id = Uuid::new_v4();
    let mut transaction = pool.begin().await.expect("begin orphan tombstone fixture");
    sqlx::query("SET LOCAL session_replication_role='replica'")
        .execute(&mut *transaction)
        .await
        .expect("suspend proof children for completed merge intent fixture");
    sqlx::query(
        "INSERT INTO identity_mutation_intents
            (id,project_id,operation_kind,status,intent_revision,
             project_metadata_revision,project_security_revision,
             winner_user_id,winner_user_revision,winner_user_security_revision,
             loser_user_id,loser_user_revision,loser_user_security_revision,
             primary_source_disposition,primary_provider_identity_id,
             primary_source_identity_revision,sessions_disposition,bindings_disposition,
             hosted_handle_digest,hosted_handle_digest_key_version,
             browser_binding_digest,browser_binding_digest_key_version,
             csrf_digest,csrf_digest_key_version,browser_binding_revision,
             correlation_id,expires_at,ready_at,terminal_at)
         VALUES ($1,$2,'merge','completed',1,1,1,$3,1,1,$4,1,1,
                 'provider',$5,1,'loser_revoked','winner_preferred',$6,1,$7,1,$8,1,1,
                 $9,transaction_timestamp()+INTERVAL '10 minutes',
                 transaction_timestamp(),transaction_timestamp())",
    )
    .bind(intent_id)
    .bind(fixture.project_id)
    .bind(fixture.winner_user_id)
    .bind(fixture.loser_user_id)
    .bind(fixture.winner_identity_id)
    .bind(vec![71_u8; 32])
    .bind(vec![72_u8; 32])
    .bind(vec![73_u8; 32])
    .bind(correlation_id)
    .execute(&mut *transaction)
    .await
    .expect("seed synthetic completed merge intent");
    sqlx::query("SET LOCAL session_replication_role='origin'")
        .execute(&mut *transaction)
        .await
        .expect("restore tombstone authority triggers");
    sqlx::query(
        "INSERT INTO project_user_merge_tombstones
            (project_id,loser_user_id,winner_user_id,loser_user_revision,
             winner_user_revision,primary_source_kind,primary_provider_identity_id,
             primary_email_identity_id,sessions_disposition,bindings_disposition,
             merged_at,correlation_id,identity_mutation_intent_id)
         VALUES ($1,$2,$3,1,1,'provider',$4,NULL,'loser_revoked','winner_preferred',
                 transaction_timestamp(),$5,$6)",
    )
    .bind(fixture.project_id)
    .bind(fixture.loser_user_id)
    .bind(fixture.winner_user_id)
    .bind(fixture.winner_identity_id)
    .bind(correlation_id)
    .bind(intent_id)
    .execute(&mut *transaction)
    .await
    .expect("stage tombstone while loser remains active");
    let error = transaction
        .commit()
        .await
        .expect_err("tombstone must reverse-require exact merged loser state");
    assert_check_violation(&error, "exact merged loser and active winner graph");
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the synthetic merged-user fixture and both reverse edge checks stay auditable together"
)]
async fn identity_lifecycle_schema_keeps_merge_winner_active() {
    let Some((_container, pool)) = migrated_pool().await else {
        return;
    };
    let fixture = seed_authority(&pool).await;
    let loser_identity_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM linked_identities
          WHERE project_id=$1 AND user_id=$2",
    )
    .bind(fixture.project_id)
    .bind(fixture.loser_user_id)
    .fetch_one(&pool)
    .await
    .expect("load loser identity");

    // Seed the already-completed side of the invariant without duplicating the full merge service
    // protocol; normal triggers are restored before exercising the reverse winner transition.
    let mut seed_merged = pool.begin().await.expect("begin merged authority seed");
    sqlx::query("SET LOCAL session_replication_role='replica'")
        .execute(&mut *seed_merged)
        .await
        .expect("suspend authority triggers for completed merge fixture");
    sqlx::query(
        "UPDATE project_users
            SET status='merged',merged_into_user_id=$1,
                primary_profile_identity_id=NULL,primary_email_identity_id=NULL
          WHERE project_id=$2 AND id=$3",
    )
    .bind(fixture.winner_user_id)
    .bind(fixture.project_id)
    .bind(fixture.loser_user_id)
    .execute(&mut *seed_merged)
    .await
    .expect("seed merged loser terminal shape");
    sqlx::query("UPDATE linked_identities SET user_id=$1 WHERE id=$2")
        .bind(fixture.winner_user_id)
        .bind(loser_identity_id)
        .execute(&mut *seed_merged)
        .await
        .expect("seed completed loser identity movement");
    sqlx::query(
        "INSERT INTO project_user_merge_tombstones
            (project_id,loser_user_id,winner_user_id,loser_user_revision,
             winner_user_revision,primary_source_kind,primary_provider_identity_id,
             primary_email_identity_id,sessions_disposition,bindings_disposition,
             merged_at,correlation_id,identity_mutation_intent_id)
         VALUES ($1,$2,$3,1,1,'provider',$4,NULL,'loser_revoked','winner_preferred',
                 transaction_timestamp(),$5,$6)",
    )
    .bind(fixture.project_id)
    .bind(fixture.loser_user_id)
    .bind(fixture.winner_user_id)
    .bind(fixture.winner_identity_id)
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .execute(&mut *seed_merged)
    .await
    .expect("seed completed merge tombstone");
    seed_merged
        .commit()
        .await
        .expect("commit completed merge fixture");

    let (wrong_primary_owner_id, _) = seed_user_with_provider_identity(
        &pool,
        fixture.project_id,
        fixture.provider_id,
        "wrong-primary-owner",
    )
    .await;
    let replacement_primary_identity_id = Uuid::new_v4();
    let mut replace_primary = pool
        .begin()
        .await
        .expect("begin winner primary replacement");
    sqlx::query(
        "INSERT INTO linked_identities
            (id,project_id,user_id,created_via_provider_configuration_id,issuer,subject,
             status,identity_revision,source_profile_digest,observed_at)
         VALUES ($1,$2,$3,$4,'https://issuer.example','winner-primary-replacement',
                 'active',1,public.owlauth_provider_source_profile_digest(NULL,NULL,NULL),transaction_timestamp())",
    )
    .bind(replacement_primary_identity_id)
    .bind(fixture.project_id)
    .bind(fixture.winner_user_id)
    .bind(fixture.provider_id)
    .execute(&mut *replace_primary)
    .await
    .expect("insert replacement winner primary identity");
    sqlx::query(
        "UPDATE project_users
            SET primary_profile_identity_id=$1,user_revision=user_revision+1,
                updated_at=transaction_timestamp()
          WHERE id=$2",
    )
    .bind(replacement_primary_identity_id)
    .bind(fixture.winner_user_id)
    .execute(&mut *replace_primary)
    .await
    .expect("select replacement winner primary identity");
    replace_primary
        .commit()
        .await
        .expect("commit winner primary replacement");

    let move_tombstone_primary = sqlx::query(
        "UPDATE linked_identities
            SET user_id=$1,identity_revision=identity_revision+1,
                updated_at=transaction_timestamp()
          WHERE id=$2",
    )
    .bind(wrong_primary_owner_id)
    .bind(fixture.winner_identity_id)
    .execute(&pool)
    .await
    .expect_err("merge tombstone primary source cannot leave its exact winner");
    assert_check_violation(
        &move_tombstone_primary,
        "primary source must belong to its exact winner",
    );

    let mut restore_identity_edge = pool
        .begin()
        .await
        .expect("begin merged identity edge insertion");
    sqlx::query(
        "INSERT INTO linked_identities
            (id,project_id,user_id,created_via_provider_configuration_id,issuer,subject,
             status,identity_revision,source_profile_digest,observed_at)
         VALUES ($1,$2,$3,$4,'https://issuer.example','merged-owner-edge',
                 'active',1,public.owlauth_provider_source_profile_digest(NULL,NULL,NULL),transaction_timestamp())",
    )
    .bind(Uuid::new_v4())
    .bind(fixture.project_id)
    .bind(fixture.loser_user_id)
    .bind(fixture.provider_id)
    .execute(&mut *restore_identity_edge)
    .await
    .expect("stage identity edge to merged loser");
    let identity_error = restore_identity_edge
        .commit()
        .await
        .expect_err("merged loser cannot regain an identity edge");
    assert_check_violation(&identity_error, "cannot retain an identity owner edge");

    let mut disable_winner = pool.begin().await.expect("begin winner disable");
    sqlx::query(
        "UPDATE project_users
            SET status='disabled',security_revision=security_revision+1,
                updated_at=transaction_timestamp()
          WHERE project_id=$1 AND id=$2",
    )
    .bind(fixture.project_id)
    .bind(fixture.winner_user_id)
    .execute(&mut *disable_winner)
    .await
    .expect("stage merge winner disable");
    let error = disable_winner
        .commit()
        .await
        .expect_err("a merge winner must remain active");
    assert_check_violation(&error, "active winner and completed tombstone");

    let mut cleanup = pool.begin().await.expect("begin merged fixture cleanup");
    sqlx::query("SET LOCAL session_replication_role='replica'")
        .execute(&mut *cleanup)
        .await
        .expect("suspend authority triggers for fixture cleanup");
    sqlx::query(
        "DELETE FROM project_user_merge_tombstones
          WHERE project_id=$1 AND loser_user_id=$2",
    )
    .bind(fixture.project_id)
    .bind(fixture.loser_user_id)
    .execute(&mut *cleanup)
    .await
    .expect("remove synthetic merge tombstone");
    sqlx::query("UPDATE linked_identities SET user_id=$1 WHERE id=$2")
        .bind(fixture.loser_user_id)
        .bind(loser_identity_id)
        .execute(&mut *cleanup)
        .await
        .expect("restore loser identity ownership");
    sqlx::query(
        "UPDATE project_users
            SET status='active',merged_into_user_id=NULL,primary_profile_identity_id=$1
          WHERE project_id=$2 AND id=$3",
    )
    .bind(loser_identity_id)
    .bind(fixture.project_id)
    .bind(fixture.loser_user_id)
    .execute(&mut *cleanup)
    .await
    .expect("restore loser authority");
    cleanup.commit().await.expect("clean up merged fixture");
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "binding attribution test keeps exact user, winner, movement, and deletion edges visible"
)]
async fn identity_lifecycle_schema_preserves_merged_binding_attribution() {
    let Some((_container, pool)) = migrated_pool().await else {
        return;
    };
    let fixture = seed_authority(&pool).await;
    let mut merge = pool.begin().await.expect("begin binding merge fixture");
    stage_synthetic_project_user_merge(
        &mut merge,
        fixture.project_id,
        fixture.loser_user_id,
        fixture.winner_user_id,
        fixture.winner_identity_id,
    )
    .await;
    merge.commit().await.expect("commit binding merge fixture");

    let active_loser_binding = sqlx::query(
        "INSERT INTO application_user_bindings
            (id,project_id,application_id,user_id,status,binding_revision)
         VALUES ($1,$2,$3,$4,'active',1)",
    )
    .bind(Uuid::new_v4())
    .bind(fixture.project_id)
    .bind(fixture.application_id)
    .bind(fixture.loser_user_id)
    .execute(&pool)
    .await
    .expect_err("merged loser cannot gain an active binding");
    assert_check_violation(
        &active_loser_binding,
        "cannot own a live Application binding",
    );

    let retained_binding_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO application_user_bindings
            (id,project_id,application_id,user_id,status,binding_revision)
         VALUES ($1,$2,$3,$4,'active',1)",
    )
    .bind(retained_binding_id)
    .bind(fixture.project_id)
    .bind(fixture.application_id)
    .bind(fixture.winner_user_id)
    .execute(&pool)
    .await
    .expect("insert retained winner binding");

    let move_active_to_loser = sqlx::query(
        "UPDATE application_user_bindings
            SET user_id=$1,binding_revision=binding_revision+1,
                updated_at=transaction_timestamp()
          WHERE id=$2",
    )
    .bind(fixture.loser_user_id)
    .bind(retained_binding_id)
    .execute(&pool)
    .await
    .expect_err("active binding cannot move to a merged loser");
    assert_check_violation(
        &move_active_to_loser,
        "cannot own a live Application binding",
    );

    let (wrong_winner_user_id, _) = seed_user_with_provider_identity(
        &pool,
        fixture.project_id,
        fixture.provider_id,
        "binding-wrong-winner",
    )
    .await;
    let wrong_winner_binding_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO application_user_bindings
            (id,project_id,application_id,user_id,status,binding_revision)
         VALUES ($1,$2,$3,$4,'active',1)",
    )
    .bind(wrong_winner_binding_id)
    .bind(fixture.project_id)
    .bind(fixture.application_id)
    .bind(wrong_winner_user_id)
    .execute(&pool)
    .await
    .expect("insert unrelated retained binding");
    let wrong_winner_binding = sqlx::query(
        "INSERT INTO application_user_bindings
            (id,project_id,application_id,user_id,status,binding_revision,
             merged_into_binding_id,merged_at)
         VALUES ($1,$2,$3,$4,'merged',1,$5,transaction_timestamp())",
    )
    .bind(Uuid::new_v4())
    .bind(fixture.project_id)
    .bind(fixture.application_id)
    .bind(fixture.loser_user_id)
    .bind(wrong_winner_binding_id)
    .execute(&pool)
    .await
    .expect_err("merged binding cannot target an unrelated user's binding");
    assert_check_violation(&wrong_winner_binding, "Project-user merge winner");

    let (active_source_user_id, _) = seed_user_with_provider_identity(
        &pool,
        fixture.project_id,
        fixture.provider_id,
        "binding-active-source",
    )
    .await;
    let active_source_tombstone = sqlx::query(
        "INSERT INTO application_user_bindings
            (id,project_id,application_id,user_id,status,binding_revision,
             merged_into_binding_id,merged_at)
         VALUES ($1,$2,$3,$4,'merged',1,$5,transaction_timestamp())",
    )
    .bind(Uuid::new_v4())
    .bind(fixture.project_id)
    .bind(fixture.application_id)
    .bind(active_source_user_id)
    .bind(retained_binding_id)
    .execute(&pool)
    .await
    .expect_err("active Project user cannot own a merged binding tombstone");
    assert_check_violation(&active_source_tombstone, "Project-user merge winner");

    let merged_binding_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO application_user_bindings
            (id,project_id,application_id,user_id,status,binding_revision,
             merged_into_binding_id,merged_at)
         VALUES ($1,$2,$3,$4,'merged',1,$5,transaction_timestamp())",
    )
    .bind(merged_binding_id)
    .bind(fixture.project_id)
    .bind(fixture.application_id)
    .bind(fixture.loser_user_id)
    .bind(retained_binding_id)
    .execute(&pool)
    .await
    .expect("insert exact merged binding attribution");

    let delete_merged = sqlx::query("DELETE FROM application_user_bindings WHERE id=$1")
        .bind(merged_binding_id)
        .execute(&pool)
        .await
        .expect_err("merged binding attribution cannot be deleted");
    assert_check_violation(&delete_merged, "attribution cannot be deleted");
}

#[tokio::test]
async fn identity_lifecycle_schema_serializes_reciprocal_project_user_merges() {
    let Some((_container, pool)) = migrated_pool().await else {
        return;
    };
    let fixture = seed_authority(&pool).await;
    let loser_identity_id: Uuid =
        sqlx::query_scalar("SELECT id FROM linked_identities WHERE project_id=$1 AND user_id=$2")
            .bind(fixture.project_id)
            .bind(fixture.loser_user_id)
            .fetch_one(&pool)
            .await
            .expect("load reciprocal merge loser identity");

    let mut first_merge = pool.begin().await.expect("begin first user merge");
    let mut second_merge = pool.begin().await.expect("begin reciprocal user merge");
    stage_synthetic_project_user_merge(
        &mut first_merge,
        fixture.project_id,
        fixture.winner_user_id,
        fixture.loser_user_id,
        loser_identity_id,
    )
    .await;
    stage_synthetic_project_user_merge(
        &mut second_merge,
        fixture.project_id,
        fixture.loser_user_id,
        fixture.winner_user_id,
        fixture.winner_identity_id,
    )
    .await;
    let (first_result, second_result) = tokio::join!(first_merge.commit(), second_merge.commit());
    assert_ne!(
        first_result.is_ok(),
        second_result.is_ok(),
        "the Project identity-graph lock permits exactly one reciprocal user merge"
    );
    let valid_users: (i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE status='active'),
                count(*) FILTER (WHERE status='merged')
           FROM project_users
          WHERE project_id=$1 AND id=ANY($2)",
    )
    .bind(fixture.project_id)
    .bind(vec![fixture.winner_user_id, fixture.loser_user_id])
    .fetch_one(&pool)
    .await
    .expect("inspect serialized reciprocal user merge");
    assert_eq!(valid_users, (1, 1));
}

#[tokio::test]
async fn identity_lifecycle_schema_serializes_merge_against_identity_attach() {
    let Some((_container, pool)) = migrated_pool().await else {
        return;
    };
    let fixture = seed_authority(&pool).await;
    let (race_winner_id, race_winner_identity_id) = seed_user_with_provider_identity(
        &pool,
        fixture.project_id,
        fixture.provider_id,
        "merge-race-winner",
    )
    .await;
    let (race_loser_id, _) = seed_user_with_provider_identity(
        &pool,
        fixture.project_id,
        fixture.provider_id,
        "merge-race-loser",
    )
    .await;
    let attached_identity_id = Uuid::new_v4();
    let mut merge = pool.begin().await.expect("begin merge-vs-attach merge");
    let mut attach = pool
        .begin()
        .await
        .expect("begin merge-vs-attach identity edge");
    stage_synthetic_project_user_merge(
        &mut merge,
        fixture.project_id,
        race_loser_id,
        race_winner_id,
        race_winner_identity_id,
    )
    .await;
    sqlx::query(
        "INSERT INTO linked_identities
            (id,project_id,user_id,created_via_provider_configuration_id,issuer,subject,
             status,identity_revision,source_profile_digest,observed_at)
         VALUES ($1,$2,$3,$4,'https://issuer.example',$5,'active',1,public.owlauth_provider_source_profile_digest(NULL,NULL,NULL),
                 transaction_timestamp())",
    )
    .bind(attached_identity_id)
    .bind(fixture.project_id)
    .bind(race_loser_id)
    .bind(fixture.provider_id)
    .bind(format!("merge-attach-{attached_identity_id}"))
    .execute(&mut *attach)
    .await
    .expect("stage concurrent identity owner edge");
    let (merge_result, attach_result) = tokio::join!(merge.commit(), attach.commit());
    assert_ne!(
        merge_result.is_ok(),
        attach_result.is_ok(),
        "merge and identity attach cannot both commit for one loser"
    );
    let merged_identity_edges: i64 = sqlx::query_scalar(
        "SELECT count(*)
           FROM project_users AS project_user
           JOIN linked_identities AS identity
             ON identity.project_id=project_user.project_id
            AND identity.user_id=project_user.id
          WHERE project_user.project_id=$1 AND project_user.status='merged'",
    )
    .bind(fixture.project_id)
    .fetch_one(&pool)
    .await
    .expect("inspect merge-vs-attach final graph");
    assert_eq!(merged_identity_edges, 0);
}
