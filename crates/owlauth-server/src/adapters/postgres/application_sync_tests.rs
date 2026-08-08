use std::{collections::BTreeMap, env, sync::Arc, time::Duration};

use async_trait::async_trait;
use owlauth_key_provider::{ProviderFormatVersion, ProviderId};
use sea_orm::{Database, EntityTrait, TransactionTrait};
use sqlx::{PgPool, postgres::PgPoolOptions};
use testcontainers::{
    GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor, wait::LogWaitStrategy},
    runners::AsyncRunner,
};
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    entity::{application_user_projection, project_user},
    projection::projection_material,
    webhook::{PostgresWebhookRepository, append_projection_event},
};
use crate::{
    adapters::{
        custody::SoftwareCustodyProvider, protected_runtime::PostgresProtectedRuntimeCustody,
        runtime_security::SoftwareProjectionVerifiedEmailProtector, system::SystemClock,
    },
    application::{
        ApplicationError, ConfigurationSecretSealers, CreateWebhookEndpoint,
        PrepareWebhookSecretRotation, WebhookControlService, WebhookDeliveryRepository,
        WebhookEndpointValidator, WebhookSecretResolver, WebhookTransportOutcome,
    },
    domain::{ApplicationUserEventType, WebhookDeliveryOutcome},
};

const POSTGRES_PORT: u16 = 5432;
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

fn docker_is_required() -> bool {
    env::var("OWLAUTH_REQUIRE_DOCKER").is_ok_and(|value| value == "1")
}

async fn fixture() -> Option<(
    testcontainers::ContainerAsync<GenericImage>,
    PgPool,
    sea_orm::DatabaseConnection,
)> {
    let container = match GenericImage::new("postgres", "17-bookworm")
        .with_exposed_port(POSTGRES_PORT.tcp())
        .with_wait_for(WaitFor::log(LogWaitStrategy::stderr(
            "database system is ready to accept connections",
        )))
        .with_env_var("POSTGRES_DB", "owlauth_application_sync_test")
        .with_env_var("POSTGRES_USER", "owlauth")
        .with_env_var("POSTGRES_PASSWORD", "owlauth_test")
        .start()
        .await
    {
        Ok(container) => container,
        Err(error) => {
            assert!(
                !docker_is_required(),
                "PostgreSQL application-sync test container is required: {error}"
            );
            eprintln!("skipping application-sync test: Docker unavailable: {error}");
            return None;
        }
    };
    let host = container.get_host().await.expect("container host");
    let port = container
        .get_host_port_ipv4(POSTGRES_PORT)
        .await
        .expect("container port");
    let url =
        format!("postgres://owlauth:owlauth_test@{host}:{port}/owlauth_application_sync_test");
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .expect("connect application-sync database");
    MIGRATOR.run(&pool).await.expect("apply all migrations");
    let database = Database::connect(&url)
        .await
        .expect("connect SeaORM application-sync database");
    Some((container, pool, database))
}

struct TestEndpointValidator;

#[async_trait]
impl WebhookEndpointValidator for TestEndpointValidator {
    async fn validate(&self, endpoint_url: &str) -> Result<(), ApplicationError> {
        if endpoint_url == "https://receiver.example.test/owlauth" {
            Ok(())
        } else {
            Err(ApplicationError::Disabled)
        }
    }
}

fn projection_protector() -> Arc<SoftwareProjectionVerifiedEmailProtector> {
    Arc::new(
        SoftwareProjectionVerifiedEmailProtector::new(
            "application-sync-test".to_owned(),
            1,
            [9; 32],
            BTreeMap::new(),
        )
        .expect("test projection protector"),
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "the fixture seeds one exact referentially complete Project user graph"
)]
async fn seed_projection(
    pool: &PgPool,
    database: &sea_orm::DatabaseConnection,
    project_id: Uuid,
    application_id: Uuid,
    user_id: Uuid,
    binding_id: Uuid,
    projection_id: Uuid,
) {
    let created_at = "2026-08-01T00:00:00Z";
    sqlx::query(
        "INSERT INTO projects
            (id,public_id,display_name,status,metadata_revision,security_revision,created_at,updated_at)
         VALUES ($1,'prj_sync01','Sync Project','active',1,1,$2::timestamptz,$2::timestamptz)",
    )
    .bind(project_id)
    .bind(created_at)
    .execute(pool)
    .await
    .expect("seed Project");
    sqlx::query("INSERT INTO project_policies (project_id) VALUES ($1)")
        .bind(project_id)
        .execute(pool)
        .await
        .expect("seed Project policy");
    sqlx::query(
        "INSERT INTO applications
            (id,project_id,public_id,display_name,application_type,status,revision,
             metadata_revision,security_revision,created_at,updated_at)
         VALUES ($1,$2,'app_sync01','Sync App','web','active',1,1,1,
             $3::timestamptz,$3::timestamptz)",
    )
    .bind(application_id)
    .bind(project_id)
    .bind(created_at)
    .execute(pool)
    .await
    .expect("seed Application");
    let provider_id = Uuid::new_v4();
    let identity_id = Uuid::new_v4();
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
         SELECT $1,$2,'oidc-sync','oidc','OIDC Sync','https://issuer.example.test',
                'sync-client','https://runtime.example.test/callback',material.id,
                'active',1 FROM material",
    )
    .bind(provider_id)
    .bind(project_id)
    .execute(pool)
    .await
    .expect("seed provider");
    let mut identity_transaction = pool.begin().await.expect("begin identity seed");
    sqlx::query(
        "INSERT INTO project_users
            (id,project_id,public_id,status,user_revision,security_revision,base_profile_digest,
             display_name,created_at,updated_at)
         VALUES ($1,$2,'usr_sync01','active',1,1,$3,'Ada',
             $4::timestamptz,$4::timestamptz)",
    )
    .bind(user_id)
    .bind(project_id)
    .bind(vec![3_u8; 32])
    .bind(created_at)
    .execute(&mut *identity_transaction)
    .await
    .expect("seed Project user");
    sqlx::query(
        "INSERT INTO linked_identities
            (id,project_id,user_id,created_via_provider_configuration_id,issuer,subject,
             status,identity_revision,source_profile_digest,display_name,observed_at,created_at,updated_at)
         VALUES ($1,$2,$3,$4,'https://issuer.example.test','sync-subject','active',1,public.owlauth_provider_source_profile_digest('Ada',NULL,NULL),
             'Ada',$5::timestamptz,$5::timestamptz,$5::timestamptz)",
    )
    .bind(identity_id)
    .bind(project_id)
    .bind(user_id)
    .bind(provider_id)
    .bind(created_at)
    .execute(&mut *identity_transaction)
    .await
    .expect("seed provider identity");
    sqlx::query("UPDATE project_users SET primary_profile_identity_id=$2 WHERE id=$1")
        .bind(user_id)
        .bind(identity_id)
        .execute(&mut *identity_transaction)
        .await
        .expect("select exact primary identity");
    identity_transaction
        .commit()
        .await
        .expect("commit exact identity graph");
    sqlx::query(
        "INSERT INTO application_user_bindings
            (id,project_id,application_id,user_id,status,binding_revision,created_at,updated_at)
         VALUES ($1,$2,$3,$4,'active',1,$5::timestamptz,$5::timestamptz)",
    )
    .bind(binding_id)
    .bind(project_id)
    .bind(application_id)
    .bind(user_id)
    .bind(created_at)
    .execute(pool)
    .await
    .expect("seed Application binding");

    let user = project_user::Entity::find_by_id(user_id)
        .one(database)
        .await
        .expect("read seeded user")
        .expect("seeded user exists");
    let (document, digest) = projection_material(&user, 1).expect("initial projection");
    sqlx::query(
        "INSERT INTO application_user_projections
            (id,project_id,binding_id,application_id,user_id,schema_name,projection_revision,
             source_user_revision,canonical_digest,source_base_profile_digest,document,
             created_at,updated_at)
         VALUES ($1,$2,$3,$4,$5,'owlauth.user.v1',1,1,$6,$7,$8,
             $9::timestamptz,$9::timestamptz)",
    )
    .bind(projection_id)
    .bind(project_id)
    .bind(binding_id)
    .bind(application_id)
    .bind(user_id)
    .bind(digest)
    .bind(user.base_profile_digest)
    .bind(document)
    .bind(created_at)
    .execute(pool)
    .await
    .expect("seed Application projection");
}

async fn insert_scoped_event(
    pool: &PgPool,
    project_id: Uuid,
    application_id: Uuid,
    binding_id: Uuid,
    user_id: Uuid,
    projection_revision: i64,
) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO application_user_events
            (id,event_id,project_id,application_id,binding_id,user_id,event_type,
             user_revision,projection_revision,projection_schema,safe_body,
             canonical_body_digest,occurred_at,replay_until,retain_until,created_at)
         VALUES ($1,$2,$3,$4,$5,$6,'user.projection.updated',1,$7,'owlauth.user.v1',
                 jsonb_build_object('data',jsonb_build_object('projection',
                     jsonb_build_object('verified_email',NULL))),
                 decode(repeat('00',32),'hex'),transaction_timestamp(),
                 transaction_timestamp()+interval '29 days',
                 transaction_timestamp()+interval '30 days',transaction_timestamp())",
    )
    .bind(id)
    .bind(format!("evt_{}", id.simple()))
    .bind(project_id)
    .bind(application_id)
    .bind(binding_id)
    .bind(user_id)
    .bind(projection_revision)
    .execute(pool)
    .await?;
    Ok(id)
}

async fn insert_pending_endpoint(pool: &PgPool, project_id: Uuid, application_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO webhook_endpoints
            (id,project_id,application_id,public_id,idempotency_key,
             secret_request_fingerprint,url,subscribed_event_types,status,revision,
             created_at,updated_at)
         VALUES ($1,$2,$3,$4,$5,decode(repeat('01',32),'hex'),$6,
                 ARRAY['user.projection.updated'],'pending',1,
                 transaction_timestamp(),transaction_timestamp())",
    )
    .bind(id)
    .bind(project_id)
    .bind(application_id)
    .bind(format!("whk_{}", id.simple()))
    .bind(format!("endpoint-{id}"))
    .bind(format!("https://{id}.example.test/owlauth"))
    .execute(pool)
    .await
    .expect("insert scoped pending endpoint");
    id
}

async fn insert_scoped_delivery(
    pool: &PgPool,
    project_id: Uuid,
    application_id: Uuid,
    endpoint_id: Uuid,
    event_id: Uuid,
    replay_of_delivery_id: Option<Uuid>,
) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::new_v4();
    let replay_sequence = i32::from(replay_of_delivery_id.is_some());
    sqlx::query(
        "INSERT INTO webhook_deliveries
            (id,project_id,application_id,endpoint_id,event_id,replay_sequence,
             replay_of_delivery_id,state,attempt_count,next_attempt_at,lease_generation,
             created_at,updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,'pending',0,transaction_timestamp(),0,
                 transaction_timestamp(),transaction_timestamp())",
    )
    .bind(id)
    .bind(project_id)
    .bind(application_id)
    .bind(endpoint_id)
    .bind(event_id)
    .bind(replay_sequence)
    .bind(replay_of_delivery_id)
    .execute(pool)
    .await?;
    Ok(id)
}

fn assert_foreign_key_violation(error: &sqlx::Error) {
    let code = error
        .as_database_error()
        .expect("PostgreSQL database error")
        .code();
    assert_eq!(code.as_deref(), Some("23503"));
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the real PostgreSQL test keeps every cross-scope webhook edge explicit"
)]
async fn webhook_graph_rejects_cross_scope_events_deliveries_and_replay_parents() {
    let Some((_container, pool, database)) = fixture().await else {
        return;
    };
    let project_a = Uuid::new_v4();
    let application_a = Uuid::new_v4();
    let user_a = Uuid::new_v4();
    let binding_a = Uuid::new_v4();
    seed_projection(
        &pool,
        &database,
        project_a,
        application_a,
        user_a,
        binding_a,
        Uuid::new_v4(),
    )
    .await;

    let application_b = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO applications
            (id,project_id,public_id,status,revision,metadata_revision,security_revision)
         VALUES ($1,$2,$3,'active',1,1,1)",
    )
    .bind(application_b)
    .bind(project_a)
    .bind(format!("app_{}", application_b.simple()))
    .execute(&pool)
    .await
    .expect("insert second Application");
    let binding_b = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO application_user_bindings
            (id,project_id,application_id,user_id,status,binding_revision)
         VALUES ($1,$2,$3,$4,'active',1)",
    )
    .bind(binding_b)
    .bind(project_a)
    .bind(application_b)
    .bind(user_a)
    .execute(&pool)
    .await
    .expect("insert second Application binding");

    let project_b = Uuid::new_v4();
    let application_c = Uuid::new_v4();
    let user_b = Uuid::new_v4();
    let binding_c = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO projects (id,public_id,status,metadata_revision,security_revision)
         VALUES ($1,$2,'active',1,1)",
    )
    .bind(project_b)
    .bind(format!("prj_{}", project_b.simple()))
    .execute(&pool)
    .await
    .expect("insert second Project");
    sqlx::query(
        "INSERT INTO applications
            (id,project_id,public_id,status,revision,metadata_revision,security_revision)
         VALUES ($1,$2,$3,'active',1,1,1)",
    )
    .bind(application_c)
    .bind(project_b)
    .bind(format!("app_{}", application_c.simple()))
    .execute(&pool)
    .await
    .expect("insert cross-Project Application");
    let provider_b = Uuid::new_v4();
    let identity_b = Uuid::new_v4();
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
         SELECT $1,$2,'scope-test','oidc','Scope Test','https://issuer.scope.test',
                'scope-client','https://runtime.scope.test/callback',material.id,
                'active',1 FROM material",
    )
    .bind(provider_b)
    .bind(project_b)
    .execute(&pool)
    .await
    .expect("insert cross-Project provider");
    let mut user_transaction = pool.begin().await.expect("begin cross-Project user seed");
    sqlx::query(
        "INSERT INTO project_users
            (id,project_id,public_id,status,user_revision,security_revision,base_profile_digest)
         VALUES ($1,$2,$3,'active',1,1,decode(repeat('02',32),'hex'))",
    )
    .bind(user_b)
    .bind(project_b)
    .bind(format!("usr_{}", user_b.simple()))
    .execute(&mut *user_transaction)
    .await
    .expect("insert cross-Project user");
    sqlx::query(
        "INSERT INTO linked_identities
            (id,project_id,user_id,created_via_provider_configuration_id,issuer,subject,
             status,identity_revision,source_profile_digest,observed_at)
         VALUES ($1,$2,$3,$4,'https://issuer.scope.test','scope-subject','active',1,public.owlauth_provider_source_profile_digest(NULL,NULL,NULL),
                 transaction_timestamp())",
    )
    .bind(identity_b)
    .bind(project_b)
    .bind(user_b)
    .bind(provider_b)
    .execute(&mut *user_transaction)
    .await
    .expect("insert cross-Project identity");
    sqlx::query("UPDATE project_users SET primary_profile_identity_id=$2 WHERE id=$1")
        .bind(user_b)
        .bind(identity_b)
        .execute(&mut *user_transaction)
        .await
        .expect("select cross-Project primary identity");
    user_transaction
        .commit()
        .await
        .expect("commit cross-Project user seed");
    sqlx::query(
        "INSERT INTO application_user_bindings
            (id,project_id,application_id,user_id,status,binding_revision)
         VALUES ($1,$2,$3,$4,'active',1)",
    )
    .bind(binding_c)
    .bind(project_b)
    .bind(application_c)
    .bind(user_b)
    .execute(&pool)
    .await
    .expect("insert cross-Project binding");

    let event_a = insert_scoped_event(&pool, project_a, application_a, binding_a, user_a, 1)
        .await
        .expect("insert first scoped event");
    let event_a2 = insert_scoped_event(&pool, project_a, application_a, binding_a, user_a, 2)
        .await
        .expect("insert second scoped event");
    let event_b = insert_scoped_event(&pool, project_a, application_b, binding_b, user_a, 1)
        .await
        .expect("insert second Application event");
    let _event_c = insert_scoped_event(&pool, project_b, application_c, binding_c, user_b, 1)
        .await
        .expect("insert second Project event");

    assert_foreign_key_violation(
        &insert_scoped_event(&pool, project_a, application_b, binding_a, user_a, 3)
            .await
            .expect_err("cross-Application binding attribution must fail"),
    );
    assert_foreign_key_violation(
        &insert_scoped_event(&pool, project_a, application_a, binding_a, user_b, 3)
            .await
            .expect_err("cross-Project historical user attribution must fail"),
    );

    let endpoint_a = insert_pending_endpoint(&pool, project_a, application_a).await;
    let endpoint_a2 = insert_pending_endpoint(&pool, project_a, application_a).await;
    let endpoint_b = insert_pending_endpoint(&pool, project_a, application_b).await;
    let endpoint_c = insert_pending_endpoint(&pool, project_b, application_c).await;
    sqlx::query(
        "INSERT INTO webhook_application_dispatch_state (project_id,application_id)
         VALUES ($1,$2),($1,$3),($4,$5)",
    )
    .bind(project_a)
    .bind(application_a)
    .bind(application_b)
    .bind(project_b)
    .bind(application_c)
    .execute(&pool)
    .await
    .expect("insert bounded dispatch ownership rows");
    let delivery_a =
        insert_scoped_delivery(&pool, project_a, application_a, endpoint_a, event_a, None)
            .await
            .expect("insert first scoped delivery");
    assert_foreign_key_violation(
        &insert_scoped_delivery(&pool, project_a, application_b, endpoint_b, event_a, None)
            .await
            .expect_err("cross-Application event delivery must fail"),
    );
    assert_foreign_key_violation(
        &insert_scoped_delivery(&pool, project_b, application_c, endpoint_c, event_a, None)
            .await
            .expect_err("cross-Project event delivery must fail"),
    );
    assert_foreign_key_violation(
        &insert_scoped_delivery(
            &pool,
            project_a,
            application_a,
            endpoint_a,
            event_a2,
            Some(delivery_a),
        )
        .await
        .expect_err("cross-event replay parent must fail"),
    );
    assert_foreign_key_violation(
        &insert_scoped_delivery(
            &pool,
            project_a,
            application_a,
            endpoint_a2,
            event_a,
            Some(delivery_a),
        )
        .await
        .expect_err("cross-endpoint replay parent must fail"),
    );
    assert!(
        insert_scoped_delivery(&pool, project_a, application_b, endpoint_b, event_b, None,)
            .await
            .is_ok()
    );
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one real PostgreSQL journey proves protected webhook sealing, exact delivery snapshots, replay conflict, and atomic erasure"
)]
async fn protected_webhook_material_is_stable_openable_and_atomically_erased() {
    let Some((_container, pool, database)) = fixture().await else {
        return;
    };
    let project_id = Uuid::new_v4();
    let application_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let binding_id = Uuid::new_v4();
    let projection_id = Uuid::new_v4();
    seed_projection(
        &pool,
        &database,
        project_id,
        application_id,
        user_id,
        binding_id,
        projection_id,
    )
    .await;

    let provider_id = ProviderId::new("software").expect("software provider ID");
    let provider_format_version = ProviderFormatVersion::new(1).expect("provider format");
    let custody = SoftwareCustodyProvider::new(provider_id.clone(), [73; 32])
        .expect("software custody provider");
    let repository = Arc::new(
        PostgresWebhookRepository::new(database.clone(), projection_protector())
            .with_custody(
                "application-sync-protected-webhook",
                provider_id.clone(),
                provider_format_version,
            )
            .expect("compose protected webhook repository"),
    );
    let service = WebhookControlService::new_protected(
        repository.clone(),
        ConfigurationSecretSealers::single(custody.clone()),
        Arc::new(TestEndpointValidator),
        Arc::new(SystemClock),
    );
    let create = |secret_byte| CreateWebhookEndpoint {
        url: "https://receiver.example.test/owlauth".to_owned(),
        subscribed_event_types: vec!["user.projection.updated".to_owned()],
        secret: Zeroizing::new(vec![secret_byte; 32]),
        idempotency_key: "protected-webhook-create".to_owned(),
    };
    let endpoint = service
        .create_endpoint(project_id, application_id, create(91), Uuid::new_v4())
        .await
        .expect("create protected webhook endpoint");
    let (material_id, safe_fingerprint, first_envelope, material_state): (
        Uuid,
        Option<String>,
        Vec<u8>,
        String,
    ) = sqlx::query_as(
        "SELECT secret.material_id,secret.safe_fingerprint,
                material.opaque_value,material.state
           FROM webhook_secret_generations secret
           JOIN protected_materials material ON material.id=secret.material_id
          WHERE secret.endpoint_id=$1 AND secret.generation=1",
    )
    .bind(endpoint.id)
    .fetch_one(&pool)
    .await
    .expect("read protected webhook material");
    assert_eq!(material_state, "live");
    assert!(safe_fingerprint.is_some());
    assert!(
        !first_envelope.windows(32).any(|window| window == [91; 32]),
        "PostgreSQL stores only the opaque envelope"
    );

    service
        .create_endpoint(project_id, application_id, create(91), Uuid::new_v4())
        .await
        .expect("replay protected endpoint with identical secret");
    let replay_envelope: Vec<u8> =
        sqlx::query_scalar("SELECT opaque_value FROM protected_materials WHERE id=$1")
            .bind(material_id)
            .fetch_one(&pool)
            .await
            .expect("read replayed protected envelope");
    assert_eq!(
        replay_envelope, first_envelope,
        "randomized retry envelopes never replace the committed authority"
    );
    assert_eq!(
        service
            .create_endpoint(project_id, application_id, create(92), Uuid::new_v4(),)
            .await,
        Err(ApplicationError::IdempotencyConflict),
        "the context-bound keyed fingerprint rejects a different secret on replay"
    );

    let protected_runtime = PostgresProtectedRuntimeCustody::new(
        database.clone(),
        "application-sync-protected-webhook",
        provider_id,
        custody.clone(),
        custody,
    )
    .expect("compose protected Runtime custody");
    let opened = WebhookSecretResolver::resolve(&protected_runtime, material_id)
        .await
        .expect("open exact protected webhook generation");
    assert_eq!(opened.as_slice(), [91; 32]);

    let endpoint = service
        .test_endpoint(
            project_id,
            application_id,
            endpoint.id,
            endpoint.revision,
            Uuid::new_v4(),
        )
        .await
        .expect("test protected endpoint");
    let endpoint = service
        .activate_endpoint(
            project_id,
            application_id,
            endpoint.id,
            endpoint.revision,
            Uuid::new_v4(),
        )
        .await
        .expect("activate protected endpoint");
    let projection = application_user_projection::Entity::find_by_id(projection_id)
        .one(&database)
        .await
        .expect("read projection")
        .expect("projection exists");
    let transaction = database
        .begin()
        .await
        .expect("begin protected webhook event");
    append_projection_event(
        &transaction,
        "prj_sync01",
        "app_sync01",
        binding_id,
        &projection,
        &projection.document,
        ApplicationUserEventType::Updated,
    )
    .await
    .expect("append protected webhook event");
    transaction
        .commit()
        .await
        .expect("commit protected webhook event");
    let claim = repository
        .claim_one(
            "protected-webhook-runtime",
            Uuid::new_v4(),
            OffsetDateTime::now_utc() + time::Duration::seconds(1),
            Duration::from_secs(30),
        )
        .await
        .expect("claim protected webhook delivery")
        .expect("protected delivery exists");
    assert_eq!(claim.primary_secret_material_id, material_id);
    let claimed_material: Option<Uuid> =
        sqlx::query_scalar("SELECT claimed_secret_material_id FROM webhook_deliveries WHERE id=$1")
            .bind(claim.delivery_id)
            .fetch_one(&pool)
            .await
            .expect("read exact delivery material snapshot");
    assert_eq!(claimed_material, Some(material_id));
    repository
        .finish(
            &claim,
            OffsetDateTime::now_utc().unix_timestamp(),
            WebhookTransportOutcome {
                outcome: WebhookDeliveryOutcome::Accepted,
                http_status: Some(204),
                duration_millis: 1,
            },
            None,
            OffsetDateTime::now_utc(),
            Uuid::new_v4(),
        )
        .await
        .expect("finish protected webhook delivery");

    service
        .disable_endpoint(
            project_id,
            application_id,
            endpoint.id,
            endpoint.revision,
            Uuid::new_v4(),
        )
        .await
        .expect("disable protected endpoint");
    let cleanup = repository
        .claim_secret_cleanup(
            "protected-webhook-cleanup",
            Uuid::new_v4(),
            OffsetDateTime::now_utc(),
            Duration::from_secs(30),
        )
        .await
        .expect("claim protected webhook cleanup")
        .expect("protected cleanup exists");
    assert_eq!(cleanup.material_id, material_id);
    repository
        .finish_secret_cleanup(&cleanup, OffsetDateTime::now_utc())
        .await
        .expect("atomically erase protected webhook material");
    let erased: (String, Option<Vec<u8>>, String) = sqlx::query_as(
        "SELECT material.state,material.opaque_value,cleanup.state
           FROM protected_materials material
           JOIN webhook_secret_cleanup_operations cleanup ON cleanup.material_id=material.id
          WHERE material.id=$1",
    )
    .bind(material_id)
    .fetch_one(&pool)
    .await
    .expect("read protected webhook erasure tombstone");
    assert_eq!(erased, ("erased".to_owned(), None, "erased".to_owned()));
    let retained_fingerprint: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT safe_fingerprint FROM protected_materials WHERE id=$1")
            .bind(material_id)
            .fetch_one(&pool)
            .await
            .expect("read protected webhook fingerprint tombstone");
    assert_eq!(retained_fingerprint.as_deref().map(<[u8]>::len), Some(32));
    assert!(
        WebhookSecretResolver::resolve(&protected_runtime, material_id)
            .await
            .is_err(),
        "an erased generation cannot be reopened"
    );
    service
        .create_endpoint(project_id, application_id, create(91), Uuid::new_v4())
        .await
        .expect("terminal replay accepts only the original protected secret");
    assert_eq!(
        service
            .create_endpoint(project_id, application_id, create(92), Uuid::new_v4())
            .await,
        Err(ApplicationError::IdempotencyConflict),
        "terminal replay compares the retained keyed fingerprint"
    );

    database.close().await.expect("close SeaORM database");
    pool.close().await;
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one real PostgreSQL journey proves pagination, retention, replay closure, and secret cleanup fencing"
)]
async fn webhook_history_retention_and_secret_cleanup_are_durable() {
    let Some((_container, pool, database)) = fixture().await else {
        return;
    };
    let project_id = Uuid::new_v4();
    let application_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let binding_id = Uuid::new_v4();
    let projection_id = Uuid::new_v4();
    seed_projection(
        &pool,
        &database,
        project_id,
        application_id,
        user_id,
        binding_id,
        projection_id,
    )
    .await;

    let provider_id = ProviderId::new("software").expect("software provider ID");
    let provider_format_version = ProviderFormatVersion::new(1).expect("provider format");
    let custody = SoftwareCustodyProvider::new(provider_id.clone(), [74; 32])
        .expect("software custody provider");
    let repository = Arc::new(
        PostgresWebhookRepository::new(database.clone(), projection_protector())
            .with_custody(
                "application-sync-durable-webhook",
                provider_id,
                provider_format_version,
            )
            .expect("compose durable webhook repository"),
    );
    let service = WebhookControlService::new_protected(
        repository.clone(),
        ConfigurationSecretSealers::single(custody),
        Arc::new(TestEndpointValidator),
        Arc::new(SystemClock),
    );
    let endpoint = service
        .create_endpoint(
            project_id,
            application_id,
            CreateWebhookEndpoint {
                url: "https://receiver.example.test/owlauth".to_owned(),
                subscribed_event_types: vec!["user.projection.updated".to_owned()],
                secret: Zeroizing::new(vec![31; 32]),
                idempotency_key: "durable-lifecycle-create".to_owned(),
            },
            Uuid::new_v4(),
        )
        .await
        .expect("prepare endpoint");
    let endpoint = service
        .test_endpoint(
            project_id,
            application_id,
            endpoint.id,
            endpoint.revision,
            Uuid::new_v4(),
        )
        .await
        .expect("test endpoint");
    let endpoint = service
        .activate_endpoint(
            project_id,
            application_id,
            endpoint.id,
            endpoint.revision,
            Uuid::new_v4(),
        )
        .await
        .expect("activate endpoint");

    let now = OffsetDateTime::now_utc();
    let mut retained_event_ids = Vec::new();
    for (revision, age_seconds) in [(1_i64, 3_i64), (2, 2), (3, 1)] {
        sqlx::query(
            "UPDATE application_user_projections
                SET projection_revision=$2,source_user_revision=$2,updated_at=$3
              WHERE id=$1",
        )
        .bind(projection_id)
        .bind(revision)
        .bind(now - time::Duration::seconds(age_seconds))
        .execute(&pool)
        .await
        .expect("advance projection revision");
        let projection = application_user_projection::Entity::find_by_id(projection_id)
            .one(&database)
            .await
            .expect("read projection revision")
            .expect("projection exists");
        let transaction = database.begin().await.expect("begin retained event");
        let event = append_projection_event(
            &transaction,
            "prj_sync01",
            "app_sync01",
            binding_id,
            &projection,
            &projection.document,
            ApplicationUserEventType::Updated,
        )
        .await
        .expect("append retained event");
        assert_eq!(
            event.replay_until - event.occurred_at,
            time::Duration::days(29),
            "PostgreSQL authors the supported replay window"
        );
        assert_eq!(
            event.retain_until - event.occurred_at,
            time::Duration::days(30),
            "payload retention leaves a full day after replay admission closes"
        );
        assert!(
            event.occurred_at > now - time::Duration::minutes(1),
            "projection timestamps must not backdate event authority"
        );
        transaction.commit().await.expect("commit retained event");
        retained_event_ids.push(event.event_id);
    }

    let first_events = service
        .list_events(project_id, application_id, None, Some(2))
        .await
        .expect("first event page");
    assert_eq!(first_events.items.len(), 2);
    assert!(first_events.next_cursor.is_some());
    assert_eq!(first_events.items[0].event_id, retained_event_ids[2]);
    assert_eq!(first_events.items[1].event_id, retained_event_ids[1]);
    let second_events = service
        .list_events(
            project_id,
            application_id,
            first_events.next_cursor.as_deref(),
            Some(2),
        )
        .await
        .expect("second event page");
    assert_eq!(second_events.items.len(), 1);
    assert_eq!(second_events.items[0].event_id, retained_event_ids[0]);
    assert!(second_events.next_cursor.is_none());

    let first_deliveries = service
        .list_deliveries(project_id, application_id, Some(endpoint.id), None, Some(2))
        .await
        .expect("first delivery page");
    assert_eq!(first_deliveries.items.len(), 2);
    let second_deliveries = service
        .list_deliveries(
            project_id,
            application_id,
            Some(endpoint.id),
            first_deliveries.next_cursor.as_deref(),
            Some(2),
        )
        .await
        .expect("second delivery page");
    assert_eq!(second_deliveries.items.len(), 1);
    let dispatch_state_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM webhook_application_dispatch_state
          WHERE project_id=$1 AND application_id=$2",
    )
    .bind(project_id)
    .bind(application_id)
    .fetch_one(&pool)
    .await
    .expect("read incremental dispatch state");
    assert_eq!(dispatch_state_count, 1);
    let (history_event_id, history_delivery_id): (Uuid, Uuid) = sqlx::query_as(
        "SELECT event_id,id FROM webhook_deliveries
          WHERE project_id=$1 AND application_id=$2 AND endpoint_id=$3
          ORDER BY created_at,id LIMIT 1",
    )
    .bind(project_id)
    .bind(application_id)
    .bind(endpoint.id)
    .fetch_one(&pool)
    .await
    .expect("read terminal-history parent");
    sqlx::query(
        "INSERT INTO webhook_deliveries
            (id,project_id,application_id,endpoint_id,event_id,replay_sequence,
             replay_of_delivery_id,state,attempt_count,next_attempt_at,lease_generation,
             created_at,updated_at,terminal_at)
         SELECT md5('bounded-terminal-history-' || value::text)::uuid,$1,$2,$3,$4,
                value,$5,'terminal',1,$6,1,$6,$6,$6
           FROM generate_series(1,500) AS value",
    )
    .bind(project_id)
    .bind(application_id)
    .bind(endpoint.id)
    .bind(history_event_id)
    .bind(history_delivery_id)
    .bind(now - time::Duration::hours(1))
    .execute(&pool)
    .await
    .expect("insert substantial retained terminal history");
    let claim_now = OffsetDateTime::now_utc() + time::Duration::seconds(1);
    let bounded_claim = repository
        .claim_one(
            "bounded-history-worker",
            Uuid::new_v4(),
            claim_now,
            Duration::from_secs(30),
        )
        .await
        .expect("claim with substantial terminal history")
        .expect("pending delivery remains claimable");
    assert_eq!(bounded_claim.attempt_number, 1);
    let terminal_history_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM webhook_deliveries
          WHERE project_id=$1 AND application_id=$2 AND state='terminal'",
    )
    .bind(project_id)
    .bind(application_id)
    .fetch_one(&pool)
    .await
    .expect("read retained terminal history count");
    assert_eq!(terminal_history_count, 500);
    repository
        .finish(
            &bounded_claim,
            now.unix_timestamp(),
            WebhookTransportOutcome {
                outcome: WebhookDeliveryOutcome::Accepted,
                http_status: Some(204),
                duration_millis: 1,
            },
            None,
            now,
            Uuid::new_v4(),
        )
        .await
        .expect("finish bounded-history claim");

    let cutoff_event_id = Uuid::new_v4();
    let cutoff_event_public_id = format!("evt_{}", cutoff_event_id.simple());
    sqlx::query(
        "INSERT INTO application_user_events
             (id,event_id,project_id,application_id,binding_id,user_id,event_type,
              user_revision,projection_revision,projection_schema,safe_body,
              canonical_body_digest,occurred_at,replay_until,retain_until,created_at)
         VALUES ($1,$2,$3,$4,$5,$6,'user.projection.updated',40,40,
                 'owlauth.user.v1',$7,$8,$9,$10,$11,$9)",
    )
    .bind(cutoff_event_id)
    .bind(&cutoff_event_public_id)
    .bind(project_id)
    .bind(application_id)
    .bind(binding_id)
    .bind(user_id)
    .bind(serde_json::json!({
        "data": { "projection": { "verified_email": null } }
    }))
    .bind(vec![40_u8; 32])
    .bind(now - time::Duration::days(29) - time::Duration::seconds(1))
    .bind(now - time::Duration::seconds(1))
    .bind(now + time::Duration::days(1))
    .execute(&pool)
    .await
    .expect("insert replay-cutoff event fixture");
    let cutoff_delivery_id = insert_scoped_delivery(
        &pool,
        project_id,
        application_id,
        endpoint.id,
        cutoff_event_id,
        None,
    )
    .await
    .expect("insert replay-cutoff delivery fixture");
    assert_eq!(
        service
            .replay_delivery(
                project_id,
                application_id,
                cutoff_delivery_id,
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::InvalidTransition),
        "replay closes before immutable payload retention"
    );
    assert!(
        service
            .list_events(project_id, application_id, None, Some(100))
            .await
            .expect("inspect post-replay retained event")
            .items
            .iter()
            .any(|event| event.event_id == cutoff_event_public_id),
        "history remains inspectable after replay admission closes"
    );

    sqlx::query(
        "UPDATE application_user_projections
            SET projection_revision=4,source_user_revision=4,updated_at=$2
          WHERE id=$1",
    )
    .bind(projection_id)
    .bind(now - time::Duration::days(31))
    .execute(&pool)
    .await
    .expect("advance expired projection revision");
    let expired_event_id = Uuid::new_v4();
    let expired_event_public_id = format!("evt_{}", expired_event_id.simple());
    let expired_delivery_id = Uuid::new_v4();
    let expired_at = now - time::Duration::days(31);
    sqlx::query(
        "INSERT INTO application_user_events
             (id,event_id,project_id,application_id,binding_id,user_id,event_type,
              user_revision,projection_revision,projection_schema,safe_body,
              canonical_body_digest,verified_email_source_identity_id,
              verified_email_ciphertext,verified_email_key_version,occurred_at,
              replay_until,retain_until,created_at)
         VALUES ($1,$2,$3,$4,$5,$6,'user.projection.updated',4,4,
                 'owlauth.user.v1',$7,$8,NULL,NULL,NULL,$9,$10,$11,$9)",
    )
    .bind(expired_event_id)
    .bind(&expired_event_public_id)
    .bind(project_id)
    .bind(application_id)
    .bind(binding_id)
    .bind(user_id)
    .bind(serde_json::json!({
        "data": { "projection": { "verified_email": null } }
    }))
    .bind(vec![41_u8; 32])
    .bind(expired_at)
    .bind(now - time::Duration::days(1))
    .bind(now - time::Duration::seconds(1))
    .execute(&pool)
    .await
    .expect("insert expired immutable event fixture");
    sqlx::query(
        "INSERT INTO webhook_deliveries
             (id,project_id,application_id,endpoint_id,event_id,replay_sequence,state,
              attempt_count,next_attempt_at,lease_generation,created_at,updated_at)
         VALUES ($1,$2,$3,$4,$5,0,'pending',0,$6,0,$6,$6)",
    )
    .bind(expired_delivery_id)
    .bind(project_id)
    .bind(application_id)
    .bind(endpoint.id)
    .bind(expired_event_id)
    .bind(expired_at)
    .execute(&pool)
    .await
    .expect("insert expired delivery fixture");
    assert_eq!(
        service
            .replay_delivery(
                project_id,
                application_id,
                expired_delivery_id,
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::InvalidTransition),
        "replay closes at the authoritative retention boundary"
    );
    assert!(
        service
            .list_events(project_id, application_id, None, Some(100))
            .await
            .expect("retained history")
            .items
            .iter()
            .all(|event| event.event_id != expired_event_public_id)
    );
    assert!(
        repository
            .maintain(now, 100)
            .await
            .expect("retention maintenance")
            > 0
    );
    let expired_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM application_user_events WHERE id=$1)")
            .bind(expired_event_id)
            .fetch_one(&pool)
            .await
            .expect("check expired event cleanup");
    assert!(!expired_exists);

    let key_event_id = Uuid::new_v4();
    let key_event_public_id = format!("evt_{}", key_event_id.simple());
    sqlx::query(
        "INSERT INTO application_user_events
             (id,event_id,project_id,application_id,binding_id,user_id,event_type,
              user_revision,projection_revision,projection_schema,safe_body,
              canonical_body_digest,verified_email_source_identity_id,
              verified_email_ciphertext,verified_email_key_version,occurred_at,
              replay_until,retain_until,created_at)
         VALUES ($1,$2,$3,$4,$5,$6,'user.projection.updated',5,5,
                 'owlauth.user.v1',$7,$8,$9,$10,1,$11,$12,$13,$11)",
    )
    .bind(key_event_id)
    .bind(key_event_public_id)
    .bind(project_id)
    .bind(application_id)
    .bind(binding_id)
    .bind(user_id)
    .bind(serde_json::json!({
        "data": { "projection": { "verified_email": null } }
    }))
    .bind(vec![42_u8; 32])
    .bind(Uuid::new_v4())
    .bind(vec![43_u8; 64])
    .bind(now - time::Duration::days(31))
    .bind(now - time::Duration::days(1))
    .bind(now - time::Duration::seconds(1))
    .execute(&pool)
    .await
    .expect("insert expired event retaining projection-email key material");

    assert!(
        repository
            .maintain(now, 100)
            .await
            .expect("clean expired key-bearing event")
            > 0
    );
    let expired_event_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM application_user_events WHERE id=$1")
            .bind(key_event_id)
            .fetch_one(&pool)
            .await
            .expect("confirm expired event cleanup");
    assert_eq!(expired_event_count, 0);

    let prepared_overlap = service
        .prepare_secret_rotation(
            project_id,
            application_id,
            endpoint.id,
            PrepareWebhookSecretRotation {
                secret: Zeroizing::new(vec![32; 32]),
                idempotency_key: "durable-lifecycle-overlap".to_owned(),
                expected_revision: endpoint.revision,
            },
            Uuid::new_v4(),
        )
        .await
        .expect("prepare overlap cleanup fixture");
    let endpoint = service
        .activate_secret_rotation(
            project_id,
            application_id,
            endpoint.id,
            prepared_overlap.generation,
            endpoint.revision,
            600,
            Uuid::new_v4(),
        )
        .await
        .expect("activate PostgreSQL-authored overlap fixture");
    let disabled = service
        .disable_endpoint(
            project_id,
            application_id,
            endpoint.id,
            endpoint.revision,
            Uuid::new_v4(),
        )
        .await
        .expect("disable endpoint");
    assert_eq!(disabled.status, "disabled");
    assert!(disabled.current_secret_generation.is_none());
    let delayed_overlap_cleanup: (String, bool) = sqlx::query_as(
        "SELECT state,not_before > transaction_timestamp()
           FROM webhook_secret_cleanup_operations
          WHERE endpoint_id=$1 AND generation=1",
    )
    .bind(endpoint.id)
    .fetch_one(&pool)
    .await
    .expect("read overlap cleanup deadline");
    assert_eq!(delayed_overlap_cleanup, ("pending".to_owned(), true));

    let terminal_endpoint_replay = service
        .create_endpoint(
            project_id,
            application_id,
            CreateWebhookEndpoint {
                url: "https://receiver.example.test/owlauth".to_owned(),
                subscribed_event_types: vec!["user.projection.updated".to_owned()],
                secret: Zeroizing::new(vec![31; 32]),
                idempotency_key: "durable-lifecycle-create".to_owned(),
            },
            Uuid::new_v4(),
        )
        .await
        .expect("terminal endpoint replay should remain stable");
    assert_eq!(terminal_endpoint_replay.status, "disabled");
    let cleanup = repository
        .claim_secret_cleanup(
            "runtime-cleanup",
            Uuid::new_v4(),
            now,
            Duration::from_secs(30),
        )
        .await
        .expect("claim secret cleanup")
        .expect("retired secret is cleanup eligible");
    let mut stale_cleanup = cleanup.clone();
    stale_cleanup.lease_generation += 1;
    assert_eq!(
        repository.finish_secret_cleanup(&stale_cleanup, now).await,
        Err(ApplicationError::RevisionConflict)
    );
    repository
        .finish_secret_cleanup(&cleanup, now)
        .await
        .expect("finish exact secret cleanup lease");
    let cleanup_state: (String, String) = sqlx::query_as(
        "SELECT cleanup.state,material.state
           FROM webhook_secret_cleanup_operations cleanup
           JOIN protected_materials material ON material.id=cleanup.material_id
          WHERE cleanup.id=$1",
    )
    .bind(cleanup.id)
    .fetch_one(&pool)
    .await
    .expect("read permanent cleanup tombstones");
    assert_eq!(cleanup_state, ("erased".to_owned(), "erased".to_owned()));

    database.close().await.expect("close SeaORM database");
    pool.close().await;
}
