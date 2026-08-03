use std::{
    collections::BTreeMap,
    env,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use sea_orm::{Database, EntityTrait, TransactionTrait};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, postgres::PgPoolOptions};
use testcontainers::{
    GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor, wait::LogWaitStrategy},
    runners::AsyncRunner,
};
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    control_lifecycle::PostgresControlLifecycleRepository,
    entity::{application_user_projection, project_user},
    projection::{
        PostgresIdentityProjectionMaterializer, PostgresProjectionEmailKeyAuthority,
        projection_material,
    },
    projection_expansion::PostgresProjectionExpansionRepository,
    provisioning::PostgresProvisioningAdapter,
    webhook::{PostgresWebhookRepository, append_projection_event},
};
use crate::{
    adapters::{
        runtime_security::{
            RuntimeKeyMaterial, SoftwareProjectionVerifiedEmailProtector,
            UnavailableDurableEmailAddressReader,
        },
        system::SystemClock,
    },
    application::{
        ApplicationError, ConfigurationSecretProvisioner, ConfirmedProjectionPolicyUpdate,
        ControlLifecyclePort, CreateWebhookEndpoint, DisableProjectUser, McpConfirmationContext,
        McpConfirmationService, PrepareWebhookSecretRotation, ProjectUserStatus,
        ProjectionExpansionWorker, ProjectionPolicyPort, ProjectionPolicyService,
        UpdateProjectionPolicy, WebhookControlService, WebhookDeliveryRepository,
        WebhookEndpointValidator, WebhookSecretPreparationState, WebhookTransportOutcome,
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

#[derive(Default)]
struct TestSecretProvisioner {
    failures_remaining: AtomicUsize,
    calls: AtomicUsize,
}

#[async_trait]
impl ConfigurationSecretProvisioner for TestSecretProvisioner {
    fn request_fingerprint(&self, value: &[u8]) -> [u8; 32] {
        Sha256::digest(value).into()
    }

    async fn provision_if_absent(
        &self,
        _alias: String,
        _value: Zeroizing<Vec<u8>>,
    ) -> Result<(), ApplicationError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self
            .failures_remaining
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            Err(ApplicationError::ExternalStore)
        } else {
            Ok(())
        }
    }
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
            RuntimeKeyMaterial::new([7; 32], [9; 32]),
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
        "INSERT INTO provider_configurations
            (id,project_id,provider_key,kind,display_name,issuer,client_id,callback_url,
             secret_ref,status,revision)
         VALUES ($1,$2,'oidc-sync','oidc','OIDC Sync','https://issuer.example.test',
             'sync-client','https://runtime.example.test/callback','provider_sync_secret',
             'active',1)",
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
             status,identity_revision,display_name,observed_at,created_at,updated_at)
         VALUES ($1,$2,$3,$4,'https://issuer.example.test','sync-subject','active',1,
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
    let (document, digest) = projection_material(&user, 1, 1, 1).expect("initial projection");
    sqlx::query(
        "INSERT INTO application_user_projections
            (id,project_id,binding_id,application_id,user_id,schema_name,projection_revision,
             source_user_revision,project_policy_revision,application_policy_revision,
             canonical_digest,document,created_at,updated_at)
         VALUES ($1,$2,$3,$4,$5,'owlauth.user.v1',1,1,1,1,$6,$7,
             $8::timestamptz,$8::timestamptz)",
    )
    .bind(projection_id)
    .bind(project_id)
    .bind(binding_id)
    .bind(application_id)
    .bind(user_id)
    .bind(digest)
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
        "INSERT INTO provider_configurations
            (id,project_id,provider_key,kind,display_name,issuer,client_id,callback_url,
             secret_ref,status,revision)
         VALUES ($1,$2,'scope-test','oidc','Scope Test','https://issuer.scope.test',
                 'scope-client','https://runtime.scope.test/callback','provider_scope_secret',
                 'active',1)",
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
             status,identity_revision,observed_at)
         VALUES ($1,$2,$3,$4,'https://issuer.scope.test','scope-subject','active',1,
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
    reason = "one real PostgreSQL test keeps the complete one-use confirmation threat matrix visible"
)]
async fn mcp_projection_policy_confirmation_is_bound_one_use_and_atomic() {
    let Some((_container, pool, database)) = fixture().await else {
        return;
    };
    let project_id = Uuid::new_v4();
    let application_id = Uuid::new_v4();
    seed_projection(
        &pool,
        &database,
        project_id,
        application_id,
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    )
    .await;
    let materializer = Arc::new(PostgresIdentityProjectionMaterializer::new(
        Arc::new(UnavailableDurableEmailAddressReader),
        projection_protector(),
    ));
    let repository = Arc::new(PostgresProjectionExpansionRepository::new(
        database.clone(),
        materializer.clone(),
    ));
    let context = McpConfirmationContext {
        instance_id: "instance-confirmation-test".to_owned(),
        control_endpoint: "https://control.example.test/mcp".to_owned(),
    };
    let service = McpConfirmationService::new(repository.clone(), context.clone())
        .expect("valid confirmation service");
    let command = ConfirmedProjectionPolicyUpdate {
        project_id,
        application_id: None,
        verified_email_enabled: true,
        expected_revision: 1,
    };

    let mismatched = service
        .preview_projection_policy_update(command.clone())
        .await
        .expect("preview exact policy expansion");
    assert!(mismatched.capability.starts_with("owl_mcp_confirm_v1_"));
    let stored_digest: Vec<u8> = sqlx::query_scalar(
        "SELECT capability_digest FROM mcp_confirmation_capabilities WHERE project_id=$1",
    )
    .bind(project_id)
    .fetch_one(&pool)
    .await
    .expect("read digest-only capability authority");
    assert_eq!(
        stored_digest,
        Sha256::digest(mismatched.capability.as_bytes()).to_vec()
    );

    sqlx::query(
        "INSERT INTO mcp_confirmation_capabilities
            (id,capability_digest,actor_kind,audience,instance_id,control_endpoint,tool_name,
             command_digest,project_id,project_metadata_revision,application_id,target_revision,
             created_at,expires_at,consumed_at)
         SELECT md5('synthetic-mcp-capacity-' || value::text)::uuid,
                decode(lpad(to_hex(value),64,'0'),'hex'),
                'deployment_operator','control_mcp','synthetic-capacity',
                'https://control.example.test/mcp','synthetic_commit',decode(repeat('00',32),'hex'),
                $1,1,NULL,1,authority_clock.now,
                authority_clock.now+interval '5 minutes',NULL
           FROM generate_series(1,4095) AS value
           CROSS JOIN (SELECT clock_timestamp() AS now) AS authority_clock",
    )
    .bind(project_id)
    .execute(&pool)
    .await
    .expect("fill the hard confirmation capacity");
    assert_eq!(
        service
            .preview_projection_policy_update(command.clone())
            .await,
        Err(ApplicationError::OperationInProgress)
    );
    sqlx::query("DELETE FROM mcp_confirmation_capabilities WHERE instance_id='synthetic-capacity'")
        .execute(&pool)
        .await
        .expect("remove synthetic capacity rows");

    let changed_command = ConfirmedProjectionPolicyUpdate {
        verified_email_enabled: false,
        ..command.clone()
    };
    assert_eq!(
        service
            .preview_projection_policy_update(changed_command.clone())
            .await,
        Err(ApplicationError::InvalidTransition),
        "MCP expansion preview rejects a no-change request"
    );
    assert_eq!(
        service
            .commit_projection_policy_update(
                changed_command,
                &mismatched.capability,
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::InvalidTransition)
    );
    let changed_project = ConfirmedProjectionPolicyUpdate {
        project_id: Uuid::new_v4(),
        ..command.clone()
    };
    assert_eq!(
        service
            .commit_projection_policy_update(
                changed_project,
                &mismatched.capability,
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::InvalidTransition)
    );
    let other_endpoint = McpConfirmationService::new(
        repository.clone(),
        McpConfirmationContext {
            control_endpoint: "https://other-control.example.test/mcp".to_owned(),
            ..context.clone()
        },
    )
    .expect("second endpoint context");
    assert_eq!(
        other_endpoint
            .commit_projection_policy_update(
                command.clone(),
                &mismatched.capability,
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::InvalidTransition)
    );
    let other_deployment = McpConfirmationService::new(
        repository.clone(),
        McpConfirmationContext {
            instance_id: "other-deployment".to_owned(),
            ..context.clone()
        },
    )
    .expect("second deployment context");
    assert_eq!(
        other_deployment
            .commit_projection_policy_update(
                command.clone(),
                &mismatched.capability,
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::InvalidTransition)
    );

    let tampered = service
        .preview_projection_policy_update(command.clone())
        .await
        .expect("preview capability for stored-binding tamper checks");
    let tampered_digest = Sha256::digest(tampered.capability.as_bytes()).to_vec();
    let audience_error = sqlx::query(
        "UPDATE mcp_confirmation_capabilities SET audience='runtime' WHERE capability_digest=$1",
    )
    .bind(tampered_digest.clone())
    .execute(&pool)
    .await
    .expect_err("database rejects a cross-audience capability");
    assert_eq!(
        audience_error
            .as_database_error()
            .expect("PostgreSQL constraint error")
            .code()
            .as_deref(),
        Some("23514")
    );
    sqlx::query(
        "UPDATE mcp_confirmation_capabilities SET tool_name='other_commit' WHERE capability_digest=$1",
    )
    .bind(tampered_digest)
    .execute(&pool)
    .await
    .expect("tamper exact tool binding for commit rejection");
    assert_eq!(
        service
            .commit_projection_policy_update(command.clone(), &tampered.capability, Uuid::new_v4())
            .await,
        Err(ApplicationError::InvalidTransition)
    );

    sqlx::query("UPDATE projects SET metadata_revision=2 WHERE id=$1")
        .bind(project_id)
        .execute(&pool)
        .await
        .expect("advance Project metadata authority");
    assert_eq!(
        service
            .commit_projection_policy_update(
                command.clone(),
                &mismatched.capability,
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::RevisionConflict)
    );
    let consumed_after_stale: Option<OffsetDateTime> = sqlx::query_scalar(
        "SELECT consumed_at FROM mcp_confirmation_capabilities WHERE capability_digest=$1",
    )
    .bind(Sha256::digest(mismatched.capability.as_bytes()).to_vec())
    .fetch_one(&pool)
    .await
    .expect("stale capability remains unconsumed");
    assert!(consumed_after_stale.is_none());
    sqlx::query("UPDATE projects SET metadata_revision=1 WHERE id=$1")
        .bind(project_id)
        .execute(&pool)
        .await
        .expect("restore isolated test fixture revision");

    let ordinary_policy = ProjectionPolicyService::new(repository.clone(), Arc::new(SystemClock));
    let ordinary_update = ordinary_policy
        .update_project(
            project_id,
            UpdateProjectionPolicy {
                verified_email_enabled: true,
                expected_revision: 1,
            },
            Uuid::new_v4(),
        )
        .await
        .expect("advance target revision through the ordinary Control service");
    assert_eq!(
        service
            .commit_projection_policy_update(
                command.clone(),
                &mismatched.capability,
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::RevisionConflict)
    );
    sqlx::query(
        "UPDATE project_policies
            SET projection_verified_email_enabled=false,projection_revision=1
          WHERE project_id=$1",
    )
    .bind(project_id)
    .execute(&pool)
    .await
    .expect("restore isolated policy fixture");
    sqlx::query("DELETE FROM projection_expansion_operations WHERE id=$1")
        .bind(
            ordinary_update
                .expansion_operation_id
                .expect("ordinary update operation"),
        )
        .execute(&pool)
        .await
        .expect("remove isolated ordinary expansion operation");

    let expired = service
        .preview_projection_policy_update(command.clone())
        .await
        .expect("preview capability to expire under PostgreSQL authority");
    sqlx::query(
        "UPDATE mcp_confirmation_capabilities
            SET created_at=clock_timestamp()-interval '10 minutes',
                expires_at=clock_timestamp()-interval '6 minutes'
          WHERE capability_digest=$1",
    )
    .bind(Sha256::digest(expired.capability.as_bytes()).to_vec())
    .execute(&pool)
    .await
    .expect("expire capability within its original bounded lifetime");
    assert_eq!(
        service
            .commit_projection_policy_update(command.clone(), &expired.capability, Uuid::new_v4())
            .await,
        Err(ApplicationError::InvalidTransition)
    );

    let accepted = service
        .preview_projection_policy_update(command.clone())
        .await
        .expect("preview accepted exact command");
    let expired_retained: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mcp_confirmation_capabilities WHERE capability_digest=$1",
    )
    .bind(Sha256::digest(expired.capability.as_bytes()).to_vec())
    .fetch_one(&pool)
    .await
    .expect("inspect bounded expiry cleanup");
    assert_eq!(expired_retained, 0);

    let restarted_repository = Arc::new(PostgresProjectionExpansionRepository::new(
        database,
        materializer,
    ));
    let restarted_service = McpConfirmationService::new(restarted_repository, context)
        .expect("recreated confirmation service");
    sqlx::query(
        "CREATE FUNCTION reject_mcp_commit_audit_for_test()
         RETURNS TRIGGER LANGUAGE plpgsql AS $$
         BEGIN
             IF NEW.action='mcp.projection_policy.update.commit' THEN
                 RAISE EXCEPTION 'injected MCP audit failure' USING ERRCODE='23514';
             END IF;
             RETURN NEW;
         END
         $$",
    )
    .execute(&pool)
    .await
    .expect("install late-transaction audit failure function");
    sqlx::query(
        "CREATE TRIGGER reject_mcp_commit_audit_for_test
         BEFORE INSERT ON audit_events
         FOR EACH ROW EXECUTE FUNCTION reject_mcp_commit_audit_for_test()",
    )
    .execute(&pool)
    .await
    .expect("install late-transaction audit failure trigger");
    assert_eq!(
        restarted_service
            .commit_projection_policy_update(command.clone(), &accepted.capability, Uuid::new_v4(),)
            .await,
        Err(ApplicationError::Persistence)
    );
    let rolled_back: (bool, i64, i64, i64) = sqlx::query_as(
        "SELECT
            (SELECT projection_verified_email_enabled FROM project_policies WHERE project_id=$1),
            (SELECT projection_revision FROM project_policies WHERE project_id=$1),
            (SELECT count(*) FROM projection_expansion_operations
              WHERE project_id=$1 AND scope_kind='project' AND target_policy_revision=2),
            (SELECT count(*) FROM mcp_confirmation_capabilities
              WHERE capability_digest=$2 AND consumed_at IS NOT NULL)",
    )
    .bind(project_id)
    .bind(Sha256::digest(accepted.capability.as_bytes()).to_vec())
    .fetch_one(&pool)
    .await
    .expect("inspect rollback after audit failure");
    assert_eq!(rolled_back, (false, 1, 0, 0));
    sqlx::query("DROP TRIGGER reject_mcp_commit_audit_for_test ON audit_events")
        .execute(&pool)
        .await
        .expect("remove late-transaction audit failure trigger");
    sqlx::query("DROP FUNCTION reject_mcp_commit_audit_for_test()")
        .execute(&pool)
        .await
        .expect("remove late-transaction audit failure function");

    let first_service = service.clone();
    let second_service = restarted_service;
    let first_command = command.clone();
    let second_command = command.clone();
    let first_capability = accepted.capability.clone();
    let second_capability = accepted.capability.clone();
    let (first, second) = tokio::join!(
        first_service.commit_projection_policy_update(
            first_command,
            &first_capability,
            Uuid::new_v4(),
        ),
        second_service.commit_projection_policy_update(
            second_command,
            &second_capability,
            Uuid::new_v4(),
        )
    );
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    let committed = first.or(second).expect("one exact commit wins");
    assert!(committed.verified_email_enabled);
    assert_eq!(committed.revision, 2);
    assert!(committed.expansion_operation_id.is_some());
    assert_eq!(
        service
            .commit_projection_policy_update(command, &accepted.capability, Uuid::new_v4())
            .await,
        Err(ApplicationError::InvalidTransition)
    );

    let application_command = ConfirmedProjectionPolicyUpdate {
        project_id,
        application_id: Some(application_id),
        verified_email_enabled: true,
        expected_revision: 1,
    };
    let application_preview = service
        .preview_projection_policy_update(application_command.clone())
        .await
        .expect("preview Application-scoped policy expansion");
    let application_policy = service
        .commit_projection_policy_update(
            application_command,
            &application_preview.capability,
            Uuid::new_v4(),
        )
        .await
        .expect("commit Application-scoped policy expansion");
    assert_eq!(application_policy.application_id, Some(application_id));
    assert_eq!(application_policy.revision, 2);
    assert!(application_policy.expansion_operation_id.is_some());

    let (mcp_audits, operations, consumed): (i64, i64, i64) = sqlx::query_as(
        "SELECT
            (SELECT count(*) FROM audit_events
              WHERE project_id=$1 AND action='mcp.projection_policy.update.commit'),
            (SELECT count(*) FROM projection_expansion_operations
              WHERE project_id=$1 AND target_policy_revision=2),
            (SELECT count(*) FROM mcp_confirmation_capabilities
              WHERE project_id=$1 AND consumed_at IS NOT NULL)",
    )
    .bind(project_id)
    .fetch_one(&pool)
    .await
    .expect("read atomic confirmation evidence");
    assert_eq!((mcp_audits, operations, consumed), (2, 2, 2));
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one real PostgreSQL journey proves the coupled policy, event, endpoint, delivery, and replay invariants"
)]
async fn application_sync_lifecycle_is_atomic_fenced_and_resumable() {
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

    let protector = projection_protector();
    let webhook_repository = Arc::new(PostgresWebhookRepository::new(
        database.clone(),
        protector.clone(),
    ));
    let secret_provisioner = Arc::new(TestSecretProvisioner {
        failures_remaining: AtomicUsize::new(1),
        calls: AtomicUsize::new(0),
    });
    let webhook_service = WebhookControlService::new(
        webhook_repository.clone(),
        secret_provisioner.clone(),
        Arc::new(TestEndpointValidator),
        Arc::new(SystemClock),
    );
    let create_endpoint = |idempotency_key: &str| CreateWebhookEndpoint {
        url: "https://receiver.example.test/owlauth".to_owned(),
        subscribed_event_types: vec![
            "user.projection.created".to_owned(),
            "user.projection.updated".to_owned(),
            "user.projection.disabled".to_owned(),
        ],
        secret: Zeroizing::new(vec![11; 32]),
        idempotency_key: idempotency_key.to_owned(),
    };
    assert_eq!(
        webhook_service
            .create_endpoint(
                project_id,
                application_id,
                create_endpoint("endpoint-create-01"),
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::ExternalStore)
    );
    let endpoint = webhook_service
        .list_endpoints(project_id, application_id)
        .await
        .expect("list prepared endpoint")
        .into_iter()
        .next()
        .expect("prepared endpoint exists");
    assert_eq!(endpoint.status, "pending");
    assert_eq!(endpoint.revision, 1);
    assert!(endpoint.current_secret_generation.is_none());

    let endpoint = webhook_service
        .test_endpoint(
            project_id,
            application_id,
            endpoint.id,
            endpoint.revision,
            Uuid::new_v4(),
        )
        .await
        .expect("test endpoint destination");
    assert_eq!(endpoint.revision, 2);
    assert!(endpoint.last_test_succeeded_at.is_some());
    assert_eq!(
        webhook_service
            .activate_endpoint(
                project_id,
                application_id,
                endpoint.id,
                endpoint.revision,
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::InvalidTransition),
        "an uncommitted external secret result must fence activation"
    );
    let endpoint = webhook_service
        .create_endpoint(
            project_id,
            application_id,
            create_endpoint("endpoint-create-recovery-02"),
            Uuid::new_v4(),
        )
        .await
        .expect("reconcile provisioned endpoint secret");
    assert_eq!(endpoint.revision, 2);
    let endpoint = webhook_service
        .activate_endpoint(
            project_id,
            application_id,
            endpoint.id,
            endpoint.revision,
            Uuid::new_v4(),
        )
        .await
        .expect("activate tested and provisioned endpoint");
    assert_eq!(endpoint.status, "active");
    assert_eq!(endpoint.revision, 3);
    assert_eq!(endpoint.current_secret_generation, Some(1));

    let prepared = webhook_service
        .prepare_secret_rotation(
            project_id,
            application_id,
            endpoint.id,
            PrepareWebhookSecretRotation {
                secret: Zeroizing::new(vec![12; 32]),
                idempotency_key: "endpoint-rotate-02".to_owned(),
                expected_revision: endpoint.revision,
            },
            Uuid::new_v4(),
        )
        .await
        .expect("prepare secret rotation");
    assert_eq!(prepared.generation, 2);
    let recovered = webhook_service
        .prepare_secret_rotation(
            project_id,
            application_id,
            endpoint.id,
            PrepareWebhookSecretRotation {
                secret: Zeroizing::new(vec![12; 32]),
                idempotency_key: "endpoint-rotate-recovery-03".to_owned(),
                expected_revision: endpoint.revision,
            },
            Uuid::new_v4(),
        )
        .await
        .expect("recover prepared rotation under a new browser idempotency key");
    assert_eq!(recovered.generation, 2);
    assert_eq!(
        recovered.preparation_state,
        WebhookSecretPreparationState::Provisioned
    );
    let prepared = webhook_service
        .prepare_secret_rotation(
            project_id,
            application_id,
            endpoint.id,
            PrepareWebhookSecretRotation {
                secret: Zeroizing::new(vec![13; 32]),
                idempotency_key: "endpoint-rotate-supersede-04".to_owned(),
                expected_revision: endpoint.revision,
            },
            Uuid::new_v4(),
        )
        .await
        .expect("supersede an abandoned prepared rotation");
    assert_eq!(prepared.generation, 3);
    let endpoint = webhook_service
        .activate_secret_rotation(
            project_id,
            application_id,
            endpoint.id,
            prepared.generation,
            endpoint.revision,
            600,
            Uuid::new_v4(),
        )
        .await
        .expect("activate secret rotation");
    assert_eq!(endpoint.current_secret_generation, Some(3));
    assert_eq!(endpoint.overlap_secret_generation, Some(1));
    let replayed_activation = webhook_service
        .activate_secret_rotation(
            project_id,
            application_id,
            endpoint.id,
            prepared.generation,
            endpoint.revision - 1,
            600,
            Uuid::new_v4(),
        )
        .await
        .expect("replay rotation activation after response loss");
    assert_eq!(replayed_activation.revision, endpoint.revision);

    let blocked_rotation = webhook_service
        .prepare_secret_rotation(
            project_id,
            application_id,
            endpoint.id,
            PrepareWebhookSecretRotation {
                secret: Zeroizing::new(vec![14; 32]),
                idempotency_key: "endpoint-rotate-before-overlap-expiry-05".to_owned(),
                expected_revision: endpoint.revision,
            },
            Uuid::new_v4(),
        )
        .await
        .expect("prepare another rotation while overlap remains live");
    assert_eq!(
        webhook_service
            .activate_secret_rotation(
                project_id,
                application_id,
                endpoint.id,
                blocked_rotation.generation,
                endpoint.revision,
                600,
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::InvalidTransition),
        "a second activation cannot shorten a PostgreSQL-authored overlap"
    );

    secret_provisioner
        .failures_remaining
        .store(1, Ordering::SeqCst);
    assert_eq!(
        webhook_service
            .prepare_secret_rotation(
                project_id,
                application_id,
                endpoint.id,
                PrepareWebhookSecretRotation {
                    secret: Zeroizing::new(vec![15; 32]),
                    idempotency_key: "endpoint-rotate-terminal-replay-06".to_owned(),
                    expected_revision: endpoint.revision,
                },
                Uuid::new_v4(),
            )
            .await
            .expect_err("interrupted rotation provisioning should fail"),
        ApplicationError::ExternalStore
    );
    webhook_service
        .prepare_secret_rotation(
            project_id,
            application_id,
            endpoint.id,
            PrepareWebhookSecretRotation {
                secret: Zeroizing::new(vec![16; 32]),
                idempotency_key: "endpoint-rotate-successor-07".to_owned(),
                expected_revision: endpoint.revision,
            },
            Uuid::new_v4(),
        )
        .await
        .expect("supersede interrupted rotation");
    let calls_before_terminal_replay = secret_provisioner.calls.load(Ordering::SeqCst);
    let terminal_replay = webhook_service
        .prepare_secret_rotation(
            project_id,
            application_id,
            endpoint.id,
            PrepareWebhookSecretRotation {
                secret: Zeroizing::new(vec![15; 32]),
                idempotency_key: "endpoint-rotate-terminal-replay-06".to_owned(),
                expected_revision: endpoint.revision,
            },
            Uuid::new_v4(),
        )
        .await
        .expect("terminal rotation replay should remain stable");
    assert_eq!(
        terminal_replay.preparation_state,
        WebhookSecretPreparationState::Terminal
    );
    assert!(!terminal_replay.already_active);
    assert_eq!(
        secret_provisioner.calls.load(Ordering::SeqCst),
        calls_before_terminal_replay,
        "terminal replay must not repeat external provisioning"
    );

    let projection = application_user_projection::Entity::find_by_id(projection_id)
        .one(&database)
        .await
        .expect("read projection")
        .expect("projection exists");
    let transaction = database.begin().await.expect("begin event transaction");
    let event = append_projection_event(
        &transaction,
        "prj_sync01",
        "app_sync01",
        binding_id,
        &projection,
        &projection.document,
        ApplicationUserEventType::Created,
    )
    .await
    .expect("append immutable event and delivery");
    transaction
        .commit()
        .await
        .expect("commit event transaction");

    let deliveries = webhook_service
        .list_deliveries(project_id, application_id, None, None, None)
        .await
        .expect("list delivery");
    assert_eq!(deliveries.items.len(), 1);
    assert_eq!(deliveries.items[0].event_id, event.event_id);
    assert!(deliveries.next_cursor.is_none());
    let now = OffsetDateTime::now_utc();
    let skewed_worker_clock = now + time::Duration::days(365);
    let claim = webhook_repository
        .claim_one(
            "runtime-sync-01",
            Uuid::new_v4(),
            skewed_worker_clock,
            Duration::from_secs(30),
        )
        .await
        .expect("claim delivery")
        .expect("pending delivery exists");
    assert!(claim.primary_secret_ref.contains("_3"));
    assert!(claim.overlap_secret_ref.is_some());
    let mut stale_claim = claim.clone();
    stale_claim.lease_generation += 1;
    assert_eq!(
        webhook_repository
            .finish(
                &stale_claim,
                now.unix_timestamp(),
                WebhookTransportOutcome {
                    outcome: WebhookDeliveryOutcome::Accepted,
                    http_status: Some(204),
                    duration_millis: 2,
                },
                None,
                now,
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::RevisionConflict)
    );
    let finish = webhook_repository.finish(
        &claim,
        now.unix_timestamp(),
        WebhookTransportOutcome {
            outcome: WebhookDeliveryOutcome::Accepted,
            http_status: Some(204),
            duration_millis: 2,
        },
        None,
        now,
        Uuid::new_v4(),
    );
    let replay = webhook_service.replay_delivery(
        project_id,
        application_id,
        claim.delivery_id,
        Uuid::new_v4(),
    );
    let (finish_result, replay_result) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(finish, replay)
    })
    .await
    .expect("finish and replay cannot deadlock under canonical owner lock order");
    finish_result.expect("finish exact fenced claim");
    let replay = replay_result.expect("replay immutable event while finish races");
    assert_eq!(replay.event_id, event.event_id);
    assert_eq!(replay.replay_sequence, 1);
    assert_eq!(replay.replay_of_delivery_id, Some(claim.delivery_id));
    let after_overlap = now
        .checked_add(time::Duration::seconds(601))
        .expect("bounded overlap timestamp");
    sqlx::query(
        "UPDATE webhook_endpoints
            SET overlap_expires_at=transaction_timestamp()-interval '1 second'
          WHERE id=$1",
    )
    .bind(endpoint.id)
    .execute(&pool)
    .await
    .expect("expire overlap under the PostgreSQL clock");
    let replay_claim = webhook_repository
        .claim_one(
            "runtime-sync-01",
            Uuid::new_v4(),
            after_overlap,
            Duration::from_secs(30),
        )
        .await
        .expect("claim replay after overlap expiry")
        .expect("replay remains pending");
    assert!(replay_claim.overlap_secret_ref.is_none());
    let retired_overlap: String = sqlx::query_scalar(
        "SELECT state FROM webhook_secret_generations WHERE endpoint_id=$1 AND generation=1",
    )
    .bind(endpoint.id)
    .fetch_one(&pool)
    .await
    .expect("read retired overlap generation");
    assert_eq!(retired_overlap, "retired");
    sqlx::query(
        "UPDATE webhook_deliveries
            SET lease_expires_at=transaction_timestamp()-interval '1 second'
          WHERE id=$1",
    )
    .bind(replay_claim.delivery_id)
    .execute(&pool)
    .await
    .expect("expire replay lease for recovery lock-order race");
    let recovery_and_claim = webhook_repository.claim_one(
        "runtime-sync-recovery-race",
        Uuid::new_v4(),
        after_overlap + time::Duration::seconds(1),
        Duration::from_secs(30),
    );
    let replay_expired = webhook_service.replay_delivery(
        project_id,
        application_id,
        replay_claim.delivery_id,
        Uuid::new_v4(),
    );
    let (recovered_claim_result, replay_expired_result) =
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(recovery_and_claim, replay_expired)
        })
        .await
        .expect("expired recovery and replay cannot deadlock");
    replay_expired_result.expect("replay remains coherent while expiry recovery races");
    if let Some(recovered_claim) =
        recovered_claim_result.expect("expired recovery produces a coherent claim result")
    {
        webhook_repository
            .finish(
                &recovered_claim,
                (after_overlap + time::Duration::seconds(1)).unix_timestamp(),
                WebhookTransportOutcome {
                    outcome: WebhookDeliveryOutcome::Accepted,
                    http_status: Some(204),
                    duration_millis: 1,
                },
                None,
                after_overlap + time::Duration::seconds(1),
                Uuid::new_v4(),
            )
            .await
            .expect("finish delivery after expiry recovery race");
    }

    let materializer = Arc::new(PostgresIdentityProjectionMaterializer::new(
        Arc::new(UnavailableDurableEmailAddressReader),
        protector,
    ));
    let projection_repository = Arc::new(PostgresProjectionExpansionRepository::new(
        database.clone(),
        materializer.clone(),
    ));
    let policy_service =
        ProjectionPolicyService::new(projection_repository.clone(), Arc::new(SystemClock));
    let project_policy = policy_service
        .update_project(
            project_id,
            UpdateProjectionPolicy {
                verified_email_enabled: true,
                expected_revision: 1,
            },
            Uuid::new_v4(),
        )
        .await
        .expect("expand Project projection policy");
    assert!(project_policy.expansion_operation_id.is_some());
    let application_policy = policy_service
        .update_application(
            project_id,
            application_id,
            UpdateProjectionPolicy {
                verified_email_enabled: true,
                expected_revision: 1,
            },
            Uuid::new_v4(),
        )
        .await
        .expect("expand Application projection policy");
    assert!(application_policy.expansion_operation_id.is_some());
    assert_eq!(
        projection_repository
            .update_project_projection_policy(
                project_id,
                UpdateProjectionPolicy {
                    verified_email_enabled: false,
                    expected_revision: 2,
                },
                OffsetDateTime::now_utc(),
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::InvalidTransition)
    );

    let worker = ProjectionExpansionWorker::new(
        projection_repository,
        Arc::new(SystemClock),
        "runtime-sync-01".to_owned(),
        Uuid::new_v4(),
        Duration::from_secs(30),
        1,
    )
    .expect("projection worker");
    while worker.run_once().await.expect("process expansion batch") {}
    let operation_states: Vec<String> = sqlx::query_scalar(
        "SELECT status FROM projection_expansion_operations ORDER BY created_at,id",
    )
    .fetch_all(&pool)
    .await
    .expect("read expansion operations");
    assert_eq!(operation_states, vec!["completed", "completed"]);
    let snapshots: (i64, i64) = sqlx::query_as(
        "SELECT project_policy_revision,application_policy_revision
         FROM application_user_projections WHERE id=$1",
    )
    .bind(projection_id)
    .fetch_one(&pool)
    .await
    .expect("read converged projection snapshots");
    assert_eq!(snapshots, (2, 2));
    let event_types: Vec<String> = sqlx::query_scalar(
        "SELECT event_type FROM application_user_events WHERE binding_id=$1
         ORDER BY projection_revision",
    )
    .bind(binding_id)
    .fetch_all(&pool)
    .await
    .expect("read immutable event sequence");
    assert_eq!(
        event_types,
        vec![
            "user.projection.created".to_owned(),
            "user.projection.updated".to_owned(),
        ],
        "both policy operations must converge to one semantic update, not duplicate events"
    );

    let lifecycle = PostgresControlLifecycleRepository::new_with_projection_materializer(
        database.clone(),
        materializer,
    );
    let disabled_user = lifecycle
        .disable_project_user(DisableProjectUser {
            project_id,
            user_id,
            expected_security_revision: 1,
            correlation_id: Uuid::new_v4(),
            now: after_overlap + time::Duration::seconds(1),
        })
        .await
        .expect("disable user through production projection materializer");
    assert_eq!(disabled_user.status, ProjectUserStatus::Disabled);
    let event_types_after_disable: Vec<String> = sqlx::query_scalar(
        "SELECT event_type FROM application_user_events WHERE binding_id=$1
         ORDER BY projection_revision",
    )
    .bind(binding_id)
    .fetch_all(&pool)
    .await
    .expect("read disabled immutable event");
    assert_eq!(
        event_types_after_disable,
        vec![
            "user.projection.created".to_owned(),
            "user.projection.updated".to_owned(),
            "user.projection.disabled".to_owned(),
        ]
    );
    let disabled_delivery_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM webhook_deliveries delivery
           JOIN application_user_events event ON event.id=delivery.event_id
          WHERE event.binding_id=$1 AND event.event_type='user.projection.disabled'",
    )
    .bind(binding_id)
    .fetch_one(&pool)
    .await
    .expect("count disabled-event delivery");
    assert_eq!(disabled_delivery_count, 1);
    lifecycle
        .disable_project_user(DisableProjectUser {
            project_id,
            user_id,
            expected_security_revision: disabled_user.security_revision,
            correlation_id: Uuid::new_v4(),
            now: after_overlap + time::Duration::seconds(2),
        })
        .await
        .expect("replay disabled user command without a second event");
    let event_count_after_noop: i64 =
        sqlx::query_scalar("SELECT count(*) FROM application_user_events WHERE binding_id=$1")
            .bind(binding_id)
            .fetch_one(&pool)
            .await
            .expect("count immutable events after no-op disable");
    assert_eq!(event_count_after_noop, 3);

    let _finish_after_disable = webhook_service
        .replay_delivery(
            project_id,
            application_id,
            claim.delivery_id,
            Uuid::new_v4(),
        )
        .await
        .expect("queue transient-finish delivery before Application disable");
    let transient_claim = webhook_repository
        .claim_one(
            "runtime-sync-disable",
            Uuid::new_v4(),
            after_overlap,
            Duration::from_secs(30),
        )
        .await
        .expect("claim delivery before Application disable")
        .expect("delivery is claimable");
    let provisioning = PostgresProvisioningAdapter::new(
        database.clone(),
        Url::parse("https://runtime.example.test").expect("runtime URL"),
        Vec::new(),
        Duration::from_secs(1),
        Duration::from_mins(1),
    );
    sqlx::query(
        "UPDATE webhook_secret_generations
            SET state='overlap',retired_at=NULL
          WHERE endpoint_id=$1 AND generation=1",
    )
    .bind(endpoint.id)
    .execute(&pool)
    .await
    .expect("restore expired overlap for lock-order race");
    sqlx::query(
        "UPDATE webhook_endpoints
            SET overlap_secret_generation=1,
                overlap_expires_at=transaction_timestamp()-interval '1 second'
          WHERE id=$1",
    )
    .bind(endpoint.id)
    .execute(&pool)
    .await
    .expect("arm expired overlap for lock-order race");
    let disable_application =
        provisioning.disable_application(project_id, application_id, 1, Uuid::new_v4());
    let maintenance_and_claim = webhook_repository.claim_one(
        "runtime-sync-race",
        Uuid::new_v4(),
        after_overlap + time::Duration::seconds(1),
        Duration::from_secs(30),
    );
    let (disabled_result, race_claim_result) =
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(disable_application, maintenance_and_claim)
        })
        .await
        .expect("overlap maintenance and Application disable cannot deadlock");
    let disabled = disabled_result.expect("disable Application and its webhook surface atomically");
    assert_eq!(disabled.status, "disabled");
    assert!(
        race_claim_result
            .expect("overlap maintenance remains coherent")
            .is_none(),
        "the delivery was already leased before the disable race"
    );

    webhook_repository
        .finish(
            &transient_claim,
            (after_overlap + time::Duration::seconds(2)).unix_timestamp(),
            WebhookTransportOutcome {
                outcome: WebhookDeliveryOutcome::Transient,
                http_status: Some(503),
                duration_millis: 1,
            },
            Some(after_overlap + time::Duration::seconds(10)),
            after_overlap + time::Duration::seconds(2),
            Uuid::new_v4(),
        )
        .await
        .expect("transient finish after disable settles as cancelled");
    let transient_state: String =
        sqlx::query_scalar("SELECT state FROM webhook_deliveries WHERE id=$1")
            .bind(transient_claim.delivery_id)
            .fetch_one(&pool)
            .await
            .expect("read transient in-flight delivery");
    assert_eq!(transient_state, "cancelled");

    sqlx::query("UPDATE applications SET status='active' WHERE id=$1")
        .bind(application_id)
        .execute(&pool)
        .await
        .expect("reactivate Application for expired recovery proof");
    sqlx::query("UPDATE webhook_endpoints SET status='active',disabled_at=NULL WHERE id=$1")
        .bind(endpoint.id)
        .execute(&pool)
        .await
        .expect("reactivate endpoint for expired recovery proof");
    let recover_after_disable = webhook_service
        .replay_delivery(
            project_id,
            application_id,
            claim.delivery_id,
            Uuid::new_v4(),
        )
        .await
        .expect("queue expired-recovery delivery before second Application disable");
    let expired_claim = webhook_repository
        .claim_one(
            "runtime-sync-disable",
            Uuid::new_v4(),
            after_overlap + time::Duration::seconds(3),
            Duration::from_secs(30),
        )
        .await
        .expect("claim delivery before second Application disable")
        .expect("expired-recovery delivery is claimable");
    assert_ne!(expired_claim.delivery_id, Uuid::nil());
    let _ = recover_after_disable;
    provisioning
        .disable_application(project_id, application_id, 2, Uuid::new_v4())
        .await
        .expect("disable Application with an in-flight lease for recovery proof");
    sqlx::query(
        "UPDATE webhook_deliveries
            SET lease_expires_at=transaction_timestamp()-interval '1 second'
          WHERE id=$1",
    )
    .bind(expired_claim.delivery_id)
    .execute(&pool)
    .await
    .expect("expire in-flight lease under the PostgreSQL clock");
    assert!(
        webhook_repository
            .claim_one(
                "runtime-sync-disable",
                Uuid::new_v4(),
                after_overlap + time::Duration::seconds(34),
                Duration::from_secs(30),
            )
            .await
            .expect("expired lease recovery after disable is safe")
            .is_none()
    );
    let expired_state: String =
        sqlx::query_scalar("SELECT state FROM webhook_deliveries WHERE id=$1")
            .bind(expired_claim.delivery_id)
            .fetch_one(&pool)
            .await
            .expect("read expired in-flight delivery");
    assert_eq!(expired_state, "cancelled");

    let endpoint_status: String =
        sqlx::query_scalar("SELECT status FROM webhook_endpoints WHERE id=$1")
            .bind(endpoint.id)
            .fetch_one(&pool)
            .await
            .expect("read disabled endpoint");
    assert_eq!(endpoint_status, "disabled");
    sqlx::query("UPDATE applications SET status='active' WHERE id=$1")
        .bind(application_id)
        .execute(&pool)
        .await
        .expect("reactivate Application for isolated Project fence proof");
    sqlx::query("UPDATE webhook_endpoints SET status='active',disabled_at=NULL WHERE id=$1")
        .bind(endpoint.id)
        .execute(&pool)
        .await
        .expect("reactivate endpoint for isolated Project fence proof");
    webhook_service
        .replay_delivery(
            project_id,
            application_id,
            claim.delivery_id,
            Uuid::new_v4(),
        )
        .await
        .expect("queue delivery before Project disable");
    provisioning
        .disable_project(project_id, 1, Uuid::new_v4())
        .await
        .expect("disable Project through exclusive owner fence");
    assert_eq!(
        webhook_service
            .create_endpoint(
                project_id,
                application_id,
                create_endpoint("project-disabled-endpoint"),
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::Disabled),
        "disabled Project must fence webhook mutation before endpoint state"
    );
    assert!(
        webhook_repository
            .claim_one(
                "runtime-sync-01",
                Uuid::new_v4(),
                after_overlap + time::Duration::seconds(3),
                Duration::from_secs(30),
            )
            .await
            .expect("disabled Project claim is safe")
            .is_none(),
        "active Application and endpoint cannot bypass disabled Project"
    );
    let disabled_project_operation_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO projection_expansion_operations
            (id,project_id,scope_kind,target_policy_revision,status,processed_count,
             lease_generation,created_at,updated_at)
         VALUES ($1,$2,'project',99,'pending',0,0,$3,$3)",
    )
    .bind(disabled_project_operation_id)
    .bind(project_id)
    .bind(after_overlap + time::Duration::seconds(3))
    .execute(&pool)
    .await
    .expect("seed expansion operation owned by disabled Project");
    assert!(
        !worker
            .run_once()
            .await
            .expect("disabled Project expansion claim is safe")
    );
    let disabled_project_operation_state: String =
        sqlx::query_scalar("SELECT status FROM projection_expansion_operations WHERE id=$1")
            .bind(disabled_project_operation_id)
            .fetch_one(&pool)
            .await
            .expect("read disabled Project expansion operation");
    assert_eq!(disabled_project_operation_state, "pending");

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

    let repository = Arc::new(PostgresWebhookRepository::new(
        database.clone(),
        projection_protector(),
    ));
    let secret_provisioner = Arc::new(TestSecretProvisioner::default());
    let service = WebhookControlService::new(
        repository.clone(),
        secret_provisioner.clone(),
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

    let process_id = "runtime-key-retirement";
    let process_incarnation = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO runtime_process_incarnations (process_id,process_incarnation,started_at)
         VALUES ($1,$2,transaction_timestamp())",
    )
    .bind(process_id)
    .bind(process_incarnation)
    .execute(&pool)
    .await
    .expect("insert Runtime key observation owner");
    sqlx::query(
        "UPDATE projection_email_key_authority
            SET authority_revision=2,write_version=2,accepted_versions=ARRAY[1,2],
                target_version=NULL,target_staged_at=NULL,updated_at=transaction_timestamp()
          WHERE singleton",
    )
    .execute(&pool)
    .await
    .expect("install two-version projection-email authority fixture");
    let mut retained_projection_keys = BTreeMap::new();
    retained_projection_keys.insert(1, RuntimeKeyMaterial::new([7; 32], [9; 32]));
    let rotating_protector = SoftwareProjectionVerifiedEmailProtector::new(
        "application-sync-test".to_owned(),
        2,
        RuntimeKeyMaterial::new([17; 32], [19; 32]),
        retained_projection_keys,
    )
    .expect("build rotating projection-email protector");
    let key_authority = PostgresProjectionEmailKeyAuthority::new(database.clone());
    key_authority
        .observe_runtime(
            process_id,
            process_incarnation,
            &rotating_protector,
            time::Duration::minutes(1),
        )
        .await
        .expect("observe both readable projection-email key versions");
    let required_processes = vec![process_id.to_owned()];
    assert_eq!(
        key_authority
            .reconcile(
                &required_processes,
                &rotating_protector,
                None,
                Some(1),
                time::Duration::milliseconds(1),
            )
            .await,
        Err(ApplicationError::Disabled),
        "an event row blocks retirement even after its retention deadline"
    );
    let retirement_before_cleanup: Option<i32> = sqlx::query_scalar(
        "SELECT retirement_version FROM projection_email_key_authority WHERE singleton",
    )
    .fetch_one(&pool)
    .await
    .expect("read blocked retirement state");
    assert!(retirement_before_cleanup.is_none());
    assert!(
        repository
            .maintain(now, 100)
            .await
            .expect("clean expired key-bearing event")
            > 0
    );
    assert_eq!(
        key_authority
            .reconcile(
                &required_processes,
                &rotating_protector,
                None,
                Some(1),
                time::Duration::milliseconds(1),
            )
            .await,
        Err(ApplicationError::Disabled),
        "first reference-free reconciliation authorizes delayed retirement"
    );
    tokio::time::sleep(Duration::from_millis(2)).await;
    key_authority
        .reconcile(
            &required_processes,
            &rotating_protector,
            None,
            Some(1),
            time::Duration::milliseconds(1),
        )
        .await
        .expect("retirement succeeds only after event cleanup and retention delay");
    let accepted_versions: Vec<i32> = sqlx::query_scalar(
        "SELECT accepted_versions FROM projection_email_key_authority WHERE singleton",
    )
    .fetch_one(&pool)
    .await
    .expect("read retired projection-email authority");
    assert_eq!(accepted_versions, vec![2]);

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

    let calls_before_terminal_replay = secret_provisioner.calls.load(Ordering::SeqCst);
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
    assert_eq!(
        secret_provisioner.calls.load(Ordering::SeqCst),
        calls_before_terminal_replay,
        "terminal endpoint replay must not repeat external provisioning"
    );

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
    let reservation_state: String = sqlx::query_scalar(
        "SELECT state FROM webhook_secret_reference_reservations WHERE secret_ref=$1",
    )
    .bind(&cleanup.secret_ref)
    .fetch_one(&pool)
    .await
    .expect("read reserved secret reference");
    assert_eq!(reservation_state, "reserved");
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
        "SELECT cleanup.state,reservation.state
           FROM webhook_secret_cleanup_operations cleanup
           JOIN webhook_secret_reference_reservations reservation
             ON reservation.secret_ref=cleanup.secret_ref
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
