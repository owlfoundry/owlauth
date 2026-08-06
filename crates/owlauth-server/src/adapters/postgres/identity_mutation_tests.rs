#![allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::type_complexity,
    reason = "real PostgreSQL lifecycle scenarios keep complete authority setup and assertions together"
)]

use std::{collections::BTreeMap, env, sync::Arc};

use async_trait::async_trait;
use sea_orm::{Database, DatabaseConnection, DatabaseTransaction, EntityTrait, TransactionTrait};
use sqlx::{PgPool, postgres::PgPoolOptions};
use testcontainers::{
    GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor, wait::LogWaitStrategy},
    runners::AsyncRunner,
};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::{
    DatabasePools,
    authentication::PostgresAuthenticationRepository,
    control_lifecycle::PostgresControlLifecycleRepository,
    email::PostgresPasswordlessEmailRepository,
    identity_mutation::PostgresControlIdentityMutationRepository,
    identity_mutation_test_support::PostgresIdentityMutationRepository,
    projection::{
        IdentityProjectionMaterializer, PostgresIdentityProjectionMaterializer,
        ProjectionCryptography,
    },
};
use crate::{
    adapters::runtime_security::{
        RuntimeKeyMaterial, SoftwareDurableEmailAddressReader,
        SoftwareProjectionVerifiedEmailProtector, SoftwareRuntimeProtector,
        UnavailableDurableEmailAddressReader,
    },
    application::{
        AdmittedEmailMethod, ApplicationError, AuthenticationRepository, BindHostedBrowser,
        CandidateEvidenceMaterial, ClaimIdentityMutationProvider, CommitEmailGeneration,
        CommitIdentityMutationEmailGeneration, CompleteIdentityMutationEmailProof,
        ControlIdentityMutationRepository, ControlLifecyclePort, CreateIdentityMutation,
        CreateIdentityMutationResult, CreateLoginTransaction, EmailProofKind,
        EstablishIdentityMutationMagicTransferContext, ExpectedIdentity, ExpectedUser,
        IdentityMutationAdmittedProviderProfile, IdentityMutationBindingsDisposition,
        IdentityMutationCandidate, IdentityMutationCandidateEvidenceContext,
        IdentityMutationCandidateKind, IdentityMutationCreateOperation,
        IdentityMutationEmailCandidate, IdentityMutationEmailProofKey,
        IdentityMutationEmailProofMaterial, IdentityMutationPrimarySourceDisposition,
        IdentityMutationProofAuthoritySelection, IdentityMutationProviderCandidate,
        IdentityMutationProviderCapabilities, IdentityMutationProviderRegistrationEvidence,
        IdentityMutationRecord, IdentityMutationSessionsDisposition, LoginRevisionSnapshot,
        MailChallengeOwner, MailOutboxRepository, MailTransportOutcome,
        PasswordlessEmailRepository, PreparedIdentityMutationCandidate,
        PreparedIdentityMutationConfirmation, PreparedIdentityMutationCreate,
        PreparedIdentityMutationProviderCompletion, ProtectedPurpose, ProtectedValue,
        ProviderProofObservation, ResolveIdentityMutationMagicTransferContext,
        RuntimeIdentityMutationRepository, RuntimeProtector, SelectEmailMethod,
        VerifyIdentityMutationEmailProof, VersionedDigest, mail_context,
    },
    config::PlaneMode,
    domain::{
        ApplicationUserEventType, IdentityKind, IdentityMutationKind, IdentityMutationSlotRole,
        IdentityMutationStatus,
    },
    http::{build_routers_with_runtime_incarnation, tests::identity_mutation_composition_config},
};

const POSTGRES_PORT: u16 = 5432;
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

fn fixture_projection_materializer() -> Arc<PostgresIdentityProjectionMaterializer> {
    Arc::new(PostgresIdentityProjectionMaterializer::new(
        Arc::new(
            SoftwareDurableEmailAddressReader::new(
                "identity-mutation-test".to_owned(),
                1,
                RuntimeKeyMaterial::new([11; 32], [12; 32]),
                BTreeMap::new(),
            )
            .expect("identity mutation durable email reader"),
        ),
        Arc::new(
            SoftwareProjectionVerifiedEmailProtector::new(
                "identity-mutation-projection-test".to_owned(),
                1,
                [104; 32],
                BTreeMap::new(),
            )
            .expect("identity mutation projection protector"),
        ),
    ))
}

fn test_projection_materializer() -> Arc<PostgresIdentityProjectionMaterializer> {
    Arc::new(PostgresIdentityProjectionMaterializer::new(
        Arc::new(UnavailableDurableEmailAddressReader),
        Arc::new(
            SoftwareProjectionVerifiedEmailProtector::new(
                "identity-mutation-inventory-test".to_owned(),
                1,
                [104; 32],
                BTreeMap::new(),
            )
            .expect("identity mutation projection protector"),
        ),
    ))
}

struct FailingProjectionMaterializer;

impl ProjectionCryptography for FailingProjectionMaterializer {
    fn projection_write_version(&self) -> i32 {
        1
    }

    fn projection_readable_versions(&self) -> std::collections::BTreeSet<i32> {
        std::collections::BTreeSet::from([1])
    }

    fn read_durable_email(
        &self,
        _project_id: Uuid,
        _identity_id: Uuid,
        _value: &ProtectedValue,
    ) -> Result<zeroize::Zeroizing<String>, ApplicationError> {
        Err(ApplicationError::ExternalStore)
    }

    fn protect_projection_email(
        &self,
        _project_id: Uuid,
        _application_id: Uuid,
        _user_id: Uuid,
        _projection_revision: i64,
        _email: &[u8],
    ) -> Result<ProtectedValue, ApplicationError> {
        Err(ApplicationError::ExternalStore)
    }

    fn unprotect_projection_email(
        &self,
        _project_id: Uuid,
        _application_id: Uuid,
        _user_id: Uuid,
        _projection_revision: i64,
        _value: &ProtectedValue,
    ) -> Result<zeroize::Zeroizing<String>, ApplicationError> {
        Err(ApplicationError::ExternalStore)
    }
}

#[async_trait]
impl IdentityProjectionMaterializer for FailingProjectionMaterializer {
    async fn fan_out_user(
        &self,
        _transaction: &DatabaseTransaction,
        _user: &super::entity::project_user::Model,
        _now: OffsetDateTime,
    ) -> Result<(), ApplicationError> {
        Err(ApplicationError::ExternalStore)
    }
}

struct Fixture {
    _container: testcontainers::ContainerAsync<GenericImage>,
    sqlx: PgPool,
    database: DatabaseConnection,
    repository: PostgresIdentityMutationRepository,
    protector: Arc<SoftwareRuntimeProtector>,
    incarnation: Uuid,
    project_id: Uuid,
    application_id: Uuid,
    provider_id: Uuid,
    user_id: Uuid,
    identity_id: Uuid,
}

fn docker_is_required() -> bool {
    env::var("OWLAUTH_REQUIRE_DOCKER").is_ok_and(|value| value == "1")
}

async fn wait_for_backend_blocked_by(pool: &PgPool, blocker_pid: i32, label: &str) -> i32 {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if let Some(blocked_pid) = sqlx::query_scalar::<_, i32>(
                "SELECT blocked.pid FROM pg_stat_activity blocked
                 WHERE blocked.datname=current_database()
                   AND blocked.wait_event_type='Lock'
                   AND $1=ANY(pg_blocking_pids(blocked.pid))
                 ORDER BY blocked.pid LIMIT 1",
            )
            .bind(blocker_pid)
            .fetch_optional(pool)
            .await
            .expect("observe PostgreSQL lock wait")
            {
                return blocked_pid;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {label}"))
}

async fn fixture() -> Option<Fixture> {
    fixture_with_provider("main", "oidc", "https://issuer.example").await
}

async fn google_fixture() -> Option<Fixture> {
    fixture_with_provider("google-main", "google", crate::domain::GOOGLE_ISSUER).await
}

async fn fixture_with_provider(
    provider_key: &str,
    provider_kind: &str,
    provider_issuer: &str,
) -> Option<Fixture> {
    let container = match GenericImage::new("postgres", "17-bookworm")
        .with_exposed_port(POSTGRES_PORT.tcp())
        .with_wait_for(WaitFor::log(LogWaitStrategy::stderr(
            "database system is ready to accept connections",
        )))
        .with_env_var("POSTGRES_DB", "owlauth_identity_mutation_test")
        .with_env_var("POSTGRES_USER", "owlauth")
        .with_env_var("POSTGRES_PASSWORD", "owlauth_test")
        .start()
        .await
    {
        Ok(container) => container,
        Err(error) => {
            assert!(
                !docker_is_required(),
                "PostgreSQL identity-mutation test container is required: {error}"
            );
            eprintln!("skipping identity-mutation repository test: Docker unavailable: {error}");
            return None;
        }
    };
    let host = container.get_host().await.expect("container host");
    let port = container
        .get_host_port_ipv4(POSTGRES_PORT)
        .await
        .expect("container port");
    let url =
        format!("postgres://owlauth:owlauth_test@{host}:{port}/owlauth_identity_mutation_test");
    let sqlx = PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .expect("connect identity-mutation database");
    MIGRATOR.run(&sqlx).await.expect("apply migrations");
    sqlx::query(
        "INSERT INTO email_identity_alias_authority
         (singleton,revision,write_version,target_version,accepted_versions)
         VALUES (TRUE,1,1,1,'[1]'::jsonb)",
    )
    .execute(&sqlx)
    .await
    .expect("seed email identity alias authority");
    let database: DatabaseConnection = Database::connect(&url)
        .await
        .expect("connect SeaORM identity-mutation database");
    let incarnation = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO runtime_process_incarnations(process_id,process_incarnation,started_at)
         VALUES ('identity-mutation-test',$1,clock_timestamp())",
    )
    .bind(incarnation)
    .execute(&sqlx)
    .await
    .expect("seed Runtime incarnation");
    let protector = Arc::new(
        SoftwareRuntimeProtector::new(
            "identity-mutation-test".to_owned(),
            1,
            RuntimeKeyMaterial::new([11; 32], [12; 32]),
            BTreeMap::new(),
        )
        .expect("test protector"),
    );
    let repository = PostgresIdentityMutationRepository::new(
        database.clone(),
        "identity-mutation-test".to_owned(),
        incarnation,
        fixture_projection_materializer(),
        Vec::new(),
    );
    let project_id = Uuid::new_v4();
    let application_id = Uuid::new_v4();
    let provider_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let identity_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO projects(id,public_id,status,metadata_revision,security_revision)
         VALUES ($1,$2,'active',1,1)",
    )
    .bind(project_id)
    .bind(format!("prj_{project_id}"))
    .execute(&sqlx)
    .await
    .expect("seed Project");
    sqlx::query(
        "INSERT INTO applications
         (id,project_id,public_id,status,revision,metadata_revision,security_revision)
         VALUES ($1,$2,$3,'active',1,1,1)",
    )
    .bind(application_id)
    .bind(project_id)
    .bind(format!("app_{application_id}"))
    .execute(&sqlx)
    .await
    .expect("seed Application");
    sqlx::query(
        "INSERT INTO project_policies
         (project_id,claims_revision,session_revision,claims_policy,session_policy)
         VALUES ($1,1,1,'{\"access_token_lifetime_seconds\":900}'::jsonb,
                 '{\"browser_session_reuse\":false,
                    \"browser_session_reuse_max_age_seconds\":28800}'::jsonb)",
    )
    .bind(project_id)
    .execute(&sqlx)
    .await
    .expect("seed Project policy");
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
         SELECT $1,$2,$3,$4,'Main',$5,'client',$6,material.id,'active',1 FROM material",
    )
    .bind(provider_id)
    .bind(project_id)
    .bind(provider_key)
    .bind(provider_kind)
    .bind(provider_issuer)
    .bind(format!(
        "https://runtime.example/projects/x/auth/callback/{provider_key}"
    ))
    .execute(&sqlx)
    .await
    .expect("seed provider");
    sqlx::query(
        "INSERT INTO application_provider_assignments
         (project_id,application_id,provider_id,status,security_revision)
         VALUES ($1,$2,$3,'active',1)",
    )
    .bind(project_id)
    .bind(application_id)
    .bind(provider_id)
    .execute(&sqlx)
    .await
    .expect("seed provider assignment");
    sqlx::query(
        "UPDATE project_email_policies SET status='enabled',allow_deployment_default=TRUE,
                 resend_after_seconds=30,transferred_magic_link_enabled=TRUE WHERE project_id=$1",
    )
    .bind(project_id)
    .execute(&sqlx)
    .await
    .expect("enable email policy");
    sqlx::query(
        "INSERT INTO application_email_assignments(project_id,application_id,status,security_revision)
         VALUES ($1,$2,'active',1)",
    )
    .bind(project_id)
    .bind(application_id)
    .execute(&sqlx)
    .await
    .expect("seed email assignment");
    sqlx::query(
        "WITH material AS (
             INSERT INTO protected_materials
                (id,scope_kind,owner_kind,owner_id,generation,material_kind,
                 provider_id,provider_format_version,context_version,context_digest,
                 opaque_value,safe_fingerprint,state)
             VALUES (gen_random_uuid(),'deployment','deployment_smtp',$2,1,
                     'configuration_secret','software',1,1,
                     decode(repeat('19',32),'hex'),decode(repeat('18',64),'hex'),$1,'live')
             RETURNING id
         )
         INSERT INTO deployment_smtp_generations
            (generation,status,revision,security_eligibility_revision,host,port,tls_mode,
             sender_address,safe_fingerprint,material_owner_id,credential_material_id)
         SELECT 1,'active',1,1,'smtp.example',465,'implicit_tls',
                'sender@example.test',$1,$2,material.id FROM material",
    )
    .bind(vec![17_u8; 32])
    .bind(Uuid::new_v4())
    .execute(&sqlx)
    .await
    .expect("seed deployment SMTP");
    sqlx::query(
        "INSERT INTO email_protection_runtime_readiness
         (process_id,process_incarnation,state,failure_class,checked_at,lease_expires_at)
         VALUES ('identity-mutation-test',$1,'ready',NULL,clock_timestamp(),
                 clock_timestamp()+interval '10 minutes')",
    )
    .bind(incarnation)
    .execute(&sqlx)
    .await
    .expect("seed email protection readiness");
    let mut seed = sqlx.begin().await.expect("begin user seed");
    sqlx::query(
        "INSERT INTO project_users
         (id,project_id,public_id,status,user_revision,security_revision,base_profile_digest)
         VALUES ($1,$2,$3,'active',1,1,$4)",
    )
    .bind(user_id)
    .bind(project_id)
    .bind(format!("usr_{user_id}"))
    .bind(vec![0_u8; 32])
    .execute(&mut *seed)
    .await
    .expect("seed user");
    sqlx::query(
        "INSERT INTO linked_identities
         (id,project_id,user_id,created_via_provider_configuration_id,issuer,subject,status,
          identity_revision,source_profile_digest,observed_at)
         VALUES ($1,$2,$3,$4,$5,'existing','active',1,public.owlauth_provider_source_profile_digest(NULL,NULL,NULL),clock_timestamp())",
    )
    .bind(identity_id)
    .bind(project_id)
    .bind(user_id)
    .bind(provider_id)
    .bind(provider_issuer)
    .execute(&mut *seed)
    .await
    .expect("seed identity");
    sqlx::query(
        "UPDATE project_users SET primary_source_kind='provider',primary_profile_identity_id=$2
         WHERE id=$1",
    )
    .bind(user_id)
    .bind(identity_id)
    .execute(&mut *seed)
    .await
    .expect("seed primary identity");
    seed.commit().await.expect("commit user seed");
    Some(Fixture {
        _container: container,
        sqlx,
        database,
        repository,
        protector,
        incarnation,
        project_id,
        application_id,
        provider_id,
        user_id,
        identity_id,
    })
}

fn digest(byte: u8) -> VersionedDigest {
    VersionedDigest {
        value: [byte; 32],
        key_version: 1,
    }
}

async fn seed_application_projection(
    fixture: &Fixture,
    application_id: Uuid,
    user_id: Uuid,
) -> (
    super::entity::application_user_projection::Model,
    serde_json::Value,
) {
    let user = super::entity::project_user::Entity::find_by_id(user_id)
        .one(&fixture.database)
        .await
        .expect("read projection user")
        .expect("projection user exists");
    let (document, canonical_digest) =
        super::projection::projection_material(&user, 1).expect("materialize projection");
    let binding_id = Uuid::new_v4();
    let projection_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO application_user_bindings
         (id,project_id,application_id,user_id,status,binding_revision)
         VALUES ($1,$2,$3,$4,'active',1)",
    )
    .bind(binding_id)
    .bind(fixture.project_id)
    .bind(application_id)
    .bind(user_id)
    .execute(&fixture.sqlx)
    .await
    .expect("seed Application binding");
    sqlx::query(
        "INSERT INTO application_user_projections
         (id,project_id,binding_id,application_id,user_id,schema_name,projection_revision,
          source_user_revision,canonical_digest,source_base_profile_digest,document)
         VALUES ($1,$2,$3,$4,$5,'owlauth.user.v1',1,1,$6,$7,$8)",
    )
    .bind(projection_id)
    .bind(fixture.project_id)
    .bind(binding_id)
    .bind(application_id)
    .bind(user_id)
    .bind(canonical_digest)
    .bind(user.base_profile_digest)
    .bind(&document)
    .execute(&fixture.sqlx)
    .await
    .expect("seed Application projection");
    let projection = super::entity::application_user_projection::Entity::find_by_id(projection_id)
        .one(&fixture.database)
        .await
        .expect("read seeded projection")
        .expect("seeded projection exists");
    (projection, document)
}

fn protected(byte: u8, len: usize) -> ProtectedValue {
    ProtectedValue {
        ciphertext: vec![byte; len],
        key_version: 1,
    }
}

fn mutation_mail_aad(
    project_id: Uuid,
    intent_id: Uuid,
    slot_id: Uuid,
    challenge_id: Uuid,
    generation: i16,
) -> Vec<u8> {
    let mut context = b"owlauth-identity-mutation-email-challenge-v1\0".to_vec();
    context.extend_from_slice(project_id.as_bytes());
    context.extend_from_slice(intent_id.as_bytes());
    context.extend_from_slice(slot_id.as_bytes());
    context.extend_from_slice(challenge_id.as_bytes());
    context.extend_from_slice(&generation.to_be_bytes());
    context
}

fn prepared_unlink(
    fixture: &Fixture,
    identity_id: Uuid,
    idempotency_key: &str,
    intent_id: Uuid,
    handle_byte: u8,
) -> PreparedIdentityMutationCreate {
    PreparedIdentityMutationCreate {
        command: CreateIdentityMutation {
            project_id: fixture.project_id,
            operation: IdentityMutationCreateOperation::Unlink {
                owner: ExpectedUser {
                    user_id: fixture.user_id,
                    expected_user_revision: 1,
                    expected_user_security_revision: 1,
                },
                identity: ExpectedIdentity {
                    identity_kind: IdentityKind::Provider,
                    identity_id,
                    expected_identity_revision: 1,
                },
                authority: IdentityMutationProofAuthoritySelection::Provider {
                    application_id: fixture.application_id,
                    provider_configuration_id: fixture.provider_id,
                },
                primary_source: IdentityMutationPrimarySourceDisposition::Preserve,
            },
            idempotency_key: idempotency_key.to_owned(),
            correlation_id: Uuid::new_v4(),
        },
        provider_capabilities: IdentityMutationProviderCapabilities::reviewed(),
        runtime_base: "https://runtime.example/".to_owned(),
        intent_id,
        hosted_handle_digest: digest(handle_byte),
        request_digest: vec![handle_byte.wrapping_add(1); 32],
        protected_create_result: protected(handle_byte.wrapping_add(2), 41),
        created_at: OffsetDateTime::UNIX_EPOCH,
        expires_at: OffsetDateTime::UNIX_EPOCH,
    }
}

fn prepared_merge(
    fixture: &Fixture,
    loser_id: Uuid,
    loser_identity_id: Uuid,
    intent_id: Uuid,
) -> PreparedIdentityMutationCreate {
    let authority = IdentityMutationProofAuthoritySelection::Provider {
        application_id: fixture.application_id,
        provider_configuration_id: fixture.provider_id,
    };
    PreparedIdentityMutationCreate {
        command: CreateIdentityMutation {
            project_id: fixture.project_id,
            operation: IdentityMutationCreateOperation::Merge {
                winner: ExpectedUser {
                    user_id: fixture.user_id,
                    expected_user_revision: 1,
                    expected_user_security_revision: 1,
                },
                winner_identity: ExpectedIdentity {
                    identity_kind: IdentityKind::Provider,
                    identity_id: fixture.identity_id,
                    expected_identity_revision: 1,
                },
                loser: ExpectedUser {
                    user_id: loser_id,
                    expected_user_revision: 1,
                    expected_user_security_revision: 1,
                },
                loser_identity: ExpectedIdentity {
                    identity_kind: IdentityKind::Provider,
                    identity_id: loser_identity_id,
                    expected_identity_revision: 1,
                },
                winner_authority: authority,
                loser_authority: authority,
                primary_source: IdentityMutationPrimarySourceDisposition::Provider(
                    ExpectedIdentity {
                        identity_kind: IdentityKind::Provider,
                        identity_id: loser_identity_id,
                        expected_identity_revision: 1,
                    },
                ),
                sessions: IdentityMutationSessionsDisposition::LoserRevoked,
                bindings: IdentityMutationBindingsDisposition::WinnerPreferred,
            },
            idempotency_key: "final-merge".to_owned(),
            correlation_id: Uuid::new_v4(),
        },
        provider_capabilities: IdentityMutationProviderCapabilities::reviewed(),
        runtime_base: "https://runtime.example/".to_owned(),
        intent_id,
        hosted_handle_digest: digest(71),
        request_digest: vec![72; 32],
        protected_create_result: protected(73, 41),
        created_at: OffsetDateTime::UNIX_EPOCH,
        expires_at: OffsetDateTime::UNIX_EPOCH,
    }
}

fn prepared_email(
    fixture: &Fixture,
    idempotency_key: &str,
    intent_id: Uuid,
) -> PreparedIdentityMutationCreate {
    let provider = IdentityMutationProofAuthoritySelection::Provider {
        application_id: fixture.application_id,
        provider_configuration_id: fixture.provider_id,
    };
    PreparedIdentityMutationCreate {
        command: CreateIdentityMutation {
            project_id: fixture.project_id,
            operation: IdentityMutationCreateOperation::Link {
                destination: ExpectedUser {
                    user_id: fixture.user_id,
                    expected_user_revision: 1,
                    expected_user_security_revision: 1,
                },
                destination_identity: ExpectedIdentity {
                    identity_kind: IdentityKind::Provider,
                    identity_id: fixture.identity_id,
                    expected_identity_revision: 1,
                },
                candidate_kind: IdentityKind::Email,
                destination_authority: provider,
                candidate_authority: IdentityMutationProofAuthoritySelection::Email {
                    application_id: fixture.application_id,
                },
            },
            idempotency_key: idempotency_key.to_owned(),
            correlation_id: Uuid::new_v4(),
        },
        provider_capabilities: IdentityMutationProviderCapabilities::reviewed(),
        runtime_base: "https://runtime.example/".to_owned(),
        intent_id,
        hosted_handle_digest: digest(21),
        request_digest: vec![22; 32],
        protected_create_result: protected(23, 41),
        created_at: OffsetDateTime::UNIX_EPOCH,
        expires_at: OffsetDateTime::UNIX_EPOCH,
    }
}

fn prepared(
    fixture: &Fixture,
    idempotency_key: &str,
    intent_id: Uuid,
) -> PreparedIdentityMutationCreate {
    let authority = IdentityMutationProofAuthoritySelection::Provider {
        application_id: fixture.application_id,
        provider_configuration_id: fixture.provider_id,
    };
    PreparedIdentityMutationCreate {
        command: CreateIdentityMutation {
            project_id: fixture.project_id,
            operation: IdentityMutationCreateOperation::Link {
                destination: ExpectedUser {
                    user_id: fixture.user_id,
                    expected_user_revision: 1,
                    expected_user_security_revision: 1,
                },
                destination_identity: ExpectedIdentity {
                    identity_kind: IdentityKind::Provider,
                    identity_id: fixture.identity_id,
                    expected_identity_revision: 1,
                },
                candidate_kind: IdentityKind::Provider,
                destination_authority: authority,
                candidate_authority: authority,
            },
            idempotency_key: idempotency_key.to_owned(),
            correlation_id: Uuid::new_v4(),
        },
        provider_capabilities: IdentityMutationProviderCapabilities::reviewed(),
        runtime_base: "https://runtime.example/".to_owned(),
        intent_id,
        hosted_handle_digest: digest(1),
        request_digest: vec![2; 32],
        protected_create_result: protected(3, 41),
        created_at: OffsetDateTime::UNIX_EPOCH,
        expires_at: OffsetDateTime::UNIX_EPOCH,
    }
}

async fn expire_attached_receipts_with_database_clock(fixture: &Fixture, intent_id: Uuid) {
    let mut setup = fixture
        .sqlx
        .acquire()
        .await
        .expect("acquire receipt expiry setup");
    sqlx::query("SET session_replication_role=replica")
        .execute(&mut *setup)
        .await
        .expect("disable authority triggers for receipt expiry fixture");
    sqlx::query(
        "UPDATE identity_proof_receipts
            SET issued_at=clock_timestamp()-interval '5 minutes',
                expires_at=clock_timestamp()-interval '1 second',
                created_at=clock_timestamp()-interval '5 minutes'
          WHERE intent_id=$1",
    )
    .bind(intent_id)
    .execute(&mut *setup)
    .await
    .expect("expire attached receipts");
    sqlx::query("SET session_replication_role=origin")
        .execute(&mut *setup)
        .await
        .expect("restore authority triggers after receipt expiry fixture");
}

async fn prove_provider_slot(
    fixture: &Fixture,
    current: IdentityMutationRecord,
    slot_id: Uuid,
    handle: u8,
    browser: u8,
    csrf: u8,
    seed: u8,
    subject: &str,
    candidate_evidence: Option<CandidateEvidenceMaterial>,
) -> IdentityMutationRecord {
    fixture
        .repository
        .start_provider(
            current.id,
            slot_id,
            &digest(handle),
            &digest(browser),
            &digest(csrf),
            current.revision,
            digest(seed),
            digest(seed.wrapping_add(1)),
            Some(protected(seed.wrapping_add(2), 17)),
            protected(seed.wrapping_add(3), 41),
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .expect("start provider proof");
    let project_public_id: String =
        sqlx::query_scalar("SELECT public_id FROM projects WHERE id=$1")
            .bind(fixture.project_id)
            .fetch_one(&fixture.sqlx)
            .await
            .expect("project public id");
    let claimed = fixture
        .repository
        .claim_provider_callback(
            current.id,
            slot_id,
            &project_public_id,
            "main",
            &digest(seed),
            &digest(browser),
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .expect("claim provider callback");
    let ClaimIdentityMutationProvider::Claimed(claimed) = claimed else {
        panic!("provider callback must be claimed");
    };
    fixture
        .repository
        .complete_provider_callback(PreparedIdentityMutationProviderCompletion {
            claimed,
            proof_slot_id: slot_id,
            observation: ProviderProofObservation {
                issuer: "https://issuer.example".to_owned(),
                subject: subject.to_owned(),
                display_name: None,
                picture_url: None,
            },
            candidate_evidence,
            receipt_id: Uuid::new_v4(),
            receipt_digest: digest(seed.wrapping_add(4)),
            now: OffsetDateTime::UNIX_EPOCH,
        })
        .await
        .expect("complete provider proof")
}

async fn committed_candidate_email_challenge(
    fixture: &Fixture,
    idempotency_key: &str,
    intent_id: Uuid,
    handle: u8,
) -> (IdentityMutationRecord, Uuid, Uuid, i16, VersionedDigest) {
    let mut prepared = prepared_email(fixture, idempotency_key, intent_id);
    prepared.hosted_handle_digest = digest(handle);
    let created = fixture
        .repository
        .create(prepared)
        .await
        .expect("create candidate email mutation");
    let CreateIdentityMutationResult::Created(_) = created else {
        panic!("candidate email mutation must be created");
    };
    let bound = fixture
        .repository
        .bind_browser(
            &digest(handle),
            &digest(24),
            &digest(25),
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .expect("bind candidate email browser");
    let owner_slot = bound
        .slots
        .iter()
        .find(|slot| slot.role == IdentityMutationSlotRole::DestinationOwner)
        .expect("candidate email destination owner")
        .id;
    let candidate_slot = bound
        .slots
        .iter()
        .find(|slot| slot.role == IdentityMutationSlotRole::CandidateIdentity)
        .expect("candidate email slot")
        .id;
    let owner_proved = prove_provider_slot(
        fixture, bound, owner_slot, handle, 24, 25, handle, "existing", None,
    )
    .await;
    let entered = fixture
        .repository
        .begin_email(
            intent_id,
            candidate_slot,
            &digest(handle),
            &digest(24),
            &digest(25),
            owner_proved.revision,
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .expect("begin candidate email");
    let generation = fixture
        .repository
        .prepare_email_generation(
            intent_id,
            candidate_slot,
            &digest(handle),
            &digest(24),
            &digest(25),
            entered.revision,
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .expect("prepare candidate email generation");
    let challenge_id = Uuid::new_v4();
    let outbox_id = Uuid::new_v4();
    let otp = digest(102);
    let committed = fixture
        .repository
        .commit_email_generation(CommitIdentityMutationEmailGeneration {
            project_id: generation.project_id,
            application_id: generation.application_id,
            intent_id,
            proof_slot_id: candidate_slot,
            expected_intent_revision: entered.revision,
            expected_generation: generation.next_generation,
            challenge_id,
            outbox_id,
            canonicalization_version: 1,
            lookup_digest: digest(103),
            address: protected(104, 41),
            otp_digest: Some(otp.clone()),
            magic_digest: None,
            envelope: protected(105, 41),
            body: protected(106, 41),
            message_id: format!("mutation-{outbox_id}"),
            suppress_delivery: false,
            admitted_method: generation.policy,
            issued_at: OffsetDateTime::UNIX_EPOCH,
            otp_expires_at: None,
            magic_expires_at: None,
            expires_at: OffsetDateTime::UNIX_EPOCH,
        })
        .await
        .expect("commit candidate email generation");
    (
        committed,
        candidate_slot,
        challenge_id,
        generation.next_generation,
        otp,
    )
}

async fn committed_login_email_challenge(
    fixture: &Fixture,
    email: &PostgresPasswordlessEmailRepository,
    seed: u8,
) -> (Uuid, Uuid, Uuid) {
    sqlx::query(
        "INSERT INTO application_redirects(project_id,application_id,redirect_uri,redirect_type)
         VALUES ($1,$2,'https://app.example/callback','web') ON CONFLICT DO NOTHING",
    )
    .bind(fixture.project_id)
    .bind(fixture.application_id)
    .execute(&fixture.sqlx)
    .await
    .expect("seed healthy login redirect");
    let admitted = AdmittedEmailMethod {
        policy_revision: 1,
        security_revision: 1,
        assignment_security_revision: 1,
        otp_enabled: true,
        magic_link_enabled: true,
        otp_digits: 6,
        otp_validity_seconds: 600,
        otp_max_attempts: 5,
        resend_after_seconds: 30,
        max_generations: 5,
        magic_validity_seconds: 600,
        signup_enabled: true,
        transferred_magic_link_enabled: false,
        smtp_selection_kind: "deployment_default".to_owned(),
        smtp_configuration_id: None,
        smtp_generation: 1,
        smtp_security_eligibility_revision: 1,
    };
    let authentication = PostgresAuthenticationRepository::new_with_runtime_identity(
        fixture.database.clone(),
        "identity-mutation-test".to_owned(),
        fixture.incarnation,
    );
    let login_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    authentication
        .create_login_transaction(CreateLoginTransaction {
            id: login_id,
            project_id: fixture.project_id,
            application_id: fixture.application_id,
            interaction: digest(seed),
            redirect_uri: "https://app.example/callback".to_owned(),
            application_pkce_challenge: "A".repeat(43),
            application_state: protected(seed.wrapping_add(1), 41),
            presentation_hint: None,
            revisions: LoginRevisionSnapshot {
                project_metadata_revision: 1,
                project_security_revision: 1,
                application_security_revision: 1,
                claims_revision: 1,
                session_revision: 1,
            },
            created_at: now,
            expires_at: now + Duration::minutes(10),
            admitted_providers: Vec::new(),
            admitted_email: Some(admitted),
        })
        .await
        .expect("create healthy login");
    authentication
        .bind_hosted_browser(BindHostedBrowser {
            interaction: digest(seed),
            expected_transaction_revision: 1,
            browser_binding: digest(seed.wrapping_add(2)),
            csrf: digest(seed.wrapping_add(3)),
            now,
        })
        .await
        .expect("bind healthy login");
    email
        .select_email_method(SelectEmailMethod {
            project_id: fixture.project_id,
            transaction_id: login_id,
            expected_transaction_revision: 2,
            browser_binding: digest(seed.wrapping_add(2)),
            csrf: digest(seed.wrapping_add(3)),
            now,
        })
        .await
        .expect("select healthy login email");
    let preparation = email
        .prepare_email_generation(
            fixture.project_id,
            login_id,
            3,
            &digest(seed.wrapping_add(2)),
            &digest(seed.wrapping_add(3)),
            now,
        )
        .await
        .expect("prepare healthy login email");
    let challenge_id = Uuid::new_v4();
    let outbox_id = Uuid::new_v4();
    email
        .commit_email_generation(CommitEmailGeneration {
            project_id: fixture.project_id,
            application_id: fixture.application_id,
            transaction_id: login_id,
            expected_transaction_revision: 3,
            expected_generation: preparation.next_generation,
            challenge_id,
            outbox_id,
            canonicalization_version: 1,
            lookup_digest: digest(seed.wrapping_add(4)),
            address: protected(seed.wrapping_add(5), 41),
            otp_digest: Some(digest(seed.wrapping_add(6))),
            magic_digest: None,
            envelope: protected(seed.wrapping_add(7), 41),
            body: protected(seed.wrapping_add(8), 41),
            message_id: format!("healthy-login-{outbox_id}"),
            suppress_delivery: false,
            issued_at: now,
            otp_expires_at: Some(now + Duration::minutes(5)),
            magic_expires_at: None,
            expires_at: now + Duration::minutes(5),
        })
        .await
        .expect("commit healthy login email");
    (login_id, challenge_id, outbox_id)
}

#[tokio::test]
async fn google_identity_proof_is_named_authority_and_ignores_custom_oidc_policy_revision() {
    let Some(fixture) = google_fixture().await else {
        return;
    };
    let subject: String = sqlx::query_scalar("SELECT subject FROM linked_identities WHERE id=$1")
        .bind(fixture.identity_id)
        .fetch_one(&fixture.sqlx)
        .await
        .expect("read seeded Google subject");
    let intent_id = Uuid::new_v4();
    let handle = 81;
    let created = fixture
        .repository
        .create(prepared_unlink(
            &fixture,
            fixture.identity_id,
            "google-proof-authority",
            intent_id,
            handle,
        ))
        .await
        .expect("create Google identity mutation");
    let CreateIdentityMutationResult::Created(created) = created else {
        panic!("Google identity mutation must be created");
    };
    let slot_id = created.slots[0].id;
    let snapshot: (String, Option<i64>) = sqlx::query_as(
        "SELECT provider_adapter_key,provider_egress_policy_revision
           FROM identity_mutation_proof_slots WHERE intent_id=$1 AND id=$2",
    )
    .bind(intent_id)
    .bind(slot_id)
    .fetch_one(&fixture.sqlx)
    .await
    .expect("read Google proof snapshot");
    assert_eq!(snapshot, ("google_oidc_profile_v1".to_owned(), None));

    let bound = fixture
        .repository
        .bind_browser(
            &digest(handle),
            &digest(82),
            &digest(83),
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .expect("bind Google proof browser");
    fixture
        .repository
        .start_provider(
            intent_id,
            slot_id,
            &digest(handle),
            &digest(82),
            &digest(83),
            bound.revision,
            digest(84),
            digest(85),
            Some(protected(86, 17)),
            protected(87, 41),
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .expect("start Google identity proof");
    sqlx::query("DELETE FROM project_provider_egress_policies WHERE project_id=$1")
        .bind(fixture.project_id)
        .execute(&fixture.sqlx)
        .await
        .expect("remove unrelated Custom OIDC policy inventory");
    let project_public_id: String =
        sqlx::query_scalar("SELECT public_id FROM projects WHERE id=$1")
            .bind(fixture.project_id)
            .fetch_one(&fixture.sqlx)
            .await
            .expect("read Project public ID");
    let claimed = fixture
        .repository
        .claim_provider_callback(
            intent_id,
            slot_id,
            &project_public_id,
            "google-main",
            &digest(84),
            &digest(82),
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .expect("claim Google callback after unrelated policy change");
    let ClaimIdentityMutationProvider::Claimed(claimed) = claimed else {
        panic!("Google callback must have one authoritative claim");
    };
    let claimed_authority = claimed
        .slots
        .iter()
        .find(|slot| slot.id == slot_id)
        .expect("claimed Google slot")
        .provider
        .as_ref()
        .expect("claimed Google authority");
    assert_eq!(
        claimed_authority.provider_kind,
        crate::domain::ProviderKind::Google
    );
    assert!(claimed_authority.provider_egress_policy_revision.is_none());
    let completed = fixture
        .repository
        .complete_provider_callback(PreparedIdentityMutationProviderCompletion {
            claimed,
            proof_slot_id: slot_id,
            observation: ProviderProofObservation {
                issuer: crate::domain::GOOGLE_ISSUER.to_owned(),
                subject,
                display_name: None,
                picture_url: None,
            },
            candidate_evidence: None,
            receipt_id: Uuid::new_v4(),
            receipt_digest: digest(88),
            now: OffsetDateTime::UNIX_EPOCH,
        })
        .await
        .expect("commit guarded Google proof evidence");
    assert_eq!(
        completed.slots[0].state,
        crate::domain::IdentityMutationSlotState::Proved
    );
}

#[tokio::test]
async fn create_replay_and_provider_callback_claim_have_single_authoritative_winner() {
    let Some(fixture) = fixture().await else {
        return;
    };
    let intent_id = Uuid::new_v4();
    let created = fixture
        .repository
        .create(prepared(&fixture, "create-race", intent_id))
        .await
        .expect("create identity mutation");
    let CreateIdentityMutationResult::Created(created) = created else {
        panic!("first create must create");
    };
    assert_eq!(created.slots.len(), 2);
    assert!(created.expires_at > OffsetDateTime::now_utc());

    let replay = fixture
        .repository
        .create(prepared(&fixture, "create-race", Uuid::new_v4()))
        .await
        .expect("replay identity mutation");
    let CreateIdentityMutationResult::Replayed {
        intent: replayed,
        protected_create_result,
    } = replay
    else {
        panic!("second create must replay");
    };
    assert_eq!(replayed.id, intent_id);
    assert!(protected_create_result.is_some());

    let bound = fixture
        .repository
        .bind_browser(
            &digest(1),
            &digest(4),
            &digest(5),
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .expect("bind Hosted browser");
    let owner_slot_id = bound
        .slots
        .iter()
        .find(|slot| slot.role == IdentityMutationSlotRole::DestinationOwner)
        .expect("destination-owner slot")
        .id;
    let started = fixture
        .repository
        .start_provider(
            intent_id,
            owner_slot_id,
            &digest(1),
            &digest(4),
            &digest(5),
            bound.revision,
            digest(6),
            digest(7),
            Some(protected(8, 17)),
            protected(9, 41),
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .expect("start provider proof");
    assert!(started.revision > bound.revision);
    let first = fixture.repository.clone();
    let second = fixture.repository.clone();
    let project_public_id: String =
        sqlx::query_scalar("SELECT public_id FROM projects WHERE id=$1")
            .bind(fixture.project_id)
            .fetch_one(&fixture.sqlx)
            .await
            .expect("Project public ID");
    let claim_a = tokio::spawn(async move {
        first
            .claim_provider_callback(
                intent_id,
                owner_slot_id,
                &project_public_id,
                "main",
                &digest(6),
                &digest(4),
                OffsetDateTime::UNIX_EPOCH,
            )
            .await
    });
    let project_public_id: String =
        sqlx::query_scalar("SELECT public_id FROM projects WHERE id=$1")
            .bind(fixture.project_id)
            .fetch_one(&fixture.sqlx)
            .await
            .expect("Project public ID");
    let claim_b = tokio::spawn(async move {
        second
            .claim_provider_callback(
                intent_id,
                owner_slot_id,
                &project_public_id,
                "main",
                &digest(6),
                &digest(4),
                OffsetDateTime::UNIX_EPOCH,
            )
            .await
    });
    let results = [
        claim_a.await.expect("claim task A").expect("claim A"),
        claim_b.await.expect("claim task B").expect("claim B"),
    ];
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, ClaimIdentityMutationProvider::Claimed(_)))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, ClaimIdentityMutationProvider::Duplicate(_)))
            .count(),
        1
    );
    let callback_owner_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM provider_callback_owners
          WHERE owner_kind='identity_mutation' AND state_id=$1",
    )
    .bind(owner_slot_id)
    .fetch_one(&fixture.sqlx)
    .await
    .expect("callback owner count");
    assert_eq!(callback_owner_count, 1);
}

#[tokio::test]
async fn cancellation_uses_database_clock_erases_terminal_result_and_has_exact_revision_cas() {
    let Some(fixture) = fixture().await else {
        return;
    };

    let expired_id = Uuid::new_v4();
    let expired = fixture
        .repository
        .create(prepared(&fixture, "expired-cancel", expired_id))
        .await
        .expect("create expiring mutation");
    let CreateIdentityMutationResult::Created(expired) = expired else {
        panic!("first mutation must be created");
    };
    // Frozen authority is immutable in production. This test-only superuser session constructs an
    // already-expired snapshot without weakening or dropping the production trigger.
    let mut setup = fixture.sqlx.acquire().await.expect("acquire expiry setup");
    sqlx::query("SET session_replication_role=replica")
        .execute(&mut *setup)
        .await
        .expect("disable triggers for test fixture setup");
    sqlx::query(
        "UPDATE identity_mutation_intents
            SET created_at=clock_timestamp()-interval '2 seconds',
                updated_at=clock_timestamp()-interval '2 seconds',
                expires_at=clock_timestamp()-interval '1 second'
          WHERE id=$1",
    )
    .bind(expired_id)
    .execute(&mut *setup)
    .await
    .expect("construct expired mutation snapshot");
    sqlx::query(
        "UPDATE identity_mutation_create_results result
            SET expires_at=intent.expires_at
           FROM identity_mutation_intents intent
          WHERE result.intent_id=intent.id AND intent.id=$1",
    )
    .bind(expired_id)
    .execute(&mut *setup)
    .await
    .expect("align terminal create-result deadline");
    sqlx::query("SET session_replication_role=origin")
        .execute(&mut *setup)
        .await
        .expect("restore production triggers");
    drop(setup);

    // The deliberately stale caller time and revision cannot authorize cancellation. The database
    // clock owns expiry, so the aggregate is expired and terminal material is erased instead.
    let terminal = fixture
        .repository
        .cancel(
            fixture.project_id,
            expired_id,
            expired.revision + 999,
            Uuid::new_v4(),
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .expect("database-clock terminalization");
    assert_eq!(terminal.status, IdentityMutationStatus::Expired);
    let erased: (Option<Vec<u8>>, Option<OffsetDateTime>) = sqlx::query_as(
        "SELECT create_result_ciphertext,erased_at
           FROM identity_mutation_create_results WHERE intent_id=$1",
    )
    .bind(expired_id)
    .fetch_one(&fixture.sqlx)
    .await
    .expect("read erased result");
    assert!(erased.0.is_none());
    assert!(erased.1.is_some());
}

#[tokio::test]
async fn expired_receipt_is_effective_deadline_and_terminalizes_live_intent() {
    let Some(fixture) = fixture().await else {
        return;
    };
    let intent_id = Uuid::new_v4();
    let created = fixture
        .repository
        .create(prepared_unlink(
            &fixture,
            fixture.identity_id,
            "receipt-deadline",
            intent_id,
            91,
        ))
        .await
        .expect("create receipt-deadline mutation");
    let CreateIdentityMutationResult::Created(_) = created else {
        panic!("receipt-deadline mutation must be created");
    };
    let bound = fixture
        .repository
        .bind_browser(
            &digest(91),
            &digest(92),
            &digest(93),
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .expect("bind receipt-deadline browser");
    let slot_id = bound.slots[0].id;
    prove_provider_slot(&fixture, bound, slot_id, 91, 92, 93, 94, "existing", None).await;

    // Build a trigger-valid snapshot where the five-minute receipt has elapsed while the
    // ten-minute intent remains live. Production authority triggers are restored before reads.
    let mut setup = fixture
        .sqlx
        .acquire()
        .await
        .expect("acquire deadline setup");
    sqlx::query("SET session_replication_role=replica")
        .execute(&mut *setup)
        .await
        .expect("disable triggers for deadline fixture");
    sqlx::query(
        "UPDATE identity_mutation_intents
            SET created_at=created_at-interval '6 minutes',
                updated_at=updated_at-interval '6 minutes',
                expires_at=expires_at-interval '6 minutes'
          WHERE id=$1",
    )
    .bind(intent_id)
    .execute(&mut *setup)
    .await
    .expect("shift live intent window");
    sqlx::query(
        "UPDATE identity_mutation_create_results result SET expires_at=intent.expires_at
           FROM identity_mutation_intents intent
          WHERE result.intent_id=intent.id AND intent.id=$1",
    )
    .bind(intent_id)
    .execute(&mut *setup)
    .await
    .expect("align create result window");
    sqlx::query(
        "UPDATE identity_mutation_proof_slots
            SET created_at=created_at-interval '6 minutes',
                updated_at=updated_at-interval '6 minutes',
                provider_started_at=provider_started_at-interval '6 minutes',
                proved_at=proved_at-interval '6 minutes'
          WHERE intent_id=$1",
    )
    .bind(intent_id)
    .execute(&mut *setup)
    .await
    .expect("align proved slot window");
    sqlx::query(
        "UPDATE identity_proof_receipts
            SET issued_at=issued_at-interval '6 minutes',
                created_at=created_at-interval '6 minutes',
                expires_at=expires_at-interval '6 minutes'
          WHERE intent_id=$1",
    )
    .bind(intent_id)
    .execute(&mut *setup)
    .await
    .expect("expire attached receipt");
    sqlx::query("SET session_replication_role=origin")
        .execute(&mut *setup)
        .await
        .expect("restore deadline authority triggers");
    drop(setup);

    assert!(matches!(
        fixture
            .repository
            .hosted_read(&digest(91), &digest(92), OffsetDateTime::UNIX_EPOCH)
            .await,
        Err(ApplicationError::NotFound)
    ));
    let record = fixture
        .repository
        .control_read(fixture.project_id, intent_id, OffsetDateTime::UNIX_EPOCH)
        .await
        .expect("read terminalized receipt deadline");
    assert_eq!(record.status, IdentityMutationStatus::Expired);
    assert!(record.expires_at < OffsetDateTime::now_utc());
    let erased: (Option<Vec<u8>>, Option<OffsetDateTime>) = sqlx::query_as(
        "SELECT create_result_ciphertext,erased_at
           FROM identity_mutation_create_results WHERE intent_id=$1",
    )
    .bind(intent_id)
    .fetch_one(&fixture.sqlx)
    .await
    .expect("read receipt-deadline erasure");
    assert!(erased.0.is_none());
    assert!(erased.1.is_some());
}

#[tokio::test]
async fn provider_entry_terminalizes_earliest_receipt_deadline_before_partial_start() {
    let Some(fixture) = fixture().await else {
        return;
    };
    let intent_id = Uuid::new_v4();
    let created = fixture
        .repository
        .create(prepared(&fixture, "provider-effective-deadline", intent_id))
        .await
        .expect("create provider deadline mutation");
    let CreateIdentityMutationResult::Created(_) = created else {
        panic!("provider deadline mutation must be created");
    };
    let bound = fixture
        .repository
        .bind_browser(
            &digest(1),
            &digest(51),
            &digest(52),
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .expect("bind provider deadline browser");
    let owner_slot = bound
        .slots
        .iter()
        .find(|slot| slot.role == IdentityMutationSlotRole::DestinationOwner)
        .expect("provider deadline owner slot")
        .id;
    let candidate_slot = bound
        .slots
        .iter()
        .find(|slot| slot.role == IdentityMutationSlotRole::CandidateIdentity)
        .expect("provider deadline candidate slot")
        .id;
    let owner_proved = prove_provider_slot(
        &fixture, bound, owner_slot, 1, 51, 52, 111, "existing", None,
    )
    .await;
    expire_attached_receipts_with_database_clock(&fixture, intent_id).await;
    assert!(matches!(
        fixture
            .repository
            .start_provider(
                intent_id,
                candidate_slot,
                &digest(1),
                &digest(51),
                &digest(52),
                owner_proved.revision,
                digest(112),
                digest(113),
                Some(protected(114, 17)),
                protected(115, 41),
                OffsetDateTime::UNIX_EPOCH + Duration::days(365),
            )
            .await,
        Err(ApplicationError::InvalidTransition)
    ));
    let terminal: (String, String, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT intent.status,slot.state,result.create_result_ciphertext
           FROM identity_mutation_intents intent
           JOIN identity_mutation_proof_slots slot ON slot.intent_id=intent.id AND slot.id=$2
           JOIN identity_mutation_create_results result ON result.intent_id=intent.id
          WHERE intent.id=$1",
    )
    .bind(intent_id)
    .bind(candidate_slot)
    .fetch_one(&fixture.sqlx)
    .await
    .expect("read provider deadline terminal state");
    assert_eq!(terminal, ("expired".to_owned(), "expired".to_owned(), None));
}

#[tokio::test]
async fn final_wrong_mutation_otp_atomically_terminalizes_owner_and_erases_material() {
    let Some(fixture) = fixture().await else {
        return;
    };
    let intent_id = Uuid::new_v4();
    let (committed, slot_id, challenge_id, generation, _otp) =
        committed_candidate_email_challenge(&fixture, "otp-exhaustion", intent_id, 121).await;
    sqlx::query("UPDATE email_challenges SET otp_attempts=otp_max_attempts-1 WHERE id=$1")
        .bind(challenge_id)
        .execute(&fixture.sqlx)
        .await
        .expect("put mutation OTP at final attempt");

    let decision = fixture
        .repository
        .verify_email_proof(VerifyIdentityMutationEmailProof {
            project_id: fixture.project_id,
            intent_id,
            proof_slot_id: slot_id,
            challenge_id,
            generation,
            proof_kind: EmailProofKind::Otp,
            proof_digest: digest(199),
            browser_binding: Some(digest(24)),
            csrf: digest(25),
            transfer_context: None,
            expected_intent_revision: committed.revision,
            now: OffsetDateTime::UNIX_EPOCH + Duration::days(365),
        })
        .await
        .expect("final wrong OTP must commit aggregate terminalization");
    assert!(matches!(
        decision,
        crate::application::IdentityMutationEmailProofDecision::Invalid
    ));
    let challenge: (String, i16, i16) = sqlx::query_as(
        "SELECT status,otp_attempts,otp_max_attempts FROM email_challenges WHERE id=$1",
    )
    .bind(challenge_id)
    .fetch_one(&fixture.sqlx)
    .await
    .expect("read exhausted typed challenge");
    assert_eq!(challenge.0, "exhausted");
    assert_eq!(challenge.1, challenge.2);
    let aggregate: (String, Option<Vec<u8>>, i64) = sqlx::query_as(
        "SELECT intent.status,result.create_result_ciphertext,
                (SELECT COUNT(*) FROM identity_mutation_proof_slots slot
                  WHERE slot.intent_id=intent.id AND slot.state='expired')
           FROM identity_mutation_intents intent
           JOIN identity_mutation_create_results result ON result.intent_id=intent.id
          WHERE intent.id=$1",
    )
    .bind(intent_id)
    .fetch_one(&fixture.sqlx)
    .await
    .expect("read terminal mutation owner");
    assert_eq!(aggregate, ("cancelled".to_owned(), None, 2));
}

#[tokio::test]
async fn effective_receipt_deadline_terminalizes_email_lookup_and_mail_claim_with_db_clock() {
    let Some(fixture) = fixture().await else {
        return;
    };

    let lookup_intent = Uuid::new_v4();
    let (_record, lookup_slot, lookup_challenge, _generation, _otp) =
        committed_candidate_email_challenge(
            &fixture,
            "email-effective-deadline",
            lookup_intent,
            122,
        )
        .await;
    expire_attached_receipts_with_database_clock(&fixture, lookup_intent).await;
    let key = fixture
        .repository
        .email_proof_key_version(IdentityMutationEmailProofKey {
            project_id: fixture.project_id,
            intent_id: lookup_intent,
            proof_slot_id: lookup_slot,
            challenge_id: lookup_challenge,
            proof_kind: EmailProofKind::Otp,
        })
        .await
        .expect("expired effective deadline returns no proof key");
    assert_eq!(key, None);
    let lookup_terminal: (String, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT intent.status,result.create_result_ciphertext
           FROM identity_mutation_intents intent
           JOIN identity_mutation_create_results result ON result.intent_id=intent.id
          WHERE intent.id=$1",
    )
    .bind(lookup_intent)
    .fetch_one(&fixture.sqlx)
    .await
    .expect("read email-lookup terminal aggregate");
    assert_eq!(lookup_terminal, ("expired".to_owned(), None));

    let mail_intent = Uuid::new_v4();
    let _ =
        committed_candidate_email_challenge(&fixture, "mail-effective-deadline", mail_intent, 123)
            .await;
    expire_attached_receipts_with_database_clock(&fixture, mail_intent).await;
    let email = PostgresPasswordlessEmailRepository::new_with_runtime_identity(
        fixture.database.clone(),
        "identity-mutation-test".to_owned(),
        fixture.incarnation,
        Vec::new(),
        Duration::minutes(5),
    );
    assert!(
        email
            .claim_due_mail(
                "effective-deadline-worker",
                OffsetDateTime::UNIX_EPOCH,
                OffsetDateTime::UNIX_EPOCH + Duration::seconds(30),
            )
            .await
            .expect("mail claim uses PostgreSQL effective deadline")
            .is_none()
    );
    let mail_terminal: (String, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT intent.status,result.create_result_ciphertext
           FROM identity_mutation_intents intent
           JOIN identity_mutation_create_results result ON result.intent_id=intent.id
          WHERE intent.id=$1",
    )
    .bind(mail_intent)
    .fetch_one(&fixture.sqlx)
    .await
    .expect("read mail terminal aggregate");
    assert_eq!(mail_terminal, ("expired".to_owned(), None));
}

#[tokio::test]
async fn generic_mail_maintenance_terminalizes_mutation_owner_without_partial_child_state() {
    let Some(fixture) = fixture().await else {
        return;
    };
    let intent_id = Uuid::new_v4();
    let (_record, _slot, challenge_id, _generation, _otp) =
        committed_candidate_email_challenge(&fixture, "mail-maintenance-owner", intent_id, 124)
            .await;
    let mut setup = fixture
        .sqlx
        .acquire()
        .await
        .expect("acquire maintenance setup");
    sqlx::query("SET session_replication_role=replica")
        .execute(&mut *setup)
        .await
        .expect("disable triggers for expired challenge fixture");
    sqlx::query(
        "UPDATE email_challenges
            SET otp_expires_at=issued_at+interval '1 millisecond',
                expires_at=issued_at+interval '1 millisecond'
          WHERE id=$1",
    )
    .bind(challenge_id)
    .execute(&mut *setup)
    .await
    .expect("expire mutation challenge by database clock");
    sqlx::query("SET session_replication_role=origin")
        .execute(&mut *setup)
        .await
        .expect("restore triggers after expired challenge fixture");
    drop(setup);
    let email = PostgresPasswordlessEmailRepository::new_with_runtime_identity(
        fixture.database.clone(),
        "identity-mutation-test".to_owned(),
        fixture.incarnation,
        Vec::new(),
        Duration::minutes(5),
    );
    let maintained = email
        .maintain_short_term_data(OffsetDateTime::UNIX_EPOCH, 100)
        .await
        .expect("maintenance synchronizes typed mutation owner");
    assert!(maintained >= 1);
    let state: (String, String, String, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT intent.status,slot.state,challenge.status,result.create_result_ciphertext
           FROM identity_mutation_intents intent
           JOIN identity_mutation_proof_slots slot ON slot.intent_id=intent.id
             AND slot.id=(SELECT identity_mutation_proof_slot_id FROM email_challenges WHERE id=$2)
           JOIN email_challenges challenge ON challenge.id=$2
           JOIN identity_mutation_create_results result ON result.intent_id=intent.id
          WHERE intent.id=$1",
    )
    .bind(intent_id)
    .bind(challenge_id)
    .fetch_one(&fixture.sqlx)
    .await
    .expect("read atomic maintenance terminal state");
    assert_eq!(
        state,
        (
            "expired".to_owned(),
            "expired".to_owned(),
            "expired".to_owned(),
            None,
        )
    );
}

#[tokio::test]
async fn mutation_mail_final_outbox_wait_rechecks_receipt_effective_deadline_atomically() {
    let Some(fixture) = fixture().await else {
        return;
    };
    let intent_id = Uuid::new_v4();
    let (_record, _slot, challenge_id, _generation, _otp) = committed_candidate_email_challenge(
        &fixture,
        "mail-final-receipt-deadline",
        intent_id,
        126,
    )
    .await;
    let outbox_id: Uuid = sqlx::query_scalar("SELECT id FROM mail_outbox WHERE challenge_id=$1")
        .bind(challenge_id)
        .fetch_one(&fixture.sqlx)
        .await
        .expect("read receipt-deadline mutation outbox");

    // Keep the outbox useful, but let an attached receipt become the earlier aggregate deadline
    // while claim is provably waiting on the final outbox FOR UPDATE.
    let mut deadline_setup = fixture
        .sqlx
        .acquire()
        .await
        .expect("acquire receipt-deadline setup");
    sqlx::query("SET session_replication_role=replica")
        .execute(&mut *deadline_setup)
        .await
        .expect("disable immutable receipt trigger for elapsed-time fixture");
    sqlx::query(
        "UPDATE identity_proof_receipts
            SET expires_at=clock_timestamp()+interval '5 seconds'
          WHERE intent_id=$1",
    )
    .bind(intent_id)
    .execute(&mut *deadline_setup)
    .await
    .expect("shorten attached receipt effective deadline");
    sqlx::query("SET session_replication_role=origin")
        .execute(&mut *deadline_setup)
        .await
        .expect("restore receipt authority triggers");
    drop(deadline_setup);
    let mut blocker = fixture
        .sqlx
        .begin()
        .await
        .expect("begin receipt-deadline blocker");
    sqlx::query(
        "UPDATE mail_outbox
            SET next_attempt_at=clock_timestamp()-interval '1 second',
                useful_until=clock_timestamp()+interval '5 minutes'
          WHERE id=$1",
    )
    .bind(outbox_id)
    .execute(&mut *blocker)
    .await
    .expect("hold final outbox while receipt expires");
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await
        .expect("read receipt-deadline blocker backend");
    let email = PostgresPasswordlessEmailRepository::new_with_runtime_identity(
        fixture.database.clone(),
        "identity-mutation-test".to_owned(),
        fixture.incarnation,
        Vec::new(),
        Duration::minutes(5),
    );
    let claiming = tokio::spawn(async move {
        email
            .claim_due_mail(
                "receipt-deadline-worker",
                OffsetDateTime::UNIX_EPOCH,
                OffsetDateTime::UNIX_EPOCH + Duration::seconds(30),
            )
            .await
    });
    wait_for_backend_blocked_by(
        &fixture.sqlx,
        blocker_pid,
        "mutation claim at final outbox lock",
    )
    .await;
    let (receipt_deadline, database_now): (OffsetDateTime, OffsetDateTime) = sqlx::query_as(
        "SELECT MIN(expires_at),clock_timestamp()
           FROM identity_proof_receipts WHERE intent_id=$1",
    )
    .bind(intent_id)
    .fetch_one(&fixture.sqlx)
    .await
    .expect("read remaining receipt deadline from PostgreSQL clock");
    let remaining_millis = (receipt_deadline - database_now)
        .whole_milliseconds()
        .max(0);
    tokio::time::sleep(std::time::Duration::from_millis(
        u64::try_from(remaining_millis)
            .expect("bounded receipt deadline")
            .saturating_add(250),
    ))
    .await;
    blocker
        .commit()
        .await
        .expect("release outbox after receipt effective deadline");
    assert!(
        claiming
            .await
            .expect("join receipt-deadline claim")
            .expect("receipt-deadline miss is not infrastructure failure")
            .is_none()
    );
    let terminal: (String, Option<Vec<u8>>, String, i16, Option<String>) = sqlx::query_as(
        "SELECT intent.status,result.create_result_ciphertext,outbox.status,outbox.attempts,
                outbox.lease_owner
           FROM identity_mutation_intents intent
           JOIN identity_mutation_create_results result ON result.intent_id=intent.id
           JOIN email_challenges challenge
             ON challenge.identity_mutation_intent_id=intent.id
           JOIN mail_outbox outbox ON outbox.challenge_id=challenge.id
          WHERE intent.id=$1",
    )
    .bind(intent_id)
    .fetch_one(&fixture.sqlx)
    .await
    .expect("read atomically expired mutation aggregate");
    assert_eq!(
        terminal,
        ("expired".to_owned(), None, "cancelled".to_owned(), 0, None)
    );
}

#[tokio::test]
async fn concurrent_cancel_has_one_exact_revision_winner() {
    let Some(fixture) = fixture().await else {
        return;
    };
    let raced_id = Uuid::new_v4();
    let raced = fixture
        .repository
        .create(prepared(&fixture, "cancel-race", raced_id))
        .await
        .expect("create cancellation race");
    let CreateIdentityMutationResult::Created(raced) = raced else {
        panic!("mutation must be created");
    };
    let revision = raced.revision;
    let project_id = fixture.project_id;
    let first = fixture.repository.clone();
    let second = fixture.repository.clone();
    let a = tokio::spawn(async move {
        first
            .cancel(
                project_id,
                raced_id,
                revision,
                Uuid::new_v4(),
                OffsetDateTime::UNIX_EPOCH,
            )
            .await
    });
    let b = tokio::spawn(async move {
        second
            .cancel(
                project_id,
                raced_id,
                revision,
                Uuid::new_v4(),
                OffsetDateTime::UNIX_EPOCH,
            )
            .await
    });
    let outcomes = [
        a.await.expect("cancel task A"),
        b.await.expect("cancel task B"),
    ];
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| result
                .as_ref()
                .is_ok_and(|record| record.status == IdentityMutationStatus::Cancelled))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| matches!(result, Err(ApplicationError::RevisionConflict)))
            .count(),
        1
    );
    let terminal_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM identity_mutation_intents
          WHERE id=$1 AND status='cancelled' AND intent_revision=$2",
    )
    .bind(raced_id)
    .bind(revision + 1)
    .fetch_one(&fixture.sqlx)
    .await
    .expect("read cancellation winner");
    assert_eq!(terminal_rows, 1);
}

#[tokio::test]
async fn final_link_consumes_both_receipts_and_creates_exact_provider_namespace_once() {
    let Some(fixture) = fixture().await else {
        return;
    };
    let intent_id = Uuid::new_v4();
    let created = fixture
        .repository
        .create(prepared(&fixture, "final-link", intent_id))
        .await
        .expect("create final link");
    let CreateIdentityMutationResult::Created(_) = created else {
        panic!("link must be created");
    };
    let bound = fixture
        .repository
        .bind_browser(
            &digest(1),
            &digest(51),
            &digest(52),
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .expect("bind link browser");
    let owner_slot = bound
        .slots
        .iter()
        .find(|slot| slot.role == IdentityMutationSlotRole::DestinationOwner)
        .expect("destination owner slot")
        .id;
    let candidate_slot = bound
        .slots
        .iter()
        .find(|slot| slot.role == IdentityMutationSlotRole::CandidateIdentity)
        .expect("candidate slot")
        .id;
    let owner_proved =
        prove_provider_slot(&fixture, bound, owner_slot, 1, 51, 52, 53, "existing", None).await;
    let context = IdentityMutationCandidateEvidenceContext {
        project_id: fixture.project_id,
        intent_id,
        proof_slot_id: candidate_slot,
        evidence_id: Uuid::new_v4(),
        evidence_revision: 1,
        candidate_kind: IdentityMutationCandidateKind::Provider,
    };
    let material = CandidateEvidenceMaterial {
        context: context.clone(),
        ciphertext: protected(60, 41),
        digest: digest(61),
    };
    let candidate_proved = prove_provider_slot(
        &fixture,
        owner_proved,
        candidate_slot,
        1,
        51,
        52,
        62,
        "new-subject",
        Some(material),
    )
    .await;
    let ready = fixture
        .repository
        .confirm_ready(
            intent_id,
            &digest(1),
            &digest(51),
            &digest(52),
            candidate_proved.revision,
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .expect("mark link ready");
    let preparation = fixture
        .repository
        .prepare_control_confirmation(
            fixture.project_id,
            intent_id,
            ready.revision,
            IdentityMutationKind::Link,
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .expect("prepare link confirmation");
    let envelope = preparation
        .candidate_evidence
        .expect("link candidate evidence");
    assert_eq!(envelope.context, context);
    let confirmation = PreparedIdentityMutationConfirmation {
        project_id: fixture.project_id,
        intent_id,
        expected_intent_revision: ready.revision,
        expected_kind: IdentityMutationKind::Link,
        candidate: Some(PreparedIdentityMutationCandidate {
            context,
            evidence_digest: digest(61),
            candidate: IdentityMutationCandidate::Provider(IdentityMutationProviderCandidate {
                issuer: "https://issuer.example".to_owned(),
                subject: "new-subject".to_owned(),
                admitted_profile: IdentityMutationAdmittedProviderProfile {
                    display_name: Some("New Identity".to_owned()),
                    picture_url: None,
                },
                registration: IdentityMutationProviderRegistrationEvidence {
                    provider_configuration_id: fixture.provider_id,
                    provider_configuration_revision: 1,
                    adapter_key: "controlled_oidc_profile_v1".to_owned(),
                    adapter_capability_revision: 1,
                    issuer: "https://issuer.example".to_owned(),
                },
            }),
        }),
        correlation_id: Uuid::new_v4(),
        now: OffsetDateTime::UNIX_EPOCH,
    };

    // A provider login completion owns graph -> provider namespace. Hold its graph lock, start the
    // real Link confirmation, then take the namespace in that same production order. If Link ever
    // regresses to namespace -> graph this forms the former deadlock cycle (or 40P01); graph-first
    // Link instead waits without owning the namespace and completes after this transaction.
    let mut login_completion = fixture
        .sqlx
        .begin()
        .await
        .expect("begin provider login path");
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended(
             'owlauth-project-identity-graph:' || $1::TEXT,0))",
    )
    .bind(fixture.project_id)
    .execute(&mut *login_completion)
    .await
    .expect("provider login holds graph");
    let confirming_repository = fixture.repository.clone();
    let confirming =
        tokio::spawn(async move { confirming_repository.confirm_control(confirmation).await });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!(
                "{}\u{1f}https://issuer.example\u{1f}new-subject",
                fixture.project_id
            ))
            .execute(&mut *login_completion),
    )
    .await
    .expect("Link must not hold provider namespace while waiting for graph")
    .expect("provider login takes namespace without 40P01");
    login_completion
        .commit()
        .await
        .expect("release provider login graph and namespace");
    let completed = confirming
        .await
        .expect("join graph-first Link confirmation")
        .expect("confirm link after provider login path");
    assert_eq!(completed.status, IdentityMutationStatus::Completed);
    let linked: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM linked_identities
          WHERE project_id=$1 AND user_id=$2 AND issuer='https://issuer.example'
            AND subject='new-subject' AND status='active'",
    )
    .bind(fixture.project_id)
    .bind(fixture.user_id)
    .fetch_one(&fixture.sqlx)
    .await
    .expect("read linked namespace");
    assert_eq!(linked, 1);
    let unconsumed: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM identity_proof_receipts
          WHERE intent_id=$1 AND consumed_at IS NULL",
    )
    .bind(intent_id)
    .fetch_one(&fixture.sqlx)
    .await
    .expect("read link receipts");
    assert_eq!(unconsumed, 0);
}

#[tokio::test]
async fn email_link_confirmation_waits_for_graph_before_email_namespace() {
    let Some(fixture) = fixture().await else {
        return;
    };
    let intent_id = Uuid::new_v4();
    let created = fixture
        .repository
        .create(prepared_email(&fixture, "email-link-lock-order", intent_id))
        .await
        .expect("create email Link");
    let CreateIdentityMutationResult::Created(_) = created else {
        panic!("email Link must be created");
    };
    let bound = fixture
        .repository
        .bind_browser(
            &digest(21),
            &digest(24),
            &digest(25),
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .expect("bind email Link browser");
    let owner_slot = bound
        .slots
        .iter()
        .find(|slot| slot.role == IdentityMutationSlotRole::DestinationOwner)
        .expect("email Link owner slot")
        .id;
    let candidate_slot = bound
        .slots
        .iter()
        .find(|slot| slot.role == IdentityMutationSlotRole::CandidateIdentity)
        .expect("email Link candidate slot")
        .id;
    let owner_proved = prove_provider_slot(
        &fixture, bound, owner_slot, 21, 24, 25, 80, "existing", None,
    )
    .await;
    let entered = fixture
        .repository
        .begin_email(
            intent_id,
            candidate_slot,
            &digest(21),
            &digest(24),
            &digest(25),
            owner_proved.revision,
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .expect("begin candidate email proof");
    let generation = fixture
        .repository
        .prepare_email_generation(
            intent_id,
            candidate_slot,
            &digest(21),
            &digest(24),
            &digest(25),
            entered.revision,
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .expect("prepare candidate email generation");
    let challenge_id = Uuid::new_v4();
    let outbox_id = Uuid::new_v4();
    let magic_digest = digest(81);
    let lookup_digest = digest(82);
    let committed = fixture
        .repository
        .commit_email_generation(CommitIdentityMutationEmailGeneration {
            project_id: generation.project_id,
            application_id: generation.application_id,
            intent_id,
            proof_slot_id: candidate_slot,
            expected_intent_revision: entered.revision,
            expected_generation: generation.next_generation,
            challenge_id,
            outbox_id,
            canonicalization_version: 1,
            lookup_digest: lookup_digest.clone(),
            address: protected(83, 41),
            otp_digest: None,
            magic_digest: Some(magic_digest.clone()),
            envelope: protected(84, 41),
            body: protected(85, 41),
            message_id: format!("email-link-{outbox_id}"),
            suppress_delivery: false,
            admitted_method: generation.policy,
            issued_at: OffsetDateTime::UNIX_EPOCH,
            otp_expires_at: None,
            magic_expires_at: None,
            expires_at: OffsetDateTime::UNIX_EPOCH,
        })
        .await
        .expect("commit candidate email generation");
    let transfer_context = digest(91);
    let transfer_csrf = digest(92);
    let established = fixture
        .repository
        .establish_magic_transfer_context(EstablishIdentityMutationMagicTransferContext {
            id: Uuid::new_v4(),
            challenge_id,
            context: transfer_context.clone(),
            csrf: transfer_csrf.clone(),
            now: OffsetDateTime::UNIX_EPOCH,
        })
        .await
        .expect("establish mutation-specific transfer gate by challenge only");
    assert_eq!(established.owner.intent_id, intent_id);
    assert_eq!(established.owner.proof_slot_id, candidate_slot);
    assert_eq!(established.expected_intent_revision, committed.revision);
    assert_eq!(
        fixture
            .repository
            .resolve_magic_transfer_context(ResolveIdentityMutationMagicTransferContext {
                challenge_id,
                project_public_id: established.project_public_id.clone(),
                intent: digest(21),
                context: digest(99),
                csrf: transfer_csrf.clone(),
                now: OffsetDateTime::UNIX_EPOCH,
            })
            .await,
        Err(ApplicationError::NotFound),
        "a copied or wrong transfer context cannot resolve challenge authority"
    );
    let resolved = fixture
        .repository
        .resolve_magic_transfer_context(ResolveIdentityMutationMagicTransferContext {
            challenge_id,
            project_public_id: established.project_public_id.clone(),
            intent: digest(21),
            context: transfer_context.clone(),
            csrf: transfer_csrf.clone(),
            now: OffsetDateTime::UNIX_EPOCH,
        })
        .await
        .expect("fresh browser resolves exact opaque-handle transfer authority");
    assert_eq!(resolved.owner, established.owner);
    let verification = VerifyIdentityMutationEmailProof {
        project_id: fixture.project_id,
        intent_id,
        proof_slot_id: candidate_slot,
        challenge_id,
        generation: generation.next_generation,
        proof_kind: EmailProofKind::MagicLink,
        proof_digest: magic_digest,
        browser_binding: None,
        csrf: transfer_csrf.clone(),
        transfer_context: Some(transfer_context.clone()),
        expected_intent_revision: committed.revision,
        now: OffsetDateTime::UNIX_EPOCH,
    };
    sqlx::query(
        "UPDATE magic_transfer_contexts SET browser_binding_required=TRUE
          WHERE challenge_id=$1 AND status='pending'",
    )
    .bind(challenge_id)
    .execute(&fixture.sqlx)
    .await
    .expect("simulate captured transfer-disabled policy");
    assert!(matches!(
        fixture
            .repository
            .verify_email_proof(verification.clone())
            .await,
        Err(ApplicationError::NotFound)
    ));
    let still_pending: (String, String) = sqlx::query_as(
        "SELECT challenge.status,transfer.status
           FROM email_challenges challenge
           JOIN magic_transfer_contexts transfer ON transfer.challenge_id=challenge.id
          WHERE challenge.id=$1",
    )
    .bind(challenge_id)
    .fetch_one(&fixture.sqlx)
    .await
    .expect("read policy-disabled non-consumption");
    assert_eq!(still_pending, ("pending".to_owned(), "pending".to_owned()));
    sqlx::query(
        "UPDATE magic_transfer_contexts SET browser_binding_required=FALSE
          WHERE challenge_id=$1 AND status='pending'",
    )
    .bind(challenge_id)
    .execute(&fixture.sqlx)
    .await
    .expect("restore captured transfer-enabled policy");
    let context = IdentityMutationCandidateEvidenceContext {
        project_id: fixture.project_id,
        intent_id,
        proof_slot_id: candidate_slot,
        evidence_id: Uuid::new_v4(),
        evidence_revision: 1,
        candidate_kind: IdentityMutationCandidateKind::Email,
    };
    let evidence_digest = digest(86);
    let proved = fixture
        .repository
        .complete_email_proof(CompleteIdentityMutationEmailProof {
            verification,
            verified_challenge_lookup: lookup_digest,
            material: IdentityMutationEmailProofMaterial::Candidate(CandidateEvidenceMaterial {
                context: context.clone(),
                ciphertext: protected(87, 41),
                digest: evidence_digest.clone(),
            }),
            receipt_id: Uuid::new_v4(),
            receipt_digest: digest(88),
        })
        .await
        .expect("complete candidate email proof");
    assert_eq!(
        fixture
            .repository
            .resolve_magic_transfer_context(ResolveIdentityMutationMagicTransferContext {
                challenge_id,
                project_public_id: established.project_public_id,
                intent: digest(21),
                context: transfer_context,
                csrf: transfer_csrf,
                now: OffsetDateTime::UNIX_EPOCH,
            })
            .await,
        Err(ApplicationError::NotFound),
        "the transfer context is one-use with the winning magic proof"
    );
    let ready = fixture
        .repository
        .confirm_ready(
            intent_id,
            &digest(21),
            &digest(24),
            &digest(25),
            proved.revision,
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .expect("mark email Link ready");
    let preparation = fixture
        .repository
        .prepare_control_confirmation(
            fixture.project_id,
            intent_id,
            ready.revision,
            IdentityMutationKind::Link,
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .expect("prepare email Link confirmation");
    assert_eq!(
        preparation
            .candidate_evidence
            .expect("prepared email evidence")
            .context,
        context
    );
    let email_identity_id = Uuid::new_v4();
    let alias = digest(89);
    let confirmation = PreparedIdentityMutationConfirmation {
        project_id: fixture.project_id,
        intent_id,
        expected_intent_revision: ready.revision,
        expected_kind: IdentityMutationKind::Link,
        candidate: Some(PreparedIdentityMutationCandidate {
            context,
            evidence_digest,
            candidate: IdentityMutationCandidate::Email(IdentityMutationEmailCandidate {
                identity_id: email_identity_id,
                canonicalization_version: 1,
                normalized_address: "new-link@example.test".to_owned(),
                lookup_aliases: vec![alias.clone()],
                active_alias: alias,
                alias_authority_revision: 1,
                durable_address: protected(90, 41),
            }),
        }),
        correlation_id: Uuid::new_v4(),
        now: OffsetDateTime::UNIX_EPOCH,
    };

    // Email login completion uses graph -> Project email namespace. Exercise the real Link
    // confirmation against that exact order: Link must wait at graph without owning email.
    let mut login_completion = fixture.sqlx.begin().await.expect("begin email login path");
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended(
             'owlauth-project-identity-graph:' || $1::TEXT,0))",
    )
    .bind(fixture.project_id)
    .execute(&mut *login_completion)
    .await
    .expect("email login holds graph");
    let confirming_repository = fixture.repository.clone();
    let confirming =
        tokio::spawn(async move { confirming_repository.confirm_control(confirmation).await });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!("email:{}", fixture.project_id))
            .execute(&mut *login_completion),
    )
    .await
    .expect("Link must not hold email namespace while waiting for graph")
    .expect("email login takes namespace without 40P01");
    login_completion
        .commit()
        .await
        .expect("release email login graph and namespace");
    let completed = confirming
        .await
        .expect("join graph-first email Link confirmation")
        .expect("confirm email Link after login path");
    assert_eq!(completed.status, IdentityMutationStatus::Completed);
    let linked: (Uuid, String, i64) = sqlx::query_as(
        "SELECT user_id,status,identity_revision FROM email_identities
          WHERE project_id=$1 AND id=$2",
    )
    .bind(fixture.project_id)
    .bind(email_identity_id)
    .fetch_one(&fixture.sqlx)
    .await
    .expect("read linked email identity");
    assert_eq!(linked, (fixture.user_id, "active".to_owned(), 1));
}

#[tokio::test]
async fn final_unlink_consumes_receipt_and_atomically_disables_only_target_identity() {
    let Some(fixture) = fixture().await else {
        return;
    };

    // Exercise the production composition, not Option-only sentinels, against this real database.
    // Runtime-only and All use a real non-nil incarnation fence; split Control and Runtime share
    // the same PostgreSQL authority while retaining disjoint capabilities.
    let runtime_config = identity_mutation_composition_config(PlaneMode::Runtime);
    let runtime_pools = DatabasePools {
        runtime: Some(fixture.database.clone()),
        client: None,
        control: None,
    };
    let runtime_only = build_routers_with_runtime_incarnation(
        &runtime_config,
        Some(&runtime_pools),
        fixture.incarnation,
    );
    let runtime_repository = runtime_only
        .runtime_identity_mutations
        .clone()
        .expect("Runtime-only production composition exposes the fenced repository");
    assert!(runtime_only.control_identity_mutations.is_none());
    assert_eq!(
        runtime_repository
            .repository_digest_versions(Uuid::new_v4(), OffsetDateTime::UNIX_EPOCH)
            .await,
        Err(ApplicationError::NotFound),
        "a current non-nil Runtime incarnation reaches the real transaction"
    );
    let stale_runtime = build_routers_with_runtime_incarnation(
        &runtime_config,
        Some(&runtime_pools),
        Uuid::new_v4(),
    );
    assert_eq!(
        stale_runtime
            .runtime_identity_mutations
            .expect("stale Runtime facade is composed but fenced")
            .repository_digest_versions(Uuid::new_v4(), OffsetDateTime::UNIX_EPOCH)
            .await,
        Err(ApplicationError::Disabled),
        "production Runtime composition rejects a stale non-nil incarnation"
    );

    let control_config = identity_mutation_composition_config(PlaneMode::Control);
    assert!(
        control_config.runtime_protection.is_none(),
        "Control-only never receives the generic Runtime protector"
    );
    let control_pools = DatabasePools {
        runtime: None,
        client: None,
        control: Some(fixture.database.clone()),
    };
    let split_control =
        build_routers_with_runtime_incarnation(&control_config, Some(&control_pools), Uuid::nil());
    assert!(split_control.runtime_identity_mutations.is_none());
    let split_control_repository = split_control
        .control_identity_mutations
        .expect("Control-only production composition exposes narrow Control authority");
    assert!(matches!(
        split_control_repository
            .repository_control_read(
                fixture.project_id,
                Uuid::new_v4(),
                OffsetDateTime::UNIX_EPOCH,
            )
            .await,
        Err(ApplicationError::NotFound)
    ));

    let all_config = identity_mutation_composition_config(PlaneMode::All);
    let all_pools = DatabasePools {
        runtime: Some(fixture.database.clone()),
        client: None,
        control: Some(fixture.database.clone()),
    };
    let all =
        build_routers_with_runtime_incarnation(&all_config, Some(&all_pools), fixture.incarnation);
    assert!(all.control_identity_mutations.is_some());
    assert_eq!(
        all.runtime_identity_mutations
            .expect("All mode composes Runtime authority")
            .repository_digest_versions(Uuid::new_v4(), OffsetDateTime::UNIX_EPOCH)
            .await,
        Err(ApplicationError::NotFound),
        "All mode uses the same current-incarnation transaction fence"
    );

    let removable_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO linked_identities
         (id,project_id,user_id,created_via_provider_configuration_id,issuer,subject,status,
          identity_revision,source_profile_digest,observed_at)
         VALUES ($1,$2,$3,$4,'https://issuer.example','removable','active',1,public.owlauth_provider_source_profile_digest(NULL,NULL,NULL),clock_timestamp())",
    )
    .bind(removable_id)
    .bind(fixture.project_id)
    .bind(fixture.user_id)
    .bind(fixture.provider_id)
    .execute(&fixture.sqlx)
    .await
    .expect("seed removable identity");

    let email_identity_id = Uuid::new_v4();
    let mut email_context = b"owlauth-email-identity-v1\0".to_vec();
    email_context.extend_from_slice(fixture.project_id.as_bytes());
    email_context.extend_from_slice(email_identity_id.as_bytes());
    let durable_email = fixture
        .protector
        .protect(
            ProtectedPurpose::EmailIdentityAddress,
            &email_context,
            b"control-only@example.com",
        )
        .expect("protect durable email source");
    sqlx::query(
        "INSERT INTO email_identities
         (id,project_id,user_id,status,identity_revision,canonicalization_version,
          address_ciphertext,address_key_version,verified_at)
         VALUES ($1,$2,$3,'active',1,1,$4,$5,clock_timestamp())",
    )
    .bind(email_identity_id)
    .bind(fixture.project_id)
    .bind(fixture.user_id)
    .bind(durable_email.ciphertext)
    .bind(durable_email.key_version)
    .execute(&fixture.sqlx)
    .await
    .expect("seed durable email source");
    let binding_id = Uuid::new_v4();
    let projection_id = Uuid::new_v4();
    let user = super::entity::project_user::Entity::find_by_id(fixture.user_id)
        .one(&fixture.database)
        .await
        .expect("read user for initial projection")
        .expect("fixture user");
    let (initial_document, initial_digest) =
        super::projection::projection_material(&user, 1).expect("initial safe projection");
    sqlx::query(
        "INSERT INTO application_user_bindings
         (id,project_id,application_id,user_id,status,binding_revision)
         VALUES ($1,$2,$3,$4,'active',1)",
    )
    .bind(binding_id)
    .bind(fixture.project_id)
    .bind(fixture.application_id)
    .bind(fixture.user_id)
    .execute(&fixture.sqlx)
    .await
    .expect("seed existing Application binding");
    sqlx::query(
        "INSERT INTO application_user_projections
         (id,project_id,binding_id,application_id,user_id,schema_name,projection_revision,
          source_user_revision,canonical_digest,source_base_profile_digest,document)
         VALUES ($1,$2,$3,$4,$5,'owlauth.user.v1',1,1,$6,$7,$8)",
    )
    .bind(projection_id)
    .bind(fixture.project_id)
    .bind(binding_id)
    .bind(fixture.application_id)
    .bind(fixture.user_id)
    .bind(initial_digest)
    .bind(user.base_profile_digest)
    .bind(initial_document)
    .execute(&fixture.sqlx)
    .await
    .expect("seed existing Application projection");

    sqlx::query("UPDATE project_users SET primary_profile_identity_id=$2 WHERE id=$1")
        .bind(fixture.user_id)
        .bind(removable_id)
        .execute(&fixture.sqlx)
        .await
        .expect("select removable identity as designated source");
    let intent_id = Uuid::new_v4();
    let mut prepared = prepared_unlink(&fixture, removable_id, "final-unlink", intent_id, 41);
    let IdentityMutationCreateOperation::Unlink { primary_source, .. } =
        &mut prepared.command.operation
    else {
        unreachable!("unlink fixture")
    };
    *primary_source = IdentityMutationPrimarySourceDisposition::Email(ExpectedIdentity {
        identity_kind: IdentityKind::Email,
        identity_id: email_identity_id,
        expected_identity_revision: 1,
    });
    let mut stale_create = prepared.clone();
    let IdentityMutationCreateOperation::Unlink { primary_source, .. } =
        &mut stale_create.command.operation
    else {
        unreachable!("unlink fixture")
    };
    *primary_source = IdentityMutationPrimarySourceDisposition::Email(ExpectedIdentity {
        identity_kind: IdentityKind::Email,
        identity_id: email_identity_id,
        expected_identity_revision: 2,
    });
    assert!(matches!(
        fixture.repository.create(stale_create).await,
        Err(ApplicationError::RevisionConflict)
    ));
    let created = fixture
        .repository
        .create(prepared)
        .await
        .expect("create unlink");
    let CreateIdentityMutationResult::Created(_) = created else {
        panic!("unlink must be created");
    };
    let bound = fixture
        .repository
        .bind_browser(
            &digest(41),
            &digest(42),
            &digest(43),
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .expect("bind unlink browser");
    let slot_id = bound.slots[0].id;
    let started = fixture
        .repository
        .start_provider(
            intent_id,
            slot_id,
            &digest(41),
            &digest(42),
            &digest(43),
            bound.revision,
            digest(44),
            digest(45),
            Some(protected(46, 17)),
            protected(47, 41),
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .expect("start unlink owner proof");
    let project_public_id: String =
        sqlx::query_scalar("SELECT public_id FROM projects WHERE id=$1")
            .bind(fixture.project_id)
            .fetch_one(&fixture.sqlx)
            .await
            .expect("project public id");
    let claimed = fixture
        .repository
        .claim_provider_callback(
            intent_id,
            slot_id,
            &project_public_id,
            "main",
            &digest(44),
            &digest(42),
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .expect("claim unlink callback");
    let ClaimIdentityMutationProvider::Claimed(claimed) = claimed else {
        panic!("unlink callback must be claimed");
    };
    assert!(claimed.revision > started.revision);
    let proved = fixture
        .repository
        .complete_provider_callback(PreparedIdentityMutationProviderCompletion {
            claimed,
            proof_slot_id: slot_id,
            observation: ProviderProofObservation {
                issuer: "https://issuer.example".to_owned(),
                subject: "removable".to_owned(),
                display_name: None,
                picture_url: None,
            },
            candidate_evidence: None,
            receipt_id: Uuid::new_v4(),
            receipt_digest: digest(48),
            now: OffsetDateTime::UNIX_EPOCH,
        })
        .await
        .expect("complete unlink owner proof");
    let ready = fixture
        .repository
        .confirm_ready(
            intent_id,
            &digest(41),
            &digest(42),
            &digest(43),
            proved.revision,
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .expect("mark unlink ready");
    let preparation = fixture
        .repository
        .prepare_control_confirmation(
            fixture.project_id,
            intent_id,
            ready.revision,
            IdentityMutationKind::Unlink,
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .expect("prepare unlink confirmation");
    assert!(preparation.candidate_evidence.is_none());
    sqlx::query(
        "DELETE FROM runtime_process_incarnations WHERE process_id='identity-mutation-test'",
    )
    .execute(&fixture.sqlx)
    .await
    .expect("take Runtime process offline before ordinary Control confirmation");
    let confirmation = PreparedIdentityMutationConfirmation {
        project_id: fixture.project_id,
        intent_id,
        expected_intent_revision: ready.revision,
        expected_kind: IdentityMutationKind::Unlink,
        candidate: None,
        correlation_id: Uuid::new_v4(),
        now: OffsetDateTime::UNIX_EPOCH,
    };
    let failing_control = PostgresControlIdentityMutationRepository::new(
        fixture.database.clone(),
        Arc::new(FailingProjectionMaterializer),
        Vec::new(),
    );
    sqlx::query("UPDATE email_identities SET identity_revision=identity_revision+1 WHERE id=$1")
        .bind(email_identity_id)
        .execute(&fixture.sqlx)
        .await
        .expect("advance frozen replacement primary revision");
    assert!(matches!(
        failing_control.confirm_control(confirmation.clone()).await,
        Err(ApplicationError::RevisionConflict)
    ));
    let stale_primary_rollback: (String, String, String) = sqlx::query_as(
        "SELECT intent.status,target.status,receipt.status
           FROM identity_mutation_intents intent
           JOIN linked_identities target ON target.project_id=intent.project_id AND target.id=$2
           JOIN identity_proof_receipts receipt ON receipt.project_id=intent.project_id
             AND receipt.intent_id=intent.id
          WHERE intent.id=$1",
    )
    .bind(intent_id)
    .bind(removable_id)
    .fetch_one(&fixture.sqlx)
    .await
    .expect("read frozen primary revision rollback state");
    assert_eq!(
        stale_primary_rollback,
        ("ready".to_owned(), "active".to_owned(), "issued".to_owned())
    );
    sqlx::query("UPDATE email_identities SET identity_revision=1 WHERE id=$1")
        .bind(email_identity_id)
        .execute(&fixture.sqlx)
        .await
        .expect("restore fixture replacement primary revision");
    match failing_control.confirm_control(confirmation.clone()).await {
        Err(error) => assert_eq!(error, ApplicationError::ExternalStore),
        Ok(_) => panic!("injected projection materializer failure must roll back confirmation"),
    }
    let rolled_back: (String, String, String) = sqlx::query_as(
        "SELECT intent.status,identity.status,receipt.status
           FROM identity_mutation_intents intent
           JOIN linked_identities identity ON identity.project_id=intent.project_id AND identity.id=$2
           JOIN identity_proof_receipts receipt ON receipt.project_id=intent.project_id AND receipt.intent_id=intent.id
          WHERE intent.id=$1",
    )
    .bind(intent_id)
    .bind(removable_id)
    .fetch_one(&fixture.sqlx)
    .await
    .expect("read materializer rollback state");
    assert_eq!(
        rolled_back,
        ("ready".to_owned(), "active".to_owned(), "issued".to_owned())
    );
    let source_reader = Arc::new(
        SoftwareDurableEmailAddressReader::new(
            "identity-mutation-test".to_owned(),
            1,
            RuntimeKeyMaterial::new([11; 32], [12; 32]),
            BTreeMap::new(),
        )
        .expect("Control exact durable-email reader"),
    );
    let projection_protector = Arc::new(
        SoftwareProjectionVerifiedEmailProtector::new(
            "identity-mutation-test".to_owned(),
            1,
            [62; 32],
            BTreeMap::new(),
        )
        .expect("Control projection-email protector"),
    );
    let missing_source = PostgresControlIdentityMutationRepository::new(
        fixture.database.clone(),
        Arc::new(PostgresIdentityProjectionMaterializer::new(
            Arc::new(UnavailableDurableEmailAddressReader),
            projection_protector.clone(),
        )),
        Vec::new(),
    );
    assert!(matches!(
        missing_source.confirm_control(confirmation.clone()).await,
        Err(ApplicationError::Disabled)
    ));
    let stale_projection_protector = Arc::new(
        SoftwareProjectionVerifiedEmailProtector::new(
            "identity-mutation-test".to_owned(),
            2,
            [72; 32],
            BTreeMap::new(),
        )
        .expect("stale projection writer"),
    );
    let stale_projection_authority = PostgresControlIdentityMutationRepository::new(
        fixture.database.clone(),
        Arc::new(PostgresIdentityProjectionMaterializer::new(
            source_reader.clone(),
            stale_projection_protector,
        )),
        Vec::new(),
    );
    assert!(matches!(
        stale_projection_authority
            .confirm_control(confirmation.clone())
            .await,
        Err(ApplicationError::Disabled)
    ));
    let key_failure_rollback: (String, String, i64, Option<i32>) = sqlx::query_as(
        "SELECT intent.status,identity.status,projection.projection_revision,
                projection.verified_email_key_version
           FROM identity_mutation_intents intent
           JOIN linked_identities identity ON identity.project_id=intent.project_id AND identity.id=$2
           JOIN application_user_projections projection ON projection.project_id=intent.project_id AND projection.id=$3
          WHERE intent.id=$1",
    )
    .bind(intent_id)
    .bind(removable_id)
    .bind(projection_id)
    .fetch_one(&fixture.sqlx)
    .await
    .expect("read key-failure rollback state");
    assert_eq!(
        key_failure_rollback,
        ("ready".to_owned(), "active".to_owned(), 1, None)
    );
    let completed = split_control_repository
        .repository_confirm_control(confirmation)
        .await
        .expect("production Control-only confirms unlink without a Runtime incarnation");
    assert_eq!(completed.status, IdentityMutationStatus::Completed);
    let target_status: String =
        sqlx::query_scalar("SELECT status FROM linked_identities WHERE id=$1")
            .bind(removable_id)
            .fetch_one(&fixture.sqlx)
            .await
            .expect("read target identity");
    let primary_status: String =
        sqlx::query_scalar("SELECT status FROM linked_identities WHERE id=$1")
            .bind(fixture.identity_id)
            .fetch_one(&fixture.sqlx)
            .await
            .expect("read primary identity");
    assert_eq!(target_status, "disabled");
    assert_eq!(primary_status, "active");
    let projected: (i64, Uuid, Vec<u8>, i32, serde_json::Value) = sqlx::query_as(
        "SELECT projection_revision,verified_email_source_identity_id,
                verified_email_ciphertext,verified_email_key_version,document
           FROM application_user_projections WHERE id=$1",
    )
    .bind(projection_id)
    .fetch_one(&fixture.sqlx)
    .await
    .expect("read synchronously committed verified-email projection");
    assert_eq!(projected.0, 2);
    assert_eq!(projected.1, email_identity_id);
    assert_eq!(projected.3, 1);
    assert_eq!(projected.4["verified_email"], serde_json::Value::Null);
    assert!(
        !projected
            .2
            .windows("control-only@example.com".len())
            .any(|window| { window == b"control-only@example.com" })
    );
    let protected_projection_email = ProtectedValue {
        ciphertext: projected.2,
        key_version: projected.3,
    };
    assert_eq!(
        crate::application::ProjectionVerifiedEmailProtector::unprotect_verified_email(
            projection_protector.as_ref(),
            fixture.project_id,
            fixture.application_id,
            fixture.user_id,
            projected.0,
            &protected_projection_email,
        )
        .expect("decrypt exact committed projection context")
        .as_str(),
        "control-only@example.com"
    );
    let runtime_projection_reader = PostgresIdentityProjectionMaterializer::new(
        Arc::new(
            SoftwareDurableEmailAddressReader::new(
                "identity-mutation-test".to_owned(),
                1,
                RuntimeKeyMaterial::new([11; 32], [12; 32]),
                BTreeMap::new(),
            )
            .expect("Runtime durable email reader"),
        ),
        projection_protector,
    );
    let stored_projection =
        super::entity::application_user_projection::Entity::find_by_id(projection_id)
            .one(&fixture.database)
            .await
            .expect("Runtime reads committed projection")
            .expect("committed projection exists");
    let runtime_document =
        super::projection::wire_projection_document(&stored_projection, &runtime_projection_reader)
            .expect("Runtime-only projection reader overlays dedicated ciphertext");
    assert_eq!(
        runtime_document["verified_email"],
        serde_json::json!("control-only@example.com")
    );
    let unconsumed: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM identity_proof_receipts
          WHERE intent_id=$1 AND consumed_at IS NULL",
    )
    .bind(intent_id)
    .fetch_one(&fixture.sqlx)
    .await
    .expect("read receipt consumption");
    assert_eq!(unconsumed, 0);
}

#[tokio::test]
async fn final_merge_has_one_concurrent_winner_moves_graph_and_writes_exact_tombstone() {
    let Some(fixture) = fixture().await else {
        return;
    };
    let loser_id = Uuid::new_v4();
    let loser_identity_id = Uuid::new_v4();
    let loser_email_identity_id = Uuid::new_v4();
    let mut loser_email_context = b"owlauth-email-identity-v1\0".to_vec();
    loser_email_context.extend_from_slice(fixture.project_id.as_bytes());
    loser_email_context.extend_from_slice(loser_email_identity_id.as_bytes());
    let loser_email = fixture
        .protector
        .protect(
            ProtectedPurpose::EmailIdentityAddress,
            &loser_email_context,
            b"merge-loser@example.com",
        )
        .expect("protect loser primary email");
    let mut seed = fixture.sqlx.begin().await.expect("begin loser seed");
    sqlx::query(
        "INSERT INTO project_users
         (id,project_id,public_id,status,user_revision,security_revision,base_profile_digest)
         VALUES ($1,$2,$3,'active',1,1,$4)",
    )
    .bind(loser_id)
    .bind(fixture.project_id)
    .bind(format!("usr_{loser_id}"))
    .bind(vec![0_u8; 32])
    .execute(&mut *seed)
    .await
    .expect("seed loser");
    sqlx::query(
        "INSERT INTO linked_identities
         (id,project_id,user_id,created_via_provider_configuration_id,issuer,subject,status,
          identity_revision,source_profile_digest,observed_at)
         VALUES ($1,$2,$3,$4,'https://issuer.example','loser','active',1,public.owlauth_provider_source_profile_digest(NULL,NULL,NULL),clock_timestamp())",
    )
    .bind(loser_identity_id)
    .bind(fixture.project_id)
    .bind(loser_id)
    .bind(fixture.provider_id)
    .execute(&mut *seed)
    .await
    .expect("seed loser identity");
    sqlx::query(
        "INSERT INTO email_identities
         (id,project_id,user_id,status,identity_revision,canonicalization_version,
          address_ciphertext,address_key_version,verified_at)
         VALUES ($1,$2,$3,'active',1,1,$4,$5,clock_timestamp())",
    )
    .bind(loser_email_identity_id)
    .bind(fixture.project_id)
    .bind(loser_id)
    .bind(loser_email.ciphertext)
    .bind(loser_email.key_version)
    .execute(&mut *seed)
    .await
    .expect("seed loser primary email");
    sqlx::query(
        "UPDATE project_users SET primary_source_kind='email',primary_email_identity_id=$2
          WHERE id=$1",
    )
    .bind(loser_id)
    .bind(loser_email_identity_id)
    .execute(&mut *seed)
    .await
    .expect("select loser email primary");
    seed.commit().await.expect("commit loser seed");
    let moved_application_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO applications
         (id,project_id,public_id,status,revision,metadata_revision,security_revision)
         VALUES ($1,$2,$3,'active',1,1,1)",
    )
    .bind(moved_application_id)
    .bind(fixture.project_id)
    .bind(format!("app_{moved_application_id}"))
    .execute(&fixture.sqlx)
    .await
    .expect("seed loser-only Application");
    let disabled_application_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO applications
         (id,project_id,public_id,status,revision,metadata_revision,security_revision)
         VALUES ($1,$2,$3,'active',1,1,1)",
    )
    .bind(disabled_application_id)
    .bind(fixture.project_id)
    .bind(format!("app_{disabled_application_id}"))
    .execute(&fixture.sqlx)
    .await
    .expect("seed disabled loser-only Application");
    // Both users already reached the same Application and the loser has immutable delivery
    // history. Merge must retain that history through its binding while deleting the loser's
    // mutable projection, which may contain stale protected PII.
    let (winner_projection, winner_document) =
        seed_application_projection(&fixture, fixture.application_id, fixture.user_id).await;
    let (loser_projection, loser_document) =
        seed_application_projection(&fixture, fixture.application_id, loser_id).await;
    let (moved_projection, moved_document) =
        seed_application_projection(&fixture, moved_application_id, loser_id).await;
    let (disabled_projection, _) =
        seed_application_projection(&fixture, disabled_application_id, loser_id).await;
    let loser_user = super::entity::project_user::Entity::find_by_id(loser_id)
        .one(&fixture.database)
        .await
        .expect("read email-primary loser")
        .expect("email-primary loser exists");
    let (disabled_document, disabled_digest) =
        super::projection::projection_material_with_verified_email(
            &loser_user,
            1,
            Some("merge-loser@example.com".to_owned()),
        )
        .expect("materialize disabled-branch PII projection");
    let disabled_storage_document = super::projection::safe_projection_document(&disabled_document)
        .expect("redact disabled-branch stored projection");
    let disabled_projection_protector = SoftwareProjectionVerifiedEmailProtector::new(
        "identity-mutation-projection-test".to_owned(),
        1,
        [104; 32],
        BTreeMap::new(),
    )
    .expect("disabled-branch projection protector");
    let disabled_protected_email = super::projection::protect_projection_verified_email(
        &disabled_projection_protector,
        fixture.project_id,
        disabled_application_id,
        loser_id,
        1,
        "merge-loser@example.com",
    )
    .expect("protect disabled-branch projection email");
    sqlx::query(
        "UPDATE application_user_projections
            SET canonical_digest=$2,document=$3,verified_email_source_identity_id=$4,
                verified_email_ciphertext=$5,verified_email_key_version=$6
          WHERE id=$1",
    )
    .bind(disabled_projection.id)
    .bind(disabled_digest)
    .bind(disabled_storage_document)
    .bind(loser_email_identity_id)
    .bind(disabled_protected_email.ciphertext)
    .bind(disabled_protected_email.key_version)
    .execute(&fixture.sqlx)
    .await
    .expect("seed retained PII on disabled-branch projection");
    let retained_projection_has_pii: bool = sqlx::query_scalar(
        "SELECT verified_email_ciphertext IS NOT NULL FROM application_user_projections WHERE id=$1",
    )
    .bind(disabled_projection.id)
    .fetch_one(&fixture.sqlx)
    .await
    .expect("confirm retained disabled-branch projection PII");
    assert!(retained_projection_has_pii);
    let disabled_projection =
        super::entity::application_user_projection::Entity::find_by_id(disabled_projection.id)
            .one(&fixture.database)
            .await
            .expect("read retained disabled-branch projection")
            .expect("retained disabled-branch projection exists");
    let event_transaction = fixture.database.begin().await.expect("begin event seed");
    for (projection, document, application_id) in [
        (&winner_projection, &winner_document, fixture.application_id),
        (&loser_projection, &loser_document, fixture.application_id),
        (&moved_projection, &moved_document, moved_application_id),
        (
            &disabled_projection,
            &disabled_document,
            disabled_application_id,
        ),
    ] {
        super::webhook::append_projection_event(
            &event_transaction,
            &format!("prj_{}", fixture.project_id),
            &format!("app_{application_id}"),
            projection.binding_id,
            projection,
            document,
            ApplicationUserEventType::Created,
        )
        .await
        .expect("append immutable initial projection event");
    }
    event_transaction.commit().await.expect("commit event seed");
    sqlx::query(
        "UPDATE application_user_bindings
            SET status='disabled',binding_revision=binding_revision+1,updated_at=clock_timestamp()
          WHERE id=$1",
    )
    .bind(disabled_projection.binding_id)
    .execute(&fixture.sqlx)
    .await
    .expect("disable loser-only binding while retaining its PII projection");

    let intent_id = Uuid::new_v4();
    let created = fixture
        .repository
        .create(prepared_merge(
            &fixture,
            loser_id,
            loser_identity_id,
            intent_id,
        ))
        .await
        .expect("create merge");
    let CreateIdentityMutationResult::Created(_) = created else {
        panic!("merge must be created");
    };
    let bound = fixture
        .repository
        .bind_browser(
            &digest(71),
            &digest(74),
            &digest(75),
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .expect("bind merge browser");
    let winner_slot = bound
        .slots
        .iter()
        .find(|slot| slot.role == IdentityMutationSlotRole::WinnerOwner)
        .expect("winner slot")
        .id;
    let loser_slot = bound
        .slots
        .iter()
        .find(|slot| slot.role == IdentityMutationSlotRole::LoserOwner)
        .expect("loser slot")
        .id;
    let winner_proved = prove_provider_slot(
        &fixture,
        bound,
        winner_slot,
        71,
        74,
        75,
        76,
        "existing",
        None,
    )
    .await;
    let loser_proved = prove_provider_slot(
        &fixture,
        winner_proved,
        loser_slot,
        71,
        74,
        75,
        81,
        "loser",
        None,
    )
    .await;
    let ready = fixture
        .repository
        .confirm_ready(
            intent_id,
            &digest(71),
            &digest(74),
            &digest(75),
            loser_proved.revision,
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .expect("mark merge ready");
    fixture
        .repository
        .prepare_control_confirmation(
            fixture.project_id,
            intent_id,
            ready.revision,
            IdentityMutationKind::Merge,
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .expect("prepare merge confirmation");
    let confirmation = PreparedIdentityMutationConfirmation {
        project_id: fixture.project_id,
        intent_id,
        expected_intent_revision: ready.revision,
        expected_kind: IdentityMutationKind::Merge,
        candidate: None,
        correlation_id: Uuid::new_v4(),
        now: OffsetDateTime::UNIX_EPOCH,
    };
    let first = fixture.repository.clone();
    let second = fixture.repository.clone();
    let confirmation_b = confirmation.clone();
    let a = tokio::spawn(async move { first.confirm_control(confirmation).await });
    let b = tokio::spawn(async move { second.confirm_control(confirmation_b).await });
    let outcomes = [
        a.await.expect("merge task A"),
        b.await.expect("merge task B"),
    ];
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| result
                .as_ref()
                .is_ok_and(|record| record.status == IdentityMutationStatus::Completed))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| matches!(result, Err(ApplicationError::RevisionConflict)))
            .count(),
        1
    );

    let loser: (String, Option<Uuid>, Option<Uuid>, Option<Uuid>) = sqlx::query_as(
        "SELECT status,merged_into_user_id,primary_profile_identity_id,primary_email_identity_id
           FROM project_users WHERE id=$1",
    )
    .bind(loser_id)
    .fetch_one(&fixture.sqlx)
    .await
    .expect("read merged loser");
    assert_eq!(loser.0, "merged");
    assert_eq!(loser.1, Some(fixture.user_id));
    assert!(loser.2.is_none());
    assert!(loser.3.is_none());
    let moved: (Uuid, i64, String) = sqlx::query_as(
        "SELECT user_id,identity_revision,status FROM linked_identities WHERE id=$1",
    )
    .bind(loser_identity_id)
    .fetch_one(&fixture.sqlx)
    .await
    .expect("read moved loser identity");
    assert_eq!(moved.0, fixture.user_id);
    assert_eq!(moved.1, 2);
    assert_eq!(moved.2, "active");
    let tombstone: (Uuid, Uuid, Uuid) = sqlx::query_as(
        "SELECT loser_user_id,winner_user_id,identity_mutation_intent_id
           FROM project_user_merge_tombstones WHERE project_id=$1 AND loser_user_id=$2",
    )
    .bind(fixture.project_id)
    .bind(loser_id)
    .fetch_one(&fixture.sqlx)
    .await
    .expect("read merge tombstone");
    assert_eq!(tombstone, (loser_id, fixture.user_id, intent_id));
    let retained_loser_events: Vec<(String, i64, String)> = sqlx::query_as(
        "SELECT event_type,projection_revision,
                safe_body #>> '{data,projection,status}' AS projection_status
           FROM application_user_events WHERE binding_id=$1
          ORDER BY projection_revision",
    )
    .bind(loser_projection.binding_id)
    .fetch_all(&fixture.sqlx)
    .await
    .expect("read retained loser events");
    assert_eq!(
        retained_loser_events,
        vec![
            ("user.projection.created".to_owned(), 1, "active".to_owned()),
            (
                "user.projection.disabled".to_owned(),
                2,
                "disabled".to_owned(),
            ),
        ]
    );
    let winner_events: Vec<(String, i64, String)> = sqlx::query_as(
        "SELECT event_type,projection_revision,
                safe_body #>> '{data,projection,status}' AS projection_status
           FROM application_user_events WHERE binding_id=$1
          ORDER BY projection_revision",
    )
    .bind(winner_projection.binding_id)
    .fetch_all(&fixture.sqlx)
    .await
    .expect("read winner events");
    assert_eq!(
        winner_events,
        vec![
            ("user.projection.created".to_owned(), 1, "active".to_owned()),
            ("user.projection.updated".to_owned(), 2, "active".to_owned()),
        ]
    );
    let deleted_loser_projection: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM application_user_projections WHERE binding_id=$1")
            .bind(loser_projection.binding_id)
            .fetch_one(&fixture.sqlx)
            .await
            .expect("read deleted loser projection");
    assert_eq!(deleted_loser_projection, 0);
    let moved_events: Vec<(String, i64, Uuid, String)> = sqlx::query_as(
        "SELECT event_type,projection_revision,user_id,
                safe_body #>> '{data,projection,status}' AS projection_status
           FROM application_user_events WHERE binding_id=$1
          ORDER BY projection_revision",
    )
    .bind(moved_projection.binding_id)
    .fetch_all(&fixture.sqlx)
    .await
    .expect("read moved-binding events");
    assert_eq!(
        moved_events,
        vec![
            (
                "user.projection.created".to_owned(),
                1,
                loser_id,
                "active".to_owned(),
            ),
            (
                "user.projection.disabled".to_owned(),
                2,
                loser_id,
                "disabled".to_owned(),
            ),
            (
                "user.projection.updated".to_owned(),
                3,
                fixture.user_id,
                "active".to_owned(),
            ),
        ]
    );
    let moved_projection_owner: (Uuid, i64) = sqlx::query_as(
        "SELECT user_id,projection_revision FROM application_user_projections WHERE binding_id=$1",
    )
    .bind(moved_projection.binding_id)
    .fetch_one(&fixture.sqlx)
    .await
    .expect("read moved winner projection");
    assert_eq!(moved_projection_owner, (fixture.user_id, 3));
    let disabled_binding: (Uuid, String, i64) = sqlx::query_as(
        "SELECT user_id,status,binding_revision FROM application_user_bindings WHERE id=$1",
    )
    .bind(disabled_projection.binding_id)
    .fetch_one(&fixture.sqlx)
    .await
    .expect("read moved disabled loser-only binding");
    assert_eq!(
        disabled_binding,
        (fixture.user_id, "disabled".to_owned(), 3)
    );
    let erased_disabled_projection: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM application_user_projections WHERE binding_id=$1")
            .bind(disabled_projection.binding_id)
            .fetch_one(&fixture.sqlx)
            .await
            .expect("read disabled loser-only projection erasure");
    assert_eq!(erased_disabled_projection, 0);
    let retained_disabled_history: Vec<(String, Uuid, Option<String>)> = sqlx::query_as(
        "SELECT event_type,user_id,
                safe_body #>> '{data,projection,verified_email}' AS verified_email
           FROM application_user_events WHERE binding_id=$1 ORDER BY projection_revision",
    )
    .bind(disabled_projection.binding_id)
    .fetch_all(&fixture.sqlx)
    .await
    .expect("read retained disabled loser-only history");
    assert_eq!(
        retained_disabled_history,
        vec![("user.projection.created".to_owned(), loser_id, None,)]
    );
    let moved_email_owner: Uuid =
        sqlx::query_scalar("SELECT user_id FROM email_identities WHERE id=$1")
            .bind(loser_email_identity_id)
            .fetch_one(&fixture.sqlx)
            .await
            .expect("read moved loser email identity");
    assert_eq!(moved_email_owner, fixture.user_id);
    let unconsumed: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM identity_proof_receipts
          WHERE intent_id=$1 AND consumed_at IS NULL",
    )
    .bind(intent_id)
    .fetch_one(&fixture.sqlx)
    .await
    .expect("read merge receipts");
    assert_eq!(unconsumed, 0);
}

#[tokio::test]
async fn mutation_mail_claim_uses_newest_generation_and_exact_typed_owner() {
    let Some(fixture) = fixture().await else {
        return;
    };
    let intent_id = Uuid::new_v4();
    let created = fixture
        .repository
        .create(prepared_email(&fixture, "mutation-mail", intent_id))
        .await
        .expect("create email mutation");
    let CreateIdentityMutationResult::Created(_) = created else {
        panic!("email mutation must be created");
    };
    let bound = fixture
        .repository
        .bind_browser(
            &digest(21),
            &digest(24),
            &digest(25),
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .expect("bind email mutation");
    let slot_id = bound
        .slots
        .iter()
        .find(|slot| slot.role == IdentityMutationSlotRole::CandidateIdentity)
        .expect("candidate email slot")
        .id;
    let entered = fixture
        .repository
        .begin_email(
            intent_id,
            slot_id,
            &digest(21),
            &digest(24),
            &digest(25),
            bound.revision,
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .expect("begin email proof");
    let first = fixture
        .repository
        .prepare_email_generation(
            intent_id,
            slot_id,
            &digest(21),
            &digest(24),
            &digest(25),
            entered.revision,
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .expect("prepare first generation");
    let first_challenge = Uuid::new_v4();
    let first_outbox = Uuid::new_v4();
    let first_aad = mutation_mail_aad(
        fixture.project_id,
        intent_id,
        slot_id,
        first_challenge,
        first.next_generation,
    );
    let first_record = fixture
        .repository
        .commit_email_generation(CommitIdentityMutationEmailGeneration {
            project_id: first.project_id,
            application_id: first.application_id,
            intent_id,
            proof_slot_id: slot_id,
            expected_intent_revision: entered.revision,
            expected_generation: first.next_generation,
            challenge_id: first_challenge,
            outbox_id: first_outbox,
            canonicalization_version: 1,
            lookup_digest: digest(26),
            address: protected(27, 41),
            otp_digest: Some(digest(28)),
            magic_digest: None,
            envelope: fixture
                .protector
                .protect(
                    ProtectedPurpose::EmailOutboxEnvelope,
                    &first_aad,
                    b"first@example.test",
                )
                .expect("protect first envelope"),
            body: fixture
                .protector
                .protect(ProtectedPurpose::EmailOutboxBody, &first_aad, b"first body")
                .expect("protect first body"),
            message_id: format!("mutation-{first_outbox}"),
            suppress_delivery: false,
            admitted_method: first.policy,
            issued_at: OffsetDateTime::UNIX_EPOCH,
            otp_expires_at: None,
            magic_expires_at: None,
            expires_at: OffsetDateTime::UNIX_EPOCH,
        })
        .await
        .expect("commit first generation");

    // Advance only the resend fixture timestamp with production triggers suppressed. The adapter
    // must supersede/cancel generation one atomically and only expose generation two to workers.
    let mut setup = fixture.sqlx.acquire().await.expect("acquire resend setup");
    sqlx::query("SET session_replication_role=replica")
        .execute(&mut *setup)
        .await
        .expect("disable triggers for resend setup");
    sqlx::query(
        "UPDATE email_challenges
            SET issued_at=issued_at-interval '31 seconds',
                otp_expires_at=otp_expires_at-interval '31 seconds',
                expires_at=expires_at-interval '31 seconds',
                created_at=created_at-interval '31 seconds',
                updated_at=updated_at-interval '31 seconds'
          WHERE id=$1",
    )
    .bind(first_challenge)
    .execute(&mut *setup)
    .await
    .expect("age first generation");
    sqlx::query(
        "UPDATE mail_outbox
            SET next_attempt_at=next_attempt_at-interval '31 seconds',
                useful_until=useful_until-interval '31 seconds',
                created_at=created_at-interval '31 seconds',
                updated_at=updated_at-interval '31 seconds'
          WHERE id=$1",
    )
    .bind(first_outbox)
    .execute(&mut *setup)
    .await
    .expect("align first outbox generation");
    sqlx::query(
        "UPDATE identity_mutation_intents
            SET created_at=created_at-interval '31 seconds',
                updated_at=updated_at-interval '31 seconds',
                expires_at=expires_at-interval '31 seconds'
          WHERE id=$1",
    )
    .bind(intent_id)
    .execute(&mut *setup)
    .await
    .expect("align frozen intent window");
    sqlx::query(
        "UPDATE identity_mutation_create_results result
            SET expires_at=intent.expires_at
           FROM identity_mutation_intents intent
          WHERE result.intent_id=intent.id AND intent.id=$1",
    )
    .bind(intent_id)
    .execute(&mut *setup)
    .await
    .expect("align create-result expiry");
    sqlx::query("SET session_replication_role=origin")
        .execute(&mut *setup)
        .await
        .expect("restore triggers after resend setup");
    drop(setup);

    let second = fixture
        .repository
        .prepare_email_generation(
            intent_id,
            slot_id,
            &digest(21),
            &digest(24),
            &digest(25),
            first_record.revision,
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .expect("prepare second generation");
    let second_challenge = Uuid::new_v4();
    let second_outbox = Uuid::new_v4();
    let second_aad = mutation_mail_aad(
        fixture.project_id,
        intent_id,
        slot_id,
        second_challenge,
        second.next_generation,
    );
    let final_record = fixture
        .repository
        .commit_email_generation(CommitIdentityMutationEmailGeneration {
            project_id: second.project_id,
            application_id: second.application_id,
            intent_id,
            proof_slot_id: slot_id,
            expected_intent_revision: first_record.revision,
            expected_generation: second.next_generation,
            challenge_id: second_challenge,
            outbox_id: second_outbox,
            canonicalization_version: 1,
            lookup_digest: digest(31),
            address: protected(32, 41),
            otp_digest: Some(digest(33)),
            magic_digest: None,
            envelope: fixture
                .protector
                .protect(
                    ProtectedPurpose::EmailOutboxEnvelope,
                    &second_aad,
                    b"second@example.test",
                )
                .expect("protect second envelope"),
            body: fixture
                .protector
                .protect(
                    ProtectedPurpose::EmailOutboxBody,
                    &second_aad,
                    b"second body",
                )
                .expect("protect second body"),
            message_id: format!("mutation-{second_outbox}"),
            suppress_delivery: false,
            admitted_method: second.policy,
            issued_at: OffsetDateTime::UNIX_EPOCH,
            otp_expires_at: None,
            magic_expires_at: None,
            expires_at: OffsetDateTime::UNIX_EPOCH,
        })
        .await
        .expect("commit second generation");

    let email = PostgresPasswordlessEmailRepository::new_with_runtime_identity(
        fixture.database.clone(),
        "identity-mutation-test".to_owned(),
        fixture.incarnation,
        Vec::new(),
        Duration::minutes(5),
    );

    // Queue an older login-owned row whose current policy is stale. The global lane selector sees
    // it first, the fully authoritative login query rejects it, and the mutation lane must still
    // make progress rather than starving behind the stale head.
    let stale_project = Uuid::new_v4();
    let stale_application = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO projects(id,public_id,status,metadata_revision,security_revision)
         VALUES ($1,$2,'active',1,1)",
    )
    .bind(stale_project)
    .bind(format!("prj_{stale_project}"))
    .execute(&fixture.sqlx)
    .await
    .expect("seed stale-lane project");
    sqlx::query(
        "INSERT INTO applications
         (id,project_id,public_id,status,revision,metadata_revision,security_revision)
         VALUES ($1,$2,$3,'active',1,1,1)",
    )
    .bind(stale_application)
    .bind(stale_project)
    .bind(format!("app_{stale_application}"))
    .execute(&fixture.sqlx)
    .await
    .expect("seed stale-lane application");
    sqlx::query(
        "INSERT INTO application_redirects(project_id,application_id,redirect_uri,redirect_type)
         VALUES ($1,$2,'https://app.example/callback','web')",
    )
    .bind(stale_project)
    .bind(stale_application)
    .execute(&fixture.sqlx)
    .await
    .expect("seed stale-lane redirect");
    sqlx::query(
        "INSERT INTO project_policies
         (project_id,claims_revision,session_revision,claims_policy,session_policy)
         VALUES ($1,1,1,'{\"access_token_lifetime_seconds\":900}'::jsonb,
                 '{\"browser_session_reuse\":false,
                    \"browser_session_reuse_max_age_seconds\":28800}'::jsonb)",
    )
    .bind(stale_project)
    .execute(&fixture.sqlx)
    .await
    .expect("seed stale-lane policy");
    sqlx::query(
        "UPDATE project_email_policies SET status='enabled',allow_deployment_default=TRUE
          WHERE project_id=$1",
    )
    .bind(stale_project)
    .execute(&fixture.sqlx)
    .await
    .expect("enable stale-lane email");
    sqlx::query(
        "INSERT INTO application_email_assignments(project_id,application_id,status,security_revision)
         VALUES ($1,$2,'active',1)",
    )
    .bind(stale_project)
    .bind(stale_application)
    .execute(&fixture.sqlx)
    .await
    .expect("seed stale-lane assignment");
    let admitted = AdmittedEmailMethod {
        policy_revision: 1,
        security_revision: 1,
        assignment_security_revision: 1,
        otp_enabled: true,
        magic_link_enabled: true,
        otp_digits: 6,
        otp_validity_seconds: 600,
        otp_max_attempts: 5,
        resend_after_seconds: 30,
        max_generations: 5,
        magic_validity_seconds: 600,
        signup_enabled: true,
        transferred_magic_link_enabled: false,
        smtp_selection_kind: "deployment_default".to_owned(),
        smtp_configuration_id: None,
        smtp_generation: 1,
        smtp_security_eligibility_revision: 1,
    };
    let authentication = PostgresAuthenticationRepository::new_with_runtime_identity(
        fixture.database.clone(),
        "identity-mutation-test".to_owned(),
        fixture.incarnation,
    );
    let login_id = Uuid::new_v4();
    let login_now = OffsetDateTime::now_utc();
    authentication
        .create_login_transaction(CreateLoginTransaction {
            id: login_id,
            project_id: stale_project,
            application_id: stale_application,
            interaction: digest(101),
            redirect_uri: "https://app.example/callback".to_owned(),
            application_pkce_challenge: "A".repeat(43),
            application_state: protected(102, 41),
            presentation_hint: None,
            revisions: LoginRevisionSnapshot {
                project_metadata_revision: 1,
                project_security_revision: 1,
                application_security_revision: 1,
                claims_revision: 1,
                session_revision: 1,
            },
            created_at: login_now,
            expires_at: login_now + Duration::minutes(10),
            admitted_providers: Vec::new(),
            admitted_email: Some(admitted),
        })
        .await
        .expect("create stale-lane login");
    authentication
        .bind_hosted_browser(BindHostedBrowser {
            interaction: digest(101),
            expected_transaction_revision: 1,
            browser_binding: digest(103),
            csrf: digest(104),
            now: login_now,
        })
        .await
        .expect("bind stale-lane login");
    email
        .select_email_method(SelectEmailMethod {
            project_id: stale_project,
            transaction_id: login_id,
            expected_transaction_revision: 2,
            browser_binding: digest(103),
            csrf: digest(104),
            now: login_now,
        })
        .await
        .expect("select stale-lane email");
    let login_preparation = email
        .prepare_email_generation(
            stale_project,
            login_id,
            3,
            &digest(103),
            &digest(104),
            login_now,
        )
        .await
        .expect("prepare stale-lane generation");
    let login_challenge = Uuid::new_v4();
    let login_outbox = Uuid::new_v4();
    email
        .commit_email_generation(CommitEmailGeneration {
            project_id: stale_project,
            application_id: stale_application,
            transaction_id: login_id,
            expected_transaction_revision: 3,
            expected_generation: login_preparation.next_generation,
            challenge_id: login_challenge,
            outbox_id: login_outbox,
            canonicalization_version: 1,
            lookup_digest: digest(105),
            address: protected(106, 41),
            otp_digest: Some(digest(107)),
            magic_digest: None,
            envelope: protected(108, 41),
            body: protected(109, 41),
            message_id: format!("stale-login-{login_outbox}"),
            suppress_delivery: false,
            issued_at: login_now,
            otp_expires_at: Some(login_now + Duration::minutes(5)),
            magic_expires_at: None,
            expires_at: login_now + Duration::minutes(5),
        })
        .await
        .expect("commit stale-lane generation");
    sqlx::query(
        "UPDATE mail_outbox SET next_attempt_at=clock_timestamp()-interval '1 minute'
          WHERE id=$1",
    )
    .bind(login_outbox)
    .execute(&fixture.sqlx)
    .await
    .expect("order stale login before mutation");
    sqlx::query("UPDATE project_email_policies SET status='disabled' WHERE project_id=$1")
        .bind(stale_project)
        .execute(&fixture.sqlx)
        .await
        .expect("stale login policy after enqueue");

    // Add a later fully eligible login head. The stale login must be ignored, then global order
    // compares this eligible login against the eligible mutation rather than letting the later
    // login leapfrog the earlier mutation from its own lane.
    let (healthy_login_id, _healthy_challenge, healthy_login_outbox) =
        committed_login_email_challenge(&fixture, &email, 140).await;
    sqlx::query(
        "UPDATE mail_outbox SET next_attempt_at=CASE
             WHEN id=$1 THEN clock_timestamp()-interval '3 minutes'
             WHEN id=$2 THEN clock_timestamp()-interval '2 minutes'
             WHEN id=$3 THEN clock_timestamp()-interval '1 minute'
           END WHERE id IN ($1,$2,$3)",
    )
    .bind(login_outbox)
    .bind(second_outbox)
    .bind(healthy_login_outbox)
    .execute(&fixture.sqlx)
    .await
    .expect("order stale login, eligible mutation, eligible login");

    let skewed_caller_now = OffsetDateTime::UNIX_EPOCH;
    let claimed = email
        .claim_due_mail(
            "mutation-worker",
            skewed_caller_now,
            skewed_caller_now + Duration::seconds(30),
        )
        .await
        .expect("claim mutation mail")
        .expect("newest mutation mail is claimable");
    assert_eq!(claimed.id, second_outbox);
    assert_eq!(claimed.challenge_id, second_challenge);
    let stale_head: (String, i16) =
        sqlx::query_as("SELECT status,attempts FROM mail_outbox WHERE id=$1")
            .bind(login_outbox)
            .fetch_one(&fixture.sqlx)
            .await
            .expect("read rejected stale login head");
    assert_eq!(stale_head, ("pending".to_owned(), 0));
    assert_eq!(claimed.challenge_generation, 2);
    assert_eq!(
        claimed.owner,
        MailChallengeOwner::IdentityMutation {
            intent_id,
            proof_slot_id: slot_id,
        }
    );
    let worker_aad = mail_context(&claimed);
    assert_eq!(worker_aad, second_aad);
    assert_eq!(
        fixture
            .protector
            .unprotect(
                ProtectedPurpose::EmailOutboxEnvelope,
                &worker_aad,
                &claimed.envelope,
            )
            .expect("worker decrypts mutation envelope")
            .as_slice(),
        b"second@example.test"
    );
    assert_eq!(
        fixture
            .protector
            .unprotect(
                ProtectedPurpose::EmailOutboxBody,
                &worker_aad,
                &claimed.body,
            )
            .expect("worker decrypts mutation body")
            .as_slice(),
        b"second body"
    );
    let first_status: String = sqlx::query_scalar("SELECT status FROM mail_outbox WHERE id=$1")
        .bind(first_outbox)
        .fetch_one(&fixture.sqlx)
        .await
        .expect("read superseded outbox");
    assert_eq!(first_status, "cancelled");

    let cancelled = fixture
        .repository
        .cancel(
            fixture.project_id,
            intent_id,
            final_record.revision,
            Uuid::new_v4(),
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .expect("terminalize while mail lease is active");
    assert_eq!(cancelled.status, IdentityMutationStatus::Cancelled);
    let active_lease: (String, Option<String>, Option<Vec<u8>>, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT status,lease_owner,envelope_ciphertext,body_ciphertext
               FROM mail_outbox WHERE id=$1",
    )
    .bind(second_outbox)
    .fetch_one(&fixture.sqlx)
    .await
    .expect("read actively leased terminal outbox");
    assert_eq!(active_lease.0, "leased");
    assert_eq!(active_lease.1.as_deref(), Some("mutation-worker"));
    assert!(active_lease.2.is_some());
    assert!(active_lease.3.is_some());
    email
        .finish_mail_attempt(
            &claimed,
            MailTransportOutcome::Delivered,
            None,
            OffsetDateTime::now_utc(),
        )
        .await
        .expect("finish preserved active lease after intent terminalization");
    let finished: (
        String,
        Option<String>,
        Option<OffsetDateTime>,
        Option<String>,
    ) = sqlx::query_as(
        "SELECT status,lease_owner,lease_expires_at,safe_outcome
               FROM mail_outbox WHERE id=$1",
    )
    .bind(second_outbox)
    .fetch_one(&fixture.sqlx)
    .await
    .expect("read finished terminal outbox");
    assert_eq!(finished.0, "delivered");
    assert!(finished.1.is_none());
    assert!(finished.2.is_none());
    assert_eq!(finished.3.as_deref(), Some("delivered"));

    // Symmetric stale-head case: an older mutation row with stale slot authority must not block
    // the fully eligible login lane, and the rejected mutation row must not burn an attempt.
    let stale_mutation_id = Uuid::new_v4();
    let (_stale_record, stale_slot, stale_challenge, _generation, _otp) =
        committed_candidate_email_challenge(
            &fixture,
            "stale-mutation-lane",
            stale_mutation_id,
            125,
        )
        .await;
    let mut stale_setup = fixture
        .sqlx
        .acquire()
        .await
        .expect("acquire stale mutation setup");
    sqlx::query("SET session_replication_role=replica")
        .execute(&mut *stale_setup)
        .await
        .expect("disable triggers for stale mutation authority");
    sqlx::query(
        "UPDATE identity_mutation_proof_slots
            SET application_security_revision=application_security_revision+1
          WHERE id=$1",
    )
    .bind(stale_slot)
    .execute(&mut *stale_setup)
    .await
    .expect("make mutation slot authority stale");
    sqlx::query("SET session_replication_role=origin")
        .execute(&mut *stale_setup)
        .await
        .expect("restore triggers after stale mutation authority");
    drop(stale_setup);
    let stale_mutation_outbox: Uuid =
        sqlx::query_scalar("SELECT id FROM mail_outbox WHERE challenge_id=$1")
            .bind(stale_challenge)
            .fetch_one(&fixture.sqlx)
            .await
            .expect("read stale mutation outbox");
    sqlx::query(
        "UPDATE mail_outbox SET next_attempt_at=CASE
             WHEN id=$1 THEN clock_timestamp()-interval '2 minutes'
             ELSE clock_timestamp()-interval '1 minute' END
          WHERE id IN ($1,$2)",
    )
    .bind(stale_mutation_outbox)
    .bind(healthy_login_outbox)
    .execute(&fixture.sqlx)
    .await
    .expect("order stale mutation before eligible login");
    let login_claim = email
        .claim_due_mail(
            "symmetric-login-worker",
            OffsetDateTime::UNIX_EPOCH,
            OffsetDateTime::UNIX_EPOCH + Duration::seconds(30),
        )
        .await
        .expect("claim eligible login behind stale mutation")
        .expect("healthy login remains claimable");
    assert_eq!(
        login_claim.owner,
        MailChallengeOwner::Login {
            transaction_id: healthy_login_id,
        }
    );
    let stale_untouched: (String, i16) =
        sqlx::query_as("SELECT status,attempts FROM mail_outbox WHERE id=$1")
            .bind(stale_mutation_outbox)
            .fetch_one(&fixture.sqlx)
            .await
            .expect("read untouched stale mutation head");
    assert_eq!(stale_untouched, ("pending".to_owned(), 0));
}

#[tokio::test]
async fn post_selection_invalidation_recompares_globally_before_switching_lanes() {
    let Some(fixture) = fixture().await else {
        return;
    };
    let email = PostgresPasswordlessEmailRepository::new_with_runtime_identity(
        fixture.database.clone(),
        "identity-mutation-test".to_owned(),
        fixture.incarnation,
        Vec::new(),
        Duration::minutes(5),
    );

    let mutation_a = Uuid::new_v4();
    let (_a_record, _a_slot, a_challenge, _a_generation, _a_otp) =
        committed_candidate_email_challenge(&fixture, "post-selection-mutation-a", mutation_a, 151)
            .await;
    let mutation_b = Uuid::new_v4();
    let (_b_record, b_slot, b_challenge, _b_generation, _b_otp) =
        committed_candidate_email_challenge(&fixture, "post-selection-mutation-b", mutation_b, 152)
            .await;
    let (_login_id, _login_challenge, login_outbox) =
        committed_login_email_challenge(&fixture, &email, 153).await;
    let a_outbox: Uuid = sqlx::query_scalar("SELECT id FROM mail_outbox WHERE challenge_id=$1")
        .bind(a_challenge)
        .fetch_one(&fixture.sqlx)
        .await
        .expect("read mutation A outbox");
    let b_outbox: Uuid = sqlx::query_scalar("SELECT id FROM mail_outbox WHERE challenge_id=$1")
        .bind(b_challenge)
        .fetch_one(&fixture.sqlx)
        .await
        .expect("read mutation B outbox");
    sqlx::query(
        "UPDATE mail_outbox SET next_attempt_at=CASE
             WHEN id=$1 THEN clock_timestamp()-interval '3 minutes'
             WHEN id=$2 THEN clock_timestamp()-interval '2 minutes'
             WHEN id=$3 THEN clock_timestamp()-interval '1 minute'
           END,
           useful_until=clock_timestamp()+interval '5 minutes'
         WHERE id IN ($1,$2,$3)",
    )
    .bind(a_outbox)
    .bind(b_outbox)
    .bind(login_outbox)
    .execute(&fixture.sqlx)
    .await
    .expect("order mutation A, mutation B, then login L");

    // Hold A's canonical intent lock and stage an expired attached receipt. Discovery sees the
    // pre-commit eligible A, then authoritative claim blocks. Once committed, A must terminalize;
    // the bounded loop must compare B against L again rather than falling through to login.
    let mut invalidator = fixture
        .sqlx
        .begin()
        .await
        .expect("begin mutation A invalidator");
    sqlx::query("SELECT id FROM identity_mutation_intents WHERE id=$1 FOR UPDATE")
        .bind(mutation_a)
        .fetch_one(&mut *invalidator)
        .await
        .expect("hold mutation A intent lock");
    sqlx::query("SET LOCAL session_replication_role=replica")
        .execute(&mut *invalidator)
        .await
        .expect("disable immutable receipt trigger for staged elapsed-time fixture");
    let expired_receipts = sqlx::query(
        "UPDATE identity_proof_receipts
            SET issued_at=clock_timestamp()-interval '5 minutes',
                expires_at=clock_timestamp()-interval '1 second',
                created_at=clock_timestamp()-interval '5 minutes'
          WHERE intent_id=$1",
    )
    .bind(mutation_a)
    .execute(&mut *invalidator)
    .await
    .expect("stage mutation A invalidation")
    .rows_affected();
    assert!(
        expired_receipts > 0,
        "mutation A must have an attached receipt"
    );
    sqlx::query("SET LOCAL session_replication_role=origin")
        .execute(&mut *invalidator)
        .await
        .expect("restore receipt authority triggers before race");
    let invalidator_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *invalidator)
        .await
        .expect("read mutation A invalidator backend");

    let claiming = tokio::spawn(async move {
        email
            .claim_due_mail(
                "global-recomparison-worker",
                OffsetDateTime::UNIX_EPOCH,
                OffsetDateTime::UNIX_EPOCH + Duration::seconds(30),
            )
            .await
    });
    wait_for_backend_blocked_by(
        &fixture.sqlx,
        invalidator_pid,
        "selected mutation A authoritative intent lock",
    )
    .await;
    invalidator
        .commit()
        .await
        .expect("commit mutation A post-selection invalidation");

    let claimed = claiming
        .await
        .expect("join globally recomparing claim")
        .expect("post-selection invalidation is not infrastructure failure")
        .expect("mutation B remains claimable");
    assert_eq!(claimed.id, b_outbox);
    assert_eq!(
        claimed.owner,
        MailChallengeOwner::IdentityMutation {
            intent_id: mutation_b,
            proof_slot_id: b_slot,
        }
    );
    let login_state: (String, i16, Option<String>) =
        sqlx::query_as("SELECT status,attempts,lease_owner FROM mail_outbox WHERE id=$1")
            .bind(login_outbox)
            .fetch_one(&fixture.sqlx)
            .await
            .expect("read non-leapfrogging login L");
    assert_eq!(login_state, ("pending".to_owned(), 0, None));
    let mutation_a_terminal: (String, Option<Vec<u8>>, String) = sqlx::query_as(
        "SELECT intent.status,result.create_result_ciphertext,outbox.status
           FROM identity_mutation_intents intent
           JOIN identity_mutation_create_results result ON result.intent_id=intent.id
           JOIN email_challenges challenge ON challenge.identity_mutation_intent_id=intent.id
           JOIN mail_outbox outbox ON outbox.challenge_id=challenge.id
          WHERE intent.id=$1",
    )
    .bind(mutation_a)
    .fetch_one(&fixture.sqlx)
    .await
    .expect("read terminalized mutation A");
    assert_eq!(
        mutation_a_terminal,
        ("expired".to_owned(), None, "cancelled".to_owned())
    );
}

#[tokio::test]
async fn control_identity_inventory_is_mixed_safe_exact_and_fails_closed_on_row_101() {
    let Some(fixture) = fixture().await else {
        return;
    };
    let email_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO email_identities
         (id,project_id,user_id,status,identity_revision,canonicalization_version,
          address_ciphertext,address_key_version,verified_at)
         VALUES ($1,$2,$3,'active',3,1,$4,1,clock_timestamp())",
    )
    .bind(email_id)
    .bind(fixture.project_id)
    .bind(fixture.user_id)
    .bind(vec![0x5a_u8; 41])
    .execute(&fixture.sqlx)
    .await
    .expect("seed encrypted email identity");

    let repository = PostgresControlLifecycleRepository::new(
        fixture.database.clone(),
        test_projection_materializer(),
    );
    let inventory = repository
        .list_project_user_identities(fixture.project_id, fixture.user_id, 100)
        .await
        .expect("bounded mixed identity inventory");
    assert_eq!(inventory.len(), 2);
    let provider = inventory
        .iter()
        .find(|identity| identity.id == fixture.identity_id)
        .expect("provider identity");
    assert_eq!(provider.provider_key.as_deref(), Some("main"));
    assert!(provider.is_primary_source);
    let email = inventory
        .iter()
        .find(|identity| identity.id == email_id)
        .expect("email identity");
    assert_eq!(email.identity_revision, 3);
    assert_eq!(email.provider_key, None);
    assert!(!email.is_primary_source);

    sqlx::query(
        "INSERT INTO linked_identities
         (id,project_id,user_id,created_via_provider_configuration_id,issuer,subject,status,
          identity_revision,source_profile_digest,observed_at)
         SELECT md5($1::TEXT || series::TEXT)::UUID,$1,$2,$3,
                'https://issuer.example','inventory-' || series::TEXT,'active',1,public.owlauth_provider_source_profile_digest(NULL,NULL,NULL),clock_timestamp()
           FROM generate_series(1,99) AS series",
    )
    .bind(fixture.project_id)
    .bind(fixture.user_id)
    .bind(fixture.provider_id)
    .execute(&fixture.sqlx)
    .await
    .expect("seed row 101 probe");
    assert_eq!(
        repository
            .list_project_user_identities(fixture.project_id, fixture.user_id, 100)
            .await
            .expect_err("mixed row 101 must fail closed rather than truncate"),
        ApplicationError::Integrity
    );
}
