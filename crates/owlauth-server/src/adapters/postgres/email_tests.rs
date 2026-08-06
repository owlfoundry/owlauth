use std::{
    collections::BTreeMap,
    env,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use sea_orm::Database;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, postgres::PgPoolOptions};
use testcontainers::{
    GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor, wait::LogWaitStrategy},
    runners::AsyncRunner,
};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    authentication::PostgresAuthenticationRepository, email::PostgresPasswordlessEmailRepository,
    email_control::PostgresEmailControlRepository, readiness::PostgresReadinessAdapter,
    runtime_authority::PostgresRuntimeAuthorityRepository,
};
use crate::adapters::{
    runtime_security::{
        EncryptedFileProviderSecretResolver, RuntimeKeyMaterial, SoftwareRuntimeProtector,
    },
    software_store::EncryptedFileStore,
    system::{Sha256RequestDigester, SystemClock},
};
use crate::application::{
    AdmittedEmailMethod, AuthenticationRepository, BindHostedBrowser, CommitEmailGeneration,
    CompleteEmailProof, ConfigurationSecretProvisioner, CreateLoginTransaction,
    CreateSmtpConfiguration, DeploymentSmtpDesiredStatus, DeploymentSmtpGeneration,
    DeploymentSmtpRegistry, EmailControlPort, EmailControlService, EmailProofKind,
    EstablishMagicTransferContext, LoginRevisionSnapshot, MailOutboxRepository,
    MailTransportOutcome, PasswordlessEmailRepository, PrepareSmtpConfiguration, PrepareSmtpTest,
    ProtectedValue, ResolveMagicTransferContext, RuntimeAuthorityRepository, RuntimeProtector,
    SelectEmailMethod, SmtpControlStatus, SmtpControlTlsMode, SmtpTlsMode, VerifyEmailProof,
    VersionedDigest,
};

const POSTGRES_PORT: u16 = 5432;
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

async fn seed_legacy_deployment_smtp(pool: &PgPool, generation: &DeploymentSmtpGeneration) {
    let tls_mode = match generation.tls_mode {
        SmtpTlsMode::ImplicitTls => "implicit_tls",
        SmtpTlsMode::StartTlsRequired => "starttls_required",
        SmtpTlsMode::DevelopmentLoopbackPlaintext => {
            panic!("legacy deployment fixture is TLS-only")
        }
    };
    sqlx::query(
        "INSERT INTO deployment_smtp_generations
         (generation,status,revision,security_eligibility_revision,host,port,tls_mode,
          sender_address,credential_ref,safe_fingerprint,explicitly_allowed_private_ips,
          material_owner_id)
         VALUES ($1,'reconciled',1,1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(generation.generation)
    .bind(&generation.host)
    .bind(i32::from(generation.port))
    .bind(tls_mode)
    .bind(&generation.sender_address)
    .bind(&generation.credential_ref)
    .bind(generation.safe_fingerprint.to_vec())
    .bind(serde_json::json!(
        generation
            .explicitly_allowed_private_ips
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    ))
    .bind(Uuid::new_v4())
    .execute(pool)
    .await
    .expect("seed legacy deployment SMTP generation");
}

#[derive(Default)]
struct CountingSmtpProvisioner {
    writes: AtomicUsize,
}

struct BarrierSmtpProvisioner {
    entered: tokio::sync::Semaphore,
    release: tokio::sync::Semaphore,
    writes: AtomicUsize,
}

impl BarrierSmtpProvisioner {
    fn new() -> Self {
        Self {
            entered: tokio::sync::Semaphore::new(0),
            release: tokio::sync::Semaphore::new(0),
            writes: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl ConfigurationSecretProvisioner for BarrierSmtpProvisioner {
    fn request_fingerprint(&self, value: &[u8]) -> [u8; 32] {
        Sha256::digest(value).into()
    }

    async fn provision_if_absent(
        &self,
        _alias: String,
        _value: Zeroizing<Vec<u8>>,
    ) -> Result<(), crate::application::ApplicationError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.entered.add_permits(1);
        self.release
            .acquire()
            .await
            .expect("test provision barrier remains open")
            .forget();
        Ok(())
    }
}

#[async_trait]
impl ConfigurationSecretProvisioner for CountingSmtpProvisioner {
    fn request_fingerprint(&self, value: &[u8]) -> [u8; 32] {
        Sha256::digest(value).into()
    }

    async fn provision_if_absent(
        &self,
        _alias: String,
        _value: Zeroizing<Vec<u8>>,
    ) -> Result<(), crate::application::ApplicationError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn digest(value: u8) -> VersionedDigest {
    digest_at(value, 1)
}

fn digest_at(value: u8, key_version: i32) -> VersionedDigest {
    VersionedDigest {
        value: [value; 32],
        key_version,
    }
}

fn protected(value: u8) -> ProtectedValue {
    ProtectedValue {
        ciphertext: vec![value; 64],
        key_version: 1,
    }
}

fn runtime_protector(
    active_version: i32,
    retained: impl IntoIterator<Item = (i32, u8)>,
) -> SoftwareRuntimeProtector {
    let active_seed = u8::try_from(active_version).expect("test key version fits in one byte");
    SoftwareRuntimeProtector::new(
        "email-alias-test".to_owned(),
        active_version,
        RuntimeKeyMaterial::new([active_seed; 32], [active_seed + 32; 32]),
        retained
            .into_iter()
            .map(|(version, value)| {
                (
                    version,
                    RuntimeKeyMaterial::new([value; 32], [value + 32; 32]),
                )
            })
            .collect::<BTreeMap<_, _>>(),
    )
    .expect("test Runtime protector")
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
    .unwrap_or_else(|_| panic!("{label} did not establish the required PostgreSQL lock wait"))
}

async fn spawn_trailing_authority_mutation(
    pool: &PgPool,
    authority_id: Uuid,
    mutation: &'static str,
) -> (tokio::task::JoinHandle<()>, i32) {
    let racing_pool = pool.clone();
    let (mutation_pid_sender, mutation_pid_receiver) = tokio::sync::oneshot::channel();
    let mutation_task = tokio::spawn(async move {
        let mut transaction = racing_pool.begin().await.expect("begin trailing authority");
        let mutation_backend_pid = sqlx::query_scalar::<_, i32>("SELECT pg_backend_pid()")
            .fetch_one(&mut *transaction)
            .await
            .expect("read trailing-authority backend pid");
        mutation_pid_sender
            .send(mutation_backend_pid)
            .expect("publish trailing-authority backend pid");
        sqlx::query(mutation)
            .bind(authority_id)
            .execute(&mut *transaction)
            .await
            .expect("apply trailing authority mutation");
        transaction
            .commit()
            .await
            .expect("commit trailing authority");
    });
    let mutation_backend_pid = mutation_pid_receiver
        .await
        .expect("receive trailing-authority backend pid");
    (mutation_task, mutation_backend_pid)
}

async fn reset_mail_for_lock_order(pool: &PgPool, challenge_id: Uuid) {
    sqlx::query(
        "UPDATE mail_outbox SET status='pending',attempts=0,
         next_attempt_at=clock_timestamp()-interval '1 second',
         useful_until=clock_timestamp()+interval '5 minutes',
         lease_owner=NULL,lease_expires_at=NULL,safe_outcome=NULL,
         delivered_at=NULL,terminal_at=NULL,redacted_at=NULL WHERE challenge_id=$1",
    )
    .bind(challenge_id)
    .execute(pool)
    .await
    .expect("reset mail for proof/claim lock-order race");
}

#[allow(
    clippy::too_many_lines,
    reason = "both deterministic PostgreSQL wait chains keep the canonical proof/claim order reviewable"
)]
async fn assert_proof_and_mail_claim_lock_order(
    pool: &PgPool,
    email: &PostgresPasswordlessEmailRepository,
    proof: VerifyEmailProof,
) {
    let challenge_id = proof.challenge_id;
    let transaction_id = proof.transaction_id;
    let now = proof.now + Duration::seconds(1);

    // Proof first: the final challenge lock is held, so proof visibly retains its exclusive
    // login lock while waiting. A mail claim must then wait behind proof at the login row rather
    // than taking the challenge first and forming the opposite edge of a deadlock.
    reset_mail_for_lock_order(pool, challenge_id).await;
    let mut challenge_blocker = pool.begin().await.expect("begin challenge blocker");
    sqlx::query("SELECT id FROM email_challenges WHERE id=$1 FOR UPDATE")
        .bind(challenge_id)
        .fetch_one(&mut *challenge_blocker)
        .await
        .expect("hold final challenge lock");
    let challenge_blocker_pid = sqlx::query_scalar::<_, i32>("SELECT pg_backend_pid()")
        .fetch_one(&mut *challenge_blocker)
        .await
        .expect("read challenge-blocker backend pid");
    let proof_repository = email.clone();
    let proof_command = proof.clone();
    let proof_task =
        tokio::spawn(async move { proof_repository.verify_email_proof(proof_command).await });
    let proof_pid =
        wait_for_backend_blocked_by(pool, challenge_blocker_pid, "proof final challenge lock")
            .await;
    let claim_repository = email.clone();
    let claim_task = tokio::spawn(async move {
        claim_repository
            .claim_due_mail("proof-first-order", now, now + Duration::seconds(30))
            .await
    });
    let claim_pid = wait_for_backend_blocked_by(pool, proof_pid, "claim login behind proof").await;
    assert_ne!(
        claim_pid, proof_pid,
        "proof and claim need distinct backends"
    );
    challenge_blocker
        .commit()
        .await
        .expect("release final challenge lock");
    assert!(matches!(
        proof_task.await.expect("join proof-first proof"),
        Ok(crate::application::EmailProofDecision::Accepted(_))
    ));
    assert!(
        claim_task
            .await
            .expect("join proof-first claim")
            .expect("proof-first claim result")
            .is_some()
    );

    // Mail first: holding only the final outbox row lets claim retain every shared authority
    // lock. Proof must wait at the first exclusive login lock; it cannot acquire challenge first.
    reset_mail_for_lock_order(pool, challenge_id).await;
    let mut outbox_blocker = pool.begin().await.expect("begin outbox blocker");
    sqlx::query("SELECT id FROM mail_outbox WHERE challenge_id=$1 FOR UPDATE")
        .bind(challenge_id)
        .fetch_one(&mut *outbox_blocker)
        .await
        .expect("hold final outbox lock");
    let outbox_blocker_pid = sqlx::query_scalar::<_, i32>("SELECT pg_backend_pid()")
        .fetch_one(&mut *outbox_blocker)
        .await
        .expect("read outbox-blocker backend pid");
    let claim_repository = email.clone();
    let claim_task = tokio::spawn(async move {
        claim_repository
            .claim_due_mail("claim-first-order", now, now + Duration::seconds(30))
            .await
    });
    let claim_pid =
        wait_for_backend_blocked_by(pool, outbox_blocker_pid, "claim final outbox lock").await;
    let proof_repository = email.clone();
    let proof_task = tokio::spawn(async move { proof_repository.verify_email_proof(proof).await });
    let proof_pid = wait_for_backend_blocked_by(pool, claim_pid, "proof login behind claim").await;
    assert_ne!(
        proof_pid, claim_pid,
        "proof and claim need distinct backends"
    );
    outbox_blocker
        .commit()
        .await
        .expect("release final outbox lock");
    assert!(
        claim_task
            .await
            .expect("join claim-first claim")
            .expect("claim-first claim result")
            .is_some()
    );
    assert!(matches!(
        proof_task.await.expect("join claim-first proof"),
        Ok(crate::application::EmailProofDecision::Accepted(_))
    ));

    sqlx::query(
        "UPDATE mail_outbox SET status='delivered',attempts=2,lease_owner=NULL,lease_expires_at=NULL
         WHERE challenge_id=$1",
    )
    .bind(challenge_id)
    .execute(pool)
    .await
    .expect("restore delivered mail after lock-order race");
    let login_status: String =
        sqlx::query_scalar("SELECT status FROM login_transactions WHERE id=$1")
            .bind(transaction_id)
            .fetch_one(pool)
            .await
            .expect("proof/claim race preserves login");
    assert_eq!(login_status, "email_challenge_pending");
}

async fn restore_claim_race_fixture(
    pool: &PgPool,
    challenge_id: Uuid,
    authority_id: Uuid,
    restore: &'static str,
    reset_outbox: bool,
) {
    sqlx::query(restore)
        .bind(authority_id)
        .execute(pool)
        .await
        .expect("restore exact claim authority");
    if reset_outbox {
        sqlx::query(
            "UPDATE mail_outbox SET status='pending',attempts=0,lease_owner=NULL,lease_expires_at=NULL
             WHERE challenge_id=$1",
        )
        .bind(challenge_id)
        .execute(pool)
        .await
        .expect("reset claimed fixture");
    }
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the deterministic commit-order harness keeps both commit orderings and exact authority mutation visible"
)]
async fn assert_mail_claim_fence_commit_orders(
    pool: &PgPool,
    email: &PostgresPasswordlessEmailRepository,
    challenge_id: Uuid,
    authority_id: Uuid,
    mutation: &'static str,
    restore: &'static str,
    label: &'static str,
    now: OffsetDateTime,
) {
    // Authority commit first: the claim blocks on the exact shared fence, then observes the
    // committed disable/supersession and returns without consuming an attempt or lease.
    let mut authority = pool.begin().await.expect("begin authority-first race");
    let mutation_backend_pid = sqlx::query_scalar::<_, i32>("SELECT pg_backend_pid()")
        .fetch_one(&mut *authority)
        .await
        .expect("read authority-first backend pid");
    sqlx::query(mutation)
        .bind(authority_id)
        .execute(&mut *authority)
        .await
        .expect("hold exact authority mutation");
    let racing_email = email.clone();
    let claim = tokio::spawn(async move {
        racing_email
            .claim_due_mail(
                &format!("authority-first-{label}"),
                now,
                now + Duration::seconds(30),
            )
            .await
    });
    let claim_pid = wait_for_backend_blocked_by(pool, mutation_backend_pid, label).await;
    assert_ne!(
        claim_pid, mutation_backend_pid,
        "claim must use a distinct backend"
    );
    authority.commit().await.expect("commit authority first");
    assert!(
        claim
            .await
            .expect("join authority-first claim")
            .expect("authority-first claim result")
            .is_none(),
        "a claim after committed {label} must fail closed"
    );
    let untouched: (String, i16, Option<String>) =
        sqlx::query_as("SELECT status,attempts,lease_owner FROM mail_outbox WHERE challenge_id=$1")
            .bind(challenge_id)
            .fetch_one(pool)
            .await
            .expect("authority-first unchanged outbox");
    assert_eq!(untouched, ("pending".to_owned(), 0, None));
    restore_claim_race_fixture(pool, challenge_id, authority_id, restore, false).await;

    // Claim commit first: hold only the final outbox row. The claim acquires every authority
    // fence and waits there; the conflicting authority mutation then waits behind the claim.
    // Releasing the final row lets the lease commit before the authority transition.
    let mut outbox_blocker = pool
        .begin()
        .await
        .expect("begin claim-first outbox blocker");
    sqlx::query("SELECT id FROM mail_outbox WHERE challenge_id=$1 FOR UPDATE")
        .bind(challenge_id)
        .fetch_one(&mut *outbox_blocker)
        .await
        .expect("hold final outbox lock");
    let outbox_blocker_pid = sqlx::query_scalar::<_, i32>("SELECT pg_backend_pid()")
        .fetch_one(&mut *outbox_blocker)
        .await
        .expect("read outbox-blocker backend pid");
    let racing_email = email.clone();
    let claim = tokio::spawn(async move {
        racing_email
            .claim_due_mail(
                &format!("claim-first-{label}"),
                now + Duration::seconds(1),
                now + Duration::seconds(31),
            )
            .await
    });
    let claim_pid = wait_for_backend_blocked_by(pool, outbox_blocker_pid, label).await;
    let (authority, mutation_backend_pid) =
        spawn_trailing_authority_mutation(pool, authority_id, mutation).await;
    assert_eq!(
        wait_for_backend_blocked_by(pool, claim_pid, label).await,
        mutation_backend_pid,
        "{label} must wait behind the claim backend that already won authority"
    );
    outbox_blocker
        .commit()
        .await
        .expect("release claim-first outbox blocker");
    assert!(
        claim
            .await
            .expect("join claim-first claim")
            .expect("claim-first result")
            .is_some(),
        "the authority-winning claim may proceed"
    );
    authority.await.expect("join trailing authority");
    restore_claim_race_fixture(pool, challenge_id, authority_id, restore, true).await;
}

async fn start_postgres() -> Option<(testcontainers::ContainerAsync<GenericImage>, String)> {
    let wait = WaitFor::log(LogWaitStrategy::stderr(
        "database system is ready to accept connections",
    ));
    let container = match GenericImage::new("postgres", "17-bookworm")
        .with_exposed_port(POSTGRES_PORT.tcp())
        .with_wait_for(wait)
        .with_env_var("POSTGRES_DB", "owlauth_email_test")
        .with_env_var("POSTGRES_USER", "owlauth")
        .with_env_var("POSTGRES_PASSWORD", "owlauth_test")
        .start()
        .await
    {
        Ok(container) => container,
        Err(error) => {
            assert!(
                !docker_is_required(),
                "PostgreSQL email test container is required: {error}"
            );
            eprintln!("skipping email integration test: Docker unavailable: {error}");
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
        format!("postgres://owlauth:owlauth_test@{host}:{port}/owlauth_email_test"),
    ))
}

#[allow(
    clippy::too_many_lines,
    reason = "the shared PostgreSQL fixture seeds one complete email authority graph"
)]
async fn seed_email_authority(
    pool: &PgPool,
    now: OffsetDateTime,
) -> (Uuid, Uuid, Uuid, AdmittedEmailMethod) {
    let project_id = Uuid::new_v4();
    let application_id = Uuid::new_v4();
    let smtp_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO projects (id, public_id, display_name, status, metadata_revision, security_revision)
         VALUES ($1, $2, 'Email Project', 'active', 1, 1)",
    )
    .bind(project_id)
    .bind(format!("prj_{}", project_id.simple()))
    .execute(pool)
    .await
    .expect("seed project");
    sqlx::query(
        "INSERT INTO applications (id, project_id, public_id, display_name, application_type, status, revision, metadata_revision, security_revision)
         VALUES ($1, $2, $3, 'Email App', 'web', 'active', 1, 1, 1)",
    )
    .bind(application_id)
    .bind(project_id)
    .bind(format!("app_{}", application_id.simple()))
    .execute(pool)
    .await
    .expect("seed application");
    sqlx::query(
        "INSERT INTO application_publishable_keys
         (id,project_id,application_id,public_id,status,revision)
         VALUES ($1,$2,$3,$4,'active',1)",
    )
    .bind(Uuid::new_v4())
    .bind(project_id)
    .bind(application_id)
    .bind(format!("pk_{}", application_id.simple()))
    .execute(pool)
    .await
    .expect("seed publishable key");
    sqlx::query(
        "INSERT INTO application_redirects (project_id, application_id, redirect_uri, redirect_type)
         VALUES ($1, $2, 'https://app.example/callback', 'web')",
    )
    .bind(project_id)
    .bind(application_id)
    .execute(pool)
    .await
    .expect("seed redirect");
    sqlx::query(
        "INSERT INTO project_policies (project_id, claims_revision, session_revision, claims_policy, session_policy)
         VALUES ($1, 1, 1, '{\"access_token_lifetime_seconds\":900}'::jsonb,
          '{\"browser_session_reuse\":false,\"browser_session_reuse_max_age_seconds\":28800}'::jsonb)",
    )
    .bind(project_id)
    .execute(pool)
    .await
    .expect("seed project policy");
    let ring_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO project_key_rings
           (id,project_id,issuer,purpose,algorithm,revision,signing_epoch)
         VALUES ($1,$2,$3,'application_tokens','EdDSA',1,1)",
    )
    .bind(ring_id)
    .bind(project_id)
    .bind(format!(
        "https://runtime.example/v1/projects/prj_{}/",
        project_id.simple()
    ))
    .execute(pool)
    .await
    .expect("seed email Project signing ring");
    sqlx::query(
        "INSERT INTO project_signing_keys
           (id,project_id,ring_id,kid,public_jwk,signer_ref,state,ring_revision,
            provisioned_at,published_at,activated_at,sign_not_before)
         VALUES ($1,$2,$3,'kid_email_ready',
           '{\"alg\":\"EdDSA\",\"crv\":\"Ed25519\",\"kid\":\"kid_email_ready\",\"kty\":\"OKP\",\"use\":\"sig\",\"x\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}'::jsonb,
           'signer/email/ready','active',1,$4,$4,$4,$4)",
    )
    .bind(Uuid::new_v4())
    .bind(project_id)
    .bind(ring_id)
    .bind(now)
    .execute(pool)
    .await
    .expect("seed active email Project signing key");
    sqlx::query(
        "UPDATE project_email_policies SET status='enabled', policy_revision=2, security_revision=2,
         otp_enabled=TRUE, magic_link_enabled=TRUE, otp_digits=6, otp_validity_seconds=600,
         otp_max_attempts=5, resend_after_seconds=30, max_generations=5,
         magic_validity_seconds=600, signup_enabled=TRUE WHERE project_id=$1",
    )
    .bind(project_id)
    .execute(pool)
    .await
    .expect("enable email policy");
    sqlx::query(
        "INSERT INTO application_email_assignments (project_id, application_id, status, security_revision)
         VALUES ($1, $2, 'active', 1)",
    )
    .bind(project_id)
    .bind(application_id)
    .execute(pool)
    .await
    .expect("seed email assignment");
    sqlx::query(
        "INSERT INTO project_smtp_configurations
         (id, project_id, status, generation, revision, security_eligibility_revision, host, port,
          tls_mode, sender_address, sender_name, reply_to, credential_ref, safe_fingerprint, created_at, updated_at)
         VALUES ($1,$2,'active',1,1,1,'smtp.example.com',465,'implicit_tls','login@example.com',
          'OwlAuth 登录','reply@example.com','smtp_test_ref',$3,$4,$4)",
    )
    .bind(smtp_id)
    .bind(project_id)
    .bind(vec![7_u8; 32])
    .bind(now)
    .execute(pool)
    .await
    .expect("seed SMTP");
    let runtime_incarnation = Uuid::nil();
    sqlx::query(
        "INSERT INTO runtime_process_incarnations
         (process_id,process_incarnation,started_at) VALUES ('runtime-1',$1,$2)
         ON CONFLICT (process_id) DO UPDATE SET
           process_incarnation=EXCLUDED.process_incarnation,started_at=EXCLUDED.started_at",
    )
    .bind(runtime_incarnation)
    .bind(now)
    .execute(pool)
    .await
    .expect("seed SMTP Runtime incarnation");
    sqlx::query(
        "INSERT INTO project_smtp_runtime_readiness
         (project_id,configuration_id,generation,process_id,process_incarnation,state,checked_at,lease_expires_at)
         VALUES ($1,$2,1,'runtime-1',$3,'ready',$4,$5)",
    )
    .bind(project_id)
    .bind(smtp_id)
    .bind(runtime_incarnation)
    .bind(now)
    .bind(now + Duration::hours(1))
    .execute(pool)
    .await
    .expect("seed SMTP Runtime readiness");
    sqlx::query(
        "INSERT INTO email_protection_runtime_readiness
         (process_id,process_incarnation,state,failure_class,checked_at,lease_expires_at)
         VALUES ('runtime-1',$1,'ready',NULL,$2,$3)
         ON CONFLICT (process_id) DO UPDATE SET
           process_incarnation=EXCLUDED.process_incarnation,state=EXCLUDED.state,
           failure_class=EXCLUDED.failure_class,checked_at=EXCLUDED.checked_at,
           lease_expires_at=EXCLUDED.lease_expires_at",
    )
    .bind(runtime_incarnation)
    .bind(now)
    .bind(now + Duration::hours(1))
    .execute(pool)
    .await
    .expect("seed exact email protection readiness");
    (
        project_id,
        application_id,
        smtp_id,
        AdmittedEmailMethod {
            policy_revision: 2,
            security_revision: 2,
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
            transferred_magic_link_enabled: true,
            smtp_selection_kind: "project".to_owned(),
            smtp_configuration_id: Some(smtp_id),
            smtp_generation: 1,
            smtp_security_eligibility_revision: 1,
        },
    )
}

fn completion(
    verification: VerifyEmailProof,
    user_seed: &str,
    identity_seed: Uuid,
) -> CompleteEmailProof {
    CompleteEmailProof {
        verification,
        new_user_id: Uuid::new_v4(),
        new_user_public_id: format!("usr_{user_seed}"),
        new_identity_id: identity_seed,
        durable_address: protected(91),
        verified_challenge_lookup: digest(5),
        lookup_aliases: vec![digest(5), digest_at(6, 2)],
        active_alias: digest(5),
        alias_authority_revision: 1,
        browser_session_id: Uuid::new_v4(),
        existing_browser_credential: None,
        browser_credential: digest(93),
        handoff_id: Uuid::new_v4(),
        handoff_ticket: digest(94),
    }
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one real PostgreSQL journey proves the email parent and completion invariants"
)]
async fn email_generation_sibling_proofs_and_completion_are_one_winner_in_postgres() {
    let Some((_container, url)) = start_postgres().await else {
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .expect("connect sqlx");
    MIGRATOR.run(&pool).await.expect("migrate schema");
    sqlx::query(
        "INSERT INTO email_identity_alias_authority
         (singleton,revision,write_version,target_version,accepted_versions)
         VALUES (TRUE,1,1,1,'[1,2]'::jsonb)",
    )
    .execute(&pool)
    .await
    .expect("seed identity alias authority");
    let database = Database::connect(&url).await.expect("connect SeaORM");
    let now = OffsetDateTime::now_utc();
    let (project_id, application_id, smtp_id, email_method) =
        seed_email_authority(&pool, now).await;
    let email_control = PostgresEmailControlRepository::new(database.clone());
    let email = PostgresPasswordlessEmailRepository::new(database.clone());
    sqlx::query(
        "DELETE FROM project_smtp_runtime_readiness
         WHERE project_id=$1 AND configuration_id=$2",
    )
    .bind(project_id)
    .bind(smtp_id)
    .execute(&pool)
    .await
    .expect("remove background readiness fixture before Runtime SMTP test");
    let operation_id = Uuid::new_v4();
    let smtp_test = PrepareSmtpTest {
        id: operation_id,
        configuration_id: smtp_id,
        recipient_ref: "smtp_test_recipient_ref".to_owned(),
        idempotency_key: "smtp-test-stable-1".to_owned(),
        request_digest: vec![44; 32],
        expected_revision: 1,
        correlation_id: Uuid::new_v4(),
    };
    let prepared = email_control
        .prepare_smtp_test(project_id, smtp_test.clone(), now)
        .await
        .expect("enqueue durable SMTP test");
    assert_eq!(
        prepared.record.state,
        crate::application::SmtpTestState::Preparing
    );
    let test_barrier = Arc::new(BarrierSmtpProvisioner::new());
    let paused_repository = PostgresEmailControlRepository::new(database.clone());
    let paused_barrier = test_barrier.clone();
    let paused_digest = smtp_test.request_digest.clone();
    let paused = tokio::spawn(async move {
        paused_repository
            .provision_and_finalize_smtp_test_enqueue(
                project_id,
                operation_id,
                &paused_digest,
                paused_barrier.as_ref(),
                Zeroizing::new(b"recipient@example.com".to_vec()),
                now,
            )
            .await
    });
    test_barrier
        .entered
        .acquire()
        .await
        .expect("SMTP-test provisioning reaches external barrier")
        .forget();
    let concurrent = CountingSmtpProvisioner::default();
    let prepared = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        email_control.provision_and_finalize_smtp_test_enqueue(
            project_id,
            operation_id,
            &smtp_test.request_digest,
            &concurrent,
            Zeroizing::new(b"recipient@example.com".to_vec()),
            now,
        ),
    )
    .await
    .expect("same-operation database claim progresses while external store is paused")
    .expect("concurrent same-reference retry finalizes");
    assert_eq!(prepared.state, crate::application::SmtpTestState::Pending);
    test_barrier.release.add_permits(1);
    let converged = paused
        .await
        .expect("join paused SMTP-test provisioning")
        .expect("paused caller converges on concurrent finalize");
    assert_eq!(converged.id, prepared.id);
    assert_eq!(test_barrier.writes.load(Ordering::SeqCst), 1);
    assert_eq!(concurrent.writes.load(Ordering::SeqCst), 1);
    let replay = email_control
        .prepare_smtp_test(project_id, smtp_test.clone(), now)
        .await
        .expect("idempotent pending replay");
    assert_eq!(replay.record.id, operation_id);
    let claimed = email
        .claim_smtp_test("runtime-a", now, now + Duration::seconds(30))
        .await
        .expect("claim test")
        .expect("test available");
    assert_eq!(claimed.idempotency_key, "smtp-test-stable-1");
    assert!(
        email
            .claim_smtp_test("runtime-b", now, now + Duration::seconds(30))
            .await
            .expect("second claim")
            .is_none()
    );
    email
        .finish_smtp_test(
            &claimed,
            MailTransportOutcome::Delivered,
            now + Duration::seconds(1),
        )
        .await
        .expect("finish Runtime SMTP test");
    let test_readiness: (String, Uuid, bool) = sqlx::query_as(
        "SELECT state,process_incarnation,lease_expires_at>$3
         FROM project_smtp_runtime_readiness
         WHERE project_id=$1 AND configuration_id=$2 AND process_id='runtime-1'",
    )
    .bind(project_id)
    .bind(smtp_id)
    .bind(now + Duration::seconds(1))
    .fetch_one(&pool)
    .await
    .expect("delivered Runtime SMTP test publishes exact-generation readiness atomically");
    assert_eq!(test_readiness, ("ready".to_owned(), Uuid::nil(), true));
    let delivered = email_control
        .get_smtp_test(project_id, operation_id)
        .await
        .expect("read result");
    assert_eq!(
        delivered.state,
        crate::application::SmtpTestState::Delivered
    );
    assert_eq!(delivered.outcome, Some(MailTransportOutcome::Delivered));
    let cleanup = email
        .claim_smtp_secret_cleanup(
            "runtime-cleanup",
            now + Duration::seconds(2),
            now + Duration::seconds(32),
        )
        .await
        .expect("claim recipient cleanup")
        .expect("terminal recipient requires erasure");
    assert_eq!(cleanup.recipient_ref, "smtp_test_recipient_ref");
    email
        .finish_smtp_secret_cleanup(&cleanup, now + Duration::seconds(3))
        .await
        .expect("record recipient erasure");
    assert!(matches!(
        email_control
            .prepare_smtp_test(
                project_id,
                PrepareSmtpTest {
                    request_digest: vec![45; 32],
                    ..smtp_test.clone()
                },
                now
            )
            .await,
        Err(crate::application::ApplicationError::IdempotencyConflict)
    ));

    let abandoned_id = Uuid::new_v4();
    let abandoned = email_control
        .prepare_smtp_test(
            project_id,
            PrepareSmtpTest {
                id: abandoned_id,
                idempotency_key: "smtp-test-abandoned-1".to_owned(),
                request_digest: vec![46; 32],
                recipient_ref: "smtp_test_abandoned_recipient".to_owned(),
                ..smtp_test.clone()
            },
            now,
        )
        .await
        .expect("prepare abandoned test");
    assert_eq!(
        abandoned.record.state,
        crate::application::SmtpTestState::Preparing
    );
    let abandoned = email_control
        .provision_and_finalize_smtp_test_enqueue(
            project_id,
            abandoned_id,
            &[46; 32],
            &CountingSmtpProvisioner::default(),
            Zeroizing::new(b"recipient@example.com".to_vec()),
            now,
        )
        .await
        .expect("enqueue abandoned test");
    assert_eq!(abandoned.state, crate::application::SmtpTestState::Pending);
    let _lost = email
        .claim_smtp_test("runtime-lost", now, now + Duration::seconds(30))
        .await
        .expect("claim abandoned")
        .expect("abandoned available");
    assert!(
        email
            .claim_smtp_test(
                "runtime-skewed",
                now + Duration::hours(1),
                now + Duration::hours(1) + Duration::seconds(30),
            )
            .await
            .expect("caller clock cannot expire a database-clock lease")
            .is_none()
    );
    assert_eq!(
        email_control
            .get_smtp_test(project_id, abandoned_id)
            .await
            .expect("live database lease remains submitting")
            .state,
        crate::application::SmtpTestState::Submitting
    );
    sqlx::query(
        "UPDATE project_smtp_test_operations
         SET lease_expires_at=clock_timestamp()-interval '1 second'
         WHERE project_id=$1 AND id=$2",
    )
    .bind(project_id)
    .bind(abandoned_id)
    .execute(&pool)
    .await
    .expect("expire SMTP-test lease with PostgreSQL clock");
    assert!(
        email
            .claim_smtp_test(
                "runtime-restart",
                now + Duration::seconds(31),
                now + Duration::seconds(61),
            )
            .await
            .expect("recover ambiguity")
            .is_none()
    );
    let ambiguous = email_control
        .get_smtp_test(project_id, abandoned_id)
        .await
        .expect("read ambiguity");
    assert_eq!(
        ambiguous.state,
        crate::application::SmtpTestState::Ambiguous
    );
    assert_eq!(ambiguous.outcome, Some(MailTransportOutcome::Ambiguous));

    let expired_id = Uuid::new_v4();
    email_control
        .prepare_smtp_test(
            project_id,
            PrepareSmtpTest {
                id: expired_id,
                idempotency_key: "smtp-test-expired-1".to_owned(),
                request_digest: vec![47; 32],
                recipient_ref: "smtp_test_expired_recipient".to_owned(),
                ..smtp_test
            },
            now,
        )
        .await
        .expect("prepare pending expiry");
    email_control
        .provision_and_finalize_smtp_test_enqueue(
            project_id,
            expired_id,
            &[47; 32],
            &CountingSmtpProvisioner::default(),
            Zeroizing::new(b"recipient@example.com".to_vec()),
            now,
        )
        .await
        .expect("finalize pending expiry");
    assert!(
        email
            .claim_smtp_test(
                "runtime-after-restart",
                now + Duration::minutes(11),
                now + Duration::minutes(11) + Duration::seconds(30),
            )
            .await
            .expect("terminalize expired pending test")
            .is_none()
    );
    let expired = email_control
        .get_smtp_test(project_id, expired_id)
        .await
        .expect("read terminal pending expiry");
    assert_eq!(expired.state, crate::application::SmtpTestState::Failed);
    assert_eq!(expired.outcome, Some(MailTransportOutcome::Transient));

    // A process may disappear after recipient prepare and resume after stale terminalization and
    // cleanup. Drain earlier terminal recipients too, then prove the exact stale tombstone blocks
    // the delayed external writer before it reaches the provisioner.
    let stale_id = Uuid::new_v4();
    let stale_ref = "smtp_test_stale_recipient";
    email_control
        .prepare_smtp_test(
            project_id,
            PrepareSmtpTest {
                id: stale_id,
                configuration_id: smtp_id,
                recipient_ref: stale_ref.to_owned(),
                idempotency_key: "smtp-test-stale-provision-1".to_owned(),
                request_digest: vec![48; 32],
                expected_revision: 1,
                correlation_id: Uuid::new_v4(),
            },
            now,
        )
        .await
        .expect("durably prepare stale recipient");
    let cleanup_now = now + Duration::minutes(12);
    let mut erased_stale = false;
    for sequence in 0..8 {
        let Some(cleanup) = email
            .claim_smtp_secret_cleanup(
                &format!("runtime-stale-cleanup-{sequence}"),
                cleanup_now + Duration::seconds(sequence),
                cleanup_now + Duration::seconds(sequence + 30),
            )
            .await
            .expect("claim terminal recipient cleanup")
        else {
            break;
        };
        erased_stale |= cleanup.recipient_ref == stale_ref;
        email
            .finish_smtp_secret_cleanup(&cleanup, cleanup_now + Duration::seconds(sequence + 1))
            .await
            .expect("tombstone terminal recipient");
    }
    assert!(erased_stale, "stale prepared recipient must be tombstoned");
    let delayed_recipient_provisioner = CountingSmtpProvisioner::default();
    assert_eq!(
        PostgresEmailControlRepository::new(database.clone())
            .provision_and_finalize_smtp_test_enqueue(
                project_id,
                stale_id,
                &[48; 32],
                &delayed_recipient_provisioner,
                Zeroizing::new(b"stale@example.com".to_vec()),
                cleanup_now + Duration::minutes(1),
            )
            .await,
        Err(crate::application::ApplicationError::InvalidTransition)
    );
    assert_eq!(
        delayed_recipient_provisioner.writes.load(Ordering::SeqCst),
        0
    );

    let authentication = PostgresAuthenticationRepository::new(database.clone());
    let deployment = DeploymentSmtpGeneration {
        generation: 7,
        desired_status: DeploymentSmtpDesiredStatus::Active,
        host: "smtp.default.example".to_owned(),
        port: 465,
        tls_mode: SmtpTlsMode::ImplicitTls,
        sender_address: "login@default.example".to_owned(),
        credential_ref: "deployment-smtp-7".to_owned(),
        safe_fingerprint: [77; 32],
        explicitly_allowed_private_ips: Vec::new(),
    };
    seed_legacy_deployment_smtp(&pool, &deployment).await;
    email
        .reconcile_deployment_smtp(&deployment, now)
        .await
        .expect("activate deployment SMTP");
    let audit_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events WHERE action='email.deployment_smtp.activated'",
    )
    .fetch_one(&pool)
    .await
    .expect("deployment SMTP audit count");
    email
        .reconcile_deployment_smtp(&deployment, now + Duration::seconds(1))
        .await
        .expect("unchanged deployment SMTP converges");
    let unchanged_audit_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events WHERE action='email.deployment_smtp.activated'",
    )
    .fetch_one(&pool)
    .await
    .expect("unchanged deployment SMTP audit count");
    assert_eq!(audit_count, unchanged_audit_count);
    email
        .reconcile_deployment_smtp(
            &DeploymentSmtpGeneration {
                desired_status: DeploymentSmtpDesiredStatus::Compromised,
                ..deployment
            },
            now + Duration::seconds(2),
        )
        .await
        .expect("compromise deployment SMTP without credential access");
    let login_command = |id: Uuid, interaction_seed: u8| CreateLoginTransaction {
        id,
        project_id,
        application_id,
        interaction: digest(interaction_seed),
        redirect_uri: "https://app.example/callback".to_owned(),
        application_pkce_challenge: "A".repeat(43),
        application_state: protected(2),
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
        admitted_email: Some(email_method.clone()),
    };
    for (mutation, expected) in [
        (
            "UPDATE projects SET status='disabled' WHERE id=$1",
            crate::application::ApplicationError::Disabled,
        ),
        (
            "UPDATE projects SET metadata_revision=2 WHERE id=$1",
            crate::application::ApplicationError::RevisionConflict,
        ),
        (
            "UPDATE projects SET security_revision=2 WHERE id=$1",
            crate::application::ApplicationError::RevisionConflict,
        ),
        (
            "UPDATE applications SET status='disabled' WHERE project_id=$1",
            crate::application::ApplicationError::Disabled,
        ),
        (
            "UPDATE applications SET security_revision=2 WHERE project_id=$1",
            crate::application::ApplicationError::RevisionConflict,
        ),
        (
            "UPDATE project_email_policies SET status='disabled' WHERE project_id=$1",
            crate::application::ApplicationError::RevisionConflict,
        ),
        (
            "UPDATE application_email_assignments SET status='disabled' WHERE project_id=$1",
            crate::application::ApplicationError::RevisionConflict,
        ),
        (
            "UPDATE project_smtp_configurations SET status='compromised' WHERE project_id=$1",
            crate::application::ApplicationError::Disabled,
        ),
    ] {
        sqlx::query(mutation)
            .bind(project_id)
            .execute(&pool)
            .await
            .expect("mutate current email authority before create");
        let rejected_id = Uuid::new_v4();
        assert_eq!(
            authentication
                .create_login_transaction(login_command(rejected_id, 40))
                .await,
            Err(expected),
        );
        let persisted: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM login_transactions WHERE id=$1")
                .bind(rejected_id)
                .fetch_one(&pool)
                .await
                .expect("rejected login count");
        assert_eq!(
            persisted, 0,
            "failed create must not snapshot stale authority"
        );
        for restore in [
            "UPDATE projects SET status='active',metadata_revision=1,security_revision=1 WHERE id=$1",
            "UPDATE applications SET status='active',security_revision=1 WHERE project_id=$1",
            "UPDATE project_email_policies SET status='enabled' WHERE project_id=$1",
            "UPDATE application_email_assignments SET status='active' WHERE project_id=$1",
            "UPDATE project_smtp_configurations SET status='active' WHERE project_id=$1",
        ] {
            sqlx::query(restore)
                .bind(project_id)
                .execute(&pool)
                .await
                .expect("restore authority fixture after create fence");
        }
    }

    let transaction_id = Uuid::new_v4();
    authentication
        .create_login_transaction(CreateLoginTransaction {
            id: transaction_id,
            project_id,
            application_id,
            interaction: digest(1),
            redirect_uri: "https://app.example/callback".to_owned(),
            application_pkce_challenge: "A".repeat(43),
            application_state: protected(2),
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
            admitted_email: Some(email_method),
        })
        .await
        .expect("create login");
    authentication
        .bind_hosted_browser(BindHostedBrowser {
            interaction: digest(1),
            expected_transaction_revision: 1,
            browser_binding: digest(3),
            csrf: digest(4),
            now: now + Duration::seconds(1),
        })
        .await
        .expect("bind browser");

    let selection = SelectEmailMethod {
        project_id,
        transaction_id,
        expected_transaction_revision: 2,
        browser_binding: digest(3),
        csrf: digest(4),
        now: now + Duration::seconds(2),
    };
    // Hold the Project mutation lock while selection reaches its owner fence. After the disable
    // commits, the blocked selection must reject without burning the login revision.
    let mut disable_project = pool.begin().await.expect("begin Project-disable race");
    sqlx::query("UPDATE projects SET status='disabled' WHERE id=$1")
        .bind(project_id)
        .execute(&mut *disable_project)
        .await
        .expect("hold Project disable lock");
    let racing_email = email.clone();
    let racing_selection = selection.clone();
    let racing_select =
        tokio::spawn(async move { racing_email.select_email_method(racing_selection).await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(!racing_select.is_finished());
    disable_project
        .commit()
        .await
        .expect("commit Project disable");
    assert_eq!(
        racing_select.await.expect("join selection race"),
        Err(crate::application::ApplicationError::RevisionConflict)
    );
    let unchanged: (String, i64) =
        sqlx::query_as("SELECT status,transaction_revision FROM login_transactions WHERE id=$1")
            .bind(transaction_id)
            .fetch_one(&pool)
            .await
            .expect("racing selection rejection state");
    assert_eq!(unchanged, ("awaiting_method_selection".to_owned(), 2));
    sqlx::query("UPDATE projects SET status='active' WHERE id=$1")
        .bind(project_id)
        .execute(&pool)
        .await
        .expect("restore Project after selection race");

    for (mutation, expected) in [
        (
            "UPDATE projects SET status='disabled' WHERE id=$1",
            crate::application::ApplicationError::RevisionConflict,
        ),
        (
            "UPDATE projects SET metadata_revision=2 WHERE id=$1",
            crate::application::ApplicationError::RevisionConflict,
        ),
        (
            "UPDATE projects SET security_revision=2 WHERE id=$1",
            crate::application::ApplicationError::RevisionConflict,
        ),
        (
            "UPDATE applications SET status='disabled' WHERE project_id=$1",
            crate::application::ApplicationError::RevisionConflict,
        ),
        (
            "UPDATE applications SET security_revision=2 WHERE project_id=$1",
            crate::application::ApplicationError::RevisionConflict,
        ),
        (
            "UPDATE project_email_policies SET status='disabled' WHERE project_id=$1",
            crate::application::ApplicationError::RevisionConflict,
        ),
        (
            "UPDATE application_email_assignments SET status='disabled' WHERE project_id=$1",
            crate::application::ApplicationError::RevisionConflict,
        ),
        (
            "UPDATE project_smtp_configurations SET status='compromised' WHERE project_id=$1",
            crate::application::ApplicationError::Disabled,
        ),
    ] {
        sqlx::query(mutation)
            .bind(project_id)
            .execute(&pool)
            .await
            .expect("mutate current email authority before selection");
        assert_eq!(
            email.select_email_method(selection.clone()).await,
            Err(expected)
        );
        let unchanged: (String, i64) = sqlx::query_as(
            "SELECT status,transaction_revision FROM login_transactions WHERE id=$1",
        )
        .bind(transaction_id)
        .fetch_one(&pool)
        .await
        .expect("selection rejection state");
        assert_eq!(unchanged, ("awaiting_method_selection".to_owned(), 2));
        for restore in [
            "UPDATE projects SET status='active',metadata_revision=1,security_revision=1 WHERE id=$1",
            "UPDATE applications SET status='active',security_revision=1 WHERE project_id=$1",
            "UPDATE project_email_policies SET status='enabled' WHERE project_id=$1",
            "UPDATE application_email_assignments SET status='active' WHERE project_id=$1",
            "UPDATE project_smtp_configurations SET status='active' WHERE project_id=$1",
        ] {
            sqlx::query(restore)
                .bind(project_id)
                .execute(&pool)
                .await
                .expect("restore authority fixture after selection fence");
        }
    }
    let (first, second) = tokio::join!(
        email.select_email_method(selection.clone()),
        email.select_email_method(selection)
    );
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);

    let preparation = email
        .prepare_email_generation(
            project_id,
            transaction_id,
            3,
            &digest(3),
            &digest(4),
            now + Duration::seconds(3),
        )
        .await
        .expect("prepare generation");
    let challenge_id = Uuid::new_v4();
    let generation = CommitEmailGeneration {
        project_id,
        application_id,
        transaction_id,
        expected_transaction_revision: 3,
        expected_generation: preparation.next_generation,
        challenge_id,
        outbox_id: Uuid::new_v4(),
        canonicalization_version: 1,
        lookup_digest: digest(5),
        address: protected(6),
        otp_digest: Some(digest_at(7, 2)),
        magic_digest: Some(digest(8)),
        envelope: protected(9),
        body: protected(10),
        message_id: format!("<{}@mail.owlauth.invalid>", Uuid::new_v4()),
        suppress_delivery: false,
        issued_at: now + Duration::seconds(3),
        otp_expires_at: Some(now + Duration::minutes(2)),
        magic_expires_at: Some(now + Duration::minutes(5)),
        expires_at: now + Duration::minutes(5),
    };
    // Likewise, hold an Application-disable mutation across the committing enqueue transaction.
    // The enqueue waits on the shared owner fence, then rejects after disable commits atomically.
    let mut disable_application = pool.begin().await.expect("begin Application-disable race");
    sqlx::query("UPDATE applications SET status='disabled' WHERE id=$1")
        .bind(application_id)
        .execute(&mut *disable_application)
        .await
        .expect("hold Application disable lock");
    let racing_email = email.clone();
    let racing_generation = generation.clone();
    let racing_commit = tokio::spawn(async move {
        racing_email
            .commit_email_generation(racing_generation)
            .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(!racing_commit.is_finished());
    disable_application
        .commit()
        .await
        .expect("commit Application disable");
    assert_eq!(
        racing_commit.await.expect("join generation race"),
        Err(crate::application::ApplicationError::RevisionConflict)
    );
    let unchanged: (String, i64, i64, i64) = sqlx::query_as(
        "SELECT login.status,login.transaction_revision,
          (SELECT COUNT(*) FROM email_challenges WHERE transaction_id=login.id),
          (SELECT COUNT(*) FROM mail_outbox WHERE transaction_id=login.id)
         FROM login_transactions login WHERE login.id=$1",
    )
    .bind(transaction_id)
    .fetch_one(&pool)
    .await
    .expect("racing generation rejection state");
    assert_eq!(unchanged, ("email_address_entry".to_owned(), 3, 0, 0));
    sqlx::query("UPDATE applications SET status='active' WHERE id=$1")
        .bind(application_id)
        .execute(&pool)
        .await
        .expect("restore Application after generation race");

    for mutation in [
        "UPDATE projects SET status='disabled' WHERE id=$1",
        "UPDATE projects SET metadata_revision=2 WHERE id=$1",
        "UPDATE projects SET security_revision=2 WHERE id=$1",
        "UPDATE applications SET status='disabled' WHERE project_id=$1",
        "UPDATE applications SET security_revision=2 WHERE project_id=$1",
    ] {
        sqlx::query(mutation)
            .bind(project_id)
            .execute(&pool)
            .await
            .expect("mutate Project/Application after challenge preparation");
        assert_eq!(
            email.commit_email_generation(generation.clone()).await,
            Err(crate::application::ApplicationError::RevisionConflict)
        );
        let unchanged: (String, i64, i64, i64) = sqlx::query_as(
            "SELECT login.status,login.transaction_revision,
              (SELECT COUNT(*) FROM email_challenges WHERE transaction_id=login.id),
              (SELECT COUNT(*) FROM mail_outbox WHERE transaction_id=login.id)
             FROM login_transactions login WHERE login.id=$1",
        )
        .bind(transaction_id)
        .fetch_one(&pool)
        .await
        .expect("rejected generation leaves no durable email work");
        assert_eq!(unchanged, ("email_address_entry".to_owned(), 3, 0, 0));
        sqlx::query(
            "UPDATE projects SET status='active',metadata_revision=1,security_revision=1 WHERE id=$1",
        )
        .bind(project_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE applications SET status='active',security_revision=1 WHERE project_id=$1",
        )
        .bind(project_id)
        .execute(&pool)
        .await
        .unwrap();
    }
    email
        .commit_email_generation(generation.clone())
        .await
        .expect("commit challenge and outbox");

    // A server-derived address suppression commits the same real challenge family and revision
    // progression as delivery, but its durable outbox disposition is terminal and unclaimable.
    // Resend still supersedes generation n, and wrong proofs follow the ordinary bounded attempt
    // path without any proof ever leaving the server.
    let suppressed_transaction_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO login_transactions
         SELECT (jsonb_populate_record(NULL::login_transactions,
           to_jsonb(source) || jsonb_build_object(
             'id',$1,'interaction_digest',$2,'status','email_address_entry','transaction_revision',3,
             'user_id',NULL,'authenticated_at',NULL,'terminal_at',NULL,'created_at',$3,'updated_at',$3))).*
         FROM login_transactions source WHERE source.id=$4",
    )
    .bind(suppressed_transaction_id)
    .bind(vec![99_u8; 32])
    .bind(now)
    .bind(transaction_id)
    .execute(&pool)
    .await
    .expect("clone selected login for suppressed equivalence");
    sqlx::query(
        "INSERT INTO login_email_method_snapshots
         SELECT (jsonb_populate_record(NULL::login_email_method_snapshots,
           to_jsonb(source) || jsonb_build_object('transaction_id',$1,'created_at',$2))).*
         FROM login_email_method_snapshots source WHERE source.transaction_id=$3",
    )
    .bind(suppressed_transaction_id)
    .bind(now)
    .bind(transaction_id)
    .execute(&pool)
    .await
    .expect("clone email snapshot for suppressed equivalence");
    let suppressed_challenge_id = Uuid::new_v4();
    let mut suppressed = generation.clone();
    suppressed.transaction_id = suppressed_transaction_id;
    suppressed.challenge_id = suppressed_challenge_id;
    suppressed.outbox_id = Uuid::new_v4();
    suppressed.message_id = format!("<{}@mail.owlauth.invalid>", suppressed.outbox_id);
    suppressed.suppress_delivery = true;
    email
        .commit_email_generation(suppressed.clone())
        .await
        .expect("commit real suppressed generation");
    let suppressed_state: (String, i64, String, i16, String, Option<String>, i16, bool) =
        sqlx::query_as(
            "SELECT login.status,login.transaction_revision,challenge.status,challenge.generation,
                    outbox.status,outbox.safe_outcome,outbox.attempts,outbox.lease_owner IS NULL
             FROM login_transactions login JOIN email_challenges challenge
               ON challenge.transaction_id=login.id JOIN mail_outbox outbox
               ON outbox.challenge_id=challenge.id
             WHERE login.id=$1 AND challenge.id=$2",
        )
        .bind(suppressed_transaction_id)
        .bind(suppressed_challenge_id)
        .fetch_one(&pool)
        .await
        .expect("reload suppressed Hosted authority state");
    assert_eq!(
        suppressed_state,
        (
            "email_challenge_pending".to_owned(),
            4,
            "pending".to_owned(),
            1,
            "cancelled".to_owned(),
            Some("policy_denied".to_owned()),
            0,
            true,
        )
    );
    sqlx::query("UPDATE mail_outbox SET next_attempt_at=$2 WHERE challenge_id=$1")
        .bind(challenge_id)
        .bind(now + Duration::minutes(4))
        .execute(&pool)
        .await
        .expect("defer admitted sibling while probing suppressed outbox");
    assert!(
        email
            .claim_due_mail(
                "suppressed-must-never-claim",
                now + Duration::seconds(4),
                now + Duration::seconds(34),
            )
            .await
            .expect("suppressed claim evaluation")
            .is_none()
    );
    // Mail authority is PostgreSQL-clock based; make the fixture durably due rather than
    // advancing a synthetic caller timestamp.
    sqlx::query(
        "UPDATE mail_outbox
            SET next_attempt_at=clock_timestamp()-interval '1 second'
          WHERE challenge_id=$1",
    )
    .bind(challenge_id)
    .execute(&pool)
    .await
    .expect("restore admitted outbox schedule");
    let wrong_suppressed = VerifyEmailProof {
        project_id,
        transaction_id: suppressed_transaction_id,
        challenge_id: suppressed_challenge_id,
        proof_kind: EmailProofKind::Otp,
        proof_digest: digest_at(250, 2),
        browser_binding: Some(digest(3)),
        csrf: digest(4),
        transfer_context: None,
        expected_transaction_revision: 4,
        now: now + Duration::seconds(5),
    };
    assert_eq!(
        email
            .verify_email_proof(wrong_suppressed.clone())
            .await
            .expect("wrong suppressed proof is generic invalid"),
        crate::application::EmailProofDecision::Invalid
    );
    assert_eq!(
        sqlx::query_scalar::<_, i16>("SELECT otp_attempts FROM email_challenges WHERE id=$1")
            .bind(suppressed_challenge_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    let second_suppressed_challenge_id = Uuid::new_v4();
    suppressed.expected_transaction_revision = 4;
    suppressed.expected_generation = 2;
    suppressed.challenge_id = second_suppressed_challenge_id;
    suppressed.outbox_id = Uuid::new_v4();
    suppressed.message_id = format!("<{}@mail.owlauth.invalid>", suppressed.outbox_id);
    suppressed.issued_at = now + Duration::seconds(40);
    email
        .commit_email_generation(suppressed)
        .await
        .expect("suppressed resend commits ordinary next generation");
    let generations: Vec<(i16, String, String)> = sqlx::query_as(
        "SELECT challenge.generation,challenge.status,outbox.status
         FROM email_challenges challenge JOIN mail_outbox outbox ON outbox.challenge_id=challenge.id
         WHERE challenge.transaction_id=$1 ORDER BY challenge.generation",
    )
    .bind(suppressed_transaction_id)
    .fetch_all(&pool)
    .await
    .expect("suppressed resend family");
    assert_eq!(
        generations,
        vec![
            (1, "superseded".to_owned(), "cancelled".to_owned()),
            (2, "pending".to_owned(), "cancelled".to_owned()),
        ]
    );
    let mut wrong_old = wrong_suppressed;
    wrong_old.expected_transaction_revision = 5;
    wrong_old.now = now + Duration::seconds(41);
    assert_eq!(
        email.verify_email_proof(wrong_old).await.unwrap(),
        crate::application::EmailProofDecision::Invalid
    );
    let wrong_new = VerifyEmailProof {
        project_id,
        transaction_id: suppressed_transaction_id,
        challenge_id: second_suppressed_challenge_id,
        proof_kind: EmailProofKind::Otp,
        proof_digest: digest_at(251, 2),
        browser_binding: Some(digest(3)),
        csrf: digest(4),
        transfer_context: None,
        expected_transaction_revision: 5,
        now: now + Duration::seconds(41),
    };
    assert_eq!(
        email.verify_email_proof(wrong_new).await.unwrap(),
        crate::application::EmailProofDecision::Invalid
    );
    sqlx::query("DELETE FROM mail_outbox WHERE transaction_id=$1")
        .bind(suppressed_transaction_id)
        .execute(&pool)
        .await
        .expect("remove suppressed outbox fixture");
    sqlx::query("DELETE FROM email_challenges WHERE transaction_id=$1")
        .bind(suppressed_transaction_id)
        .execute(&pool)
        .await
        .expect("remove suppressed challenge fixture");
    sqlx::query("DELETE FROM login_transactions WHERE id=$1")
        .bind(suppressed_transaction_id)
        .execute(&pool)
        .await
        .expect("remove suppressed login fixture by cascade");

    assert_eq!(
        email
            .email_proof_key_version(
                project_id,
                transaction_id,
                challenge_id,
                EmailProofKind::Otp,
            )
            .await
            .expect("generation-bound OTP key version"),
        Some(2)
    );

    // Nullable proof columns are an admitted-mode contract, not a persistence failure. Both
    // OTP-only and magic-only challenges return no key version for unsupported submissions while
    // retaining the admitted sibling proof.
    sqlx::query(
        "UPDATE email_challenges SET magic_digest=NULL,magic_digest_key_version=NULL,
         magic_expires_at=NULL WHERE id=$1",
    )
    .bind(challenge_id)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        email
            .email_proof_key_version(
                project_id,
                transaction_id,
                challenge_id,
                EmailProofKind::MagicLink,
            )
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        email
            .email_proof_key_version(
                project_id,
                transaction_id,
                challenge_id,
                EmailProofKind::Otp,
            )
            .await
            .unwrap(),
        Some(2)
    );
    sqlx::query(
        "UPDATE email_challenges SET magic_digest=$2,magic_digest_key_version=1,
         magic_expires_at=$3,otp_digest=NULL,otp_digest_key_version=NULL,otp_expires_at=NULL
         WHERE id=$1",
    )
    .bind(challenge_id)
    .bind(vec![8_u8; 32])
    .bind(now + Duration::minutes(5))
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        email
            .email_proof_key_version(
                project_id,
                transaction_id,
                challenge_id,
                EmailProofKind::Otp,
            )
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        email
            .email_proof_key_version(
                project_id,
                transaction_id,
                challenge_id,
                EmailProofKind::MagicLink,
            )
            .await
            .unwrap(),
        Some(1)
    );
    sqlx::query(
        "UPDATE email_challenges SET otp_digest=$2,otp_digest_key_version=2,
         otp_expires_at=$3 WHERE id=$1",
    )
    .bind(challenge_id)
    .bind(vec![7_u8; 32])
    .bind(now + Duration::minutes(2))
    .execute(&pool)
    .await
    .unwrap();

    for (disable, restore) in [
        (
            "UPDATE projects SET status='disabled' WHERE id=$1",
            "UPDATE projects SET status='active' WHERE id=$1",
        ),
        (
            "UPDATE applications SET status='disabled' WHERE project_id=$1",
            "UPDATE applications SET status='active' WHERE project_id=$1",
        ),
    ] {
        sqlx::query(disable)
            .bind(project_id)
            .execute(&pool)
            .await
            .expect("disable owner after enqueue");
        assert!(
            email
                .claim_due_mail(
                    "runtime-disabled-owner",
                    now + Duration::seconds(4),
                    now + Duration::seconds(34),
                )
                .await
                .expect("disabled owner is not claimable")
                .is_none()
        );
        let untouched: (String, i16) =
            sqlx::query_as("SELECT status,attempts FROM mail_outbox WHERE challenge_id=$1")
                .bind(challenge_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(untouched, ("pending".to_owned(), 0));
        sqlx::query(restore)
            .bind(project_id)
            .execute(&pool)
            .await
            .expect("restore owner after claim fence");
    }

    // A pinned generation remains authoritative while it is active, regardless of unrelated
    // later lifecycle rows. Abandoned provisioning is represented by removing its never-active
    // pending row; it likewise cannot revoke the captured predecessor.
    for (status, label) in [("pending", "pending"), ("disabled", "disabled")] {
        let newer_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO project_smtp_configurations
             (id,project_id,status,generation,revision,security_eligibility_revision,host,port,
              tls_mode,sender_address,sender_name,reply_to,credential_ref,safe_fingerprint,created_at,updated_at)
             SELECT $1,project_id,$2,2,1,1,host,port,tls_mode,sender_address,sender_name,reply_to,
                    credential_ref,safe_fingerprint,created_at,updated_at
             FROM project_smtp_configurations WHERE id=$3",
        )
        .bind(newer_id)
        .bind(status)
        .bind(smtp_id)
        .execute(&pool)
        .await
        .unwrap_or_else(|error| panic!("insert {label} Project n+1: {error}"));
        assert!(
            email
                .claim_due_mail(
                    &format!("project-newer-{label}"),
                    now + Duration::seconds(4),
                    now + Duration::seconds(34),
                )
                .await
                .unwrap_or_else(|error| panic!("claim past {label} Project n+1: {error}"))
                .is_some(),
            "unrelated {label} Project n+1 must not revoke pinned active n"
        );
        sqlx::query("DELETE FROM project_smtp_configurations WHERE id=$1")
            .bind(newer_id)
            .execute(&pool)
            .await
            .unwrap();
        restore_claim_race_fixture(&pool, challenge_id, project_id, "SELECT $1", true).await;
    }
    let abandoned_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO project_smtp_configurations
         (id,project_id,status,generation,revision,security_eligibility_revision,host,port,
          tls_mode,sender_address,sender_name,reply_to,credential_ref,safe_fingerprint,created_at,updated_at)
         SELECT $1,project_id,'pending',2,1,1,host,port,tls_mode,sender_address,sender_name,reply_to,
                credential_ref,safe_fingerprint,created_at,updated_at
         FROM project_smtp_configurations WHERE id=$2",
    )
    .bind(abandoned_id)
    .bind(smtp_id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("DELETE FROM project_smtp_configurations WHERE id=$1")
        .bind(abandoned_id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        email
            .claim_due_mail(
                "project-newer-abandoned",
                now + Duration::seconds(4),
                now + Duration::seconds(34),
            )
            .await
            .unwrap()
            .is_some()
    );
    restore_claim_race_fixture(&pool, challenge_id, project_id, "SELECT $1", true).await;

    // A pending outbox survives planned Project rotation while its exact predecessor remains in
    // the bounded retained overlap, then becomes ineligible at the exact retained deadline.
    let rotated_project_smtp_id = Uuid::new_v4();
    sqlx::query(
        "UPDATE project_smtp_configurations
            SET status='retained',retained_until=clock_timestamp()+interval '10 minutes'
          WHERE id=$1",
    )
    .bind(smtp_id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO project_smtp_configurations
         (id,project_id,status,generation,revision,security_eligibility_revision,host,port,
          tls_mode,sender_address,sender_name,reply_to,credential_ref,safe_fingerprint,created_at,updated_at)
         SELECT $1,project_id,'active',2,1,1,host,port,tls_mode,sender_address,sender_name,reply_to,
                'smtp_rotated_ref',safe_fingerprint,created_at,updated_at
         FROM project_smtp_configurations WHERE id=$2",
    )
    .bind(rotated_project_smtp_id)
    .bind(smtp_id)
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        email
            .claim_due_mail(
                "project-retained-overlap",
                now + Duration::seconds(4),
                now + Duration::seconds(34),
            )
            .await
            .unwrap()
            .is_some()
    );
    restore_claim_race_fixture(&pool, challenge_id, project_id, "SELECT $1", true).await;
    sqlx::query(
        "UPDATE project_smtp_configurations
            SET retained_until=clock_timestamp()-interval '1 second'
          WHERE id=$1",
    )
    .bind(smtp_id)
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        email
            .claim_due_mail(
                "project-retained-expired",
                now + Duration::seconds(4),
                now + Duration::seconds(34),
            )
            .await
            .unwrap()
            .is_none()
    );
    sqlx::query("DELETE FROM project_smtp_configurations WHERE id=$1")
        .bind(rotated_project_smtp_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE project_smtp_configurations SET status='active',retained_until=NULL WHERE id=$1",
    )
    .bind(smtp_id)
    .execute(&pool)
    .await
    .unwrap();

    // Planned deployment rotation retains the captured predecessor for the overlap window.
    sqlx::query(
        "INSERT INTO deployment_smtp_generations
         (generation,status,revision,security_eligibility_revision,host,port,tls_mode,sender_address,
          credential_ref,safe_fingerprint,explicitly_allowed_private_ips,material_owner_id,created_at,updated_at)
         VALUES (1,'active',1,1,'smtp.example.com',465,'implicit_tls','deployment@example.com',
                 'deployment_ref',$1,'[]'::jsonb,md5('email-test-deployment-1')::uuid,$2,$2),
                (2,'reconciled',1,1,'smtp.example.com',465,'implicit_tls','deployment@example.com',
                 'deployment_ref_2',$1,'[]'::jsonb,md5('email-test-deployment-2')::uuid,$2,$2)",
    )
    .bind(vec![8_u8; 32])
    .bind(now)
    .execute(&pool)
    .await
    .unwrap();
    let mut rewrite_smtp_fixture = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *rewrite_smtp_fixture)
        .await
        .unwrap();
    sqlx::query(
        "WITH snapshot AS (
           UPDATE login_email_method_snapshots SET smtp_selection_kind='deployment_default',
             smtp_configuration_id=NULL,smtp_generation=1,smtp_security_eligibility_revision=1
           WHERE transaction_id=$1 RETURNING transaction_id),
         challenge AS (
           UPDATE email_challenges SET smtp_selection_kind='deployment_default',
             smtp_configuration_id=NULL,smtp_generation=1,smtp_security_eligibility_revision=1
           WHERE transaction_id=$1 RETURNING transaction_id)
         UPDATE mail_outbox SET smtp_selection_kind='deployment_default',smtp_configuration_id=NULL,
           smtp_generation=1,smtp_security_eligibility_revision=1 WHERE transaction_id=$1",
    )
    .bind(transaction_id)
    .execute(&mut *rewrite_smtp_fixture)
    .await
    .unwrap();
    rewrite_smtp_fixture.commit().await.unwrap();
    assert!(
        email
            .claim_due_mail(
                "deployment-newer-reconciled",
                now + Duration::seconds(4),
                now + Duration::seconds(34),
            )
            .await
            .unwrap()
            .is_some()
    );
    restore_claim_race_fixture(&pool, challenge_id, project_id, "SELECT $1", true).await;
    sqlx::query(
        "UPDATE deployment_smtp_generations
            SET status='retained',retained_until=clock_timestamp()+interval '10 minutes'
          WHERE generation=1",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("UPDATE deployment_smtp_generations SET status='active' WHERE generation=2")
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        email
            .claim_due_mail(
                "deployment-retained-overlap",
                now + Duration::seconds(4),
                now + Duration::seconds(34),
            )
            .await
            .unwrap()
            .is_some()
    );
    restore_claim_race_fixture(&pool, challenge_id, project_id, "SELECT $1", true).await;
    sqlx::query(
        "UPDATE deployment_smtp_generations
            SET retained_until=clock_timestamp()-interval '1 second'
          WHERE generation=1",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        email
            .claim_due_mail(
                "deployment-retained-expired",
                now + Duration::seconds(4),
                now + Duration::seconds(34),
            )
            .await
            .unwrap()
            .is_none()
    );
    for terminal in ["disabled", "compromised"] {
        sqlx::query(
            "UPDATE deployment_smtp_generations SET status=$1,retained_until=NULL,
             security_eligibility_revision=2 WHERE generation=1",
        )
        .bind(terminal)
        .execute(&pool)
        .await
        .unwrap();
        assert!(
            email
                .claim_due_mail(
                    &format!("deployment-{terminal}"),
                    now + Duration::seconds(4),
                    now + Duration::seconds(34),
                )
                .await
                .unwrap()
                .is_none()
        );
        sqlx::query(
            "UPDATE deployment_smtp_generations SET status='retained',retained_until=$1,
             security_eligibility_revision=1 WHERE generation=1",
        )
        .bind(now + Duration::minutes(10))
        .execute(&pool)
        .await
        .unwrap();
    }
    let mut restore_smtp_fixture = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *restore_smtp_fixture)
        .await
        .unwrap();
    sqlx::query(
        "WITH snapshot AS (
           UPDATE login_email_method_snapshots SET smtp_selection_kind='project',
             smtp_configuration_id=$1,smtp_generation=1,smtp_security_eligibility_revision=1
           WHERE transaction_id=$2 RETURNING transaction_id),
         challenge AS (
           UPDATE email_challenges SET smtp_selection_kind='project',smtp_configuration_id=$1,
             smtp_generation=1,smtp_security_eligibility_revision=1
           WHERE transaction_id=$2 RETURNING transaction_id)
         UPDATE mail_outbox SET smtp_selection_kind='project',smtp_configuration_id=$1,
           smtp_generation=1,smtp_security_eligibility_revision=1 WHERE transaction_id=$2",
    )
    .bind(smtp_id)
    .bind(transaction_id)
    .execute(&mut *restore_smtp_fixture)
    .await
    .unwrap();
    restore_smtp_fixture.commit().await.unwrap();
    sqlx::query("DELETE FROM deployment_smtp_generations WHERE generation IN (1,2)")
        .execute(&pool)
        .await
        .unwrap();

    // Every revoking claim authority participates in a real PostgreSQL commit-order race. If the
    // disable/compromise/supersession commits first, the later claim is inert; if the claim holds
    // every shared fence first, the transition waits and only the already-won lease may proceed.
    for (authority_id, mutation, restore, label) in [
        (
            project_id,
            "UPDATE project_email_policies SET status='disabled' WHERE project_id=$1",
            "UPDATE project_email_policies SET status='enabled' WHERE project_id=$1",
            "policy-disable",
        ),
        (
            project_id,
            "UPDATE application_email_assignments SET status='disabled' WHERE project_id=$1",
            "UPDATE application_email_assignments SET status='active' WHERE project_id=$1",
            "assignment-disable",
        ),
        (
            smtp_id,
            "UPDATE project_smtp_configurations SET status='disabled',security_eligibility_revision=security_eligibility_revision+1 WHERE id=$1",
            "UPDATE project_smtp_configurations SET status='active',security_eligibility_revision=1 WHERE id=$1",
            "smtp-disable",
        ),
        (
            smtp_id,
            "UPDATE project_smtp_configurations SET status='compromised',security_eligibility_revision=security_eligibility_revision+1 WHERE id=$1",
            "UPDATE project_smtp_configurations SET status='active',security_eligibility_revision=1 WHERE id=$1",
            "smtp-compromise",
        ),
        (
            challenge_id,
            "UPDATE email_challenges SET status='superseded',terminal_at=updated_at WHERE id=$1",
            "UPDATE email_challenges SET status='pending',terminal_at=NULL WHERE id=$1",
            "challenge-supersession",
        ),
    ] {
        assert_mail_claim_fence_commit_orders(
            &pool,
            &email,
            challenge_id,
            authority_id,
            mutation,
            restore,
            label,
            now + Duration::seconds(4),
        )
        .await;
    }

    let first_claim = email
        .claim_due_mail(
            "runtime-a",
            now + Duration::seconds(4),
            now + Duration::seconds(34),
        )
        .await
        .expect("claim outbox")
        .expect("mail was due");
    assert_eq!(first_claim.attempts, 1);
    assert_eq!(first_claim.envelope_from, "login@example.com");
    assert_eq!(first_claim.sender_name.as_deref(), Some("OwlAuth 登录"));
    assert_eq!(first_claim.reply_to.as_deref(), Some("reply@example.com"));
    assert!(
        email
            .claim_due_mail(
                "runtime-b",
                now + Duration::hours(1),
                now + Duration::hours(1) + Duration::seconds(30),
            )
            .await
            .expect("leased mail remains unavailable")
            .is_none()
    );
    sqlx::query(
        "UPDATE mail_outbox SET lease_expires_at=clock_timestamp()-interval '1 second'
         WHERE id=$1",
    )
    .bind(first_claim.id)
    .execute(&pool)
    .await
    .expect("expire lease with the PostgreSQL authority clock");
    let mut recovered = email
        .claim_due_mail(
            "runtime-b",
            now + Duration::seconds(35),
            now + Duration::seconds(65),
        )
        .await
        .expect("recover expired lease")
        .expect("expired lease was reclaimable");
    assert_eq!(recovered.attempts, 2);

    // Maintenance uses the caller clock for domain retention timestamps, but PostgreSQL is the
    // sole authority for a live lease. Keep the fixture in the application timestamp domain so
    // its usefulness remains valid relative to created_at and next_attempt_at.
    let maintenance_useful_until = now + Duration::minutes(4);
    recovered.useful_until = sqlx::query_scalar(
        "UPDATE mail_outbox SET max_attempts=8,useful_until=$2 WHERE id=$1
         RETURNING useful_until",
    )
    .bind(recovered.id)
    .bind(maintenance_useful_until)
    .fetch_one(&pool)
    .await
    .expect("stage the live usefulness predicate");
    email
        .maintain_short_term_data(recovered.useful_until + Duration::seconds(1), 100)
        .await
        .expect("usefulness maintenance leaves a live database lease intact");
    let live_lease: (String, Option<String>, bool) = sqlx::query_as(
        "SELECT status,lease_owner,lease_expires_at>clock_timestamp()
         FROM mail_outbox WHERE id=$1",
    )
    .bind(recovered.id)
    .fetch_one(&pool)
    .await
    .expect("inspect live lease after maintenance");
    assert_eq!(
        live_lease,
        ("leased".to_owned(), Some("runtime-b".to_owned()), true)
    );
    assert_eq!(
        email
            .finish_mail_attempt(
                &first_claim,
                MailTransportOutcome::Delivered,
                None,
                now + Duration::seconds(36),
            )
            .await,
        Err(crate::application::ApplicationError::RevisionConflict)
    );
    email
        .finish_mail_attempt(
            &recovered,
            MailTransportOutcome::Delivered,
            None,
            now + Duration::seconds(36),
        )
        .await
        .expect("the live claimant commits despite a skewed maintenance attempt");

    // Reuse the completed fixture as a non-leased control to prove the usefulness cleanup class
    // itself executes deterministically, independent of the preceding live-lease assertion.
    sqlx::query(
        "UPDATE mail_outbox SET status='pending',attempts=0,max_attempts=8,
           next_attempt_at=$2,useful_until=$2,lease_owner=NULL,lease_expires_at=NULL,
           safe_outcome=NULL,delivered_at=NULL,terminal_at=NULL WHERE id=$1",
    )
    .bind(recovered.id)
    .bind(recovered.useful_until)
    .execute(&pool)
    .await
    .expect("stage the non-leased usefulness control");
    email
        .maintain_short_term_data(recovered.useful_until + Duration::seconds(1), 100)
        .await
        .expect("run the usefulness cleanup class");
    let usefulness_control_status: String =
        sqlx::query_scalar("SELECT status FROM mail_outbox WHERE id=$1")
            .bind(recovered.id)
            .fetch_one(&pool)
            .await
            .expect("inspect the usefulness control");
    assert_eq!(usefulness_control_status, "expired");

    // Exercise the independent final-attempt sweep with an actually expired PostgreSQL lease;
    // the original application-clock usefulness remains in the future, so only the attempts
    // predicate can select this row.
    assert!(recovered.useful_until > now + Duration::minutes(1));
    sqlx::query(
        "UPDATE mail_outbox SET status='leased',safe_outcome=NULL,terminal_at=NULL,
           delivered_at=NULL,lease_owner='expired-maintenance-fixture',
           lease_expires_at=clock_timestamp()-interval '1 second',attempts=max_attempts
         WHERE id=$1",
    )
    .bind(recovered.id)
    .execute(&pool)
    .await
    .expect("stage an actually expired final-attempt lease");
    email
        .maintain_short_term_data(now + Duration::minutes(1), 100)
        .await
        .expect("maintenance terminalizes an expired database lease");
    let expired_lease: (String, Option<String>, Option<OffsetDateTime>) =
        sqlx::query_as("SELECT status,lease_owner,lease_expires_at FROM mail_outbox WHERE id=$1")
            .bind(recovered.id)
            .fetch_one(&pool)
            .await
            .expect("inspect expired lease after maintenance");
    assert_eq!(expired_lease, ("permanent_failure".to_owned(), None, None));
    sqlx::query(
        "UPDATE mail_outbox SET status='delivered',safe_outcome='delivered',
           useful_until=$2,max_attempts=8,delivered_at=$3,terminal_at=$3,updated_at=$3
         WHERE id=$1",
    )
    .bind(recovered.id)
    .bind(recovered.useful_until)
    .bind(now + Duration::seconds(36))
    .execute(&pool)
    .await
    .expect("restore the delivered fixture for the remaining journey");

    let establish = |context, csrf| EstablishMagicTransferContext {
        id: Uuid::new_v4(),
        challenge_id,
        context: digest(context),
        csrf: digest(csrf),
        now: now + Duration::seconds(36),
    };
    let (first_gate, second_gate) = tokio::join!(
        email.establish_magic_transfer_context(establish(20, 21)),
        email.establish_magic_transfer_context(establish(22, 23))
    );
    first_gate.expect("concurrent scanner transfer gate");
    second_gate.expect("concurrent browser transfer gate");
    for (context, csrf) in [(24, 25), (26, 27), (28, 29), (30, 31), (32, 33), (34, 35)] {
        email
            .establish_magic_transfer_context(establish(context, csrf))
            .await
            .expect("bounded transfer gate");
    }
    assert_eq!(
        email
            .establish_magic_transfer_context(establish(36, 37))
            .await,
        Err(crate::application::ApplicationError::NotFound),
        "ninth live context must fail without evicting a valid browser"
    );
    for (context, csrf) in [(20, 21), (22, 23)] {
        let resolved = email
            .resolve_magic_transfer_context(ResolveMagicTransferContext {
                challenge_id,
                project_public_id: format!("prj_{}", project_id.simple()),
                transaction_id,
                context: digest(context),
                csrf: digest(csrf),
                now: now + Duration::seconds(36),
            })
            .await
            .expect("resolve transfer gate");
        assert_eq!(resolved.project_id, project_id);
        assert!(!resolved.browser_binding_required);
    }

    let otp = VerifyEmailProof {
        project_id,
        transaction_id,
        challenge_id,
        proof_kind: EmailProofKind::Otp,
        proof_digest: digest_at(7, 2),
        browser_binding: Some(digest(3)),
        csrf: digest(4),
        transfer_context: None,
        expected_transaction_revision: 4,
        now: now + Duration::seconds(36),
    };
    let magic = VerifyEmailProof {
        proof_kind: EmailProofKind::MagicLink,
        proof_digest: digest(8),
        browser_binding: None,
        csrf: digest(21),
        transfer_context: Some(digest(20)),
        ..otp.clone()
    };
    let copied_magic = VerifyEmailProof {
        csrf: digest(23),
        transfer_context: Some(digest(22)),
        ..magic.clone()
    };
    assert_proof_and_mail_claim_lock_order(&pool, &email, otp.clone()).await;
    let expired_otp = email
        .verify_email_proof(VerifyEmailProof {
            now: now + Duration::minutes(3),
            ..otp.clone()
        })
        .await;
    assert!(
        matches!(
            expired_otp,
            Ok(crate::application::EmailProofDecision::Invalid)
        ),
        "unexpected expired OTP decision: {expired_otp:?}"
    );
    assert!(matches!(
        email
            .verify_email_proof(VerifyEmailProof {
                now: now + Duration::minutes(3),
                ..magic.clone()
            })
            .await,
        Ok(crate::application::EmailProofDecision::Accepted(_))
    ));
    assert!(matches!(
        email.verify_email_proof(otp.clone()).await,
        Ok(crate::application::EmailProofDecision::Accepted(_))
    ));
    assert!(matches!(
        email.verify_email_proof(magic.clone()).await,
        Ok(crate::application::EmailProofDecision::Accepted(_))
    ));

    assert!(matches!(
        email.verify_email_proof(copied_magic.clone()).await,
        Ok(crate::application::EmailProofDecision::Accepted(_))
    ));

    email_control
        .terminate_smtp_configuration(
            project_id,
            smtp_id,
            1,
            true,
            Uuid::new_v4(),
            now + Duration::seconds(37),
        )
        .await
        .expect("mark delivered generation compromised");
    assert!(
        email
            .complete_email_proof(completion(
                magic.clone(),
                "must_not_complete",
                Uuid::new_v4(),
            ))
            .await
            .is_err(),
        "a proof delivered through a subsequently compromised SMTP generation must not complete"
    );
    let counts_after_rejection: (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM email_identities),
                (SELECT COUNT(*) FROM project_browser_sessions),
                (SELECT COUNT(*) FROM handoff_tickets)",
    )
    .fetch_one(&pool)
    .await
    .expect("rejected completion counts");
    assert_eq!(counts_after_rejection, (0, 0, 0));
    // Restore the fixture directly only so this long integration test can continue proving the
    // independent one-winner and retirement invariants. Production transitions never restore a
    // compromised generation.
    sqlx::query(
        "UPDATE project_smtp_configurations SET status='active',revision=1,
         security_eligibility_revision=1,updated_at=$2 WHERE id=$1",
    )
    .bind(smtp_id)
    .bind(now + Duration::seconds(38))
    .execute(&pool)
    .await
    .expect("restore test-only SMTP fixture");

    let mut mismatched_digest = completion(magic.clone(), "mismatched_digest", Uuid::new_v4());
    mismatched_digest.verified_challenge_lookup.value[0] ^= 1;
    assert_eq!(
        email.complete_email_proof(mismatched_digest).await,
        Err(crate::application::ApplicationError::Integrity),
        "candidate lookup bytes must exact-match the re-locked challenge"
    );
    let mut mismatched_version = completion(magic.clone(), "mismatched_version", Uuid::new_v4());
    mismatched_version.verified_challenge_lookup.key_version = 2;
    assert_eq!(
        email.complete_email_proof(mismatched_version).await,
        Err(crate::application::ApplicationError::Integrity),
        "candidate lookup version must exact-match the re-locked challenge"
    );

    // Model retirement after this v1 challenge was issued. Durable identity resolution now uses
    // only v2, while the verified challenge-local v1 lookup remains independently authoritative.
    sqlx::query(
        "UPDATE email_identity_alias_authority
         SET revision=2,write_version=2,target_version=2,accepted_versions='[2]'::jsonb,
             retirement_version=2,updated_at=$1 WHERE singleton=TRUE",
    )
    .bind(now + Duration::seconds(39))
    .execute(&pool)
    .await
    .expect("retire durable v1 alias authority around a live v1 challenge");

    let mut magic_completion = completion(magic, "magic_winner", Uuid::new_v4());
    magic_completion.lookup_aliases = vec![digest_at(6, 2)];
    magic_completion.active_alias = digest_at(6, 2);
    magic_completion.alias_authority_revision = 2;
    let mut copied_completion = completion(copied_magic, "copied_winner", Uuid::new_v4());
    copied_completion.lookup_aliases = vec![digest_at(6, 2)];
    copied_completion.active_alias = digest_at(6, 2);
    copied_completion.alias_authority_revision = 2;
    let (magic_result, copied_result) = tokio::join!(
        email.complete_email_proof(magic_completion),
        email.complete_email_proof(copied_completion)
    );
    assert_eq!(
        usize::from(magic_result.is_ok()) + usize::from(copied_result.is_ok()),
        1,
        "exactly one transferred browser must consume the newest parent"
    );
    let challenge_status: String =
        sqlx::query_scalar("SELECT status FROM email_challenges WHERE id = $1")
            .bind(challenge_id)
            .fetch_one(&pool)
            .await
            .expect("challenge status");
    assert_eq!(challenge_status, "consumed");
    let counts: (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM email_identities),
                (SELECT COUNT(*) FROM project_browser_sessions),
                (SELECT COUNT(*) FROM handoff_tickets)",
    )
    .fetch_one(&pool)
    .await
    .expect("completion counts");
    assert_eq!(counts, (1, 1, 1));
    let identity_alias_versions: Vec<i32> =
        sqlx::query_scalar("SELECT digest_key_version FROM email_identity_aliases ORDER BY 1")
            .fetch_all(&pool)
            .await
            .expect("durable identity aliases after challenge-version retirement");
    assert_eq!(
        identity_alias_versions,
        vec![2],
        "current durable alias authority, not the challenge-local version, resolves the identity"
    );
    // Restore the long monolith's original authority fixture after the focused retirement proof;
    // the production lifecycle remains monotonic and is covered by the dedicated cutover test.
    sqlx::query(
        "UPDATE email_identity_alias_authority
         SET revision=1,write_version=1,target_version=1,accepted_versions='[1,2]'::jsonb,
             retirement_version=NULL,updated_at=$1 WHERE singleton=TRUE",
    )
    .bind(now + Duration::seconds(40))
    .execute(&pool)
    .await
    .expect("restore original alias-authority fixture");
    sqlx::query(
        "UPDATE email_identity_aliases
         SET digest_key_version=1,lookup_digest=$1 WHERE project_id=$2",
    )
    .bind(digest(5).value.to_vec())
    .bind(project_id)
    .execute(&pool)
    .await
    .expect("restore original durable alias fixture");

    sqlx::query(
        "CREATE TABLE email_backlog_ids
         (sequence INTEGER PRIMARY KEY,transaction_id UUID,challenge_id UUID,outbox_id UUID)",
    )
    .execute(&pool)
    .await
    .expect("create backlog identity map");
    sqlx::query(
        "INSERT INTO email_backlog_ids
         SELECT value,gen_random_uuid(),gen_random_uuid(),gen_random_uuid()
         FROM generate_series(1,150) value",
    )
    .execute(&pool)
    .await
    .expect("seed backlog identity map");
    sqlx::query(
        "INSERT INTO login_transactions
         SELECT (jsonb_populate_record(NULL::login_transactions,
           to_jsonb(source) || jsonb_build_object(
             'id',ids.transaction_id,'interaction_digest',concat('\\x',lpad(to_hex(ids.sequence),64,'0')),
             'status','email_challenge_pending','transaction_revision',4,'user_id',NULL,
             'authenticated_at',NULL,'terminal_at',NULL,'expires_at',$2,'created_at',$1,'updated_at',$1))).*
         FROM email_backlog_ids ids
         CROSS JOIN LATERAL (SELECT * FROM login_transactions WHERE id=$3) source",
    )
    .bind(now)
    .bind(now + Duration::minutes(10))
    .bind(transaction_id)
    .execute(&pool)
    .await
    .expect("seed backlog logins");
    sqlx::query(
        "INSERT INTO email_challenges
         SELECT (jsonb_populate_record(NULL::email_challenges,
           to_jsonb(source) || jsonb_build_object(
             'id',ids.challenge_id,'transaction_id',ids.transaction_id,'status','pending','generation',1,
             'otp_attempts',0,'issued_at',$1,'otp_expires_at',$2,'magic_expires_at',$2,
             'expires_at',$3,'consumed_at',NULL,'terminal_at',NULL,'redacted_at',NULL,
             'created_at',$1,'updated_at',$1))).*
         FROM email_backlog_ids ids
         CROSS JOIN LATERAL (SELECT * FROM email_challenges WHERE id=$4) source",
    )
    .bind(now)
    .bind(now + Duration::minutes(8))
    .bind(now + Duration::minutes(9))
    .bind(challenge_id)
    .execute(&pool)
    .await
    .expect("seed backlog challenges");
    sqlx::query(
        "INSERT INTO mail_outbox
         SELECT (jsonb_populate_record(NULL::mail_outbox,
           to_jsonb(source) || jsonb_build_object(
             'id',ids.outbox_id,'transaction_id',ids.transaction_id,'challenge_id',ids.challenge_id,
             'challenge_generation',1,'status','pending','message_id',concat('<',ids.outbox_id,'@mail.owlauth.invalid>'),
             'attempts',CASE WHEN ids.sequence=150 THEN 0 ELSE source.max_attempts END,
             'next_attempt_at',$1,'lease_owner',NULL,'lease_expires_at',NULL,'safe_outcome',NULL,
             'useful_until',$2,'delivered_at',NULL,'terminal_at',NULL,'redacted_at',NULL,
             'created_at',$1,'updated_at',$1))).*
         FROM email_backlog_ids ids
         CROSS JOIN LATERAL (SELECT * FROM mail_outbox WHERE challenge_id=$3) source",
    )
    .bind(now)
    .bind(now + Duration::minutes(8))
    .bind(challenge_id)
    .execute(&pool)
    .await
    .expect("seed terminalizable outbox backlog");
    assert_eq!(
        email
            .maintain_short_term_data(now + Duration::seconds(5), 25)
            .await
            .expect("first bounded backlog maintenance"),
        25
    );
    let progress = email
        .claim_due_mail(
            "runtime-backlog-progress",
            now + Duration::seconds(5),
            now + Duration::seconds(35),
        )
        .await
        .expect("claim through terminalizable backlog")
        .expect("one valid due job remains claimable");
    email
        .finish_mail_attempt(
            &progress,
            MailTransportOutcome::Permanent,
            None,
            now + Duration::seconds(6),
        )
        .await
        .expect("finish backlog progress job");
    loop {
        let remaining: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM mail_outbox outbox JOIN email_backlog_ids ids ON ids.outbox_id=outbox.id
             WHERE outbox.status IN ('pending','retry','ambiguous','leased')",
        )
        .fetch_one(&pool)
        .await
        .expect("remaining terminalizable backlog");
        if remaining == 0 {
            break;
        }
        let affected = email
            .maintain_short_term_data(now + Duration::seconds(7), 25)
            .await
            .expect("converge bounded backlog");
        assert!((1..=25).contains(&affected));
    }
    sqlx::query("DELETE FROM mail_outbox WHERE id IN (SELECT outbox_id FROM email_backlog_ids)")
        .execute(&pool)
        .await
        .expect("remove backlog outbox fixtures");
    sqlx::query(
        "DELETE FROM email_challenges WHERE id IN (SELECT challenge_id FROM email_backlog_ids)",
    )
    .execute(&pool)
    .await
    .expect("remove backlog challenge fixtures");
    sqlx::query(
        "DELETE FROM login_transactions WHERE id IN (SELECT transaction_id FROM email_backlog_ids)",
    )
    .execute(&pool)
    .await
    .expect("remove backlog login fixtures");

    let durable_base_digest: Vec<u8> =
        sqlx::query_scalar("SELECT base_profile_digest FROM project_users LIMIT 1")
            .fetch_one(&pool)
            .await
            .expect("durable email user base digest");
    let empty_profile_digest = super::projection::base_profile_digest(None, None, None, None)
        .expect("canonical empty base profile digest");
    assert_eq!(durable_base_digest, empty_profile_digest);
    let old_candidate_digest = Sha256::digest(
        serde_json::to_vec(&serde_json::json!({
            "display_name": serde_json::Value::Null,
            "locale": serde_json::Value::Null,
            "picture_url": serde_json::Value::Null,
            "verified_email": "person@example.test",
        }))
        .unwrap(),
    );
    assert_ne!(
        durable_base_digest,
        old_candidate_digest.to_vec(),
        "durable projection digest must not verify an offline email candidate"
    );
    let second_project = Uuid::new_v4();
    let second_user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO projects
         (id,public_id,display_name,status,metadata_revision,security_revision)
         VALUES ($1,$2,'Other Email Project','active',1,1)",
    )
    .bind(second_project)
    .bind(format!("prj_other_{}", second_project.simple()))
    .execute(&pool)
    .await
    .expect("second Project");
    let second_identity = Uuid::new_v4();
    let mut second_seed = pool.begin().await.expect("second Project identity seed");
    sqlx::query(
        "INSERT INTO project_users
         (id,project_id,public_id,status,user_revision,security_revision,
          primary_source_kind,base_profile_digest,local_display_name_set,local_picture_url_set,
          local_locale_set,created_at,updated_at)
         VALUES ($1,$2,$3,'active',1,1,'email',$4,FALSE,FALSE,FALSE,$5,$5)",
    )
    .bind(second_user)
    .bind(second_project)
    .bind(format!("usr_other_{}", second_user.simple()))
    .bind(&durable_base_digest)
    .bind(now)
    .execute(&mut *second_seed)
    .await
    .expect("second Project email-independent user digest");
    sqlx::query(
        "INSERT INTO email_identities
         (id,project_id,user_id,status,identity_revision,canonicalization_version,
          address_ciphertext,address_key_version,verified_at,created_at,updated_at)
         VALUES ($1,$2,$3,'active',1,1,$4,1,$5,$5,$5)",
    )
    .bind(second_identity)
    .bind(second_project)
    .bind(second_user)
    .bind(vec![92_u8; 64])
    .bind(now)
    .execute(&mut *second_seed)
    .await
    .expect("second Project protected email source");
    sqlx::query(
        "UPDATE project_users SET primary_email_identity_id=$3
         WHERE project_id=$1 AND id=$2",
    )
    .bind(second_project)
    .bind(second_user)
    .bind(second_identity)
    .execute(&mut *second_seed)
    .await
    .expect("bind second Project primary email source");
    second_seed
        .commit()
        .await
        .expect("commit second Project identity");
    let cross_project_digests: Vec<Vec<u8>> =
        sqlx::query_scalar("SELECT base_profile_digest FROM project_users ORDER BY project_id")
            .fetch_all(&pool)
            .await
            .expect("cross-Project base digests");
    assert!(
        cross_project_digests
            .iter()
            .all(|value| value == &empty_profile_digest)
    );

    let challenge_payload: (Vec<u8>, i32) = sqlx::query_as(
        "SELECT address_ciphertext,address_key_version FROM email_challenges WHERE id=$1",
    )
    .bind(challenge_id)
    .fetch_one(&pool)
    .await
    .expect("challenge payload before cleanup");
    let outbox_payload: (Vec<u8>, i32, Vec<u8>, i32) = sqlx::query_as(
        "SELECT envelope_ciphertext,envelope_key_version,body_ciphertext,body_key_version
         FROM mail_outbox WHERE challenge_id=$1",
    )
    .bind(challenge_id)
    .fetch_one(&pool)
    .await
    .expect("outbox payload before cleanup");
    let cleanup_time = now + Duration::minutes(22);
    for status in [
        "consumed",
        "exhausted",
        "expired",
        "superseded",
        "delivery_unavailable",
    ] {
        sqlx::query(
            "UPDATE email_challenges SET status=$2,consumed_at=CASE WHEN $2='consumed' THEN $3 ELSE NULL END,
             terminal_at=$3,address_ciphertext=$4,address_key_version=$5,redacted_at=NULL WHERE id=$1",
        )
        .bind(challenge_id)
        .bind(status)
        .bind(now)
        .bind(&challenge_payload.0)
        .bind(challenge_payload.1)
        .execute(&pool)
        .await
        .expect("stage terminal challenge payload");
        let affected = email
            .maintain_short_term_data(cleanup_time, 1)
            .await
            .expect("bounded challenge redaction");
        assert_eq!(affected, 1);
        assert!(
            sqlx::query_scalar::<_, Option<Vec<u8>>>(
                "SELECT address_ciphertext FROM email_challenges WHERE id=$1",
            )
            .bind(challenge_id)
            .fetch_one(&pool)
            .await
            .expect("challenge redaction state")
            .is_none()
        );
    }
    for status in [
        "delivered",
        "permanent_failure",
        "ambiguous",
        "cancelled",
        "expired",
    ] {
        sqlx::query(
            "UPDATE mail_outbox SET status=$2,terminal_at=$3,envelope_ciphertext=$4,
             envelope_key_version=$5,body_ciphertext=$6,body_key_version=$7,redacted_at=NULL,
             lease_owner=NULL,lease_expires_at=NULL WHERE challenge_id=$1",
        )
        .bind(challenge_id)
        .bind(status)
        .bind(now)
        .bind(&outbox_payload.0)
        .bind(outbox_payload.1)
        .bind(&outbox_payload.2)
        .bind(outbox_payload.3)
        .execute(&pool)
        .await
        .expect("stage terminal outbox payload");
        let affected = email
            .maintain_short_term_data(cleanup_time, 1)
            .await
            .expect("bounded outbox redaction");
        assert_eq!(affected, 1);
    }
    // An abandoned pending challenge first terminalizes and then redacts within the same bounded
    // tick while its still-active protection key remains configured.
    sqlx::query(
        "UPDATE email_challenges SET status='pending',consumed_at=NULL,terminal_at=NULL,
         issued_at=$2,otp_expires_at=$3,magic_expires_at=$3,expires_at=$4,
         address_ciphertext=$5,address_key_version=$6,redacted_at=NULL WHERE id=$1",
    )
    .bind(challenge_id)
    .bind(now - Duration::minutes(29))
    .bind(now - Duration::minutes(25))
    .bind(now - Duration::minutes(20))
    .bind(&challenge_payload.0)
    .bind(challenge_payload.1)
    .execute(&pool)
    .await
    .expect("stage abandoned challenge");
    let maintained = email
        .maintain_short_term_data(now, 2)
        .await
        .expect("bounded abandoned cleanup");
    assert_eq!(maintained, 2);
    let transfer_deleted = email
        .maintain_short_term_data(cleanup_time, 100)
        .await
        .expect("terminal transfer-context deletion");
    assert_eq!(transfer_deleted, 8);
    let redaction: (String, bool, bool, i64) = sqlx::query_as(
        "SELECT challenge.status,challenge.address_ciphertext IS NULL,
                outbox.envelope_ciphertext IS NULL AND outbox.body_ciphertext IS NULL,
                (SELECT COUNT(*) FROM magic_transfer_contexts)
         FROM email_challenges challenge JOIN mail_outbox outbox ON outbox.challenge_id=challenge.id
         WHERE challenge.id=$1",
    )
    .bind(challenge_id)
    .fetch_one(&pool)
    .await
    .expect("short-term payload redaction");
    assert_eq!(redaction, ("expired".to_owned(), true, true, 0));

    sqlx::query(
        "UPDATE project_smtp_configurations
         SET status='retained',retained_until=$2 WHERE project_id=$1 AND id=$3",
    )
    .bind(project_id)
    .bind(now + Duration::minutes(1))
    .bind(smtp_id)
    .execute(&pool)
    .await
    .expect("expire retained Project SMTP generation");
    sqlx::query(
        "UPDATE deployment_smtp_generations
         SET status='retained',retained_until=$2 WHERE generation=$1",
    )
    .bind(7_i32)
    .bind(now + Duration::minutes(1))
    .execute(&pool)
    .await
    .expect("expire retained deployment SMTP generation");
    let cleanup_now = now + Duration::minutes(12);
    for _ in 0..2 {
        let cleanup = email
            .claim_smtp_credential_cleanup(
                "runtime-cleanup",
                cleanup_now,
                cleanup_now + Duration::seconds(30),
            )
            .await
            .expect("claim expired SMTP generation cleanup")
            .expect("cleanup available");
        email
            .finish_smtp_credential_cleanup(&cleanup, cleanup_now)
            .await
            .expect("finish idempotent external credential erase ledger");
    }
    assert!(
        email
            .claim_smtp_credential_cleanup(
                "runtime-cleanup",
                cleanup_now,
                cleanup_now + Duration::seconds(30),
            )
            .await
            .expect("cleanup exhaustion")
            .is_none()
    );
    let retirement_counts: (i64, i64, i64) = sqlx::query_as(
        "SELECT
          (SELECT COUNT(*) FROM project_smtp_configurations WHERE status='retired'),
          (SELECT COUNT(*) FROM deployment_smtp_generations WHERE status='retired'),
          (SELECT COUNT(*) FROM smtp_credential_cleanup_operations WHERE state='erased')",
    )
    .fetch_one(&pool)
    .await
    .expect("retirement closure inventory");
    assert_eq!(retirement_counts, (1, 1, 2));

    // Disabled and compromised generations enter the same durable retirement ledger as expired
    // overlap rows. A still-live configuration sharing the credential reference blocks every
    // external erase until all references are retired.
    let disabled_smtp_id = Uuid::new_v4();
    let compromised_smtp_id = Uuid::new_v4();
    let shared_blocker_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO project_smtp_configurations
         (id,project_id,status,generation,revision,security_eligibility_revision,host,port,tls_mode,
          sender_address,credential_ref,safe_fingerprint,created_at,updated_at)
         VALUES ($1,$2,'disabled',20,2,2,'smtp.example.com',465,'implicit_tls','login@example.com',
                 'terminal_shared_ref',$5,$6,$6),
                ($3,$2,'compromised',21,2,2,'smtp.example.com',465,'implicit_tls','login@example.com',
                 'terminal_shared_ref',$5,$6,$6),
                ($4,$2,'active',22,1,1,'smtp.example.com',465,'implicit_tls','login@example.com',
                 'terminal_shared_ref',$5,$6,$6)",
    )
    .bind(disabled_smtp_id)
    .bind(project_id)
    .bind(compromised_smtp_id)
    .bind(shared_blocker_id)
    .bind(vec![9_u8; 32])
    .bind(cleanup_now)
    .execute(&pool)
    .await
    .expect("seed terminal Project cleanup matrix");
    sqlx::query(
        "INSERT INTO deployment_smtp_generations
         (generation,status,revision,security_eligibility_revision,host,port,tls_mode,sender_address,
          credential_ref,safe_fingerprint,explicitly_allowed_private_ips,material_owner_id,created_at,updated_at)
         VALUES (20,'disabled',2,2,'smtp.example.com',465,'implicit_tls','deployment@example.com',
                 'terminal_shared_ref',$1,'[]'::jsonb,md5('email-test-deployment-20')::uuid,$2,$2),
                (21,'compromised',2,2,'smtp.example.com',465,'implicit_tls','deployment@example.com',
                 'terminal_shared_ref',$1,'[]'::jsonb,md5('email-test-deployment-21')::uuid,$2,$2)",
    )
    .bind(vec![10_u8; 32])
    .bind(cleanup_now)
    .execute(&pool)
    .await
    .expect("seed terminal deployment cleanup matrix");
    assert!(
        email
            .claim_smtp_credential_cleanup(
                "shared-ref-blocked",
                cleanup_now + Duration::seconds(1),
                cleanup_now + Duration::seconds(31),
            )
            .await
            .expect("retire terminal generations while shared ref remains live")
            .is_none()
    );
    let blocked: (i64, i64, i64) = sqlx::query_as(
        "SELECT
          (SELECT COUNT(*) FROM project_smtp_configurations
           WHERE generation IN (20,21) AND status='retired'),
          (SELECT COUNT(*) FROM deployment_smtp_generations
           WHERE generation IN (20,21) AND status='retired'),
          (SELECT COUNT(*) FROM smtp_credential_cleanup_operations
           WHERE credential_ref='terminal_shared_ref' AND state='pending')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(blocked, (2, 2, 4));
    sqlx::query(
        "UPDATE project_smtp_configurations SET status='disabled',security_eligibility_revision=2
         WHERE id=$1",
    )
    .bind(shared_blocker_id)
    .execute(&pool)
    .await
    .unwrap();
    let cleanup = email
        .claim_smtp_credential_cleanup(
            "terminal-cleanup",
            cleanup_now + Duration::seconds(2),
            cleanup_now + Duration::seconds(32),
        )
        .await
        .unwrap()
        .expect("one shared-reference cleanup operation owns the external erase");
    email
        .finish_smtp_credential_cleanup(&cleanup, cleanup_now + Duration::seconds(2))
        .await
        .unwrap();
    // Sibling operations converge against the durable erased tombstone without repeating the
    // external erase or audit. One bounded call terminalizes one sibling operation.
    for _ in 0..4 {
        assert!(
            email
                .claim_smtp_credential_cleanup(
                    "terminal-cleanup",
                    cleanup_now + Duration::seconds(2),
                    cleanup_now + Duration::seconds(32),
                )
                .await
                .unwrap()
                .is_none()
        );
    }

    // A process loss after leasing does not lose the external erase. The same durable operation
    // is recoverable after lease expiry and can then converge normally.
    sqlx::query(
        "INSERT INTO deployment_smtp_generations
         (generation,status,revision,security_eligibility_revision,host,port,tls_mode,sender_address,
          credential_ref,safe_fingerprint,explicitly_allowed_private_ips,material_owner_id,created_at,updated_at)
         VALUES (30,'compromised',2,2,'smtp.example.com',465,'implicit_tls','deployment@example.com',
                 'crash_recovery_ref',$1,'[]'::jsonb,md5('email-test-deployment-30')::uuid,$2,$2)",
    )
    .bind(vec![11_u8; 32])
    .bind(cleanup_now)
    .execute(&pool)
    .await
    .unwrap();
    let crash_time = cleanup_now + Duration::seconds(3);
    let abandoned_cleanup = email
        .claim_smtp_credential_cleanup(
            "cleanup-crashed",
            crash_time,
            crash_time + Duration::seconds(30),
        )
        .await
        .unwrap()
        .expect("lease crash-recoverable cleanup");
    assert!(
        email
            .claim_smtp_credential_cleanup(
                "cleanup-too-early",
                crash_time + Duration::seconds(1),
                crash_time + Duration::seconds(31),
            )
            .await
            .unwrap()
            .is_none()
    );
    let recovered_cleanup = email
        .claim_smtp_credential_cleanup(
            "cleanup-recovered",
            crash_time + Duration::seconds(31),
            crash_time + Duration::seconds(61),
        )
        .await
        .unwrap()
        .expect("recover expired cleanup lease");
    assert_eq!(recovered_cleanup.id, abandoned_cleanup.id);
    email
        .finish_smtp_credential_cleanup(&recovered_cleanup, crash_time + Duration::seconds(31))
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM smtp_credential_cleanup_operations WHERE state='erased'",
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        8
    );

    // An exact completed create replay remains a stable retired tombstone after external erase.
    // The controlled write-only store proves the old idempotency key never provisions again.
    let replay_revision: i64 =
        sqlx::query_scalar("SELECT security_revision FROM projects WHERE id=$1")
            .bind(project_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let provisioner = Arc::new(CountingSmtpProvisioner::default());
    let smtp_service = EmailControlService::new(
        Arc::new(PostgresEmailControlRepository::new(database.clone())),
        provisioner.clone(),
        Arc::new(SystemClock),
        Arc::new(Sha256RequestDigester),
    );
    let replay_command = || CreateSmtpConfiguration {
        host: "replay.smtp.example".to_owned(),
        port: 465,
        tls_mode: SmtpControlTlsMode::ImplicitTls,
        sender_address: "replay@example.com".to_owned(),
        sender_name: None,
        reply_to: None,
        credential: Zeroizing::new(r#"{"username":"replay","password":"secret"}"#.to_owned()),
        idempotency_key: "smtp-erased-replay-1".to_owned(),
        expected_project_security_revision: replay_revision,
        correlation_id: Uuid::new_v4(),
    };
    let replay_configuration = smtp_service
        .create_smtp(project_id, replay_command())
        .await
        .expect("create SMTP operation before erased replay");
    assert_eq!(provisioner.writes.load(Ordering::SeqCst), 1);
    let replay_credential_ref: String =
        sqlx::query_scalar("SELECT credential_ref FROM project_smtp_configurations WHERE id=$1")
            .bind(replay_configuration.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    email_control
        .terminate_smtp_configuration(
            project_id,
            replay_configuration.id,
            replay_configuration.revision,
            true,
            Uuid::new_v4(),
            cleanup_now + Duration::seconds(40),
        )
        .await
        .expect("compromise replay generation");
    let erased_replay_cleanup = email
        .claim_smtp_credential_cleanup(
            "erased-replay-cleanup",
            cleanup_now + Duration::seconds(41),
            cleanup_now + Duration::seconds(71),
        )
        .await
        .unwrap()
        .expect("claim erased replay credential");
    assert_eq!(erased_replay_cleanup.credential_ref, replay_credential_ref);
    email
        .finish_smtp_credential_cleanup(&erased_replay_cleanup, cleanup_now + Duration::seconds(42))
        .await
        .unwrap();
    let replay_audits_before: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events WHERE project_id=$1
         AND action IN ('email.smtp.prepared','email.smtp.reconciled')",
    )
    .bind(project_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let tombstone = smtp_service
        .create_smtp(project_id, replay_command())
        .await
        .expect("exact old create replay returns durable tombstone");
    assert_eq!(tombstone.status, SmtpControlStatus::Retired);
    assert_eq!(provisioner.writes.load(Ordering::SeqCst), 1);
    let replay_audits_after: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events WHERE project_id=$1
         AND action IN ('email.smtp.prepared','email.smtp.reconciled')",
    )
    .bind(project_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(replay_audits_before, replay_audits_after);

    // A committed cleanup reservation wins over both Project registration and deployment
    // reconciliation. Neither path can publish a live generation before the external erase and
    // durable tombstone complete.
    let race_ref = "smtp_cleanup_reserved_race_ref";
    sqlx::query(
        "INSERT INTO deployment_smtp_generations
         (generation,status,revision,security_eligibility_revision,host,port,tls_mode,
          sender_address,credential_ref,safe_fingerprint,explicitly_allowed_private_ips,
          material_owner_id,created_at,updated_at)
         VALUES (40,'compromised',2,2,'race.smtp.example',465,'implicit_tls',
                 'race@example.com',$1,$2,'[]'::jsonb,md5('email-test-deployment-40')::uuid,$3,$3)",
    )
    .bind(race_ref)
    .bind(vec![40_u8; 32])
    .bind(cleanup_now + Duration::seconds(50))
    .execute(&pool)
    .await
    .unwrap();
    let reserved_cleanup = email
        .claim_smtp_credential_cleanup(
            "reservation-paused-after-commit",
            cleanup_now + Duration::seconds(51),
            cleanup_now + Duration::seconds(81),
        )
        .await
        .unwrap()
        .expect("cleanup reservation committed before simulated external erase");
    assert_eq!(reserved_cleanup.credential_ref, race_ref);
    let current_project_revision: i64 =
        sqlx::query_scalar("SELECT security_revision FROM projects WHERE id=$1")
            .bind(project_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(matches!(
        email_control
            .prepare_smtp_configuration(
                project_id,
                PrepareSmtpConfiguration {
                    id: Uuid::new_v4(),
                    host: "race.smtp.example".to_owned(),
                    port: 465,
                    tls_mode: SmtpControlTlsMode::ImplicitTls,
                    sender_address: "race@example.com".to_owned(),
                    sender_name: None,
                    reply_to: None,
                    operation_alias: "reserved-project-race-1".to_owned(),
                    credential_ref: race_ref.to_owned(),
                    request_digest: vec![51; 32],
                    safe_fingerprint: Some([51; 32]),
                    expected_project_security_revision: current_project_revision,
                    correlation_id: Uuid::new_v4(),
                },
                cleanup_now + Duration::seconds(52),
            )
            .await,
        Err(crate::application::ApplicationError::InvalidTransition)
    ));
    assert!(matches!(
        email
            .reconcile_deployment_smtp(
                &DeploymentSmtpGeneration {
                    generation: 41,
                    desired_status: DeploymentSmtpDesiredStatus::Active,
                    host: "race.smtp.example".to_owned(),
                    port: 465,
                    tls_mode: SmtpTlsMode::ImplicitTls,
                    sender_address: "race@example.com".to_owned(),
                    credential_ref: race_ref.to_owned(),
                    safe_fingerprint: [51; 32],
                    explicitly_allowed_private_ips: Vec::new(),
                },
                cleanup_now + Duration::seconds(52),
            )
            .await,
        Err(crate::application::ApplicationError::InvalidTransition)
    ));
    // Simulate a worker crash after the durable reservation. Once its lease expires, the same
    // reservation owner is recovered rather than allowing a sibling operation to starve it.
    let recovered_cleanup = email
        .claim_smtp_credential_cleanup(
            "reservation-crash-recovery",
            cleanup_now + Duration::seconds(82),
            cleanup_now + Duration::seconds(112),
        )
        .await
        .unwrap()
        .expect("expired reserved cleanup lease is recoverable");
    assert_eq!(recovered_cleanup.id, reserved_cleanup.id);
    assert_eq!(recovered_cleanup.credential_ref, race_ref);
    email
        .finish_smtp_credential_cleanup(&recovered_cleanup, cleanup_now + Duration::seconds(83))
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM project_smtp_configurations
             WHERE credential_ref=$1 AND status<>'retired'",
        )
        .bind(race_ref)
        .fetch_one(&pool)
        .await
        .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT state FROM smtp_credential_reference_reservations WHERE credential_ref=$1",
        )
        .bind(race_ref)
        .fetch_one(&pool)
        .await
        .unwrap(),
        "erased"
    );

    // Once provisioning enters its external write, no PostgreSQL transaction remains open.
    // A concurrent disable must make deterministic progress while the external store is paused;
    // the guarded finalize then loses to the terminal owner state.
    let barrier_ref = format!("smtp_barrier_{}", Uuid::new_v4().simple());
    let barrier_revision: i64 =
        sqlx::query_scalar("SELECT security_revision FROM projects WHERE id=$1")
            .bind(project_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let barrier_prepared = email_control
        .prepare_smtp_configuration(
            project_id,
            PrepareSmtpConfiguration {
                id: Uuid::new_v4(),
                host: "barrier.smtp.example".to_owned(),
                port: 465,
                tls_mode: SmtpControlTlsMode::ImplicitTls,
                sender_address: "barrier@example.com".to_owned(),
                sender_name: None,
                reply_to: None,
                operation_alias: "barrier-provision-serialization-1".to_owned(),
                credential_ref: barrier_ref.clone(),
                request_digest: vec![60; 32],
                safe_fingerprint: Some([60; 32]),
                expected_project_security_revision: barrier_revision,
                correlation_id: Uuid::new_v4(),
            },
            cleanup_now + Duration::seconds(100),
        )
        .await
        .expect("prepare barrier-controlled SMTP provision");
    let barrier = Arc::new(BarrierSmtpProvisioner::new());
    let provision_repository = PostgresEmailControlRepository::new(database.clone());
    let provision_barrier = barrier.clone();
    let provision_prepared = barrier_prepared.clone();
    let provision_task = tokio::spawn(async move {
        provision_repository
            .provision_and_finalize_smtp_configuration(
                project_id,
                &provision_prepared,
                provision_barrier.as_ref(),
                Zeroizing::new(b"barrier-secret".to_vec()),
                cleanup_now + Duration::seconds(101),
            )
            .await
    });
    barrier
        .entered
        .acquire()
        .await
        .expect("provision reaches external barrier")
        .forget();
    let disable_repository = PostgresEmailControlRepository::new(database.clone());
    let barrier_configuration_id = barrier_prepared.record.id;
    let barrier_configuration_revision = barrier_prepared.record.revision;
    let disable_task = tokio::spawn(async move {
        disable_repository
            .terminate_smtp_configuration(
                project_id,
                barrier_configuration_id,
                barrier_configuration_revision,
                false,
                Uuid::new_v4(),
                cleanup_now + Duration::seconds(102),
            )
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), disable_task)
        .await
        .expect("disable is not blocked by paused external provisioning")
        .expect("join barrier disable")
        .expect("disable commits while external provisioning is paused");
    barrier.release.add_permits(1);
    assert_eq!(
        provision_task.await.expect("join barrier provision"),
        Err(crate::application::ApplicationError::InvalidTransition),
        "post-write finalize must lose to the committed terminal owner state"
    );
    assert_eq!(barrier.writes.load(Ordering::SeqCst), 1);
    let barrier_cleanup = email
        .claim_smtp_credential_cleanup(
            "barrier-cleanup",
            cleanup_now + Duration::seconds(103),
            cleanup_now + Duration::seconds(133),
        )
        .await
        .unwrap()
        .expect("cleanup follows the committed disable and rejected finalize");
    assert_eq!(barrier_cleanup.credential_ref, barrier_ref);
    email
        .finish_smtp_credential_cleanup(&barrier_cleanup, cleanup_now + Duration::seconds(104))
        .await
        .unwrap();

    // Model process loss after durable prepare and a delayed writer resuming only after disable,
    // cleanup reservation, external erase, and tombstone. The new repository instance must check
    // the terminal owner/reference state before making any external write.
    let delayed_ref = format!("smtp_delayed_{}", Uuid::new_v4().simple());
    let delayed_revision: i64 =
        sqlx::query_scalar("SELECT security_revision FROM projects WHERE id=$1")
            .bind(project_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let delayed = email_control
        .prepare_smtp_configuration(
            project_id,
            PrepareSmtpConfiguration {
                id: Uuid::new_v4(),
                host: "delayed.smtp.example".to_owned(),
                port: 465,
                tls_mode: SmtpControlTlsMode::ImplicitTls,
                sender_address: "delayed@example.com".to_owned(),
                sender_name: None,
                reply_to: None,
                operation_alias: "delayed-provision-after-erase-1".to_owned(),
                credential_ref: delayed_ref.clone(),
                request_digest: vec![61; 32],
                safe_fingerprint: Some([61; 32]),
                expected_project_security_revision: delayed_revision,
                correlation_id: Uuid::new_v4(),
            },
            cleanup_now + Duration::seconds(120),
        )
        .await
        .expect("durably prepare delayed SMTP provision");
    email_control
        .terminate_smtp_configuration(
            project_id,
            delayed.record.id,
            delayed.record.revision,
            false,
            Uuid::new_v4(),
            cleanup_now + Duration::seconds(121),
        )
        .await
        .expect("disable before delayed provision resumes");
    let delayed_cleanup = email
        .claim_smtp_credential_cleanup(
            "delayed-provision-cleanup",
            cleanup_now + Duration::seconds(122),
            cleanup_now + Duration::seconds(152),
        )
        .await
        .unwrap()
        .expect("reserve delayed reference for erase");
    assert_eq!(delayed_cleanup.credential_ref, delayed_ref);
    email
        .finish_smtp_credential_cleanup(&delayed_cleanup, cleanup_now + Duration::seconds(123))
        .await
        .expect("tombstone delayed reference after erase");
    let delayed_provisioner = CountingSmtpProvisioner::default();
    assert_eq!(
        PostgresEmailControlRepository::new(database.clone())
            .provision_and_finalize_smtp_configuration(
                project_id,
                &delayed,
                &delayed_provisioner,
                Zeroizing::new(b"delayed-secret".to_vec()),
                cleanup_now + Duration::seconds(124),
            )
            .await,
        Err(crate::application::ApplicationError::InvalidTransition)
    );
    assert_eq!(delayed_provisioner.writes.load(Ordering::SeqCst), 0);

    // A locked old-key short-term row is skipped by the bounded terminalizer, but must remain
    // visible in inventory and keep readiness unavailable until a later retry can terminalize it.
    let locked_outbox_id: Uuid =
        sqlx::query_scalar("SELECT id FROM mail_outbox ORDER BY id LIMIT 1")
            .fetch_one(&pool)
            .await
            .expect("short-term protection fixture");
    sqlx::query(
        "UPDATE mail_outbox SET status='pending',
         envelope_ciphertext=decode(repeat('aa',41),'hex'),envelope_key_version=2,
         body_ciphertext=decode(repeat('bb',41),'hex'),body_key_version=2,
         lease_owner=NULL,lease_expires_at=NULL,safe_outcome=NULL,terminal_at=NULL,delivered_at=NULL,
         redacted_at=NULL WHERE id=$1",
    )
    .bind(locked_outbox_id)
    .execute(&pool)
    .await
    .expect("stage unreadable short-term payload");
    let mut short_term_lock = pool.begin().await.expect("begin short-term lock");
    sqlx::query("SELECT id FROM mail_outbox WHERE id=$1 FOR UPDATE")
        .bind(locked_outbox_id)
        .fetch_one(&mut *short_term_lock)
        .await
        .expect("lock unreadable short-term payload");
    assert!(matches!(
        email
            .reconcile_protection_inventory(&[1], &[1], now + Duration::minutes(5))
            .await,
        Err(crate::application::ApplicationError::Integrity)
    ));
    let still_pending: String = sqlx::query_scalar("SELECT status FROM mail_outbox WHERE id=$1")
        .bind(locked_outbox_id)
        .fetch_one(&pool)
        .await
        .expect("locked payload remains pending");
    assert_eq!(still_pending, "pending");
    short_term_lock
        .rollback()
        .await
        .expect("release short-term lock");
    email
        .reconcile_protection_inventory(&[1], &[1], now + Duration::minutes(5))
        .await
        .expect("retry terminalizes unlocked unreadable short-term payload");

    // Challenge lookup digests share the durable email-identity namespace, while every other
    // challenge/outbox value is short-lived. Exercise reconciliation with deliberately
    // non-overlapping version numbers so matching numeric versions cannot hide a namespace bug.
    let namespace_challenge_id: Uuid =
        sqlx::query_scalar("SELECT challenge_id FROM mail_outbox WHERE id=$1")
            .bind(locked_outbox_id)
            .fetch_one(&pool)
            .await
            .expect("lookup-namespace challenge fixture");
    let mut namespace_fixture = pool.begin().await.expect("begin namespace fixture");
    sqlx::query(
        "UPDATE email_challenges SET status='superseded',terminal_at=$2
         WHERE transaction_id=(SELECT transaction_id FROM email_challenges WHERE id=$1)
           AND id<>$1 AND status='pending'",
    )
    .bind(namespace_challenge_id)
    .bind(now + Duration::minutes(6))
    .execute(&mut *namespace_fixture)
    .await
    .expect("retire any sibling pending challenge fixture");
    sqlx::query(
        "UPDATE email_challenges SET status='pending',terminal_at=NULL,consumed_at=NULL,
         lookup_digest_key_version=2,address_ciphertext=decode(repeat('cc',41),'hex'),
         address_key_version=1,redacted_at=NULL,
         otp_digest_key_version=CASE WHEN otp_digest IS NULL THEN NULL ELSE 1 END,
         magic_digest_key_version=CASE WHEN magic_digest IS NULL THEN NULL ELSE 1 END
         WHERE id=$1",
    )
    .bind(namespace_challenge_id)
    .execute(&mut *namespace_fixture)
    .await
    .expect("stage live challenge with split key namespaces");
    sqlx::query("UPDATE email_challenges SET lookup_digest_key_version=2 WHERE status='pending'")
        .execute(&mut *namespace_fixture)
        .await
        .expect("align other live lookup digests with durable namespace");
    sqlx::query(
        "UPDATE mail_outbox SET status='pending',
         envelope_ciphertext=decode(repeat('dd',41),'hex'),envelope_key_version=1,
         body_ciphertext=decode(repeat('ee',41),'hex'),body_key_version=1,redacted_at=NULL,
         safe_outcome=NULL,terminal_at=NULL,delivered_at=NULL,lease_owner=NULL,lease_expires_at=NULL
         WHERE id=$1",
    )
    .bind(locked_outbox_id)
    .execute(&mut *namespace_fixture)
    .await
    .expect("stage live outbox with short-term namespace");
    sqlx::query("UPDATE email_identity_aliases SET digest_key_version=2")
        .execute(&mut *namespace_fixture)
        .await
        .expect("stage durable identity digests at version two");
    sqlx::query("UPDATE email_identities SET address_key_version=2")
        .execute(&mut *namespace_fixture)
        .await
        .expect("stage durable identity protection at version two");
    namespace_fixture
        .commit()
        .await
        .expect("commit split namespace fixture");

    let inventory = email
        .reconcile_protection_inventory(&[1], &[2], now + Duration::minutes(6))
        .await
        .expect("independently readable key namespaces remain ready");
    assert_eq!(inventory.short_term_digest_versions, [1].into());
    assert_eq!(inventory.short_term_protection_versions, [1].into());
    assert_eq!(inventory.durable_digest_versions, [2].into());
    assert_eq!(inventory.durable_protection_versions, [2].into());
    let live_statuses: (String, String) = sqlx::query_as(
        "SELECT challenge.status,outbox.status FROM email_challenges challenge
         JOIN mail_outbox outbox ON outbox.project_id=challenge.project_id
          AND outbox.challenge_id=challenge.id
         WHERE challenge.id=$1 AND outbox.id=$2",
    )
    .bind(namespace_challenge_id)
    .bind(locked_outbox_id)
    .fetch_one(&pool)
    .await
    .expect("live split-namespace work remains available");
    assert_eq!(live_statuses, ("pending".to_owned(), "pending".to_owned()));

    assert!(matches!(
        email
            .reconcile_protection_inventory(&[1], &[1], now + Duration::minutes(7))
            .await,
        Err(crate::application::ApplicationError::Integrity)
    ));
    let statuses_after_missing_identity: (String, String) = sqlx::query_as(
        "SELECT challenge.status,outbox.status FROM email_challenges challenge
         JOIN mail_outbox outbox ON outbox.project_id=challenge.project_id
          AND outbox.challenge_id=challenge.id
         WHERE challenge.id=$1 AND outbox.id=$2",
    )
    .bind(namespace_challenge_id)
    .bind(locked_outbox_id)
    .fetch_one(&pool)
    .await
    .expect("missing identity key does not terminalize readable short-term work");
    assert_eq!(statuses_after_missing_identity, live_statuses);
    sqlx::query(
        "UPDATE project_smtp_configurations SET status='active',retained_until=NULL
         WHERE id=$1",
    )
    .bind(smtp_id)
    .execute(&pool)
    .await
    .expect("restore SMTP prerequisite for scoped protection readiness");
    email
        .record_email_protection_readiness(false, Some("integrity"), now + Duration::minutes(7))
        .await
        .expect("persist scoped email protection failure");
    let protection_status: (String, Option<String>) = sqlx::query_as(
        "SELECT state,failure_class FROM email_protection_runtime_readiness
         WHERE process_id='runtime-1'",
    )
    .fetch_one(&pool)
    .await
    .expect("bounded email protection status");
    assert_eq!(
        protection_status,
        ("unavailable".to_owned(), Some("integrity".to_owned()))
    );
    let (project_public_id, application_public_id): (String, String) = sqlx::query_as(
        "SELECT project.public_id,application.public_id FROM projects project
         JOIN applications application ON application.project_id=project.id
         WHERE project.id=$1 AND application.id=$2",
    )
    .bind(project_id)
    .bind(application_id)
    .fetch_one(&pool)
    .await
    .expect("public email authority IDs");
    let readiness = PostgresReadinessAdapter::new(
        database.clone(),
        "runtime-1".to_owned(),
        Uuid::nil(),
        vec!["runtime-1".to_owned()],
        std::time::Duration::from_secs(30),
    );
    let unavailable_public = readiness
        .public_application_config(&project_public_id, &application_public_id)
        .await
        .expect("non-email public configuration remains available");
    assert!(!unavailable_public.email_available);
    let before: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM email_challenges),
                (SELECT COUNT(*) FROM mail_outbox)",
    )
    .fetch_one(&pool)
    .await
    .expect("email work counts before unavailable attempt");
    assert_eq!(
        email
            .prepare_email_generation(
                project_id,
                Uuid::new_v4(),
                1,
                &digest(1),
                &digest(2),
                now + Duration::minutes(8),
            )
            .await,
        Err(crate::application::ApplicationError::Disabled)
    );
    assert_eq!(
        email
            .claim_due_mail(
                "protection-unavailable-worker",
                now + Duration::minutes(8),
                now + Duration::minutes(8) + Duration::seconds(30),
            )
            .await,
        Err(crate::application::ApplicationError::Disabled)
    );
    let after: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM email_challenges),
                (SELECT COUNT(*) FROM mail_outbox)",
    )
    .fetch_one(&pool)
    .await
    .expect("email work counts after unavailable attempt");
    assert_eq!(after, before);

    email
        .record_email_protection_readiness(true, None, now + Duration::minutes(9))
        .await
        .expect("restored long-term ring reopens exact Runtime capability");
    let restored_prerequisites: (String, String, String, bool, String, bool, i64) = sqlx::query_as(
        "SELECT policy.status,assignment.status,smtp.status,
                smtp_ready.lease_expires_at>transaction_timestamp(),protection.state,
                protection.lease_expires_at>transaction_timestamp(),
                (SELECT COUNT(*) FROM project_signing_keys signing
                 WHERE signing.project_id=$1 AND signing.state='active')
         FROM project_email_policies policy
         JOIN application_email_assignments assignment
           ON assignment.project_id=policy.project_id AND assignment.application_id=$2
         JOIN project_smtp_configurations smtp ON smtp.project_id=policy.project_id
         JOIN project_smtp_runtime_readiness smtp_ready
           ON smtp_ready.project_id=smtp.project_id AND smtp_ready.configuration_id=smtp.id
          AND smtp_ready.generation=smtp.generation AND smtp_ready.process_id='runtime-1'
         JOIN email_protection_runtime_readiness protection
           ON protection.process_id='runtime-1'
         WHERE policy.project_id=$1",
    )
    .bind(project_id)
    .bind(application_id)
    .fetch_one(&pool)
    .await
    .expect("restored public email prerequisites");
    assert_eq!(
        restored_prerequisites,
        (
            "enabled".to_owned(),
            "active".to_owned(),
            "active".to_owned(),
            true,
            "ready".to_owned(),
            true,
            1,
        )
    );
    let restored_public = readiness
        .public_application_config(&project_public_id, &application_public_id)
        .await
        .expect("restored public email configuration");
    assert!(restored_public.email_available);
    assert!(matches!(
        email
            .prepare_email_generation(
                project_id,
                Uuid::new_v4(),
                1,
                &digest(1),
                &digest(2),
                now + Duration::minutes(9),
            )
            .await,
        Err(crate::application::ApplicationError::NotFound)
    ));
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one real restore journey proves missing-secret isolation, restart persistence, and reconciliation"
)]
async fn project_smtp_restore_readiness_is_project_scoped_and_restart_safe_in_postgres() {
    let Some((_container, url)) = start_postgres().await else {
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .expect("connect sqlx");
    MIGRATOR.run(&pool).await.expect("migrate schema");
    let now = OffsetDateTime::now_utc();
    let (affected_project, affected_application, affected_smtp, _) =
        seed_email_authority(&pool, now).await;
    let (healthy_project, healthy_application, healthy_smtp, _) =
        seed_email_authority(&pool, now).await;
    let database = Database::connect(&url).await.expect("connect SeaORM");
    let repository = PostgresPasswordlessEmailRepository::new(database.clone());
    let secret_root =
        env::temp_dir().join(format!("owlauth-project-smtp-restore-{}", Uuid::new_v4()));
    let store = EncryptedFileStore::new(secret_root.clone(), [42; 32]).expect("test Runtime store");
    let affected_credential = b"affected-restored-smtp-secret".to_vec();
    let healthy_credential = b"healthy-restored-smtp-secret".to_vec();
    let affected_ref = format!("restore_affected_{}", affected_project.simple());
    let healthy_ref = format!("restore_healthy_{}", healthy_project.simple());
    ConfigurationSecretProvisioner::provision_if_absent(
        &store,
        healthy_ref.clone(),
        Zeroizing::new(healthy_credential.clone()),
    )
    .await
    .expect("healthy restored SMTP secret");
    sqlx::query(
        "UPDATE project_smtp_configurations
         SET credential_ref=CASE WHEN project_id=$1 THEN $2 ELSE $3 END,
             safe_fingerprint=CASE WHEN project_id=$1 THEN $4 ELSE $5 END
         WHERE (project_id=$1 AND id=$6) OR (project_id=$7 AND id=$8)",
    )
    .bind(affected_project)
    .bind(&affected_ref)
    .bind(&healthy_ref)
    .bind(store.request_fingerprint(&affected_credential))
    .bind(store.request_fingerprint(&healthy_credential))
    .bind(affected_smtp)
    .bind(healthy_project)
    .bind(healthy_smtp)
    .execute(&pool)
    .await
    .unwrap();
    // Put one invalid active generation strictly beyond the first 100 candidates: one hundred
    // retained predecessors have no observation, while the active row has a restored ready row.
    // All predecessors share one valid external reference, which is safe because they are
    // immutable generations of the same Project in this restore fixture.
    for generation in 2..=101 {
        sqlx::query(
            "INSERT INTO project_smtp_configurations
             (id,project_id,status,generation,revision,security_eligibility_revision,host,port,
              tls_mode,sender_address,sender_name,reply_to,credential_ref,safe_fingerprint,
              retained_until,created_at,updated_at)
             SELECT $1,project_id,'retained',$2,1,1,host,port,tls_mode,sender_address,sender_name,
                    reply_to,$3,$4,$5,created_at,updated_at
             FROM project_smtp_configurations WHERE project_id=$6 AND id=$7",
        )
        .bind(Uuid::new_v4())
        .bind(generation)
        .bind(&healthy_ref)
        .bind(store.request_fingerprint(&healthy_credential))
        .bind(now + Duration::minutes(30))
        .bind(affected_project)
        .bind(affected_smtp)
        .execute(&pool)
        .await
        .expect("seed retained restore page");
    }
    let deployment = DeploymentSmtpGeneration {
        generation: 91,
        desired_status: DeploymentSmtpDesiredStatus::Active,
        host: "smtp.default.example".to_owned(),
        port: 465,
        tls_mode: SmtpTlsMode::ImplicitTls,
        sender_address: "login@default.example".to_owned(),
        credential_ref: "restore-default-91".to_owned(),
        safe_fingerprint: [91; 32],
        explicitly_allowed_private_ips: Vec::new(),
    };
    seed_legacy_deployment_smtp(&pool, &deployment).await;
    repository
        .reconcile_deployment_smtp(&deployment, now)
        .await
        .expect("seed active deployment fallback");
    let resolver = EncryptedFileProviderSecretResolver::new(store.clone());
    let restored = crate::composition::reconcile_project_smtp_readiness_restore(
        &repository,
        &resolver,
        now + Duration::seconds(1),
    )
    .await
    .expect("complete every bounded Runtime restore page");
    assert_eq!(restored, 102, "restore must inspect the page beyond 100");

    let authority = PostgresRuntimeAuthorityRepository::new(database.clone());
    assert!(matches!(
        authority
            .prepare_login_start(
                &format!("prj_{}", affected_project.simple()),
                &format!("app_{}", affected_application.simple()),
                &format!("pk_{}", affected_application.simple()),
                "https://app.example/callback",
            )
            .await,
        Err(crate::application::ApplicationError::Disabled)
    ));
    let healthy = authority
        .prepare_login_start(
            &format!("prj_{}", healthy_project.simple()),
            &format!("app_{}", healthy_application.simple()),
            &format!("pk_{}", healthy_application.simple()),
            "https://app.example/callback",
        )
        .await
        .expect("unrelated Project remains Runtime-ready");
    assert!(healthy.admitted_email.is_some());

    // A fresh repository instance models Runtime restart. The durable unavailable observation
    // remains fail-closed until a later bounded secret reconciliation proves the exact reference.
    let restarted = PostgresPasswordlessEmailRepository::new(database.clone());
    let observed: String = sqlx::query_scalar(
        "SELECT state FROM project_smtp_runtime_readiness
         WHERE project_id=$1 AND configuration_id=$2 AND generation=1",
    )
    .bind(affected_project)
    .bind(affected_smtp)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(observed, "unavailable");
    ConfigurationSecretProvisioner::provision_if_absent(
        &store,
        affected_ref,
        Zeroizing::new(affected_credential),
    )
    .await
    .expect("reconcile restored affected Project secret");
    crate::composition::reconcile_project_smtp_readiness_restore(
        &restarted,
        &resolver,
        now + Duration::seconds(2),
    )
    .await
    .expect("complete restore epoch recovers exact Project SMTP eligibility");
    assert!(
        PostgresRuntimeAuthorityRepository::new(database.clone())
            .prepare_login_start(
                &format!("prj_{}", affected_project.simple()),
                &format!("app_{}", affected_application.simple()),
                &format!("pk_{}", affected_application.simple()),
                "https://app.example/callback",
            )
            .await
            .expect("affected Project recovers without global restart")
            .admitted_email
            .is_some()
    );

    // Unexpired retained predecessors remain in the bounded restore inventory even though only
    // the active successor is advertised for new logins.
    sqlx::query(
        "UPDATE project_smtp_configurations SET status='retained',retained_until=$3
         WHERE project_id=$1 AND id=$2",
    )
    .bind(affected_project)
    .bind(affected_smtp)
    .bind(now + Duration::minutes(5))
    .execute(&pool)
    .await
    .unwrap();
    let retained = restarted
        .project_smtp_readiness_candidates(now + Duration::seconds(3), 100)
        .await
        .unwrap();
    assert!(retained.iter().any(|candidate| {
        candidate.project_id == affected_project && candidate.configuration_id == affected_smtp
    }));
    std::fs::remove_dir_all(secret_root).expect("remove test Runtime store");
}

#[tokio::test]
#[allow(
    clippy::similar_names,
    clippy::too_many_lines,
    reason = "one PostgreSQL lifecycle names each Runtime incarnation while proving roster and restart fences"
)]
async fn project_smtp_activation_requires_fresh_complete_runtime_roster_in_postgres() {
    let Some((_container, url)) = start_postgres().await else {
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .expect("connect sqlx");
    MIGRATOR.run(&pool).await.expect("migrate schema");
    let now = OffsetDateTime::now_utc();
    let (project_id, application_id, active_id, _) = seed_email_authority(&pool, now).await;
    let pending_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO project_smtp_configurations
         (id,project_id,status,generation,revision,security_eligibility_revision,host,port,
          tls_mode,sender_address,sender_name,reply_to,credential_ref,safe_fingerprint,created_at,updated_at)
         SELECT $1,project_id,'pending',2,1,1,host,port,tls_mode,sender_address,sender_name,
                reply_to,'pending-roster-ref',$2,$3,$3
         FROM project_smtp_configurations WHERE project_id=$4 AND id=$5",
    )
    .bind(pending_id)
    .bind(vec![8_u8; 32])
    .bind(now)
    .bind(project_id)
    .bind(active_id)
    .execute(&pool)
    .await
    .expect("seed pending SMTP generation");
    let database = Database::connect(&url).await.expect("connect SeaORM");
    let roster = vec!["runtime-a".to_owned(), "runtime-b".to_owned()];
    let control =
        PostgresEmailControlRepository::new_with_runtime_roster(database.clone(), roster.clone());
    let activate = |at| {
        control.activate_smtp_configuration(
            project_id,
            pending_id,
            1,
            at + Duration::hours(1),
            Uuid::new_v4(),
            at,
        )
    };
    assert!(matches!(
        activate(now).await,
        Err(crate::application::ApplicationError::InvalidTransition)
    ));

    let runtime_a_incarnation = Uuid::new_v4();
    let runtime_a = PostgresPasswordlessEmailRepository::new_with_runtime_identity(
        database.clone(),
        "runtime-a".to_owned(),
        runtime_a_incarnation,
        roster.clone(),
        Duration::minutes(5),
    );
    runtime_a
        .claim_runtime_incarnation(now)
        .await
        .expect("runtime-a claims its startup incarnation");
    runtime_a
        .record_email_protection_readiness(true, None, now)
        .await
        .expect("runtime-a long-term email ring ready");
    runtime_a
        .fail_close_project_smtp_restore_inventory(now)
        .await
        .expect("runtime-a fail-closes its restore inventory");
    let runtime_a_candidates = runtime_a
        .project_smtp_readiness_candidates(now, 100)
        .await
        .expect("pending generation is inventoried");
    let pending = runtime_a_candidates
        .iter()
        .find(|candidate| candidate.configuration_id == pending_id)
        .expect("pending candidate")
        .clone();
    let active = runtime_a_candidates
        .iter()
        .find(|candidate| candidate.configuration_id == active_id)
        .expect("active candidate")
        .clone();
    runtime_a
        .record_project_smtp_readiness(&active, true, now)
        .await
        .expect("runtime-a active ready");
    runtime_a
        .record_project_smtp_readiness(&pending, true, now)
        .await
        .expect("runtime-a ready");
    assert!(matches!(
        activate(now + Duration::seconds(1)).await,
        Err(crate::application::ApplicationError::InvalidTransition)
    ));

    let (project_public_id, application_public_id): (String, String) = sqlx::query_as(
        "SELECT project.public_id,application.public_id FROM projects project
         JOIN applications application ON application.project_id=project.id
         WHERE project.id=$1 AND application.id=$2",
    )
    .bind(project_id)
    .bind(application_id)
    .fetch_one(&pool)
    .await
    .expect("public capability authority IDs");
    let public_readiness = PostgresReadinessAdapter::new(
        database.clone(),
        "runtime-a".to_owned(),
        runtime_a_incarnation,
        roster.clone(),
        std::time::Duration::from_secs(30),
    );
    let missing_peer_public = public_readiness
        .public_application_config(&project_public_id, &application_public_id)
        .await
        .expect("public configuration remains available while a required Runtime is absent");
    assert!(!missing_peer_public.email_available);
    assert!(!missing_peer_public.login_available);
    assert!(missing_peer_public.providers.is_empty());
    let runtime_a_authority = PostgresRuntimeAuthorityRepository::new_with_runtime_identity(
        database.clone(),
        "runtime-a".to_owned(),
        runtime_a_incarnation,
        roster.clone(),
    );
    assert!(matches!(
        runtime_a_authority
            .prepare_login_start(
                &project_public_id,
                &application_public_id,
                &format!("pk_{}", application_id.simple()),
                "https://app.example/callback",
            )
            .await,
        Err(crate::application::ApplicationError::Disabled)
    ));

    let provider_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO provider_configurations
           (id,project_id,provider_key,kind,display_name,issuer,client_id,callback_url,
            secret_ref,status,revision)
         VALUES ($1,$2,'workforce','oidc','Workforce SSO','https://issuer.example/',
                 'email-roster-client','https://runtime.example/callback',
                 'provider/email-roster','active',1)",
    )
    .bind(provider_id)
    .bind(project_id)
    .execute(&pool)
    .await
    .expect("seed provider capability beside unavailable email");
    sqlx::query(
        "INSERT INTO application_provider_assignments
           (project_id,application_id,provider_id,status,security_revision)
         VALUES ($1,$2,$3,'active',1)",
    )
    .bind(project_id)
    .bind(application_id)
    .bind(provider_id)
    .execute(&pool)
    .await
    .expect("assign provider beside unavailable email");
    let provider_only_public = public_readiness
        .public_application_config(&project_public_id, &application_public_id)
        .await
        .expect("provider capability remains available independently");
    assert!(!provider_only_public.email_available);
    assert!(provider_only_public.login_available);
    assert_eq!(provider_only_public.providers.len(), 1);
    assert_eq!(provider_only_public.providers[0].key, "workforce");

    let runtime_b_incarnation = Uuid::new_v4();
    let runtime_b = PostgresPasswordlessEmailRepository::new_with_runtime_identity(
        database.clone(),
        "runtime-b".to_owned(),
        runtime_b_incarnation,
        roster.clone(),
        Duration::minutes(5),
    );
    runtime_b
        .claim_runtime_incarnation(now + Duration::seconds(1))
        .await
        .expect("runtime-b claims its startup incarnation");
    runtime_b
        .record_email_protection_readiness(true, None, now + Duration::seconds(1))
        .await
        .expect("runtime-b long-term email ring ready");
    runtime_b
        .fail_close_project_smtp_restore_inventory(now + Duration::seconds(1))
        .await
        .expect("runtime-b fail-closes its restore inventory");
    runtime_b
        .record_project_smtp_readiness(&active, true, now + Duration::seconds(1))
        .await
        .expect("runtime-b active ready");
    runtime_b
        .record_project_smtp_readiness(&pending, false, now + Duration::seconds(1))
        .await
        .expect("runtime-b mismatch");
    assert!(matches!(
        activate(now + Duration::seconds(2)).await,
        Err(crate::application::ApplicationError::InvalidTransition)
    ));
    let complete_active_public = public_readiness
        .public_application_config(&project_public_id, &application_public_id)
        .await
        .expect("complete active-generation roster restores public email capability");
    assert!(complete_active_public.email_available);
    assert!(complete_active_public.login_available);
    assert_eq!(complete_active_public.providers.len(), 1);

    sqlx::query(
        "UPDATE project_smtp_runtime_readiness
         SET checked_at=transaction_timestamp()-INTERVAL '2 seconds',
             lease_expires_at=transaction_timestamp()-INTERVAL '1 second'
         WHERE project_id=$1 AND configuration_id=$2 AND process_id='runtime-b'",
    )
    .bind(project_id)
    .bind(active_id)
    .execute(&pool)
    .await
    .expect("expire required runtime-b active-generation readiness lease");
    let expired_peer_public = public_readiness
        .public_application_config(&project_public_id, &application_public_id)
        .await
        .expect("provider configuration remains available after peer lease expiry");
    assert!(!expired_peer_public.email_available);
    assert!(expired_peer_public.login_available);
    assert_eq!(expired_peer_public.providers.len(), 1);
    runtime_b
        .record_project_smtp_readiness(&active, true, now + Duration::seconds(2))
        .await
        .expect("runtime-b renews active-generation readiness");

    let runtime_b2_incarnation = Uuid::new_v4();
    let runtime_b2 = PostgresPasswordlessEmailRepository::new_with_runtime_identity(
        database.clone(),
        "runtime-b".to_owned(),
        runtime_b2_incarnation,
        roster.clone(),
        Duration::minutes(5),
    );
    runtime_b2
        .claim_runtime_incarnation(now + Duration::seconds(2))
        .await
        .expect("replacement runtime-b claims the stable process identity");
    runtime_b2
        .record_email_protection_readiness(true, None, now + Duration::seconds(2))
        .await
        .expect("replacement runtime-b long-term email ring ready");
    runtime_b2
        .fail_close_project_smtp_restore_inventory(now + Duration::seconds(2))
        .await
        .expect("replacement runtime-b fail-closes inherited SMTP readiness");
    let replaced_peer_public = public_readiness
        .public_application_config(&project_public_id, &application_public_id)
        .await
        .expect("provider configuration remains available during peer replacement");
    assert!(!replaced_peer_public.email_available);
    assert!(replaced_peer_public.login_available);
    assert_eq!(replaced_peer_public.providers.len(), 1);
    runtime_b2
        .record_project_smtp_readiness(&active, true, now + Duration::seconds(2))
        .await
        .expect("replacement runtime-b restores active readiness");
    runtime_b2
        .record_project_smtp_readiness(&pending, true, now + Duration::seconds(2))
        .await
        .expect("replacement runtime-b restores pending readiness");
    let replaced_peer_ready_public = public_readiness
        .public_application_config(&project_public_id, &application_public_id)
        .await
        .expect("replacement peer readiness restores public email capability");
    assert!(replaced_peer_ready_public.email_available);
    assert!(replaced_peer_ready_public.login_available);
    assert_eq!(replaced_peer_ready_public.providers.len(), 1);
    let runtime_b = runtime_b2;

    // Pending is still non-advertised even with complete readiness; only activation changes the
    // active immutable generation selected for new login snapshots.
    let before = runtime_a_authority
        .prepare_login_start(
            &format!("prj_{}", project_id.simple()),
            &format!("app_{}", application_id.simple()),
            &format!("pk_{}", application_id.simple()),
            "https://app.example/callback",
        )
        .await
        .expect("existing active generation remains advertised");
    assert_eq!(before.admitted_email.unwrap().smtp_generation, 1);
    let activated = activate(now + Duration::seconds(3))
        .await
        .expect("complete current Runtime roster permits activation");
    assert_eq!(activated.generation, 2);

    // A restarted process fail-closes its prior incarnation before it can serve. Old evidence
    // therefore cannot authorize a later pending generation even while its lease was unexpired.
    let pending_restart = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO project_smtp_configurations
         (id,project_id,status,generation,revision,security_eligibility_revision,host,port,
          tls_mode,sender_address,sender_name,reply_to,credential_ref,safe_fingerprint,created_at,updated_at)
         SELECT $1,project_id,'pending',3,1,1,host,port,tls_mode,sender_address,sender_name,
                reply_to,'restart-ref',$2,$3,$3
         FROM project_smtp_configurations WHERE project_id=$4 AND id=$5",
    )
    .bind(pending_restart)
    .bind(vec![9_u8; 32])
    .bind(now)
    .bind(project_id)
    .bind(pending_id)
    .execute(&pool)
    .await
    .expect("seed restart generation");
    let restart_candidate = runtime_a
        .project_smtp_readiness_candidates(now + Duration::seconds(4), 100)
        .await
        .unwrap()
        .into_iter()
        .find(|candidate| candidate.configuration_id == pending_restart)
        .unwrap();
    runtime_a
        .record_project_smtp_readiness(&restart_candidate, true, now + Duration::seconds(4))
        .await
        .unwrap();
    runtime_b
        .record_project_smtp_readiness(&restart_candidate, true, now + Duration::seconds(4))
        .await
        .unwrap();
    let runtime_a2_incarnation = Uuid::new_v4();
    let runtime_a2 = PostgresPasswordlessEmailRepository::new_with_runtime_identity(
        database.clone(),
        "runtime-a".to_owned(),
        runtime_a2_incarnation,
        roster.clone(),
        Duration::minutes(5),
    );
    runtime_a2
        .claim_runtime_incarnation(now + Duration::seconds(5))
        .await
        .expect("replacement Runtime claims the stable process identity");
    runtime_a2
        .record_email_protection_readiness(true, None, now + Duration::seconds(5))
        .await
        .expect("replacement Runtime long-term email ring ready");
    runtime_a2
        .fail_close_project_smtp_restore_inventory(now + Duration::seconds(5))
        .await
        .expect("restart fail-closes old incarnation");
    runtime_a2
        .record_project_smtp_readiness(&pending, true, now + Duration::seconds(6))
        .await
        .expect("replacement Runtime records active-generation readiness");
    runtime_a2
        .record_project_smtp_readiness(&restart_candidate, true, now + Duration::seconds(6))
        .await
        .expect("replacement Runtime records matching readiness");
    assert_eq!(
        runtime_a
            .record_project_smtp_readiness(&restart_candidate, true, now + Duration::seconds(6))
            .await,
        Err(crate::application::ApplicationError::Disabled),
        "a replaced Runtime must not enter the readiness mutation transaction"
    );
    let preserved: (Uuid, String) = sqlx::query_as(
        "SELECT process_incarnation,state FROM project_smtp_runtime_readiness
         WHERE project_id=$1 AND configuration_id=$2 AND process_id='runtime-a'",
    )
    .bind(project_id)
    .bind(pending_restart)
    .fetch_one(&pool)
    .await
    .expect("replacement readiness remains present");
    assert_eq!(preserved, (runtime_a2_incarnation, "ready".to_owned()));
    assert!(matches!(
        runtime_a_authority
            .prepare_login_start(
                &format!("prj_{}", project_id.simple()),
                &format!("app_{}", application_id.simple()),
                &format!("pk_{}", application_id.simple()),
                "https://app.example/callback",
            )
            .await,
        Err(crate::application::ApplicationError::Disabled)
    ));
    assert!(matches!(
        runtime_a
            .project_smtp_readiness_candidates(now + Duration::seconds(7), 100)
            .await,
        Err(crate::application::ApplicationError::Disabled)
    ));
    assert_eq!(
        runtime_a
            .claim_due_mail(
                "runtime-a-stale",
                now + Duration::seconds(7),
                now + Duration::seconds(37),
            )
            .await,
        Err(crate::application::ApplicationError::Disabled)
    );

    PostgresRuntimeAuthorityRepository::new_with_runtime_identity(
        database.clone(),
        "runtime-a".to_owned(),
        runtime_a2_incarnation,
        roster.clone(),
    )
    .prepare_login_start(
        &format!("prj_{}", project_id.simple()),
        &format!("app_{}", application_id.simple()),
        &format!("pk_{}", application_id.simple()),
        "https://app.example/callback",
    )
    .await
    .expect("replacement Runtime may use its own fresh readiness");

    // Operation-first: block only the target readiness row. The repository call reaches that row
    // only after acquiring its incarnation share lock; replacement must then block behind the
    // repository backend rather than merely behind this test harness.
    let mut readiness_blocker = pool.begin().await.expect("begin readiness-row blocker");
    sqlx::query(
        "SELECT process_id FROM project_smtp_runtime_readiness
         WHERE project_id=$1 AND configuration_id=$2 AND process_id='runtime-a' FOR UPDATE",
    )
    .bind(project_id)
    .bind(pending_restart)
    .fetch_one(&mut *readiness_blocker)
    .await
    .expect("hold only the final readiness row");
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *readiness_blocker)
        .await
        .expect("identify readiness blocker");
    let racing_runtime_a2 = runtime_a2.clone();
    let racing_candidate = restart_candidate.clone();
    let readiness = tokio::spawn(async move {
        racing_runtime_a2
            .record_project_smtp_readiness(&racing_candidate, true, now + Duration::seconds(8))
            .await
    });
    let readiness_pid =
        wait_for_backend_blocked_by(&pool, blocker_pid, "Runtime readiness final row").await;
    let runtime_a3_incarnation = Uuid::new_v4();
    let runtime_a3 = PostgresPasswordlessEmailRepository::new_with_runtime_identity(
        database.clone(),
        "runtime-a".to_owned(),
        runtime_a3_incarnation,
        roster.clone(),
        Duration::minutes(5),
    );
    let claiming_runtime_a3 = runtime_a3.clone();
    let replacement = tokio::spawn(async move {
        claiming_runtime_a3
            .claim_runtime_incarnation(now + Duration::seconds(9))
            .await
    });
    let replacement_pid =
        wait_for_backend_blocked_by(&pool, readiness_pid, "Runtime incarnation replacement").await;
    assert_ne!(
        replacement_pid, readiness_pid,
        "replacement must wait behind the repository backend holding the incarnation fence"
    );
    readiness_blocker
        .commit()
        .await
        .expect("release final readiness row");
    readiness
        .await
        .expect("join operation-first readiness")
        .expect("A2 readiness commits before replacement");
    replacement
        .await
        .expect("join replacement")
        .expect("replacement proceeds after business commit");

    // Replacement-first: hold A4's UPSERT uncommitted, prove the repository call waits on it,
    // then commit replacement. A3 must return Disabled without changing A2's last committed row.
    let runtime_a4_incarnation = Uuid::new_v4();
    let mut replacement_first = pool.begin().await.expect("begin replacement-first UPSERT");
    let replacement_first_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *replacement_first)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO runtime_process_incarnations
           (process_id,process_incarnation,started_at) VALUES ('runtime-a',$1,$2)
         ON CONFLICT (process_id) DO UPDATE SET process_incarnation=EXCLUDED.process_incarnation,
           started_at=EXCLUDED.started_at",
    )
    .bind(runtime_a4_incarnation)
    .bind(now + Duration::seconds(10))
    .execute(&mut *replacement_first)
    .await
    .expect("hold replacement-first incarnation update");
    let reverse_candidate = restart_candidate.clone();
    let stale_after_commit = tokio::spawn(async move {
        runtime_a3
            .record_project_smtp_readiness(&reverse_candidate, true, now + Duration::seconds(11))
            .await
    });
    let stale_pid = wait_for_backend_blocked_by(
        &pool,
        replacement_first_pid,
        "replacement-first Runtime readiness",
    )
    .await;
    assert_ne!(stale_pid, replacement_first_pid);
    replacement_first
        .commit()
        .await
        .expect("commit replacement before stale operation");
    assert_eq!(
        stale_after_commit.await.expect("join stale A3 readiness"),
        Err(crate::application::ApplicationError::Disabled)
    );
    let current: Uuid = sqlx::query_scalar(
        "SELECT process_incarnation FROM runtime_process_incarnations
         WHERE process_id='runtime-a'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(current, runtime_a4_incarnation);

    assert!(matches!(
        PostgresRuntimeAuthorityRepository::new_with_runtime_identity(
            database,
            "runtime-a".to_owned(),
            runtime_a2_incarnation,
            roster,
        )
        .prepare_login_start(
            &format!("prj_{}", project_id.simple()),
            &format!("app_{}", application_id.simple()),
            &format!("pk_{}", application_id.simple()),
            "https://app.example/callback",
        )
        .await,
        Err(crate::application::ApplicationError::Disabled)
    ));

    // The normal lifecycle cannot grow beyond 32 live generations, and listing reserves space
    // for every live authority before adding newer terminal history.
    for generation in 4..=32 {
        sqlx::query(
            "INSERT INTO project_smtp_configurations
             (id,project_id,status,generation,revision,security_eligibility_revision,host,port,
              tls_mode,sender_address,sender_name,reply_to,credential_ref,safe_fingerprint,created_at,updated_at)
             SELECT $1,project_id,'pending',$2,1,1,host,port,tls_mode,sender_address,sender_name,
                    reply_to,$3,$4,$5,$5
             FROM project_smtp_configurations WHERE project_id=$6 AND id=$7",
        )
        .bind(Uuid::new_v4())
        .bind(generation)
        .bind(format!("bounded-live-{generation}"))
        .bind(vec![u8::try_from(generation).unwrap(); 32])
        .bind(now)
        .bind(project_id)
        .bind(pending_id)
        .execute(&pool)
        .await
        .expect("seed bounded live SMTP generation");
    }
    let project_revision: i64 =
        sqlx::query_scalar("SELECT security_revision FROM projects WHERE id=$1")
            .bind(project_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(matches!(
        control
            .prepare_smtp_configuration(
                project_id,
                PrepareSmtpConfiguration {
                    id: Uuid::new_v4(),
                    host: "bounded.smtp.example".to_owned(),
                    port: 465,
                    tls_mode: SmtpControlTlsMode::ImplicitTls,
                    sender_address: "bounded@example.com".to_owned(),
                    sender_name: None,
                    reply_to: None,
                    operation_alias: "bounded-live-generation-33".to_owned(),
                    credential_ref: "bounded-live-generation-33".to_owned(),
                    request_digest: vec![33; 32],
                    safe_fingerprint: Some([33; 32]),
                    expected_project_security_revision: project_revision,
                    correlation_id: Uuid::new_v4(),
                },
                now + Duration::seconds(7),
            )
            .await,
        Err(crate::application::ApplicationError::InvalidTransition)
    ));
    for generation in 33..=70 {
        sqlx::query(
            "INSERT INTO project_smtp_configurations
             (id,project_id,status,generation,revision,security_eligibility_revision,host,port,
              tls_mode,sender_address,sender_name,reply_to,credential_ref,safe_fingerprint,created_at,updated_at)
             SELECT $1,project_id,'retired',$2,1,1,host,port,tls_mode,sender_address,sender_name,
                    reply_to,$3,$4,$5,$5
             FROM project_smtp_configurations WHERE project_id=$6 AND id=$7",
        )
        .bind(Uuid::new_v4())
        .bind(generation)
        .bind(format!("terminal-history-{generation}"))
        .bind(vec![u8::try_from(generation).unwrap(); 32])
        .bind(now)
        .bind(project_id)
        .bind(pending_id)
        .execute(&pool)
        .await
        .expect("seed newer terminal SMTP history");
    }
    let listed = control
        .list_smtp_configurations(project_id)
        .await
        .expect("bounded list contains every live generation");
    assert_eq!(listed.len(), 32);
    assert!(
        listed.iter().any(|record| {
            record.id == pending_id && record.status == SmtpControlStatus::Active
        })
    );
    assert!(
        listed.iter().any(|record| {
            record.id == active_id && record.status == SmtpControlStatus::Retained
        })
    );
    assert_eq!(
        listed
            .iter()
            .filter(|record| {
                matches!(
                    record.status,
                    SmtpControlStatus::Pending
                        | SmtpControlStatus::Active
                        | SmtpControlStatus::Retained
                )
            })
            .count(),
        32
    );
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one real PostgreSQL journey proves rolling roster, cutover, and retirement fences"
)]
async fn email_alias_cutover_requires_current_complete_live_runtime_roster_in_postgres() {
    let Some((_container, url)) = start_postgres().await else {
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .expect("connect sqlx");
    MIGRATOR.run(&pool).await.expect("migrate schema");
    let database = Database::connect(&url).await.expect("connect SeaORM");
    let email = PostgresPasswordlessEmailRepository::new(database.clone());
    let peer_email = PostgresPasswordlessEmailRepository::new_with_runtime_identity(
        database.clone(),
        "runtime-peer".to_owned(),
        Uuid::nil(),
        vec!["runtime-1".to_owned(), "runtime-peer".to_owned()],
        Duration::minutes(5),
    );
    let now = OffsetDateTime::now_utc();
    let v1 = runtime_protector(1, []);
    let v1_with_v2 = runtime_protector(1, [(2, 2)]);
    let v2 = runtime_protector(2, [(1, 1)]);

    email
        .claim_runtime_incarnation(now)
        .await
        .expect("claim alias-maintenance Runtime incarnation");
    email
        .rewrap_durable_email_identities(
            &v1,
            100,
            "runtime-1",
            &["runtime-1".to_owned()],
            now + Duration::minutes(5),
            false,
            false,
            now,
        )
        .await
        .expect("initialize v1 authority");
    let (project_id, _, _, _) = seed_email_authority(&pool, now).await;
    for index in 0..101_u16 {
        let user_id = Uuid::new_v4();
        let identity_id = Uuid::new_v4();
        let public_id = format!("usr_alias_{index:03}");
        let mut seed = pool.begin().await.expect("begin identity seed");
        sqlx::query(
            "INSERT INTO project_users
             (id,project_id,public_id,status,user_revision,security_revision,primary_profile_identity_id,
              primary_source_kind,base_profile_digest,local_display_name_set,local_picture_url_set,
              local_locale_set,created_at,updated_at)
             VALUES ($1,$2,$3,'active',1,1,NULL,'email',$4,FALSE,FALSE,FALSE,$5,$5)",
        )
        .bind(user_id)
        .bind(project_id)
        .bind(public_id)
        .bind(index.to_be_bytes().repeat(16))
        .bind(now)
        .execute(&mut *seed)
        .await
        .expect("seed alias user");
        let mut context = b"owlauth-email-identity-v1\0".to_vec();
        context.extend_from_slice(project_id.as_bytes());
        context.extend_from_slice(identity_id.as_bytes());
        let address = format!("alias-{index:03}@example.test");
        let protected = v1
            .protect(
                crate::application::ProtectedPurpose::EmailIdentityAddress,
                &context,
                address.as_bytes(),
            )
            .expect("protect v1 identity address");
        sqlx::query(
            "INSERT INTO email_identities
             (id,project_id,user_id,status,identity_revision,canonicalization_version,
              address_ciphertext,address_key_version,verified_at,created_at,updated_at)
             VALUES ($1,$2,$3,$4,1,1,$5,$6,$7,$7,$7)",
        )
        .bind(identity_id)
        .bind(project_id)
        .bind(user_id)
        .bind(if index == 100 { "disabled" } else { "active" })
        .bind(protected.ciphertext)
        .bind(protected.key_version)
        .bind(now)
        .execute(&mut *seed)
        .await
        .expect("seed v1 identity");
        sqlx::query(
            "UPDATE project_users SET primary_email_identity_id=$3
             WHERE project_id=$1 AND id=$2",
        )
        .bind(project_id)
        .bind(user_id)
        .bind(identity_id)
        .execute(&mut *seed)
        .await
        .expect("set primary email identity");
        let alias = v1
            .digest(
                crate::application::OpaquePurpose::EmailIdentityLookup,
                project_id.as_bytes(),
                address.as_bytes(),
            )
            .expect("digest v1 identity alias");
        sqlx::query(
            "INSERT INTO email_identity_aliases
             (project_id,identity_id,canonicalization_version,digest_key_version,lookup_digest,created_at)
             VALUES ($1,$2,1,$3,$4,$5)",
        )
        .bind(project_id)
        .bind(identity_id)
        .bind(alias.key_version)
        .bind(alias.value.to_vec())
        .bind(now)
        .execute(&mut *seed)
        .await
        .expect("seed v1 identity alias");
        seed.commit().await.expect("commit identity seed");
    }
    let first_batch = email
        .rewrap_durable_email_identities(
            &v2,
            100,
            "runtime-1",
            &["runtime-1".to_owned(), "runtime-missing".to_owned()],
            now + Duration::minutes(5),
            true,
            false,
            now + Duration::seconds(1),
        )
        .await
        .expect("stage v2 with missing required Runtime");
    assert_eq!(first_batch, 100);
    let authority: (i64, i32) = sqlx::query_as(
        "SELECT revision,write_version FROM email_identity_alias_authority WHERE singleton=TRUE",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(authority, (2, 1));

    // A configured roster cannot hide an additional still-live old Runtime.
    email
        .rewrap_durable_email_identities(
            &v2,
            100,
            "runtime-1",
            &["runtime-1".to_owned()],
            now + Duration::minutes(5),
            true,
            false,
            now + Duration::seconds(2),
        )
        .await
        .expect("live old Runtime blocks cutover");
    let write_version: i32 = sqlx::query_scalar(
        "SELECT write_version FROM email_identity_alias_authority WHERE singleton=TRUE",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(write_version, 1);

    sqlx::query(
        "UPDATE email_identity_alias_runtime_observations SET lease_expires_at=$1
         WHERE process_id='runtime-1'",
    )
    .bind(now)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "WITH current AS (
           INSERT INTO runtime_process_incarnations
             (process_id,process_incarnation,started_at) VALUES ('runtime-peer',$3,$2)
           ON CONFLICT (process_id) DO UPDATE SET process_incarnation=EXCLUDED.process_incarnation,
             started_at=EXCLUDED.started_at RETURNING process_incarnation)
         INSERT INTO email_identity_alias_runtime_observations
           (process_id,process_incarnation,active_version,observed_authority_revision,
            lease_expires_at,updated_at)
         SELECT 'runtime-peer',process_incarnation,2,1,$1,$2 FROM current",
    )
    .bind(now + Duration::minutes(5))
    .bind(now)
    .bind(Uuid::nil())
    .execute(&pool)
    .await
    .unwrap();
    email
        .rewrap_durable_email_identities(
            &v2,
            100,
            "runtime-1",
            &["runtime-1".to_owned(), "runtime-peer".to_owned()],
            now + Duration::minutes(5),
            true,
            false,
            now + Duration::seconds(3),
        )
        .await
        .expect("stale observed authority revision blocks cutover");
    let write_version: i32 = sqlx::query_scalar(
        "SELECT write_version FROM email_identity_alias_authority WHERE singleton=TRUE",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(write_version, 1);

    sqlx::query(
        "UPDATE email_identity_alias_runtime_observations
         SET observed_authority_revision=2,updated_at=$1 WHERE process_id='runtime-peer'",
    )
    .bind(now + Duration::seconds(4))
    .execute(&pool)
    .await
    .unwrap();
    email
        .rewrap_durable_email_identities(
            &v2,
            100,
            "runtime-1",
            &["runtime-1".to_owned(), "runtime-peer".to_owned()],
            now + Duration::minutes(5),
            true,
            false,
            now + Duration::seconds(4),
        )
        .await
        .expect("expired old lease and current complete roster permit cutover");
    let authority: (i64, i32, serde_json::Value, Option<i32>) = sqlx::query_as(
        "SELECT revision,write_version,accepted_versions,retirement_version
         FROM email_identity_alias_authority WHERE singleton=TRUE",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(authority, (3, 2, serde_json::json!([1, 2]), None));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM email_identity_aliases WHERE digest_key_version=1",
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        101
    );

    // Reusing cutover cannot authorize retirement, and the peer has not observed revision 3.
    email
        .rewrap_durable_email_identities(
            &v2,
            100,
            "runtime-1",
            &["runtime-1".to_owned(), "runtime-peer".to_owned()],
            now + Duration::minutes(5),
            true,
            false,
            now + Duration::seconds(5),
        )
        .await
        .expect("cutover maintenance preserves predecessor overlap");
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM email_identity_aliases WHERE digest_key_version=1",
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        101
    );

    // Roll back before retirement while v1 retains v2 readability. Bounded batches restore v1
    // protection before the authority selects v1, without deleting either accepted alias set.
    sqlx::query("UPDATE email_identity_alias_runtime_observations SET lease_expires_at=$1")
        .bind(now)
        .execute(&pool)
        .await
        .unwrap();
    for second in 6..=8 {
        email
            .rewrap_durable_email_identities(
                &v1_with_v2,
                100,
                "runtime-1",
                &["runtime-1".to_owned()],
                now + Duration::minutes(5),
                true,
                false,
                now + Duration::seconds(second),
            )
            .await
            .expect("bounded rollback convergence");
    }
    let rollback: (i64, i32, serde_json::Value, i64, i64) = sqlx::query_as(
        "SELECT authority.revision,authority.write_version,authority.accepted_versions,
          (SELECT COUNT(*) FROM email_identity_aliases WHERE digest_key_version=1),
          (SELECT COUNT(*) FROM email_identity_aliases WHERE digest_key_version=2)
         FROM email_identity_alias_authority authority WHERE singleton=TRUE",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(rollback, (4, 1, serde_json::json!([1, 2]), 101, 101));

    // Cut over again after both exact roster members observe rollback revision 4.
    sqlx::query("UPDATE email_identity_alias_runtime_observations SET lease_expires_at=$1")
        .bind(now)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO email_identity_alias_runtime_observations
           (process_id,process_incarnation,active_version,observed_authority_revision,
            lease_expires_at,updated_at)
         SELECT 'runtime-peer',process_incarnation,2,4,$1,$2
         FROM runtime_process_incarnations WHERE process_id='runtime-peer'
         ON CONFLICT (process_id) DO UPDATE SET
           process_incarnation=EXCLUDED.process_incarnation,active_version=2,
           observed_authority_revision=4,lease_expires_at=EXCLUDED.lease_expires_at,
           updated_at=EXCLUDED.updated_at",
    )
    .bind(now + Duration::minutes(5))
    .bind(now + Duration::seconds(9))
    .execute(&pool)
    .await
    .unwrap();
    for second in 10..=12 {
        email
            .rewrap_durable_email_identities(
                &v2,
                100,
                "runtime-1",
                &["runtime-1".to_owned(), "runtime-peer".to_owned()],
                now + Duration::minutes(5),
                true,
                false,
                now + Duration::seconds(second),
            )
            .await
            .expect("second bounded cutover convergence");
    }
    let overlap: (i64, i32, serde_json::Value, Option<i32>, i64) = sqlx::query_as(
        "SELECT authority.revision,authority.write_version,authority.accepted_versions,
          authority.retirement_version,
          (SELECT COUNT(*) FROM email_identity_aliases WHERE digest_key_version=1)
         FROM email_identity_alias_authority authority WHERE singleton=TRUE",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(overlap, (5, 2, serde_json::json!([1, 2]), None, 101));

    // A retire-only request that begins before complete post-cutover observation is durably
    // stale. It cannot become authorization merely by remaining pre-set while the roster catches
    // up; operators must roll it off after overlap verification and then start a later rollout.
    email
        .rewrap_durable_email_identities(
            &v2,
            100,
            "runtime-1",
            &["runtime-1".to_owned(), "runtime-peer".to_owned()],
            now + Duration::minutes(5),
            false,
            true,
            now + Duration::seconds(13),
        )
        .await
        .expect("stale pre-observation retirement request remains inert");
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM email_identity_aliases WHERE digest_key_version=1",
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        101
    );
    sqlx::query(
        "UPDATE email_identity_alias_runtime_observations
         SET observed_authority_revision=5,updated_at=$1 WHERE process_id='runtime-peer'",
    )
    .bind(now + Duration::seconds(14))
    .execute(&pool)
    .await
    .unwrap();

    // Explicitly remove the stale request. Complete roster observation now records a separate
    // overlap-verification authority revision; cutover itself still deleted no aliases and the
    // rollback window remained available throughout.
    email
        .rewrap_durable_email_identities(
            &v2,
            100,
            "runtime-1",
            &["runtime-1".to_owned(), "runtime-peer".to_owned()],
            now + Duration::minutes(5),
            false,
            false,
            now + Duration::seconds(14),
        )
        .await
        .expect("local post-cutover overlap observation converges");
    sqlx::query(
        "UPDATE email_identity_alias_runtime_observations
         SET active_version=2,
             observed_authority_revision=(SELECT revision FROM email_identity_alias_authority
                                          WHERE singleton=TRUE),
             updated_at=$1 WHERE process_id='runtime-peer'",
    )
    .bind(now + Duration::seconds(15))
    .execute(&pool)
    .await
    .expect("peer reports the new overlap authority revision");
    email
        .rewrap_durable_email_identities(
            &v2,
            100,
            "runtime-1",
            &["runtime-1".to_owned(), "runtime-peer".to_owned()],
            now + Duration::minutes(5),
            false,
            false,
            now + Duration::seconds(16),
        )
        .await
        .expect("complete post-cutover overlap observation converges");
    let verified: (i64, Option<i64>, i64) = sqlx::query_as(
        "SELECT authority.revision,authority.overlap_verified_revision,
          (SELECT COUNT(*) FROM email_identity_aliases WHERE digest_key_version=1)
         FROM email_identity_alias_authority authority WHERE singleton=TRUE",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(verified, (6, Some(6), 101));

    // Only the later distinct retire-only rollout across every live/required member can collapse
    // accepted_versions and begin bounded predecessor deletion.
    email
        .rewrap_durable_email_identities(
            &v2,
            100,
            "runtime-1",
            &["runtime-1".to_owned(), "runtime-peer".to_owned()],
            now + Duration::minutes(5),
            false,
            true,
            now + Duration::seconds(17),
        )
        .await
        .expect("first retire-only member cannot authorize the roster");
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM email_identity_aliases WHERE digest_key_version=1",
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        101
    );
    let retired_first = peer_email
        .rewrap_durable_email_identities(
            &v2,
            100,
            "runtime-peer",
            &["runtime-1".to_owned(), "runtime-peer".to_owned()],
            now + Duration::minutes(5),
            false,
            true,
            now + Duration::seconds(18),
        )
        .await
        .expect("complete later retire-only rollout deletes one bounded batch");
    assert_eq!(retired_first, 100);
    let retired_tail = email
        .rewrap_durable_email_identities(
            &v2,
            100,
            "runtime-1",
            &["runtime-1".to_owned(), "runtime-peer".to_owned()],
            now + Duration::minutes(5),
            true,
            false,
            now + Duration::seconds(19),
        )
        .await
        .expect("durable retirement fence deletes the bounded tail");
    assert_eq!(retired_tail, 1);
    let closure: (i64, i32, serde_json::Value, Option<i32>, i64, i64, i64, i64, i64) =
        sqlx::query_as(
            "SELECT authority.revision,authority.write_version,authority.accepted_versions,
             authority.retirement_version,
             (SELECT COUNT(*) FROM email_identities WHERE address_key_version=2),
             (SELECT COUNT(*) FROM email_identities WHERE status='disabled' AND address_key_version=2),
             (SELECT COUNT(*) FROM email_identity_aliases WHERE digest_key_version=2),
             (SELECT COALESCE(SUM(affected_rows),0)::BIGINT
              FROM email_identity_alias_authority_events WHERE action='aliases_retired'),
             (SELECT COUNT(*) FROM email_identity_alias_authority_events
              WHERE action IN ('rollback','retirement_authorized'))
             FROM email_identity_alias_authority authority WHERE singleton=TRUE",
        )
        .fetch_one(&pool)
        .await
        .expect("two-phase alias closure inventory");
    assert_eq!(
        closure,
        (7, 2, serde_json::json!([2]), Some(2), 101, 1, 101, 101, 2)
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM email_identity_aliases WHERE digest_key_version=1",
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        0
    );

    database.close().await.expect("close SeaORM");
    pool.close().await;
}
