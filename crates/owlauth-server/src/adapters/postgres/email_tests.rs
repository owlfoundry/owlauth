use std::env;

use super::{
    authentication::PostgresAuthenticationRepository,
    email::PostgresPasswordlessEmailRepository,
    mail_delivery_safety::{MailDeliveryAuthorization, authorize_mail_delivery_with_limit},
};
use crate::application::{
    AdmittedEmailMethod, AuthenticationRepository, BindHostedBrowser, CommitEmailGeneration,
    CompleteEmailProof, CreateLoginTransaction, EmailProofKind, EstablishMagicTransferContext,
    LoginRevisionSnapshot, MailOutboxRepository, MailTransportOutcome, PasswordlessEmailRepository,
    ProtectedValue, ResolveMagicTransferContext, SelectEmailMethod, VerifyEmailProof,
    VersionedDigest,
};
use sea_orm::{Database, TransactionTrait};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, postgres::PgPoolOptions};
use testcontainers::{
    GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor, wait::LogWaitStrategy},
    runners::AsyncRunner,
};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

const POSTGRES_PORT: u16 = 5432;
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

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
    reason = "the shared email test fixture keeps one coherent PostgreSQL authority graph visible"
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
    let signing_key_id = Uuid::new_v4();
    let signing_material_id = Uuid::new_v4();
    let mut signing_transaction = pool
        .begin()
        .await
        .expect("signing fixture transaction should begin");
    sqlx::query(
        "INSERT INTO protected_materials
         (id,scope_kind,project_id,owner_kind,owner_id,generation,material_kind,
          provider_id,provider_format_version,context_version,context_digest,state)
         VALUES ($1,'project',$2,'signing_key',$3,1,'signing_key','software',1,1,$4,'pending')",
    )
    .bind(signing_material_id)
    .bind(project_id)
    .bind(signing_key_id)
    .bind(vec![11_u8; 32])
    .execute(&mut *signing_transaction)
    .await
    .expect("reserve active signing material");
    sqlx::query(
        "INSERT INTO project_signing_keys
           (id,project_id,ring_id,kid,public_jwk,state,ring_revision,
            provisioned_at,published_at,activated_at,sign_not_before,
            signer_material_id,signer_material_generation)
         VALUES ($1,$2,$3,'kid_email_ready',
           '{\"alg\":\"EdDSA\",\"crv\":\"Ed25519\",\"kid\":\"kid_email_ready\",\"kty\":\"OKP\",\"use\":\"sig\",\"x\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}'::jsonb,
           'active',1,$4,$4,$4,$4,$5,1)",
    )
    .bind(signing_key_id)
    .bind(project_id)
    .bind(ring_id)
    .bind(now)
    .bind(signing_material_id)
    .execute(&mut *signing_transaction)
    .await
    .expect("seed active email Project signing key");
    sqlx::query(
        "UPDATE protected_materials SET state='live',opaque_value=$2,updated_at=$3 WHERE id=$1",
    )
    .bind(signing_material_id)
    .bind(vec![12_u8; 64])
    .bind(now)
    .execute(&mut *signing_transaction)
    .await
    .expect("finalize active signing material");
    signing_transaction
        .commit()
        .await
        .expect("signing fixture owner and material should commit atomically");
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
    let smtp_material_id = Uuid::new_v4();
    let mut smtp_transaction = pool
        .begin()
        .await
        .expect("SMTP fixture transaction should begin");
    sqlx::query(
        "INSERT INTO protected_materials
         (id,scope_kind,project_id,owner_kind,owner_id,generation,material_kind,
          provider_id,provider_format_version,context_version,context_digest,state)
         VALUES ($1,'project',$2,'project_smtp',$3,1,'configuration_secret',
                 'software',1,1,$4,'pending')",
    )
    .bind(smtp_material_id)
    .bind(project_id)
    .bind(smtp_id)
    .bind(vec![13_u8; 32])
    .execute(&mut *smtp_transaction)
    .await
    .expect("reserve SMTP material");
    sqlx::query(
        "INSERT INTO project_smtp_configurations
         (id, project_id, status, generation, revision, security_eligibility_revision, host, port,
          tls_mode, sender_address, sender_name, reply_to, safe_fingerprint,
          credential_material_id, created_at, updated_at)
         VALUES ($1,$2,'active',1,1,1,'smtp.example.com',465,'implicit_tls','login@example.com',
          'OwlAuth 登录','reply@example.com',$3,$4,$5,$5)",
    )
    .bind(smtp_id)
    .bind(project_id)
    .bind(vec![7_u8; 32])
    .bind(smtp_material_id)
    .bind(now)
    .execute(&mut *smtp_transaction)
    .await
    .expect("seed SMTP");
    sqlx::query(
        "UPDATE protected_materials
         SET state='live',opaque_value=$2,safe_fingerprint=$3,updated_at=$4 WHERE id=$1",
    )
    .bind(smtp_material_id)
    .bind(vec![14_u8; 64])
    .bind(vec![7_u8; 32])
    .bind(now)
    .execute(&mut *smtp_transaction)
    .await
    .expect("finalize SMTP material");
    smtp_transaction
        .commit()
        .await
        .expect("SMTP fixture owner and material should commit atomically");
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

async fn create_selected_email_login(
    authentication: &PostgresAuthenticationRepository,
    email: &PostgresPasswordlessEmailRepository,
    project_id: Uuid,
    application_id: Uuid,
    method: AdmittedEmailMethod,
    now: OffsetDateTime,
    seed: u8,
) -> Uuid {
    let transaction_id = Uuid::new_v4();
    authentication
        .create_login_transaction(CreateLoginTransaction {
            id: transaction_id,
            project_id,
            application_id,
            interaction: digest(seed),
            redirect_uri: "https://app.example/callback".to_owned(),
            application_pkce_challenge: "A".repeat(43),
            application_state: protected(seed.wrapping_add(1)),
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
            admitted_email: Some(method),
        })
        .await
        .expect("create suppression login");
    authentication
        .bind_hosted_browser(BindHostedBrowser {
            interaction: digest(seed),
            expected_transaction_revision: 1,
            browser_binding: digest(seed.wrapping_add(2)),
            csrf: digest(seed.wrapping_add(3)),
            now: now + Duration::seconds(1),
        })
        .await
        .expect("bind suppression browser");
    email
        .select_email_method(SelectEmailMethod {
            project_id,
            transaction_id,
            expected_transaction_revision: 2,
            browser_binding: digest(seed.wrapping_add(2)),
            csrf: digest(seed.wrapping_add(3)),
            now: now + Duration::seconds(2),
        })
        .await
        .expect("select suppression email method");
    transaction_id
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
    let database = Database::connect(&url).await.expect("connect SeaORM");
    let now = OffsetDateTime::now_utc();
    let (project_id, application_id, smtp_id, email_method) =
        seed_email_authority(&pool, now).await;
    let email = PostgresPasswordlessEmailRepository::new(database.clone());
    let authentication = PostgresAuthenticationRepository::new(database.clone());
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
            "UPDATE projects SET status='disabled', security_revision=security_revision + 1 WHERE id=$1",
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
        sqlx::query(
            "UPDATE projects
                SET status='active', security_revision=security_revision + 1
              WHERE id=$1 AND status='disabled'",
        )
        .bind(project_id)
        .execute(&pool)
        .await
        .expect("restore disabled project before resetting revisions");
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
            admitted_email: Some(email_method.clone()),
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
    sqlx::query(
        "UPDATE projects SET status='disabled',security_revision=security_revision + 1 WHERE id=$1",
    )
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
    sqlx::query(
        "UPDATE projects SET status='active',security_revision=security_revision + 1 WHERE id=$1",
    )
    .bind(project_id)
    .execute(&pool)
    .await
    .expect("restore Project after selection race");
    sqlx::query("UPDATE projects SET security_revision=1 WHERE id=$1")
        .bind(project_id)
        .execute(&pool)
        .await
        .expect("restore Project revision after selection race");

    for (mutation, expected) in [
        (
            "UPDATE projects SET status='disabled',security_revision=security_revision + 1 WHERE id=$1",
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
        sqlx::query(
            "UPDATE projects
                SET status='active', security_revision=security_revision + 1
              WHERE id=$1 AND status='disabled'",
        )
        .bind(project_id)
        .execute(&pool)
        .await
        .expect("restore disabled Project before resetting selection revisions");
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
        recipient_digests: vec![digest(5)],
        address: protected(6),
        otp_digest: Some(digest_at(7, 2)),
        magic_digest: Some(digest(8)),
        envelope: protected(9),
        body: protected(10),
        message_id: format!("<{}@mail.owlauth.invalid>", Uuid::new_v4()),
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
        "UPDATE projects SET status='disabled',security_revision=security_revision + 1 WHERE id=$1",
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
            "UPDATE projects
                SET status='active', security_revision=security_revision + 1
              WHERE id=$1 AND status='disabled'",
        )
        .bind(project_id)
        .execute(&pool)
        .await
        .expect("restore disabled Project before resetting generation revisions");
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

    let backlog_probe = database
        .begin()
        .await
        .expect("begin bounded Project backlog probe");
    assert_eq!(
        authorize_mail_delivery_with_limit(&backlog_probe, project_id, 1, &[digest(108)], 30, 1,)
            .await
            .expect("evaluate bounded Project backlog"),
        MailDeliveryAuthorization::ProjectBacklogFull
    );
    backlog_probe
        .rollback()
        .await
        .expect("rollback bounded Project backlog probe");

    // Different login owners for the same Project and canonical recipient share one durable
    // side-effect decision. The active/retained digest candidates keep that decision stable while
    // the email identity digest key changes, and both callers still commit a generic generation.
    let suppression_parent_time = now - Duration::minutes(2);
    let suppression_left = create_selected_email_login(
        &authentication,
        &email,
        project_id,
        application_id,
        email_method.clone(),
        suppression_parent_time,
        110,
    )
    .await;
    let suppression_right = create_selected_email_login(
        &authentication,
        &email,
        project_id,
        application_id,
        email_method,
        suppression_parent_time,
        120,
    )
    .await;
    let retained_recipient = digest(109);
    let active_recipient = digest_at(119, 2);
    let suppression_command = |transaction_id, lookup_digest| CommitEmailGeneration {
        transaction_id,
        expected_transaction_revision: 3,
        expected_generation: 1,
        challenge_id: Uuid::new_v4(),
        outbox_id: Uuid::new_v4(),
        lookup_digest,
        recipient_digests: vec![retained_recipient.clone(), active_recipient.clone()],
        message_id: format!("<{}@mail.owlauth.invalid>", Uuid::new_v4()),
        // The caller clock is behind PostgreSQL by more than the suppression window. Outbox
        // creation time is PostgreSQL-authored, so both commits still share one recent-recipient
        // decision instead of dispatching twice from a stale process timestamp.
        issued_at: now - Duration::seconds(31),
        otp_expires_at: Some(now + Duration::minutes(2)),
        magic_expires_at: Some(now + Duration::minutes(5)),
        expires_at: now + Duration::minutes(5),
        ..generation.clone()
    };
    let (suppression_left_result, suppression_right_result) = tokio::join!(
        email.commit_email_generation(suppression_command(
            suppression_left,
            retained_recipient.clone(),
        )),
        email.commit_email_generation(suppression_command(
            suppression_right,
            active_recipient.clone(),
        )),
    );
    suppression_left_result.expect("first canonical-recipient generation should commit");
    suppression_right_result
        .expect("second canonical-recipient generation should commit generically");
    let suppression_shape: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT
           (SELECT COUNT(*) FROM email_challenges
             WHERE transaction_id=ANY($1) AND status='pending'),
           (SELECT COUNT(*) FROM email_challenges
             WHERE transaction_id=ANY($1) AND status='delivery_unavailable'),
           (SELECT COUNT(*) FROM mail_outbox WHERE transaction_id=ANY($1)),
           (SELECT COUNT(*) FROM login_transactions
             WHERE id=ANY($1) AND transaction_revision=4)",
    )
    .bind(vec![suppression_left, suppression_right])
    .fetch_one(&pool)
    .await
    .expect("canonical-recipient suppression shape");
    assert_eq!(suppression_shape, (1, 1, 1, 2));
    let suppression_transactions = vec![suppression_left, suppression_right];
    sqlx::query("DELETE FROM mail_outbox WHERE transaction_id=ANY($1)")
        .bind(&suppression_transactions)
        .execute(&pool)
        .await
        .expect("remove suppression fixture mail");
    sqlx::query("DELETE FROM email_challenges WHERE transaction_id=ANY($1)")
        .bind(&suppression_transactions)
        .execute(&pool)
        .await
        .expect("remove suppression fixture challenges");
    sqlx::query("DELETE FROM login_transactions WHERE id=ANY($1)")
        .bind(&suppression_transactions)
        .execute(&pool)
        .await
        .expect("remove suppression fixture logins");

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
            "UPDATE projects SET status='disabled',security_revision=security_revision + 1 WHERE id=$1",
            "UPDATE projects SET status='active',security_revision=security_revision + 1 WHERE id=$1",
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
        sqlx::query("UPDATE projects SET security_revision=1 WHERE id=$1 AND status='active'")
            .bind(project_id)
            .execute(&pool)
            .await
            .expect("restore Project revision after claim fence");
    }

    // Mail claim eligibility is PostgreSQL-clock based. Make the fixture durably due before the
    // lock-order races rather than relying on elapsed wall time in preceding test scenarios.
    sqlx::query(
        "UPDATE mail_outbox
            SET next_attempt_at=clock_timestamp()-interval '1 second'
          WHERE challenge_id=$1",
    )
    .bind(challenge_id)
    .execute(&pool)
    .await
    .expect("stage due outbox for claim authority races");

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
            "auth-a",
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
                "auth-b",
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
            "auth-b",
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
        ("leased".to_owned(), Some("auth-b".to_owned()), true)
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

    sqlx::query(
        "UPDATE project_smtp_configurations
         SET status='compromised',revision=revision+1,
             security_eligibility_revision=security_eligibility_revision+1,updated_at=$3
         WHERE project_id=$1 AND id=$2",
    )
    .bind(project_id)
    .bind(smtp_id)
    .bind(now + Duration::seconds(37))
    .execute(&pool)
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

    // Durable lookup uses the process-local active and retained ring, while new alias data writes
    // only the active version. The challenge-local v1 lookup remains independently authoritative.
    let aliases = vec![digest_at(6, 1), digest_at(6, 2)];
    let mut magic_completion = completion(magic, "magic_winner", Uuid::new_v4());
    magic_completion.lookup_aliases = aliases.clone();
    magic_completion.active_alias = digest_at(6, 2);
    magic_completion.alias_authority_revision = 1;
    let mut copied_completion = completion(copied_magic, "copied_winner", Uuid::new_v4());
    copied_completion.lookup_aliases = aliases;
    copied_completion.active_alias = digest_at(6, 2);
    copied_completion.alias_authority_revision = 1;
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
        "new durable aliases use only the configured active version"
    );

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
            "auth-backlog-progress",
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
    email
        .maintain_short_term_data(cleanup_time, 100)
        .await
        .expect("terminal transfer-context deletion");
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
}
