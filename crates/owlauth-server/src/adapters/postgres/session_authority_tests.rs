use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    sync::Arc,
};

use sea_orm::Database;
use sqlx::{PgPool, postgres::PgPoolOptions};
use testcontainers::{
    GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor, wait::LogWaitStrategy},
    runners::AsyncRunner,
};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::{
    authentication::PostgresAuthenticationRepository,
    control_lifecycle::PostgresControlLifecycleRepository,
    identity_mutation_test_support::PostgresIdentityMutationRepository,
    managed_connection::PostgresManagedConnectionRepository,
    managed_reauthorization::PostgresManagedReauthorizationRepository,
    projection::PostgresIdentityProjectionMaterializer,
    runtime_authority::PostgresRuntimeAuthorityRepository,
    session_authority::PostgresSessionAuthorityRepository,
};
use crate::adapters::runtime_security::{
    ManagedCredentialKeyMaterial, RuntimeKeyMaterial, SoftwareManagedCredentialProtector,
    SoftwareProjectionVerifiedEmailProtector, SoftwareRuntimeProtector,
    UnavailableDurableEmailAddressReader,
};
use crate::{
    application::{
        AccessTokenSessionLookup, AdmittedProviderMethod, ApplicationError,
        AuthenticatedIdentityEvidence, AuthenticationRepository, BindBrowserLogout,
        BindHostedBrowser, BoundedManagedProfile, ClaimIdentityMutationProvider,
        ClaimManagedReauthorization, ClaimProviderCallback, Clock, CommitHandoffExchange,
        CompleteAuthenticatedIdentity, ConfirmBrowserLogout, ControlLifecyclePort,
        CreateIdentityMutation, CreateIdentityMutationResult, CreateLoginTransaction,
        CreateManagedReauthorization, CreateManagedReauthorizationResult, DenyProviderCallback,
        DisableProjectUser, ExpectedIdentity, ExpectedUser, FailManagedReauthorization,
        FailProviderExchange, IdentityMutationBindingsDisposition, IdentityMutationCreateOperation,
        IdentityMutationPrimarySourceDisposition, IdentityMutationProofAuthoritySelection,
        IdentityMutationProviderCapabilities, IdentityMutationSessionsDisposition,
        LoginRevisionSnapshot, LogoutApplicationSession, ManagedAdapterCapabilitySnapshot,
        ManagedConnectionRepository, ManagedCredentialCapability, ManagedCredentialContext,
        ManagedCredentialProtector, ManagedInteractionCleanupService,
        ManagedReauthorizationRepository, ManagedReauthorizationStatus, PrepareBrowserLogout,
        PrepareHandoffExchange, PrepareRefreshRotation, PreparedIdentityMutationConfirmation,
        PreparedIdentityMutationCreate, PreparedIdentityMutationProviderCompletion,
        PreparedManagedReauthorizationCreate, ProtectedPurpose, ProtectedValue,
        ProviderProofObservation, ProviderRevocationResult, RecoverProviderExchanges,
        RefreshPreparationResult, RefreshRotationResult, RenewableProviderCredential,
        RotateRefreshToken, RuntimeAuthorityRepository, RuntimeIdentityMutationRepository,
        RuntimeProtector, SelectProviderMethod, SessionAuthorityRepository,
        VerifiedProviderIdentity, VersionedDigest,
    },
    domain::{
        BoundedProviderProfile, IdentityKind, IdentityMutationKind, IdentityMutationSlotRole,
        IdentityMutationStatus, ProfileDisplayName, ProfileLocale, ProfilePictureUrl,
        ProviderIssuer, ProviderSubject,
    },
};

const POSTGRES_PORT: u16 = 5432;
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

struct FixedClock(OffsetDateTime);

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

fn callback_capability_snapshot() -> ManagedCredentialCapability {
    ManagedCredentialCapability {
        adapter_key: "controlled_oidc_profile_v1".to_owned(),
        adapter_revision: 1,
        exact_scopes: ["offline_access", "openid", "profile"]
            .map(str::to_owned)
            .to_vec(),
        supports_revocation: true,
    }
}

fn managed_capability_snapshot() -> ManagedAdapterCapabilitySnapshot {
    ManagedAdapterCapabilitySnapshot {
        adapter_key: "controlled_oidc_profile_v1".to_owned(),
        adapter_revision: 1,
        exact_scopes: ["offline_access", "openid", "profile"]
            .map(str::to_owned)
            .to_vec(),
        provider_pkce_required: true,
        oidc_nonce_required: true,
        supports_revocation: true,
    }
}

#[derive(Clone)]
#[allow(
    clippy::struct_field_names,
    reason = "explicit identifier ownership keeps the integration fixture unambiguous"
)]
struct SeededAuthority {
    project_id: Uuid,
    application_id: Uuid,
    provider_id: Uuid,
    provider_key: String,
    ring_id: Uuid,
    signing_key_id: Uuid,
    project_public_id: String,
    callback_url: String,
}

fn docker_is_required() -> bool {
    env::var("OWLAUTH_REQUIRE_DOCKER").is_ok_and(|value| value == "1")
}

fn digest(value: u8) -> VersionedDigest {
    VersionedDigest {
        value: [value; 32],
        key_version: 1,
    }
}

fn protected(value: u8) -> ProtectedValue {
    ProtectedValue {
        ciphertext: vec![value; 32],
        key_version: 1,
    }
}

async fn assert_reauthorization_material_scrubbed(pool: &PgPool, interaction_id: Uuid) {
    let scrubbed: bool = sqlx::query_scalar(
        r"SELECT interaction.interaction_digest IS NULL
                  AND interaction.interaction_digest_key_version IS NULL
                  AND (
                    (interaction.status IN ('completed','provider_exchange_failed')
                     AND interaction.expires_at > interaction.terminal_at
                     AND interaction.browser_binding_digest IS NOT NULL
                     AND interaction.browser_binding_key_version IS NOT NULL
                     AND interaction.csrf_digest IS NOT NULL
                     AND interaction.csrf_key_version IS NOT NULL
                     AND interaction.upstream_state_digest IS NULL
                     AND interaction.upstream_state_key_version IS NULL)
                    OR
                    (interaction.status NOT IN ('completed','provider_exchange_failed')
                     AND interaction.browser_binding_digest IS NULL
                     AND interaction.browser_binding_key_version IS NULL
                     AND interaction.csrf_digest IS NULL
                     AND interaction.csrf_key_version IS NULL
                     AND interaction.upstream_state_digest IS NULL
                     AND interaction.upstream_state_key_version IS NULL)
                  )
                  AND interaction.oidc_nonce_digest IS NULL
                  AND interaction.oidc_nonce_key_version IS NULL
                  AND interaction.provider_pkce_ciphertext IS NULL
                  AND interaction.provider_pkce_key_version IS NULL
             FROM managed_provider_reauthorization_interactions AS interaction
            WHERE interaction.id=$1",
    )
    .bind(interaction_id)
    .fetch_one(pool)
    .await
    .expect("inspect terminal managed reauthorization material");
    assert!(
        scrubbed,
        "terminal interaction {interaction_id} retained one-use material"
    );
}

#[allow(clippy::too_many_arguments)]
async fn start_managed_callback_fixture(
    repository: &PostgresManagedReauthorizationRepository,
    seeded: &SeededAuthority,
    user_id: Uuid,
    connection_id: Uuid,
    connection_revision: i64,
    connection_generation: i64,
    credential_generation: i64,
    interaction_id: Uuid,
    digest_seed: u8,
    now: OffsetDateTime,
) -> (VersionedDigest, VersionedDigest) {
    repository
        .create(PreparedManagedReauthorizationCreate {
            capability: managed_capability_snapshot(),
            command: CreateManagedReauthorization {
                project_id: seeded.project_id,
                user_id,
                connection_id,
                application_id: seeded.application_id,
                expected_connection_revision: connection_revision,
                expected_connection_generation: connection_generation,
                expected_credential_generation: credential_generation,
                idempotency_key: format!("managed-stale-{interaction_id}"),
                correlation_id: Uuid::new_v4(),
            },
            interaction_id,
            interaction_digest: digest(digest_seed),
            request_digest: vec![digest_seed.wrapping_add(1); 32],
            protected_create_result: ProtectedValue {
                ciphertext: vec![digest_seed.wrapping_add(2); 48],
                key_version: 1,
            },
            expires_at: now + Duration::minutes(9),
            now,
        })
        .await
        .expect("create stale-authority callback fixture");
    let browser = digest(digest_seed.wrapping_add(3));
    let csrf = digest(digest_seed.wrapping_add(4));
    let bound = repository
        .bind_browser(
            &digest(digest_seed),
            &browser,
            &csrf,
            now + Duration::seconds(1),
        )
        .await
        .expect("bind stale-authority callback browser");
    let state = digest(digest_seed.wrapping_add(5));
    repository
        .start_provider(
            interaction_id,
            &digest(digest_seed),
            &browser,
            &csrf,
            bound.revision,
            state.clone(),
            digest(digest_seed.wrapping_add(6)),
            Some(ProtectedValue {
                ciphertext: vec![digest_seed.wrapping_add(7); 48],
                key_version: 1,
            }),
            true,
            now + Duration::seconds(2),
        )
        .await
        .expect("start stale-authority callback provider");
    (state, browser)
}

#[allow(clippy::too_many_arguments)]
fn prepared_create_replay(
    seeded: &SeededAuthority,
    user_id: Uuid,
    connection_id: Uuid,
    expected_connection_revision: i64,
    expected_connection_generation: i64,
    expected_credential_generation: i64,
    interaction_id: Uuid,
    idempotency_key: String,
    request_digest: u8,
    create_result: u8,
    expires_at: OffsetDateTime,
    now: OffsetDateTime,
) -> PreparedManagedReauthorizationCreate {
    PreparedManagedReauthorizationCreate {
        capability: managed_capability_snapshot(),
        command: CreateManagedReauthorization {
            project_id: seeded.project_id,
            user_id,
            connection_id,
            application_id: seeded.application_id,
            expected_connection_revision,
            expected_connection_generation,
            expected_credential_generation,
            idempotency_key,
            correlation_id: Uuid::new_v4(),
        },
        interaction_id,
        interaction_digest: digest(request_digest.wrapping_add(64)),
        request_digest: vec![request_digest; 32],
        protected_create_result: ProtectedValue {
            ciphertext: vec![create_result; 48],
            key_version: 1,
        },
        expires_at,
        now,
    }
}

async fn assert_create_replay(
    repository: &PostgresManagedReauthorizationRepository,
    prepared: PreparedManagedReauthorizationCreate,
    expected_status: ManagedReauthorizationStatus,
    expected_ciphertext: Option<u8>,
) {
    let result = repository
        .create(prepared)
        .await
        .expect("terminal create-idempotency replay must remain deterministic");
    let CreateManagedReauthorizationResult::Replayed {
        interaction,
        protected_create_result,
    } = result
    else {
        panic!("terminal create-idempotency replay must never create a second interaction")
    };
    assert_eq!(interaction.status, expected_status);
    match (protected_create_result, expected_ciphertext) {
        (Some(protected), Some(expected)) => {
            assert_eq!(protected.key_version, 1);
            assert_eq!(protected.ciphertext, vec![expected; 48]);
        }
        (None, None) => {}
        _ => panic!("terminal replay returned the wrong live-result/tombstone shape"),
    }
}

async fn age_reauthorization_deadline(
    pool: &PgPool,
    interaction_id: Uuid,
    deadline: OffsetDateTime,
) {
    let aged = sqlx::query(
        r"WITH aged_interaction AS (
             UPDATE managed_provider_reauthorization_interactions
                SET expires_at=$1
              WHERE id=$2
          RETURNING id
           )
           UPDATE managed_reauthorization_create_results AS result
              SET expires_at=$1
             FROM aged_interaction
            WHERE result.interaction_id=aged_interaction.id",
    )
    .bind(deadline)
    .bind(interaction_id)
    .execute(pool)
    .await
    .expect("age the interaction and its exact create-result deadline atomically");
    assert_eq!(aged.rows_affected(), 1);
}

async fn start_postgres() -> Option<(testcontainers::ContainerAsync<GenericImage>, String)> {
    let wait = WaitFor::log(LogWaitStrategy::stderr(
        "database system is ready to accept connections",
    ));
    let container = match GenericImage::new("postgres", "17-bookworm")
        .with_exposed_port(POSTGRES_PORT.tcp())
        .with_wait_for(wait)
        .with_env_var("POSTGRES_DB", "owlauth_session_test")
        .with_env_var("POSTGRES_USER", "owlauth")
        .with_env_var("POSTGRES_PASSWORD", "owlauth_test")
        .start()
        .await
    {
        Ok(container) => container,
        Err(error) => {
            assert!(
                !docker_is_required(),
                "PostgreSQL session authority test container is required: {error}"
            );
            eprintln!("skipping session authority test: Docker unavailable: {error}");
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
        format!("postgres://owlauth:owlauth_test@{host}:{port}/owlauth_session_test"),
    ))
}

#[allow(
    clippy::too_many_lines,
    reason = "the fixture keeps one coherent PostgreSQL authority seed visible"
)]
async fn seed_authority(pool: &PgPool, now: OffsetDateTime, namespace: &str) -> SeededAuthority {
    sqlx::query(
        "INSERT INTO runtime_process_incarnations
         (process_id, process_incarnation, started_at) VALUES ('runtime-1', $1, $2)
         ON CONFLICT (process_id) DO UPDATE SET
           process_incarnation=EXCLUDED.process_incarnation, started_at=EXCLUDED.started_at",
    )
    .bind(Uuid::nil())
    .bind(now)
    .execute(pool)
    .await
    .expect("claim exact test Runtime incarnation");
    let project_public_id = format!("prj_{namespace}");
    let application_public_id = format!("app_{namespace}");
    let callback_url =
        format!("https://runtime.example/projects/{project_public_id}/auth/callback/oidc-main");
    let seeded = SeededAuthority {
        project_id: Uuid::new_v4(),
        application_id: Uuid::new_v4(),
        provider_id: Uuid::new_v4(),
        provider_key: "oidc-main".to_owned(),
        ring_id: Uuid::new_v4(),
        signing_key_id: Uuid::new_v4(),
        project_public_id,
        callback_url,
    };
    sqlx::query(
        "INSERT INTO projects
            (id, public_id, belongs_to, display_name, status, metadata_revision, security_revision)
         VALUES ($1, $2, NULL, 'Session Project', 'active', 1, 1)",
    )
    .bind(seeded.project_id)
    .bind(&seeded.project_public_id)
    .execute(pool)
    .await
    .expect("seed Project");
    sqlx::query(
        "INSERT INTO applications
            (id, project_id, public_id, display_name, application_type, status,
             revision, metadata_revision, security_revision)
         VALUES ($1, $2, $3, 'Session App', 'web', 'active', 1, 1, 1)",
    )
    .bind(seeded.application_id)
    .bind(seeded.project_id)
    .bind(application_public_id)
    .execute(pool)
    .await
    .expect("seed Application");
    sqlx::query(
        "INSERT INTO application_redirects
            (project_id, application_id, redirect_uri, redirect_type)
         VALUES ($1, $2, 'https://app.example/callback', 'web')",
    )
    .bind(seeded.project_id)
    .bind(seeded.application_id)
    .execute(pool)
    .await
    .expect("seed redirect");
    sqlx::query(
        "INSERT INTO project_policies
            (project_id, claims_revision, session_revision, claims_policy, session_policy)
         VALUES ($1, 1, 1,
            '{\"access_token_lifetime_seconds\":900}'::jsonb,
            '{\"browser_session_reuse\":true,\"browser_session_reuse_max_age_seconds\":28800}'::jsonb)",
    )
    .bind(seeded.project_id)
    .execute(pool)
    .await
    .expect("seed policy");
    sqlx::query(
        "INSERT INTO provider_configurations
            (id, project_id, provider_key, kind, display_name, issuer, client_id,
             callback_url, secret_ref, status, revision)
         VALUES ($1, $2, 'oidc-main', 'oidc', 'OIDC', 'https://issuer.example',
             'client',
             $3, 'secret/ref/oidc-main', 'active', 1)",
    )
    .bind(seeded.provider_id)
    .bind(seeded.project_id)
    .bind(&seeded.callback_url)
    .execute(pool)
    .await
    .expect("seed provider");
    sqlx::query(
        "INSERT INTO application_provider_assignments
            (project_id, application_id, provider_id, status, security_revision)
         VALUES ($1, $2, $3, 'active', 1)",
    )
    .bind(seeded.project_id)
    .bind(seeded.application_id)
    .bind(seeded.provider_id)
    .execute(pool)
    .await
    .expect("seed assignment");
    sqlx::query(
        "INSERT INTO project_key_rings
            (id, project_id, issuer, purpose, algorithm, revision, signing_epoch)
         VALUES ($1, $2, $3, 'application_tokens', 'EdDSA', 1, 1)",
    )
    .bind(seeded.ring_id)
    .bind(seeded.project_id)
    .bind(format!(
        "https://runtime.example/projects/{}",
        seeded.project_public_id
    ))
    .execute(pool)
    .await
    .expect("seed signing ring");
    sqlx::query(
        "INSERT INTO project_signing_keys
            (id, project_id, ring_id, kid, public_jwk, signer_ref, state, ring_revision,
             provisioned_at, published_at, activated_at, sign_not_before)
         VALUES ($1, $2, $3, 'kid_test01',
             '{\"alg\":\"EdDSA\",\"crv\":\"Ed25519\",\"kid\":\"kid_test01\",\"kty\":\"OKP\",\"use\":\"sig\",\"x\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}'::jsonb,
             'signer/ref/test01', 'active', 1, $4, $4, $4, $4)",
    )
    .bind(seeded.signing_key_id)
    .bind(seeded.project_id)
    .bind(seeded.ring_id)
    .bind(now - Duration::seconds(10))
    .execute(pool)
    .await
    .expect("seed active signing key");
    seeded
}

#[derive(Clone, Copy)]
struct ManagedFixture {
    user_id: Uuid,
    connection_id: Uuid,
}

async fn insert_managed_fixture(
    pool: &PgPool,
    seeded: &SeededAuthority,
    protector: &dyn ManagedCredentialProtector,
    now: OffsetDateTime,
    suffix: u8,
) -> ManagedFixture {
    let user_id = Uuid::new_v4();
    let identity_id = Uuid::new_v4();
    let connection_id = Uuid::new_v4();
    let mut transaction = pool
        .begin()
        .await
        .expect("begin managed fixture transaction");
    sqlx::query(
        "INSERT INTO project_users
           (id,project_id,public_id,status,user_revision,security_revision,base_profile_digest,
            display_name,created_at,updated_at)
         VALUES ($1,$2,$3,'active',1,1,$4,'Managed fixture',$5,$5)",
    )
    .bind(user_id)
    .bind(seeded.project_id)
    .bind(format!("usr_matrix_{suffix:03}"))
    .bind(vec![suffix; 32])
    .bind(now)
    .execute(&mut *transaction)
    .await
    .expect("insert managed fixture user");
    sqlx::query(
        "INSERT INTO linked_identities
           (id,project_id,user_id,created_via_provider_configuration_id,issuer,subject,status,
            identity_revision,display_name,observed_at,created_at,updated_at)
         VALUES ($1,$2,$3,$4,'https://issuer.example',$5,'active',1,'Managed fixture',$6,$6,$6)",
    )
    .bind(identity_id)
    .bind(seeded.project_id)
    .bind(user_id)
    .bind(seeded.provider_id)
    .bind(format!("managed-matrix-subject-{suffix:03}"))
    .bind(now)
    .execute(&mut *transaction)
    .await
    .expect("insert managed fixture identity");
    sqlx::query("UPDATE project_users SET primary_profile_identity_id=$1 WHERE id=$2")
        .bind(identity_id)
        .bind(user_id)
        .execute(&mut *transaction)
        .await
        .expect("select managed fixture profile identity");
    let context = ManagedCredentialContext {
        project_id: seeded.project_id,
        provider_configuration_id: seeded.provider_id,
        linked_identity_id: identity_id,
        connection_id,
        connection_generation: 1,
        credential_generation: 1,
    };
    let protected = protector
        .protect_credential(&context, format!("managed-secret-{suffix:03}").as_bytes())
        .expect("protect managed fixture credential");
    sqlx::query(
        "INSERT INTO managed_provider_connections
           (id,project_id,provider_configuration_id,linked_identity_id,user_id,state,revision,
            generation,credential_generation,project_security_revision,provider_revision,
            user_security_revision,identity_revision,managed_profile_revision,adapter_key,
            adapter_capability_revision,
            required_scopes,supports_revocation,last_safe_outcome,
            next_synchronize_at,next_renewal_at,created_at,updated_at)
         VALUES ($1,$2,$3,$4,$5,'active',1,1,1,1,1,1,1,1,
                 'controlled_oidc_profile_v1',1,
                 ARRAY['offline_access','openid','profile'],TRUE,'fixture_ready',$6,$6,$6,$6)",
    )
    .bind(connection_id)
    .bind(seeded.project_id)
    .bind(seeded.provider_id)
    .bind(identity_id)
    .bind(user_id)
    .bind(now)
    .execute(&mut *transaction)
    .await
    .expect("insert managed fixture connection");
    sqlx::query(
        "INSERT INTO managed_provider_credentials
           (project_id,connection_id,connection_generation,credential_generation,key_version,
            ciphertext,created_at) VALUES ($1,$2,1,1,$3,$4,$5)",
    )
    .bind(seeded.project_id)
    .bind(connection_id)
    .bind(protected.key_version)
    .bind(protected.ciphertext)
    .bind(now)
    .execute(&mut *transaction)
    .await
    .expect("insert managed fixture credential");
    transaction
        .commit()
        .await
        .expect("commit managed fixture transaction");
    ManagedFixture {
        user_id,
        connection_id,
    }
}

async fn insert_managed_for_existing_identity(
    pool: &PgPool,
    seeded: &SeededAuthority,
    user_id: Uuid,
    protector: &dyn ManagedCredentialProtector,
    now: OffsetDateTime,
) -> ManagedFixture {
    let identity_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM linked_identities
          WHERE project_id=$1 AND user_id=$2 AND issuer='https://issuer.example'
            AND subject='shared-subject'",
    )
    .bind(seeded.project_id)
    .bind(user_id)
    .fetch_one(pool)
    .await
    .expect("load existing identity for managed lock-order fixture");
    let connection_id = Uuid::new_v4();
    let context = ManagedCredentialContext {
        project_id: seeded.project_id,
        provider_configuration_id: seeded.provider_id,
        linked_identity_id: identity_id,
        connection_id,
        connection_generation: 1,
        credential_generation: 1,
    };
    let protected = protector
        .protect_credential(&context, b"existing-identity-managed-secret")
        .expect("protect existing identity credential");
    sqlx::query(
        "INSERT INTO managed_provider_connections
           (id,project_id,provider_configuration_id,linked_identity_id,user_id,state,revision,
            generation,credential_generation,project_security_revision,provider_revision,
            user_security_revision,identity_revision,managed_profile_revision,adapter_key,
            adapter_capability_revision,required_scopes,supports_revocation,last_safe_outcome,
            next_synchronize_at,next_renewal_at,created_at,updated_at)
         VALUES ($1,$2,$3,$4,$5,'active',1,1,1,1,1,1,1,1,
                 'controlled_oidc_profile_v1',1,
                 ARRAY['offline_access','openid','profile'],TRUE,'fixture_ready',$6,$6,$6,$6)",
    )
    .bind(connection_id)
    .bind(seeded.project_id)
    .bind(seeded.provider_id)
    .bind(identity_id)
    .bind(user_id)
    .bind(now)
    .execute(pool)
    .await
    .expect("insert existing identity managed connection");
    sqlx::query(
        "INSERT INTO managed_provider_credentials
           (project_id,connection_id,connection_generation,credential_generation,key_version,
            ciphertext,created_at) VALUES ($1,$2,1,1,$3,$4,$5)",
    )
    .bind(seeded.project_id)
    .bind(connection_id)
    .bind(protected.key_version)
    .bind(protected.ciphertext)
    .bind(now)
    .execute(pool)
    .await
    .expect("insert existing identity managed credential");
    ManagedFixture {
        user_id,
        connection_id,
    }
}

async fn prepare_provider_login(
    authentication: &PostgresAuthenticationRepository,
    seeded: &SeededAuthority,
    seed: u8,
    now: OffsetDateTime,
) -> crate::application::LoginTransactionRecord {
    let login = authentication
        .create_login_transaction(CreateLoginTransaction {
            id: Uuid::new_v4(),
            project_id: seeded.project_id,
            application_id: seeded.application_id,
            interaction: digest(seed),
            redirect_uri: "https://app.example/callback".to_owned(),
            application_pkce_challenge: "A".repeat(43),
            application_state: protected(seed + 1),
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
            admitted_providers: vec![AdmittedProviderMethod {
                kind: crate::domain::ProviderKind::Oidc,
                method_key: seeded.provider_key.clone(),
                provider_id: seeded.provider_id,
                display_name: "OIDC".to_owned(),
                issuer: "https://issuer.example".to_owned(),
                provider_revision: 1,
                provider_egress_policy_revision: Some(1),
                assignment_security_revision: 1,
            }],
            admitted_email: None,
        })
        .await
        .expect("create generic login");
    authentication
        .bind_hosted_browser(BindHostedBrowser {
            interaction: digest(seed),
            expected_transaction_revision: 1,
            browser_binding: digest(seed + 2),
            csrf: digest(seed + 3),
            now: now + Duration::seconds(1),
        })
        .await
        .expect("bind Hosted browser");
    authentication
        .select_provider_method(SelectProviderMethod {
            project_id: seeded.project_id,
            transaction_id: login.id,
            expected_transaction_revision: 2,
            method_key: seeded.provider_key.clone(),
            provider_id: seeded.provider_id,
            browser_binding: digest(seed + 2),
            csrf: digest(seed + 3),
            callback_url: seeded.callback_url.clone(),
            upstream_state: digest(seed + 4),
            oidc_nonce: digest(seed + 5),
            provider_pkce: protected(seed + 6),
            now: now + Duration::seconds(2),
        })
        .await
        .expect("select provider")
}

async fn claim_provider_login(
    authentication: &PostgresAuthenticationRepository,
    seeded: &SeededAuthority,
    seed: u8,
    now: OffsetDateTime,
) -> crate::application::ClaimedProviderExchange {
    let login = prepare_provider_login(authentication, seeded, seed, now).await;
    authentication
        .claim_provider_callback(ClaimProviderCallback {
            transaction_id: login.id,
            project_public_id: seeded.project_public_id.clone(),
            provider_key: seeded.provider_key.clone(),
            upstream_state: digest(seed + 4),
            browser_binding: digest(seed + 2),
            readable_key_versions: [1].into_iter().collect(),
            now: now + Duration::seconds(3),
        })
        .await
        .expect("claim callback")
}

fn attach_managed_credential(
    command: &mut CompleteAuthenticatedIdentity,
    value: &[u8],
    adapter_revision: i64,
) {
    let AuthenticatedIdentityEvidence::Provider(identity) = &mut command.evidence;
    identity.renewable_credential = Some(RenewableProviderCredential {
        value: zeroize::Zeroizing::new(value.to_vec()),
        granted_scopes: ["offline_access", "openid", "profile"]
            .map(str::to_owned)
            .to_vec(),
        supports_revocation: true,
    });
    let mut capability = callback_capability_snapshot();
    capability.adapter_revision = adapter_revision;
    identity.managed_capability = Some(capability);
}

fn completion_command(
    seeded: &SeededAuthority,
    claimed: &crate::application::ClaimedProviderExchange,
    seed: u8,
    now: OffsetDateTime,
) -> CompleteAuthenticatedIdentity {
    CompleteAuthenticatedIdentity {
        project_id: seeded.project_id,
        transaction_id: claimed.transaction.id,
        expected_transaction_revision: claimed.transaction.transaction_revision,
        evidence: AuthenticatedIdentityEvidence::Provider(VerifiedProviderIdentity {
            issuer: ProviderIssuer::parse("https://issuer.example".to_owned()).expect("issuer"),
            subject: ProviderSubject::parse("shared-subject".to_owned()).expect("subject"),
            display_name: Some(ProfileDisplayName::parse("Ada".to_owned()).expect("display name")),
            picture_url: None,
            locale: None,
            renewable_credential: None,
            managed_capability: None,
        }),
        new_user_id: Uuid::new_v4(),
        new_user_public_id: format!("usr_identity{seed:02}"),
        new_identity_id: Uuid::new_v4(),
        browser_session_id: Uuid::new_v4(),
        existing_browser_credential: None,
        browser_credential: digest(seed + 7),
        handoff_id: Uuid::new_v4(),
        handoff_ticket: digest(seed + 8),
        now: now + Duration::seconds(4),
    }
}

#[tokio::test]
async fn provider_callback_unreadable_nonce_or_pkce_is_non_mutating_in_postgres() {
    let Some((_container, url)) = start_postgres().await else {
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .expect("callback preclaim PostgreSQL pool");
    MIGRATOR
        .run(&pool)
        .await
        .expect("callback preclaim migrations");
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .expect("whole-second callback preclaim time");
    let seeded = seed_authority(&pool, now, "preclaim01").await;
    let database = Database::connect(&url)
        .await
        .expect("callback preclaim SeaORM pool");
    let authentication = PostgresAuthenticationRepository::new(database);
    let login = prepare_provider_login(&authentication, &seeded, 31, now).await;
    sqlx::query(
        "UPDATE login_transactions
            SET oidc_nonce_digest_key_version=2,provider_pkce_key_version=3
          WHERE id=$1",
    )
    .bind(login.id)
    .execute(&pool)
    .await
    .expect("freeze distinct unavailable callback key versions");

    for readable_key_versions in [BTreeSet::from([1, 3]), BTreeSet::from([1, 2])] {
        assert_eq!(
            authentication
                .claim_provider_callback(ClaimProviderCallback {
                    transaction_id: login.id,
                    project_public_id: seeded.project_public_id.clone(),
                    provider_key: seeded.provider_key.clone(),
                    upstream_state: digest(35),
                    browser_binding: digest(33),
                    readable_key_versions,
                    now: now + Duration::seconds(3),
                })
                .await,
            Err(ApplicationError::Integrity)
        );
        let state: (String, i64) = sqlx::query_as(
            "SELECT status,transaction_revision FROM login_transactions WHERE id=$1",
        )
        .bind(login.id)
        .fetch_one(&pool)
        .await
        .expect("inspect non-mutated callback transaction");
        assert_eq!(state, ("provider_authorization_started".to_owned(), 3));
        let audit_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_events
              WHERE target_id=$1 AND action='auth.callback.claimed'",
        )
        .bind(login.id)
        .fetch_one(&pool)
        .await
        .expect("count callback claim audits");
        assert_eq!(audit_count, 0);
    }
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one real PostgreSQL journey proves the complete Google managed credential lifecycle"
)]
async fn google_managed_workers_use_named_authority_without_project_egress_snapshot() {
    let Some((_container, url)) = start_postgres().await else {
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(6)
        .connect(&url)
        .await
        .expect("Google managed-worker PostgreSQL pool");
    MIGRATOR.run(&pool).await.expect("session migrations");
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .expect("whole-second test time");
    let seeded = seed_authority(&pool, now, "googlemanaged").await;
    let mut provider_setup = pool
        .begin()
        .await
        .expect("begin Google provider fixture setup");
    sqlx::query("SET LOCAL session_replication_role='replica'")
        .execute(&mut *provider_setup)
        .await
        .expect("disable compatibility trigger for preselected Google fixture");
    sqlx::query(
        "UPDATE provider_configurations
            SET adapter_kind='google',issuer=$1,managed_profile_enabled=TRUE,
                onboarding_policy_revision=NULL
          WHERE project_id=$2 AND id=$3",
    )
    .bind(crate::domain::GOOGLE_ISSUER)
    .bind(seeded.project_id)
    .bind(seeded.provider_id)
    .execute(&mut *provider_setup)
    .await
    .expect("select Google named-provider authority");
    provider_setup
        .commit()
        .await
        .expect("commit Google provider fixture setup");
    let protector = SoftwareRuntimeProtector::new(
        "google-managed-test".to_owned(),
        1,
        RuntimeKeyMaterial::new([71; 32], [72; 32]),
        BTreeMap::new(),
    )
    .expect("Google managed credential protector");
    let fixture = insert_managed_fixture(&pool, &seeded, &protector, now, 71).await;
    sqlx::query(
        "UPDATE managed_provider_connections
            SET adapter_key='google_oidc_profile_v1',required_scopes=ARRAY['openid','profile']
          WHERE project_id=$1 AND id=$2",
    )
    .bind(seeded.project_id)
    .bind(fixture.connection_id)
    .execute(&pool)
    .await
    .expect("snapshot Google managed capability");
    sqlx::query("DELETE FROM project_provider_egress_policies WHERE project_id=$1")
        .bind(seeded.project_id)
        .execute(&pool)
        .await
        .expect("named Google worker must not require Custom OIDC policy inventory");
    let database = Database::connect(&url)
        .await
        .expect("Google managed-worker SeaORM pool");
    let repository = PostgresManagedConnectionRepository::new(database.clone());

    let read = repository
        .claim_next_read(Uuid::new_v4(), now, now + Duration::seconds(30))
        .await
        .expect("claim Google profile read")
        .expect("Google profile read should be due");
    assert_eq!(
        read.guard.provider_kind,
        crate::domain::ProviderKind::Google
    );
    assert!(read.guard.provider_egress_policy_revision.is_none());
    assert!(read.guard.egress_policy.is_none());
    assert!(
        repository
            .finish_read_failure(
                &read,
                "test_release",
                now + Duration::hours(1),
                now + Duration::seconds(1),
            )
            .await
            .expect("release Google profile claim")
    );

    sqlx::query("UPDATE managed_provider_connections SET next_renewal_at=$1 WHERE id=$2")
        .bind(now)
        .bind(fixture.connection_id)
        .execute(&pool)
        .await
        .expect("make Google renewal due");
    let renewal = repository
        .prepare_next_renewal(
            Uuid::new_v4(),
            now + Duration::seconds(2),
            now + Duration::seconds(32),
            true,
        )
        .await
        .expect("prepare Google renewal")
        .expect("Google renewal should be due");
    assert_eq!(
        renewal.claim.guard.provider_kind,
        crate::domain::ProviderKind::Google
    );
    assert!(
        renewal
            .claim
            .guard
            .provider_egress_policy_revision
            .is_none()
    );
    assert!(
        repository
            .mark_renewal_submitted(&renewal, now + Duration::seconds(3))
            .await
            .expect("mark Google renewal submitted")
    );
    let successor_context = ManagedCredentialContext {
        project_id: seeded.project_id,
        provider_configuration_id: seeded.provider_id,
        linked_identity_id: renewal.claim.guard.linked_identity_id,
        connection_id: fixture.connection_id,
        connection_generation: renewal.claim.guard.connection_generation + 1,
        credential_generation: renewal.claim.guard.credential_generation + 1,
    };
    let successor = protector
        .protect_credential(&successor_context, b"google-renewal-successor")
        .expect("protect Google successor");
    let successor = repository
        .commit_renewal_successor(&renewal, successor, now + Duration::seconds(4))
        .await
        .expect("commit Google successor")
        .expect("Google successor should win");
    assert!(
        repository
            .finish_successor_without_profile(&successor, now + Duration::seconds(5))
            .await
            .expect("finish Google successor")
    );

    repository
        .request_revocation(
            seeded.project_id,
            fixture.user_id,
            fixture.connection_id,
            successor.connection_revision,
            successor.connection_generation,
            Uuid::new_v4(),
            now + Duration::seconds(6),
        )
        .await
        .expect("request Google revocation");
    let revocation = repository
        .claim_next_revocation(
            Uuid::new_v4(),
            now + Duration::seconds(7),
            now + Duration::seconds(37),
        )
        .await
        .expect("claim Google revocation")
        .expect("Google revocation should be due");
    assert_eq!(
        revocation.guard.provider_kind,
        crate::domain::ProviderKind::Google
    );
    assert!(revocation.guard.provider_egress_policy_revision.is_none());
    assert!(
        repository
            .release_revocation_claim(&revocation, now + Duration::seconds(8))
            .await
            .expect("release Google revocation claim")
    );
    database.close().await.expect("close Google SeaORM pool");
    pool.close().await;
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the integration test proves one complete identity-to-logout authority journey"
)]
async fn callback_handoff_and_refresh_replay_are_authoritative_in_postgres() {
    let Some((_container, url)) = start_postgres().await else {
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(12)
        .connect(&url)
        .await
        .expect("test PostgreSQL pool");
    MIGRATOR.run(&pool).await.expect("session migrations");
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .expect("whole-second test time");
    let seeded = seed_authority(&pool, now, "session01").await;
    sqlx::query("UPDATE provider_configurations SET managed_profile_enabled = TRUE WHERE id = $1")
        .bind(seeded.provider_id)
        .execute(&pool)
        .await
        .expect("enable fixed managed profile capability");

    let database = Database::connect(&url).await.expect("SeaORM test pool");
    let authentication = PostgresAuthenticationRepository::new(database.clone());
    let protector = Arc::new(
        SoftwareRuntimeProtector::new(
            "managed-test-deployment".to_owned(),
            1,
            RuntimeKeyMaterial::new([1; 32], [2; 32]),
            BTreeMap::new(),
        )
        .expect("managed test protector"),
    );
    let sessions = PostgresSessionAuthorityRepository::with_protectors(
        database.clone(),
        protector.clone(),
        protector.clone(),
    );
    let callback_url = seeded.callback_url.clone();
    let login = authentication
        .create_login_transaction(CreateLoginTransaction {
            id: Uuid::new_v4(),
            project_id: seeded.project_id,
            application_id: seeded.application_id,
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
            admitted_providers: vec![AdmittedProviderMethod {
                kind: crate::domain::ProviderKind::Oidc,
                method_key: seeded.provider_key.clone(),
                provider_id: seeded.provider_id,
                display_name: "OIDC".to_owned(),
                issuer: "https://issuer.example".to_owned(),
                provider_revision: 1,
                provider_egress_policy_revision: Some(1),
                assignment_security_revision: 1,
            }],
            admitted_email: None,
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
        .expect("bind Hosted browser");
    authentication
        .select_provider_method(SelectProviderMethod {
            project_id: seeded.project_id,
            transaction_id: login.id,
            expected_transaction_revision: 2,
            method_key: seeded.provider_key.clone(),
            provider_id: seeded.provider_id,
            browser_binding: digest(3),
            csrf: digest(4),
            callback_url: callback_url.clone(),
            upstream_state: digest(5),
            oidc_nonce: digest(6),
            provider_pkce: protected(7),
            now: now + Duration::seconds(2),
        })
        .await
        .expect("select provider");
    let claimed = authentication
        .claim_provider_callback(ClaimProviderCallback {
            transaction_id: login.id,
            project_public_id: seeded.project_public_id.clone(),
            provider_key: "oidc-main".to_owned(),
            upstream_state: digest(5),
            browser_binding: digest(3),
            readable_key_versions: [1].into_iter().collect(),
            now: now + Duration::seconds(3),
        })
        .await
        .expect("claim callback");

    let browser_session_id = Uuid::new_v4();
    let handoff_id = Uuid::new_v4();
    let issued = sessions
        .complete_authenticated_identity(CompleteAuthenticatedIdentity {
            project_id: seeded.project_id,
            transaction_id: login.id,
            expected_transaction_revision: claimed.transaction.transaction_revision,
            evidence: AuthenticatedIdentityEvidence::Provider(VerifiedProviderIdentity {
                issuer: ProviderIssuer::parse("https://issuer.example".to_owned()).expect("issuer"),
                subject: ProviderSubject::parse("subject-1".to_owned()).expect("subject"),
                display_name: Some(
                    ProfileDisplayName::parse("Ada".to_owned()).expect("display name"),
                ),
                picture_url: Some(
                    ProfilePictureUrl::parse("https://cdn.example/ada.png".to_owned())
                        .expect("picture URL"),
                ),
                locale: None,
                renewable_credential: Some(RenewableProviderCredential {
                    value: zeroize::Zeroizing::new(b"renewable-secret-sentinel".to_vec()),
                    granted_scopes: ["offline_access", "openid", "profile"]
                        .map(str::to_owned)
                        .to_vec(),
                    supports_revocation: true,
                }),
                managed_capability: Some(callback_capability_snapshot()),
            }),
            new_user_id: Uuid::new_v4(),
            new_user_public_id: "usr_session01".to_owned(),
            new_identity_id: Uuid::new_v4(),
            browser_session_id,
            existing_browser_credential: None,
            browser_credential: digest(9),
            handoff_id,
            handoff_ticket: digest(10),
            now: now + Duration::seconds(4),
        })
        .await
        .expect("complete provider callback");
    assert_eq!(issued.browser_session_id, browser_session_id);
    assert_eq!(issued.handoff_id, handoff_id);

    let email_identity_id = Uuid::new_v4();
    let mut email_context = Vec::with_capacity(58);
    email_context.extend_from_slice(b"owlauth-email-identity-v1\0");
    email_context.extend_from_slice(seeded.project_id.as_bytes());
    email_context.extend_from_slice(email_identity_id.as_bytes());
    let protected_email = protector
        .protect(
            ProtectedPurpose::EmailIdentityAddress,
            &email_context,
            b"ada@example.test",
        )
        .expect("protect durable verified email");
    sqlx::query(
        "INSERT INTO email_identities
            (id,project_id,user_id,status,identity_revision,canonicalization_version,
             address_ciphertext,address_key_version,verified_at)
         VALUES ($1,$2,$3,'active',1,1,$4,$5,$6)",
    )
    .bind(email_identity_id)
    .bind(seeded.project_id)
    .bind(issued.user_id)
    .bind(protected_email.ciphertext)
    .bind(protected_email.key_version)
    .bind(now + Duration::seconds(4))
    .execute(&pool)
    .await
    .expect("insert verified email identity");
    sqlx::query(
        "UPDATE project_users
            SET primary_source_kind='email',primary_profile_identity_id=NULL,
                primary_email_identity_id=$2,user_revision=user_revision+1
          WHERE project_id=$1 AND id=$3",
    )
    .bind(seeded.project_id)
    .bind(email_identity_id)
    .bind(issued.user_id)
    .execute(&pool)
    .await
    .expect("select primary verified email");
    sqlx::query(
        "UPDATE project_policies SET projection_verified_email_enabled=TRUE WHERE project_id=$1",
    )
    .bind(seeded.project_id)
    .execute(&pool)
    .await
    .expect("admit verified email at Project boundary");
    sqlx::query("UPDATE applications SET projection_verified_email_enabled=TRUE WHERE id=$1")
        .bind(seeded.application_id)
        .execute(&pool)
        .await
        .expect("admit verified email at Application boundary");

    let identity_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM linked_identities
         WHERE project_id = $1 AND issuer = 'https://issuer.example' AND subject = 'subject-1'",
    )
    .bind(seeded.project_id)
    .fetch_one(&pool)
    .await
    .expect("count identities");
    assert_eq!(identity_count, 1);
    let managed_connection: (Uuid, String, i64, i64, i64, OffsetDateTime, OffsetDateTime) =
        sqlx::query_as(
            "SELECT id, state, revision, generation, credential_generation,
                next_synchronize_at, next_renewal_at
           FROM managed_provider_connections WHERE project_id = $1 AND user_id = $2",
        )
        .bind(seeded.project_id)
        .bind(issued.user_id)
        .fetch_one(&pool)
        .await
        .expect("managed callback connection");
    assert_eq!(
        (
            &managed_connection.1,
            managed_connection.2,
            managed_connection.3,
            managed_connection.4
        ),
        (&"active".to_owned(), 1, 1, 1)
    );
    assert_eq!(
        managed_connection.6 - managed_connection.5,
        Duration::days(30)
    );
    let credential_is_ciphertext: bool = sqlx::query_scalar(
        "SELECT position($1::bytea in ciphertext) = 0
           FROM managed_provider_credentials WHERE project_id = $2 AND connection_id =
             (SELECT id FROM managed_provider_connections WHERE project_id = $2 AND user_id = $3)",
    )
    .bind(b"renewable-secret-sentinel".as_slice())
    .bind(seeded.project_id)
    .bind(issued.user_id)
    .fetch_one(&pool)
    .await
    .expect("credential ciphertext inventory");
    assert!(credential_is_ciphertext);

    // Exercise the distinct managed-reauthorization owner against real PostgreSQL. The
    // create-only target ciphertext is replayable for one identical Control command, while
    // browser binding, provider start, stale start and cancellation are revision CASes.
    let linked_identity_id: Uuid = sqlx::query_scalar(
        "SELECT linked_identity_id FROM managed_provider_connections WHERE id = $1",
    )
    .bind(managed_connection.0)
    .fetch_one(&pool)
    .await
    .expect("managed linked identity");
    let interaction_id = Uuid::new_v4();
    let idempotency_key = format!("managed-reauth-{interaction_id}");
    let prepared_reauthorization =
        |candidate_id: Uuid, candidate_key: String, request_digest: Vec<u8>, ciphertext: u8| {
            let interaction_digest = if candidate_key == idempotency_key {
                digest(31)
            } else {
                digest(ciphertext)
            };
            PreparedManagedReauthorizationCreate {
                capability: managed_capability_snapshot(),
                command: CreateManagedReauthorization {
                    project_id: seeded.project_id,
                    user_id: issued.user_id,
                    connection_id: managed_connection.0,
                    application_id: seeded.application_id,
                    expected_connection_revision: 1,
                    expected_connection_generation: 1,
                    expected_credential_generation: 1,
                    idempotency_key: candidate_key,
                    correlation_id: Uuid::new_v4(),
                },
                interaction_id: candidate_id,
                interaction_digest,
                request_digest,
                protected_create_result: ProtectedValue {
                    ciphertext: vec![ciphertext; 48],
                    key_version: 1,
                },
                expires_at: now + Duration::minutes(9),
                now: now + Duration::seconds(5),
            }
        };
    let reauthorizations = PostgresManagedReauthorizationRepository::new(database.clone());
    let created = reauthorizations
        .create(prepared_reauthorization(
            interaction_id,
            idempotency_key.clone(),
            vec![32; 32],
            33,
        ))
        .await
        .expect("create managed reauthorization");
    let CreateManagedReauthorizationResult::Created(created) = created else {
        panic!("first managed reauthorization create must own the result")
    };
    assert_eq!(created.linked_identity_id, linked_identity_id);
    assert_eq!(created.provider_display_name, "OIDC");
    let rewrite_provider_display = sqlx::query(
        "UPDATE managed_provider_reauthorization_interactions
            SET provider_display_name='different provider'
          WHERE id=$1",
    )
    .bind(interaction_id)
    .execute(&pool)
    .await;
    assert!(
        rewrite_provider_display.is_err(),
        "managed reauthorization freezes its insertion-time provider display"
    );
    let rewrite_provider_kind = sqlx::query(
        "UPDATE managed_provider_reauthorization_interactions
            SET provider_kind='google'
          WHERE id=$1",
    )
    .bind(interaction_id)
    .execute(&pool)
    .await;
    assert!(
        rewrite_provider_kind.is_err(),
        "managed reauthorization freezes its insertion-time provider kind"
    );
    let rewrite_provider_egress = sqlx::query(
        "UPDATE managed_provider_reauthorization_interactions
            SET provider_egress_policy_revision=provider_egress_policy_revision+1
          WHERE id=$1",
    )
    .bind(interaction_id)
    .execute(&pool)
    .await;
    assert!(
        rewrite_provider_egress.is_err(),
        "managed reauthorization freezes its insertion-time provider egress authority"
    );
    let rewrite_provider_secret = sqlx::query(
        "UPDATE managed_provider_reauthorization_interactions
            SET secret_material_id=NULL,secret_ref='different/provider/secret'
          WHERE id=$1",
    )
    .bind(interaction_id)
    .execute(&pool)
    .await;
    assert!(
        rewrite_provider_secret.is_err(),
        "managed reauthorization freezes its insertion-time provider secret authority"
    );
    assert_eq!(created.adapter_key, "controlled_oidc_profile_v1");
    assert_eq!(created.adapter_capability_revision, 1);
    assert_eq!(
        created.required_scopes,
        ["offline_access", "openid", "profile"]
            .map(str::to_owned)
            .to_vec()
    );
    assert!(created.provider_pkce_required);
    assert!(created.oidc_nonce_required);
    assert!(created.supports_revocation);
    assert_eq!(
        created.status,
        ManagedReauthorizationStatus::AwaitingBrowserBinding
    );
    let replayed = reauthorizations
        .create(prepared_reauthorization(
            Uuid::new_v4(),
            idempotency_key.clone(),
            vec![32; 32],
            99,
        ))
        .await
        .expect("replay identical managed reauthorization");
    let CreateManagedReauthorizationResult::Replayed {
        interaction: replayed,
        protected_create_result: Some(replayed_target),
    } = replayed
    else {
        panic!("identical replay must return its still-live protected create result")
    };
    assert_eq!(replayed.id, interaction_id);
    assert_eq!(replayed_target.ciphertext, vec![33; 48]);

    let persisted_idempotency: (Option<Uuid>, String, String, String, Option<Uuid>, Vec<u8>) =
        sqlx::query_as(
            "SELECT project_id, operation_kind, request_scope, state, result_resource_id, request_digest
               FROM control_idempotency_records WHERE idempotency_key=$1",
        )
        .bind(&idempotency_key)
        .fetch_one(&pool)
        .await
        .expect("inspect managed reauthorization idempotency metadata");
    assert_eq!(persisted_idempotency.0, Some(seeded.project_id));
    assert_eq!(persisted_idempotency.1, "managed_reauthorization.create");
    assert_eq!(persisted_idempotency.2, seeded.project_id.to_string());
    assert_eq!(persisted_idempotency.3, "completed");
    assert_eq!(persisted_idempotency.4, Some(interaction_id));
    assert_eq!(persisted_idempotency.5, vec![32; 32]);

    let Err(digest_mismatch) = reauthorizations
        .create(prepared_reauthorization(
            Uuid::new_v4(),
            idempotency_key.clone(),
            vec![94; 32],
            94,
        ))
        .await
    else {
        panic!("same-lane idempotency digest mismatch must conflict")
    };
    assert_eq!(digest_mismatch, ApplicationError::IdempotencyConflict);

    let cross_operation_key = format!("managed-cross-operation-{}", Uuid::new_v4());
    sqlx::query(
        "INSERT INTO control_idempotency_records
           (idempotency_key,project_id,request_digest,state,operation_kind,request_scope,response,completed_at)
         VALUES ($1,$2,$3,'completed','application.create',$4,'{}'::jsonb,transaction_timestamp())",
    )
    .bind(&cross_operation_key)
    .bind(seeded.project_id)
    .bind(vec![32_u8; 32])
    .bind(seeded.project_id.to_string())
    .execute(&pool)
    .await
    .expect("seed a deployment-global cross-operation idempotency owner");
    let Err(cross_operation) = reauthorizations
        .create(prepared_reauthorization(
            Uuid::new_v4(),
            cross_operation_key.clone(),
            vec![32; 32],
            95,
        ))
        .await
    else {
        panic!("cross-operation idempotency key reuse must conflict")
    };
    assert_eq!(cross_operation, ApplicationError::IdempotencyConflict);
    let cross_operation_effects: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM managed_reauthorization_create_results WHERE idempotency_key=$1",
    )
    .bind(&cross_operation_key)
    .fetch_one(&pool)
    .await
    .expect("inspect rejected cross-operation effects");
    assert_eq!(cross_operation_effects, 0);

    let cross_scope_key = format!("managed-cross-scope-{}", Uuid::new_v4());
    sqlx::query(
        "INSERT INTO control_idempotency_records
           (idempotency_key,project_id,request_digest,state,operation_kind,request_scope,response,completed_at)
         VALUES ($1,$2,$3,'completed','managed_reauthorization.create','deployment','{}'::jsonb,transaction_timestamp())",
    )
    .bind(&cross_scope_key)
    .bind(seeded.project_id)
    .bind(vec![32_u8; 32])
    .execute(&pool)
    .await
    .expect("seed an incompatible managed reauthorization request scope");
    let Err(cross_scope) = reauthorizations
        .create(prepared_reauthorization(
            Uuid::new_v4(),
            cross_scope_key.clone(),
            vec![32; 32],
            98,
        ))
        .await
    else {
        panic!("cross-scope idempotency key reuse must conflict")
    };
    assert_eq!(cross_scope, ApplicationError::IdempotencyConflict);
    let cross_scope_effects: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM managed_reauthorization_create_results WHERE idempotency_key=$1",
    )
    .bind(&cross_scope_key)
    .fetch_one(&pool)
    .await
    .expect("inspect rejected cross-scope effects");
    assert_eq!(cross_scope_effects, 0);

    let race_key = format!("managed-reauth-race-{}", Uuid::new_v4());
    let race_first_id = Uuid::new_v4();
    let race_second_id = Uuid::new_v4();
    let race_first_repository = reauthorizations.clone();
    let race_second_repository = reauthorizations.clone();
    let (race_first, race_second) = tokio::join!(
        race_first_repository.create(prepared_reauthorization(
            race_first_id,
            race_key.clone(),
            vec![96; 32],
            96,
        )),
        race_second_repository.create(prepared_reauthorization(
            race_second_id,
            race_key.clone(),
            vec![96; 32],
            97,
        )),
    );
    let race_first = race_first.expect("first concurrent idempotent create");
    let race_second = race_second.expect("second concurrent idempotent create");
    let (race_winner, race_replay, race_ciphertext) = match (race_first, race_second) {
        (
            CreateManagedReauthorizationResult::Created(created),
            CreateManagedReauthorizationResult::Replayed {
                interaction,
                protected_create_result: Some(target),
            },
        )
        | (
            CreateManagedReauthorizationResult::Replayed {
                interaction,
                protected_create_result: Some(target),
            },
            CreateManagedReauthorizationResult::Created(created),
        ) => (created.id, interaction.id, target.ciphertext),
        _ => panic!("concurrent identical creates must have exactly one owner and one replay"),
    };
    assert_eq!(race_replay, race_winner);
    let expected_ciphertext = if race_winner == race_first_id { 96 } else { 97 };
    assert_eq!(race_ciphertext, vec![expected_ciphertext; 48]);
    let race_effects: (i64, i64) = sqlx::query_as(
        "SELECT
           (SELECT count(*) FROM managed_provider_reauthorization_interactions WHERE id IN ($1,$2)),
           (SELECT count(*) FROM managed_reauthorization_create_results WHERE idempotency_key=$3)",
    )
    .bind(race_first_id)
    .bind(race_second_id)
    .bind(&race_key)
    .fetch_one(&pool)
    .await
    .expect("inspect concurrent idempotent create effects");
    assert_eq!(race_effects, (1, 1));

    let bound = reauthorizations
        .bind_browser(
            &digest(31),
            &digest(34),
            &digest(35),
            now + Duration::seconds(6),
        )
        .await
        .expect("bind managed reauthorization browser once");
    assert_eq!(
        bound.status,
        ManagedReauthorizationStatus::AwaitingProviderStart
    );
    let started = reauthorizations
        .start_provider(
            interaction_id,
            &digest(31),
            &digest(34),
            &digest(35),
            bound.revision,
            digest(36),
            digest(37),
            Some(ProtectedValue {
                ciphertext: vec![38; 48],
                key_version: 1,
            }),
            true,
            now + Duration::seconds(7),
        )
        .await
        .expect("start fixed managed provider");
    assert_eq!(
        started.status,
        ManagedReauthorizationStatus::ProviderAuthorizationStarted
    );
    let stale_start = reauthorizations
        .start_provider(
            interaction_id,
            &digest(31),
            &digest(34),
            &digest(35),
            bound.revision,
            digest(39),
            digest(40),
            Some(ProtectedValue {
                ciphertext: vec![41; 48],
                key_version: 1,
            }),
            true,
            now + Duration::seconds(8),
        )
        .await;
    assert!(matches!(
        stale_start,
        Err(crate::application::ApplicationError::RevisionConflict)
    ));
    let cancelled = reauthorizations
        .cancel(
            seeded.project_id,
            issued.user_id,
            managed_connection.0,
            interaction_id,
            started.revision,
            Uuid::new_v4(),
            now + Duration::seconds(9),
        )
        .await
        .expect("cancel exact managed reauthorization revision");
    assert_eq!(cancelled.status, ManagedReauthorizationStatus::Cancelled);
    assert_reauthorization_material_scrubbed(&pool, interaction_id).await;
    let cancellation_deadline = now + Duration::seconds(20);
    age_reauthorization_deadline(&pool, interaction_id, cancellation_deadline).await;
    assert_create_replay(
        &reauthorizations,
        prepared_create_replay(
            &seeded,
            issued.user_id,
            managed_connection.0,
            1,
            1,
            1,
            Uuid::new_v4(),
            idempotency_key.clone(),
            32,
            99,
            cancellation_deadline,
            now + Duration::seconds(10),
        ),
        ManagedReauthorizationStatus::Cancelled,
        Some(33),
    )
    .await;
    let cancellation_sweeper = PostgresManagedConnectionRepository::new(database.clone());
    assert_eq!(
        cancellation_sweeper
            .terminalize_expired_interactions(256, now + Duration::seconds(21))
            .await
            .expect("passively tombstone the due explicit cancellation"),
        1
    );
    let cancelled_tombstone: (String, i64, Option<Vec<u8>>, Option<Vec<u8>>, bool) =
        sqlx::query_as(
            "SELECT interaction.status,interaction.revision,result.request_digest,
                result.create_result_ciphertext,
                result.erased_at=$2 AND result.erased_at>=result.expires_at
           FROM managed_provider_reauthorization_interactions AS interaction
           JOIN managed_reauthorization_create_results AS result
             ON result.interaction_id=interaction.id
          WHERE interaction.id=$1",
        )
        .bind(interaction_id)
        .bind(now + Duration::seconds(21))
        .fetch_one(&pool)
        .await
        .expect("inspect passively swept explicit cancellation");
    assert_eq!(cancelled_tombstone.0, "cancelled");
    assert_eq!(cancelled_tombstone.1, cancelled.revision);
    assert!(cancelled_tombstone.2.is_none());
    assert!(cancelled_tombstone.3.is_none());
    assert!(cancelled_tombstone.4);
    for attempt in [Duration::seconds(22), Duration::seconds(23)] {
        assert_create_replay(
            &reauthorizations,
            prepared_create_replay(
                &seeded,
                issued.user_id,
                managed_connection.0,
                1,
                1,
                1,
                Uuid::new_v4(),
                idempotency_key.clone(),
                32,
                99,
                cancellation_deadline,
                now + attempt,
            ),
            ManagedReauthorizationStatus::Cancelled,
            None,
        )
        .await;
    }
    let erased: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT create_result_ciphertext FROM managed_reauthorization_create_results WHERE interaction_id=$1",
    )
    .bind(interaction_id)
    .fetch_one(&pool)
    .await
    .expect("managed create result inventory");
    assert!(erased.is_none());

    let managed_repository = PostgresManagedConnectionRepository::new(database.clone());
    sqlx::query(
        "UPDATE managed_provider_connections SET next_renewal_at = $1 WHERE project_id = $2 AND id = $3",
    )
    .bind(now)
    .bind(seeded.project_id)
    .bind(managed_connection.0)
    .execute(&pool)
    .await
    .expect("make renewable generation due");
    let first_worker = Uuid::new_v4();
    let prepared = managed_repository
        .prepare_next_renewal(
            first_worker,
            now + Duration::seconds(1),
            now + Duration::seconds(31),
            true,
        )
        .await
        .expect("prepare durable renewal")
        .expect("renewal is due");
    sqlx::query(
        "UPDATE managed_provider_renewal_operations SET lease_expires_at = $1 WHERE id = $2",
    )
    .bind(now + Duration::seconds(1))
    .bind(prepared.operation_id)
    .execute(&pool)
    .await
    .expect("expire operation lease after process loss");
    sqlx::query(
        "UPDATE managed_provider_connections SET lease_expires_at = $1 WHERE project_id = $2 AND id = $3",
    )
    .bind(now + Duration::seconds(1))
    .bind(seeded.project_id)
    .bind(managed_connection.0)
    .execute(&pool)
    .await
    .expect("expire connection lease after process loss");
    let reclaimed = managed_repository
        .prepare_next_renewal(
            Uuid::new_v4(),
            now + Duration::seconds(2),
            now + Duration::seconds(32),
            true,
        )
        .await
        .expect("reclaim prepared renewal")
        .expect("prepared operation remains recoverable");
    assert_eq!(reclaimed.operation_id, prepared.operation_id);
    assert_eq!(reclaimed.attempt_id, prepared.attempt_id);
    assert_eq!(reclaimed.operation_state, prepared.operation_state);
    assert!(
        managed_repository
            .mark_renewal_submitted(&reclaimed, now + Duration::seconds(3))
            .await
            .expect("persist submitted before provider dispatch")
    );
    sqlx::query("UPDATE managed_provider_renewal_operations SET lease_expires_at=$1 WHERE id=$2")
        .bind(now + Duration::seconds(3))
        .bind(prepared.operation_id)
        .execute(&pool)
        .await
        .expect("expire submitted operation lease after process loss");
    sqlx::query(
        "UPDATE managed_provider_connections SET lease_expires_at=$1 WHERE project_id=$2 AND id=$3",
    )
    .bind(now + Duration::seconds(3))
    .bind(seeded.project_id)
    .bind(managed_connection.0)
    .execute(&pool)
    .await
    .expect("expire submitted connection lease after process loss");
    let submitted = managed_repository
        .prepare_next_renewal(
            Uuid::new_v4(),
            now + Duration::seconds(4),
            now + Duration::seconds(34),
            true,
        )
        .await
        .expect("reclaim submitted renewal")
        .expect("replayable submitted operation remains recoverable");
    assert_eq!(submitted.operation_id, prepared.operation_id);
    assert_eq!(submitted.attempt_id, prepared.attempt_id);
    assert_eq!(
        submitted.operation_state,
        crate::application::RenewalOperationState::Submitted
    );
    sqlx::query("UPDATE managed_provider_renewal_operations SET lease_expires_at=$1 WHERE id=$2")
        .bind(now + Duration::seconds(4))
        .bind(prepared.operation_id)
        .execute(&pool)
        .await
        .expect("expire submitted operation lease before policy drift recovery");
    sqlx::query(
        "UPDATE managed_provider_connections SET lease_expires_at=$1 WHERE project_id=$2 AND id=$3",
    )
    .bind(now + Duration::seconds(4))
    .bind(seeded.project_id)
    .bind(managed_connection.0)
    .execute(&pool)
    .await
    .expect("expire submitted connection lease before policy drift recovery");
    sqlx::query(
        "UPDATE project_provider_egress_policies SET revision=revision+1 WHERE project_id=$1",
    )
    .bind(seeded.project_id)
    .execute(&pool)
    .await
    .expect("advance Custom OIDC egress authority after dispatch");
    let stale_submitted = managed_repository
        .prepare_next_renewal(
            Uuid::new_v4(),
            now + Duration::seconds(5),
            now + Duration::seconds(35),
            true,
        )
        .await
        .expect("stale submitted renewal must remain recoverable for terminalization")
        .expect("stale submitted operation remains durable");
    assert_eq!(stale_submitted.operation_id, prepared.operation_id);
    assert_eq!(
        stale_submitted.operation_state,
        crate::application::RenewalOperationState::Submitted
    );
    assert!(!stale_submitted.authority_valid);
    assert!(stale_submitted.claim.guard.egress_policy.is_none());
    assert_eq!(
        stale_submitted.claim.guard.provider_egress_policy_revision,
        Some(1)
    );
    sqlx::query(
        "UPDATE project_provider_egress_policies SET revision=revision-1 WHERE project_id=$1",
    )
    .bind(seeded.project_id)
    .execute(&pool)
    .await
    .expect("restore shared fixture egress authority");
    sqlx::query("DELETE FROM managed_provider_renewal_operations WHERE id = $1")
        .bind(prepared.operation_id)
        .execute(&pool)
        .await
        .expect("remove recovered operation from shared fixture");
    sqlx::query(
        "UPDATE managed_provider_connections
            SET next_renewal_at = $1, lease_owner = NULL, lease_kind = NULL, lease_expires_at = NULL
          WHERE project_id = $2 AND id = $3",
    )
    .bind(now + Duration::days(30))
    .bind(seeded.project_id)
    .bind(managed_connection.0)
    .execute(&pool)
    .await
    .expect("restore fixture after renewal recovery proof");

    // A disconnected predecessor is recovery input, not successor authority. Leave its stale
    // provider/profile/adapter snapshots and revocation truth untouched while current Control
    // authority and the adapter-owned capability advance. Its inaccessible credential proves the
    // successor cannot be an accidental reuse of predecessor material.
    sqlx::query(
        "UPDATE provider_configurations
            SET revision=revision+1, managed_profile_revision=managed_profile_revision+1
          WHERE project_id=$1 AND id=$2",
    )
    .bind(seeded.project_id)
    .bind(seeded.provider_id)
    .execute(&pool)
    .await
    .expect("advance current provider and managed-profile authority");
    sqlx::query(
        "UPDATE managed_provider_credentials SET ciphertext=NULL,destroyed_at=$1
          WHERE project_id=$2 AND connection_id=$3 AND credential_generation=1",
    )
    .bind(now + Duration::seconds(9))
    .bind(seeded.project_id)
    .bind(managed_connection.0)
    .execute(&pool)
    .await
    .expect("destroy disconnected predecessor material");
    sqlx::query(
        "UPDATE managed_provider_connections
            SET state='disconnected',disconnected_at=$1,next_synchronize_at=NULL,next_renewal_at=NULL
          WHERE project_id=$2 AND id=$3",
    )
    .bind(now + Duration::seconds(9))
    .bind(seeded.project_id)
    .bind(managed_connection.0)
    .execute(&pool)
    .await
    .expect("make predecessor disconnected");
    let successor_capability = ManagedAdapterCapabilitySnapshot {
        adapter_key: "controlled_oidc_profile_v2".to_owned(),
        adapter_revision: 2,
        exact_scopes: ["email", "offline_access", "openid", "profile"]
            .map(str::to_owned)
            .to_vec(),
        provider_pkce_required: true,
        oidc_nonce_required: true,
        supports_revocation: true,
    };
    let success_interaction_id = Uuid::new_v4();
    let recovery_created = reauthorizations
        .create(PreparedManagedReauthorizationCreate {
            capability: successor_capability.clone(),
            command: CreateManagedReauthorization {
                project_id: seeded.project_id,
                user_id: issued.user_id,
                connection_id: managed_connection.0,
                application_id: seeded.application_id,
                expected_connection_revision: 1,
                expected_connection_generation: 1,
                expected_credential_generation: 1,
                idempotency_key: format!("managed-reauth-{success_interaction_id}"),
                correlation_id: Uuid::new_v4(),
            },
            interaction_id: success_interaction_id,
            interaction_digest: digest(42),
            request_digest: vec![43; 32],
            protected_create_result: ProtectedValue {
                ciphertext: vec![44; 48],
                key_version: 1,
            },
            expires_at: now + Duration::minutes(9),
            now: now + Duration::seconds(10),
        })
        .await
        .expect("create disconnected current-authority recovery");
    let CreateManagedReauthorizationResult::Created(recovery_created) = recovery_created else {
        panic!("disconnected recovery must create a new interaction")
    };
    assert_eq!(recovery_created.provider_revision, 2);
    assert_eq!(recovery_created.managed_profile_revision, 2);
    assert_eq!(recovery_created.adapter_key, "controlled_oidc_profile_v2");
    assert_eq!(recovery_created.adapter_capability_revision, 2);
    assert_eq!(
        recovery_created.required_scopes,
        successor_capability.exact_scopes
    );
    let success_bound = reauthorizations
        .bind_browser(
            &digest(42),
            &digest(45),
            &digest(46),
            now + Duration::seconds(11),
        )
        .await
        .expect("bind successful managed reauthorization");
    reauthorizations
        .start_provider(
            success_interaction_id,
            &digest(42),
            &digest(45),
            &digest(46),
            success_bound.revision,
            digest(47),
            digest(48),
            Some(ProtectedValue {
                ciphertext: vec![49; 48],
                key_version: 1,
            }),
            false,
            now + Duration::seconds(12),
        )
        .await
        .expect("start successful managed reauthorization with provider revocation unsupported");
    let managed_claim_result = reauthorizations
        .claim_callback(
            success_interaction_id,
            &seeded.project_public_id,
            &seeded.provider_key,
            &digest(47),
            &digest(45),
            now + Duration::seconds(13),
        )
        .await
        .expect("claim successful managed callback");
    let ClaimManagedReauthorization::Claimed(managed_claimed) = managed_claim_result else {
        panic!("first exact managed callback must win")
    };
    let duplicate = reauthorizations
        .claim_callback(
            success_interaction_id,
            &seeded.project_public_id,
            &seeded.provider_key,
            &digest(47),
            &digest(45),
            now + Duration::seconds(13),
        )
        .await
        .expect("read losing duplicate managed callback");
    assert!(matches!(
        duplicate,
        ClaimManagedReauthorization::Duplicate(_)
    ));
    let successor = reauthorizations
        .complete_callback(
            &managed_claimed,
            ProtectedValue {
                ciphertext: vec![50; 48],
                key_version: 1,
            },
            Uuid::new_v4(),
            now + Duration::seconds(14),
        )
        .await
        .expect("commit successful managed successor");
    assert_eq!(
        (
            successor.successor.connection_revision,
            successor.successor.connection_generation,
            successor.successor.credential_generation
        ),
        (2, 2, 2)
    );
    #[allow(
        clippy::type_complexity,
        reason = "the real PostgreSQL recovery inventory intentionally asserts one atomic snapshot"
    )]
    let success_state: (
        String,
        String,
        i64,
        i64,
        i64,
        i64,
        Option<Vec<u8>>,
        i64,
        i64,
        String,
        i64,
        Vec<String>,
        bool,
    ) = sqlx::query_as(
        "SELECT interaction.status, connection.state, connection.revision, connection.generation,
                connection.credential_generation,
                (SELECT count(*) FROM managed_provider_credentials AS history
                  WHERE history.connection_id=connection.id),
                predecessor.ciphertext, connection.provider_revision,
                connection.managed_profile_revision, connection.adapter_key,
                connection.adapter_capability_revision, connection.required_scopes,
                connection.supports_revocation
           FROM managed_provider_reauthorization_interactions AS interaction
           JOIN managed_provider_connections AS connection ON connection.id=interaction.connection_id
           JOIN managed_provider_credentials AS predecessor
             ON predecessor.connection_id=connection.id AND predecessor.credential_generation=1
          WHERE interaction.id=$1",
    )
    .bind(success_interaction_id)
    .fetch_one(&pool)
    .await
    .expect("successful managed reauthorization state");
    assert_eq!(success_state.0, "completed");
    assert_eq!(success_state.1, "active");
    assert_eq!(
        (success_state.2, success_state.3, success_state.4),
        (2, 2, 2)
    );
    assert_eq!(success_state.5, 2);
    assert!(success_state.6.is_none());
    assert_eq!((success_state.7, success_state.8), (2, 2));
    assert_eq!(success_state.9, "controlled_oidc_profile_v2");
    assert_eq!(success_state.10, 2);
    assert_eq!(
        success_state.11,
        ["email", "offline_access", "openid", "profile"]
            .map(str::to_owned)
            .to_vec()
    );
    assert!(!success_state.12);
    assert_reauthorization_material_scrubbed(&pool, success_interaction_id).await;
    assert_create_replay(
        &reauthorizations,
        prepared_create_replay(
            &seeded,
            issued.user_id,
            managed_connection.0,
            1,
            1,
            1,
            Uuid::new_v4(),
            format!("managed-reauth-{success_interaction_id}"),
            43,
            99,
            now + Duration::minutes(9),
            now + Duration::seconds(15),
        ),
        ManagedReauthorizationStatus::Completed,
        Some(44),
    )
    .await;
    let success_audits_before_retry: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events")
        .fetch_one(&pool)
        .await
        .expect("count successful interaction audits before response-loss retry");
    let terminal_success_retry = reauthorizations
        .claim_callback(
            success_interaction_id,
            &seeded.project_public_id,
            &seeded.provider_key,
            &digest(47),
            &digest(45),
            now + Duration::seconds(15),
        )
        .await
        .expect("authenticate successful terminal response-loss retry");
    assert!(matches!(
        terminal_success_retry,
        ClaimManagedReauthorization::Duplicate(ref terminal)
            if terminal.status == ManagedReauthorizationStatus::Completed
    ));
    assert!(matches!(
        reauthorizations
            .claim_callback(
                success_interaction_id,
                &seeded.project_public_id,
                &seeded.provider_key,
                &digest(47),
                &digest(99),
                now + Duration::seconds(15),
            )
            .await,
        Err(crate::application::ApplicationError::NotFound)
    ));
    let success_after_retry: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT connection.revision,connection.generation,connection.credential_generation,
                (SELECT count(*) FROM audit_events)
           FROM managed_provider_connections AS connection WHERE connection.id=$1",
    )
    .bind(managed_connection.0)
    .fetch_one(&pool)
    .await
    .expect("successful terminal retry remains read-only");
    assert_eq!(success_after_retry, (2, 2, 2, success_audits_before_retry));
    assert!(matches!(
        reauthorizations
            .digest_versions(success_interaction_id, now + Duration::minutes(10))
            .await,
        Err(crate::application::ApplicationError::NotFound)
    ));
    for attempt in [Duration::minutes(10), Duration::minutes(11)] {
        assert_create_replay(
            &reauthorizations,
            prepared_create_replay(
                &seeded,
                issued.user_id,
                managed_connection.0,
                1,
                1,
                1,
                Uuid::new_v4(),
                format!("managed-reauth-{success_interaction_id}"),
                43,
                99,
                now + Duration::minutes(9),
                now + attempt,
            ),
            ManagedReauthorizationStatus::Completed,
            None,
        )
        .await;
    }
    let success_tombstone_erased: bool = sqlx::query_scalar(
        "SELECT upstream_state_digest IS NULL AND upstream_state_key_version IS NULL
                AND browser_binding_digest IS NULL AND browser_binding_key_version IS NULL
                AND csrf_digest IS NULL AND csrf_key_version IS NULL
           FROM managed_provider_reauthorization_interactions WHERE id=$1",
    )
    .bind(success_interaction_id)
    .fetch_one(&pool)
    .await
    .expect("inspect successful post-deadline tombstone erasure");
    assert!(success_tombstone_erased);
    // Restore the shared fixture's revocation-capable provider before the later revocation
    // durability matrix; the recovery assertions above already observed the stored false truth.
    sqlx::query(
        "UPDATE managed_provider_connections
            SET supports_revocation=true,provider_revision=1,managed_profile_revision=1,
                adapter_key='controlled_oidc_profile_v1',adapter_capability_revision=1,
                required_scopes=ARRAY['offline_access','openid','profile']::text[]
          WHERE project_id=$1 AND id=$2",
    )
    .bind(seeded.project_id)
    .bind(managed_connection.0)
    .execute(&pool)
    .await
    .expect("restore revocation-capable shared fixture");
    sqlx::query(
        "UPDATE provider_configurations SET revision=1,managed_profile_revision=1
          WHERE project_id=$1 AND id=$2",
    )
    .bind(seeded.project_id)
    .bind(seeded.provider_id)
    .execute(&pool)
    .await
    .expect("restore shared provider authority fixture");
    assert!(matches!(
        reauthorizations
            .fail_callback(
                &managed_claimed,
                "provider_exchange_failed",
                now + Duration::seconds(14),
            )
            .await
            .expect("losing failure CAS remains readable"),
        FailManagedReauthorization::TerminalWinner(ref winner)
            if winner.status == ManagedReauthorizationStatus::Completed
    ));
    let winner_after_loser: (String, i64, i64, i64) = sqlx::query_as(
        "SELECT interaction.status,connection.revision,connection.generation,
                connection.credential_generation
           FROM managed_provider_reauthorization_interactions AS interaction
           JOIN managed_provider_connections AS connection ON connection.id=interaction.connection_id
          WHERE interaction.id=$1",
    )
    .bind(success_interaction_id)
    .fetch_one(&pool)
    .await
    .expect("winner remains authoritative after losing failure CAS");
    assert_eq!(winner_after_loser, ("completed".to_owned(), 2, 2, 2));

    // Claimed provider-exchange failure uses the same terminal scrub boundary.
    let failed_interaction_id = Uuid::new_v4();
    reauthorizations
        .create(PreparedManagedReauthorizationCreate {
            capability: managed_capability_snapshot(),
            command: CreateManagedReauthorization {
                project_id: seeded.project_id,
                user_id: issued.user_id,
                connection_id: managed_connection.0,
                application_id: seeded.application_id,
                expected_connection_revision: 2,
                expected_connection_generation: 2,
                expected_credential_generation: 2,
                idempotency_key: format!("managed-reauth-{failed_interaction_id}"),
                correlation_id: Uuid::new_v4(),
            },
            interaction_id: failed_interaction_id,
            interaction_digest: digest(151),
            request_digest: vec![152; 32],
            protected_create_result: ProtectedValue {
                ciphertext: vec![153; 48],
                key_version: 1,
            },
            expires_at: now + Duration::minutes(9),
            now: now + Duration::seconds(15),
        })
        .await
        .expect("create failing managed reauthorization");
    let failed_bound = reauthorizations
        .bind_browser(
            &digest(151),
            &digest(154),
            &digest(155),
            now + Duration::seconds(16),
        )
        .await
        .expect("bind failing managed reauthorization");
    reauthorizations
        .start_provider(
            failed_interaction_id,
            &digest(151),
            &digest(154),
            &digest(155),
            failed_bound.revision,
            digest(156),
            digest(157),
            Some(ProtectedValue {
                ciphertext: vec![158; 48],
                key_version: 1,
            }),
            true,
            now + Duration::seconds(17),
        )
        .await
        .expect("start failing managed provider");
    let failed_claim = reauthorizations
        .claim_callback(
            failed_interaction_id,
            &seeded.project_public_id,
            &seeded.provider_key,
            &digest(156),
            &digest(154),
            now + Duration::seconds(18),
        )
        .await
        .expect("claim failing managed callback");
    let ClaimManagedReauthorization::Claimed(failed_claim) = failed_claim else {
        panic!("first failing callback must be claimed")
    };
    assert!(matches!(
        reauthorizations
            .fail_callback(
                &failed_claim,
                "provider_exchange_failed",
                now + Duration::seconds(19),
            )
            .await
            .expect("terminalize claimed provider failure"),
        FailManagedReauthorization::Terminalized(ref terminal)
            if terminal.status == ManagedReauthorizationStatus::ProviderExchangeFailed
    ));
    assert_reauthorization_material_scrubbed(&pool, failed_interaction_id).await;
    assert_create_replay(
        &reauthorizations,
        prepared_create_replay(
            &seeded,
            issued.user_id,
            managed_connection.0,
            2,
            2,
            2,
            Uuid::new_v4(),
            format!("managed-reauth-{failed_interaction_id}"),
            152,
            199,
            now + Duration::minutes(9),
            now + Duration::seconds(20),
        ),
        ManagedReauthorizationStatus::ProviderExchangeFailed,
        Some(153),
    )
    .await;
    let failed_audits_before_retry: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events")
        .fetch_one(&pool)
        .await
        .expect("count failed interaction audits before response-loss retry");
    let terminal_failure_retry = reauthorizations
        .claim_callback(
            failed_interaction_id,
            &seeded.project_public_id,
            &seeded.provider_key,
            &digest(156),
            &digest(154),
            now + Duration::seconds(20),
        )
        .await
        .expect("authenticate failed terminal response-loss retry");
    assert!(matches!(
        terminal_failure_retry,
        ClaimManagedReauthorization::Duplicate(ref terminal)
            if terminal.status == ManagedReauthorizationStatus::ProviderExchangeFailed
    ));
    let failed_after_retry: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT connection.revision,connection.generation,connection.credential_generation,
                (SELECT count(*) FROM audit_events)
           FROM managed_provider_connections AS connection WHERE connection.id=$1",
    )
    .bind(managed_connection.0)
    .fetch_one(&pool)
    .await
    .expect("failed terminal retry remains read-only");
    assert_eq!(failed_after_retry, (2, 2, 2, failed_audits_before_retry));
    assert!(matches!(
        reauthorizations
            .digest_versions(failed_interaction_id, now + Duration::minutes(10))
            .await,
        Err(crate::application::ApplicationError::NotFound)
    ));
    for attempt in [Duration::minutes(10), Duration::minutes(11)] {
        assert_create_replay(
            &reauthorizations,
            prepared_create_replay(
                &seeded,
                issued.user_id,
                managed_connection.0,
                2,
                2,
                2,
                Uuid::new_v4(),
                format!("managed-reauth-{failed_interaction_id}"),
                152,
                199,
                now + Duration::minutes(9),
                now + attempt,
            ),
            ManagedReauthorizationStatus::ProviderExchangeFailed,
            None,
        )
        .await;
    }
    let failed_tombstone_erased: bool = sqlx::query_scalar(
        "SELECT upstream_state_digest IS NULL AND upstream_state_key_version IS NULL
                AND browser_binding_digest IS NULL AND browser_binding_key_version IS NULL
                AND csrf_digest IS NULL AND csrf_key_version IS NULL
           FROM managed_provider_reauthorization_interactions WHERE id=$1",
    )
    .bind(failed_interaction_id)
    .fetch_one(&pool)
    .await
    .expect("inspect failed post-deadline tombstone erasure");
    assert!(failed_tombstone_erased);

    // Both digest-triggered and ID-triggered expiry must commit the terminal state before the
    // lookup material is erased; callers receive no fallback owner path.
    let digest_expiry_id = Uuid::new_v4();
    reauthorizations
        .create(PreparedManagedReauthorizationCreate {
            capability: managed_capability_snapshot(),
            command: CreateManagedReauthorization {
                project_id: seeded.project_id,
                user_id: issued.user_id,
                connection_id: managed_connection.0,
                application_id: seeded.application_id,
                expected_connection_revision: 2,
                expected_connection_generation: 2,
                expected_credential_generation: 2,
                idempotency_key: format!("managed-reauth-{digest_expiry_id}"),
                correlation_id: Uuid::new_v4(),
            },
            interaction_id: digest_expiry_id,
            interaction_digest: digest(161),
            request_digest: vec![162; 32],
            protected_create_result: ProtectedValue {
                ciphertext: vec![163; 48],
                key_version: 1,
            },
            expires_at: now + Duration::seconds(25),
            now: now + Duration::seconds(20),
        })
        .await
        .expect("create digest-expiring managed reauthorization");
    assert!(matches!(
        reauthorizations
            .bind_browser(
                &digest(161),
                &digest(164),
                &digest(165),
                now + Duration::seconds(26),
            )
            .await,
        Err(ApplicationError::NotFound)
    ));
    let digest_expired: (String, i64) = sqlx::query_as(
        "SELECT status,revision FROM managed_provider_reauthorization_interactions WHERE id=$1",
    )
    .bind(digest_expiry_id)
    .fetch_one(&pool)
    .await
    .expect("inspect digest-triggered expiry");
    assert_eq!(digest_expired, ("expired".to_owned(), 2));
    assert_reauthorization_material_scrubbed(&pool, digest_expiry_id).await;
    for attempt in [Duration::seconds(26), Duration::seconds(27)] {
        assert_create_replay(
            &reauthorizations,
            prepared_create_replay(
                &seeded,
                issued.user_id,
                managed_connection.0,
                2,
                2,
                2,
                Uuid::new_v4(),
                format!("managed-reauth-{digest_expiry_id}"),
                162,
                199,
                now + Duration::seconds(25),
                now + attempt,
            ),
            ManagedReauthorizationStatus::Expired,
            None,
        )
        .await;
    }

    let id_expiry_id = Uuid::new_v4();
    reauthorizations
        .create(PreparedManagedReauthorizationCreate {
            capability: managed_capability_snapshot(),
            command: CreateManagedReauthorization {
                project_id: seeded.project_id,
                user_id: issued.user_id,
                connection_id: managed_connection.0,
                application_id: seeded.application_id,
                expected_connection_revision: 2,
                expected_connection_generation: 2,
                expected_credential_generation: 2,
                idempotency_key: format!("managed-reauth-{id_expiry_id}"),
                correlation_id: Uuid::new_v4(),
            },
            interaction_id: id_expiry_id,
            interaction_digest: digest(171),
            request_digest: vec![172; 32],
            protected_create_result: ProtectedValue {
                ciphertext: vec![173; 48],
                key_version: 1,
            },
            expires_at: now + Duration::seconds(27),
            now: now + Duration::seconds(21),
        })
        .await
        .expect("create ID-expiring managed reauthorization");
    let id_expired = reauthorizations
        .control_read(
            seeded.project_id,
            issued.user_id,
            managed_connection.0,
            id_expiry_id,
            now + Duration::seconds(28),
        )
        .await
        .expect("expire managed reauthorization by ID");
    assert_eq!(id_expired.status, ManagedReauthorizationStatus::Expired);
    assert_reauthorization_material_scrubbed(&pool, id_expiry_id).await;

    // A submitted renewal commits its successor, destroys the predecessor and terminalizes the
    // durable operation in one transaction. A late duplicate is a guarded read-only miss.
    sqlx::query(
        "UPDATE managed_provider_connections SET next_renewal_at=$1 WHERE project_id=$2 AND id=$3",
    )
    .bind(now + Duration::seconds(15))
    .bind(seeded.project_id)
    .bind(managed_connection.0)
    .execute(&pool)
    .await
    .expect("make successor due for atomic renewal proof");
    let renewal = managed_repository
        .prepare_next_renewal(
            Uuid::new_v4(),
            now + Duration::seconds(15),
            now + Duration::seconds(45),
            false,
        )
        .await
        .expect("prepare successor renewal")
        .expect("successor renewal is due");
    assert!(
        managed_repository
            .mark_renewal_submitted(&renewal, now + Duration::seconds(16))
            .await
            .expect("mark successor renewal submitted")
    );
    let renewal_successor_context = ManagedCredentialContext {
        project_id: renewal.claim.guard.project_id,
        provider_configuration_id: renewal.claim.guard.provider_configuration_id,
        linked_identity_id: renewal.claim.guard.linked_identity_id,
        connection_id: renewal.claim.guard.connection_id,
        connection_generation: renewal.claim.guard.connection_generation + 1,
        credential_generation: renewal.claim.guard.credential_generation + 1,
    };
    let protected_renewal_successor = protector
        .protect_credential(&renewal_successor_context, b"renewable-generation-three")
        .expect("protect renewal successor with retained key one");
    let successor_guard = managed_repository
        .commit_renewal_successor(
            &renewal,
            protected_renewal_successor,
            now + Duration::seconds(17),
        )
        .await
        .expect("commit renewal successor")
        .expect("exact renewal wins");
    assert_eq!(
        (
            successor_guard.connection_revision,
            successor_guard.connection_generation,
            successor_guard.credential_generation,
        ),
        (3, 3, 3)
    );
    assert!(
        managed_repository
            .commit_renewal_successor(
                &renewal,
                ProtectedValue {
                    ciphertext: vec![52; 48],
                    key_version: 1,
                },
                now + Duration::seconds(18),
            )
            .await
            .expect("late duplicate renewal is readable")
            .is_none()
    );
    let atomic_state: (String, Option<Vec<u8>>, Option<Vec<u8>>, i64) = sqlx::query_as(
        "SELECT operation.state, predecessor.ciphertext, successor.ciphertext,
                (SELECT count(*) FROM managed_provider_credentials history
                  WHERE history.connection_id=connection.id)
           FROM managed_provider_renewal_operations operation
           JOIN managed_provider_connections connection ON connection.id=operation.connection_id
           JOIN managed_provider_credentials predecessor ON predecessor.connection_id=connection.id
                AND predecessor.credential_generation=2
           JOIN managed_provider_credentials successor ON successor.connection_id=connection.id
                AND successor.credential_generation=3
          WHERE operation.id=$1",
    )
    .bind(renewal.operation_id)
    .fetch_one(&pool)
    .await
    .expect("inspect atomic renewal boundary");
    assert_eq!(atomic_state.0, "successor_committed");
    assert!(atomic_state.1.is_none());
    assert!(atomic_state.2.is_some());
    assert_eq!(atomic_state.3, 3);
    assert!(
        managed_repository
            .finish_successor_profile_failure(
                &successor_guard,
                "read_transient",
                now + Duration::seconds(21),
                now + Duration::seconds(18),
            )
            .await
            .expect("release successor profile stage")
    );

    let inventory = managed_repository
        .required_key_versions()
        .await
        .expect("load exact managed key inventory");
    assert_eq!(inventory, [1].into_iter().collect());
    let rotating_protector = SoftwareRuntimeProtector::new(
        "managed-test-deployment".to_owned(),
        2,
        RuntimeKeyMaterial::new([3; 32], [4; 32]),
        BTreeMap::from([(1, RuntimeKeyMaterial::new([1; 32], [2; 32]))]),
    )
    .expect("rotating managed protector");
    sqlx::query("UPDATE provider_configurations SET managed_profile_enabled=FALSE WHERE id=$1")
        .bind(seeded.provider_id)
        .execute(&pool)
        .await
        .expect("disable sync authority before retirement rewrap");
    let rewrap_claim = managed_repository
        .claim_next_rewrap(
            Uuid::new_v4(),
            2,
            now + Duration::seconds(19),
            now + Duration::seconds(49),
        )
        .await
        .expect("enumerate one old managed credential")
        .expect("old key one is a bounded rewrap candidate");
    let plaintext = rotating_protector
        .unprotect_credential(&renewal_successor_context, &rewrap_claim.protected)
        .expect("retained key decrypts the live candidate");
    assert_eq!(plaintext.as_slice(), b"renewable-generation-three");
    let rewrapped = rotating_protector
        .protect_credential(&renewal_successor_context, plaintext.as_ref())
        .expect("active key protects the candidate");
    assert_eq!(rewrapped.key_version, 2);
    assert!(
        managed_repository
            .finish_rewrap(&rewrap_claim, 1, rewrapped, now + Duration::seconds(20),)
            .await
            .expect("fenced Runtime rewrap commits")
    );
    sqlx::query("UPDATE provider_configurations SET managed_profile_enabled=TRUE WHERE id=$1")
        .bind(seeded.provider_id)
        .execute(&pool)
        .await
        .expect("restore sync authority after retirement rewrap");
    assert!(
        managed_repository
            .claim_next_rewrap(
                Uuid::new_v4(),
                2,
                now + Duration::seconds(21),
                now + Duration::seconds(51),
            )
            .await
            .expect("check rewrap closure")
            .is_none()
    );
    assert_eq!(
        managed_repository
            .required_key_versions()
            .await
            .expect("load rewrapped key inventory"),
        [2].into_iter().collect()
    );

    // Control only persists the revocation intent. Runtime claims it after restart using the
    // explicit revocation lease. Unsupported discovery consumes the intent without destroying
    // the predecessor or stranding a renewal lease.
    let requested = managed_repository
        .request_revocation(
            seeded.project_id,
            issued.user_id,
            managed_connection.0,
            3,
            3,
            Uuid::new_v4(),
            now + Duration::seconds(20),
        )
        .await
        .expect("enqueue exact revocation intent");
    assert_eq!(requested.last_safe_outcome, "revocation_requested");
    let listed = managed_repository
        .list_metadata(seeded.project_id, issued.user_id, 10)
        .await
        .expect("list managed metadata after action");
    assert_eq!(listed.len(), 1);
    assert_eq!(requested.capability_key, listed[0].capability_key);
    assert_eq!(requested.capability_key, "controlled_oidc_profile_v1");
    let revocation_claim = managed_repository
        .claim_next_revocation(
            Uuid::new_v4(),
            now + Duration::seconds(21),
            now + Duration::seconds(51),
        )
        .await
        .expect("claim revocation after runtime restart")
        .expect("durable revocation intent remains due");
    // An adapter preflight that proves no request was dispatched may release the claim and
    // downgrade capability without crossing the destructive boundary.
    assert!(
        managed_repository
            .release_revocation_claim(&revocation_claim, now + Duration::seconds(22))
            .await
            .expect("release undispatched revocation")
    );
    sqlx::query(
        "UPDATE managed_provider_connections SET revision=revision+1,
         last_safe_outcome='revocation_unsupported',supports_revocation=FALSE,
         revocation_requested_at=NULL,revocation_disposition=NULL
         WHERE project_id=$1 AND id=$2",
    )
    .bind(seeded.project_id)
    .bind(managed_connection.0)
    .execute(&pool)
    .await
    .expect("persist pre-dispatch unsupported capability");
    let unsupported = managed_repository
        .metadata_for_owner(seeded.project_id, issued.user_id, managed_connection.0)
        .await
        .expect("unsupported revocation remains observable");
    assert_eq!(unsupported.last_safe_outcome, "revocation_unsupported");
    assert!(!unsupported.supports_revocation);
    assert_eq!((unsupported.revision, unsupported.generation), (5, 3));

    // User-qualified Control actions carry the exact owner into the mutation predicate. A wrong
    // owner preflight is NotFound, while even a caller that bypasses preflight cannot mutate.
    let wrong_owner = Uuid::new_v4();
    assert_eq!(
        managed_repository
            .metadata_for_owner(seeded.project_id, wrong_owner, managed_connection.0)
            .await,
        Err(ApplicationError::NotFound)
    );
    let owner_fence_before: (
        String,
        i64,
        i64,
        Option<OffsetDateTime>,
        Option<OffsetDateTime>,
    ) = sqlx::query_as(
        "SELECT last_safe_outcome,revision,generation,next_renewal_at,revocation_requested_at
               FROM managed_provider_connections WHERE project_id=$1 AND id=$2",
    )
    .bind(seeded.project_id)
    .bind(managed_connection.0)
    .fetch_one(&pool)
    .await
    .expect("snapshot owner-fenced connection");
    assert_eq!(
        managed_repository
            .request_synchronize(
                seeded.project_id,
                wrong_owner,
                managed_connection.0,
                5,
                3,
                now + Duration::seconds(20),
            )
            .await,
        Err(ApplicationError::RevisionConflict)
    );
    assert_eq!(
        managed_repository
            .request_revocation(
                seeded.project_id,
                wrong_owner,
                managed_connection.0,
                5,
                3,
                Uuid::new_v4(),
                now + Duration::seconds(20),
            )
            .await,
        Err(ApplicationError::RevisionConflict)
    );
    assert_eq!(
        managed_repository
            .disconnect(
                seeded.project_id,
                wrong_owner,
                managed_connection.0,
                5,
                3,
                now + Duration::seconds(20),
            )
            .await,
        Err(ApplicationError::RevisionConflict)
    );
    let owner_fence_after: (
        String,
        i64,
        i64,
        Option<OffsetDateTime>,
        Option<OffsetDateTime>,
    ) = sqlx::query_as(
        "SELECT last_safe_outcome,revision,generation,next_renewal_at,revocation_requested_at
               FROM managed_provider_connections WHERE project_id=$1 AND id=$2",
    )
    .bind(seeded.project_id)
    .bind(managed_connection.0)
    .fetch_one(&pool)
    .await
    .expect("verify failed owner actions are non-mutating");
    assert_eq!(owner_fence_after, owner_fence_before);

    let worker_id = Uuid::new_v4();
    let claim = managed_repository
        .claim_next_read(
            worker_id,
            now + Duration::seconds(21),
            now + Duration::seconds(51),
        )
        .await
        .expect("claim managed profile read")
        .expect("managed callback connection is due");
    assert_eq!(
        managed_repository
            .disconnect(
                seeded.project_id,
                issued.user_id,
                managed_connection.0,
                5,
                3,
                now + Duration::seconds(22),
            )
            .await,
        Err(ApplicationError::RevisionConflict),
        "disconnect must not bypass an active profile-read lease"
    );
    managed_repository
        .disconnect(
            seeded.project_id,
            issued.user_id,
            managed_connection.0,
            5,
            3,
            now + Duration::seconds(52),
        )
        .await
        .expect("disconnect recovers after the read lease expires");
    let stale_commit = managed_repository
        .commit_read_profile(
            &claim,
            BoundedManagedProfile {
                profile: BoundedProviderProfile {
                    display_name: Some(ProfileDisplayName::parse("Late Ada".to_owned()).unwrap()),
                    picture_url: None,
                    locale: Some(ProfileLocale::parse("en-GB".to_owned()).unwrap()),
                },
                observed_at: now + Duration::seconds(23),
            },
            now + Duration::hours(6),
            now + Duration::seconds(23),
        )
        .await
        .expect("stale commit returns a guarded miss");
    assert!(
        !stale_commit,
        "late provider work must not resurrect disconnect"
    );
    let disconnected: (String, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT connection.state, credential.ciphertext
           FROM managed_provider_connections AS connection
           JOIN managed_provider_credentials AS credential
             ON credential.project_id = connection.project_id AND credential.connection_id = connection.id
          WHERE connection.project_id = $1 AND connection.id = $2",
    )
    .bind(seeded.project_id)
    .bind(managed_connection.0)
    .fetch_one(&pool)
    .await
    .expect("disconnected credential inventory");
    assert_eq!(disconnected, ("disconnected".to_owned(), None));

    let primary_identity: Option<Uuid> = sqlx::query_scalar(
        "SELECT primary_profile_identity_id FROM project_users
         WHERE project_id = $1 AND id = $2",
    )
    .bind(seeded.project_id)
    .bind(issued.user_id)
    .fetch_one(&pool)
    .await
    .expect("load primary identity");
    let linked_identity: Uuid = sqlx::query_scalar(
        "SELECT id FROM linked_identities WHERE project_id = $1 AND user_id = $2",
    )
    .bind(seeded.project_id)
    .bind(issued.user_id)
    .fetch_one(&pool)
    .await
    .expect("load linked identity");
    assert_eq!(primary_identity, None);
    assert_ne!(linked_identity, email_identity_id);
    let primary_email_identity: Option<Uuid> = sqlx::query_scalar(
        "SELECT primary_email_identity_id FROM project_users
         WHERE project_id=$1 AND id=$2",
    )
    .bind(seeded.project_id)
    .bind(issued.user_id)
    .fetch_one(&pool)
    .await
    .expect("load primary email identity");
    assert_eq!(primary_email_identity, Some(email_identity_id));

    let reuse_login = authentication
        .create_login_transaction(CreateLoginTransaction {
            id: Uuid::new_v4(),
            project_id: seeded.project_id,
            application_id: seeded.application_id,
            interaction: digest(17),
            redirect_uri: "https://app.example/callback".to_owned(),
            application_pkce_challenge: "B".repeat(43),
            application_state: protected(18),
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
            admitted_providers: vec![AdmittedProviderMethod {
                kind: crate::domain::ProviderKind::Oidc,
                method_key: seeded.provider_key.clone(),
                provider_id: seeded.provider_id,
                display_name: "OIDC".to_owned(),
                issuer: "https://issuer.example".to_owned(),
                provider_revision: 1,
                provider_egress_policy_revision: Some(1),
                assignment_security_revision: 1,
            }],
            admitted_email: None,
        })
        .await
        .expect("create reuse login");
    authentication
        .bind_hosted_browser(BindHostedBrowser {
            interaction: digest(17),
            expected_transaction_revision: 1,
            browser_binding: digest(19),
            csrf: digest(20),
            now: now + Duration::seconds(4),
        })
        .await
        .expect("bind reuse browser");
    let reused = sessions
        .confirm_browser_session_reuse(crate::application::ConfirmBrowserSessionReuse {
            project_id: seeded.project_id,
            transaction_id: reuse_login.id,
            expected_transaction_revision: 2,
            browser_binding: digest(19),
            csrf: digest(20),
            browser_credential: digest(9),
            handoff_id: Uuid::new_v4(),
            handoff_ticket: digest(21),
            now: now + Duration::seconds(5),
        })
        .await
        .expect("confirm explicit browser-session reuse");
    assert_eq!(reused.user_id, issued.user_id);
    assert_eq!(reused.browser_session_id, browser_session_id);
    let reused_authenticated_at: OffsetDateTime =
        sqlx::query_scalar("SELECT authenticated_at FROM handoff_tickets WHERE id = $1")
            .bind(reused.handoff_id)
            .fetch_one(&pool)
            .await
            .expect("load reuse authentication time");
    assert_eq!(reused_authenticated_at, now + Duration::seconds(4));

    let exchange_at = now + Duration::seconds(6);
    let handoff_preparation = sessions
        .prepare_handoff_exchange(PrepareHandoffExchange {
            project_id: seeded.project_id,
            application_id: seeded.application_id,
            handoff_ticket: digest(10),
            application_pkce_challenge: "A".repeat(43),
            now: exchange_at,
        })
        .await
        .expect("prepare authoritative handoff exchange");
    assert_eq!(handoff_preparation.user_id, issued.user_id);
    assert_eq!(handoff_preparation.projection_revision, 1);
    assert_eq!(
        handoff_preparation.projection_document["user_id"],
        issued.user_public_id
    );
    assert_eq!(
        handoff_preparation.projection_document["verified_email"],
        "ada@example.test"
    );
    let stale_exchange = CommitHandoffExchange {
        project_id: seeded.project_id,
        application_id: seeded.application_id,
        handoff_ticket: digest(10),
        application_pkce_challenge: "A".repeat(43),
        preparation: handoff_preparation,
        binding_id: Uuid::new_v4(),
        projection_id: Uuid::new_v4(),
        application_session_id: Uuid::new_v4(),
        refresh_family_id: Uuid::new_v4(),
        refresh_generation_id: Uuid::new_v4(),
        refresh_token: digest(12),
        allowed_clock_skew_seconds: 60,
        now: exchange_at,
    };
    sqlx::query("UPDATE project_users SET user_revision = 2 WHERE id = $1")
        .bind(issued.user_id)
        .execute(&pool)
        .await
        .expect("advance user revision after prepare");
    sqlx::query("UPDATE project_policies SET projection_revision = 2 WHERE project_id = $1")
        .bind(seeded.project_id)
        .execute(&pool)
        .await
        .expect("advance Project projection policy after prepare");
    sqlx::query("UPDATE applications SET projection_revision = 2 WHERE id = $1")
        .bind(seeded.application_id)
        .execute(&pool)
        .await
        .expect("advance Application projection policy after prepare");
    sqlx::query("UPDATE project_key_rings SET signing_epoch = 2 WHERE id = $1")
        .bind(seeded.ring_id)
        .execute(&pool)
        .await
        .expect("advance signing epoch after prepare");
    let stale_error = sessions
        .commit_handoff_exchange(stale_exchange.clone())
        .await
        .expect_err("stale prepared handoff must not commit");
    assert_eq!(
        stale_error,
        crate::application::ApplicationError::RevisionConflict
    );
    let fresh_preparation = sessions
        .prepare_handoff_exchange(PrepareHandoffExchange {
            project_id: seeded.project_id,
            application_id: seeded.application_id,
            handoff_ticket: digest(10),
            application_pkce_challenge: "A".repeat(43),
            now: exchange_at,
        })
        .await
        .expect("reprepare handoff after owner revisions change");
    assert_eq!(fresh_preparation.user_revision, 2);
    assert_eq!(fresh_preparation.project_projection_revision, 2);
    assert_eq!(fresh_preparation.application_projection_revision, 2);
    assert_eq!(fresh_preparation.signing_epoch, 2);
    let expected_projection = fresh_preparation.projection_document.clone();
    let exchange = CommitHandoffExchange {
        preparation: fresh_preparation,
        binding_id: Uuid::new_v4(),
        projection_id: Uuid::new_v4(),
        application_session_id: Uuid::new_v4(),
        refresh_family_id: Uuid::new_v4(),
        refresh_generation_id: Uuid::new_v4(),
        ..stale_exchange
    };
    let stale_incarnation_exchange = exchange.clone();
    let (exchange_a, exchange_b) = tokio::join!(
        sessions.commit_handoff_exchange(exchange.clone()),
        sessions.commit_handoff_exchange(exchange)
    );
    assert!(
        matches!(
            (&exchange_a, &exchange_b),
            (Ok(_), Err(_)) | (Err(_), Ok(_))
        ),
        "one handoff consumer must win: {exchange_a:?} {exchange_b:?}"
    );
    let session = exchange_a.or(exchange_b).expect("one handoff exchange");
    let binding_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM application_user_bindings
         WHERE project_id = $1 AND application_id = $2 AND user_id = $3",
    )
    .bind(seeded.project_id)
    .bind(seeded.application_id)
    .bind(issued.user_id)
    .fetch_one(&pool)
    .await
    .expect("count Application binding");
    assert_eq!(binding_count, 1);
    let projection_application: Uuid = sqlx::query_scalar(
        "SELECT application_id FROM application_user_projections
         WHERE project_id = $1 AND binding_id = $2",
    )
    .bind(seeded.project_id)
    .bind(session.binding_id)
    .fetch_one(&pool)
    .await
    .expect("load Application projection");
    assert_eq!(projection_application, seeded.application_id);
    let at_rest_projection: (String, Option<Vec<u8>>, Option<i32>, Option<Uuid>) = sqlx::query_as(
        "SELECT document::TEXT,verified_email_ciphertext,
                    verified_email_key_version,verified_email_source_identity_id
               FROM application_user_projections WHERE binding_id=$1",
    )
    .bind(session.binding_id)
    .fetch_one(&pool)
    .await
    .expect("load protected Application projection");
    assert!(!at_rest_projection.0.contains("ada@example.test"));
    assert!(at_rest_projection.0.contains("\"verified_email\": null"));
    assert!(at_rest_projection.1.is_some());
    assert_eq!(at_rest_projection.2, Some(1));
    assert_eq!(at_rest_projection.3, Some(email_identity_id));

    sqlx::query(
        "UPDATE application_user_projections
         SET document = jsonb_set(document, '{display_name}', to_jsonb('stale'::text)),
             canonical_digest = $2
         WHERE binding_id = $1",
    )
    .bind(session.binding_id)
    .bind(vec![3_u8; 32])
    .execute(&pool)
    .await
    .expect("corrupt stored projection before current-user read");
    let runtime = PostgresRuntimeAuthorityRepository::with_runtime_protector(
        database.clone(),
        protector.clone(),
    );
    let current = runtime
        .current_session(
            AccessTokenSessionLookup {
                project_id: seeded.project_id,
                application_public_id: "app_session01".to_owned(),
                user_public_id: issued.user_public_id.clone(),
                application_session_id: session.application_session_id,
                claims_revision: 1,
                now: exchange_at,
            },
            false,
        )
        .await
        .expect("current-user read lazily repairs projection material");
    assert_eq!(current.projection_revision, session.projection_revision);
    assert_eq!(current.projection_document, expected_projection);

    sqlx::query(
        "UPDATE applications
            SET projection_verified_email_enabled=FALSE,projection_revision=3 WHERE id=$1",
    )
    .bind(seeded.application_id)
    .execute(&pool)
    .await
    .expect("close Application verified-email projection gate");
    let gated_off = runtime
        .current_session(
            AccessTokenSessionLookup {
                project_id: seeded.project_id,
                application_public_id: "app_session01".to_owned(),
                user_public_id: issued.user_public_id.clone(),
                application_session_id: session.application_session_id,
                claims_revision: 1,
                now: exchange_at,
            },
            false,
        )
        .await
        .expect("repair projection after one policy gate closes");
    assert_eq!(
        gated_off.projection_document["verified_email"],
        serde_json::Value::Null
    );
    assert_eq!(gated_off.projection_revision, 2);

    sqlx::query(
        "UPDATE applications
            SET projection_verified_email_enabled=TRUE,projection_revision=4 WHERE id=$1",
    )
    .bind(seeded.application_id)
    .execute(&pool)
    .await
    .expect("reopen Application verified-email projection gate");

    let (family_expires_at, initial_retain_until): (OffsetDateTime, OffsetDateTime) =
        sqlx::query_as(
            "SELECT families.absolute_expires_at, generations.retain_until
             FROM refresh_families AS families
             JOIN refresh_token_generations AS generations ON generations.family_id = families.id
             WHERE families.id = $1 AND generations.generation = 1",
        )
        .bind(session.refresh_family_id)
        .fetch_one(&pool)
        .await
        .expect("load initial refresh retention");
    assert_eq!(
        initial_retain_until,
        family_expires_at + Duration::seconds(60)
    );

    let refresh_at = exchange_at + Duration::seconds(1);
    sqlx::query(
        "UPDATE application_user_projections
         SET document = jsonb_set(document, '{display_name}', to_jsonb('stale_document_only'::text)),
             verified_email_source_identity_id=NULL,
             verified_email_ciphertext=NULL,
             verified_email_key_version=NULL
         WHERE binding_id = $1",
    )
    .bind(session.binding_id)
    .execute(&pool)
    .await
    .expect("corrupt only projection document before refresh");
    let refresh_preparation = sessions
        .prepare_refresh_rotation(PrepareRefreshRotation {
            project_id: seeded.project_id,
            application_id: seeded.application_id,
            presented_token: digest(12),
            now: refresh_at,
        })
        .await
        .expect("prepare authoritative refresh rotation");
    let RefreshPreparationResult::Ready(refresh_preparation) = refresh_preparation else {
        panic!("current refresh token must prepare for rotation");
    };
    assert_eq!(refresh_preparation.generation, 1);
    assert_eq!(
        refresh_preparation.projection_document["verified_email"],
        "ada@example.test"
    );
    assert_eq!(
        refresh_preparation.projection_revision,
        gated_off.projection_revision + 1
    );
    let expected_projection = refresh_preparation.projection_document.clone();
    let expected_projection_revision = refresh_preparation.projection_revision;
    let current_after_refresh_repair = runtime
        .current_session(
            AccessTokenSessionLookup {
                project_id: seeded.project_id,
                application_public_id: "app_session01".to_owned(),
                user_public_id: issued.user_public_id.clone(),
                application_session_id: session.application_session_id,
                claims_revision: 1,
                now: refresh_at,
            },
            false,
        )
        .await
        .expect("refresh repair must protect email under the Application context");
    assert_eq!(
        current_after_refresh_repair.projection_document,
        expected_projection
    );

    sqlx::query(
        "ALTER TABLE application_user_projections
         DISABLE TRIGGER application_user_projections_source_base_digest_fill",
    )
    .execute(&pool)
    .await
    .expect("disable compatibility trigger for legacy-null fixture");
    sqlx::query(
        "UPDATE application_user_projections
         SET source_base_profile_digest = NULL
         WHERE binding_id = $1",
    )
    .bind(session.binding_id)
    .execute(&pool)
    .await
    .expect("simulate legacy projection without source digest");
    sqlx::query(
        "ALTER TABLE application_user_projections
         ENABLE TRIGGER application_user_projections_source_base_digest_fill",
    )
    .execute(&pool)
    .await
    .expect("restore projection compatibility trigger");
    let source_digest_repair = sessions
        .prepare_refresh_rotation(PrepareRefreshRotation {
            project_id: seeded.project_id,
            application_id: seeded.application_id,
            presented_token: digest(12),
            now: refresh_at,
        })
        .await
        .expect("repair source digest during refresh preparation");
    let RefreshPreparationResult::Ready(source_digest_repair) = source_digest_repair else {
        panic!("current refresh token must remain eligible during storage repair");
    };
    assert_eq!(
        source_digest_repair.projection_revision,
        expected_projection_revision
    );
    assert_eq!(
        source_digest_repair.projection_document,
        expected_projection
    );
    let refresh_a = RotateRefreshToken {
        project_id: seeded.project_id,
        application_id: seeded.application_id,
        presented_token: digest(12),
        preparation: *source_digest_repair,
        successor_generation_id: Uuid::new_v4(),
        successor_token: digest(13),
        now: refresh_at,
    };
    let refresh_b = RotateRefreshToken {
        successor_generation_id: Uuid::new_v4(),
        successor_token: digest(14),
        ..refresh_a.clone()
    };
    let stale_incarnation_refresh = refresh_a.clone();
    let (rotated_a, rotated_b) = tokio::join!(
        sessions.rotate_refresh_token(refresh_a),
        sessions.rotate_refresh_token(refresh_b)
    );
    assert!(
        matches!(
            (&rotated_a, &rotated_b),
            (
                Ok(RefreshRotationResult::Rotated { .. }),
                Ok(RefreshRotationResult::ReplayRevoked { .. })
            ) | (
                Ok(RefreshRotationResult::ReplayRevoked { .. }),
                Ok(RefreshRotationResult::Rotated { .. })
            )
        ),
        "one rotation and one replay revocation are required: {rotated_a:?} {rotated_b:?}"
    );
    let (family_status, reason): (String, Option<String>) =
        sqlx::query_as("SELECT status, revocation_reason FROM refresh_families WHERE id = $1")
            .bind(session.refresh_family_id)
            .fetch_one(&pool)
            .await
            .expect("load refresh family");
    assert_eq!(family_status, "revoked");
    assert_eq!(reason.as_deref(), Some("replay"));
    let successor_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM refresh_token_generations
         WHERE family_id = $1 AND generation = 2 AND status = 'current'",
    )
    .bind(session.refresh_family_id)
    .fetch_one(&pool)
    .await
    .expect("count successor");
    assert_eq!(successor_count, 1);
    let successor_retain_until: OffsetDateTime = sqlx::query_scalar(
        "SELECT retain_until FROM refresh_token_generations
         WHERE family_id = $1 AND generation = 2",
    )
    .bind(session.refresh_family_id)
    .fetch_one(&pool)
    .await
    .expect("load successor retention");
    assert_eq!(
        successor_retain_until,
        family_expires_at + Duration::seconds(60)
    );

    sqlx::query(
        "UPDATE applications
            SET projection_verified_email_enabled=FALSE,projection_revision=5 WHERE id=$1",
    )
    .bind(seeded.application_id)
    .execute(&pool)
    .await
    .expect("close Application verified-email gate before Control disable");
    let gated_off_again = runtime
        .current_session(
            AccessTokenSessionLookup {
                project_id: seeded.project_id,
                application_public_id: "app_session01".to_owned(),
                user_public_id: issued.user_public_id.clone(),
                application_session_id: session.application_session_id,
                claims_revision: 1,
                now: refresh_at,
            },
            true,
        )
        .await
        .expect("clear protected projection material through Runtime authority");
    assert_eq!(gated_off_again.projection_revision, 4);
    assert_eq!(
        gated_off_again.projection_document["verified_email"],
        serde_json::Value::Null
    );

    let prepared = sessions
        .prepare_browser_logout(PrepareBrowserLogout {
            id: Uuid::new_v4(),
            project_id: seeded.project_id,
            application_id: seeded.application_id,
            user_id: issued.user_id,
            application_session_id: session.application_session_id,
            browser_session_id,
            preparation: digest(15),
            now: refresh_at + Duration::seconds(1),
        })
        .await
        .expect("prepare browser logout");
    let bound = sessions
        .bind_browser_logout(BindBrowserLogout {
            preparation: digest(15),
            browser_credential: digest(9),
            expected_interaction_revision: prepared.interaction_revision,
            csrf: digest(16),
            now: refresh_at + Duration::seconds(2),
        })
        .await
        .expect("bind browser logout CSRF");
    let confirm = ConfirmBrowserLogout {
        preparation: digest(15),
        browser_credential: digest(9),
        csrf: digest(16),
        expected_interaction_revision: bound.interaction_revision,
        now: refresh_at + Duration::seconds(3),
    };
    let stale_incarnation_browser_logout = confirm.clone();
    let (confirmed_a, confirmed_b) = tokio::join!(
        sessions.confirm_browser_logout(confirm.clone()),
        sessions.confirm_browser_logout(confirm)
    );
    assert!(
        matches!(
            (&confirmed_a, &confirmed_b),
            (Ok(_), Err(_)) | (Err(_), Ok(_))
        ),
        "one browser logout confirmation must win: {confirmed_a:?} {confirmed_b:?}"
    );
    let browser_status: String =
        sqlx::query_scalar("SELECT status FROM project_browser_sessions WHERE id = $1")
            .bind(browser_session_id)
            .fetch_one(&pool)
            .await
            .expect("load browser session");
    assert_eq!(browser_status, "terminated");

    sqlx::query(
        "UPDATE application_user_projections
         SET document=jsonb_set(document, '{display_name}', to_jsonb('stale_after_replacement'::text)),
             canonical_digest=decode(repeat('03', 32), 'hex')
         WHERE binding_id=$1",
    )
    .bind(session.binding_id)
    .execute(&pool)
    .await
    .expect("corrupt projection before stale current-session read");
    let audit_before_replacement: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events")
        .fetch_one(&pool)
        .await
        .expect("count audit events before Runtime replacement");
    let refresh_before_replacement: (String, i64, i64, i64) = sqlx::query_as(
        "SELECT status, family_revision::BIGINT, current_generation::BIGINT,
           (SELECT count(*) FROM refresh_token_generations WHERE family_id=$1)
         FROM refresh_families WHERE id=$1",
    )
    .bind(session.refresh_family_id)
    .fetch_one(&pool)
    .await
    .expect("snapshot refresh authority before Runtime replacement");
    let browser_before_replacement: (String, i64) = sqlx::query_as(
        "SELECT status, session_revision::BIGINT FROM project_browser_sessions WHERE id=$1",
    )
    .bind(browser_session_id)
    .fetch_one(&pool)
    .await
    .expect("snapshot browser session before Runtime replacement");
    let logout_before_replacement: (String, i64) = sqlx::query_as(
        "SELECT status, interaction_revision::BIGINT
         FROM project_browser_logout_interactions WHERE preparation_digest=$1",
    )
    .bind(digest(15).value.to_vec())
    .fetch_one(&pool)
    .await
    .expect("snapshot browser logout before Runtime replacement");
    let authority_counts_before_replacement: (i64, i64, i64) = sqlx::query_as(
        "SELECT
           (SELECT count(*) FROM handoff_tickets),
           (SELECT count(*) FROM application_sessions),
           (SELECT count(*) FROM application_user_bindings)",
    )
    .fetch_one(&pool)
    .await
    .expect("snapshot authority row counts before Runtime replacement");
    let projection_before_replacement: (i64, String, String) = sqlx::query_as(
        "SELECT projection_revision::BIGINT, document::TEXT, encode(canonical_digest, 'hex')
         FROM application_user_projections WHERE binding_id=$1",
    )
    .bind(session.binding_id)
    .fetch_one(&pool)
    .await
    .expect("snapshot projection before Runtime replacement");
    let login_count_before_replacement: i64 =
        sqlx::query_scalar("SELECT count(*) FROM login_transactions")
            .fetch_one(&pool)
            .await
            .expect("count logins before Runtime replacement");

    // One disabled and one active Application may intentionally share an origin. Project-level
    // CORS authorization is existential and must not route through an arbitrary disabled owner.
    let disabled_shared_origin_application = Uuid::nil();
    sqlx::query(
        "INSERT INTO applications
           (id,project_id,public_id,display_name,application_type,status,revision,metadata_revision,security_revision)
         VALUES ($1,$2,'app_disabled_shared_origin','Disabled shared origin','web','disabled',1,1,1)",
    )
    .bind(disabled_shared_origin_application)
    .bind(seeded.project_id)
    .execute(&pool)
    .await
    .expect("seed disabled shared-origin Application");
    sqlx::query(
        "INSERT INTO application_origins (project_id,application_id,origin)
         VALUES ($1,$2,'https://app.example'),($1,$3,'https://app.example')",
    )
    .bind(seeded.project_id)
    .bind(seeded.application_id)
    .bind(disabled_shared_origin_application)
    .execute(&pool)
    .await
    .expect("seed disabled shared origin");
    assert!(
        runtime
            .project_origin_allowed(&seeded.project_public_id, "https://app.example")
            .await
            .expect("active sibling authorizes shared origin")
    );

    let replacement_runtime_incarnation = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO runtime_process_incarnations
         (process_id, process_incarnation, started_at) VALUES ('runtime-1', $1, $2)
         ON CONFLICT (process_id) DO UPDATE SET
           process_incarnation=EXCLUDED.process_incarnation, started_at=EXCLUDED.started_at",
    )
    .bind(replacement_runtime_incarnation)
    .bind(refresh_at + Duration::seconds(4))
    .execute(&pool)
    .await
    .expect("replace the Runtime incarnation");
    let disabled = crate::application::ApplicationError::Disabled;
    assert_eq!(
        authentication
            .create_login_transaction(CreateLoginTransaction {
                id: Uuid::new_v4(),
                project_id: seeded.project_id,
                application_id: seeded.application_id,
                interaction: digest(31),
                redirect_uri: "https://app.example/callback".to_owned(),
                application_pkce_challenge: "A".repeat(43),
                application_state: protected(32),
                presentation_hint: None,
                revisions: LoginRevisionSnapshot {
                    project_metadata_revision: 1,
                    project_security_revision: 1,
                    application_security_revision: 1,
                    claims_revision: 1,
                    session_revision: 1,
                },
                created_at: refresh_at + Duration::seconds(4),
                expires_at: refresh_at + Duration::minutes(10) + Duration::seconds(4),
                admitted_providers: vec![AdmittedProviderMethod {
                    kind: crate::domain::ProviderKind::Oidc,
                    method_key: seeded.provider_key.clone(),
                    provider_id: seeded.provider_id,
                    display_name: "OIDC".to_owned(),
                    issuer: "https://issuer.example".to_owned(),
                    provider_revision: 1,
                    provider_egress_policy_revision: Some(1),
                    assignment_security_revision: 1,
                }],
                admitted_email: None,
            })
            .await,
        Err(disabled)
    );
    assert_eq!(
        sessions
            .commit_handoff_exchange(stale_incarnation_exchange)
            .await,
        Err(disabled)
    );
    assert_eq!(
        sessions
            .complete_authenticated_identity(completion_command(&seeded, &claimed, 41, now))
            .await,
        Err(disabled)
    );
    assert_eq!(
        authentication
            .fail_provider_exchange(FailProviderExchange {
                project_id: seeded.project_id,
                transaction_id: login.id,
                expected_transaction_revision: 1,
                now: refresh_at + Duration::seconds(4),
            })
            .await,
        Err(disabled)
    );
    assert_eq!(
        sessions
            .rotate_refresh_token(stale_incarnation_refresh)
            .await,
        Err(disabled)
    );
    assert_eq!(
        sessions
            .logout_application_session(LogoutApplicationSession {
                project_id: seeded.project_id,
                application_id: seeded.application_id,
                user_id: issued.user_id,
                application_session_id: session.application_session_id,
                now: refresh_at + Duration::seconds(4),
            })
            .await,
        Err(disabled)
    );
    assert_eq!(
        sessions
            .recover_abandoned_provider_exchanges(RecoverProviderExchanges {
                abandoned_before: refresh_at,
                now: refresh_at + Duration::seconds(4),
                limit: 10,
            })
            .await,
        Err(disabled)
    );
    assert_eq!(
        sessions
            .confirm_browser_logout(stale_incarnation_browser_logout)
            .await,
        Err(disabled)
    );
    assert_eq!(
        runtime
            .resolve_application(&seeded.project_public_id, "app_session01", "pk_unused")
            .await,
        Err(disabled)
    );
    assert_eq!(
        runtime
            .resolve_public_application(&seeded.project_public_id, "app_session01")
            .await,
        Err(disabled)
    );
    assert_eq!(
        runtime
            .exact_application_origin(
                seeded.project_id,
                seeded.application_id,
                "https://app.example",
            )
            .await,
        Err(disabled)
    );
    assert_eq!(
        runtime
            .project_origin_allowed(&seeded.project_public_id, "https://app.example")
            .await,
        Err(disabled)
    );
    assert_eq!(
        runtime
            .browser_session_reuse_available(seeded.project_id, &digest(9), refresh_at)
            .await,
        Err(disabled)
    );
    assert_eq!(
        runtime
            .verification_key(&seeded.project_public_id, "kid_test01", refresh_at)
            .await,
        Err(disabled)
    );
    assert_eq!(
        runtime
            .browser_logout_context(&digest(15), refresh_at)
            .await,
        Err(disabled)
    );
    assert_eq!(
        runtime
            .current_session(
                AccessTokenSessionLookup {
                    project_id: seeded.project_id,
                    application_public_id: "app_session01".to_owned(),
                    user_public_id: issued.user_public_id.clone(),
                    application_session_id: session.application_session_id,
                    claims_revision: 1,
                    now: refresh_at,
                },
                false,
            )
            .await,
        Err(disabled)
    );
    let login_count_after_replacement: i64 =
        sqlx::query_scalar("SELECT count(*) FROM login_transactions")
            .fetch_one(&pool)
            .await
            .expect("count logins after stale Runtime calls");
    assert_eq!(
        login_count_after_replacement,
        login_count_before_replacement
    );
    let application_session_status: String =
        sqlx::query_scalar("SELECT status FROM application_sessions WHERE id=$1")
            .bind(session.application_session_id)
            .fetch_one(&pool)
            .await
            .expect("load application session after stale logout");
    assert_eq!(application_session_status, "active");
    let audit_after_replacement: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events")
        .fetch_one(&pool)
        .await
        .expect("count audit events after stale calls");
    let refresh_after_replacement: (String, i64, i64, i64) = sqlx::query_as(
        "SELECT status, family_revision::BIGINT, current_generation::BIGINT,
           (SELECT count(*) FROM refresh_token_generations WHERE family_id=$1)
         FROM refresh_families WHERE id=$1",
    )
    .bind(session.refresh_family_id)
    .fetch_one(&pool)
    .await
    .expect("snapshot refresh authority after stale calls");
    let browser_after_replacement: (String, i64) = sqlx::query_as(
        "SELECT status, session_revision::BIGINT FROM project_browser_sessions WHERE id=$1",
    )
    .bind(browser_session_id)
    .fetch_one(&pool)
    .await
    .expect("snapshot browser session after stale calls");
    let logout_after_replacement: (String, i64) = sqlx::query_as(
        "SELECT status, interaction_revision::BIGINT
         FROM project_browser_logout_interactions WHERE preparation_digest=$1",
    )
    .bind(digest(15).value.to_vec())
    .fetch_one(&pool)
    .await
    .expect("snapshot browser logout after stale calls");
    let authority_counts_after_replacement: (i64, i64, i64) = sqlx::query_as(
        "SELECT
           (SELECT count(*) FROM handoff_tickets),
           (SELECT count(*) FROM application_sessions),
           (SELECT count(*) FROM application_user_bindings)",
    )
    .fetch_one(&pool)
    .await
    .expect("snapshot authority row counts after stale calls");
    let projection_after_replacement: (i64, String, String) = sqlx::query_as(
        "SELECT projection_revision::BIGINT, document::TEXT, encode(canonical_digest, 'hex')
         FROM application_user_projections WHERE binding_id=$1",
    )
    .bind(session.binding_id)
    .fetch_one(&pool)
    .await
    .expect("snapshot projection after stale current-session read");
    assert_eq!(audit_after_replacement, audit_before_replacement);
    assert_eq!(refresh_after_replacement, refresh_before_replacement);
    assert_eq!(browser_after_replacement, browser_before_replacement);
    assert_eq!(logout_after_replacement, logout_before_replacement);
    assert_eq!(
        authority_counts_after_replacement,
        authority_counts_before_replacement
    );
    assert_eq!(projection_after_replacement, projection_before_replacement);

    let control = PostgresControlLifecycleRepository::new(database.clone());
    let disabled = control
        .disable_project_user(DisableProjectUser {
            project_id: seeded.project_id,
            user_id: issued.user_id,
            expected_security_revision: 1,
            correlation_id: Uuid::new_v4(),
            now: refresh_at + Duration::seconds(4),
        })
        .await
        .expect("disable user and fan out the authoritative projection");
    assert_eq!(disabled.user_revision, 3);
    let disabled_projection: (i64, i64, String) = sqlx::query_as(
        "SELECT projection_revision, source_user_revision, document->>'status'
         FROM application_user_projections WHERE binding_id = $1",
    )
    .bind(session.binding_id)
    .fetch_one(&pool)
    .await
    .expect("load disabled projection");
    assert_eq!(disabled_projection, (5, 3, "disabled".to_owned()));

    let audit_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events
         WHERE project_id = $1 AND action LIKE 'auth.%' AND safe_context = '{}'::jsonb",
    )
    .bind(seeded.project_id)
    .fetch_one(&pool)
    .await
    .expect("count credential-free Runtime audit events");
    assert_eq!(audit_count, 14);

    database.close().await.expect("close SeaORM pool");
    pool.close().await;
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the real PostgreSQL concurrency proof keeps both complete transactions visible"
)]
async fn ordinary_login_and_managed_profile_share_canonical_user_identity_lock_order() {
    let Some((_container, url)) = start_postgres().await else {
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(12)
        .connect(&url)
        .await
        .expect("lock-order PostgreSQL pool");
    MIGRATOR.run(&pool).await.expect("lock-order migrations");
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .expect("whole-second lock-order time");
    let seeded = seed_authority(&pool, now, "lockorder01").await;
    sqlx::query("UPDATE provider_configurations SET managed_profile_enabled=TRUE WHERE id=$1")
        .bind(seeded.provider_id)
        .execute(&pool)
        .await
        .expect("enable lock-order managed provider");
    let database = Database::connect(&url)
        .await
        .expect("lock-order SeaORM pool");
    let authentication = PostgresAuthenticationRepository::new(database.clone());
    let sessions = PostgresSessionAuthorityRepository::new(database.clone());
    let first_claim = claim_provider_login(&authentication, &seeded, 71, now).await;
    let issued = sessions
        .complete_authenticated_identity(completion_command(&seeded, &first_claim, 71, now))
        .await
        .expect("create existing identity");
    let ordinary_claim = claim_provider_login(&authentication, &seeded, 81, now).await;
    let protector = SoftwareRuntimeProtector::new(
        "lock-order-deployment".to_owned(),
        1,
        RuntimeKeyMaterial::new([61; 32], [62; 32]),
        BTreeMap::new(),
    )
    .expect("lock-order protector");
    let fixture =
        insert_managed_for_existing_identity(&pool, &seeded, issued.user_id, &protector, now).await;
    let managed = PostgresManagedConnectionRepository::new(database.clone());
    let guard_claim = managed
        .claim_for_revocation(
            seeded.project_id,
            issued.user_id,
            fixture.connection_id,
            1,
            1,
            Uuid::new_v4(),
            now,
            now + Duration::seconds(30),
        )
        .await
        .expect("capture managed profile guard");
    assert!(
        managed
            .release_revocation_claim(&guard_claim, now)
            .await
            .expect("release lock-order guard lease")
    );
    let ordinary = sessions.complete_authenticated_identity(completion_command(
        &seeded,
        &ordinary_claim,
        81,
        now + Duration::seconds(1),
    ));
    let managed_profile = managed.commit_reauthorization_profile(
        &guard_claim.guard,
        BoundedManagedProfile {
            profile: BoundedProviderProfile {
                display_name: Some(
                    ProfileDisplayName::parse("Concurrent managed profile".to_owned())
                        .expect("bounded concurrent profile"),
                ),
                picture_url: None,
                locale: Some(ProfileLocale::parse("en-US".to_owned()).expect("bounded locale")),
            },
            observed_at: now + Duration::seconds(1),
        },
        now + Duration::hours(6),
        now + Duration::seconds(1),
    );
    let (ordinary_result, managed_result) =
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(ordinary, managed_profile)
        })
        .await
        .expect("canonical lock order prevents deadlock");
    let ordinary_result = ordinary_result.expect("ordinary existing-identity login completes");
    assert_eq!(ordinary_result.user_id, issued.user_id);
    let _managed_committed = managed_result.expect("managed completion returns coherent fence");
    let coherent: (i64, i64, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT count(*) OVER (),identity.identity_revision,credential.ciphertext
           FROM linked_identities identity
           JOIN managed_provider_connections connection
             ON connection.project_id=identity.project_id AND connection.linked_identity_id=identity.id
           JOIN managed_provider_credentials credential
             ON credential.project_id=connection.project_id AND credential.connection_id=connection.id
            AND credential.credential_generation=connection.credential_generation
          WHERE identity.project_id=$1 AND identity.issuer='https://issuer.example'
            AND identity.subject='shared-subject'",
    )
    .bind(seeded.project_id)
    .fetch_one(&pool)
    .await
    .expect("inspect coherent concurrent identity result");
    assert_eq!(coherent.0, 1);
    assert!(coherent.1 >= 1);
    assert!(coherent.2.is_some());

    database
        .close()
        .await
        .expect("close lock-order SeaORM pool");
    pool.close().await;
}

#[tokio::test]
#[allow(
    clippy::type_complexity,
    reason = "the nullable tuple mirrors the exact short-term denial columns"
)]
async fn ordinary_provider_denial_validates_owner_and_erases_callback_secrets() {
    let Some((_container, url)) = start_postgres().await else {
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .expect("ordinary-denial PostgreSQL pool");
    MIGRATOR
        .run(&pool)
        .await
        .expect("ordinary-denial migrations");
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .expect("whole-second ordinary-denial time");
    let seeded = seed_authority(&pool, now, "denylogin01").await;
    let database = Database::connect(&url)
        .await
        .expect("ordinary-denial SeaORM pool");
    let authentication = PostgresAuthenticationRepository::new(database.clone());
    let login = prepare_provider_login(&authentication, &seeded, 101, now).await;
    let denial =
        |project_public_id: String, browser_binding: VersionedDigest| DenyProviderCallback {
            transaction_id: login.id,
            project_public_id,
            provider_key: seeded.provider_key.clone(),
            upstream_state: digest(105),
            browser_binding,
            safe_outcome: "auth.callback.denied_access",
            now: now + Duration::seconds(3),
        };
    assert_eq!(
        authentication
            .deny_provider_callback(denial(seeded.project_public_id.clone(), digest(199)))
            .await
            .expect_err("wrong browser denial is read-only"),
        ApplicationError::NotFound
    );
    assert_eq!(
        authentication
            .deny_provider_callback(denial("prj_wrong-owner".to_owned(), digest(103)))
            .await
            .expect_err("wrong Project denial is read-only"),
        ApplicationError::NotFound
    );
    let untouched: String = sqlx::query_scalar("SELECT status FROM login_transactions WHERE id=$1")
        .bind(login.id)
        .fetch_one(&pool)
        .await
        .expect("inspect read-only denial failures");
    assert_eq!(untouched, "provider_authorization_started");
    let denied = authentication
        .deny_provider_callback(denial(seeded.project_public_id.clone(), digest(103)))
        .await
        .expect("terminalize exact ordinary denial");
    assert_eq!(denied.status.as_str(), "provider_exchange_failed");
    let erased: (
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
    ) = sqlx::query_as(
        "SELECT browser_binding_digest,csrf_digest,upstream_state_digest,
                oidc_nonce_digest,provider_pkce_ciphertext
           FROM login_transactions WHERE id=$1",
    )
    .bind(login.id)
    .fetch_one(&pool)
    .await
    .expect("inspect ordinary denial secret erasure");
    assert_eq!(erased, (None, None, None, None, None));
    assert!(matches!(
        authentication
            .deny_provider_callback(denial(seeded.project_public_id.clone(), digest(103)))
            .await,
        Err(ApplicationError::NotFound)
    ));
    let audits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events
          WHERE target_id=$1 AND action='auth.callback.denied_access'",
    )
    .bind(login.id)
    .fetch_one(&pool)
    .await
    .expect("count low-cardinality denial audit");
    assert_eq!(audits, 1);

    database
        .close()
        .await
        .expect("close ordinary-denial SeaORM pool");
    pool.close().await;
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the deterministic PostgreSQL lock race remains visible end to end"
)]
async fn read_evidence_rolls_back_when_control_revocation_wins_connection_lock() {
    let Some((_container, url)) = start_postgres().await else {
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .expect("read-evidence PostgreSQL pool");
    MIGRATOR.run(&pool).await.expect("read-evidence migrations");
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .expect("whole-second read-evidence time");
    let seeded = seed_authority(&pool, now, "readrace01").await;
    sqlx::query("UPDATE provider_configurations SET managed_profile_enabled=TRUE WHERE id=$1")
        .bind(seeded.provider_id)
        .execute(&pool)
        .await
        .expect("enable read-evidence managed provider");
    let protector = SoftwareRuntimeProtector::new(
        "read-evidence-deployment".to_owned(),
        1,
        RuntimeKeyMaterial::new([91; 32], [92; 32]),
        BTreeMap::new(),
    )
    .expect("read-evidence protector");
    let fixture = insert_managed_fixture(&pool, &seeded, &protector, now, 91).await;
    let database = Database::connect(&url)
        .await
        .expect("read-evidence SeaORM pool");
    let repository = PostgresManagedConnectionRepository::new(database.clone());
    let guard = repository
        .claim_for_revocation(
            seeded.project_id,
            fixture.user_id,
            fixture.connection_id,
            1,
            1,
            Uuid::new_v4(),
            now,
            now + Duration::seconds(30),
        )
        .await
        .expect("capture exact read-evidence guard");
    assert!(
        repository
            .release_revocation_claim(&guard, now)
            .await
            .expect("release synthetic guard lease")
    );

    // Hold the same connection-row update that Control's request_revocation performs. The
    // read-evidence transaction can lock Project/provider/user/identity while it waits here, but
    // it may not touch ciphertext until this exact lifecycle lock resolves.
    let mut control = pool.begin().await.expect("begin Control revocation");
    sqlx::query(
        "UPDATE managed_provider_connections
            SET revision=revision+1,revocation_requested_at=$1,
                revocation_disposition='revoke',last_safe_outcome='revocation_requested',updated_at=$1
          WHERE id=$2 AND revision=1 AND generation=1",
    )
    .bind(now + Duration::seconds(1))
    .bind(fixture.connection_id)
    .execute(&mut *control)
    .await
    .expect("hold Control lifecycle winner");
    let concurrent = repository.clone();
    let exact_guard = guard.guard.clone();
    let fence = tokio::spawn(async move {
        concurrent
            .fence_read_evidence(
                &exact_guard,
                false,
                "read_invalid_credential",
                now + Duration::seconds(2),
            )
            .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(
        !fence.is_finished(),
        "evidence must wait for the exact lifecycle row lock"
    );
    control.commit().await.expect("commit Control revocation");
    assert!(
        !fence
            .await
            .expect("join read-evidence race")
            .expect("read-evidence race remains coherent")
    );
    let coherent: (String, i64, bool, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT connection.state,connection.revision,
                connection.revocation_requested_at IS NOT NULL,credential.ciphertext
           FROM managed_provider_connections connection
           JOIN managed_provider_credentials credential
             ON credential.project_id=connection.project_id AND credential.connection_id=connection.id
            AND credential.credential_generation=connection.credential_generation
          WHERE connection.id=$1",
    )
    .bind(fixture.connection_id)
    .fetch_one(&pool)
    .await
    .expect("inspect atomic read-evidence loser");
    assert_eq!(coherent.0, "active");
    assert_eq!(coherent.1, 2);
    assert!(coherent.2);
    assert!(
        coherent.3.is_some(),
        "losing evidence must roll ciphertext destruction back"
    );

    database
        .close()
        .await
        .expect("close read-evidence SeaORM pool");
    pool.close().await;
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    clippy::type_complexity,
    reason = "the real PostgreSQL test keeps queued and post-dispatch login races visible"
)]
async fn destructive_intent_refuses_login_credential_replacement_until_terminal() {
    let Some((_container, url)) = start_postgres().await else {
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(12)
        .connect(&url)
        .await
        .expect("destructive-login PostgreSQL pool");
    MIGRATOR
        .run(&pool)
        .await
        .expect("destructive-login migrations");
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .expect("whole-second destructive-login time");
    let seeded = seed_authority(&pool, now, "intentlogin01").await;
    sqlx::query("UPDATE provider_configurations SET managed_profile_enabled=TRUE WHERE id=$1")
        .bind(seeded.provider_id)
        .execute(&pool)
        .await
        .expect("enable managed callback");
    let database = Database::connect(&url)
        .await
        .expect("destructive-login SeaORM pool");
    let authentication = PostgresAuthenticationRepository::new(database.clone());
    let protector = Arc::new(
        SoftwareRuntimeProtector::new(
            "destructive-login-deployment".to_owned(),
            1,
            RuntimeKeyMaterial::new([81; 32], [82; 32]),
            BTreeMap::new(),
        )
        .expect("destructive-login protector"),
    );
    let sessions = PostgresSessionAuthorityRepository::with_managed_protector(
        database.clone(),
        protector.clone(),
    );
    let managed = PostgresManagedConnectionRepository::new(database.clone());

    let identity_claim = claim_provider_login(&authentication, &seeded, 11, now).await;
    let identity = sessions
        .complete_authenticated_identity(completion_command(&seeded, &identity_claim, 11, now))
        .await
        .expect("establish ordinary identity");
    let install_claim = claim_provider_login(&authentication, &seeded, 31, now).await;
    let mut install = completion_command(&seeded, &install_claim, 31, now);
    attach_managed_credential(&mut install, b"adapter-owned-initial", 7);
    let installed = sessions
        .complete_authenticated_identity(install)
        .await
        .expect("install adapter-owned managed credential");
    assert_eq!(installed.user_id, identity.user_id);
    let connection: (Uuid, i64, i64, i64, i64, String, bool) = sqlx::query_as(
        "SELECT id,revision,generation,credential_generation,adapter_capability_revision,
                array_to_string(required_scopes,','),supports_revocation
           FROM managed_provider_connections WHERE project_id=$1 AND user_id=$2",
    )
    .bind(seeded.project_id)
    .bind(identity.user_id)
    .fetch_one(&pool)
    .await
    .expect("inspect adapter-owned callback snapshot");
    assert_eq!(connection.1, 1);
    assert_eq!(connection.2, 1);
    assert_eq!(connection.3, 1);
    assert_eq!(
        connection.4, 7,
        "repository must not stamp its former hard-coded revision"
    );
    assert_eq!(connection.5, "offline_access,openid,profile");
    assert!(connection.6);
    let fairness_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM managed_provider_claim_fairness
          WHERE project_id=$1 AND provider_configuration_id=$2 AND queue_kind='outbound'",
    )
    .bind(seeded.project_id)
    .bind(seeded.provider_id)
    .fetch_one(&pool)
    .await
    .expect("inspect install-side fairness materialization");
    assert_eq!(fairness_rows, 1);

    let reauthorizations = PostgresManagedReauthorizationRepository::new(database.clone());
    let denial_interaction = Uuid::new_v4();
    let mut denial_capability = managed_capability_snapshot();
    denial_capability.adapter_revision = 7;
    reauthorizations
        .create(PreparedManagedReauthorizationCreate {
            capability: denial_capability,
            command: CreateManagedReauthorization {
                project_id: seeded.project_id,
                user_id: identity.user_id,
                connection_id: connection.0,
                application_id: seeded.application_id,
                expected_connection_revision: 1,
                expected_connection_generation: 1,
                expected_credential_generation: 1,
                idempotency_key: format!("managed-denial-{denial_interaction}"),
                correlation_id: Uuid::new_v4(),
            },
            interaction_id: denial_interaction,
            interaction_digest: digest(121),
            request_digest: vec![122; 32],
            protected_create_result: ProtectedValue {
                ciphertext: vec![123; 48],
                key_version: 1,
            },
            expires_at: now + Duration::minutes(9),
            now: now + Duration::seconds(1),
        })
        .await
        .expect("create managed denial interaction");
    let denial_bound = reauthorizations
        .bind_browser(
            &digest(121),
            &digest(122),
            &digest(123),
            now + Duration::seconds(2),
        )
        .await
        .expect("bind managed denial browser");
    reauthorizations
        .start_provider(
            denial_interaction,
            &digest(121),
            &digest(122),
            &digest(123),
            denial_bound.revision,
            digest(124),
            digest(125),
            Some(protected(126)),
            true,
            now + Duration::seconds(3),
        )
        .await
        .expect("start managed denial provider");
    assert!(matches!(
        reauthorizations
            .deny_callback(
                &seeded.project_public_id,
                &seeded.provider_key,
                &digest(124),
                &digest(199),
                "auth.callback.denied_access",
                now + Duration::seconds(4),
            )
            .await,
        Err(ApplicationError::NotFound)
    ));
    assert!(matches!(
        reauthorizations
            .deny_callback(
                "prj_wrong-managed-owner",
                &seeded.provider_key,
                &digest(124),
                &digest(122),
                "auth.callback.denied_access",
                now + Duration::seconds(4),
            )
            .await,
        Err(ApplicationError::NotFound)
    ));
    let denied = reauthorizations
        .deny_callback(
            &seeded.project_public_id,
            &seeded.provider_key,
            &digest(124),
            &digest(122),
            "auth.callback.denied_access",
            now + Duration::seconds(4),
        )
        .await
        .expect("terminalize exact managed denial");
    assert_eq!(
        denied.status,
        ManagedReauthorizationStatus::ProviderExchangeFailed
    );
    let erased_managed: (
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
    ) = sqlx::query_as(
        "SELECT interaction_digest,browser_binding_digest,csrf_digest,upstream_state_digest,
                oidc_nonce_digest,provider_pkce_ciphertext
           FROM managed_provider_reauthorization_interactions WHERE id=$1",
    )
    .bind(denial_interaction)
    .fetch_one(&pool)
    .await
    .expect("inspect managed denial secret erasure");
    assert_eq!(
        erased_managed,
        (
            None,
            Some(vec![124; 32]),
            Some(vec![122; 32]),
            None,
            None,
            None,
        )
    );
    let erased_create: (Option<Vec<u8>>, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT request_digest,create_result_ciphertext
           FROM managed_reauthorization_create_results WHERE interaction_id=$1",
    )
    .bind(denial_interaction)
    .fetch_one(&pool)
    .await
    .expect("inspect managed denial create-result retention");
    assert_eq!(erased_create, (Some(vec![122; 32]), Some(vec![123; 48])));
    assert_reauthorization_material_scrubbed(&pool, denial_interaction).await;
    assert!(matches!(
        reauthorizations
            .deny_callback(
                &seeded.project_public_id,
                &seeded.provider_key,
                &digest(124),
                &digest(122),
                "auth.callback.denied_access",
                now + Duration::seconds(4),
            )
            .await,
        Ok(record) if record.status == ManagedReauthorizationStatus::ProviderExchangeFailed
    ));

    let queued_login_claim = claim_provider_login(&authentication, &seeded, 51, now).await;
    managed
        .request_revocation(
            seeded.project_id,
            identity.user_id,
            connection.0,
            1,
            1,
            Uuid::new_v4(),
            now + Duration::seconds(5),
        )
        .await
        .expect("queue exact destructive intent");
    let mut queued_login = completion_command(&seeded, &queued_login_claim, 51, now);
    attach_managed_credential(&mut queued_login, b"must-not-cross-queued-intent", 8);
    let queued_handoff = sessions
        .complete_authenticated_identity(queued_login)
        .await
        .expect("ordinary handoff survives queued destructive intent");
    assert_eq!(queued_handoff.user_id, identity.user_id);
    let after_queued: (i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT connection.revision,connection.generation,connection.credential_generation,
                connection.adapter_capability_revision,
                count(credential.*) FILTER (WHERE credential.ciphertext IS NOT NULL)
           FROM managed_provider_connections connection
           LEFT JOIN managed_provider_credentials credential
             ON credential.project_id=connection.project_id AND credential.connection_id=connection.id
          WHERE connection.id=$1
          GROUP BY connection.revision,connection.generation,connection.credential_generation,
                   connection.adapter_capability_revision",
    )
    .bind(connection.0)
    .fetch_one(&pool)
    .await
    .expect("inspect queued intent generation");
    assert_eq!(after_queued, (2, 1, 1, 7, 1));
    let revocation = managed
        .claim_next_revocation(
            Uuid::new_v4(),
            now + Duration::seconds(6),
            now + Duration::seconds(36),
        )
        .await
        .expect("queued claim loop remains healthy")
        .expect("queued intent remains authoritative");
    assert_eq!(revocation.guard.connection_generation, 1);
    assert!(
        managed
            .mark_revocation_dispatched(&revocation, now + Duration::seconds(7))
            .await
            .expect("cross destructive dispatch boundary")
    );

    let post_dispatch_claim = claim_provider_login(&authentication, &seeded, 71, now).await;
    let mut post_dispatch = completion_command(&seeded, &post_dispatch_claim, 71, now);
    attach_managed_credential(&mut post_dispatch, b"must-not-cross-dispatch", 9);
    let post_dispatch_handoff = sessions
        .complete_authenticated_identity(post_dispatch)
        .await
        .expect("ordinary handoff survives post-dispatch recovery window");
    assert_eq!(post_dispatch_handoff.user_id, identity.user_id);
    let post_dispatch_state: (i64, i64, i64, Option<Vec<u8>>, bool) = sqlx::query_as(
        "SELECT connection.generation,connection.credential_generation,
                connection.adapter_capability_revision,credential.ciphertext,
                connection.revocation_dispatch_started_at IS NOT NULL
           FROM managed_provider_connections connection
           JOIN managed_provider_credentials credential
             ON credential.project_id=connection.project_id AND credential.connection_id=connection.id
            AND credential.credential_generation=connection.credential_generation
          WHERE connection.id=$1",
    )
    .bind(connection.0)
    .fetch_one(&pool)
    .await
    .expect("inspect post-dispatch generation fence");
    assert_eq!(post_dispatch_state.0, 1);
    assert_eq!(post_dispatch_state.1, 1);
    assert_eq!(post_dispatch_state.2, 7);
    assert!(post_dispatch_state.3.is_none());
    assert!(post_dispatch_state.4);
    assert!(
        managed
            .claim_next_revocation(
                Uuid::new_v4(),
                now + Duration::seconds(40),
                now + Duration::seconds(70),
            )
            .await
            .expect("post-dispatch recovery loop continues")
            .is_none()
    );
    let terminal: (String, i64, i64, Option<OffsetDateTime>) = sqlx::query_as(
        "SELECT state,generation,credential_generation,revocation_requested_at
           FROM managed_provider_connections WHERE id=$1",
    )
    .bind(connection.0)
    .fetch_one(&pool)
    .await
    .expect("inspect terminal ambiguous generation");
    assert_eq!(terminal.0, "reauth_required");
    assert_eq!(terminal.1, 2);
    assert_eq!(terminal.2, 1);
    assert!(terminal.3.is_none());

    database
        .close()
        .await
        .expect("close destructive-login SeaORM pool");
    pool.close().await;
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the real PostgreSQL test proves both login/renewal generation orders and late-result fencing"
)]
async fn ordinary_login_truthfully_supersedes_old_generation_renewals() {
    let Some((_container, url)) = start_postgres().await else {
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(12)
        .connect(&url)
        .await
        .expect("login-renewal PostgreSQL pool");
    MIGRATOR.run(&pool).await.expect("login-renewal migrations");
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .expect("whole-second login-renewal time");
    let seeded = seed_authority(&pool, now, "loginrenew01").await;
    sqlx::query("UPDATE provider_configurations SET managed_profile_enabled=TRUE WHERE id=$1")
        .bind(seeded.provider_id)
        .execute(&pool)
        .await
        .expect("enable managed callback");
    let database = Database::connect(&url)
        .await
        .expect("login-renewal SeaORM pool");
    let authentication = PostgresAuthenticationRepository::new(database.clone());
    let protector = Arc::new(
        SoftwareRuntimeProtector::new(
            "login-renewal-deployment".to_owned(),
            1,
            RuntimeKeyMaterial::new([91; 32], [92; 32]),
            BTreeMap::new(),
        )
        .expect("login-renewal protector"),
    );
    let sessions = PostgresSessionAuthorityRepository::with_managed_protector(
        database.clone(),
        protector.clone(),
    );
    let managed = PostgresManagedConnectionRepository::new(database.clone());

    let identity_claim = claim_provider_login(&authentication, &seeded, 12, now).await;
    let identity = sessions
        .complete_authenticated_identity(completion_command(&seeded, &identity_claim, 12, now))
        .await
        .expect("establish login-renewal identity");
    let install_claim = claim_provider_login(&authentication, &seeded, 32, now).await;
    let mut install = completion_command(&seeded, &install_claim, 32, now);
    attach_managed_credential(&mut install, b"login-renewal-generation-one", 1);
    sessions
        .complete_authenticated_identity(install)
        .await
        .expect("install initial login-renewal credential");
    let connection_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM managed_provider_connections WHERE project_id=$1 AND user_id=$2",
    )
    .bind(seeded.project_id)
    .bind(identity.user_id)
    .fetch_one(&pool)
    .await
    .expect("load login-renewal connection");

    let race_now = now + Duration::minutes(1);

    // Order one: renewal commits first; a later login legitimately advances again without
    // rewriting the already truthful successor_committed operation.
    sqlx::query(
        "UPDATE managed_provider_connections SET next_renewal_at=$1 WHERE project_id=$2 AND id=$3",
    )
    .bind(race_now + Duration::seconds(1))
    .bind(seeded.project_id)
    .bind(connection_id)
    .execute(&pool)
    .await
    .expect("make first generation due");
    let committed_renewal = managed
        .prepare_next_renewal(
            Uuid::new_v4(),
            race_now + Duration::seconds(1),
            race_now + Duration::seconds(31),
            true,
        )
        .await
        .expect("prepare first renewal")
        .expect("first renewal due");
    assert!(
        managed
            .mark_renewal_submitted(&committed_renewal, race_now + Duration::seconds(2))
            .await
            .expect("submit first renewal")
    );
    let committed_context = ManagedCredentialContext {
        project_id: seeded.project_id,
        provider_configuration_id: seeded.provider_id,
        linked_identity_id: committed_renewal.claim.guard.linked_identity_id,
        connection_id,
        connection_generation: 2,
        credential_generation: 2,
    };
    let committed_secret = protector
        .protect_credential(&committed_context, b"renewal-generation-two")
        .expect("protect first renewal successor");
    let committed_guard = managed
        .commit_renewal_successor(
            &committed_renewal,
            committed_secret,
            race_now + Duration::seconds(3),
        )
        .await
        .expect("commit first renewal")
        .expect("first renewal wins");
    assert_eq!(
        (
            committed_guard.connection_revision,
            committed_guard.connection_generation,
            committed_guard.credential_generation,
        ),
        (2, 2, 2)
    );
    let after_renewal_login_claim =
        claim_provider_login(&authentication, &seeded, 52, race_now).await;
    let mut after_renewal_login =
        completion_command(&seeded, &after_renewal_login_claim, 52, race_now);
    attach_managed_credential(&mut after_renewal_login, b"login-generation-three", 1);
    sessions
        .complete_authenticated_identity(after_renewal_login)
        .await
        .expect("login advances after committed renewal");
    let committed_state: (String, String, i64, i64, i64) = sqlx::query_as(
        "SELECT operation.state,connection.state,connection.revision,connection.generation,
                connection.credential_generation
           FROM managed_provider_renewal_operations operation
           JOIN managed_provider_connections connection ON connection.id=operation.connection_id
          WHERE operation.id=$1",
    )
    .bind(committed_renewal.operation_id)
    .fetch_one(&pool)
    .await
    .expect("inspect renewal-first order");
    assert_eq!(
        committed_state,
        (
            "successor_committed".to_owned(),
            "active".to_owned(),
            3,
            3,
            3
        )
    );

    // Order two: the provider call is already submitted when login wins. The old operation is
    // durably terminal and a late success/failure cannot mutate or demote the fresh generation.
    sqlx::query(
        "UPDATE managed_provider_connections SET next_renewal_at=$1 WHERE project_id=$2 AND id=$3",
    )
    .bind(race_now + Duration::seconds(5))
    .bind(seeded.project_id)
    .bind(connection_id)
    .execute(&pool)
    .await
    .expect("make third generation due");
    let outstanding = managed
        .prepare_next_renewal(
            Uuid::new_v4(),
            race_now + Duration::seconds(5),
            race_now + Duration::seconds(35),
            true,
        )
        .await
        .expect("prepare outstanding renewal")
        .expect("third generation renewal due");
    assert!(
        managed
            .mark_renewal_submitted(&outstanding, race_now + Duration::seconds(6))
            .await
            .expect("submit outstanding renewal")
    );
    let winning_login_now = race_now + Duration::seconds(10);
    let winning_login_claim =
        claim_provider_login(&authentication, &seeded, 72, winning_login_now).await;
    let mut winning_login =
        completion_command(&seeded, &winning_login_claim, 72, winning_login_now);
    attach_managed_credential(&mut winning_login, b"login-generation-four", 1);
    sessions
        .complete_authenticated_identity(winning_login)
        .await
        .expect("login supersedes outstanding renewal");
    let superseded: (
        String,
        String,
        Option<OffsetDateTime>,
        Option<Uuid>,
        Option<OffsetDateTime>,
        Option<OffsetDateTime>,
    ) = sqlx::query_as(
        "SELECT state,safe_outcome,terminal_at,lease_owner,lease_expires_at,submitted_at
           FROM managed_provider_renewal_operations WHERE id=$1",
    )
    .bind(outstanding.operation_id)
    .fetch_one(&pool)
    .await
    .expect("inspect login-superseded operation");
    assert_eq!(superseded.0, "superseded_by_login");
    assert_eq!(superseded.1, "superseded_by_login");
    assert!(superseded.2.is_some());
    assert!(superseded.3.is_none());
    assert!(superseded.4.is_none());
    assert!(
        superseded.5.is_some(),
        "possibly dispatched boundary must remain truthful"
    );
    let reclaimable: bool = sqlx::query_scalar(
        "SELECT state IN ('prepared','submitted')
           FROM managed_provider_renewal_operations WHERE id=$1",
    )
    .bind(outstanding.operation_id)
    .fetch_one(&pool)
    .await
    .expect("inspect old recovery eligibility");
    assert!(!reclaimable);
    assert!(
        managed
            .commit_renewal_successor(
                &outstanding,
                ProtectedValue {
                    ciphertext: vec![93; 48],
                    key_version: 1,
                },
                race_now + Duration::seconds(15),
            )
            .await
            .expect("late provider success is fenced")
            .is_none()
    );
    assert!(
        !managed
            .terminalize_renewal(
                &outstanding,
                crate::application::RenewalOperationState::ReauthRequired,
                "late_old_generation_failure",
                race_now + Duration::seconds(16),
            )
            .await
            .expect("late provider failure is fenced")
    );
    let fresh: (String, i64, i64, i64, i64, i32, Vec<u8>) = sqlx::query_as(
        "SELECT connection.state,connection.revision,connection.generation,
                connection.credential_generation,
                count(history.*) FILTER (WHERE history.ciphertext IS NOT NULL),
                credential.key_version,credential.ciphertext
           FROM managed_provider_connections connection
           JOIN managed_provider_credentials credential
             ON credential.project_id=connection.project_id AND credential.connection_id=connection.id
            AND credential.credential_generation=connection.credential_generation
           LEFT JOIN managed_provider_credentials history
             ON history.project_id=connection.project_id AND history.connection_id=connection.id
          WHERE connection.id=$1
          GROUP BY connection.state,connection.revision,connection.generation,
                   connection.credential_generation,credential.key_version,credential.ciphertext",
    )
    .bind(connection_id)
    .fetch_one(&pool)
    .await
    .expect("inspect fresh login generation after late results");
    assert_eq!(
        (&fresh.0, fresh.1, fresh.2, fresh.3, fresh.4),
        (&"active".to_owned(), 4, 4, 4, 1)
    );
    let fresh_context = ManagedCredentialContext {
        project_id: seeded.project_id,
        provider_configuration_id: seeded.provider_id,
        linked_identity_id: outstanding.claim.guard.linked_identity_id,
        connection_id,
        connection_generation: 4,
        credential_generation: 4,
    };
    let fresh_plaintext = protector
        .unprotect_credential(
            &fresh_context,
            &ProtectedValue {
                key_version: fresh.5,
                ciphertext: fresh.6,
            },
        )
        .expect("decrypt fresh login credential after late renewal results");
    assert_eq!(fresh_plaintext.as_slice(), b"login-generation-four");

    // A merely prepared operation is terminalized by the same bounded generation update and
    // cannot cross the dispatch boundary after the login has advanced authority.
    sqlx::query(
        "UPDATE managed_provider_connections SET next_renewal_at=$1 WHERE project_id=$2 AND id=$3",
    )
    .bind(race_now + Duration::seconds(17))
    .bind(seeded.project_id)
    .bind(connection_id)
    .execute(&pool)
    .await
    .expect("make fourth generation due");
    let prepared_only = managed
        .prepare_next_renewal(
            Uuid::new_v4(),
            race_now + Duration::seconds(17),
            race_now + Duration::seconds(47),
            true,
        )
        .await
        .expect("prepare old-generation operation")
        .expect("fourth generation renewal due");
    let prepared_login_now = race_now + Duration::seconds(20);
    let prepared_login_claim =
        claim_provider_login(&authentication, &seeded, 92, prepared_login_now).await;
    let mut prepared_login =
        completion_command(&seeded, &prepared_login_claim, 92, prepared_login_now);
    attach_managed_credential(&mut prepared_login, b"login-generation-five", 1);
    sessions
        .complete_authenticated_identity(prepared_login)
        .await
        .expect("login supersedes prepared renewal");
    let prepared_terminal: (
        String,
        String,
        Option<OffsetDateTime>,
        Option<OffsetDateTime>,
    ) = sqlx::query_as(
        "SELECT state,safe_outcome,terminal_at,submitted_at
               FROM managed_provider_renewal_operations WHERE id=$1",
    )
    .bind(prepared_only.operation_id)
    .fetch_one(&pool)
    .await
    .expect("inspect prepared operation terminalization");
    assert_eq!(prepared_terminal.0, "superseded_by_login");
    assert_eq!(prepared_terminal.1, "superseded_by_login");
    assert!(prepared_terminal.2.is_some());
    assert!(prepared_terminal.3.is_none());
    assert!(
        !managed
            .mark_renewal_submitted(&prepared_only, race_now + Duration::seconds(25))
            .await
            .expect("superseded prepared operation cannot dispatch")
    );
    let final_generation: (String, i64, i64) = sqlx::query_as(
        "SELECT state,generation,credential_generation
           FROM managed_provider_connections WHERE id=$1",
    )
    .bind(connection_id)
    .fetch_one(&pool)
    .await
    .expect("inspect login generation after prepared supersession");
    assert_eq!(final_generation, ("active".to_owned(), 5, 5));

    database
        .close()
        .await
        .expect("close login-renewal SeaORM pool");
    pool.close().await;
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    clippy::type_complexity,
    reason = "the real PostgreSQL matrix keeps code/denial and generation/authority stale races explicit"
)]
async fn stale_managed_callbacks_terminalize_without_touching_current_generation() {
    let Some((_container, url)) = start_postgres().await else {
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(12)
        .connect(&url)
        .await
        .expect("stale-callback PostgreSQL pool");
    MIGRATOR
        .run(&pool)
        .await
        .expect("stale-callback migrations");
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .expect("whole-second stale-callback time");
    let seeded = seed_authority(&pool, now, "stalecallback01").await;
    sqlx::query("UPDATE provider_configurations SET managed_profile_enabled=TRUE WHERE id=$1")
        .bind(seeded.provider_id)
        .execute(&pool)
        .await
        .expect("enable stale-callback managed profile");
    let database = Database::connect(&url)
        .await
        .expect("stale-callback SeaORM pool");
    let authentication = PostgresAuthenticationRepository::new(database.clone());
    let protector = Arc::new(
        SoftwareRuntimeProtector::new(
            "stale-callback-deployment".to_owned(),
            1,
            RuntimeKeyMaterial::new([101; 32], [102; 32]),
            BTreeMap::new(),
        )
        .expect("stale-callback protector"),
    );
    let sessions =
        PostgresSessionAuthorityRepository::with_managed_protector(database.clone(), protector);
    let reauthorizations = PostgresManagedReauthorizationRepository::new(database.clone());

    let identity_claim = claim_provider_login(&authentication, &seeded, 13, now).await;
    let identity = sessions
        .complete_authenticated_identity(completion_command(&seeded, &identity_claim, 13, now))
        .await
        .expect("establish stale-callback identity");
    let install_claim = claim_provider_login(&authentication, &seeded, 33, now).await;
    let mut install = completion_command(&seeded, &install_claim, 33, now);
    attach_managed_credential(&mut install, b"stale-callback-generation-one", 1);
    sessions
        .complete_authenticated_identity(install)
        .await
        .expect("install stale-callback managed credential");
    let connection_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM managed_provider_connections WHERE project_id=$1 AND user_id=$2",
    )
    .bind(seeded.project_id)
    .bind(identity.user_id)
    .fetch_one(&pool)
    .await
    .expect("load stale-callback connection");

    // Both callback payload kinds freeze generation one before an ordinary login installs
    // generation two. Their exact state/browser owner remains valid, but connection authority is
    // stale and must terminalize without a provider exchange or generation mutation.
    let code_after_login = Uuid::new_v4();
    let denial_after_login = Uuid::new_v4();
    let callback_time = now + Duration::minutes(1);
    let (code_state, code_browser) = start_managed_callback_fixture(
        &reauthorizations,
        &seeded,
        identity.user_id,
        connection_id,
        1,
        1,
        1,
        code_after_login,
        181,
        callback_time,
    )
    .await;
    let (denial_state, denial_browser) = start_managed_callback_fixture(
        &reauthorizations,
        &seeded,
        identity.user_id,
        connection_id,
        1,
        1,
        1,
        denial_after_login,
        191,
        callback_time,
    )
    .await;
    let advancing_claim = claim_provider_login(&authentication, &seeded, 53, callback_time).await;
    let mut advancing_login = completion_command(&seeded, &advancing_claim, 53, callback_time);
    attach_managed_credential(&mut advancing_login, b"stale-callback-generation-two", 1);
    sessions
        .complete_authenticated_identity(advancing_login)
        .await
        .expect("ordinary login advances managed generation");
    let current_after_login: (String, i64, i64, i64, i32, Vec<u8>, i64) = sqlx::query_as(
        "SELECT connection.state,connection.revision,connection.generation,
                connection.credential_generation,credential.key_version,credential.ciphertext,
                count(history.*) FILTER (WHERE history.ciphertext IS NOT NULL)
           FROM managed_provider_connections connection
           JOIN managed_provider_credentials credential
             ON credential.project_id=connection.project_id AND credential.connection_id=connection.id
            AND credential.credential_generation=connection.credential_generation
           LEFT JOIN managed_provider_credentials history
             ON history.project_id=connection.project_id AND history.connection_id=connection.id
          WHERE connection.id=$1
          GROUP BY connection.state,connection.revision,connection.generation,
                   connection.credential_generation,credential.key_version,credential.ciphertext",
    )
    .bind(connection_id)
    .fetch_one(&pool)
    .await
    .expect("snapshot login-advanced connection");
    let stale_code = reauthorizations
        .claim_callback(
            code_after_login,
            &seeded.project_public_id,
            &seeded.provider_key,
            &code_state,
            &code_browser,
            callback_time + Duration::seconds(6),
        )
        .await
        .expect("terminalize generation-stale code callback");
    assert!(matches!(
        stale_code,
        ClaimManagedReauthorization::TerminalizedStaleAuthority
    ));
    let stale_code_status: String = sqlx::query_scalar(
        "SELECT status FROM managed_provider_reauthorization_interactions WHERE id=$1",
    )
    .bind(code_after_login)
    .fetch_one(&pool)
    .await
    .expect("inspect generation-stale code terminal state");
    assert_eq!(stale_code_status, "provider_exchange_failed");
    let stale_denial = reauthorizations
        .deny_callback(
            &seeded.project_public_id,
            &seeded.provider_key,
            &denial_state,
            &denial_browser,
            "auth.callback.denied_access",
            callback_time + Duration::seconds(7),
        )
        .await
        .expect("terminalize generation-stale denial callback");
    assert_eq!(
        stale_denial.status,
        ManagedReauthorizationStatus::ProviderExchangeFailed
    );
    for interaction_id in [code_after_login, denial_after_login] {
        assert_reauthorization_material_scrubbed(&pool, interaction_id).await;
    }
    assert!(matches!(
        reauthorizations
            .claim_callback(
                code_after_login,
                &seeded.project_public_id,
                &seeded.provider_key,
                &code_state,
                &code_browser,
                callback_time + Duration::seconds(8),
            )
            .await,
        Ok(ClaimManagedReauthorization::Duplicate(record))
            if record.status == ManagedReauthorizationStatus::ProviderExchangeFailed
    ));
    assert!(matches!(
        reauthorizations
            .deny_callback(
                &seeded.project_public_id,
                &seeded.provider_key,
                &denial_state,
                &denial_browser,
                "auth.callback.denied_access",
                callback_time + Duration::seconds(8),
            )
            .await,
        Ok(record) if record.status == ManagedReauthorizationStatus::ProviderExchangeFailed
    ));
    let after_generation_stale: (String, i64, i64, i64, i32, Vec<u8>, i64) =
        sqlx::query_as(
            "SELECT connection.state,connection.revision,connection.generation,
                    connection.credential_generation,credential.key_version,credential.ciphertext,
                    count(history.*) FILTER (WHERE history.ciphertext IS NOT NULL)
               FROM managed_provider_connections connection
               JOIN managed_provider_credentials credential
                 ON credential.project_id=connection.project_id AND credential.connection_id=connection.id
                AND credential.credential_generation=connection.credential_generation
               LEFT JOIN managed_provider_credentials history
                 ON history.project_id=connection.project_id AND history.connection_id=connection.id
              WHERE connection.id=$1
              GROUP BY connection.state,connection.revision,connection.generation,
                       connection.credential_generation,credential.key_version,credential.ciphertext",
        )
        .bind(connection_id)
        .fetch_one(&pool)
        .await
        .expect("inspect connection after generation-stale callbacks");
    assert_eq!(after_generation_stale, current_after_login);

    // Repeat both payload kinds with a still-current connection but a drifted provider revision.
    let code_after_authority_drift = Uuid::new_v4();
    let denial_after_authority_drift = Uuid::new_v4();
    let authority_time = callback_time + Duration::minutes(1);
    let (drift_code_state, drift_code_browser) = start_managed_callback_fixture(
        &reauthorizations,
        &seeded,
        identity.user_id,
        connection_id,
        current_after_login.1,
        current_after_login.2,
        current_after_login.3,
        code_after_authority_drift,
        211,
        authority_time,
    )
    .await;
    let (drift_denial_state, drift_denial_browser) = start_managed_callback_fixture(
        &reauthorizations,
        &seeded,
        identity.user_id,
        connection_id,
        current_after_login.1,
        current_after_login.2,
        current_after_login.3,
        denial_after_authority_drift,
        221,
        authority_time,
    )
    .await;
    sqlx::query("UPDATE provider_configurations SET revision=revision+1 WHERE id=$1")
        .bind(seeded.provider_id)
        .execute(&pool)
        .await
        .expect("drift frozen provider revision");
    let drifted_code = reauthorizations
        .claim_callback(
            code_after_authority_drift,
            &seeded.project_public_id,
            &seeded.provider_key,
            &drift_code_state,
            &drift_code_browser,
            authority_time + Duration::seconds(3),
        )
        .await
        .expect("terminalize authority-stale code callback");
    assert!(matches!(
        drifted_code,
        ClaimManagedReauthorization::TerminalizedStaleAuthority
    ));
    let drifted_denial = reauthorizations
        .deny_callback(
            &seeded.project_public_id,
            &seeded.provider_key,
            &drift_denial_state,
            &drift_denial_browser,
            "auth.callback.denied_access",
            authority_time + Duration::seconds(4),
        )
        .await
        .expect("terminalize authority-stale denial callback");
    assert_eq!(
        drifted_denial.status,
        ManagedReauthorizationStatus::ProviderExchangeFailed
    );
    for interaction_id in [code_after_authority_drift, denial_after_authority_drift] {
        assert_reauthorization_material_scrubbed(&pool, interaction_id).await;
    }
    assert!(matches!(
        reauthorizations
            .claim_callback(
                code_after_authority_drift,
                &seeded.project_public_id,
                &seeded.provider_key,
                &drift_code_state,
                &drift_code_browser,
                authority_time + Duration::seconds(5),
            )
            .await,
        Ok(ClaimManagedReauthorization::Duplicate(record))
            if record.status == ManagedReauthorizationStatus::ProviderExchangeFailed
    ));
    assert!(matches!(
        reauthorizations
            .deny_callback(
                &seeded.project_public_id,
                &seeded.provider_key,
                &drift_denial_state,
                &drift_denial_browser,
                "auth.callback.denied_access",
                authority_time + Duration::seconds(5),
            )
            .await,
        Ok(record) if record.status == ManagedReauthorizationStatus::ProviderExchangeFailed
    ));
    let after_authority_stale: (String, i64, i64, i64, i32, Vec<u8>, i64) =
        sqlx::query_as(
            "SELECT connection.state,connection.revision,connection.generation,
                    connection.credential_generation,credential.key_version,credential.ciphertext,
                    count(history.*) FILTER (WHERE history.ciphertext IS NOT NULL)
               FROM managed_provider_connections connection
               JOIN managed_provider_credentials credential
                 ON credential.project_id=connection.project_id AND credential.connection_id=connection.id
                AND credential.credential_generation=connection.credential_generation
               LEFT JOIN managed_provider_credentials history
                 ON history.project_id=connection.project_id AND history.connection_id=connection.id
              WHERE connection.id=$1
              GROUP BY connection.state,connection.revision,connection.generation,
                       connection.credential_generation,credential.key_version,credential.ciphertext",
        )
        .bind(connection_id)
        .fetch_one(&pool)
        .await
        .expect("inspect connection after authority-stale callbacks");
    assert_eq!(after_authority_stale, current_after_login);
    let stale_audits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events
          WHERE target_id IN ($1,$2,$3,$4)
            AND action IN ('managed_reauthorization.code_authority_stale',
                           'managed_reauthorization.denial_authority_stale')",
    )
    .bind(code_after_login)
    .bind(denial_after_login)
    .bind(code_after_authority_drift)
    .bind(denial_after_authority_drift)
    .fetch_one(&pool)
    .await
    .expect("inspect safe stale-authority audits");
    assert_eq!(stale_audits, 4);

    database
        .close()
        .await
        .expect("close stale-callback SeaORM pool");
    pool.close().await;
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the integration test proves identity convergence and bounded projection fan-out"
)]
async fn identity_creation_is_serialized_and_project_scoped_in_postgres() {
    let Some((_container, url)) = start_postgres().await else {
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(12)
        .connect(&url)
        .await
        .expect("test PostgreSQL pool");
    MIGRATOR.run(&pool).await.expect("session migrations");
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .expect("whole-second test time");
    let first_project = seed_authority(&pool, now, "identity01").await;
    let second_project = seed_authority(&pool, now, "identity02").await;

    let database = Database::connect(&url).await.expect("SeaORM test pool");
    let authentication = PostgresAuthenticationRepository::new(database.clone());
    let projection_materializer = Arc::new(PostgresIdentityProjectionMaterializer::new(
        Arc::new(UnavailableDurableEmailAddressReader),
        Arc::new(
            SoftwareProjectionVerifiedEmailProtector::new(
                "provider-profile-event-test".to_owned(),
                1,
                [102; 32],
                BTreeMap::new(),
            )
            .expect("provider profile projection protector"),
        ),
    ));
    let sessions = PostgresSessionAuthorityRepository::new(database.clone())
        .with_projection_materializer(projection_materializer);
    let first_claim = claim_provider_login(&authentication, &first_project, 21, now).await;
    let competing_claim = claim_provider_login(&authentication, &first_project, 41, now).await;
    let other_project_claim = claim_provider_login(&authentication, &second_project, 61, now).await;

    let (first, competing) = tokio::join!(
        sessions.complete_authenticated_identity(completion_command(
            &first_project,
            &first_claim,
            21,
            now,
        )),
        sessions.complete_authenticated_identity(completion_command(
            &first_project,
            &competing_claim,
            41,
            now,
        )),
    );
    let first = first.expect("first identity completion");
    let competing = competing.expect("competing identity completion");
    assert_eq!(first.user_id, competing.user_id);

    let other_project = sessions
        .complete_authenticated_identity(completion_command(
            &second_project,
            &other_project_claim,
            61,
            now,
        ))
        .await
        .expect("other Project identity completion");
    assert_ne!(first.user_id, other_project.user_id);

    let first_project_identity_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM linked_identities
         WHERE project_id = $1 AND issuer = 'https://issuer.example'
           AND subject = 'shared-subject'",
    )
    .bind(first_project.project_id)
    .fetch_one(&pool)
    .await
    .expect("count first Project identities");
    let second_project_identity_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM linked_identities
         WHERE project_id = $1 AND issuer = 'https://issuer.example'
           AND subject = 'shared-subject'",
    )
    .bind(second_project.project_id)
    .fetch_one(&pool)
    .await
    .expect("count second Project identities");
    assert_eq!(first_project_identity_count, 1);
    assert_eq!(second_project_identity_count, 1);
    let first_project_user_revision: i64 = sqlx::query_scalar(
        "SELECT user_revision FROM project_users WHERE project_id = $1 AND id = $2",
    )
    .bind(first_project.project_id)
    .bind(first.user_id)
    .fetch_one(&pool)
    .await
    .expect("load converged user revision");
    assert_eq!(first_project_user_revision, 1);

    let secondary_provider_id = Uuid::new_v4();
    let secondary_callback_url = format!(
        "https://runtime.example/projects/{}/auth/callback/oidc-secondary",
        first_project.project_public_id
    );
    sqlx::query(
        "INSERT INTO provider_configurations
            (id, project_id, provider_key, kind, display_name, issuer, client_id,
             callback_url, secret_ref, status, revision)
         VALUES ($1, $2, 'oidc-secondary', 'oidc', 'OIDC',
             'https://issuer.example', 'client-secondary', $3,
             'secret/ref/oidc-secondary', 'active', 1)",
    )
    .bind(secondary_provider_id)
    .bind(first_project.project_id)
    .bind(&secondary_callback_url)
    .execute(&pool)
    .await
    .expect("insert same-issuer provider registration");
    sqlx::query(
        "INSERT INTO application_provider_assignments
            (project_id, application_id, provider_id, status, security_revision)
         VALUES ($1, $2, $3, 'active', 1)",
    )
    .bind(first_project.project_id)
    .bind(first_project.application_id)
    .bind(secondary_provider_id)
    .execute(&pool)
    .await
    .expect("assign same-issuer provider registration");
    sqlx::query(
        "UPDATE application_provider_assignments
         SET status = 'disabled', security_revision = security_revision + 1
         WHERE project_id = $1 AND application_id = $2 AND provider_id = $3",
    )
    .bind(first_project.project_id)
    .bind(first_project.application_id)
    .bind(first_project.provider_id)
    .execute(&pool)
    .await
    .expect("disable the creation registration assignment");
    let secondary_registration = SeededAuthority {
        provider_id: secondary_provider_id,
        provider_key: "oidc-secondary".to_owned(),
        callback_url: secondary_callback_url,
        ..first_project.clone()
    };

    let binding_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO application_user_bindings
            (id, project_id, application_id, user_id, status, binding_revision)
         VALUES ($1, $2, $3, $4, 'active', 1)",
    )
    .bind(binding_id)
    .bind(first_project.project_id)
    .bind(first_project.application_id)
    .bind(first.user_id)
    .execute(&pool)
    .await
    .expect("insert existing Application binding");
    sqlx::query(
        "INSERT INTO application_user_projections
            (id, project_id, binding_id, application_id, user_id, schema_name,
             projection_revision, source_user_revision, project_policy_revision,
             application_policy_revision, canonical_digest, source_base_profile_digest, document)
         VALUES ($1, $2, $3, $4, $5, 'owlauth.user.v1', 1, 1, 1, 1, $6, $6, $7)",
    )
    .bind(Uuid::new_v4())
    .bind(first_project.project_id)
    .bind(binding_id)
    .bind(first_project.application_id)
    .bind(first.user_id)
    .bind(vec![1_u8; 32])
    .bind(serde_json::json!({
        "user_id": "usr_stale_projection",
        "user_revision": 1,
        "projection_schema": "owlauth.user.v1",
        "projection_revision": 1,
        "display_name": "Stale",
        "picture_url": null,
        "locale": null,
        "verified_email": null,
        "status": "active",
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z"
    }))
    .execute(&pool)
    .await
    .expect("insert existing projection");
    let profile_change_claim =
        claim_provider_login(&authentication, &secondary_registration, 81, now).await;
    let mut profile_change =
        completion_command(&secondary_registration, &profile_change_claim, 81, now);
    let AuthenticatedIdentityEvidence::Provider(profile) = &mut profile_change.evidence;
    profile.display_name =
        Some(ProfileDisplayName::parse("Grace".to_owned()).expect("changed display name"));
    sessions
        .complete_authenticated_identity(profile_change)
        .await
        .expect("complete primary-profile change");
    let (
        user_revision,
        projection_revision,
        source_user_revision,
        project_policy_revision,
        application_policy_revision,
        document,
        canonical_digest,
    ): (i64, i64, i64, i64, i64, serde_json::Value, Vec<u8>) = sqlx::query_as(
        "SELECT users.user_revision, projections.projection_revision,
                    projections.source_user_revision, projections.project_policy_revision,
                    projections.application_policy_revision, projections.document,
                    projections.canonical_digest
             FROM project_users AS users
             JOIN application_user_projections AS projections
               ON projections.project_id = users.project_id AND projections.user_id = users.id
             WHERE users.project_id = $1 AND users.id = $2",
    )
    .bind(first_project.project_id)
    .bind(first.user_id)
    .fetch_one(&pool)
    .await
    .expect("load fanned-out projection");
    assert_eq!(user_revision, 2);
    assert_eq!(projection_revision, 2);
    assert_eq!(source_user_revision, 2);
    assert_eq!(project_policy_revision, 1);
    assert_eq!(application_policy_revision, 1);
    assert_eq!(document["display_name"], "Grace");
    assert_ne!(canonical_digest, vec![1_u8; 32]);
    let profile_event_types: Vec<String> = sqlx::query_scalar(
        "SELECT event_type FROM application_user_events WHERE binding_id=$1
         ORDER BY projection_revision",
    )
    .bind(binding_id)
    .fetch_all(&pool)
    .await
    .expect("read provider profile immutable event");
    assert_eq!(profile_event_types, vec!["user.projection.updated"]);
    let creation_provenance: Uuid = sqlx::query_scalar(
        "SELECT created_via_provider_configuration_id
         FROM linked_identities
         WHERE project_id = $1 AND issuer = 'https://issuer.example'
           AND subject = 'shared-subject'",
    )
    .bind(first_project.project_id)
    .fetch_one(&pool)
    .await
    .expect("load immutable identity creation provenance");
    assert_eq!(creation_provenance, first_project.provider_id);
    sqlx::query(
        "UPDATE application_user_projections
         SET document = jsonb_set(document, '{display_name}', to_jsonb('stale'::text)),
             canonical_digest = $2
         WHERE binding_id = $1",
    )
    .bind(binding_id)
    .bind(vec![2_u8; 32])
    .execute(&pool)
    .await
    .expect("corrupt only the stored projection material");
    let digest_only_repair = sessions
        .prepare_handoff_exchange(PrepareHandoffExchange {
            project_id: first_project.project_id,
            application_id: first_project.application_id,
            handoff_ticket: digest(89),
            application_pkce_challenge: "A".repeat(43),
            now: now + Duration::seconds(5),
        })
        .await
        .expect("prepare digest-only stale projection repair");
    assert_eq!(digest_only_repair.user_revision, 2);
    assert_eq!(
        digest_only_repair.projection_revision, 2,
        "storage-only repair must not invent an Application-visible revision"
    );
    assert_eq!(
        digest_only_repair.projection_document["display_name"],
        "Grace"
    );

    let before_digest_repair: (i64, i64, i64, OffsetDateTime, OffsetDateTime) = sqlx::query_as(
        "SELECT identities.identity_revision, users.user_revision,
                    projections.projection_revision, users.updated_at, identities.updated_at
             FROM linked_identities AS identities
             JOIN project_users AS users
               ON users.project_id = identities.project_id AND users.id = identities.user_id
             JOIN application_user_projections AS projections
               ON projections.project_id = users.project_id AND projections.user_id = users.id
             WHERE identities.project_id = $1 AND identities.subject = 'shared-subject'",
    )
    .bind(first_project.project_id)
    .fetch_one(&pool)
    .await
    .expect("load revisions before digest-only repair");
    sqlx::query(
        "ALTER TABLE linked_identities
         DISABLE TRIGGER linked_identities_source_profile_digest_fill",
    )
    .execute(&pool)
    .await
    .expect("disable compatibility trigger for legacy-null fixture");
    sqlx::query(
        "UPDATE linked_identities SET source_profile_digest = NULL
         WHERE project_id = $1 AND subject = 'shared-subject'",
    )
    .bind(first_project.project_id)
    .execute(&pool)
    .await
    .expect("simulate legacy provider source without digest");
    sqlx::query(
        "ALTER TABLE linked_identities
         ENABLE TRIGGER linked_identities_source_profile_digest_fill",
    )
    .execute(&pool)
    .await
    .expect("restore provider-source compatibility trigger");
    sqlx::query("UPDATE project_users SET base_profile_digest = $2 WHERE id = $1")
        .bind(first.user_id)
        .bind(vec![6_u8; 32])
        .execute(&pool)
        .await
        .expect("corrupt only user base digest");
    let repair_claim =
        claim_provider_login(&authentication, &secondary_registration, 91, now).await;
    let mut repair_command = completion_command(&secondary_registration, &repair_claim, 91, now);
    let AuthenticatedIdentityEvidence::Provider(repair_profile) = &mut repair_command.evidence;
    repair_profile.display_name =
        Some(ProfileDisplayName::parse("Grace".to_owned()).expect("same display name"));
    sessions
        .complete_authenticated_identity(repair_command)
        .await
        .expect("provider completion repairs digest-only corruption");
    let after_digest_repair: (i64, i64, i64, OffsetDateTime, OffsetDateTime) = sqlx::query_as(
        "SELECT identities.identity_revision, users.user_revision,
                    projections.projection_revision, users.updated_at, identities.updated_at
             FROM linked_identities AS identities
             JOIN project_users AS users
               ON users.project_id = identities.project_id AND users.id = identities.user_id
             JOIN application_user_projections AS projections
               ON projections.project_id = users.project_id AND projections.user_id = users.id
             WHERE identities.project_id = $1 AND identities.subject = 'shared-subject'",
    )
    .bind(first_project.project_id)
    .fetch_one(&pool)
    .await
    .expect("load revisions after digest-only repair");
    assert_eq!(after_digest_repair, before_digest_repair);
    let event_count_after_digest_repair: i64 =
        sqlx::query_scalar("SELECT count(*) FROM application_user_events WHERE binding_id=$1")
            .bind(binding_id)
            .fetch_one(&pool)
            .await
            .expect("count events after provider digest-only no-op");
    assert_eq!(event_count_after_digest_repair, 1);

    let orphan_count: i64 = sqlx::query_scalar(
        "SELECT count(*)
         FROM project_users AS users
         LEFT JOIN linked_identities AS identities
           ON identities.project_id = users.project_id AND identities.user_id = users.id
         WHERE users.project_id = $1 AND identities.id IS NULL",
    )
    .bind(first_project.project_id)
    .fetch_one(&pool)
    .await
    .expect("count orphan users");
    assert_eq!(orphan_count, 0);

    database.close().await.expect("close SeaORM pool");
    pool.close().await;
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the integration test keeps terminal failure and contended recovery together"
)]
async fn claimed_provider_failures_are_terminal_and_abandoned_claims_are_recovered() {
    let Some((_container, url)) = start_postgres().await else {
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .expect("test PostgreSQL pool");
    MIGRATOR.run(&pool).await.expect("session migrations");
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .expect("whole-second test time");
    let seeded = seed_authority(&pool, now, "recovery01").await;
    let database = Database::connect(&url).await.expect("SeaORM test pool");
    let authentication = PostgresAuthenticationRepository::new(database.clone());
    let sessions = PostgresSessionAuthorityRepository::new(database.clone());

    let claimed = claim_provider_login(&authentication, &seeded, 101, now).await;
    let mut invalid = completion_command(&seeded, &claimed, 101, now);
    invalid.browser_credential.key_version = 0;
    let error = sessions
        .complete_authenticated_identity(invalid)
        .await
        .expect_err("invalid post-claim credential must fail terminally");
    assert_eq!(error, crate::application::ApplicationError::InvalidInput);
    let (status, terminal_at): (String, Option<OffsetDateTime>) =
        sqlx::query_as("SELECT status, terminal_at FROM login_transactions WHERE id = $1")
            .bind(claimed.transaction.id)
            .fetch_one(&pool)
            .await
            .expect("load terminal provider failure");
    assert_eq!(status, "provider_exchange_failed");
    assert_eq!(terminal_at, Some(now + Duration::seconds(4)));

    let revision_claimed = claim_provider_login(&authentication, &seeded, 111, now).await;
    let mut stale_revision = completion_command(&seeded, &revision_claimed, 111, now);
    stale_revision.expected_transaction_revision += 1;
    let revision_error = sessions
        .complete_authenticated_identity(stale_revision)
        .await
        .expect_err("prepared revision mismatch must fail terminally");
    assert_eq!(
        revision_error,
        crate::application::ApplicationError::RevisionConflict
    );
    let revision_status: String =
        sqlx::query_scalar("SELECT status FROM login_transactions WHERE id = $1")
            .bind(revision_claimed.transaction.id)
            .fetch_one(&pool)
            .await
            .expect("load revision-conflict terminal failure");
    assert_eq!(revision_status, "provider_exchange_failed");

    let locked_abandoned = claim_provider_login(&authentication, &seeded, 121, now).await;
    let recoverable = claim_provider_login(&authentication, &seeded, 141, now).await;
    let mut blocker = pool.begin().await.expect("begin blocking transaction");
    sqlx::query("SELECT id FROM login_transactions WHERE id = $1 FOR UPDATE")
        .bind(locked_abandoned.transaction.id)
        .fetch_one(&mut *blocker)
        .await
        .expect("lock one abandoned exchange");
    let recovered = sessions
        .recover_abandoned_provider_exchanges(RecoverProviderExchanges {
            abandoned_before: now + Duration::seconds(4),
            limit: 10,
            now: now + Duration::seconds(10),
        })
        .await
        .expect("recover unlocked abandoned provider exchange");
    assert_eq!(recovered, 1);
    let recovered_status: String =
        sqlx::query_scalar("SELECT status FROM login_transactions WHERE id = $1")
            .bind(recoverable.transaction.id)
            .fetch_one(&pool)
            .await
            .expect("load recovered provider exchange");
    assert_eq!(recovered_status, "provider_exchange_failed");
    let locked_status: String =
        sqlx::query_scalar("SELECT status FROM login_transactions WHERE id = $1")
            .bind(locked_abandoned.transaction.id)
            .fetch_one(&pool)
            .await
            .expect("load skipped locked exchange");
    assert_eq!(locked_status, "provider_exchange_in_progress");
    blocker
        .rollback()
        .await
        .expect("release abandoned row lock");
    let recovered_after_unlock = sessions
        .recover_abandoned_provider_exchanges(RecoverProviderExchanges {
            abandoned_before: now + Duration::seconds(4),
            limit: 10,
            now: now + Duration::seconds(11),
        })
        .await
        .expect("recover previously locked provider exchange");
    assert_eq!(recovered_after_unlock, 1);
    let recovery_audit_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events
         WHERE project_id = $1 AND action = 'auth.provider_exchange.recovered'
           AND safe_context = '{}'::jsonb",
    )
    .bind(seeded.project_id)
    .fetch_one(&pool)
    .await
    .expect("count recovery audit");
    assert_eq!(recovery_audit_count, 2);

    database.close().await.expect("close SeaORM pool");
    pool.close().await;
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the process-loss proof keeps each durable boundary assertion visible"
)]
async fn revocation_process_loss_after_dispatch_boundary_never_replays_ciphertext() {
    let Some((_container, url)) = start_postgres().await else {
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .expect("revocation crash PostgreSQL pool");
    MIGRATOR
        .run(&pool)
        .await
        .expect("revocation crash migrations");
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .expect("whole-second revocation crash time");
    let seeded = seed_authority(&pool, now, "revocationcrash").await;
    sqlx::query("UPDATE provider_configurations SET managed_profile_enabled=TRUE WHERE id=$1")
        .bind(seeded.provider_id)
        .execute(&pool)
        .await
        .expect("enable crash-test managed provider");
    let protector = SoftwareRuntimeProtector::new(
        "revocation-crash-deployment".to_owned(),
        1,
        RuntimeKeyMaterial::new([51; 32], [52; 32]),
        BTreeMap::new(),
    )
    .expect("revocation crash protector");
    let fixture = insert_managed_fixture(&pool, &seeded, &protector, now, 90).await;
    let database = Database::connect(&url)
        .await
        .expect("revocation crash SeaORM pool");
    let repository = PostgresManagedConnectionRepository::new(database.clone());
    repository
        .request_revocation(
            seeded.project_id,
            fixture.user_id,
            fixture.connection_id,
            1,
            1,
            Uuid::new_v4(),
            now,
        )
        .await
        .expect("queue crash-test revocation");
    let claim = repository
        .claim_next_revocation(Uuid::new_v4(), now, now + Duration::seconds(2))
        .await
        .expect("claim crash-test revocation")
        .expect("revocation due");
    let memory_only = protector
        .unprotect_credential(
            &crate::application::ManagedCredentialContext {
                project_id: claim.guard.project_id,
                provider_configuration_id: claim.guard.provider_configuration_id,
                linked_identity_id: claim.guard.linked_identity_id,
                connection_id: claim.guard.connection_id,
                connection_generation: claim.guard.connection_generation,
                credential_generation: claim.guard.credential_generation,
            },
            &claim.protected,
        )
        .expect("claim retains one in-memory dispatch copy");
    assert!(!memory_only.is_empty());
    assert!(
        repository
            .mark_revocation_dispatched(&claim, now + Duration::seconds(1))
            .await
            .expect("commit destructive dispatch boundary")
    );
    let ciphertext: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT ciphertext FROM managed_provider_credentials
          WHERE project_id=$1 AND connection_id=$2 AND credential_generation=1",
    )
    .bind(seeded.project_id)
    .bind(fixture.connection_id)
    .fetch_one(&pool)
    .await
    .expect("inspect destroyed crash-test ciphertext");
    assert!(ciphertext.is_none());
    // Simulate process loss by dropping the only plaintext without calling the provider result
    // finisher. While the original lease is live, no other worker can reclaim it.
    drop(memory_only);
    assert!(
        repository
            .claim_next_revocation(
                Uuid::new_v4(),
                now + Duration::seconds(1),
                now + Duration::seconds(3),
            )
            .await
            .expect("probe live destructive lease")
            .is_none()
    );
    // After lease expiry, recovery terminalizes the unknown remote result and still returns no
    // credential-bearing claim. The dead process is fenced from overwriting the terminal row.
    assert!(
        repository
            .claim_next_revocation(
                Uuid::new_v4(),
                now + Duration::seconds(3),
                now + Duration::seconds(5),
            )
            .await
            .expect("recover ambiguous dispatch")
            .is_none()
    );
    let terminal = repository
        .metadata_for_owner(seeded.project_id, fixture.user_id, fixture.connection_id)
        .await
        .expect("read crash-safe terminal state");
    assert_eq!(terminal.state, "reauth_required");
    assert_eq!(
        terminal.last_safe_outcome,
        "provider_revocation_result_unknown"
    );
    assert_eq!(
        repository
            .finish_revocation(
                &claim,
                ProviderRevocationResult::Confirmed,
                now + Duration::seconds(3),
            )
            .await,
        Err(ApplicationError::RevisionConflict)
    );
    database
        .close()
        .await
        .expect("close revocation crash SeaORM pool");
    pool.close().await;
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    clippy::type_complexity,
    reason = "the managed worker matrix keeps cross-queue durability and fencing evidence together"
)]
async fn managed_worker_queues_are_fair_durable_and_destructive_in_postgres() {
    let Some((_container, url)) = start_postgres().await else {
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(16)
        .connect(&url)
        .await
        .expect("managed matrix PostgreSQL pool");
    MIGRATOR
        .run(&pool)
        .await
        .expect("managed matrix migrations");
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .expect("whole-second managed matrix time");
    let first = seed_authority(&pool, now, "managedmatrix01").await;
    let second = seed_authority(&pool, now, "managedmatrix02").await;
    sqlx::query(
        "UPDATE provider_configurations SET managed_profile_enabled=TRUE
          WHERE id=$1 OR id=$2",
    )
    .bind(first.provider_id)
    .bind(second.provider_id)
    .execute(&pool)
    .await
    .expect("enable managed matrix providers");
    let protector = SoftwareRuntimeProtector::new(
        "managed-matrix-deployment".to_owned(),
        1,
        RuntimeKeyMaterial::new([11; 32], [12; 32]),
        BTreeMap::new(),
    )
    .expect("managed matrix protector");
    let database = Database::connect(&url)
        .await
        .expect("managed matrix SeaORM pool");
    let repository = PostgresManagedConnectionRepository::new(database.clone());

    // Read scheduling is round-robin across Project/provider groups even when the first group
    // retains an older backlog. Two simultaneous workers also claim distinct SKIP LOCKED rows.
    let read_a = insert_managed_fixture(&pool, &first, &protector, now, 1).await;
    let read_b = insert_managed_fixture(&pool, &first, &protector, now, 2).await;
    let read_c = insert_managed_fixture(&pool, &second, &protector, now, 3).await;
    let first_read = repository
        .claim_next_read(Uuid::new_v4(), now, now + Duration::seconds(30))
        .await
        .expect("claim first fair read")
        .expect("first fair read exists");
    assert!(
        repository
            .finish_read_failure(&first_read, "matrix_retry", now - Duration::seconds(1), now,)
            .await
            .expect("release first fair read")
    );
    let second_read = repository
        .claim_next_read(
            Uuid::new_v4(),
            now + Duration::seconds(1),
            now + Duration::seconds(31),
        )
        .await
        .expect("claim second fair read")
        .expect("second fair read exists");
    assert_ne!(
        first_read.guard.project_id, second_read.guard.project_id,
        "an unserved Project/provider group must outrank an older same-group backlog"
    );
    assert!(
        repository
            .finish_read_failure(
                &second_read,
                "matrix_retry",
                now - Duration::seconds(1),
                now + Duration::seconds(1),
            )
            .await
            .expect("release second fair read")
    );
    let third_read = repository
        .claim_next_read(
            Uuid::new_v4(),
            now + Duration::seconds(2),
            now + Duration::seconds(32),
        )
        .await
        .expect("claim third fair read")
        .expect("third fair read exists");
    assert_eq!(third_read.guard.project_id, first_read.guard.project_id);
    assert!(
        repository
            .finish_read_failure(
                &third_read,
                "matrix_retry",
                now + Duration::hours(1),
                now + Duration::seconds(2),
            )
            .await
            .expect("release third fair read")
    );
    sqlx::query(
        "UPDATE managed_provider_connections SET next_synchronize_at=$1,next_renewal_at=$1
          WHERE id=$2 OR id=$3 OR id=$4",
    )
    .bind(now + Duration::hours(1))
    .bind(read_a.connection_id)
    .bind(read_b.connection_id)
    .bind(read_c.connection_id)
    .execute(&pool)
    .await
    .expect("retire fair read fixtures");

    let concurrent_a = insert_managed_fixture(&pool, &first, &protector, now, 4).await;
    let concurrent_same_provider = insert_managed_fixture(&pool, &first, &protector, now, 5).await;
    let concurrent_b = insert_managed_fixture(&pool, &second, &protector, now, 6).await;
    let replica_database = Database::connect(&url)
        .await
        .expect("second Runtime replica pool");
    let replica = PostgresManagedConnectionRepository::new(replica_database.clone());
    let concurrent_now = now + Duration::seconds(31);
    let (claim_a, claim_b) = tokio::join!(
        repository.claim_next_read(
            Uuid::new_v4(),
            concurrent_now,
            concurrent_now + Duration::seconds(30),
        ),
        replica.claim_next_read(
            Uuid::new_v4(),
            concurrent_now,
            concurrent_now + Duration::seconds(30),
        ),
    );
    let claim_a = claim_a.expect("first replica read").expect("first row");
    let claim_b = claim_b.expect("second replica read").expect("second row");
    assert_ne!(
        claim_a.guard.provider_configuration_id, claim_b.guard.provider_configuration_id,
        "durable provider budgets permit at most one claim per provider across replicas"
    );
    assert!(
        repository
            .claim_next_read(
                Uuid::new_v4(),
                concurrent_now,
                concurrent_now + Duration::seconds(30),
            )
            .await
            .expect("budgeted third claim")
            .is_none(),
        "the second same-provider connection must remain queued while its distributed lease lives"
    );
    for claim in [&claim_a, &claim_b] {
        assert!(
            repository
                .finish_read_failure(
                    claim,
                    "matrix_concurrent_complete",
                    concurrent_now + Duration::hours(1),
                    concurrent_now,
                )
                .await
                .expect("release concurrent read")
        );
    }

    // The same durable budget spans queue kinds. A renewal claim on one connection suppresses
    // revocation on a sibling connection at the same Project/provider across repositories, while
    // another provider remains serviceable. If that Runtime crashes, the sibling revocation is
    // claimable immediately after the durable lease expires.
    sqlx::query(
        "UPDATE managed_provider_connections
            SET next_synchronize_at=$1,next_renewal_at=$1
          WHERE state='active' AND revocation_requested_at IS NULL",
    )
    .bind(concurrent_now + Duration::hours(2))
    .execute(&pool)
    .await
    .expect("isolate cross-queue provider budget phase");
    sqlx::query(
        "UPDATE managed_provider_claim_fairness
            SET last_claimed_at='epoch'::timestamptz,lease_owner=NULL,lease_expires_at=NULL",
    )
    .execute(&pool)
    .await
    .expect("reset cross-queue fairness history");
    let budget_renewal =
        insert_managed_fixture(&pool, &first, &protector, concurrent_now, 40).await;
    let budget_revoke_same =
        insert_managed_fixture(&pool, &first, &protector, concurrent_now, 41).await;
    let budget_revoke_other =
        insert_managed_fixture(&pool, &second, &protector, concurrent_now, 42).await;
    for (seeded, fixture) in [(&first, budget_revoke_same), (&second, budget_revoke_other)] {
        repository
            .request_revocation(
                seeded.project_id,
                fixture.user_id,
                fixture.connection_id,
                1,
                1,
                Uuid::new_v4(),
                concurrent_now + Duration::seconds(1),
            )
            .await
            .expect("enqueue cross-queue revocation");
    }
    let crashed_renewal = repository
        .prepare_next_renewal(
            Uuid::new_v4(),
            concurrent_now + Duration::seconds(2),
            concurrent_now + Duration::seconds(32),
            false,
        )
        .await
        .expect("claim cross-queue renewal budget")
        .expect("cross-queue renewal exists");
    assert_eq!(
        crashed_renewal.claim.guard.connection_id,
        budget_renewal.connection_id
    );
    let other_provider_revocation = replica
        .claim_next_revocation(
            Uuid::new_v4(),
            concurrent_now + Duration::seconds(2),
            concurrent_now + Duration::seconds(32),
        )
        .await
        .expect("other-provider revocation claim")
        .expect("other provider is not starved");
    assert_eq!(
        other_provider_revocation.guard.connection_id,
        budget_revoke_other.connection_id
    );
    assert!(
        replica
            .claim_next_revocation(
                Uuid::new_v4(),
                concurrent_now + Duration::seconds(2),
                concurrent_now + Duration::seconds(32),
            )
            .await
            .expect("same-provider cross-queue suppression")
            .is_none()
    );
    assert!(
        replica
            .mark_revocation_dispatched(
                &other_provider_revocation,
                concurrent_now + Duration::seconds(2),
            )
            .await
            .expect("mark other-provider revocation dispatched")
    );
    replica
        .finish_revocation(
            &other_provider_revocation,
            ProviderRevocationResult::Confirmed,
            concurrent_now + Duration::seconds(3),
        )
        .await
        .expect("finish other-provider revocation");
    assert!(
        replica
            .claim_next_revocation(
                Uuid::new_v4(),
                concurrent_now + Duration::seconds(31),
                concurrent_now + Duration::seconds(61),
            )
            .await
            .expect("pre-expiry cross-queue suppression")
            .is_none()
    );
    let recovered_after_crash = replica
        .claim_next_revocation(
            Uuid::new_v4(),
            concurrent_now + Duration::seconds(33),
            concurrent_now + Duration::seconds(63),
        )
        .await
        .expect("post-crash budget recovery")
        .expect("same-provider revocation recovers after lease expiry");
    assert_eq!(
        recovered_after_crash.guard.connection_id,
        budget_revoke_same.connection_id
    );
    assert!(
        replica
            .mark_revocation_dispatched(
                &recovered_after_crash,
                concurrent_now + Duration::seconds(33),
            )
            .await
            .expect("mark recovered revocation dispatched")
    );
    replica
        .finish_revocation(
            &recovered_after_crash,
            ProviderRevocationResult::Confirmed,
            concurrent_now + Duration::seconds(34),
        )
        .await
        .expect("finish recovered same-provider revocation");
    assert!(
        !repository
            .terminalize_renewal(
                &crashed_renewal,
                crate::application::RenewalOperationState::Abandoned,
                "budget_crash_test_complete",
                concurrent_now + Duration::seconds(34),
            )
            .await
            .expect("expired crash-test owner cannot terminalize")
    );
    sqlx::query("DELETE FROM managed_provider_renewal_operations WHERE id=$1")
        .bind(crashed_renewal.operation_id)
        .execute(&pool)
        .await
        .expect("remove expired crash-test operation");
    sqlx::query(
        "UPDATE managed_provider_connections
            SET lease_owner=NULL,lease_kind=NULL,lease_expires_at=NULL,
                next_synchronize_at=$1,next_renewal_at=$1
          WHERE id=$2",
    )
    .bind(concurrent_now + Duration::hours(2))
    .bind(budget_renewal.connection_id)
    .execute(&pool)
    .await
    .expect("retire crash-test connection");
    replica_database
        .close()
        .await
        .expect("close second Runtime replica pool");
    sqlx::query(
        "UPDATE managed_provider_connections SET next_renewal_at=$1
          WHERE id=$2 OR id=$3 OR id=$4",
    )
    .bind(now + Duration::hours(1))
    .bind(concurrent_a.connection_id)
    .bind(concurrent_same_provider.connection_id)
    .bind(concurrent_b.connection_id)
    .execute(&pool)
    .await
    .expect("retire concurrent renewal fixtures");

    // Prepared renewal recovery uses the same persistent Project/provider fairness cursor.
    // Once both groups have recoverable backlog, reclaiming one cannot immediately starve the
    // other even when the first operation has the older preparation timestamp.
    sqlx::query(
        "UPDATE managed_provider_connections
            SET next_synchronize_at=$1,next_renewal_at=$1
          WHERE state='active' AND revocation_requested_at IS NULL",
    )
    .bind(now + Duration::hours(2))
    .execute(&pool)
    .await
    .expect("isolate prepared renewal fairness phase");
    let renewal_a = insert_managed_fixture(&pool, &first, &protector, now, 30).await;
    let renewal_b = insert_managed_fixture(&pool, &second, &protector, now, 31).await;
    let prepared_a = repository
        .prepare_next_renewal(Uuid::new_v4(), now, now + Duration::seconds(30), false)
        .await
        .expect("prepare first fair renewal")
        .expect("first fair renewal exists");
    let prepared_b = repository
        .prepare_next_renewal(
            Uuid::new_v4(),
            now + Duration::seconds(1),
            now + Duration::seconds(31),
            false,
        )
        .await
        .expect("prepare second fair renewal")
        .expect("second fair renewal exists");
    assert_ne!(
        prepared_a.claim.guard.project_id,
        prepared_b.claim.guard.project_id
    );
    assert!(
        [renewal_a.connection_id, renewal_b.connection_id]
            .contains(&prepared_a.claim.guard.connection_id)
    );
    assert!(
        [renewal_a.connection_id, renewal_b.connection_id]
            .contains(&prepared_b.claim.guard.connection_id)
    );
    for prepared in [&prepared_a, &prepared_b] {
        assert!(
            repository
                .release_prepared_failure(
                    prepared,
                    "matrix_fair_retry",
                    now - Duration::seconds(1),
                    now + Duration::seconds(2),
                )
                .await
                .expect("release fair renewal")
        );
    }
    let reclaimed_a = repository
        .prepare_next_renewal(
            Uuid::new_v4(),
            now + Duration::seconds(3),
            now + Duration::seconds(33),
            false,
        )
        .await
        .expect("reclaim least-recently-served renewal")
        .expect("first fair recovery exists");
    assert_eq!(reclaimed_a.operation_id, prepared_a.operation_id);
    assert!(
        repository
            .release_prepared_failure(
                &reclaimed_a,
                "matrix_fair_retry",
                now - Duration::seconds(1),
                now + Duration::seconds(4),
            )
            .await
            .expect("release reclaimed renewal")
    );
    let reclaimed_b = repository
        .prepare_next_renewal(
            Uuid::new_v4(),
            now + Duration::seconds(5),
            now + Duration::seconds(35),
            false,
        )
        .await
        .expect("reclaim other renewal group")
        .expect("second fair recovery exists");
    assert_eq!(reclaimed_b.operation_id, prepared_b.operation_id);
    for prepared in [&reclaimed_b] {
        assert!(
            repository
                .release_prepared_failure(
                    prepared,
                    "matrix_fair_complete",
                    now + Duration::hours(1),
                    now + Duration::seconds(6),
                )
                .await
                .expect("retire fair renewal")
        );
    }
    sqlx::query("DELETE FROM managed_provider_renewal_operations WHERE id=$1 OR id=$2")
        .bind(prepared_a.operation_id)
        .bind(prepared_b.operation_id)
        .execute(&pool)
        .await
        .expect("terminalize fair renewal fixtures");
    sqlx::query(
        "UPDATE managed_provider_connections SET next_synchronize_at=$1,next_renewal_at=$1
          WHERE id=$2 OR id=$3",
    )
    .bind(now + Duration::hours(1))
    .bind(renewal_a.connection_id)
    .bind(renewal_b.connection_id)
    .execute(&pool)
    .await
    .expect("retire fair renewal connections");

    // A frozen non-replayable submitted operation is recovered only to become terminal. Its
    // predecessor is destroyed, so neither restart nor a late result can reuse it.
    let non_replay = insert_managed_fixture(&pool, &first, &protector, now, 6).await;
    let prepared = repository
        .prepare_next_renewal(Uuid::new_v4(), now, now + Duration::seconds(30), false)
        .await
        .expect("prepare non-replay renewal")
        .expect("non-replay renewal due");
    assert_eq!(prepared.claim.guard.connection_id, non_replay.connection_id);
    assert_eq!(
        prepared.claim.guard.adapter_key,
        "controlled_oidc_profile_v1"
    );
    assert_eq!(prepared.claim.guard.adapter_capability_revision, 1);
    assert!(
        repository
            .mark_renewal_submitted(&prepared, now + Duration::seconds(1))
            .await
            .expect("persist non-replay submission")
    );
    sqlx::query("UPDATE managed_provider_renewal_operations SET lease_expires_at=$1 WHERE id=$2")
        .bind(now + Duration::seconds(1))
        .bind(prepared.operation_id)
        .execute(&pool)
        .await
        .expect("expire non-replay operation lease");
    sqlx::query("UPDATE managed_provider_connections SET lease_expires_at=$1 WHERE id=$2")
        .bind(now + Duration::seconds(1))
        .bind(non_replay.connection_id)
        .execute(&pool)
        .await
        .expect("expire non-replay connection lease");
    sqlx::query("UPDATE projects SET security_revision=2 WHERE id=$1")
        .bind(first.project_id)
        .execute(&pool)
        .await
        .expect("invalidate submitted renewal authority");
    let recovered = repository
        .prepare_next_renewal(
            Uuid::new_v4(),
            now + Duration::seconds(2),
            now + Duration::seconds(32),
            true,
        )
        .await
        .expect("recover frozen non-replay submission")
        .expect("submitted operation remains recoverable for terminalization");
    assert!(!recovered.adapter_idempotent_replay);
    assert!(!recovered.authority_valid);
    assert_eq!(
        recovered.claim.guard.adapter_key,
        prepared.claim.guard.adapter_key
    );
    assert_eq!(
        recovered.claim.guard.adapter_capability_revision,
        prepared.claim.guard.adapter_capability_revision
    );
    assert_eq!(
        recovered.operation_state,
        crate::application::RenewalOperationState::Submitted
    );
    assert!(
        repository
            .terminalize_renewal(
                &recovered,
                crate::application::RenewalOperationState::ReauthRequired,
                "renewal_authority_stale",
                now + Duration::seconds(3),
            )
            .await
            .expect("terminalize non-replay ambiguity")
    );
    let non_replay_state: (String, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT connection.state,credential.ciphertext
           FROM managed_provider_connections connection
           JOIN managed_provider_credentials credential
             ON credential.connection_id=connection.id AND credential.project_id=connection.project_id
          WHERE connection.id=$1 AND credential.credential_generation=1",
    )
    .bind(non_replay.connection_id)
    .fetch_one(&pool)
    .await
    .expect("inspect non-replay terminal state");
    assert_eq!(non_replay_state, ("reauth_required".to_owned(), None));
    let stale_authority_audit: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events
          WHERE target_id=$1 AND action='managed_connection.reauthorization_required'",
    )
    .bind(non_replay.connection_id)
    .fetch_one(&pool)
    .await
    .expect("count stale-authority terminalization audit");
    assert_eq!(stale_authority_audit, 1);
    sqlx::query("UPDATE projects SET security_revision=1 WHERE id=$1")
        .bind(first.project_id)
        .execute(&pool)
        .await
        .expect("restore authority after submitted recovery proof");

    // Confirmed and ambiguous revocation are both destructive; only the authoritative state
    // differs. Revocation scheduling also serves an unclaimed Project/provider group next.
    let revoke_confirmed = insert_managed_fixture(&pool, &first, &protector, now, 7).await;
    let revoke_ambiguous = insert_managed_fixture(&pool, &second, &protector, now, 8).await;
    sqlx::query(
        "UPDATE managed_provider_claim_fairness
            SET last_claimed_at='epoch'::timestamptz,lease_owner=NULL,lease_expires_at=NULL",
    )
    .execute(&pool)
    .await
    .expect("reset fairness history for revocation phase");
    for (seeded, fixture) in [(&first, revoke_confirmed), (&second, revoke_ambiguous)] {
        repository
            .request_revocation(
                seeded.project_id,
                fixture.user_id,
                fixture.connection_id,
                1,
                1,
                Uuid::new_v4(),
                now + Duration::seconds(4),
            )
            .await
            .expect("enqueue matrix revocation");
    }
    let revocation_a = repository
        .claim_next_revocation(
            Uuid::new_v4(),
            now + Duration::seconds(5),
            now + Duration::seconds(35),
        )
        .await
        .expect("claim first fair revocation")
        .expect("first revocation exists");
    assert!(
        repository
            .release_revocation_claim(&revocation_a, now + Duration::seconds(5))
            .await
            .expect("release first fair revocation")
    );
    let revocation_b = repository
        .claim_next_revocation(
            Uuid::new_v4(),
            now + Duration::seconds(6),
            now + Duration::seconds(36),
        )
        .await
        .expect("claim second fair revocation")
        .expect("second revocation exists");
    assert_ne!(revocation_a.guard.project_id, revocation_b.guard.project_id);
    let first_result = if revocation_b.guard.connection_id == revoke_confirmed.connection_id {
        ProviderRevocationResult::Confirmed
    } else {
        ProviderRevocationResult::Ambiguous
    };
    assert!(
        repository
            .mark_revocation_dispatched(&revocation_b, now + Duration::seconds(6))
            .await
            .expect("mark second fair revocation dispatched")
    );
    let finished_b = repository
        .finish_revocation(&revocation_b, first_result, now + Duration::seconds(7))
        .await
        .expect("finish second fair revocation");
    assert!(matches!(
        finished_b.state.as_str(),
        "revoked" | "reauth_required"
    ));
    let revocation_a_reclaimed = repository
        .claim_next_revocation(
            Uuid::new_v4(),
            now + Duration::seconds(8),
            now + Duration::seconds(38),
        )
        .await
        .expect("reclaim first revocation")
        .expect("released revocation intent remains durable");
    assert_eq!(
        revocation_a_reclaimed.guard.connection_id,
        revocation_a.guard.connection_id
    );
    let second_result =
        if revocation_a_reclaimed.guard.connection_id == revoke_confirmed.connection_id {
            ProviderRevocationResult::Confirmed
        } else {
            ProviderRevocationResult::Ambiguous
        };
    assert!(
        repository
            .mark_revocation_dispatched(&revocation_a_reclaimed, now + Duration::seconds(8))
            .await
            .expect("mark first fair revocation dispatched")
    );
    repository
        .finish_revocation(
            &revocation_a_reclaimed,
            second_result,
            now + Duration::seconds(9),
        )
        .await
        .expect("finish first fair revocation");
    for (fixture, expected) in [
        (revoke_confirmed, "revoked"),
        (revoke_ambiguous, "reauth_required"),
    ] {
        let state: (String, Option<Vec<u8>>) = sqlx::query_as(
            "SELECT connection.state,credential.ciphertext
               FROM managed_provider_connections connection
               JOIN managed_provider_credentials credential
                 ON credential.connection_id=connection.id AND credential.project_id=connection.project_id
              WHERE connection.id=$1",
        )
        .bind(fixture.connection_id)
        .fetch_one(&pool)
        .await
        .expect("inspect destructive revocation state");
        assert_eq!(state, (expected.to_owned(), None));
    }

    let authority_race = insert_managed_fixture(&pool, &first, &protector, now, 43).await;
    repository
        .request_revocation(
            first.project_id,
            authority_race.user_id,
            authority_race.connection_id,
            1,
            1,
            Uuid::new_v4(),
            now + Duration::seconds(9),
        )
        .await
        .expect("enqueue authority-race revocation");
    sqlx::query("UPDATE projects SET security_revision=2 WHERE id=$1")
        .bind(first.project_id)
        .execute(&pool)
        .await
        .expect("invalidate queued revocation authority");
    assert!(
        repository
            .claim_next_revocation(
                Uuid::new_v4(),
                now + Duration::seconds(10),
                now + Duration::seconds(40),
            )
            .await
            .expect("bounded stale revocation cleanup")
            .is_none()
    );
    let authority_race_state: (String, Option<Vec<u8>>, Option<OffsetDateTime>) =
        sqlx::query_as(
            "SELECT connection.state,credential.ciphertext,connection.revocation_requested_at
               FROM managed_provider_connections connection
               JOIN managed_provider_credentials credential
                 ON credential.connection_id=connection.id AND credential.project_id=connection.project_id
              WHERE connection.id=$1",
        )
        .bind(authority_race.connection_id)
        .fetch_one(&pool)
        .await
        .expect("inspect authority-race revocation terminality");
    assert_eq!(
        authority_race_state,
        ("reauth_required".to_owned(), None, None)
    );
    sqlx::query("UPDATE projects SET security_revision=1 WHERE id=$1")
        .bind(first.project_id)
        .execute(&pool)
        .await
        .expect("restore project authority after revocation race proof");

    // Invalid and authoritative-revocation read evidence use the same generation fence and
    // destroy the credential before publishing reauthorization-required/revoked state.
    for (suffix, revoked, expected) in [(9, false, "reauth_required"), (10, true, "revoked")] {
        let fixture = insert_managed_fixture(&pool, &first, &protector, now, suffix).await;
        let claim = repository
            .claim_for_revocation(
                first.project_id,
                fixture.user_id,
                fixture.connection_id,
                1,
                1,
                Uuid::new_v4(),
                now + Duration::seconds(10),
                now + Duration::seconds(40),
            )
            .await
            .expect("obtain exact evidence guard");
        assert!(
            repository
                .release_revocation_claim(&claim, now + Duration::seconds(10))
                .await
                .expect("release evidence guard lease")
        );
        assert!(
            repository
                .fence_read_evidence(
                    &claim.guard,
                    revoked,
                    if revoked {
                        "read_confirmed_revocation"
                    } else {
                        "read_invalid_credential"
                    },
                    now + Duration::seconds(11),
                )
                .await
                .expect("commit destructive read evidence")
        );
        let state: (String, Option<Vec<u8>>) = sqlx::query_as(
            "SELECT connection.state,credential.ciphertext
               FROM managed_provider_connections connection
               JOIN managed_provider_credentials credential
                 ON credential.connection_id=connection.id AND credential.project_id=connection.project_id
              WHERE connection.id=$1",
        )
        .bind(fixture.connection_id)
        .fetch_one(&pool)
        .await
        .expect("inspect read evidence state");
        assert_eq!(state, (expected.to_owned(), None));
    }

    // Post-UserInfo evidence is stale if any material authority class changes while the network
    // call is in flight. Each stale observation is discarded and its successor remains usable.
    for (index, suffix) in [60_u8, 61, 62, 63].into_iter().enumerate() {
        let fixture = insert_managed_fixture(&pool, &first, &protector, now, suffix).await;
        let claim = repository
            .claim_for_revocation(
                first.project_id,
                fixture.user_id,
                fixture.connection_id,
                1,
                1,
                Uuid::new_v4(),
                now + Duration::seconds(11),
                now + Duration::seconds(41),
            )
            .await
            .expect("capture pre-UserInfo authority snapshot");
        assert!(
            repository
                .release_revocation_claim(&claim, now + Duration::seconds(11))
                .await
                .expect("release simulated UserInfo scheduling lease")
        );
        match index {
            0 => {
                sqlx::query("UPDATE projects SET security_revision=2 WHERE id=$1")
                    .bind(first.project_id)
                    .execute(&pool)
                    .await
                    .expect("advance Project authority during UserInfo");
            }
            1 => {
                sqlx::query("UPDATE provider_configurations SET revision=2 WHERE id=$1")
                    .bind(first.provider_id)
                    .execute(&pool)
                    .await
                    .expect("advance provider authority during UserInfo");
            }
            2 => {
                sqlx::query("UPDATE project_users SET status='disabled' WHERE id=$1")
                    .bind(fixture.user_id)
                    .execute(&pool)
                    .await
                    .expect("disable user during UserInfo");
            }
            3 => {
                sqlx::query(
                    "UPDATE linked_identities SET identity_revision=identity_revision+1
                     WHERE project_id=$1 AND user_id=$2",
                )
                .bind(first.project_id)
                .bind(fixture.user_id)
                .execute(&pool)
                .await
                .expect("advance identity authority during UserInfo");
            }
            _ => unreachable!(),
        }
        assert!(
            !repository
                .fence_read_evidence(
                    &claim.guard,
                    false,
                    "read_invalid_credential",
                    now + Duration::seconds(12),
                )
                .await
                .expect("discard stale destructive evidence")
        );
        assert!(
            !repository
                .finish_successor_profile_failure(
                    &crate::application::SuccessorProfileClaim {
                        guard: claim.guard.clone(),
                        lease_owner: claim.lease_owner,
                        lease_expires_at: claim.lease_expires_at,
                    },
                    "read_transient",
                    now + Duration::minutes(1),
                    now + Duration::seconds(12),
                )
                .await
                .expect("discard stale non-destructive scheduling result")
        );
        let unchanged: (String, Option<Vec<u8>>, String) = sqlx::query_as(
            "SELECT connection.state,credential.ciphertext,connection.last_safe_outcome
               FROM managed_provider_connections connection
               JOIN managed_provider_credentials credential
                 ON credential.project_id=connection.project_id
                AND credential.connection_id=connection.id
                AND credential.credential_generation=connection.credential_generation
              WHERE connection.id=$1",
        )
        .bind(fixture.connection_id)
        .fetch_one(&pool)
        .await
        .expect("inspect stale evidence discard");
        assert_eq!(unchanged.0, "active");
        assert!(unchanged.1.is_some());
        assert_eq!(unchanged.2, "fixture_ready");
        match index {
            0 => {
                sqlx::query("UPDATE projects SET security_revision=1 WHERE id=$1")
                    .bind(first.project_id)
                    .execute(&pool)
                    .await
                    .expect("restore Project authority");
            }
            1 => {
                sqlx::query("UPDATE provider_configurations SET revision=1 WHERE id=$1")
                    .bind(first.provider_id)
                    .execute(&pool)
                    .await
                    .expect("restore provider authority");
            }
            2 => {
                sqlx::query("UPDATE project_users SET status='active' WHERE id=$1")
                    .bind(fixture.user_id)
                    .execute(&pool)
                    .await
                    .expect("restore user authority");
            }
            3 => {}
            _ => unreachable!(),
        }
        sqlx::query(
            "UPDATE managed_provider_connections SET state='disconnected',revision=revision+1,
             generation=generation+1,last_safe_outcome='test_retired',next_synchronize_at=NULL,
             next_renewal_at=NULL,disconnected_at=$1 WHERE id=$2",
        )
        .bind(now + Duration::seconds(13))
        .bind(fixture.connection_id)
        .execute(&pool)
        .await
        .expect("retire stale-evidence fixture");
    }

    // Provider work that returns after a revocation or disconnect fence cannot install a
    // successor. Revocation then owns destructive completion, while disconnect has already
    // destroyed the predecessor locally.
    let stale_revoke = insert_managed_fixture(&pool, &first, &protector, now, 11).await;
    let stale_revoke_renewal = repository
        .prepare_next_renewal(
            Uuid::new_v4(),
            now + Duration::seconds(12),
            now + Duration::seconds(42),
            false,
        )
        .await
        .expect("prepare renewal raced by revocation")
        .expect("revocation race renewal exists");
    assert_eq!(
        stale_revoke_renewal.claim.guard.connection_id,
        stale_revoke.connection_id
    );
    assert!(
        repository
            .mark_renewal_submitted(&stale_revoke_renewal, now + Duration::seconds(13))
            .await
            .expect("submit renewal raced by revocation")
    );
    sqlx::query("UPDATE managed_provider_connections SET lease_expires_at=$1 WHERE id=$2")
        .bind(now + Duration::seconds(13))
        .bind(stale_revoke.connection_id)
        .execute(&pool)
        .await
        .expect("expire renewal lease before revocation request");
    repository
        .request_revocation(
            first.project_id,
            stale_revoke.user_id,
            stale_revoke.connection_id,
            1,
            1,
            Uuid::new_v4(),
            now + Duration::seconds(14),
        )
        .await
        .expect("revocation wins stale renewal race");
    let stale_revoke_context = ManagedCredentialContext {
        project_id: first.project_id,
        provider_configuration_id: first.provider_id,
        linked_identity_id: stale_revoke_renewal.claim.guard.linked_identity_id,
        connection_id: stale_revoke.connection_id,
        connection_generation: 2,
        credential_generation: 2,
    };
    let stale_successor = protector
        .protect_credential(&stale_revoke_context, b"stale-revocation-successor")
        .expect("protect stale revocation successor");
    assert!(
        repository
            .commit_renewal_successor(
                &stale_revoke_renewal,
                stale_successor,
                now + Duration::seconds(15),
            )
            .await
            .expect("fence stale renewal after revocation")
            .is_none()
    );
    let revocation = repository
        .claim_next_revocation(
            Uuid::new_v4(),
            now + Duration::seconds(16),
            now + Duration::seconds(46),
        )
        .await
        .expect("claim winning revocation")
        .expect("winning revocation remains durable");
    assert_eq!(revocation.guard.connection_id, stale_revoke.connection_id);
    assert!(
        repository
            .mark_revocation_dispatched(&revocation, now + Duration::seconds(16))
            .await
            .expect("mark winning revocation dispatched")
    );
    repository
        .finish_revocation(
            &revocation,
            ProviderRevocationResult::Confirmed,
            now + Duration::seconds(17),
        )
        .await
        .expect("finish winning revocation");

    let stale_disconnect = insert_managed_fixture(&pool, &first, &protector, now, 12).await;
    let stale_disconnect_renewal = repository
        .prepare_next_renewal(
            Uuid::new_v4(),
            now + Duration::seconds(18),
            now + Duration::seconds(48),
            false,
        )
        .await
        .expect("prepare renewal raced by disconnect")
        .expect("disconnect race renewal exists");
    assert_eq!(
        stale_disconnect_renewal.claim.guard.connection_id,
        stale_disconnect.connection_id
    );
    assert!(
        repository
            .mark_renewal_submitted(&stale_disconnect_renewal, now + Duration::seconds(19))
            .await
            .expect("submit renewal raced by disconnect")
    );
    assert_eq!(
        repository
            .disconnect(
                first.project_id,
                stale_disconnect.user_id,
                stale_disconnect.connection_id,
                1,
                1,
                now + Duration::seconds(20),
            )
            .await,
        Err(ApplicationError::RevisionConflict),
        "disconnect must not bypass an active submitted-renewal lease"
    );
    repository
        .disconnect(
            first.project_id,
            stale_disconnect.user_id,
            stale_disconnect.connection_id,
            1,
            1,
            now + Duration::seconds(49),
        )
        .await
        .expect("disconnect queues provider revocation after lease recovery");
    let stale_disconnect_context = ManagedCredentialContext {
        project_id: first.project_id,
        provider_configuration_id: first.provider_id,
        linked_identity_id: stale_disconnect_renewal.claim.guard.linked_identity_id,
        connection_id: stale_disconnect.connection_id,
        connection_generation: 2,
        credential_generation: 2,
    };
    let stale_disconnect_successor = protector
        .protect_credential(&stale_disconnect_context, b"stale-disconnect-successor")
        .expect("protect stale disconnect successor");
    assert!(
        repository
            .commit_renewal_successor(
                &stale_disconnect_renewal,
                stale_disconnect_successor,
                now + Duration::seconds(50),
            )
            .await
            .expect("fence stale renewal after disconnect")
            .is_none()
    );
    for (fixture, outcome) in [
        (stale_disconnect, ProviderRevocationResult::Ambiguous),
        (
            insert_managed_fixture(&pool, &first, &protector, now, 44).await,
            ProviderRevocationResult::Confirmed,
        ),
        (
            insert_managed_fixture(&pool, &first, &protector, now, 45).await,
            ProviderRevocationResult::Unsupported,
        ),
    ] {
        if fixture.connection_id != stale_disconnect.connection_id {
            repository
                .disconnect(
                    first.project_id,
                    fixture.user_id,
                    fixture.connection_id,
                    1,
                    1,
                    now + Duration::seconds(51),
                )
                .await
                .expect("queue supported disconnect revocation matrix");
        }
        let claim = repository
            .claim_next_revocation(
                Uuid::new_v4(),
                now + Duration::seconds(52),
                now + Duration::seconds(82),
            )
            .await
            .expect("claim disconnect revocation matrix")
            .expect("disconnect revocation intent remains durable");
        assert_eq!(claim.guard.connection_id, fixture.connection_id);
        assert!(
            repository
                .mark_revocation_dispatched(&claim, now + Duration::seconds(52))
                .await
                .expect("mark disconnect revocation dispatched")
        );
        let disconnected = repository
            .finish_revocation(&claim, outcome, now + Duration::seconds(53))
            .await
            .expect("finish disconnect revocation matrix");
        assert_eq!(disconnected.state, "disconnected");
        let credential: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT ciphertext FROM managed_provider_credentials
              WHERE project_id=$1 AND connection_id=$2 AND credential_generation=1",
        )
        .bind(first.project_id)
        .bind(fixture.connection_id)
        .fetch_one(&pool)
        .await
        .expect("inspect disconnected credential destruction");
        assert!(credential.is_none());
    }

    // Once revocation intent is durable, Control cannot create a competing reauthorization.
    // This closes the opposite ordering before Hosted/provider material is issued.
    let reauth_fenced = insert_managed_fixture(&pool, &first, &protector, now, 13).await;
    let requested = repository
        .request_revocation(
            first.project_id,
            reauth_fenced.user_id,
            reauth_fenced.connection_id,
            1,
            1,
            Uuid::new_v4(),
            now + Duration::seconds(22),
        )
        .await
        .expect("persist reauthorization fence intent");
    let reauthorizations = PostgresManagedReauthorizationRepository::new(database.clone());
    let fenced_interaction = Uuid::new_v4();
    let create = reauthorizations
        .create(PreparedManagedReauthorizationCreate {
            capability: managed_capability_snapshot(),
            command: CreateManagedReauthorization {
                project_id: first.project_id,
                user_id: reauth_fenced.user_id,
                connection_id: reauth_fenced.connection_id,
                application_id: first.application_id,
                expected_connection_revision: requested.revision,
                expected_connection_generation: requested.generation,
                expected_credential_generation: requested.credential_generation,
                idempotency_key: format!("matrix-fenced-{fenced_interaction}"),
                correlation_id: Uuid::new_v4(),
            },
            interaction_id: fenced_interaction,
            interaction_digest: digest(201),
            request_digest: vec![202; 32],
            protected_create_result: ProtectedValue {
                ciphertext: vec![203; 48],
                key_version: 1,
            },
            expires_at: now + Duration::minutes(9),
            now: now + Duration::seconds(23),
        })
        .await;
    assert!(
        create.is_err(),
        "revocation intent must fence reauthorization create"
    );
    let interaction_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM managed_provider_reauthorization_interactions WHERE id=$1",
    )
    .bind(fenced_interaction)
    .fetch_one(&pool)
    .await
    .expect("count fenced reauthorization interactions");
    assert_eq!(interaction_count, 0);

    // A late worker that lost the stable submitted attempt cannot use its failed successor CAS to
    // terminalize the operation currently owned by a reclaiming Runtime. The current owner can
    // still atomically commit the same-attempt successor.
    let race_now = now + Duration::seconds(90);
    sqlx::query(
        "UPDATE managed_provider_connections
            SET next_synchronize_at=$1,next_renewal_at=$1
          WHERE state='active' AND revocation_requested_at IS NULL",
    )
    .bind(race_now + Duration::hours(2))
    .execute(&pool)
    .await
    .expect("isolate late renewal owner race");
    let owner_race = insert_managed_fixture(&pool, &first, &protector, race_now, 46).await;
    let late_owner = repository
        .prepare_next_renewal(
            Uuid::new_v4(),
            race_now,
            race_now + Duration::seconds(30),
            true,
        )
        .await
        .expect("prepare late-owner race")
        .expect("late-owner renewal is due");
    assert_eq!(
        late_owner.claim.guard.connection_id,
        owner_race.connection_id
    );
    assert!(
        repository
            .mark_renewal_submitted(&late_owner, race_now + Duration::seconds(1))
            .await
            .expect("submit late-owner race")
    );
    sqlx::query("UPDATE managed_provider_renewal_operations SET lease_expires_at=$1 WHERE id=$2")
        .bind(race_now + Duration::seconds(1))
        .bind(late_owner.operation_id)
        .execute(&pool)
        .await
        .expect("expire late operation owner");
    sqlx::query("UPDATE managed_provider_connections SET lease_expires_at=$1 WHERE id=$2")
        .bind(race_now + Duration::seconds(1))
        .bind(owner_race.connection_id)
        .execute(&pool)
        .await
        .expect("expire late connection owner");
    sqlx::query(
        "UPDATE managed_provider_claim_fairness SET lease_expires_at=$1
          WHERE project_id=$2 AND provider_configuration_id=$3 AND queue_kind='outbound'",
    )
    .bind(race_now + Duration::seconds(1))
    .bind(first.project_id)
    .bind(first.provider_id)
    .execute(&pool)
    .await
    .expect("expire late provider budget owner");
    let current_owner = repository
        .prepare_next_renewal(
            Uuid::new_v4(),
            race_now + Duration::seconds(2),
            race_now + Duration::seconds(82),
            true,
        )
        .await
        .expect("reclaim stable submitted attempt")
        .expect("current renewal owner exists");
    assert_eq!(current_owner.operation_id, late_owner.operation_id);
    assert_eq!(current_owner.attempt_id, late_owner.attempt_id);
    let owner_race_context = ManagedCredentialContext {
        project_id: first.project_id,
        provider_configuration_id: first.provider_id,
        linked_identity_id: current_owner.claim.guard.linked_identity_id,
        connection_id: owner_race.connection_id,
        connection_generation: 2,
        credential_generation: 2,
    };
    let race_successor = protector
        .protect_credential(&owner_race_context, b"stable-attempt-successor")
        .expect("protect stable-attempt successor");
    assert!(
        repository
            .commit_renewal_successor(
                &late_owner,
                race_successor.clone(),
                race_now + Duration::seconds(3),
            )
            .await
            .expect("late successor CAS is a guarded miss")
            .is_none()
    );
    assert!(
        !repository
            .terminalize_renewal(
                &late_owner,
                crate::application::RenewalOperationState::ReauthRequired,
                "successor_commit_fenced",
                race_now + Duration::seconds(3),
            )
            .await
            .expect("late terminalization loses the owner CAS")
    );
    let committed = repository
        .commit_renewal_successor(
            &current_owner,
            race_successor,
            race_now + Duration::seconds(3),
        )
        .await
        .expect("current owner successor commit")
        .expect("current owner wins the stable attempt");
    assert_eq!(
        (
            committed.connection_generation,
            committed.credential_generation,
        ),
        (2, 2)
    );

    // The successor's profile stage retains both the exact connection lease and the shared
    // Project/provider budget. A second repository/worker can claim neither this due successor
    // nor another due connection for the same provider until the owner completes or expires.
    let replica_repository = PostgresManagedConnectionRepository::new(database.clone());
    let peer = insert_managed_fixture(&pool, &first, &protector, race_now, 47).await;
    let persisted_profile_lease: (Option<Uuid>, Option<String>, Option<OffsetDateTime>) =
        sqlx::query_as(
            "SELECT lease_owner,lease_kind,lease_expires_at
               FROM managed_provider_connections WHERE id=$1",
        )
        .bind(owner_race.connection_id)
        .fetch_one(&pool)
        .await
        .expect("inspect durable successor profile lease");
    assert_eq!(
        persisted_profile_lease.0,
        Some(current_owner.claim.lease_owner)
    );
    assert_eq!(persisted_profile_lease.1.as_deref(), Some("renewal"));
    assert_eq!(persisted_profile_lease.2, Some(committed.lease_expires_at));
    assert!(
        replica_repository
            .prepare_next_renewal(
                Uuid::new_v4(),
                race_now + Duration::seconds(4),
                race_now + Duration::seconds(34),
                true,
            )
            .await
            .expect("replica profile-stage claim attempt")
            .is_none(),
        "profile-stage owner must retain the connection and provider budget"
    );
    // Deterministically model four delayed provider calls of nine seconds each plus intervening
    // durable boundaries. Every provider call remains below its ten-second timeout, while the
    // profile CAS happens 41 seconds after the claim (past the rejected fixed 30-second lease).
    // The declared 40-second adapter budget plus persistence/safety yields this 80-second lease,
    // so the exact successor profile still commits and releases the provider budget.
    assert!(
        repository
            .commit_successor_profile(
                &committed,
                BoundedManagedProfile {
                    profile: BoundedProviderProfile {
                        display_name: Some(
                            ProfileDisplayName::parse("Delayed managed profile".to_owned())
                                .expect("bounded delayed profile"),
                        ),
                        picture_url: None,
                        locale: Some(
                            ProfileLocale::parse("en-US".to_owned())
                                .expect("bounded delayed locale"),
                        ),
                    },
                    observed_at: race_now + Duration::seconds(40),
                },
                race_now + Duration::hours(6),
                race_now + Duration::seconds(41),
            )
            .await
            .expect("commit cumulatively delayed successor profile")
    );
    let delayed_profile_state: (String, Option<OffsetDateTime>, Option<OffsetDateTime>) =
        sqlx::query_as(
            "SELECT last_safe_outcome,last_synchronized_at,next_synchronize_at
               FROM managed_provider_connections WHERE id=$1",
        )
        .bind(owner_race.connection_id)
        .fetch_one(&pool)
        .await
        .expect("inspect delayed successor profile completion");
    assert_eq!(delayed_profile_state.0, "read_succeeded");
    assert_eq!(
        delayed_profile_state.1,
        Some(race_now + Duration::seconds(41))
    );
    assert_eq!(delayed_profile_state.2, Some(race_now + Duration::hours(6)));
    let peer_renewal = replica_repository
        .prepare_next_renewal(
            Uuid::new_v4(),
            race_now + Duration::seconds(42),
            race_now + Duration::seconds(122),
            true,
        )
        .await
        .expect("claim after profile completion")
        .expect("completion releases provider budget");
    assert_eq!(peer_renewal.claim.guard.connection_id, peer.connection_id);
    assert!(
        replica_repository
            .mark_renewal_submitted(&peer_renewal, race_now + Duration::seconds(43))
            .await
            .expect("submit peer renewal")
    );
    let peer_successor_context = ManagedCredentialContext {
        project_id: first.project_id,
        provider_configuration_id: first.provider_id,
        linked_identity_id: peer_renewal.claim.guard.linked_identity_id,
        connection_id: peer.connection_id,
        connection_generation: 2,
        credential_generation: 2,
    };
    let peer_successor = protector
        .protect_credential(&peer_successor_context, b"peer-profile-stage-successor")
        .expect("protect peer successor");
    let peer_profile = replica_repository
        .commit_renewal_successor(
            &peer_renewal,
            peer_successor,
            race_now + Duration::seconds(44),
        )
        .await
        .expect("commit peer successor")
        .expect("peer successor wins");
    assert!(
        repository
            .prepare_next_renewal(
                Uuid::new_v4(),
                race_now + Duration::seconds(45),
                race_now + Duration::seconds(125),
                true,
            )
            .await
            .expect("pre-expiry recovery attempt")
            .is_none(),
        "a crashed profile owner is not reclaimable before lease expiry"
    );
    assert!(
        !repository
            .commit_successor_profile(
                &peer_profile,
                BoundedManagedProfile {
                    profile: BoundedProviderProfile {
                        display_name: None,
                        picture_url: None,
                        locale: None,
                    },
                    observed_at: peer_profile.lease_expires_at,
                },
                peer_profile.lease_expires_at + Duration::hours(6),
                peer_profile.lease_expires_at + Duration::seconds(1),
            )
            .await
            .expect("expired successor profile is an explicit guarded miss"),
        "profile completion after exact lease expiry must report false"
    );
    let pending_after_false_cas: (String, Option<OffsetDateTime>) = sqlx::query_as(
        "SELECT last_safe_outcome,next_synchronize_at
           FROM managed_provider_connections WHERE id=$1",
    )
    .bind(peer.connection_id)
    .fetch_one(&pool)
    .await
    .expect("inspect false profile-CAS scheduling state");
    assert_eq!(pending_after_false_cas.0, "successor_profile_pending");
    assert_eq!(
        pending_after_false_cas.1,
        Some(peer_profile.lease_expires_at + Duration::minutes(1))
    );
    assert!(
        repository
            .prepare_next_renewal(
                Uuid::new_v4(),
                peer_profile.lease_expires_at + Duration::seconds(1),
                peer_profile.lease_expires_at + Duration::seconds(81),
                true,
            )
            .await
            .expect("post-expiry cooldown claim attempt")
            .is_none(),
        "an expired profile CAS must not immediately hot-loop credential renewal"
    );
    let recovered = repository
        .prepare_next_renewal(
            Uuid::new_v4(),
            peer_profile.lease_expires_at + Duration::seconds(61),
            peer_profile.lease_expires_at + Duration::seconds(141),
            true,
        )
        .await
        .expect("post-cooldown recovery attempt")
        .expect("profile-stage crash is recoverable after its bounded cooldown");
    assert_eq!(recovered.claim.guard.connection_id, peer.connection_id);
    assert_ne!(recovered.claim.lease_owner, peer_profile.lease_owner);
    assert!(
        repository
            .release_prepared_failure(
                &recovered,
                "test_release",
                peer_profile.lease_expires_at + Duration::hours(1),
                peer_profile.lease_expires_at + Duration::seconds(62),
            )
            .await
            .expect("release recovered prepared operation")
    );

    // The no-profile completion path is equally authority- and owner-fenced. A stale frozen
    // connection snapshot cannot release the lease; restoring the exact snapshot permits the
    // same owner to complete and release it.
    sqlx::query(
        "UPDATE managed_provider_connections
            SET next_synchronize_at=$1,next_renewal_at=$1
          WHERE state='active' AND lease_owner IS NULL",
    )
    .bind(peer_profile.lease_expires_at + Duration::hours(2))
    .execute(&pool)
    .await
    .expect("isolate no-profile fixture");
    let no_profile = insert_managed_fixture(&pool, &first, &protector, race_now, 48).await;
    let no_profile_renewal = repository
        .prepare_next_renewal(
            Uuid::new_v4(),
            peer_profile.lease_expires_at + Duration::seconds(3),
            peer_profile.lease_expires_at + Duration::seconds(33),
            true,
        )
        .await
        .expect("prepare no-profile renewal")
        .expect("no-profile fixture is due");
    assert_eq!(
        no_profile_renewal.claim.guard.connection_id,
        no_profile.connection_id
    );
    assert!(
        repository
            .mark_renewal_submitted(
                &no_profile_renewal,
                peer_profile.lease_expires_at + Duration::seconds(4),
            )
            .await
            .expect("submit no-profile renewal")
    );
    let no_profile_context = ManagedCredentialContext {
        project_id: first.project_id,
        provider_configuration_id: first.provider_id,
        linked_identity_id: no_profile_renewal.claim.guard.linked_identity_id,
        connection_id: no_profile.connection_id,
        connection_generation: 2,
        credential_generation: 2,
    };
    let no_profile_successor = protector
        .protect_credential(&no_profile_context, b"no-profile-successor")
        .expect("protect no-profile successor");
    let no_profile_claim = repository
        .commit_renewal_successor(
            &no_profile_renewal,
            no_profile_successor,
            peer_profile.lease_expires_at + Duration::seconds(5),
        )
        .await
        .expect("commit no-profile successor")
        .expect("no-profile successor wins");
    sqlx::query(
        "UPDATE managed_provider_connections SET provider_revision=provider_revision+1 WHERE id=$1",
    )
    .bind(no_profile.connection_id)
    .execute(&pool)
    .await
    .expect("make no-profile connection snapshot stale");
    assert!(
        !repository
            .finish_successor_without_profile(
                &no_profile_claim,
                peer_profile.lease_expires_at + Duration::seconds(6),
            )
            .await
            .expect("stale no-profile completion is fenced")
    );
    let retained_owner: Option<Uuid> =
        sqlx::query_scalar("SELECT lease_owner FROM managed_provider_connections WHERE id=$1")
            .bind(no_profile.connection_id)
            .fetch_one(&pool)
            .await
            .expect("inspect fenced no-profile owner");
    assert_eq!(retained_owner, Some(no_profile_claim.lease_owner));
    sqlx::query("UPDATE managed_provider_connections SET provider_revision=$1 WHERE id=$2")
        .bind(no_profile_claim.guard.provider_revision)
        .bind(no_profile.connection_id)
        .execute(&pool)
        .await
        .expect("restore exact no-profile snapshot");
    assert!(
        repository
            .finish_successor_without_profile(
                &no_profile_claim,
                peer_profile.lease_expires_at + Duration::seconds(7),
            )
            .await
            .expect("exact no-profile completion releases")
    );

    // Required inventory fails closed when key one is absent and becomes a strict subset only
    // after the retained version is restored. This is the startup/retirement readiness input.
    let inventory_fixture = insert_managed_fixture(&pool, &first, &protector, now, 14).await;
    sqlx::query(
        "UPDATE managed_provider_connections SET next_synchronize_at=$1,next_renewal_at=$1
          WHERE id=$2",
    )
    .bind(now + Duration::hours(1))
    .bind(inventory_fixture.connection_id)
    .execute(&pool)
    .await
    .expect("keep inventory fixture live but not due");
    // Production composition gives the cleanup service only Runtime short-term readable
    // versions. Managed credential readiness remains a distinct long-lived ring inventory.
    let unreadable_interaction = Uuid::new_v4();
    reauthorizations
        .create(PreparedManagedReauthorizationCreate {
            capability: managed_capability_snapshot(),
            command: CreateManagedReauthorization {
                project_id: first.project_id,
                user_id: inventory_fixture.user_id,
                connection_id: inventory_fixture.connection_id,
                application_id: first.application_id,
                expected_connection_revision: 1,
                expected_connection_generation: 1,
                expected_credential_generation: 1,
                idempotency_key: format!("restart-unreadable-{unreadable_interaction}"),
                correlation_id: Uuid::new_v4(),
            },
            interaction_id: unreadable_interaction,
            interaction_digest: digest(211),
            request_digest: vec![212; 32],
            protected_create_result: ProtectedValue {
                ciphertext: vec![213; 48],
                key_version: 1,
            },
            expires_at: now + Duration::minutes(9),
            now: now + Duration::seconds(30),
        })
        .await
        .expect("seed restart interaction");
    sqlx::query(
        "UPDATE managed_provider_reauthorization_interactions
            SET interaction_digest_key_version=2 WHERE id=$1",
    )
    .bind(unreadable_interaction)
    .execute(&pool)
    .await
    .expect("simulate retired short-lived interaction key");
    sqlx::query(
        "UPDATE managed_reauthorization_create_results
            SET create_result_key_version=2 WHERE interaction_id=$1",
    )
    .bind(unreadable_interaction)
    .execute(&pool)
    .await
    .expect("simulate retired create-result key");

    let required = repository
        .required_key_versions()
        .await
        .expect("load long-lived managed credential inventory");
    assert_eq!(required, BTreeSet::from([1]));
    let runtime_two = SoftwareRuntimeProtector::new(
        "managed-matrix-deployment".to_owned(),
        2,
        RuntimeKeyMaterial::new([31; 32], [32; 32]),
        BTreeMap::new(),
    )
    .expect("Runtime version-two ring");
    let managed_one = SoftwareManagedCredentialProtector::new(
        "managed-matrix-deployment".to_owned(),
        1,
        ManagedCredentialKeyMaterial::new([41; 32]),
        BTreeMap::new(),
    )
    .expect("managed version-one ring");
    assert!(
        required.is_subset(&ManagedCredentialProtector::readable_key_versions(
            &managed_one
        ))
    );
    let runtime_two_cleanup = ManagedInteractionCleanupService::new(
        Arc::new(PostgresManagedConnectionRepository::new(database.clone())),
        RuntimeProtector::readable_key_versions(&runtime_two),
        RuntimeProtector::readable_key_versions(&runtime_two),
        Arc::new(FixedClock(now + Duration::seconds(31))),
    )
    .expect("production-shaped Runtime version-two cleanup wiring");
    assert_eq!(
        runtime_two_cleanup
            .cleanup(256)
            .await
            .expect("retain Runtime-readable version-two interaction"),
        0
    );
    let retained_status: String = sqlx::query_scalar(
        "SELECT status FROM managed_provider_reauthorization_interactions WHERE id=$1",
    )
    .bind(unreadable_interaction)
    .fetch_one(&pool)
    .await
    .expect("inspect Runtime-readable retained interaction");
    assert_eq!(retained_status, "awaiting_browser_binding");

    sqlx::query(
        "UPDATE managed_provider_credentials SET key_version=2 WHERE ciphertext IS NOT NULL",
    )
    .execute(&pool)
    .await
    .expect("advance long-lived managed credential timeline independently");
    let required_two = repository
        .required_key_versions()
        .await
        .expect("load version-two managed credential inventory");
    assert_eq!(required_two, BTreeSet::from([2]));
    let managed_two = SoftwareManagedCredentialProtector::new(
        "managed-matrix-deployment".to_owned(),
        2,
        ManagedCredentialKeyMaterial::new([42; 32]),
        BTreeMap::new(),
    )
    .expect("managed version-two ring");
    assert!(
        required_two.is_subset(&ManagedCredentialProtector::readable_key_versions(
            &managed_two
        ))
    );
    let runtime_one = SoftwareRuntimeProtector::new(
        "managed-matrix-deployment".to_owned(),
        1,
        RuntimeKeyMaterial::new([33; 32], [34; 32]),
        BTreeMap::new(),
    )
    .expect("Runtime version-one ring");
    let runtime_one_cleanup = ManagedInteractionCleanupService::new(
        Arc::new(PostgresManagedConnectionRepository::new(database.clone())),
        RuntimeProtector::readable_key_versions(&runtime_one),
        RuntimeProtector::readable_key_versions(&runtime_one),
        Arc::new(FixedClock(now + Duration::seconds(31))),
    )
    .expect("production-shaped Runtime version-one cleanup wiring");
    assert_eq!(
        runtime_one_cleanup
            .cleanup(256)
            .await
            .expect("terminalize Runtime-unreadable version-two interaction"),
        1
    );
    let restored_interaction: (String, i64, Option<Vec<u8>>, Option<OffsetDateTime>) =
        sqlx::query_as(
            "SELECT interaction.status,interaction.revision,
                    result.create_result_ciphertext,result.erased_at
               FROM managed_provider_reauthorization_interactions AS interaction
               JOIN managed_reauthorization_create_results AS result
                 ON result.interaction_id=interaction.id
              WHERE interaction.id=$1",
        )
        .bind(unreadable_interaction)
        .fetch_one(&pool)
        .await
        .expect("read restored interaction");
    assert_eq!(restored_interaction.0, "cancelled");
    assert_eq!(restored_interaction.2, Some(vec![213; 48]));
    assert!(restored_interaction.3.is_none());
    let restore_audit: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events
          WHERE target_id=$1
            AND action='managed_reauthorization.unreadable_key_terminalized'",
    )
    .bind(unreadable_interaction)
    .fetch_one(&pool)
    .await
    .expect("count restore terminalization audit");
    assert_eq!(restore_audit, 1);

    let unreadable_deadline = now + Duration::seconds(31);
    age_reauthorization_deadline(&pool, unreadable_interaction, unreadable_deadline).await;
    assert_eq!(
        repository
            .terminalize_expired_interactions(256, now + Duration::seconds(32))
            .await
            .expect("passively tombstone the due unreadable-key cancellation"),
        1
    );
    let unreadable_tombstone: (String, i64, Option<Vec<u8>>, Option<Vec<u8>>, bool) =
        sqlx::query_as(
            "SELECT interaction.status,interaction.revision,result.request_digest,
                    result.create_result_ciphertext,
                    result.erased_at=$2 AND result.erased_at>=result.expires_at
               FROM managed_provider_reauthorization_interactions AS interaction
               JOIN managed_reauthorization_create_results AS result
                 ON result.interaction_id=interaction.id
              WHERE interaction.id=$1",
        )
        .bind(unreadable_interaction)
        .bind(now + Duration::seconds(32))
        .fetch_one(&pool)
        .await
        .expect("inspect passively swept unreadable-key cancellation");
    assert_eq!(unreadable_tombstone.0, "cancelled");
    assert_eq!(unreadable_tombstone.1, restored_interaction.1);
    assert!(unreadable_tombstone.2.is_none());
    assert!(unreadable_tombstone.3.is_none());
    assert!(unreadable_tombstone.4);
    for attempt in [Duration::seconds(33), Duration::seconds(34)] {
        assert_create_replay(
            &reauthorizations,
            prepared_create_replay(
                &first,
                inventory_fixture.user_id,
                inventory_fixture.connection_id,
                1,
                1,
                1,
                Uuid::new_v4(),
                format!("restart-unreadable-{unreadable_interaction}"),
                212,
                250,
                unreadable_deadline,
                now + attempt,
            ),
            ManagedReauthorizationStatus::Cancelled,
            None,
        )
        .await;
    }

    sqlx::query(
        "UPDATE managed_provider_credentials SET key_version=1 WHERE ciphertext IS NOT NULL",
    )
    .execute(&pool)
    .await
    .expect("restore shared credential inventory fixture");

    // Ordinary expiration also converges continuously in bounded batches, even if nobody reads
    // the abandoned interactions again. Its cleanup is independent of listener/key readiness.
    let expired_interaction = Uuid::new_v4();
    reauthorizations
        .create(PreparedManagedReauthorizationCreate {
            capability: managed_capability_snapshot(),
            command: CreateManagedReauthorization {
                project_id: first.project_id,
                user_id: inventory_fixture.user_id,
                connection_id: inventory_fixture.connection_id,
                application_id: first.application_id,
                expected_connection_revision: 1,
                expected_connection_generation: 1,
                expected_credential_generation: 1,
                idempotency_key: format!("expired-sweep-{expired_interaction}"),
                correlation_id: Uuid::new_v4(),
            },
            interaction_id: expired_interaction,
            interaction_digest: digest(221),
            request_digest: vec![222; 32],
            protected_create_result: ProtectedValue {
                ciphertext: vec![223; 48],
                key_version: 1,
            },
            expires_at: now + Duration::minutes(9),
            now: now + Duration::seconds(30),
        })
        .await
        .expect("seed ordinary expired interaction");
    age_reauthorization_deadline(&pool, expired_interaction, now + Duration::seconds(31)).await;
    sqlx::query(
        r"WITH source AS (
             SELECT * FROM managed_provider_reauthorization_interactions WHERE id=$1
           )
           INSERT INTO managed_provider_reauthorization_interactions
             (id,project_id,project_public_id,connection_id,linked_identity_id,user_id,
              provider_configuration_id,provider_key,issuer,provider_kind,subject,client_id,secret_ref,
              secret_material_id,provider_egress_policy_revision,application_id,
              expected_connection_generation,expected_credential_generation,
              expected_connection_revision,project_security_revision,user_security_revision,
              identity_revision,provider_revision,managed_profile_revision,application_revision,
              assignment_security_revision,callback_url,adapter_key,adapter_capability_revision,
              supports_revocation,required_scopes,provider_pkce_required,oidc_nonce_required,
              interaction_digest,interaction_digest_key_version,revision,status,expires_at,created_at)
           SELECT md5('managed-expired-scale-' || series.value::text)::uuid,
                  source.project_id,source.project_public_id,source.connection_id,
                  source.linked_identity_id,source.user_id,source.provider_configuration_id,
                  source.provider_key,source.issuer,source.provider_kind,source.subject,
                  source.client_id,source.secret_ref,source.secret_material_id,
                  source.provider_egress_policy_revision,source.application_id,
                  source.expected_connection_generation,
                  source.expected_credential_generation,source.expected_connection_revision,
                  source.project_security_revision,source.user_security_revision,
                  source.identity_revision,source.provider_revision,source.managed_profile_revision,
                  source.application_revision,source.assignment_security_revision,
                  source.callback_url,source.adapter_key,source.adapter_capability_revision,
                  source.supports_revocation,source.required_scopes,source.provider_pkce_required,
                  source.oidc_nonce_required,
                  decode(md5('expired-' || series.value::text) ||
                         md5('expired-digest-' || series.value::text),'hex'),
                  1,1,'awaiting_browser_binding',source.expires_at,source.created_at
             FROM source CROSS JOIN generate_series(1,512) AS series(value)",
    )
    .bind(expired_interaction)
    .execute(&pool)
    .await
    .expect("seed expired sweep backlog larger than one batch");
    let mut expired_cleaned = 0_u64;
    let mut expired_batches = 0_u64;
    while expired_cleaned < 513 {
        let batch = repository
            .terminalize_expired_interactions(256, now + Duration::seconds(32))
            .await
            .expect("bounded ordinary expiration pass");
        assert!(batch > 0 && batch <= 256);
        expired_cleaned += batch;
        expired_batches += 1;
        assert_eq!(
            repository
                .required_key_versions()
                .await
                .expect("listener readiness inventory remains isolated"),
            BTreeSet::from([1])
        );
    }
    assert_eq!((expired_cleaned, expired_batches), (513, 3));
    let erased_expired: (
        String,
        Option<Vec<u8>>,
        Option<i32>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<OffsetDateTime>,
    ) = sqlx::query_as(
        "SELECT interaction.status,interaction.interaction_digest,
                interaction.interaction_digest_key_version,result.request_digest,
                result.create_result_ciphertext,result.erased_at
           FROM managed_provider_reauthorization_interactions interaction
           JOIN managed_reauthorization_create_results result ON result.interaction_id=interaction.id
          WHERE interaction.id=$1",
    )
    .bind(expired_interaction)
    .fetch_one(&pool)
    .await
    .expect("inspect ordinary expiration erasure");
    assert_eq!(erased_expired.0, "expired");
    assert!(erased_expired.1.is_none());
    assert!(erased_expired.2.is_none());
    assert!(erased_expired.3.is_none());
    assert!(erased_expired.4.is_none());
    assert!(erased_expired.5.is_some());

    // A restart backlog one row beyond the historical 4096 cap remains a short-term cleanup
    // concern, never global readiness. Seventeen bounded worker passes converge 4097 rows while
    // the exact long-lived credential inventory remains readable throughout.
    sqlx::query(
        r"WITH source AS (
             SELECT * FROM managed_provider_reauthorization_interactions WHERE id=$1
           )
           INSERT INTO managed_provider_reauthorization_interactions
             (id,project_id,project_public_id,connection_id,linked_identity_id,user_id,
              provider_configuration_id,provider_key,issuer,provider_kind,subject,client_id,secret_ref,
              secret_material_id,provider_egress_policy_revision,application_id,
              expected_connection_generation,expected_credential_generation,
              expected_connection_revision,project_security_revision,user_security_revision,
              identity_revision,provider_revision,managed_profile_revision,application_revision,
              assignment_security_revision,callback_url,adapter_key,adapter_capability_revision,
              supports_revocation,required_scopes,provider_pkce_required,oidc_nonce_required,
              interaction_digest,interaction_digest_key_version,revision,status,
              expires_at,created_at)
           SELECT md5('managed-restore-scale-' || series.value::text)::uuid,
                  source.project_id,source.project_public_id,source.connection_id,
                  source.linked_identity_id,source.user_id,source.provider_configuration_id,
                  source.provider_key,source.issuer,source.provider_kind,source.subject,
                  source.client_id,source.secret_ref,source.secret_material_id,
                  source.provider_egress_policy_revision,source.application_id,
                  source.expected_connection_generation,
                  source.expected_credential_generation,source.expected_connection_revision,
                  source.project_security_revision,source.user_security_revision,
                  source.identity_revision,source.provider_revision,source.managed_profile_revision,
                  source.application_revision,source.assignment_security_revision,
                  source.callback_url,source.adapter_key,source.adapter_capability_revision,
                  source.supports_revocation,source.required_scopes,source.provider_pkce_required,
                  source.oidc_nonce_required,
                  decode(md5(series.value::text) || md5('digest-' || series.value::text),'hex'),
                  9,1,'awaiting_browser_binding',$2,source.created_at
             FROM source CROSS JOIN generate_series(1,4097) AS series(value)",
    )
    .bind(unreadable_interaction)
    .bind(now + Duration::minutes(9))
    .execute(&pool)
    .await
    .expect("seed 4097-row restart cleanup backlog");
    assert_eq!(
        repository
            .required_key_versions()
            .await
            .expect("inventory stays credential-only during short-key backlog"),
        BTreeSet::from([1])
    );
    let mut cleaned = 0_u64;
    let mut batches = 0_u64;
    while cleaned < 4097 {
        let batch = repository
            .terminalize_unreadable_interactions(
                &BTreeSet::from([1]),
                &BTreeSet::from([1]),
                256,
                now + Duration::seconds(32 + i64::try_from(batches).expect("bounded batches")),
            )
            .await
            .expect("bounded restart cleanup pass");
        assert!(batch > 0 && batch <= 256);
        cleaned += batch;
        batches += 1;
    }
    assert_eq!(cleaned, 4097);
    assert_eq!(batches, 17);
    let remaining_unreadable: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM managed_provider_reauthorization_interactions
          WHERE status NOT IN ('completed','provider_exchange_failed','expired','cancelled')
            AND interaction_digest_key_version=9",
    )
    .fetch_one(&pool)
    .await
    .expect("count remaining unreadable restart interactions");
    assert_eq!(remaining_unreadable, 0);

    // By contrast, restart with a missing long-lived managed credential key remains
    // readiness-fatal independently of the Runtime short-term ring.
    let missing = SoftwareManagedCredentialProtector::new(
        "managed-matrix-deployment".to_owned(),
        2,
        ManagedCredentialKeyMaterial::new([43; 32]),
        BTreeMap::new(),
    )
    .expect("managed protector missing retained key");
    assert!(!required.is_subset(&ManagedCredentialProtector::readable_key_versions(&missing)));
    let restored = SoftwareManagedCredentialProtector::new(
        "managed-matrix-deployment".to_owned(),
        2,
        ManagedCredentialKeyMaterial::new([43; 32]),
        BTreeMap::from([(1, ManagedCredentialKeyMaterial::new([44; 32]))]),
    )
    .expect("managed protector with retained key");
    assert!(
        required.is_subset(&ManagedCredentialProtector::readable_key_versions(
            &restored
        ))
    );

    database
        .close()
        .await
        .expect("close managed matrix SeaORM pool");
    pool.close().await;
}

async fn prepared_handoff_for_project_graph_lock_test(
    authentication: &PostgresAuthenticationRepository,
    sessions: &PostgresSessionAuthorityRepository,
    seeded: &SeededAuthority,
    seed: u8,
    now: OffsetDateTime,
) -> (Uuid, CommitHandoffExchange) {
    let claimed = claim_provider_login(authentication, seeded, seed, now).await;
    let completion = completion_command(seeded, &claimed, seed, now);
    let handoff_ticket = completion.handoff_ticket.clone();
    let issued = sessions
        .complete_authenticated_identity(completion)
        .await
        .expect("complete lock-order callback fixture");
    let exchange_at = now + Duration::seconds(5);
    let preparation = sessions
        .prepare_handoff_exchange(PrepareHandoffExchange {
            project_id: seeded.project_id,
            application_id: seeded.application_id,
            handoff_ticket: handoff_ticket.clone(),
            application_pkce_challenge: "A".repeat(43),
            now: exchange_at,
        })
        .await
        .expect("prepare lock-order handoff fixture");
    (
        issued.user_id,
        CommitHandoffExchange {
            project_id: seeded.project_id,
            application_id: seeded.application_id,
            handoff_ticket,
            application_pkce_challenge: "A".repeat(43),
            preparation,
            binding_id: Uuid::new_v4(),
            projection_id: Uuid::new_v4(),
            application_session_id: Uuid::new_v4(),
            refresh_family_id: Uuid::new_v4(),
            refresh_generation_id: Uuid::new_v4(),
            refresh_token: digest(seed.wrapping_add(9)),
            allowed_clock_skew_seconds: 60,
            now: exchange_at,
        },
    )
}

async fn wait_for_project_graph_waiter(pool: &PgPool) {
    for _ in 0..300 {
        let waiting: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                 SELECT 1 FROM pg_locks
                  WHERE locktype = 'advisory' AND NOT granted
             )",
        )
        .fetch_one(pool)
        .await
        .expect("inspect Project graph advisory waiters");
        if waiting {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("repository writer never waited behind the Project graph lock");
}

async fn wait_for_graph_holder_blocked_on_authority_row(pool: &PgPool) {
    for _ in 0..300 {
        let observed: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                 SELECT 1
                   FROM pg_locks graph_lock
                   JOIN pg_locks row_wait
                     ON row_wait.pid=graph_lock.pid AND NOT row_wait.granted
                  WHERE graph_lock.locktype='advisory' AND graph_lock.granted
                    AND row_wait.locktype IN ('transactionid','tuple')
             )",
        )
        .fetch_one(pool)
        .await
        .expect("inspect merge graph holder blocked on authority row");
        if observed {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("real merge never held the Project graph while waiting for authority rows");
}

async fn lock_merge_users(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    first: Uuid,
    second: Uuid,
) {
    let mut user_ids = [first, second];
    user_ids.sort_unstable();
    for user_id in user_ids {
        sqlx::query("SELECT id FROM project_users WHERE id=$1 FOR UPDATE")
            .bind(user_id)
            .execute(&mut **transaction)
            .await
            .expect("externally lock merge authority user");
    }
}

async fn create_merge_winner(
    authentication: &PostgresAuthenticationRepository,
    sessions: &PostgresSessionAuthorityRepository,
    pool: &PgPool,
    seeded: &SeededAuthority,
    seed: u8,
    subject: &str,
    now: OffsetDateTime,
) -> (Uuid, Uuid) {
    let claimed = claim_provider_login(authentication, seeded, seed, now).await;
    let mut completion = completion_command(seeded, &claimed, seed, now);
    let AuthenticatedIdentityEvidence::Provider(identity) = &mut completion.evidence;
    identity.subject = ProviderSubject::parse(subject.to_owned()).expect("merge winner subject");
    let issued = sessions
        .complete_authenticated_identity(completion)
        .await
        .expect("complete merge winner identity");
    let identity_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM linked_identities
          WHERE project_id=$1 AND user_id=$2 AND issuer='https://issuer.example'
            AND subject=$3 AND status='active'",
    )
    .bind(seeded.project_id)
    .bind(issued.user_id)
    .bind(subject)
    .fetch_one(pool)
    .await
    .expect("load merge winner identity");
    (issued.user_id, identity_id)
}

#[allow(clippy::too_many_arguments)]
fn prepared_merge_for_lock_test(
    seeded: &SeededAuthority,
    winner_user_id: Uuid,
    winner_identity_id: Uuid,
    loser_user_id: Uuid,
    loser_identity_id: Uuid,
    intent_id: Uuid,
    idempotency_key: &str,
    handle_seed: u8,
) -> PreparedIdentityMutationCreate {
    let authority = IdentityMutationProofAuthoritySelection::Provider {
        application_id: seeded.application_id,
        provider_configuration_id: seeded.provider_id,
    };
    PreparedIdentityMutationCreate {
        command: CreateIdentityMutation {
            project_id: seeded.project_id,
            operation: IdentityMutationCreateOperation::Merge {
                winner: ExpectedUser {
                    user_id: winner_user_id,
                    expected_user_revision: 1,
                    expected_user_security_revision: 1,
                },
                winner_identity: ExpectedIdentity {
                    identity_kind: IdentityKind::Provider,
                    identity_id: winner_identity_id,
                    expected_identity_revision: 1,
                },
                loser: ExpectedUser {
                    user_id: loser_user_id,
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
                        identity_id: winner_identity_id,
                        expected_identity_revision: 1,
                    },
                ),
                sessions: IdentityMutationSessionsDisposition::LoserRevoked,
                bindings: IdentityMutationBindingsDisposition::WinnerPreferred,
            },
            idempotency_key: idempotency_key.to_owned(),
            correlation_id: Uuid::new_v4(),
        },
        provider_capabilities: IdentityMutationProviderCapabilities::reviewed(),
        runtime_base: "https://runtime.example/".to_owned(),
        intent_id,
        hosted_handle_digest: digest(handle_seed),
        request_digest: vec![handle_seed.wrapping_add(1); 32],
        protected_create_result: ProtectedValue {
            ciphertext: vec![handle_seed.wrapping_add(2); 41],
            key_version: 1,
        },
        created_at: OffsetDateTime::UNIX_EPOCH,
        expires_at: OffsetDateTime::UNIX_EPOCH,
    }
}

#[allow(clippy::too_many_arguments)]
async fn prove_merge_owner(
    repository: &PostgresIdentityMutationRepository,
    seeded: &SeededAuthority,
    current: crate::application::IdentityMutationRecord,
    slot_id: Uuid,
    handle_seed: u8,
    proof_seed: u8,
    subject: &str,
) -> crate::application::IdentityMutationRecord {
    repository
        .start_provider(
            current.id,
            slot_id,
            &digest(handle_seed),
            &digest(handle_seed.wrapping_add(3)),
            &digest(handle_seed.wrapping_add(4)),
            current.revision,
            digest(proof_seed),
            digest(proof_seed.wrapping_add(1)),
            Some(ProtectedValue {
                ciphertext: vec![proof_seed.wrapping_add(2); 17],
                key_version: 1,
            }),
            ProtectedValue {
                ciphertext: vec![proof_seed.wrapping_add(3); 41],
                key_version: 1,
            },
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .expect("start real merge owner proof");
    let claimed = repository
        .claim_provider_callback(
            current.id,
            slot_id,
            &seeded.project_public_id,
            &seeded.provider_key,
            &digest(proof_seed),
            &digest(handle_seed.wrapping_add(3)),
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .expect("claim real merge owner proof");
    let ClaimIdentityMutationProvider::Claimed(claimed) = claimed else {
        panic!("fresh merge owner callback must be claimed");
    };
    repository
        .complete_provider_callback(PreparedIdentityMutationProviderCompletion {
            claimed,
            proof_slot_id: slot_id,
            observation: ProviderProofObservation {
                issuer: "https://issuer.example".to_owned(),
                subject: subject.to_owned(),
                display_name: None,
                picture_url: None,
            },
            candidate_evidence: None,
            receipt_id: Uuid::new_v4(),
            receipt_digest: digest(proof_seed.wrapping_add(4)),
            now: OffsetDateTime::UNIX_EPOCH,
        })
        .await
        .expect("complete real merge owner proof")
}

#[allow(clippy::too_many_arguments)]
async fn ready_merge_confirmation(
    repository: &PostgresIdentityMutationRepository,
    seeded: &SeededAuthority,
    winner_user_id: Uuid,
    winner_identity_id: Uuid,
    winner_subject: &str,
    loser_user_id: Uuid,
    loser_identity_id: Uuid,
    loser_subject: &str,
    idempotency_key: &str,
    handle_seed: u8,
) -> (Uuid, PreparedIdentityMutationConfirmation) {
    let intent_id = Uuid::new_v4();
    let created = repository
        .create(prepared_merge_for_lock_test(
            seeded,
            winner_user_id,
            winner_identity_id,
            loser_user_id,
            loser_identity_id,
            intent_id,
            idempotency_key,
            handle_seed,
        ))
        .await
        .expect("create real merge intent");
    let CreateIdentityMutationResult::Created(_) = created else {
        panic!("fresh lock-order merge must be created");
    };
    let bound = repository
        .bind_browser(
            &digest(handle_seed),
            &digest(handle_seed.wrapping_add(3)),
            &digest(handle_seed.wrapping_add(4)),
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .expect("bind real merge Hosted browser");
    let winner_slot = bound
        .slots
        .iter()
        .find(|slot| slot.role == IdentityMutationSlotRole::WinnerOwner)
        .expect("real merge winner slot")
        .id;
    let loser_slot = bound
        .slots
        .iter()
        .find(|slot| slot.role == IdentityMutationSlotRole::LoserOwner)
        .expect("real merge loser slot")
        .id;
    let winner_proved = prove_merge_owner(
        repository,
        seeded,
        bound,
        winner_slot,
        handle_seed,
        handle_seed.wrapping_add(5),
        winner_subject,
    )
    .await;
    let loser_proved = prove_merge_owner(
        repository,
        seeded,
        winner_proved,
        loser_slot,
        handle_seed,
        handle_seed.wrapping_add(10),
        loser_subject,
    )
    .await;
    let ready = repository
        .confirm_ready(
            intent_id,
            &digest(handle_seed),
            &digest(handle_seed.wrapping_add(3)),
            &digest(handle_seed.wrapping_add(4)),
            loser_proved.revision,
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .expect("mark real merge ready");
    let preparation = repository
        .prepare_control_confirmation(
            seeded.project_id,
            intent_id,
            ready.revision,
            IdentityMutationKind::Merge,
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .expect("prepare real merge control confirmation");
    assert!(preparation.candidate_evidence.is_none());
    (
        intent_id,
        PreparedIdentityMutationConfirmation {
            project_id: seeded.project_id,
            intent_id,
            expected_intent_revision: ready.revision,
            expected_kind: IdentityMutationKind::Merge,
            candidate: None,
            correlation_id: Uuid::new_v4(),
            now: OffsetDateTime::UNIX_EPOCH,
        },
    )
}

async fn assert_merge_graph(
    pool: &PgPool,
    project_id: Uuid,
    winner_user_id: Uuid,
    loser_user_id: Uuid,
    loser_identity_id: Uuid,
    intent_id: Uuid,
) {
    let winner_status: String = sqlx::query_scalar("SELECT status FROM project_users WHERE id=$1")
        .bind(winner_user_id)
        .fetch_one(pool)
        .await
        .expect("read merge winner");
    assert_eq!(winner_status, "active");
    let loser: (String, Option<Uuid>) =
        sqlx::query_as("SELECT status,merged_into_user_id FROM project_users WHERE id=$1")
            .bind(loser_user_id)
            .fetch_one(pool)
            .await
            .expect("read merge loser");
    assert_eq!(loser, ("merged".to_owned(), Some(winner_user_id)));
    let identity_owner: (Uuid, String, i64) = sqlx::query_as(
        "SELECT user_id,status,identity_revision FROM linked_identities WHERE id=$1",
    )
    .bind(loser_identity_id)
    .fetch_one(pool)
    .await
    .expect("read moved loser identity");
    assert_eq!(identity_owner, (winner_user_id, "active".to_owned(), 2));
    let tombstone: (Uuid, Uuid, Uuid) = sqlx::query_as(
        "SELECT loser_user_id,winner_user_id,identity_mutation_intent_id
           FROM project_user_merge_tombstones WHERE project_id=$1 AND loser_user_id=$2",
    )
    .bind(project_id)
    .bind(loser_user_id)
    .fetch_one(pool)
    .await
    .expect("read exact merge tombstone");
    assert_eq!(
        tombstone,
        (loser_user_id, winner_user_id, intent_id),
        "merge tombstone must preserve the exact authority decision"
    );
    let intent: (String, i64) = sqlx::query_as(
        "SELECT status,
                (SELECT count(*) FROM identity_proof_receipts receipt
                  WHERE receipt.intent_id=intent.id AND receipt.status<>'consumed')
           FROM identity_mutation_intents intent WHERE intent.id=$1",
    )
    .bind(intent_id)
    .fetch_one(pool)
    .await
    .expect("read completed merge and receipt authority");
    assert_eq!(intent, ("completed".to_owned(), 0));
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one PostgreSQL fixture proves both historical merge lock cycles end to end"
)]
async fn project_graph_lock_serializes_merge_against_handoff_and_refresh_writers() {
    let Some((_container, url)) = start_postgres().await else {
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(16)
        .connect(&url)
        .await
        .expect("lock-order PostgreSQL pool");
    MIGRATOR.run(&pool).await.expect("lock-order migrations");
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .expect("whole-second lock-order time");
    let handoff_project = seed_authority(&pool, now, "lockhandoff").await;
    let refresh_project = seed_authority(&pool, now, "lockrefresh").await;
    let database = Database::connect(&url)
        .await
        .expect("lock-order SeaORM pool");
    let authentication = PostgresAuthenticationRepository::new(database.clone());
    let sessions = PostgresSessionAuthorityRepository::new(database.clone());
    let mutation_protector = Arc::new(
        SoftwareRuntimeProtector::new(
            "lock-order-test".to_owned(),
            1,
            RuntimeKeyMaterial::new([91; 32], [92; 32]),
            BTreeMap::new(),
        )
        .expect("lock-order Runtime protector"),
    );
    let mutations = PostgresIdentityMutationRepository::new(
        database.clone(),
        "runtime-1".to_owned(),
        Uuid::nil(),
        mutation_protector,
        Vec::new(),
    );

    // Construct a real, ready Merge aggregate through the production lifecycle. An external row
    // lock pauses confirm_control only after it owns the graph lock. The real handoff writer must
    // then become an observable advisory waiter, proving it cannot take the loser user first.
    let (handoff_loser_id, handoff_command) = prepared_handoff_for_project_graph_lock_test(
        &authentication,
        &sessions,
        &handoff_project,
        20,
        now,
    )
    .await;
    let handoff_loser_identity_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM linked_identities
          WHERE project_id=$1 AND user_id=$2 AND issuer='https://issuer.example'
            AND subject='shared-subject' AND status='active'",
    )
    .bind(handoff_project.project_id)
    .bind(handoff_loser_id)
    .fetch_one(&pool)
    .await
    .expect("load handoff merge loser identity");
    let handoff_winner_subject = "lock-handoff-winner";
    let (handoff_winner_id, handoff_winner_identity_id) = create_merge_winner(
        &authentication,
        &sessions,
        &pool,
        &handoff_project,
        40,
        handoff_winner_subject,
        now,
    )
    .await;
    let (handoff_intent_id, handoff_confirmation) = ready_merge_confirmation(
        &mutations,
        &handoff_project,
        handoff_winner_id,
        handoff_winner_identity_id,
        handoff_winner_subject,
        handoff_loser_id,
        handoff_loser_identity_id,
        "shared-subject",
        "lock-order-handoff-merge",
        100,
    )
    .await;
    let handoff_binding_id = handoff_command.binding_id;
    let handoff_session_id = handoff_command.application_session_id;
    let handoff_family_id = handoff_command.refresh_family_id;
    let mut handoff_authority_lock = pool
        .begin()
        .await
        .expect("begin external handoff merge authority lock");
    lock_merge_users(
        &mut handoff_authority_lock,
        handoff_winner_id,
        handoff_loser_id,
    )
    .await;
    let handoff_merger = {
        let mutations = mutations.clone();
        tokio::spawn(async move { mutations.confirm_control(handoff_confirmation).await })
    };
    wait_for_graph_holder_blocked_on_authority_row(&pool).await;
    let handoff_writer = {
        let sessions = sessions.clone();
        tokio::spawn(async move { sessions.commit_handoff_exchange(handoff_command).await })
    };
    wait_for_project_graph_waiter(&pool).await;
    handoff_authority_lock
        .commit()
        .await
        .expect("release handoff merge authority rows");
    let handoff_merge = tokio::time::timeout(std::time::Duration::from_secs(10), handoff_merger)
        .await
        .expect("real handoff-side merge completes without deadlock")
        .expect("real handoff-side merge task joins")
        .expect("real handoff-side merge wins without Persistence/40P01");
    assert_eq!(handoff_merge.status, IdentityMutationStatus::Completed);
    let handoff_result = tokio::time::timeout(std::time::Duration::from_secs(10), handoff_writer)
        .await
        .expect("handoff writer completes without deadlock")
        .expect("handoff writer task joins");
    assert!(
        matches!(
            handoff_result,
            Err(ApplicationError::RevisionConflict | ApplicationError::InvalidTransition)
        ),
        "merge must beat handoff one-way without Persistence/40P01: {handoff_result:?}"
    );
    assert_merge_graph(
        &pool,
        handoff_project.project_id,
        handoff_winner_id,
        handoff_loser_id,
        handoff_loser_identity_id,
        handoff_intent_id,
    )
    .await;
    let handoff_artifacts: (i64, i64, i64) = sqlx::query_as(
        "SELECT
           (SELECT count(*) FROM application_user_bindings WHERE id=$1),
           (SELECT count(*) FROM application_sessions WHERE id=$2),
           (SELECT count(*) FROM refresh_families WHERE id=$3)",
    )
    .bind(handoff_binding_id)
    .bind(handoff_session_id)
    .bind(handoff_family_id)
    .fetch_one(&pool)
    .await
    .expect("count losing handoff artifacts");
    assert_eq!(
        handoff_artifacts,
        (0, 0, 0),
        "losing handoff must create no binding, session, or refresh family"
    );

    // Repeat the same real Merge window against a real prepared refresh rotation. This time the
    // loser already owns a committed session/family. Merge must revoke them according to the
    // frozen LoserRevoked disposition before rotation can create a successor.
    let (refresh_loser_id, refresh_handoff) = prepared_handoff_for_project_graph_lock_test(
        &authentication,
        &sessions,
        &refresh_project,
        60,
        now,
    )
    .await;
    let refresh_loser_identity_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM linked_identities
          WHERE project_id=$1 AND user_id=$2 AND issuer='https://issuer.example'
            AND subject='shared-subject' AND status='active'",
    )
    .bind(refresh_project.project_id)
    .bind(refresh_loser_id)
    .fetch_one(&pool)
    .await
    .expect("load refresh merge loser identity");
    let refresh_token = refresh_handoff.refresh_token.clone();
    let issued_session = sessions
        .commit_handoff_exchange(refresh_handoff)
        .await
        .expect("commit refresh lock-order fixture");
    let prepared_refresh = sessions
        .prepare_refresh_rotation(PrepareRefreshRotation {
            project_id: refresh_project.project_id,
            application_id: refresh_project.application_id,
            presented_token: refresh_token.clone(),
            now: now + Duration::seconds(6),
        })
        .await
        .expect("prepare refresh lock-order fixture");
    let RefreshPreparationResult::Ready(prepared_refresh) = prepared_refresh else {
        panic!("fresh current token must prepare for rotation");
    };
    // Keep the prepared rotation real while excluding projection fan-out from this lock-order
    // regression. Rotation has already frozen its active binding authority; after Merge wins it
    // must stop at the revoked session/family before this independently disabled binding matters.
    sqlx::query(
        "UPDATE application_user_bindings
            SET status='disabled',binding_revision=binding_revision+1,updated_at=$2
          WHERE id=$1",
    )
    .bind(issued_session.binding_id)
    .bind(now + Duration::seconds(6))
    .execute(&pool)
    .await
    .expect("isolate refresh lock-order fixture from active projection fan-out");
    let successor_generation_id = Uuid::new_v4();
    let rotate_command = RotateRefreshToken {
        project_id: refresh_project.project_id,
        application_id: refresh_project.application_id,
        presented_token: refresh_token,
        preparation: *prepared_refresh,
        successor_generation_id,
        successor_token: digest(70),
        now: now + Duration::seconds(7),
    };
    let refresh_winner_subject = "lock-refresh-winner";
    let (refresh_winner_id, refresh_winner_identity_id) = create_merge_winner(
        &authentication,
        &sessions,
        &pool,
        &refresh_project,
        80,
        refresh_winner_subject,
        now,
    )
    .await;
    let (refresh_intent_id, refresh_confirmation) = ready_merge_confirmation(
        &mutations,
        &refresh_project,
        refresh_winner_id,
        refresh_winner_identity_id,
        refresh_winner_subject,
        refresh_loser_id,
        refresh_loser_identity_id,
        "shared-subject",
        "lock-order-refresh-merge",
        120,
    )
    .await;
    let mut refresh_authority_lock = pool
        .begin()
        .await
        .expect("begin external refresh merge authority lock");
    lock_merge_users(
        &mut refresh_authority_lock,
        refresh_winner_id,
        refresh_loser_id,
    )
    .await;
    let refresh_merger = {
        let mutations = mutations.clone();
        tokio::spawn(async move { mutations.confirm_control(refresh_confirmation).await })
    };
    wait_for_graph_holder_blocked_on_authority_row(&pool).await;
    let refresh_writer = {
        let sessions = sessions.clone();
        tokio::spawn(async move { sessions.rotate_refresh_token(rotate_command).await })
    };
    wait_for_project_graph_waiter(&pool).await;
    refresh_authority_lock
        .commit()
        .await
        .expect("release refresh merge authority rows");
    let refresh_merge = tokio::time::timeout(std::time::Duration::from_secs(10), refresh_merger)
        .await
        .expect("real refresh-side merge completes without deadlock")
        .expect("real refresh-side merge task joins")
        .expect("real refresh-side merge wins without Persistence/40P01");
    assert_eq!(refresh_merge.status, IdentityMutationStatus::Completed);
    let refresh_result = tokio::time::timeout(std::time::Duration::from_secs(10), refresh_writer)
        .await
        .expect("refresh writer completes without deadlock")
        .expect("refresh writer task joins");
    assert!(
        matches!(refresh_result, Err(ApplicationError::InvalidTransition)),
        "merge must beat refresh one-way without Persistence/40P01: {refresh_result:?}"
    );
    assert_merge_graph(
        &pool,
        refresh_project.project_id,
        refresh_winner_id,
        refresh_loser_id,
        refresh_loser_identity_id,
        refresh_intent_id,
    )
    .await;
    let session_status: (String, i64, Option<OffsetDateTime>) = sqlx::query_as(
        "SELECT status,session_revision,revoked_at FROM application_sessions WHERE id=$1",
    )
    .bind(issued_session.application_session_id)
    .fetch_one(&pool)
    .await
    .expect("load merge-revoked refresh session");
    assert_eq!(session_status.0, "revoked");
    assert_eq!(session_status.1, 2);
    assert!(session_status.2.is_some());
    let family_status: (String, i64, String, Option<OffsetDateTime>) = sqlx::query_as(
        "SELECT status,family_revision,revocation_reason,revoked_at
           FROM refresh_families WHERE id=$1",
    )
    .bind(issued_session.refresh_family_id)
    .fetch_one(&pool)
    .await
    .expect("load merge-revoked refresh family");
    assert_eq!(family_status.0, "revoked");
    assert_eq!(family_status.1, 2);
    assert_eq!(family_status.2, "owner_invalidated");
    assert!(family_status.3.is_some());
    let successor_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM refresh_token_generations
          WHERE family_id=$1 AND (id=$2 OR generation>1)",
    )
    .bind(issued_session.refresh_family_id)
    .bind(successor_generation_id)
    .fetch_one(&pool)
    .await
    .expect("count losing refresh successors");
    assert_eq!(
        successor_count, 0,
        "losing refresh must create no successor generation"
    );

    database
        .close()
        .await
        .expect("close lock-order SeaORM pool");
    pool.close().await;
}
