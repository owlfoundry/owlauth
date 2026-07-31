use std::env;

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
    session_authority::PostgresSessionAuthorityRepository,
};
use crate::{
    application::{
        AdmittedProviderMethod, AuthenticationRepository, BindBrowserLogout, BindHostedBrowser,
        ClaimProviderCallback, CommitHandoffExchange, CompleteProviderCallback,
        ConfirmBrowserLogout, CreateLoginTransaction, LoginRevisionSnapshot, PrepareBrowserLogout,
        PrepareHandoffExchange, PrepareRefreshRotation, ProtectedValue, RecoverProviderExchanges,
        RefreshPreparationResult, RefreshRotationResult, RotateRefreshToken, SelectProviderMethod,
        SessionAuthorityRepository, VerifiedProviderIdentity, VersionedDigest,
    },
    domain::{ProfileDisplayName, ProfilePictureUrl, ProviderIssuer, ProviderSubject},
};

const POSTGRES_PORT: u16 = 5432;
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

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

async fn claim_provider_login(
    authentication: &PostgresAuthenticationRepository,
    seeded: &SeededAuthority,
    seed: u8,
    now: OffsetDateTime,
) -> crate::application::ClaimedProviderExchange {
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
                method_key: seeded.provider_key.clone(),
                provider_id: seeded.provider_id,
                display_name: "OIDC".to_owned(),
                issuer: "https://issuer.example".to_owned(),
                provider_revision: 1,
                assignment_security_revision: 1,
            }],
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
        .expect("select provider");
    authentication
        .claim_provider_callback(ClaimProviderCallback {
            project_public_id: seeded.project_public_id.clone(),
            provider_key: seeded.provider_key.clone(),
            upstream_state: digest(seed + 4),
            browser_binding: digest(seed + 2),
            now: now + Duration::seconds(3),
        })
        .await
        .expect("claim callback")
}

fn completion_command(
    seeded: &SeededAuthority,
    claimed: &crate::application::ClaimedProviderExchange,
    seed: u8,
    now: OffsetDateTime,
) -> CompleteProviderCallback {
    CompleteProviderCallback {
        project_id: seeded.project_id,
        transaction_id: claimed.transaction.id,
        expected_transaction_revision: claimed.transaction.transaction_revision,
        identity: VerifiedProviderIdentity {
            issuer: ProviderIssuer::parse("https://issuer.example".to_owned()).expect("issuer"),
            subject: ProviderSubject::parse("shared-subject".to_owned()).expect("subject"),
            display_name: Some(ProfileDisplayName::parse("Ada".to_owned()).expect("display name")),
            picture_url: None,
        },
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

    let database = Database::connect(&url).await.expect("SeaORM test pool");
    let authentication = PostgresAuthenticationRepository::new(database.clone());
    let sessions = PostgresSessionAuthorityRepository::new(database.clone());
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
                method_key: seeded.provider_key.clone(),
                provider_id: seeded.provider_id,
                display_name: "OIDC".to_owned(),
                issuer: "https://issuer.example".to_owned(),
                provider_revision: 1,
                assignment_security_revision: 1,
            }],
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
            project_public_id: seeded.project_public_id.clone(),
            provider_key: "oidc-main".to_owned(),
            upstream_state: digest(5),
            browser_binding: digest(3),
            now: now + Duration::seconds(3),
        })
        .await
        .expect("claim callback");

    let browser_session_id = Uuid::new_v4();
    let handoff_id = Uuid::new_v4();
    let issued = sessions
        .complete_provider_callback(CompleteProviderCallback {
            project_id: seeded.project_id,
            transaction_id: login.id,
            expected_transaction_revision: claimed.transaction.transaction_revision,
            identity: VerifiedProviderIdentity {
                issuer: ProviderIssuer::parse("https://issuer.example".to_owned()).expect("issuer"),
                subject: ProviderSubject::parse("subject-1".to_owned()).expect("subject"),
                display_name: Some(
                    ProfileDisplayName::parse("Ada".to_owned()).expect("display name"),
                ),
                picture_url: Some(
                    ProfilePictureUrl::parse("https://cdn.example/ada.png".to_owned())
                        .expect("picture URL"),
                ),
            },
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

    let identity_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM linked_identities
         WHERE project_id = $1 AND issuer = 'https://issuer.example' AND subject = 'subject-1'",
    )
    .bind(seeded.project_id)
    .fetch_one(&pool)
    .await
    .expect("count identities");
    assert_eq!(identity_count, 1);
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
    assert_eq!(primary_identity, Some(linked_identity));

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
                method_key: seeded.provider_key.clone(),
                provider_id: seeded.provider_id,
                display_name: "OIDC".to_owned(),
                issuer: "https://issuer.example".to_owned(),
                provider_revision: 1,
                assignment_security_revision: 1,
            }],
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
    let exchange = CommitHandoffExchange {
        preparation: fresh_preparation,
        binding_id: Uuid::new_v4(),
        projection_id: Uuid::new_v4(),
        application_session_id: Uuid::new_v4(),
        refresh_family_id: Uuid::new_v4(),
        refresh_generation_id: Uuid::new_v4(),
        ..stale_exchange
    };
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
    let refresh_a = RotateRefreshToken {
        project_id: seeded.project_id,
        application_id: seeded.application_id,
        presented_token: digest(12),
        preparation: *refresh_preparation,
        successor_generation_id: Uuid::new_v4(),
        successor_token: digest(13),
        now: refresh_at,
    };
    let refresh_b = RotateRefreshToken {
        successor_generation_id: Uuid::new_v4(),
        successor_token: digest(14),
        ..refresh_a.clone()
    };
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
    let sessions = PostgresSessionAuthorityRepository::new(database.clone());
    let first_claim = claim_provider_login(&authentication, &first_project, 21, now).await;
    let competing_claim = claim_provider_login(&authentication, &first_project, 41, now).await;
    let other_project_claim = claim_provider_login(&authentication, &second_project, 61, now).await;

    let (first, competing) = tokio::join!(
        sessions.complete_provider_callback(completion_command(
            &first_project,
            &first_claim,
            21,
            now,
        )),
        sessions.complete_provider_callback(completion_command(
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
        .complete_provider_callback(completion_command(
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
             application_policy_revision, canonical_digest, document)
         VALUES ($1, $2, $3, $4, $5, 'owlauth.user.v1', 1, 1, 1, 1, $6, $7)",
    )
    .bind(Uuid::new_v4())
    .bind(first_project.project_id)
    .bind(binding_id)
    .bind(first_project.application_id)
    .bind(first.user_id)
    .bind(vec![1_u8; 32])
    .bind(serde_json::json!({"stale": true}))
    .execute(&pool)
    .await
    .expect("insert existing projection");
    let profile_change_claim =
        claim_provider_login(&authentication, &secondary_registration, 81, now).await;
    let mut profile_change =
        completion_command(&secondary_registration, &profile_change_claim, 81, now);
    profile_change.identity.display_name =
        Some(ProfileDisplayName::parse("Grace".to_owned()).expect("changed display name"));
    sessions
        .complete_provider_callback(profile_change)
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
         SET document = '{\"stale\":true}'::jsonb, canonical_digest = $2
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
    assert_eq!(digest_only_repair.projection_revision, 3);
    assert_eq!(
        digest_only_repair.projection_document["display_name"],
        "Grace"
    );

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
        .complete_provider_callback(invalid)
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
        .complete_provider_callback(stale_revision)
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
