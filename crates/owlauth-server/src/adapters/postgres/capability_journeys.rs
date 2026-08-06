use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use crc::{CRC_32_ISO_HDLC, Crc};
use owlauth_key_provider::{
    ConfigurationSecretSealer, DestroyOutcome, DestroySigningKeyRequest, InspectSigningKeyRequest,
    MaterialKind, OpaqueHandle, ProviderError, ProviderErrorClass, ProviderFormatVersion,
    ProviderFormatVersions, ProviderId, ProvisionSigningKeyRequest, ProvisionedSigningKey,
    RetryClassification, SigningAlgorithm, SigningKeyProvisioner, SigningProviderCapabilities,
    SigningPublicKey,
};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, DbBackend, EntityTrait,
    IntoActiveModel, QueryFilter, QuerySelect, Statement, TransactionTrait,
};
use sha2::{Digest, Sha256};
use sqlx::{Connection, PgConnection};
use testcontainers::{
    GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor, wait::LogWaitStrategy},
    runners::AsyncRunner,
};
use tokio::time::timeout;
use tower::ServiceExt;
use uuid::Uuid;

use super::*;
use crate::{
    adapters::{
        client_key_security::{ClientKeyDigestMaterial, SoftwareClientKeyRing},
        custody::SoftwareCustodyProvider,
        migrations::{SchemaError, prepare_schema, verify_url},
        postgres::{
            client_api::RuntimeClientEmailLookupDigester,
            client_key::PostgresClientKeyRepository,
            client_readiness::PostgresClientDigestReadinessAdapter,
            custody::{
                MaterialOwnerKind, MaterialPurpose, ProtectedMaterialRepository,
                finalize_pending_material, lock_material_inventory,
            },
            custody_import::PostgresCustodyImporter,
            email_control::PostgresEmailControlRepository,
            entity::{
                application, application_provider_assignment, application_publishable_key,
                audit_event, control_idempotency_record, key_provisioning_operation,
                key_state_event, project, project_signing_key, project_user, protected_material,
                provider_configuration, provider_secret_operation, runtime_publication_lease,
            },
            provider_egress::PostgresProviderEgressPolicyRepository,
            provisioning::PostgresProvisioningAdapter,
            readiness::PostgresReadinessAdapter,
            unit_of_work::ProjectUnitOfWork,
        },
        protected_runtime::PostgresProtectedRuntimeCustody,
        runtime_security::{RuntimeKeyMaterial, SoftwareRuntimeProtector},
        software_store::EncryptedFileStore,
        system::{Sha256RequestDigester, SystemClock, SystemEntropy},
    },
    application::{
        AcknowledgeProjectClientKeyDelivery, ApplicationError, ApplicationProvisioningPort,
        ClientDigestReadinessService, ClientEmailLookupDigester, ClientKeyLifecycleService,
        CompleteIdempotency, ConfigurationSecretProvisioner, ConfigurationSecretStore,
        CreateApplication, CreateProject, CreateProjectClientKey, CreateProjectClientKeyResult,
        CreateProvider, CreateSmtpConfiguration, EmailControlService, NewProject, PrepareProvider,
        PreparedProvider, PreparedSigningKey, ProjectProvisioningPort, ProjectRecord,
        ProviderEgressPolicyPort, ProviderProvisioningPort, ProvisionedProtectedSigningMaterial,
        ProvisioningInfrastructure, ProvisioningOperationState, ProvisioningService,
        ReadinessService, ReconcileDeploymentSmtpGeneration, ReplaceApplicationConfiguration,
        RequestDigester, RevokeProjectClientKey, RuntimeProtector, SignerStore,
        SigningKeyProvisioningPort, SigningProviderAction, SigningProviderCall,
        SigningProviderLease, SmtpControlTlsMode, SmtpCredentialResolver, UpdateProject,
        UpdateProjectPolicy,
    },
    composition::{ServerError, build_http_capabilities, validate_provider_readiness},
    config::{MigrationMode, PlaneMode, ServerConfig},
    domain::{ApplicationType, ProviderEgressMode, ProviderEgressPolicy, ProviderKind},
    http::{build_routers_with_capabilities, build_routers_with_runtime_incarnation},
    providers::ProviderRegistrations,
};

const POSTGRES_PORT: u16 = 5432;

fn sea_orm_sqlstate(error: &sea_orm::DbErr) -> Option<String> {
    let sqlx_error = match error {
        sea_orm::DbErr::Exec(sea_orm::RuntimeErr::SqlxError(error))
        | sea_orm::DbErr::Query(sea_orm::RuntimeErr::SqlxError(error)) => error.as_ref(),
        _ => return None,
    };
    match sqlx_error {
        sqlx::Error::Database(error) => error.code().map(std::borrow::Cow::into_owned),
        _ => None,
    }
}

async fn wait_for_sqlx_backend_blocked_by(
    observer: &mut PgConnection,
    blocker_pid: i32,
    label: &str,
) -> i32 {
    timeout(Duration::from_secs(10), async {
        loop {
            if let Some(blocked_pid) = sqlx::query_scalar::<_, i32>(
                "SELECT blocked.pid FROM pg_stat_activity blocked
                 WHERE blocked.datname=current_database()
                   AND blocked.wait_event_type='Lock'
                   AND $1=ANY(pg_blocking_pids(blocked.pid))
                 ORDER BY blocked.pid LIMIT 1",
            )
            .bind(blocker_pid)
            .fetch_optional(&mut *observer)
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

async fn bump_project_metadata_revision(
    database: &DatabaseConnection,
    project_id: Uuid,
) -> Result<(), ApplicationError> {
    let project = project::Entity::find_by_id(project_id)
        .one(database)
        .await
        .map_err(|_| ApplicationError::Persistence)?
        .ok_or(ApplicationError::NotFound)?;
    let next_revision = project.metadata_revision + 1;
    let mut active = project.into_active_model();
    active.metadata_revision = Set(next_revision);
    active
        .update(database)
        .await
        .map(|_| ())
        .map_err(|_| ApplicationError::Persistence)
}

#[derive(Clone)]
struct RevisionBumpingSignerStore {
    inner: EncryptedFileStore,
    database: DatabaseConnection,
    project_id: Uuid,
    bumped: Arc<AtomicBool>,
    put_calls: Arc<AtomicUsize>,
}

#[async_trait]
impl SignerStore for RevisionBumpingSignerStore {
    async fn put_if_absent(
        &self,
        alias: String,
        seed: zeroize::Zeroizing<[u8; 32]>,
    ) -> Result<(), ApplicationError> {
        self.put_calls.fetch_add(1, Ordering::SeqCst);
        SignerStore::put_if_absent(&self.inner, alias, seed).await?;
        if !self.bumped.swap(true, Ordering::SeqCst) {
            bump_project_metadata_revision(&self.database, self.project_id).await?;
        }
        Ok(())
    }

    async fn public_jwk(
        &self,
        alias: String,
        kid: &str,
    ) -> Result<serde_json::Value, ApplicationError> {
        SignerStore::public_jwk(&self.inner, alias, kid).await
    }

    async fn verify(
        &self,
        alias: String,
        kid: &str,
        public_jwk: &serde_json::Value,
    ) -> Result<(), ApplicationError> {
        SignerStore::verify(&self.inner, alias, kid, public_jwk).await
    }
}

#[derive(Clone)]
struct RevisionBumpingSecretStore {
    inner: EncryptedFileStore,
    database: DatabaseConnection,
    project_id: Uuid,
    bumped: Arc<AtomicBool>,
    put_calls: Arc<AtomicUsize>,
}

#[async_trait]
impl ConfigurationSecretStore for RevisionBumpingSecretStore {
    fn request_fingerprint(&self, value: &[u8]) -> [u8; 32] {
        ConfigurationSecretStore::request_fingerprint(&self.inner, value)
    }

    async fn put_if_absent(
        &self,
        alias: String,
        value: zeroize::Zeroizing<Vec<u8>>,
    ) -> Result<(), ApplicationError> {
        self.put_calls.fetch_add(1, Ordering::SeqCst);
        ConfigurationSecretStore::put_if_absent(&self.inner, alias, value).await?;
        if !self.bumped.swap(true, Ordering::SeqCst) {
            bump_project_metadata_revision(&self.database, self.project_id).await?;
        }
        Ok(())
    }

    async fn ensure_readable(&self, alias: String) -> Result<(), ApplicationError> {
        ConfigurationSecretStore::ensure_readable(&self.inner, alias).await
    }
}

#[derive(Default)]
struct RemoteSigningState {
    object: Option<(Vec<u8>, Vec<u8>)>,
    provision_calls: usize,
    inspect_calls: usize,
    destroy_calls: usize,
    ambiguous_provision_once: bool,
    provision_failure_once: Option<(ProviderErrorClass, RetryClassification)>,
    destroy_failure_once: Option<(ProviderErrorClass, RetryClassification)>,
    destroy_failures: usize,
}

#[derive(Clone)]
struct StatefulRemoteSigningProvider {
    provider_id: ProviderId,
    state: Arc<Mutex<RemoteSigningState>>,
    revision_bump: Option<(DatabaseConnection, Uuid, Arc<AtomicBool>)>,
}

impl StatefulRemoteSigningProvider {
    fn new(provider_id: ProviderId, state: Arc<Mutex<RemoteSigningState>>) -> Self {
        Self {
            provider_id,
            state,
            revision_bump: None,
        }
    }

    fn with_revision_bump(mut self, database: DatabaseConnection, project_id: Uuid) -> Self {
        self.revision_bump = Some((database, project_id, Arc::new(AtomicBool::new(false))));
        self
    }

    fn result(handle: Vec<u8>, public_key: Vec<u8>) -> ProvisionedSigningKey {
        ProvisionedSigningKey {
            handle: OpaqueHandle::new(handle).expect("fake remote handle should be bounded"),
            public_key: SigningPublicKey::new(SigningAlgorithm::Ed25519, public_key)
                .expect("fake remote public key should be normalized"),
        }
    }
}

#[async_trait]
impl SigningKeyProvisioner for StatefulRemoteSigningProvider {
    fn provider_id(&self) -> ProviderId {
        self.provider_id.clone()
    }

    fn capabilities(&self) -> SigningProviderCapabilities {
        SigningProviderCapabilities::new(
            &[SigningAlgorithm::Ed25519],
            ProviderFormatVersions::new(&[ProviderFormatVersion::new(1).unwrap()]).unwrap(),
        )
        .unwrap()
    }

    async fn provision(
        &self,
        request: ProvisionSigningKeyRequest,
    ) -> Result<ProvisionedSigningKey, ProviderError> {
        let (handle, public_key, ambiguous) = {
            let mut state = self.state.lock().unwrap();
            state.provision_calls += 1;
            if let Some((error_class, retry)) = state.provision_failure_once.take() {
                return Err(ProviderError::new(error_class, retry));
            }
            let operation_byte = request.operation_id.as_bytes()[0];
            let object = state
                .object
                .get_or_insert_with(|| (vec![operation_byte; 48], vec![operation_byte; 32]));
            let result = (object.0.clone(), object.1.clone());
            let ambiguous = std::mem::take(&mut state.ambiguous_provision_once);
            (result.0, result.1, ambiguous)
        };
        if let Some((database, project_id, bumped)) = &self.revision_bump
            && !bumped.swap(true, Ordering::SeqCst)
        {
            bump_project_metadata_revision(database, *project_id)
                .await
                .map_err(|_| {
                    ProviderError::new(
                        ProviderErrorClass::Unavailable,
                        RetryClassification::Reconcile,
                    )
                })?;
        }
        if ambiguous {
            return Err(ProviderError::new(
                ProviderErrorClass::Unavailable,
                RetryClassification::Reconcile,
            ));
        }
        Ok(Self::result(handle, public_key))
    }

    async fn inspect(
        &self,
        _request: InspectSigningKeyRequest,
    ) -> Result<ProvisionedSigningKey, ProviderError> {
        let object = {
            let mut state = self.state.lock().unwrap();
            state.inspect_calls += 1;
            state.object.clone()
        };
        object.map_or_else(
            || {
                Err(ProviderError::new(
                    ProviderErrorClass::NotFound,
                    RetryClassification::ExactInputSafe,
                ))
            },
            |(handle, public_key)| Ok(Self::result(handle, public_key)),
        )
    }

    async fn destroy(
        &self,
        request: DestroySigningKeyRequest,
    ) -> Result<DestroyOutcome, ProviderError> {
        let mut state = self.state.lock().unwrap();
        state.destroy_calls += 1;
        if let Some((error_class, retry)) = state.destroy_failure_once.take() {
            return Err(ProviderError::new(error_class, retry));
        }
        if state.destroy_failures > 0 {
            state.destroy_failures -= 1;
            return Err(ProviderError::new(
                ProviderErrorClass::Unavailable,
                RetryClassification::Reconcile,
            ));
        }
        let Some((expected_handle, _)) = &state.object else {
            return Ok(DestroyOutcome::AlreadyAbsent);
        };
        if !request
            .handle
            .expose(|handle| handle == expected_handle.as_slice())
        {
            return Err(ProviderError::new(
                ProviderErrorClass::Integrity,
                RetryClassification::Never,
            ));
        }
        state.object = None;
        Ok(DestroyOutcome::Destroyed)
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one regression helper exercises every provider-effect finalizer under the same expired lease"
)]
async fn assert_expired_signing_provider_lease_is_fenced(
    database: &DatabaseConnection,
    adapter: &PostgresProvisioningAdapter,
    project_id: Uuid,
    operation: &key_provisioning_operation::Model,
) {
    let key = project_signing_key::Entity::find_by_id(operation.key_id)
        .one(database)
        .await
        .expect("expired-lease key query should work")
        .expect("expired-lease key should exist");
    let prepared = PreparedSigningKey {
        operation_id: operation.id,
        ring_id: operation.ring_id,
        key_id: operation.key_id,
        kid: key.kid,
        signer_ref: key.signer_ref,
        request_digest: operation.request_digest.clone(),
        state: ProvisioningOperationState::Submitted,
    };
    let now = time::OffsetDateTime::now_utc();
    let lease = match adapter
        .claim_signing_provider_action(
            project_id,
            &prepared,
            now,
            now + time::Duration::seconds(30),
        )
        .await
        .expect("submitted operation should be leased for inspection")
    {
        SigningProviderAction::Inspect(lease) => lease,
        action => panic!("submitted operation claimed an unexpected action: {action:?}"),
    };
    let leased = key_provisioning_operation::Entity::find_by_id(operation.id)
        .one(database)
        .await
        .expect("leased operation query should work")
        .expect("leased operation should exist");
    let mut expired = leased.into_active_model();
    expired.provider_lease_expires_at = Set(Some(now - time::Duration::seconds(1)));
    expired
        .update(database)
        .await
        .expect("provider lease should be expired for the fencing fixture");

    for provider_call in [SigningProviderCall::Provision, SigningProviderCall::Inspect] {
        assert_eq!(
            adapter
                .record_signing_provider_failure(
                    project_id,
                    &prepared,
                    lease,
                    provider_call,
                    ProviderErrorClass::Unavailable,
                    RetryClassification::Reconcile,
                    None,
                    now,
                )
                .await,
            Err(ApplicationError::OperationInProgress),
            "an expired {provider_call:?} result must not finalize"
        );
    }
    assert_eq!(
        adapter
            .record_signing_provider_absence(project_id, &prepared, lease, now)
            .await,
        Err(ApplicationError::OperationInProgress),
        "an expired inspection absence must not finalize"
    );
    assert_eq!(
        adapter
            .queue_signing_provider_cleanup(project_id, &prepared, lease, now)
            .await,
        Err(ApplicationError::OperationInProgress),
        "an expired result must not queue cleanup"
    );
    assert_eq!(
        adapter
            .record_protected_signing_key_material(
                project_id,
                &prepared,
                operation.expected_project_revision,
                lease,
                ProvisionedProtectedSigningMaterial {
                    material_id: operation
                        .material_id
                        .expect("remote operation should reserve material"),
                    handle: OpaqueHandle::new(vec![7; 48]).unwrap(),
                    public_key: SigningPublicKey::new(SigningAlgorithm::Ed25519, vec![8; 32],)
                        .unwrap(),
                },
                serde_json::Value::Null,
                now,
            )
            .await,
        Err(ApplicationError::OperationInProgress),
        "an expired provision result must not be contained"
    );

    let leased = key_provisioning_operation::Entity::find_by_id(operation.id)
        .one(database)
        .await
        .expect("expired operation query should work")
        .expect("expired operation should remain durable");
    assert_eq!(leased.state, "submitted");
    assert_eq!(leased.provider_lease_token, Some(lease.token));
    let mut cleanup_leased = leased.into_active_model();
    cleanup_leased.state = Set("cleanup_leased".to_owned());
    cleanup_leased
        .update(database)
        .await
        .expect("cleanup lease fixture should be staged");
    assert_eq!(
        adapter
            .complete_signing_provider_cleanup(
                project_id,
                &prepared,
                lease,
                true,
                Uuid::new_v4(),
                now,
            )
            .await,
        Err(ApplicationError::OperationInProgress),
        "an expired cleanup result must not finalize"
    );
    let cleanup_leased = key_provisioning_operation::Entity::find_by_id(operation.id)
        .one(database)
        .await
        .expect("expired cleanup query should work")
        .expect("expired cleanup should remain durable");
    assert_eq!(cleanup_leased.state, "cleanup_leased");
    assert_eq!(cleanup_leased.provider_lease_token, Some(lease.token));

    let mut restored = cleanup_leased.into_active_model();
    restored.state = Set("submitted".to_owned());
    restored.provider_lease_token = Set(None);
    restored.provider_lease_expires_at = Set(None);
    restored
        .update(database)
        .await
        .expect("historical-provider recovery fixture should be restored");
}

fn docker_is_required() -> bool {
    env::var("OWLAUTH_REQUIRE_DOCKER").is_ok_and(|value| value == "1")
}

fn unavailable_or_fail(error: impl std::fmt::Display) -> bool {
    assert!(
        !docker_is_required(),
        "PostgreSQL test container is required but failed to start: {error}"
    );
    eprintln!("skipping PostgreSQL adapter test: Docker unavailable: {error}");
    false
}

#[allow(
    clippy::too_many_lines,
    reason = "integration fixture enumerates the complete split-plane key configuration"
)]
fn server_config(migration_url: &str, runtime_url: &str, control_url: &str) -> ServerConfig {
    let values = BTreeMap::from([
        ("OWLAUTH_MODE".to_owned(), "all".to_owned()),
        (
            "OWLAUTH_CONTROL_API_KEY".to_owned(),
            format!("owl_ctrl_v1_{}", "A".repeat(43)),
        ),
        (
            "OWLAUTH_INSTANCE_ID".to_owned(),
            "test-deployment".to_owned(),
        ),
        (
            "OWLAUTH_SOFTWARE_CUSTODY_KEY".to_owned(),
            "Hh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4".to_owned(),
        ),
        (
            "OWLAUTH_SIGNER_STORE_ROOT".to_owned(),
            "/tmp/owlauth-postgres-test-signers".to_owned(),
        ),
        (
            "OWLAUTH_SIGNER_STORE_KEY".to_owned(),
            "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE".to_owned(),
        ),
        (
            "OWLAUTH_CONFIGURATION_SECRET_STORE_ROOT".to_owned(),
            "/tmp/owlauth-postgres-test-secrets".to_owned(),
        ),
        (
            "OWLAUTH_CONFIGURATION_SECRET_STORE_KEY".to_owned(),
            "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI".to_owned(),
        ),
        (
            "OWLAUTH_MIGRATION_OWNER_ROLE".to_owned(),
            "owlauth_owner".to_owned(),
        ),
        (
            "OWLAUTH_DATABASE_LOCK_TIMEOUT_MS".to_owned(),
            "250".to_owned(),
        ),
        ("OWLAUTH_POSTGRES_URL".to_owned(), runtime_url.to_owned()),
        (
            "OWLAUTH_RUNTIME_PROCESS_ID".to_owned(),
            "runtime-test-process".to_owned(),
        ),
        ("OWLAUTH_RUNTIME_KEY_VERSION".to_owned(), "1".to_owned()),
        (
            "OWLAUTH_RUNTIME_DIGEST_KEY".to_owned(),
            "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM".to_owned(),
        ),
        (
            "OWLAUTH_ADMISSION_DIGEST_KEY".to_owned(),
            "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU".to_owned(),
        ),
        (
            "OWLAUTH_RUNTIME_PROTECTION_KEY".to_owned(),
            "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ".to_owned(),
        ),
        (
            "OWLAUTH_EMAIL_IDENTITY_KEY_VERSION".to_owned(),
            "1".to_owned(),
        ),
        (
            "OWLAUTH_EMAIL_IDENTITY_DIGEST_KEY".to_owned(),
            "PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0".to_owned(),
        ),
        (
            "OWLAUTH_EMAIL_IDENTITY_PROTECTION_KEY".to_owned(),
            "Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4".to_owned(),
        ),
        (
            "OWLAUTH_PROJECTION_EMAIL_KEY_VERSION".to_owned(),
            "1".to_owned(),
        ),
        (
            "OWLAUTH_PROJECTION_EMAIL_PROTECTION_KEY".to_owned(),
            "R0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0c".to_owned(),
        ),
        (
            "OWLAUTH_MANAGED_REAUTHORIZATION_KEY_VERSION".to_owned(),
            "1".to_owned(),
        ),
        (
            "OWLAUTH_MANAGED_REAUTHORIZATION_DIGEST_KEY".to_owned(),
            "CgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgo".to_owned(),
        ),
        (
            "OWLAUTH_MANAGED_REAUTHORIZATION_PROTECTION_KEY".to_owned(),
            "CwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCws".to_owned(),
        ),
        (
            "OWLAUTH_IDENTITY_MUTATION_EVIDENCE_KEY_VERSION".to_owned(),
            "1".to_owned(),
        ),
        (
            "OWLAUTH_IDENTITY_MUTATION_EVIDENCE_DIGEST_KEY".to_owned(),
            "EBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBA".to_owned(),
        ),
        (
            "OWLAUTH_IDENTITY_MUTATION_EVIDENCE_PROTECTION_KEY".to_owned(),
            "ERERERERERERERERERERERERERERERERERERERERERE".to_owned(),
        ),
        (
            "OWLAUTH_MANAGED_CREDENTIAL_KEY_VERSION".to_owned(),
            "1".to_owned(),
        ),
        (
            "OWLAUTH_MANAGED_CREDENTIAL_KEY".to_owned(),
            "BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgY".to_owned(),
        ),
        (
            "OWLAUTH_PROVIDER_ALLOWED_ORIGINS".to_owned(),
            "https://accounts.example/".to_owned(),
        ),
        (
            "OWLAUTH_CLIENT_PROCESS_ID".to_owned(),
            "capability-client".to_owned(),
        ),
        (
            "OWLAUTH_REQUIRED_CLIENT_PROCESS_IDS".to_owned(),
            "capability-client".to_owned(),
        ),
        (
            "OWLAUTH_CLIENT_KEY_DIGEST_KEY_VERSION".to_owned(),
            "1".to_owned(),
        ),
        (
            "OWLAUTH_CLIENT_KEY_DIGEST_KEY".to_owned(),
            "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo".to_owned(),
        ),
        (
            "OWLAUTH_RUNTIME_POSTGRES_URL".to_owned(),
            runtime_url.to_owned(),
        ),
        (
            "OWLAUTH_CLIENT_POSTGRES_URL".to_owned(),
            runtime_url.to_owned(),
        ),
        (
            "OWLAUTH_CONTROL_POSTGRES_URL".to_owned(),
            control_url.to_owned(),
        ),
        (
            "OWLAUTH_MIGRATION_POSTGRES_URL".to_owned(),
            migration_url.to_owned(),
        ),
        (
            "OWLAUTH_RUNTIME_DATABASE_MAX_CONNECTIONS".to_owned(),
            "2".to_owned(),
        ),
        (
            "OWLAUTH_CONTROL_DATABASE_MAX_CONNECTIONS".to_owned(),
            "2".to_owned(),
        ),
    ]);
    ServerConfig::from_values_for_test(&values).expect("database test config should parse")
}

async fn complete_once(database: DatabaseConnection, key: String) -> CompleteIdempotency {
    let unit = ProjectUnitOfWork::begin(&database)
        .await
        .expect("claim Unit of Work should begin");
    let outcome = unit
        .complete_idempotency_once(&key, serde_json::json!({"accepted": true}))
        .await
        .expect("conditional completion should execute");
    unit.commit().await.expect("claim should commit");
    outcome
}

#[test]
fn plane_modes_select_separate_pool_sets() {
    assert!(PlaneMode::Runtime.has_runtime());
    assert!(!PlaneMode::Runtime.has_control());
    assert!(!PlaneMode::Control.has_runtime());
    assert!(PlaneMode::Control.has_control());
    assert!(PlaneMode::All.has_runtime());
    assert!(PlaneMode::All.has_control());
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the application/publication journey preserves one Project graph through constraints, lock ordering, publication, snapshots, HTTP, and disable races"
)]
async fn verify_application_and_publication_journeys(
    created_project: ProjectRecord,
    key_fence_project_id: Uuid,
    provisioning: ProvisioningService,
    control: &DatabaseConnection,
    config: &ServerConfig,
    pools: &DatabasePools,
    readiness: ReadinessService,
    secondary_readiness: ReadinessService,
    unexpected_readiness: ReadinessService,
    signer_store: EncryptedFileStore,
    secret_store: EncryptedFileStore,
    signer_root: std::path::PathBuf,
    admin_url: &str,
    control_url: String,
) -> Uuid {
    let created_application = provisioning
        .create_application(
            created_project.id,
            CreateApplication {
                display_name: "Browser application".to_owned(),
                application_type: ApplicationType::Web,
                idempotency_key: "application-create-12345678".to_owned(),
            },
            Uuid::new_v4(),
        )
        .await
        .expect("Application creation should commit");

    let concurrent_application = CreateApplication {
        display_name: "Concurrent application".to_owned(),
        application_type: ApplicationType::Web,
        idempotency_key: "application-concurrent-same-12345678".to_owned(),
    };
    let (concurrent_application_left, concurrent_application_right) = tokio::join!(
        provisioning.create_application(
            created_project.id,
            concurrent_application.clone(),
            Uuid::new_v4(),
        ),
        provisioning
            .create_application(created_project.id, concurrent_application, Uuid::new_v4(),),
    );
    assert_eq!(
        concurrent_application_left.expect("one concurrent Application create should commit"),
        concurrent_application_right.expect("same-key Application create should replay")
    );

    let (conflicting_application_left, conflicting_application_right) = tokio::join!(
        provisioning.create_application(
            created_project.id,
            CreateApplication {
                display_name: "Concurrent application left".to_owned(),
                application_type: ApplicationType::Web,
                idempotency_key: "application-concurrent-conflict-12345678".to_owned(),
            },
            Uuid::new_v4(),
        ),
        provisioning.create_application(
            created_project.id,
            CreateApplication {
                display_name: "Concurrent application right".to_owned(),
                application_type: ApplicationType::Web,
                idempotency_key: "application-concurrent-conflict-12345678".to_owned(),
            },
            Uuid::new_v4(),
        ),
    );
    assert!(matches!(
        (
            &conflicting_application_left,
            &conflicting_application_right
        ),
        (Ok(_), Err(ApplicationError::IdempotencyConflict))
            | (Err(ApplicationError::IdempotencyConflict), Ok(_))
    ));

    let application_idempotency =
        control_idempotency_record::Entity::find_by_id("application-create-12345678")
            .one(control)
            .await
            .expect("idempotency metadata should be queryable")
            .expect("Application creation should retain its replay record");
    assert_eq!(application_idempotency.project_id, Some(created_project.id));
    assert_eq!(
        application_idempotency.result_resource_id,
        Some(created_application.id)
    );
    assert_eq!(application_idempotency.operation_kind, "application.create");
    assert!(application_idempotency.expires_at.is_none());
    let configured_application = provisioning
        .replace_application_configuration(
            created_project.id,
            created_application.id,
            ReplaceApplicationConfiguration {
                redirect_uris: vec!["https://app.example/callback".to_owned()],
                allowed_origins: vec!["https://app.example".to_owned()],
                expected_security_revision: created_application.security_revision,
            },
            Uuid::new_v4(),
        )
        .await
        .expect("exact Application configuration should commit");
    assert_eq!(configured_application.security_revision, 2);
    assert_eq!(
        configured_application.configuration.redirect_uris,
        ["https://app.example/callback"]
    );

    let mut direct_sql = PgConnection::connect(&control_url)
        .await
        .expect("direct constraint test connection should open");
    let duplicate_redirect = sqlx::query(
        "INSERT INTO application_redirects \
         (project_id, application_id, redirect_uri, redirect_type) \
         VALUES ($1, $2, $3, 'web')",
    )
    .bind(created_project.id)
    .bind(created_application.id)
    .bind("https://app.example/callback")
    .execute(&mut direct_sql)
    .await
    .expect_err("duplicate exact redirect must be rejected");
    assert_eq!(
        duplicate_redirect
            .as_database_error()
            .expect("duplicate redirect should be a database error")
            .code()
            .as_deref(),
        Some("23505")
    );
    let duplicate_origin = sqlx::query(
        "INSERT INTO application_origins (project_id, application_id, origin) \
         VALUES ($1, $2, $3)",
    )
    .bind(created_project.id)
    .bind(created_application.id)
    .bind("https://app.example")
    .execute(&mut direct_sql)
    .await
    .expect_err("duplicate exact origin must be rejected");
    assert_eq!(
        duplicate_origin
            .as_database_error()
            .expect("duplicate origin should be a database error")
            .code()
            .as_deref(),
        Some("23505")
    );
    let cross_project_redirect = sqlx::query(
        "INSERT INTO application_redirects \
         (project_id, application_id, redirect_uri, redirect_type) \
         VALUES ($1, $2, $3, 'web')",
    )
    .bind(key_fence_project_id)
    .bind(created_application.id)
    .bind("https://cross-project.example/callback")
    .execute(&mut direct_sql)
    .await
    .expect_err("cross-Project child must be rejected");
    assert_eq!(
        cross_project_redirect
            .as_database_error()
            .expect("cross-Project child should be a database error")
            .code()
            .as_deref(),
        Some("23503")
    );
    let malformed_public_id = sqlx::query(
        "INSERT INTO projects \
         (id, public_id, status, metadata_revision, security_revision) \
         VALUES ($1, 'invalid/public', 'active', 1, 1)",
    )
    .bind(Uuid::new_v4())
    .execute(&mut direct_sql)
    .await
    .expect_err("unsafe public ID characters must be rejected");
    assert_eq!(
        malformed_public_id
            .as_database_error()
            .expect("malformed public ID should be a database error")
            .code()
            .as_deref(),
        Some("23514")
    );
    let changed_public_id = sqlx::query("UPDATE projects SET public_id = $1 WHERE id = $2")
        .bind("prj_replaced_identity")
        .bind(created_project.id)
        .execute(&mut direct_sql)
        .await
        .expect_err("Project public identity must be immutable");
    assert_eq!(
        changed_public_id
            .as_database_error()
            .expect("immutable Project identity should be a database error")
            .code()
            .as_deref(),
        Some("23514")
    );
    let audit_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM audit_events WHERE project_id = $1 ORDER BY occurred_at, id LIMIT 1",
    )
    .bind(created_project.id)
    .fetch_one(&mut direct_sql)
    .await
    .expect("audit fixture should exist");
    for statement in [
        "UPDATE audit_events SET safe_context = '{\"changed\":true}'::jsonb WHERE id = $1",
        "DELETE FROM audit_events WHERE id = $1",
    ] {
        let audit_mutation = sqlx::query(statement)
            .bind(audit_id)
            .execute(&mut direct_sql)
            .await
            .expect_err("audit mutation must be rejected");
        assert_eq!(
            audit_mutation
                .as_database_error()
                .expect("audit mutation should be a database error")
                .code()
                .as_deref(),
            Some("23514")
        );
    }
    direct_sql
        .close()
        .await
        .expect("direct constraint connection should close");

    let signing_key = provisioning
        .provision_signing_key(
            created_project.id,
            "signing-operation-12345678".to_owned(),
            created_project.metadata_revision,
            Uuid::new_v4(),
        )
        .await
        .expect("signing material should reconcile and publish");
    let operation = key_provisioning_operation::Entity::find()
        .filter(key_provisioning_operation::Column::OperationAlias.eq("signing-operation-12345678"))
        .one(control)
        .await
        .expect("key operation should be queryable")
        .expect("key operation should be durable");
    let mut operation_active = operation.into_active_model();
    operation_active.state = Set("stored".to_owned());
    operation_active.completed_at = Set(None);
    operation_active
        .update(control)
        .await
        .expect("stored recovery fixture should persist");
    let key = project_signing_key::Entity::find_by_id(signing_key.id)
        .one(control)
        .await
        .expect("signing key should be queryable")
        .expect("signing key should exist");
    let mut key_active = key.into_active_model();
    key_active.state = Set("provisioning".to_owned());
    key_active
        .update(control)
        .await
        .expect("stored recovery fixture should persist");
    let restarted_provisioning = ProvisioningService::new(
        Arc::new(PostgresProvisioningAdapter::new(
            control.clone(),
            url::Url::parse("https://identity.example/runtime/").unwrap(),
            vec![
                "runtime-test-process".to_owned(),
                "runtime-secondary-process".to_owned(),
            ],
            Duration::from_millis(10),
            Duration::from_secs(1),
        )),
        ProvisioningInfrastructure::new(
            signer_store.clone(),
            secret_store.clone(),
            SystemClock,
            SystemEntropy,
            Sha256RequestDigester,
            false,
        ),
    );
    let signing_key = restarted_provisioning
        .provision_signing_key(
            created_project.id,
            "signing-operation-12345678".to_owned(),
            created_project.metadata_revision,
            Uuid::new_v4(),
        )
        .await
        .expect("a restarted adapter should finalize the same stored key operation");
    assert_eq!(signing_key.state, "published");
    assert_eq!(signing_key.ring_revision, 3);

    let mut jwk_constraint_sql = PgConnection::connect(&control_url)
        .await
        .expect("JWK constraint test connection should open");
    for (statement, expectation) in [
        (
            "UPDATE project_signing_keys \
             SET public_jwk = public_jwk || '{\"d\":\"private\"}'::jsonb WHERE id = $1",
            "private JWK material must be rejected",
        ),
        (
            "UPDATE project_signing_keys \
             SET public_jwk = jsonb_set(public_jwk, '{kid}', '\"kid_wrong_identity\"') \
             WHERE id = $1",
            "JWK kid must equal the stable row kid",
        ),
    ] {
        let invalid_jwk = sqlx::query(statement)
            .bind(signing_key.id)
            .execute(&mut jwk_constraint_sql)
            .await
            .expect_err(expectation);
        assert_eq!(
            invalid_jwk
                .as_database_error()
                .expect("invalid JWK should be a database error")
                .code()
                .as_deref(),
            Some("23514")
        );
    }
    jwk_constraint_sql
        .close()
        .await
        .expect("JWK constraint test connection should close");

    assert_eq!(
        provisioning
            .activate_signing_key(
                created_project.id,
                signing_key.id,
                signing_key.ring_revision,
                Uuid::new_v4(),
            )
            .await,
        Err(crate::application::ApplicationError::PublicationPending)
    );

    // Replacement first: public readiness must block on the exact incarnation before it can
    // touch any Project/Application row. Rolling the replacement transaction back lets the
    // same operation proceed with the still-current incarnation.
    let mut observer = PgConnection::connect(admin_url)
        .await
        .expect("readiness lock observer should open");
    let mut incarnation_blocker = PgConnection::connect(&control_url)
        .await
        .expect("incarnation blocker should open");
    sqlx::query("BEGIN")
        .execute(&mut incarnation_blocker)
        .await
        .expect("begin replacement-first transaction");
    sqlx::query(
        "UPDATE runtime_process_incarnations SET process_incarnation=$2
         WHERE process_id=$1",
    )
    .bind("runtime-test-process")
    .bind(Uuid::new_v4())
    .execute(&mut incarnation_blocker)
    .await
    .expect("stage Runtime incarnation replacement");
    let incarnation_blocker_pid = sqlx::query_scalar::<_, i32>("SELECT pg_backend_pid()")
        .fetch_one(&mut incarnation_blocker)
        .await
        .expect("read incarnation-blocker backend pid");
    let readiness_for_public_order = readiness.clone();
    let project_public_id = created_project.public_id.clone();
    let application_public_id = created_application.public_id.clone();
    let public_read = tokio::spawn(async move {
        readiness_for_public_order
            .public_application_config(&project_public_id, &application_public_id)
            .await
    });
    let public_read_pid = wait_for_sqlx_backend_blocked_by(
        &mut observer,
        incarnation_blocker_pid,
        "public config exact-incarnation first lock",
    )
    .await;
    assert_ne!(public_read_pid, incarnation_blocker_pid);
    sqlx::query("ROLLBACK")
        .execute(&mut incarnation_blocker)
        .await
        .expect("roll back staged Runtime replacement");
    public_read
        .await
        .expect("join replacement-first public read")
        .expect("public read should resume on the exact current incarnation");

    // Runtime first: hold only the final key-ring row. JWKS must retain the exact incarnation
    // lock while waiting there, forcing a concurrent replacement to wait behind Runtime. Once
    // JWKS commits its lease and replacement wins, Control must reject that predecessor lease.
    secondary_readiness
        .project_jwks(&created_project.public_id)
        .await
        .expect("seed every other required Runtime publication lease");
    let mut ring_blocker = PgConnection::connect(&control_url)
        .await
        .expect("key-ring blocker should open");
    sqlx::query("BEGIN")
        .execute(&mut ring_blocker)
        .await
        .expect("begin Runtime-first ring transaction");
    sqlx::query("SELECT id FROM project_key_rings WHERE project_id=$1 FOR UPDATE")
        .bind(created_project.id)
        .fetch_one(&mut ring_blocker)
        .await
        .expect("hold final key-ring lock");
    let ring_blocker_pid = sqlx::query_scalar::<_, i32>("SELECT pg_backend_pid()")
        .fetch_one(&mut ring_blocker)
        .await
        .expect("read ring-blocker backend pid");
    let readiness_for_jwks_order = readiness.clone();
    let project_public_id = created_project.public_id.clone();
    let jwks_read = tokio::spawn(async move {
        readiness_for_jwks_order
            .project_jwks(&project_public_id)
            .await
    });
    let jwks_read_pid =
        wait_for_sqlx_backend_blocked_by(&mut observer, ring_blocker_pid, "JWKS final ring lock")
            .await;
    let replacement_incarnation = Uuid::new_v4();
    let replacement_url = control_url.clone();
    let (replacement_pid_sender, replacement_pid_receiver) = tokio::sync::oneshot::channel();
    let replacement = tokio::spawn(async move {
        let mut connection = PgConnection::connect(&replacement_url)
            .await
            .expect("replacement connection should open");
        sqlx::query("BEGIN")
            .execute(&mut connection)
            .await
            .expect("begin Runtime replacement");
        let pid = sqlx::query_scalar::<_, i32>("SELECT pg_backend_pid()")
            .fetch_one(&mut connection)
            .await
            .expect("read replacement backend pid");
        replacement_pid_sender
            .send(pid)
            .expect("publish replacement backend pid");
        sqlx::query(
            "UPDATE runtime_process_incarnations SET process_incarnation=$2
             WHERE process_id=$1",
        )
        .bind("runtime-test-process")
        .bind(replacement_incarnation)
        .execute(&mut connection)
        .await
        .expect("replace Runtime incarnation");
        sqlx::query("COMMIT")
            .execute(&mut connection)
            .await
            .expect("commit Runtime replacement");
    });
    let replacement_pid = replacement_pid_receiver
        .await
        .expect("receive replacement backend pid");
    assert_eq!(
        wait_for_sqlx_backend_blocked_by(
            &mut observer,
            jwks_read_pid,
            "replacement behind in-flight JWKS",
        )
        .await,
        replacement_pid
    );
    sqlx::query("ROLLBACK")
        .execute(&mut ring_blocker)
        .await
        .expect("release final key-ring lock");
    let ordered_jwks = jwks_read
        .await
        .expect("join Runtime-first JWKS read")
        .expect("JWKS read should commit before replacement");
    assert_eq!(ordered_jwks.revision, signing_key.ring_revision);
    replacement.await.expect("join Runtime replacement");
    tokio::time::sleep(Duration::from_millis(15)).await;
    assert_eq!(
        provisioning
            .activate_signing_key(
                created_project.id,
                signing_key.id,
                signing_key.ring_revision,
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::PublicationPending),
        "Control must not trust a predecessor-incarnation publication lease"
    );
    let key_after_stale_activation = provisioning
        .list_signing_keys(created_project.id)
        .await
        .expect("signing keys should remain queryable")
        .into_iter()
        .find(|key| key.id == signing_key.id)
        .expect("published key should remain present");
    assert_eq!(key_after_stale_activation.state, "published");
    sqlx::query(
        "UPDATE runtime_process_incarnations SET process_incarnation=$2
         WHERE process_id=$1",
    )
    .bind("runtime-test-process")
    .bind(Uuid::from_u128(1))
    .execute(&mut incarnation_blocker)
    .await
    .expect("restore primary Runtime test incarnation");
    sqlx::query(
        "DELETE FROM runtime_publication_leases
         WHERE project_id=$1 AND process_id='runtime-secondary-process'",
    )
    .bind(created_project.id)
    .execute(&mut incarnation_blocker)
    .await
    .expect("restore the later missing-secondary publication fixture");

    let published_jwks = readiness
        .project_jwks(&created_project.public_id)
        .await
        .expect("Runtime should load and lease the published JWKS revision");
    assert_eq!(published_jwks.revision, signing_key.ring_revision);
    assert_eq!(published_jwks.keys.len(), 1);
    tokio::time::sleep(Duration::from_millis(15)).await;
    assert_eq!(
        provisioning
            .activate_signing_key(
                created_project.id,
                signing_key.id,
                signing_key.ring_revision,
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::PublicationPending)
    );
    secondary_readiness
        .project_jwks(&created_project.public_id)
        .await
        .expect("every required Runtime process should observe the revision");
    tokio::time::sleep(Duration::from_millis(15)).await;
    let active_key = provisioning
        .activate_signing_key(
            created_project.id,
            signing_key.id,
            signing_key.ring_revision,
            Uuid::new_v4(),
        )
        .await
        .expect("activation should succeed after the propagation interval");
    assert_eq!(active_key.state, "active");

    unexpected_readiness
        .project_jwks(&created_project.public_id)
        .await
        .expect("an additional live Runtime should lease its loaded revision");
    let policy_before_reduction = provisioning
        .get_project_policy(created_project.id)
        .await
        .expect("current policy should be queryable");
    provisioning
        .update_project_policy(
            created_project.id,
            UpdateProjectPolicy {
                access_token_lifetime_seconds: 60,
                browser_session_reuse: policy_before_reduction.browser_session_reuse,
                expected_claims_revision: policy_before_reduction.claims_revision,
                expected_session_revision: policy_before_reduction.session_revision,
            },
            Uuid::new_v4(),
        )
        .await
        .expect("lowering the Project token policy should commit");

    let rotating_key = provisioning
        .provision_signing_key(
            created_project.id,
            "signing-rotation-12345678".to_owned(),
            created_project.metadata_revision,
            Uuid::new_v4(),
        )
        .await
        .expect("a second key should publish for safe rotation");
    let rotation_jwks = readiness
        .project_jwks(&created_project.public_id)
        .await
        .expect("primary Runtime should observe the rotation revision");
    secondary_readiness
        .project_jwks(&created_project.public_id)
        .await
        .expect("secondary Runtime should observe the rotation revision");
    assert_eq!(rotation_jwks.keys.len(), 2);
    tokio::time::sleep(Duration::from_millis(15)).await;
    assert_eq!(
        provisioning
            .activate_signing_key(
                created_project.id,
                rotating_key.id,
                rotating_key.ring_revision,
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::PublicationPending),
        "an unexpected live Runtime with a stale revision must block activation"
    );
    let unexpected_lease = runtime_publication_lease::Entity::find()
        .filter(runtime_publication_lease::Column::ProjectId.eq(created_project.id))
        .filter(runtime_publication_lease::Column::ProcessId.eq("runtime-unexpected-process"))
        .one(control)
        .await
        .expect("unexpected Runtime lease should be queryable")
        .expect("unexpected Runtime lease should exist");
    let mut unexpected_lease_active = unexpected_lease.into_active_model();
    let database_now: time::OffsetDateTime = sqlx::query_scalar("SELECT transaction_timestamp()")
        .fetch_one(&mut incarnation_blocker)
        .await
        .expect("database time should be queryable for explicit lease expiry");
    let expired_at = database_now - time::Duration::seconds(1);
    unexpected_lease_active.first_observed_at = Set(expired_at - time::Duration::seconds(2));
    unexpected_lease_active.last_observed_at = Set(expired_at - time::Duration::seconds(1));
    unexpected_lease_active.expires_at = Set(expired_at);
    unexpected_lease_active
        .update(control)
        .await
        .expect("drained Runtime lease should expire");
    let (left_activation, right_activation) = tokio::join!(
        provisioning.activate_signing_key(
            created_project.id,
            rotating_key.id,
            rotating_key.ring_revision,
            Uuid::new_v4(),
        ),
        provisioning.activate_signing_key(
            created_project.id,
            rotating_key.id,
            rotating_key.ring_revision,
            Uuid::new_v4(),
        )
    );
    let rotated_active_key = match (left_activation, right_activation) {
        (
            Ok(active),
            Err(ApplicationError::RevisionConflict | ApplicationError::InvalidTransition),
        )
        | (
            Err(ApplicationError::RevisionConflict | ApplicationError::InvalidTransition),
            Ok(active),
        ) => active,
        outcomes => panic!("exactly one concurrent activation must commit: {outcomes:?}"),
    };
    let retiring_key = provisioning
        .list_signing_keys(created_project.id)
        .await
        .expect("rotated keys should be queryable")
        .into_iter()
        .find(|key| key.id == active_key.id)
        .expect("the former active key should remain in the ring");
    assert_eq!(retiring_key.state, "retiring");
    let rotation_time = rotated_active_key
        .sign_not_before
        .expect("the newly active key should record its activation time");
    assert_eq!(
        retiring_key.verify_not_after,
        Some(
            rotation_time
                + time::Duration::seconds(i64::from(
                    crate::domain::MAX_ACCESS_TOKEN_LIFETIME_SECONDS,
                ))
                + time::Duration::seconds(1)
                + time::Duration::milliseconds(10)
        ),
        "a reduced Project policy must not shorten the hard maximum verification overlap"
    );

    assert_eq!(
        provisioning
            .retire_signing_key(
                created_project.id,
                retiring_key.id,
                rotated_active_key.ring_revision,
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::InvalidTransition)
    );
    let retiring_model = project_signing_key::Entity::find_by_id(retiring_key.id)
        .one(control)
        .await
        .expect("retiring key should be queryable")
        .expect("retiring key should exist");
    let mut retiring_active = retiring_model.into_active_model();
    let database_now: time::OffsetDateTime = sqlx::query_scalar("SELECT transaction_timestamp()")
        .fetch_one(&mut incarnation_blocker)
        .await
        .expect("database time should be queryable for the retention cutoff");
    let elapsed_cutoff = database_now - time::Duration::seconds(1);
    retiring_active.sign_not_before = Set(Some(elapsed_cutoff - time::Duration::microseconds(1)));
    retiring_active.verify_not_after = Set(Some(elapsed_cutoff));
    retiring_active
        .update(control)
        .await
        .expect("test cutoff should advance past the retention window");
    let post_cutoff_jwks = readiness
        .project_jwks(&created_project.public_id)
        .await
        .expect("expired retiring keys should leave Runtime JWKS");
    assert_eq!(post_cutoff_jwks.keys.len(), 1);
    let retired_key = provisioning
        .retire_signing_key(
            created_project.id,
            retiring_key.id,
            rotated_active_key.ring_revision,
            Uuid::new_v4(),
        )
        .await
        .expect("retirement should finalize only after verification cutoff");
    assert_eq!(retired_key.state, "retired");
    let active_key = provisioning
        .list_signing_keys(created_project.id)
        .await
        .expect("the active key should remain queryable")
        .into_iter()
        .find(|key| key.id == rotated_active_key.id)
        .expect("the rotated key should remain active");
    assert_eq!(active_key.state, "active");
    assert_eq!(active_key.ring_revision, retired_key.ring_revision);
    assert!(
        key_state_event::Entity::find()
            .filter(key_state_event::Column::ProjectId.eq(created_project.id))
            .all(control)
            .await
            .expect("key lifecycle events should be queryable")
            .len()
            >= 6
    );

    let provider = provisioning
        .create_provider(
            created_project.id,
            CreateProvider {
                kind: crate::domain::ProviderKind::Oidc,
                provider_key: "workforce".to_owned(),
                display_name: "Workforce SSO".to_owned(),
                issuer: "https://accounts.example/".to_owned(),
                client_id: "owlauth-test".to_owned(),
                client_secret: zeroize::Zeroizing::new("provider-secret".to_owned()),
                managed_profile_enabled: false,
                idempotency_key: "provider-operation-12345678".to_owned(),
                expected_project_revision: created_project.metadata_revision,
                egress_policy_revision: Some(1),
            },
            Uuid::new_v4(),
        )
        .await
        .expect("provider secret should reconcile without disclosure");
    let operation = provider_secret_operation::Entity::find()
        .filter(provider_secret_operation::Column::OperationAlias.eq("provider-operation-12345678"))
        .one(control)
        .await
        .expect("provider operation should be queryable")
        .expect("provider operation should be durable");
    let mut operation_active = operation.into_active_model();
    operation_active.state = Set("stored".to_owned());
    operation_active.completed_at = Set(None);
    operation_active
        .update(control)
        .await
        .expect("stored provider recovery fixture should persist");
    let provider_model = provider_configuration::Entity::find_by_id(provider.id)
        .one(control)
        .await
        .expect("provider should be queryable")
        .expect("provider should exist");
    let mut provider_active = provider_model.into_active_model();
    provider_active.status = Set("provisioning".to_owned());
    provider_active.secret_ref = Set(None);
    provider_active.revision = Set(1);
    provider_active
        .update(control)
        .await
        .expect("stored provider recovery fixture should persist");
    let provider = restarted_provisioning
        .create_provider(
            created_project.id,
            CreateProvider {
                kind: crate::domain::ProviderKind::Oidc,
                provider_key: "workforce".to_owned(),
                display_name: "Workforce SSO".to_owned(),
                issuer: "https://accounts.example/".to_owned(),
                client_id: "owlauth-test".to_owned(),
                client_secret: zeroize::Zeroizing::new("provider-secret".to_owned()),
                managed_profile_enabled: false,
                idempotency_key: "provider-operation-12345678".to_owned(),
                expected_project_revision: created_project.metadata_revision,
                egress_policy_revision: Some(1),
            },
            Uuid::new_v4(),
        )
        .await
        .expect("a restarted adapter should finalize the same stored provider operation");
    assert_eq!(provider.status, "active");
    let mut callback_constraint_sql = PgConnection::connect(&control_url)
        .await
        .expect("callback constraint test connection should open");
    let changed_callback =
        sqlx::query("UPDATE provider_configurations SET callback_url = $1 WHERE id = $2")
            .bind("https://identity.example/runtime/projects/replaced/auth/callback/workforce")
            .bind(provider.id)
            .execute(&mut callback_constraint_sql)
            .await
            .expect_err("provider callback identity must be immutable");
    assert_eq!(
        changed_callback
            .as_database_error()
            .expect("immutable callback should be a database error")
            .code()
            .as_deref(),
        Some("23514")
    );
    callback_constraint_sql
        .close()
        .await
        .expect("callback constraint test connection should close");

    bump_project_metadata_revision(control, created_project.id)
        .await
        .expect("completed replay fence fixture should advance Project metadata");
    let completed_key_operation = key_provisioning_operation::Entity::find()
        .filter(key_provisioning_operation::Column::OperationAlias.eq("signing-operation-12345678"))
        .one(control)
        .await
        .expect("completed key operation should be queryable")
        .expect("completed key operation should exist");
    let completed_key_model = project_signing_key::Entity::find_by_id(signing_key.id)
        .one(control)
        .await
        .expect("completed key should be queryable")
        .expect("completed key should exist");
    let prepared_key = PreparedSigningKey {
        operation_id: completed_key_operation.id,
        ring_id: completed_key_operation.ring_id,
        key_id: completed_key_operation.key_id,
        kid: completed_key_model.kid,
        signer_ref: completed_key_model.signer_ref,
        request_digest: completed_key_operation.request_digest,
        state: ProvisioningOperationState::Prepared,
    };
    let completed_provider_operation = provider_secret_operation::Entity::find()
        .filter(provider_secret_operation::Column::OperationAlias.eq("provider-operation-12345678"))
        .one(control)
        .await
        .expect("completed provider operation should be queryable")
        .expect("completed provider operation should exist");
    let prepared_provider = PreparedProvider {
        operation_id: completed_provider_operation.id,
        provider_id: completed_provider_operation.provider_id,
        request_digest: completed_provider_operation.request_digest,
        state: ProvisioningOperationState::Prepared,
    };
    let completed_stage_adapter = PostgresProvisioningAdapter::new(
        control.clone(),
        url::Url::parse("https://identity.example/runtime/").unwrap(),
        vec!["runtime-test-process".to_owned()],
        Duration::from_millis(10),
        Duration::from_secs(1),
    );
    let replayed_at = time::OffsetDateTime::now_utc();
    completed_stage_adapter
        .record_signing_key_material(
            created_project.id,
            &prepared_key,
            created_project.metadata_revision,
            serde_json::json!({}),
            replayed_at,
        )
        .await
        .expect("an in-flight key record stage should observe concurrent completion");
    let stage_replayed_key = completed_stage_adapter
        .publish_signing_key(
            created_project.id,
            &prepared_key,
            created_project.metadata_revision,
            Uuid::new_v4(),
            replayed_at,
        )
        .await
        .expect("an in-flight key publish stage should observe concurrent completion");
    assert_eq!(stage_replayed_key.id, signing_key.id);
    completed_stage_adapter
        .mark_provider_secret_stored(
            created_project.id,
            &prepared_provider,
            created_project.metadata_revision,
            replayed_at,
        )
        .await
        .expect("an in-flight provider store stage should observe concurrent completion");
    let stage_replayed_provider = completed_stage_adapter
        .finalize_provider(
            created_project.id,
            &prepared_provider,
            created_project.metadata_revision,
            "unused-after-completion".to_owned(),
            Uuid::new_v4(),
            replayed_at,
        )
        .await
        .expect("an in-flight provider finalize stage should observe concurrent completion");
    assert_eq!(stage_replayed_provider.id, provider.id);

    let replayed_signing_key = restarted_provisioning
        .provision_signing_key(
            created_project.id,
            "signing-operation-12345678".to_owned(),
            created_project.metadata_revision,
            Uuid::new_v4(),
        )
        .await
        .expect("a completed key operation should replay across later Project revisions");
    assert_eq!(replayed_signing_key.id, signing_key.id);
    let replayed_provider = restarted_provisioning
        .create_provider(
            created_project.id,
            CreateProvider {
                kind: crate::domain::ProviderKind::Oidc,
                provider_key: "workforce".to_owned(),
                display_name: "Workforce SSO".to_owned(),
                issuer: "https://accounts.example/".to_owned(),
                client_id: "owlauth-test".to_owned(),
                client_secret: zeroize::Zeroizing::new("provider-secret".to_owned()),
                managed_profile_enabled: false,
                idempotency_key: "provider-operation-12345678".to_owned(),
                expected_project_revision: created_project.metadata_revision,
                egress_policy_revision: Some(1),
            },
            Uuid::new_v4(),
        )
        .await
        .expect("a completed provider operation should replay across later Project revisions");
    assert_eq!(replayed_provider.id, provider.id);

    let assigned = provisioning
        .assign_provider(
            created_project.id,
            provider.id,
            created_application.id,
            configured_application.security_revision,
            Uuid::new_v4(),
        )
        .await
        .expect("same-Project provider assignment should commit");
    assert_eq!(assigned.assigned_application_ids, [created_application.id]);

    let public_config = readiness
        .public_application_config(&created_project.public_id, &created_application.public_id)
        .await
        .expect("Runtime public configuration should resolve exact IDs");
    assert!(public_config.login_available);
    assert_eq!(public_config.providers.len(), 1);
    assert_eq!(public_config.providers[0].key, "workforce");
    assert_eq!(public_config.publishable_keys.len(), 1);
    assert_eq!(assigned.revision, provider.revision + 1);

    let mut changed_legacy_egress_config = config.clone();
    changed_legacy_egress_config.provider_allowed_origins =
        vec!["https://different-provider.example/".to_owned()];
    let mut blocked_egress_routers = build_routers_with_runtime_incarnation(
        &changed_legacy_egress_config,
        Some(pools),
        Uuid::from_u128(1),
    );
    blocked_egress_routers.mark_ready();
    let blocked_egress_response = blocked_egress_routers
        .runtime
        .take()
        .expect("Runtime router should be composed")
        .oneshot(
            Request::get(format!(
                "/v1/projects/{}/auth/config?application_id={}",
                created_project.public_id, created_application.public_id
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(blocked_egress_response.status(), StatusCode::OK);
    let blocked_egress_json: serde_json::Value = serde_json::from_slice(
        &to_bytes(blocked_egress_response.into_body(), 1_000_000)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        blocked_egress_json["providers"],
        serde_json::json!([{
            "key": "workforce",
            "display_name": "Workforce SSO",
            "kind": "oidc"
        }])
    );
    assert_eq!(blocked_egress_json["login_available"], true);

    let snapshot_mutation = control
        .begin()
        .await
        .expect("snapshot race transaction should begin");
    project::Entity::find_by_id(created_project.id)
        .lock_exclusive()
        .one(&snapshot_mutation)
        .await
        .expect("Project guard should be lockable")
        .expect("Project should exist");
    let assignment = application_provider_assignment::Entity::find_by_id((
        created_project.id,
        created_application.id,
        provider.id,
    ))
    .lock_exclusive()
    .one(&snapshot_mutation)
    .await
    .expect("assignment should be lockable")
    .expect("assignment should exist");
    let application = application::Entity::find_by_id(created_application.id)
        .lock_exclusive()
        .one(&snapshot_mutation)
        .await
        .expect("Application should be lockable")
        .expect("Application should exist");
    let provider_model = provider_configuration::Entity::find_by_id(provider.id)
        .lock_exclusive()
        .one(&snapshot_mutation)
        .await
        .expect("provider should be lockable")
        .expect("provider should exist");
    let next_application_revision = application.security_revision + 1;
    let mut assignment_active = assignment.into_active_model();
    assignment_active.status = Set("disabled".to_owned());
    assignment_active.security_revision = Set(next_application_revision);
    assignment_active
        .update(&snapshot_mutation)
        .await
        .expect("unassignment fixture should stage");
    let next_aggregate_revision = application.revision + 1;
    let mut application_active = application.into_active_model();
    application_active.security_revision = Set(next_application_revision);
    application_active.revision = Set(next_aggregate_revision);
    application_active
        .update(&snapshot_mutation)
        .await
        .expect("Application revision fixture should stage");
    let next_provider_revision = provider_model.revision + 1;
    let mut provider_active = provider_model.into_active_model();
    provider_active.revision = Set(next_provider_revision);
    provider_active
        .update(&snapshot_mutation)
        .await
        .expect("provider revision fixture should stage");

    let readiness_for_race = readiness.clone();
    let project_public_id = created_project.public_id.clone();
    let application_public_id = created_application.public_id.clone();
    let mut snapshot_read = tokio::spawn(async move {
        readiness_for_race
            .public_application_config(&project_public_id, &application_public_id)
            .await
    });
    assert!(
        timeout(Duration::from_millis(50), &mut snapshot_read)
            .await
            .is_err(),
        "Runtime snapshot must wait for the conflicting Project mutation"
    );
    snapshot_mutation
        .commit()
        .await
        .expect("unassignment fixture should commit");
    let raced_public_config = snapshot_read
        .await
        .expect("snapshot task should complete")
        .expect("post-commit public config should remain available");
    assert!(raced_public_config.providers.is_empty());

    let application_after_unassignment = provisioning
        .get_application(created_project.id, created_application.id)
        .await
        .expect("Application revision should reflect unassignment");
    let reassigned = provisioning
        .assign_provider(
            created_project.id,
            provider.id,
            created_application.id,
            application_after_unassignment.security_revision,
            Uuid::new_v4(),
        )
        .await
        .expect("a current command should reactivate the terminal assignment row");
    assert_eq!(reassigned.revision, next_provider_revision + 1);
    assert_eq!(
        provisioning
            .disable_provider(
                created_project.id,
                provider.id,
                assigned.revision,
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::RevisionConflict),
        "an assignment revision must fence a concurrent stale provider disable"
    );

    let application_before_configuration_race = provisioning
        .get_application(created_project.id, created_application.id)
        .await
        .expect("Application should be queryable before concurrent configuration");
    let (left_configuration, right_configuration) = tokio::join!(
        provisioning.replace_application_configuration(
            created_project.id,
            created_application.id,
            ReplaceApplicationConfiguration {
                redirect_uris: vec!["https://app.example/callback-a".to_owned()],
                allowed_origins: vec!["https://app.example".to_owned()],
                expected_security_revision: application_before_configuration_race.security_revision,
            },
            Uuid::new_v4(),
        ),
        provisioning.replace_application_configuration(
            created_project.id,
            created_application.id,
            ReplaceApplicationConfiguration {
                redirect_uris: vec!["https://app.example/callback-b".to_owned()],
                allowed_origins: vec!["https://app.example".to_owned()],
                expected_security_revision: application_before_configuration_race.security_revision,
            },
            Uuid::new_v4(),
        )
    );
    assert!(matches!(
        (&left_configuration, &right_configuration),
        (Ok(_), Err(ApplicationError::RevisionConflict))
            | (Err(ApplicationError::RevisionConflict), Ok(_))
    ));

    assert_eq!(
        provisioning
            .get_application(Uuid::new_v4(), created_application.id)
            .await,
        Err(crate::application::ApplicationError::NotFound)
    );

    let revoked = provisioning
        .revoke_signing_key(
            created_project.id,
            active_key.id,
            active_key.ring_revision,
            Uuid::new_v4(),
        )
        .await
        .expect("emergency revocation should commit");
    assert_eq!(revoked.state, "revoked");
    let revoked_jwks = readiness
        .project_jwks(&created_project.public_id)
        .await
        .expect("Runtime should publish the post-revocation revision");
    assert!(revoked_jwks.keys.is_empty());
    assert!(revoked_jwks.signing_epoch > published_jwks.signing_epoch);

    let mut routers =
        build_routers_with_runtime_incarnation(config, Some(pools), Uuid::from_u128(1));
    routers.mark_ready();
    let control_router = routers.control.take().expect("Control router should exist");
    let denied = control_router
        .clone()
        .oneshot(
            Request::get(format!(
                "/v1/projects/{}/applications/{}",
                created_project.id,
                Uuid::new_v4()
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    let listed = control_router
        .oneshot(
            Request::get("/v1/projects")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer owl_ctrl_v1_{}", "A".repeat(43)),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(listed.status(), StatusCode::OK);
    let listed_body = to_bytes(listed.into_body(), 1_000_000).await.unwrap();
    assert!(
        std::str::from_utf8(&listed_body)
            .unwrap()
            .contains(&created_project.public_id)
    );

    let runtime_router = routers.runtime.take().expect("Runtime router should exist");
    let runtime_config_uri = format!(
        "/v1/projects/{}/auth/config?application_id={}",
        created_project.public_id, created_application.public_id
    );
    let leaked_credential = runtime_router
        .clone()
        .oneshot(
            Request::get(&runtime_config_uri)
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer owl_ctrl_v1_{}", "A".repeat(43)),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(leaked_credential.status(), StatusCode::BAD_REQUEST);
    let public_response = runtime_router
        .clone()
        .oneshot(
            Request::get(&runtime_config_uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(public_response.status(), StatusCode::OK);
    assert_eq!(public_response.headers()[header::CACHE_CONTROL], "no-store");
    let runtime_body = to_bytes(public_response.into_body(), 1_000_000)
        .await
        .unwrap();
    let runtime_json: serde_json::Value = serde_json::from_slice(&runtime_body).unwrap();
    assert_eq!(runtime_json["login_available"], false);
    assert!(runtime_json.get("belongs_to").is_none());
    assert!(runtime_json.get("client_secret").is_none());

    let jwks_response = runtime_router
        .oneshot(
            Request::get(format!(
                "/projects/{}/.well-known/jwks.json",
                created_project.public_id
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(jwks_response.status(), StatusCode::OK);
    let jwks_json: serde_json::Value = serde_json::from_slice(
        &to_bytes(jwks_response.into_body(), 1_000_000)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(jwks_json["keys"], serde_json::json!([]));

    let current_application = provisioning
        .get_application(created_project.id, created_application.id)
        .await
        .expect("Application should remain available before disablement");
    let disabled_application = provisioning
        .disable_application(
            created_project.id,
            created_application.id,
            current_application.security_revision,
            Uuid::new_v4(),
        )
        .await
        .expect("Application disablement should commit atomically");
    assert_eq!(disabled_application.status, "disabled");
    assert_eq!(
        application_provider_assignment::Entity::find_by_id((
            created_project.id,
            created_application.id,
            provider.id,
        ))
        .one(control)
        .await
        .expect("assignment should be queryable")
        .expect("assignment should remain as terminal history")
        .status,
        "disabled"
    );
    assert_eq!(
        application_publishable_key::Entity::find()
            .filter(application_publishable_key::Column::ProjectId.eq(created_project.id))
            .filter(application_publishable_key::Column::ApplicationId.eq(created_application.id),)
            .one(control)
            .await
            .expect("publishable key should be queryable")
            .expect("publishable key should remain as terminal history")
            .status,
        "disabled"
    );
    assert_eq!(
        provider_configuration::Entity::find_by_id(provider.id)
            .one(control)
            .await
            .expect("provider should be queryable")
            .expect("provider should remain configured")
            .status,
        "active"
    );
    assert_eq!(
        readiness
            .public_application_config(&created_project.public_id, &created_application.public_id,)
            .await,
        Err(ApplicationError::NotFound)
    );

    let current_project = provisioning
        .get_project(created_project.id)
        .await
        .expect("current Project metadata revision should be queryable");
    let unavailable_signer_key = provisioning
        .provision_signing_key(
            created_project.id,
            "signing-missing-material-12345678".to_owned(),
            current_project.metadata_revision,
            Uuid::new_v4(),
        )
        .await
        .expect("a key should publish before signer validation");
    readiness
        .project_jwks(&created_project.public_id)
        .await
        .expect("primary Runtime should observe the new revision");
    secondary_readiness
        .project_jwks(&created_project.public_id)
        .await
        .expect("secondary Runtime should observe the new revision");
    let primary_lease = runtime_publication_lease::Entity::find()
        .filter(runtime_publication_lease::Column::ProjectId.eq(created_project.id))
        .filter(runtime_publication_lease::Column::ProcessId.eq("runtime-test-process"))
        .one(control)
        .await
        .expect("primary lease should be queryable")
        .expect("primary lease should exist");
    let database_now: time::OffsetDateTime = sqlx::query_scalar("SELECT transaction_timestamp()")
        .fetch_one(&mut incarnation_blocker)
        .await
        .expect("database time should be queryable for explicit lease expiry");
    let mut primary_lease_active = primary_lease.into_active_model();
    primary_lease_active.first_observed_at = Set(database_now - time::Duration::seconds(3));
    primary_lease_active.last_observed_at = Set(database_now - time::Duration::seconds(2));
    primary_lease_active.expires_at = Set(database_now - time::Duration::seconds(1));
    let expired_primary_lease = primary_lease_active
        .update(control)
        .await
        .expect("primary Runtime lease should expire explicitly");
    assert!(expired_primary_lease.expires_at <= database_now);
    assert_eq!(
        provisioning
            .activate_signing_key(
                created_project.id,
                unavailable_signer_key.id,
                unavailable_signer_key.ring_revision,
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::PublicationPending)
    );
    readiness
        .project_jwks(&created_project.public_id)
        .await
        .expect("primary Runtime should renew its stale lease");
    secondary_readiness
        .project_jwks(&created_project.public_id)
        .await
        .expect("secondary Runtime should renew its stale lease");
    let renewed_primary_lease = runtime_publication_lease::Entity::find()
        .filter(runtime_publication_lease::Column::ProjectId.eq(created_project.id))
        .filter(runtime_publication_lease::Column::ProcessId.eq("runtime-test-process"))
        .one(control)
        .await
        .expect("renewed primary lease should be queryable")
        .expect("primary lease should still exist");
    assert!(
        renewed_primary_lease.first_observed_at > expired_primary_lease.first_observed_at,
        "an expired same-revision lease starts a new propagation observation"
    );
    assert_eq!(
        renewed_primary_lease.first_observed_at,
        renewed_primary_lease.last_observed_at
    );
    tokio::time::sleep(Duration::from_millis(15)).await;
    let signer_model = project_signing_key::Entity::find_by_id(unavailable_signer_key.id)
        .one(control)
        .await
        .expect("signing key should be queryable")
        .expect("signing key should exist");
    std::fs::remove_file(signer_root.join(format!("{}.owls", signer_model.signer_ref)))
        .expect("signer material should be removable for the controlled failure");
    assert_eq!(
        provisioning
            .activate_signing_key(
                created_project.id,
                unavailable_signer_key.id,
                unavailable_signer_key.ring_revision,
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::Integrity)
    );

    let lease_before_disable = runtime_publication_lease::Entity::find()
        .filter(runtime_publication_lease::Column::ProjectId.eq(created_project.id))
        .filter(runtime_publication_lease::Column::ProcessId.eq("runtime-test-process"))
        .one(control)
        .await
        .expect("pre-disable lease should be queryable")
        .expect("pre-disable lease should exist");
    let disable_transaction = control
        .begin()
        .await
        .expect("disable race transaction should begin");
    let locked_project = project::Entity::find_by_id(created_project.id)
        .lock_exclusive()
        .one(&disable_transaction)
        .await
        .expect("Project should lock for disable race")
        .expect("Project should exist");
    let mut disabled = locked_project.into_active_model();
    disabled.status = Set("disabled".to_owned());
    disabled.security_revision = Set(created_project.security_revision + 1);
    disabled
        .update(&disable_transaction)
        .await
        .expect("uncommitted disable should update the locked Project");

    let raced_readiness = readiness.clone();
    let raced_project_public_id = created_project.public_id.clone();
    let jwks_read =
        tokio::spawn(async move { raced_readiness.project_jwks(&raced_project_public_id).await });
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert!(
        !jwks_read.is_finished(),
        "JWKS read must serialize behind the Project disable lock"
    );
    disable_transaction
        .commit()
        .await
        .expect("Project disable race should commit");
    assert_eq!(
        jwks_read.await.expect("JWKS race task should join"),
        Err(ApplicationError::NotFound)
    );
    let lease_after_disable = runtime_publication_lease::Entity::find()
        .filter(runtime_publication_lease::Column::ProjectId.eq(created_project.id))
        .filter(runtime_publication_lease::Column::ProcessId.eq("runtime-test-process"))
        .one(control)
        .await
        .expect("post-disable lease should be queryable")
        .expect("post-disable lease should remain as history");
    assert_eq!(
        lease_after_disable.last_observed_at, lease_before_disable.last_observed_at,
        "a JWKS read that loses the disable race must not write a lease"
    );

    created_project.id
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the revision-fence journey preserves Project revisions across signing and provider external effects"
)]
async fn verify_project_and_external_effect_revision_fences(
    created_project: ProjectRecord,
    provisioning: &ProvisioningService,
    store_root: &std::path::Path,
    control: &DatabaseConnection,
) -> (ProjectRecord, Uuid) {
    let initial_policy = provisioning
        .get_project_policy(created_project.id)
        .await
        .expect("new Projects should have an atomic default policy");
    assert_eq!(initial_policy.access_token_lifetime_seconds, 900);
    assert!(!initial_policy.browser_session_reuse);
    assert_eq!(
        (
            initial_policy.claims_revision,
            initial_policy.session_revision
        ),
        (1, 1)
    );
    let updated_policy = provisioning
        .update_project_policy(
            created_project.id,
            UpdateProjectPolicy {
                access_token_lifetime_seconds: 1_200,
                browser_session_reuse: true,
                expected_claims_revision: initial_policy.claims_revision,
                expected_session_revision: initial_policy.session_revision,
            },
            Uuid::new_v4(),
        )
        .await
        .expect("policy revisions should advance atomically");
    assert_eq!(
        (
            updated_policy.claims_revision,
            updated_policy.session_revision
        ),
        (2, 2)
    );
    assert_eq!(
        provisioning
            .update_project_policy(
                created_project.id,
                UpdateProjectPolicy {
                    access_token_lifetime_seconds: 1_800,
                    browser_session_reuse: false,
                    expected_claims_revision: 1,
                    expected_session_revision: 2,
                },
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::RevisionConflict)
    );

    assert_eq!(
        provisioning
            .list_projects(Some("customer-42".to_owned()))
            .await
            .expect("owner filtering should succeed")
            .iter()
            .map(|project| project.id)
            .collect::<Vec<_>>(),
        [created_project.id]
    );
    assert!(
        provisioning
            .list_projects(Some("customer".to_owned()))
            .await
            .expect("owner filtering is exact")
            .is_empty()
    );
    let moved_project = provisioning
        .update_project(
            created_project.id,
            UpdateProject {
                display_name: created_project.display_name.clone(),
                belongs_to: Some("customer-84".to_owned()),
                expected_metadata_revision: created_project.metadata_revision,
            },
            Uuid::new_v4(),
        )
        .await
        .expect("Project ownership metadata should be replaceable");
    assert!(
        provisioning
            .list_projects(Some("customer-42".to_owned()))
            .await
            .expect("old owner filter should succeed")
            .is_empty()
    );
    let created_project = provisioning
        .update_project(
            moved_project.id,
            UpdateProject {
                display_name: moved_project.display_name.clone(),
                belongs_to: None,
                expected_metadata_revision: moved_project.metadata_revision,
            },
            Uuid::new_v4(),
        )
        .await
        .expect("Project ownership metadata should be clearable");
    assert_eq!(created_project.belongs_to, None);

    let key_fence_project = provisioning
        .create_project(
            CreateProject {
                display_name: "Key fence project".to_owned(),
                belongs_to: None,
                idempotency_key: "key-fence-project-12345678".to_owned(),
            },
            Uuid::new_v4(),
        )
        .await
        .expect("key fence Project should be created");
    let key_fence_signer_root = store_root.join("key-fence-signers");
    let key_fence_signer = EncryptedFileStore::new(key_fence_signer_root.clone(), [21; 32])
        .expect("key fence signer store should initialize");
    let key_fence_secret = EncryptedFileStore::new(store_root.join("key-fence-secrets"), [22; 32])
        .expect("key fence secret store should initialize");
    let key_fence_put_calls = Arc::new(AtomicUsize::new(0));
    let key_revision_store = RevisionBumpingSignerStore {
        inner: key_fence_signer,
        database: control.clone(),
        project_id: key_fence_project.id,
        bumped: Arc::new(AtomicBool::new(false)),
        put_calls: key_fence_put_calls.clone(),
    };
    let key_fence_service = ProvisioningService::new(
        Arc::new(PostgresProvisioningAdapter::new(
            control.clone(),
            url::Url::parse("https://identity.example/runtime/").unwrap(),
            vec!["runtime-test-process".to_owned()],
            Duration::from_millis(10),
            Duration::from_secs(1),
        )),
        ProvisioningInfrastructure::new(
            key_revision_store.clone(),
            key_fence_secret.clone(),
            SystemClock,
            SystemEntropy,
            Sha256RequestDigester,
            false,
        ),
    );
    assert_eq!(
        key_fence_service
            .provision_signing_key(
                key_fence_project.id,
                "key-fence-operation-12345678".to_owned(),
                key_fence_project.metadata_revision,
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::RevisionConflict),
        "a Project metadata change after signer creation must fence material recording"
    );
    let key_fence_operation = key_provisioning_operation::Entity::find()
        .filter(
            key_provisioning_operation::Column::OperationAlias.eq("key-fence-operation-12345678"),
        )
        .one(control)
        .await
        .expect("key fence operation should be queryable")
        .expect("key fence operation should remain durable");
    assert_eq!(key_fence_operation.state, "prepared");
    assert_eq!(
        key_fence_operation.expected_project_revision,
        key_fence_project.metadata_revision
    );
    let key_fence_resource_id = key_fence_operation.key_id;
    assert_eq!(
        std::fs::read_dir(&key_fence_signer_root)
            .expect("key fence signer directory should exist")
            .count(),
        1
    );
    assert_eq!(key_fence_put_calls.load(Ordering::SeqCst), 1);
    let restarted_key_fence_service = ProvisioningService::new(
        Arc::new(PostgresProvisioningAdapter::new(
            control.clone(),
            url::Url::parse("https://identity.example/runtime/").unwrap(),
            vec!["runtime-test-process".to_owned()],
            Duration::from_millis(10),
            Duration::from_secs(1),
        )),
        ProvisioningInfrastructure::new(
            key_revision_store,
            key_fence_secret,
            SystemClock,
            SystemEntropy,
            Sha256RequestDigester,
            false,
        ),
    );
    assert_eq!(
        restarted_key_fence_service
            .reconcile_signing_key(
                key_fence_project.id,
                key_fence_resource_id,
                key_fence_project.metadata_revision,
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::RevisionConflict),
        "restart and retry must preserve the captured stale fence rather than overwrite it"
    );
    let retried_key_fence_operation = key_provisioning_operation::Entity::find()
        .filter(
            key_provisioning_operation::Column::OperationAlias.eq("key-fence-operation-12345678"),
        )
        .one(control)
        .await
        .expect("retried key fence operation should be queryable")
        .expect("retried key fence operation should remain durable");
    assert_eq!(retried_key_fence_operation.id, key_fence_operation.id);
    assert_eq!(retried_key_fence_operation.key_id, key_fence_resource_id);
    assert_eq!(
        std::fs::read_dir(&key_fence_signer_root)
            .expect("key fence signer directory should remain readable")
            .count(),
        1,
        "retry must not create a replacement signer"
    );
    assert_eq!(
        key_fence_put_calls.load(Ordering::SeqCst),
        1,
        "a stale prepared operation must fail before another signer call"
    );
    let mut stored_key_fence_operation = retried_key_fence_operation.into_active_model();
    stored_key_fence_operation.state = Set("stored".to_owned());
    stored_key_fence_operation
        .update(control)
        .await
        .expect("stored stale key operation fixture should persist");
    let reconciled_key = restarted_key_fence_service
        .reconcile_signing_key(
            key_fence_project.id,
            key_fence_resource_id,
            key_fence_project.metadata_revision + 1,
            Uuid::new_v4(),
        )
        .await
        .expect("current authorization should reconcile the same stored key operation");
    assert_eq!(reconciled_key.id, key_fence_resource_id);
    let reconciled_key_fence_operation = key_provisioning_operation::Entity::find()
        .filter(
            key_provisioning_operation::Column::OperationAlias.eq("key-fence-operation-12345678"),
        )
        .one(control)
        .await
        .expect("reconciled key operation should be queryable")
        .expect("reconciled key operation should remain durable");
    assert_eq!(reconciled_key_fence_operation.id, key_fence_operation.id);
    assert_eq!(reconciled_key_fence_operation.state, "completed");
    assert_eq!(
        reconciled_key_fence_operation.expected_project_revision,
        key_fence_project.metadata_revision + 1
    );
    assert_eq!(
        std::fs::read_dir(&key_fence_signer_root)
            .expect("reconciled signer directory should remain readable")
            .count(),
        1,
        "reauthorization must reconcile the original signer alias"
    );
    assert_eq!(
        key_fence_put_calls.load(Ordering::SeqCst),
        2,
        "reauthorization should verify the original external signer alias once"
    );

    let abandon_adapter = PostgresProvisioningAdapter::new(
        control.clone(),
        url::Url::parse("https://identity.example/runtime/").unwrap(),
        vec!["runtime-test-process".to_owned()],
        Duration::from_millis(10),
        Duration::from_secs(1),
    );
    let incomplete = abandon_adapter
        .prepare_signing_key(
            key_fence_project.id,
            "key-abandon-operation-12345678".to_owned(),
            "signer/key-abandon-operation-12345678".to_owned(),
            key_fence_project.metadata_revision + 1,
            vec![7; 32],
        )
        .await
        .expect("a durable pre-material key should be prepared");
    let incomplete_record = abandon_adapter
        .get_signing_key(key_fence_project.id, incomplete.key_id)
        .await
        .expect("the pre-material key should remain listable");
    assert_eq!(incomplete_record.public_jwk, serde_json::json!({}));
    let abandoned = restarted_key_fence_service
        .revoke_signing_key(
            key_fence_project.id,
            incomplete.key_id,
            incomplete_record.ring_revision,
            Uuid::new_v4(),
        )
        .await
        .expect("revoking a pre-material key should atomically abandon it");
    assert_eq!(abandoned.state, "abandoned");
    assert_eq!(abandoned.public_jwk, serde_json::json!({}));
    let abandoned_operation =
        key_provisioning_operation::Entity::find_by_id(incomplete.operation_id)
            .one(control)
            .await
            .expect("abandoned key operation should be queryable")
            .expect("abandoned key operation should remain durable");
    assert_eq!(abandoned_operation.state, "abandoned");
    assert_eq!(
        restarted_key_fence_service
            .reconcile_signing_key(
                key_fence_project.id,
                incomplete.key_id,
                key_fence_project.metadata_revision + 1,
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::InvalidTransition),
        "an abandoned key operation must not be resumed"
    );

    let provider_fence_project = provisioning
        .create_project(
            CreateProject {
                display_name: "Provider fence project".to_owned(),
                belongs_to: None,
                idempotency_key: "provider-fence-project-12345678".to_owned(),
            },
            Uuid::new_v4(),
        )
        .await
        .expect("provider fence Project should be created");
    let provider_fence_signer =
        EncryptedFileStore::new(store_root.join("provider-fence-signers"), [23; 32])
            .expect("provider fence signer store should initialize");
    let provider_fence_secret_root = store_root.join("provider-fence-secrets");
    let provider_fence_secret =
        EncryptedFileStore::new(provider_fence_secret_root.clone(), [24; 32])
            .expect("provider fence secret store should initialize");
    let provider_fence_put_calls = Arc::new(AtomicUsize::new(0));
    let provider_revision_store = RevisionBumpingSecretStore {
        inner: provider_fence_secret,
        database: control.clone(),
        project_id: provider_fence_project.id,
        bumped: Arc::new(AtomicBool::new(false)),
        put_calls: provider_fence_put_calls.clone(),
    };
    let provider_fence_service = ProvisioningService::new(
        Arc::new(PostgresProvisioningAdapter::new(
            control.clone(),
            url::Url::parse("https://identity.example/runtime/").unwrap(),
            vec!["runtime-test-process".to_owned()],
            Duration::from_millis(10),
            Duration::from_secs(1),
        )),
        ProvisioningInfrastructure::new(
            provider_fence_signer.clone(),
            provider_revision_store.clone(),
            SystemClock,
            SystemEntropy,
            Sha256RequestDigester,
            false,
        ),
    );
    let provider_fence_command = || CreateProvider {
        kind: crate::domain::ProviderKind::Oidc,
        provider_key: "fenced-workforce".to_owned(),
        display_name: "Fenced Workforce".to_owned(),
        issuer: "https://fenced-accounts.example/".to_owned(),
        client_id: "owlauth-fence-test".to_owned(),
        client_secret: zeroize::Zeroizing::new("provider-fence-secret".to_owned()),
        managed_profile_enabled: false,
        idempotency_key: "provider-fence-operation-12345678".to_owned(),
        expected_project_revision: provider_fence_project.metadata_revision,
        egress_policy_revision: Some(1),
    };
    assert_eq!(
        provider_fence_service
            .create_provider(
                provider_fence_project.id,
                provider_fence_command(),
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::RevisionConflict),
        "a Project metadata change after secret creation must fence stored-state recording"
    );
    let provider_fence_operation = provider_secret_operation::Entity::find()
        .filter(
            provider_secret_operation::Column::OperationAlias
                .eq("provider-fence-operation-12345678"),
        )
        .one(control)
        .await
        .expect("provider fence operation should be queryable")
        .expect("provider fence operation should remain durable");
    assert_eq!(provider_fence_operation.state, "prepared");
    assert_eq!(
        provider_fence_operation.expected_project_revision,
        provider_fence_project.metadata_revision
    );
    let provider_fence_resource_id = provider_fence_operation.provider_id;
    assert_eq!(
        std::fs::read_dir(&provider_fence_secret_root)
            .expect("provider fence secret directory should exist")
            .count(),
        1
    );
    assert_eq!(provider_fence_put_calls.load(Ordering::SeqCst), 1);
    let restarted_provider_fence_service = ProvisioningService::new(
        Arc::new(PostgresProvisioningAdapter::new(
            control.clone(),
            url::Url::parse("https://identity.example/runtime/").unwrap(),
            vec!["runtime-test-process".to_owned()],
            Duration::from_millis(10),
            Duration::from_secs(1),
        )),
        ProvisioningInfrastructure::new(
            provider_fence_signer,
            provider_revision_store,
            SystemClock,
            SystemEntropy,
            Sha256RequestDigester,
            false,
        ),
    );
    assert_eq!(
        restarted_provider_fence_service
            .reconcile_provider(
                provider_fence_project.id,
                provider_fence_resource_id,
                zeroize::Zeroizing::new("provider-fence-secret".to_owned()),
                provider_fence_project.metadata_revision,
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::RevisionConflict),
        "restart and retry must preserve the captured stale provider fence"
    );
    let retried_provider_fence_operation = provider_secret_operation::Entity::find()
        .filter(
            provider_secret_operation::Column::OperationAlias
                .eq("provider-fence-operation-12345678"),
        )
        .one(control)
        .await
        .expect("retried provider fence operation should be queryable")
        .expect("retried provider fence operation should remain durable");
    assert_eq!(
        retried_provider_fence_operation.id,
        provider_fence_operation.id
    );
    assert_eq!(
        retried_provider_fence_operation.provider_id,
        provider_fence_resource_id
    );
    assert_eq!(
        std::fs::read_dir(&provider_fence_secret_root)
            .expect("provider fence secret directory should remain readable")
            .count(),
        1,
        "retry must not create a replacement secret"
    );
    assert_eq!(
        provider_fence_put_calls.load(Ordering::SeqCst),
        1,
        "a stale prepared operation must fail before another secret-store call"
    );
    let mut conflicting_provider_fence_command = provider_fence_command();
    conflicting_provider_fence_command.display_name = "Different Workforce".to_owned();
    assert_eq!(
        restarted_provider_fence_service
            .create_provider(
                provider_fence_project.id,
                conflicting_provider_fence_command,
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::IdempotencyConflict),
        "digest conflict must take precedence over a stale captured revision"
    );
    assert_eq!(
        provider_fence_put_calls.load(Ordering::SeqCst),
        1,
        "digest conflict must fail before another secret-store call"
    );
    let mut stored_provider_fence_operation = retried_provider_fence_operation.into_active_model();
    stored_provider_fence_operation.state = Set("stored".to_owned());
    stored_provider_fence_operation
        .update(control)
        .await
        .expect("stored stale provider operation fixture should persist");
    assert_eq!(
        restarted_provider_fence_service
            .reconcile_provider(
                provider_fence_project.id,
                provider_fence_resource_id,
                zeroize::Zeroizing::new("wrong-provider-fence-secret".to_owned()),
                provider_fence_project.metadata_revision + 1,
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::IdempotencyConflict),
        "resource-keyed reconciliation must reject a different re-entered secret"
    );
    assert_eq!(
        provider_fence_put_calls.load(Ordering::SeqCst),
        1,
        "wrong secret reconciliation must fail before another external write"
    );
    let reconciled_provider = restarted_provider_fence_service
        .reconcile_provider(
            provider_fence_project.id,
            provider_fence_resource_id,
            zeroize::Zeroizing::new("provider-fence-secret".to_owned()),
            provider_fence_project.metadata_revision + 1,
            Uuid::new_v4(),
        )
        .await
        .expect("current authorization should reconcile the same stored provider operation");
    assert_eq!(reconciled_provider.id, provider_fence_resource_id);
    let reconciled_provider_fence_operation = provider_secret_operation::Entity::find()
        .filter(
            provider_secret_operation::Column::OperationAlias
                .eq("provider-fence-operation-12345678"),
        )
        .one(control)
        .await
        .expect("reconciled provider operation should be queryable")
        .expect("reconciled provider operation should remain durable");
    assert_eq!(
        reconciled_provider_fence_operation.id,
        provider_fence_operation.id
    );
    assert_eq!(reconciled_provider_fence_operation.state, "completed");
    assert_eq!(
        reconciled_provider_fence_operation.expected_project_revision,
        provider_fence_project.metadata_revision + 1
    );
    assert_eq!(
        std::fs::read_dir(&provider_fence_secret_root)
            .expect("reconciled provider secret directory should remain readable")
            .count(),
        1,
        "reauthorization must reconcile the original provider secret alias"
    );
    assert_eq!(
        provider_fence_put_calls.load(Ordering::SeqCst),
        2,
        "reauthorization should verify the original external secret alias once"
    );

    (created_project, key_fence_project.id)
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the listenerless import journey preserves its complete inventory, resume, and cutover sequence"
)]
async fn verify_listenerless_custody_import(
    custody_project: ProjectRecord,
    config: ServerConfig,
    control: &DatabaseConnection,
    provisioning: ProvisioningService,
    signer_store: EncryptedFileStore,
    secret_store: EncryptedFileStore,
    secret_root: std::path::PathBuf,
    software_custody: SoftwareCustodyProvider,
) {
    // The listenerless importer resumes from durable operations, verifies legacy plaintext,
    // attaches every owner/snapshot, and performs the inventory check plus authority switch in
    // one final transaction.
    let legacy_import_project = provisioning
        .get_project(custody_project.id)
        .await
        .expect("legacy import Project should remain active");
    control
        .execute_raw(Statement::from_string(
            DbBackend::Postgres,
            "UPDATE custody_cutover_authority
            SET mode='legacy',revision=revision+1,legacy_inventory_completed_at=NULL,
                protected_at=NULL,updated_at=transaction_timestamp()
          WHERE singleton"
                .to_owned(),
        ))
        .await
        .expect("legacy upgrade fixture should enter legacy authority");
    let mut control_only_config = config.clone();
    control_only_config.mode = PlaneMode::Control;
    let control_only_pools = DatabasePools {
        runtime: None,
        client: None,
        control: Some(control.clone()),
    };
    assert_eq!(
        validate_provider_readiness(
            &control_only_config,
            &control_only_pools,
            &ProviderRegistrations::new(),
        )
        .await,
        Err(ServerError::ProviderReadiness),
        "Control-only business serving must remain stopped until custody cutover is protected"
    );

    let prepared_with_effect_id = Uuid::new_v4();
    let prepared_without_effect_id = Uuid::new_v4();
    let prepared_with_effect_alias = "legacy-prepared-effect-12345678";
    let prepared_without_effect_alias = "legacy-prepared-no-effect-12345678";
    for (provider_id, provider_key, operation_alias) in [
        (
            prepared_with_effect_id,
            "legacy-prepared-effect",
            prepared_with_effect_alias,
        ),
        (
            prepared_without_effect_id,
            "legacy-prepared-no-effect",
            prepared_without_effect_alias,
        ),
    ] {
        control
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "INSERT INTO provider_configurations
                 (id,project_id,provider_key,kind,adapter_kind,display_name,issuer,client_id,
                  callback_url,status,revision)
                 VALUES ($1,$2,$3,'oidc','oidc',$4,$5,$6,$7,'provisioning',1)",
                vec![
                    provider_id.into(),
                    legacy_import_project.id.into(),
                    provider_key.into(),
                    format!("Prepared {provider_key}").into(),
                    format!("https://{provider_key}.example/").into(),
                    format!("{provider_key}-client").into(),
                    format!(
                        "https://identity.example/runtime/projects/test/auth/callback/{provider_key}"
                    )
                    .into(),
                ],
            ))
            .await
            .expect("legacy prepared provider should insert");
        control
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "INSERT INTO provider_secret_operations
                 (id,project_id,provider_id,operation_alias,request_digest,state,
                  expected_project_revision,expected_provider_revision)
                 VALUES ($1,$2,$3,$4,$5,'prepared',$6,1)",
                vec![
                    Uuid::new_v4().into(),
                    legacy_import_project.id.into(),
                    provider_id.into(),
                    operation_alias.into(),
                    vec![71_u8; 32].into(),
                    legacy_import_project.metadata_revision.into(),
                ],
            ))
            .await
            .expect("legacy prepared provider operation should insert");
    }
    let prepared_effect_digest = Sha256::digest(prepared_with_effect_alias.as_bytes());
    let prepared_effect_reference = format!(
        "secret_{}_{}",
        legacy_import_project.id.simple(),
        URL_SAFE_NO_PAD.encode(&prepared_effect_digest[..16])
    );
    ConfigurationSecretProvisioner::provision_if_absent(
        &secret_store,
        prepared_effect_reference,
        zeroize::Zeroizing::new(b"prepared-provider-secret".to_vec()),
    )
    .await
    .expect("legacy prepared provider effect should be written");

    let legacy_provider = provisioning
        .create_provider(
            legacy_import_project.id,
            CreateProvider {
                kind: ProviderKind::Oidc,
                provider_key: "legacy-import-provider".to_owned(),
                display_name: "Legacy import provider".to_owned(),
                issuer: "https://legacy-import.example/".to_owned(),
                client_id: "legacy-import-client".to_owned(),
                client_secret: zeroize::Zeroizing::new("legacy-import-secret".to_owned()),
                managed_profile_enabled: false,
                idempotency_key: "legacy-import-provider-12345678".to_owned(),
                expected_project_revision: legacy_import_project.metadata_revision,
                egress_policy_revision: Some(1),
            },
            Uuid::new_v4(),
        )
        .await
        .expect("legacy bridge fixture should write one file-backed provider");
    let legacy_project_after_provider = provisioning
        .get_project(legacy_import_project.id)
        .await
        .expect("legacy import Project should remain active after provider creation");
    let legacy_smtp_control = EmailControlService::new(
        Arc::new(PostgresEmailControlRepository::new(control.clone())),
        Arc::new(secret_store.clone()),
        Arc::new(SystemClock),
        Arc::new(Sha256RequestDigester),
    );
    let legacy_smtp = legacy_smtp_control
        .create_smtp(
            legacy_import_project.id,
            CreateSmtpConfiguration {
                host: "smtp.legacy-import.example".to_owned(),
                port: 465,
                tls_mode: SmtpControlTlsMode::ImplicitTls,
                sender_address: "login@legacy-import.example".to_owned(),
                sender_name: Some("Legacy importer".to_owned()),
                reply_to: None,
                credential: zeroize::Zeroizing::new(
                    r#"{"username":"legacy","password":"legacy-password"}"#.to_owned(),
                ),
                idempotency_key: "legacy-import-smtp-12345678".to_owned(),
                expected_project_security_revision: legacy_project_after_provider.security_revision,
                correlation_id: Uuid::new_v4(),
            },
        )
        .await
        .expect("legacy bridge fixture should write one file-backed SMTP credential");
    let legacy_smtp_fingerprint = legacy_smtp
        .safe_fingerprint
        .expect("legacy SMTP should retain its safe request fingerprint");
    let legacy_provider_owner = provider_configuration::Entity::find_by_id(legacy_provider.id)
        .one(control)
        .await
        .expect("legacy provider owner query should work")
        .expect("legacy provider owner should exist");
    let legacy_reference = legacy_provider_owner
        .secret_ref
        .expect("legacy provider should retain its file alias before import");

    // A live legacy ceremony snapshots the same provider alias. Import must atomically make the
    // protected material live before switching both the provider owner and this historical
    // interaction to the material ID.
    let legacy_application_id = Uuid::new_v4();
    let legacy_user_id = Uuid::new_v4();
    let legacy_identity_id = Uuid::new_v4();
    let legacy_connection_id = Uuid::new_v4();
    let legacy_reauthorization_id = Uuid::new_v4();
    let legacy_fixture = control
        .begin()
        .await
        .expect("legacy managed reauthorization fixture transaction should begin");
    legacy_fixture
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO applications (id,project_id,public_id,status,revision)
             VALUES ($1,$2,'legacy_import_app','active',1)",
            vec![
                legacy_application_id.into(),
                legacy_import_project.id.into(),
            ],
        ))
        .await
        .expect("legacy import Application should insert");
    legacy_fixture
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO application_provider_assignments
                (project_id,application_id,provider_id,status,security_revision)
             VALUES ($1,$2,$3,'active',1)",
            vec![
                legacy_import_project.id.into(),
                legacy_application_id.into(),
                legacy_provider.id.into(),
            ],
        ))
        .await
        .expect("legacy import provider assignment should insert");
    legacy_fixture
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO project_users
                (id,project_id,public_id,status,base_profile_digest)
             VALUES ($1,$2,'legacy_user_01','active',$3)",
            vec![
                legacy_user_id.into(),
                legacy_import_project.id.into(),
                vec![81_u8; 32].into(),
            ],
        ))
        .await
        .expect("legacy import user should insert");
    legacy_fixture
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO linked_identities
                (id,project_id,user_id,created_via_provider_configuration_id,issuer,subject,
                 status,identity_revision,observed_at)
             SELECT $1,$2,$3,$4,provider.issuer,'legacy-import-subject','active',1,
                    transaction_timestamp()
               FROM provider_configurations AS provider
              WHERE provider.id=$4 AND provider.project_id=$2",
            vec![
                legacy_identity_id.into(),
                legacy_import_project.id.into(),
                legacy_user_id.into(),
                legacy_provider.id.into(),
            ],
        ))
        .await
        .expect("legacy import identity should insert");
    legacy_fixture
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "UPDATE project_users SET primary_profile_identity_id=$2 WHERE id=$1",
            vec![legacy_user_id.into(), legacy_identity_id.into()],
        ))
        .await
        .expect("legacy import identity should become the primary provider source");
    legacy_fixture
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO managed_provider_connections
                (id,project_id,provider_configuration_id,linked_identity_id,user_id,state,
                 revision,generation,credential_generation,project_security_revision,
                 provider_revision,user_security_revision,identity_revision,
                 managed_profile_revision,adapter_key,adapter_capability_revision,
                 required_scopes,supports_revocation,last_safe_outcome,created_at,updated_at)
             SELECT $1,$2,$3,$4,$5,'reauth_required',1,1,1,project.security_revision,
                    provider.revision,1,1,provider.managed_profile_revision,
                    'controlled_oidc_profile_v1',1,ARRAY['openid']::text[],true,
                    'reauth_required',transaction_timestamp(),transaction_timestamp()
               FROM projects AS project
               JOIN provider_configurations AS provider
                 ON provider.project_id=project.id AND provider.id=$3
              WHERE project.id=$2",
            vec![
                legacy_connection_id.into(),
                legacy_import_project.id.into(),
                legacy_provider.id.into(),
                legacy_identity_id.into(),
                legacy_user_id.into(),
            ],
        ))
        .await
        .expect("legacy import managed connection should insert");
    legacy_fixture
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO managed_provider_reauthorization_interactions
                (id,project_id,project_public_id,connection_id,linked_identity_id,user_id,
                 provider_configuration_id,provider_key,provider_display_name,issuer,provider_kind,
                 subject,client_id,secret_ref,provider_egress_policy_revision,application_id,
                 expected_connection_generation,expected_credential_generation,
                 expected_connection_revision,project_security_revision,user_security_revision,
                 identity_revision,provider_revision,managed_profile_revision,application_revision,
                 assignment_security_revision,callback_url,adapter_key,
                 adapter_capability_revision,supports_revocation,required_scopes,
                 provider_pkce_required,oidc_nonce_required,revision,status,expires_at,created_at)
             SELECT $1,$2,project.public_id,$3,$4,$5,provider.id,provider.provider_key,
                    provider.display_name,provider.issuer,'oidc','legacy-import-subject',
                    provider.client_id,$6,1,$7,1,1,1,project.security_revision,1,1,
                    provider.revision,provider.managed_profile_revision,application.revision,1,
                    provider.callback_url,'controlled_oidc_profile_v1',1,true,
                    ARRAY['openid']::text[],true,true,1,'awaiting_browser_binding',
                    transaction_timestamp()+INTERVAL '10 minutes',transaction_timestamp()
               FROM projects AS project
               JOIN provider_configurations AS provider
                 ON provider.project_id=project.id AND provider.id=$8
               JOIN applications AS application
                 ON application.project_id=project.id AND application.id=$7
              WHERE project.id=$2",
            vec![
                legacy_reauthorization_id.into(),
                legacy_import_project.id.into(),
                legacy_connection_id.into(),
                legacy_identity_id.into(),
                legacy_user_id.into(),
                legacy_reference.clone().into(),
                legacy_application_id.into(),
                legacy_provider.id.into(),
            ],
        ))
        .await
        .expect("legacy managed reauthorization snapshot should insert");
    legacy_fixture
        .commit()
        .await
        .expect("legacy managed reauthorization fixture should commit atomically");

    let legacy_path = secret_root.join(format!("{legacy_reference}.owls"));
    let interrupted_path = secret_root.join(format!("{legacy_reference}.interrupted"));
    let importer = PostgresCustodyImporter::new(
        control.clone(),
        "test-deployment",
        signer_store.clone(),
        secret_store.clone(),
        software_custody.clone(),
    )
    .expect("listenerless importer should compose");

    control
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "UPDATE project_smtp_configurations SET safe_fingerprint=$2 WHERE id=$1",
            vec![legacy_smtp.id.into(), vec![99_u8; 32].into()],
        ))
        .await
        .expect("legacy fingerprint mismatch fixture should install");
    assert_eq!(
        importer.run().await,
        Err(ApplicationError::Integrity),
        "a retained legacy fingerprint mismatch must block cutover"
    );
    let mismatched_operation = control
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT state,failure_class,attempt_count FROM custody_import_operations
              WHERE owner_kind='project_smtp' AND owner_id=$1",
            vec![legacy_smtp.id.into()],
        ))
        .await
        .expect("mismatched import operation query should work")
        .expect("mismatched import operation should remain durable");
    assert_eq!(
        mismatched_operation
            .try_get::<String>("", "state")
            .expect("operation state should decode"),
        "failed"
    );
    assert_eq!(
        mismatched_operation
            .try_get::<String>("", "failure_class")
            .expect("operation failure class should decode"),
        "mismatch"
    );
    control
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "UPDATE project_smtp_configurations SET safe_fingerprint=$2 WHERE id=$1",
            vec![
                legacy_smtp.id.into(),
                legacy_smtp_fingerprint.to_vec().into(),
            ],
        ))
        .await
        .expect("legacy fingerprint should restore for resume");

    std::fs::rename(&legacy_path, &interrupted_path)
        .expect("legacy file should be temporarily unavailable");
    assert_eq!(
        importer.run().await,
        Err(ApplicationError::Integrity),
        "a missing retained legacy file must block cutover"
    );
    let failed_operation = control
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT state,attempt_count FROM custody_import_operations
              WHERE owner_kind='provider_secret' AND owner_id=$1",
            vec![legacy_provider.id.into()],
        ))
        .await
        .expect("failed import operation query should work")
        .expect("failed import operation should remain durable");
    assert_eq!(
        failed_operation
            .try_get::<String>("", "state")
            .expect("operation state should decode"),
        "failed"
    );
    assert_eq!(
        failed_operation
            .try_get::<i32>("", "attempt_count")
            .expect("operation attempt count should decode"),
        1
    );
    let incomplete_authority = ProtectedMaterialRepository::new(control.clone(), "test-deployment")
        .expect("custody authority repository should compose")
        .authority()
        .await
        .expect("importing authority should remain readable");
    assert_eq!(
        importer.complete_cutover(incomplete_authority).await,
        Err(ApplicationError::InvalidTransition),
        "the authority-locking cutover transaction must reject incomplete inventory"
    );
    std::fs::rename(&interrupted_path, &legacy_path)
        .expect("legacy file should be restored for resume");
    let import_report = importer
        .run()
        .await
        .expect("legacy inventory should resume and import");
    assert!(import_report.imported >= 1);
    validate_provider_readiness(
        &control_only_config,
        &control_only_pools,
        &ProviderRegistrations::new(),
    )
    .await
    .expect("Control-only readiness may pass after protected cutover");
    let resumed_operation = control
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT state,attempt_count FROM custody_import_operations
              WHERE owner_kind='provider_secret' AND owner_id=$1",
            vec![legacy_provider.id.into()],
        ))
        .await
        .expect("resumed import operation query should work")
        .expect("resumed import operation should remain durable");
    assert_eq!(
        resumed_operation
            .try_get::<String>("", "state")
            .expect("operation state should decode"),
        "verified"
    );
    assert_eq!(
        resumed_operation
            .try_get::<i32>("", "attempt_count")
            .expect("operation attempt count should decode"),
        2
    );
    let imported_provider = provider_configuration::Entity::find_by_id(legacy_provider.id)
        .one(control)
        .await
        .expect("imported provider query should work")
        .expect("imported provider should remain present");
    assert!(imported_provider.secret_ref.is_none());
    assert!(imported_provider.secret_material_id.is_some());
    let imported_reauthorization = control
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT secret_ref,secret_material_id
               FROM managed_provider_reauthorization_interactions
              WHERE id=$1",
            vec![legacy_reauthorization_id.into()],
        ))
        .await
        .expect("imported managed reauthorization snapshot query should work")
        .expect("imported managed reauthorization snapshot should remain readable");
    assert!(
        imported_reauthorization
            .try_get::<Option<String>>("", "secret_ref")
            .expect("legacy secret reference should decode")
            .is_none()
    );
    assert_eq!(
        imported_reauthorization
            .try_get::<Option<Uuid>>("", "secret_material_id")
            .expect("protected secret material ID should decode"),
        imported_provider.secret_material_id,
        "legacy interaction and provider must converge on the exact protected material"
    );
    let imported_prepared_provider =
        provider_configuration::Entity::find_by_id(prepared_with_effect_id)
            .one(control)
            .await
            .expect("prepared provider import query should work")
            .expect("prepared provider with a durable file effect should be retained");
    assert_eq!(imported_prepared_provider.status, "active");
    assert_eq!(imported_prepared_provider.revision, 2);
    assert!(imported_prepared_provider.secret_ref.is_none());
    assert!(imported_prepared_provider.secret_material_id.is_some());
    assert!(
        provider_configuration::Entity::find_by_id(prepared_without_effect_id)
            .one(control)
            .await
            .expect("abandoned prepared provider query should work")
            .is_none(),
        "a prepare-stage crash without a file effect should remove the unpublished reservation"
    );
    let abandoned_audit = audit_event::Entity::find()
        .filter(audit_event::Column::ProjectId.eq(legacy_import_project.id))
        .filter(audit_event::Column::TargetId.eq(prepared_without_effect_id))
        .filter(audit_event::Column::Action.eq("custody.legacy_provider_abandoned"))
        .one(control)
        .await
        .expect("legacy abandonment audit query should work");
    assert!(abandoned_audit.is_some());
}

#[allow(
    clippy::too_many_lines,
    reason = "the capacity journey compares concurrent creates and prepared-operation replay at each bound"
)]
async fn verify_capacity_and_replay_limits(control_url: &str) {
    let mut capacity_sql = PgConnection::connect(control_url)
        .await
        .expect("capacity fixture connection should open");
    let project_count: i64 = sqlx::query_scalar("SELECT count(*) FROM projects")
        .fetch_one(&mut capacity_sql)
        .await
        .expect("Project count should be queryable");
    assert!(project_count < 100, "capacity fixture needs room to fill");
    let filler_project_ids = (project_count..99)
        .map(|_| Uuid::new_v4())
        .collect::<Vec<_>>();
    let filler_project_public_ids = filler_project_ids
        .iter()
        .map(|id| format!("prj_capacity_{}", id.simple()))
        .collect::<Vec<_>>();
    sqlx::query(
        "INSERT INTO projects \
         (id, public_id, status, metadata_revision, security_revision) \
         SELECT seed.id, seed.public_id, 'active', 1, 1 \
         FROM UNNEST($1::uuid[], $2::text[]) AS seed(id, public_id)",
    )
    .bind(&filler_project_ids)
    .bind(&filler_project_public_ids)
    .execute(&mut capacity_sql)
    .await
    .expect("Project capacity fixtures should insert");

    let capacity_database = sea_orm::Database::connect(control_url)
        .await
        .expect("capacity adapter pool should open");
    let capacity_adapter = PostgresProvisioningAdapter::new(
        capacity_database.clone(),
        url::Url::parse("https://identity.example/runtime/").unwrap(),
        Vec::new(),
        Duration::from_millis(10),
        Duration::from_secs(1),
    );
    let left_project_command = CreateProject {
        display_name: "Capacity winner left".to_owned(),
        belongs_to: None,
        idempotency_key: "project-capacity-left-12345678".to_owned(),
    };
    let right_project_command = CreateProject {
        display_name: "Capacity winner right".to_owned(),
        belongs_to: None,
        idempotency_key: "project-capacity-right-12345678".to_owned(),
    };
    let (left_project, right_project) = tokio::join!(
        capacity_adapter.create_project(left_project_command.clone(), Uuid::new_v4()),
        capacity_adapter.create_project(right_project_command.clone(), Uuid::new_v4()),
    );
    let (capacity_project, replay_project_command) = match (left_project, right_project) {
        (Ok(created), Err(ApplicationError::InvalidInput)) => (created, left_project_command),
        (Err(ApplicationError::InvalidInput), Ok(created)) => (created, right_project_command),
        outcomes => panic!("exactly one concurrent capacity create must commit: {outcomes:?}"),
    };
    assert_eq!(
        capacity_adapter
            .create_project(replay_project_command, Uuid::new_v4())
            .await
            .expect("completed Project replay must survive full capacity"),
        capacity_project
    );
    assert_eq!(
        capacity_adapter
            .create_project(
                CreateProject {
                    display_name: "Over capacity".to_owned(),
                    belongs_to: None,
                    idempotency_key: "project-over-capacity-12345678".to_owned(),
                },
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::InvalidInput)
    );

    let first_application_command = CreateApplication {
        display_name: "Capacity replay application".to_owned(),
        application_type: ApplicationType::Web,
        idempotency_key: "application-capacity-replay-12345678".to_owned(),
    };
    let first_capacity_application = capacity_adapter
        .create_application(
            capacity_project.id,
            first_application_command.clone(),
            Uuid::new_v4(),
        )
        .await
        .expect("first capacity Application should commit");
    let filler_application_ids = (1..99).map(|_| Uuid::new_v4()).collect::<Vec<_>>();
    let filler_application_public_ids = filler_application_ids
        .iter()
        .map(|id| format!("app_capacity_{}", id.simple()))
        .collect::<Vec<_>>();
    sqlx::query(
        "INSERT INTO applications (id, project_id, public_id, status, revision) \
         SELECT seed.id, $3, seed.public_id, 'active', 1 \
         FROM UNNEST($1::uuid[], $2::text[]) AS seed(id, public_id)",
    )
    .bind(&filler_application_ids)
    .bind(&filler_application_public_ids)
    .bind(capacity_project.id)
    .execute(&mut capacity_sql)
    .await
    .expect("Application capacity fixtures should insert");
    let left_application_command = CreateApplication {
        display_name: "Capacity winner left".to_owned(),
        application_type: ApplicationType::Web,
        idempotency_key: "application-capacity-left-12345678".to_owned(),
    };
    let right_application_command = CreateApplication {
        display_name: "Capacity winner right".to_owned(),
        application_type: ApplicationType::Web,
        idempotency_key: "application-capacity-right-12345678".to_owned(),
    };
    let (left_application, right_application) = tokio::join!(
        capacity_adapter.create_application(
            capacity_project.id,
            left_application_command.clone(),
            Uuid::new_v4(),
        ),
        capacity_adapter.create_application(
            capacity_project.id,
            right_application_command.clone(),
            Uuid::new_v4(),
        ),
    );
    let (capacity_application, replay_application_command) =
        match (left_application, right_application) {
            (Ok(created), Err(ApplicationError::InvalidInput)) => {
                (created, left_application_command)
            }
            (Err(ApplicationError::InvalidInput), Ok(created)) => {
                (created, right_application_command)
            }
            outcomes => {
                panic!(
                    "exactly one concurrent Application capacity create must commit: {outcomes:?}"
                )
            }
        };
    assert_eq!(
        capacity_adapter
            .create_application(
                capacity_project.id,
                replay_application_command,
                Uuid::new_v4(),
            )
            .await
            .expect("capacity-winning Application should replay at full capacity"),
        capacity_application
    );
    assert_eq!(
        capacity_adapter
            .create_application(
                capacity_project.id,
                first_application_command,
                Uuid::new_v4(),
            )
            .await
            .expect("completed Application replay must survive full capacity"),
        first_capacity_application
    );

    let first_provider_command = PrepareProvider {
        kind: crate::domain::ProviderKind::Oidc,
        provider_key: "capacity_replay".to_owned(),
        display_name: "Capacity replay provider".to_owned(),
        issuer: "https://accounts.example/".to_owned(),
        client_id: "capacity-client".to_owned(),
        managed_profile_enabled: false,
        operation_alias: "provider-capacity-replay-12345678".to_owned(),
        expected_project_revision: capacity_project.metadata_revision,
        egress_policy_revision: Some(1),
        request_digest: vec![31; 32],
    };
    let first_capacity_provider = capacity_adapter
        .prepare_provider(capacity_project.id, first_provider_command.clone())
        .await
        .expect("first capacity provider should prepare");
    let filler_provider_ids = (1..100).map(|_| Uuid::new_v4()).collect::<Vec<_>>();
    let filler_provider_keys = (1..100)
        .map(|index| format!("capacity_{index}"))
        .collect::<Vec<_>>();
    sqlx::query(
        "INSERT INTO provider_configurations \
         (id, project_id, provider_key, kind, display_name, issuer, client_id, \
          callback_url, secret_ref, status, revision) \
         SELECT seed.id, $3, seed.provider_key, 'oidc', 'Capacity provider', \
                'https://accounts.example/', 'capacity-client', \
                'https://identity.example/runtime/capacity/' || seed.provider_key, \
                NULL, 'provisioning', 1 \
         FROM UNNEST($1::uuid[], $2::text[]) AS seed(id, provider_key)",
    )
    .bind(&filler_provider_ids)
    .bind(&filler_provider_keys)
    .bind(capacity_project.id)
    .execute(&mut capacity_sql)
    .await
    .expect("provider capacity fixtures should insert");
    assert!(matches!(
        capacity_adapter
            .prepare_provider(
                capacity_project.id,
                PrepareProvider {
                    kind: crate::domain::ProviderKind::Oidc,
                    provider_key: "capacity_overflow".to_owned(),
                    display_name: "Over capacity".to_owned(),
                    issuer: "https://accounts.example/".to_owned(),
                    client_id: "capacity-client".to_owned(),
                    managed_profile_enabled: false,
                    operation_alias: "provider-over-capacity-12345678".to_owned(),
                    expected_project_revision: capacity_project.metadata_revision,
                    egress_policy_revision: Some(1),
                    request_digest: vec![32; 32],
                },
            )
            .await,
        Err(ApplicationError::InvalidInput)
    ));
    let replayed_capacity_provider = capacity_adapter
        .prepare_provider(capacity_project.id, first_provider_command)
        .await
        .expect("prepared provider replay must survive full capacity");
    assert_eq!(
        replayed_capacity_provider.provider_id,
        first_capacity_provider.provider_id
    );
    assert_eq!(
        replayed_capacity_provider.operation_id,
        first_capacity_provider.operation_id
    );

    let first_capacity_key = capacity_adapter
        .prepare_signing_key(
            capacity_project.id,
            "key-capacity-replay-12345678".to_owned(),
            "signer-capacity-replay-12345678".to_owned(),
            capacity_project.metadata_revision,
            vec![41; 32],
        )
        .await
        .expect("first capacity key should prepare");
    let filler_key_ids = (1..100).map(|_| Uuid::new_v4()).collect::<Vec<_>>();
    let filler_kids = filler_key_ids
        .iter()
        .map(|id| format!("kid_capacity_{}", id.simple()))
        .collect::<Vec<_>>();
    let filler_signer_refs = filler_key_ids
        .iter()
        .map(|id| format!("signer_capacity_{}", id.simple()))
        .collect::<Vec<_>>();
    sqlx::query(
        "INSERT INTO project_signing_keys \
         (id, project_id, ring_id, kid, public_jwk, signer_ref, state, ring_revision) \
         SELECT seed.id, $4, $5, seed.kid, '{}'::jsonb, seed.signer_ref, \
                'provisioning', 1 \
         FROM UNNEST($1::uuid[], $2::text[], $3::text[]) \
              AS seed(id, kid, signer_ref)",
    )
    .bind(&filler_key_ids)
    .bind(&filler_kids)
    .bind(&filler_signer_refs)
    .bind(capacity_project.id)
    .bind(first_capacity_key.ring_id)
    .execute(&mut capacity_sql)
    .await
    .expect("signing-key capacity fixtures should insert");
    assert!(matches!(
        capacity_adapter
            .prepare_signing_key(
                capacity_project.id,
                "key-over-capacity-12345678".to_owned(),
                "signer-over-capacity-12345678".to_owned(),
                capacity_project.metadata_revision,
                vec![42; 32],
            )
            .await,
        Err(ApplicationError::InvalidInput)
    ));
    let replayed_capacity_key = capacity_adapter
        .prepare_signing_key(
            capacity_project.id,
            "key-capacity-replay-12345678".to_owned(),
            "signer-capacity-replay-12345678".to_owned(),
            capacity_project.metadata_revision,
            vec![41; 32],
        )
        .await
        .expect("prepared key replay must survive full capacity");
    assert_eq!(replayed_capacity_key.key_id, first_capacity_key.key_id);
    assert_eq!(
        replayed_capacity_key.operation_id,
        first_capacity_key.operation_id
    );

    sqlx::query(
        "UPDATE provider_configurations \
         SET secret_ref = 'capacity-secret', status = 'active' \
         WHERE id = ANY($1::uuid[])",
    )
    .bind(&filler_provider_ids[..51])
    .execute(&mut capacity_sql)
    .await
    .expect("assignment provider fixtures should activate");
    sqlx::query(
        "INSERT INTO application_provider_assignments \
         (project_id, application_id, provider_id, status, security_revision) \
         SELECT $2, $3, provider_id, 'active', 1 \
         FROM UNNEST($1::uuid[]) AS seed(provider_id)",
    )
    .bind(&filler_provider_ids[..50])
    .bind(capacity_project.id)
    .bind(first_capacity_application.id)
    .execute(&mut capacity_sql)
    .await
    .expect("assignment capacity fixtures should insert");
    assert_eq!(
        capacity_adapter
            .assign_provider(
                capacity_project.id,
                filler_provider_ids[50],
                first_capacity_application.id,
                first_capacity_application.security_revision,
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::InvalidTransition)
    );
    capacity_sql
        .close()
        .await
        .expect("capacity fixture connection should close");
    capacity_database
        .close()
        .await
        .expect("capacity pool should close");
}

async fn verify_provisioning_lock_timeout(
    adapter: Arc<PostgresProvisioningAdapter>,
    control: &DatabaseConnection,
    blocker_url: &str,
    project: &ProjectRecord,
) {
    let mut blocker = PgConnection::connect(blocker_url)
        .await
        .expect("independent provisioning blocker should open");
    sqlx::query("BEGIN")
        .execute(&mut blocker)
        .await
        .expect("provisioning blocker should begin");
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut blocker)
        .await
        .expect("provisioning blocker backend ID should be readable");
    sqlx::query("SELECT id FROM projects WHERE id=$1 FOR UPDATE")
        .bind(project.id)
        .execute(&mut blocker)
        .await
        .expect("provisioning blocker should own Project row");
    let operation_alias = "signing-lock-timeout-12345678".to_owned();
    let subject_alias = operation_alias.clone();
    let project_id = project.id;
    let expected_revision = project.metadata_revision;
    let subject = tokio::spawn(async move {
        SigningKeyProvisioningPort::prepare_signing_key(
            adapter.as_ref(),
            project_id,
            subject_alias,
            "signer-lock-timeout-12345678".to_owned(),
            expected_revision,
            vec![91; 32],
        )
        .await
    });
    let mut observer = PgConnection::connect(blocker_url)
        .await
        .expect("provisioning lock observer should open");
    wait_for_sqlx_backend_blocked_by(&mut observer, blocker_pid, "signing provisioning").await;
    assert!(
        matches!(
            subject.await.expect("provisioning subject should join"),
            Err(ApplicationError::Persistence)
        ),
        "provisioning lock timeout must remain a persistence failure"
    );
    assert!(
        key_provisioning_operation::Entity::find()
            .filter(key_provisioning_operation::Column::ProjectId.eq(project_id))
            .filter(key_provisioning_operation::Column::OperationAlias.eq(operation_alias))
            .one(control)
            .await
            .expect("timed-out provisioning operation should be queryable")
            .is_none()
    );
    observer
        .close()
        .await
        .expect("provisioning observer should close");
    sqlx::query("ROLLBACK")
        .execute(&mut blocker)
        .await
        .expect("provisioning blocker should release");
    blocker
        .close()
        .await
        .expect("provisioning blocker should close");
}

#[allow(
    clippy::too_many_lines,
    reason = "the custody authority journey keeps stale-revision and lock-timeout rollback/retry evidence together"
)]
async fn verify_terminal_custody_authority_fence(
    control: &DatabaseConnection,
    blocker_url: &str,
    project_id: Uuid,
) {
    // Every protected writer reserves under the locked custody authority and finalization
    // rechecks the exact mode/revision after the external provider effect. A cutover race makes
    // the losing writer retry instead of committing material under stale authority.
    let authority_fence = ProtectedMaterialRepository::new(control.clone(), "test-deployment")
        .expect("custody authority repository");
    let stale_material_id = Uuid::new_v4();
    authority_fence
        .reserve_project(
            project_id,
            stale_material_id,
            MaterialOwnerKind::ProviderSecret,
            Uuid::new_v4(),
            1,
            MaterialKind::ConfigurationSecret,
            MaterialPurpose::ProviderClientSecret,
            ProviderId::new("software").expect("provider ID"),
            ProviderFormatVersion::new(1).expect("format version"),
        )
        .await
        .expect("protected reservation should snapshot authority");
    control
        .execute_raw(Statement::from_string(
            DbBackend::Postgres,
            "UPDATE custody_cutover_authority
                SET mode='importing',revision=revision+1,protected_at=NULL,
                    updated_at=transaction_timestamp()
              WHERE singleton"
                .to_owned(),
        ))
        .await
        .expect("simulate an authority revision race");
    let stale_finalize = control.begin().await.expect("finalize transaction");
    assert_eq!(
        finalize_pending_material(
            &stale_finalize,
            stale_material_id,
            Some(project_id),
            vec![7; 32],
            Some(vec![8; 32]),
            time::OffsetDateTime::now_utc(),
        )
        .await,
        Err(ApplicationError::RevisionConflict)
    );
    stale_finalize
        .rollback()
        .await
        .expect("stale finalize should roll back");
    assert_eq!(
        authority_fence
            .reserve_project(
                project_id,
                Uuid::new_v4(),
                MaterialOwnerKind::ProviderSecret,
                Uuid::new_v4(),
                1,
                MaterialKind::ConfigurationSecret,
                MaterialPurpose::ProviderClientSecret,
                ProviderId::new("software").expect("provider ID"),
                ProviderFormatVersion::new(1).expect("format version"),
            )
            .await,
        Err(ApplicationError::Disabled)
    );

    control
        .execute_raw(Statement::from_string(
            DbBackend::Postgres,
            "UPDATE custody_cutover_authority
                SET mode='protected',revision=revision+1,
                    legacy_inventory_completed_at=COALESCE(
                        legacy_inventory_completed_at,transaction_timestamp()
                    ),
                    protected_at=COALESCE(protected_at,transaction_timestamp()),
                    updated_at=transaction_timestamp()
              WHERE singleton"
                .to_owned(),
        ))
        .await
        .expect("restore protected custody mode for contention retry");
    let mut blocker = PgConnection::connect(blocker_url)
        .await
        .expect("independent custody blocker should open");
    sqlx::query("BEGIN")
        .execute(&mut blocker)
        .await
        .expect("custody blocker should begin");
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut blocker)
        .await
        .expect("custody blocker backend ID should be readable");
    sqlx::query("SELECT revision FROM custody_cutover_authority WHERE singleton FOR UPDATE")
        .execute(&mut blocker)
        .await
        .expect("custody blocker should own authority row");
    let retry_material_id = Uuid::new_v4();
    let retry_owner_id = Uuid::new_v4();
    let subject_authority = authority_fence.clone();
    let subject = tokio::spawn(async move {
        subject_authority
            .reserve_project(
                project_id,
                retry_material_id,
                MaterialOwnerKind::ProviderSecret,
                retry_owner_id,
                1,
                MaterialKind::ConfigurationSecret,
                MaterialPurpose::ProviderClientSecret,
                ProviderId::new("software").expect("provider ID"),
                ProviderFormatVersion::new(1).expect("format version"),
            )
            .await
    });
    let mut observer = PgConnection::connect(blocker_url)
        .await
        .expect("custody lock observer should open");
    wait_for_sqlx_backend_blocked_by(&mut observer, blocker_pid, "custody authority reservation")
        .await;
    assert_eq!(
        subject.await.expect("custody subject task should join"),
        Err(ApplicationError::Persistence),
        "database lock timeout must roll back without implicit replay"
    );
    assert!(
        protected_material::Entity::find_by_id(retry_material_id)
            .one(control)
            .await
            .expect("timed-out custody reservation should be queryable")
            .is_none()
    );
    observer
        .close()
        .await
        .expect("custody observer should close");
    sqlx::query("ROLLBACK")
        .execute(&mut blocker)
        .await
        .expect("custody blocker should release");
    blocker.close().await.expect("custody blocker should close");
    authority_fence
        .reserve_project(
            project_id,
            retry_material_id,
            MaterialOwnerKind::ProviderSecret,
            retry_owner_id,
            1,
            MaterialKind::ConfigurationSecret,
            MaterialPurpose::ProviderClientSecret,
            ProviderId::new("software").expect("provider ID"),
            ProviderFormatVersion::new(1).expect("format version"),
        )
        .await
        .expect("explicit custody retry should reserve exactly once");
    authority_fence
        .erase_project(
            project_id,
            retry_material_id,
            time::OffsetDateTime::now_utc(),
        )
        .await
        .expect("retry fixture should become an erased tombstone");
}

#[allow(
    clippy::too_many_lines,
    reason = "the serving-pool journey keeps pool isolation, unit-of-work, idempotency, and egress authority together"
)]
async fn verify_pools_unit_of_work_and_egress(config: &ServerConfig) -> DatabasePools {
    let pools = create_pools(config)
        .await
        .expect("separate serving pools should open");
    let runtime = pools.runtime.as_ref().expect("Runtime pool should exist");
    let control = pools.control.as_ref().expect("Control pool should exist");
    for (plane, database) in [("Runtime", runtime), ("Control", control)] {
        let first = database
            .begin()
            .await
            .expect("first physical slot should acquire");
        let second = database
            .begin()
            .await
            .expect("second physical slot should acquire");
        let mut backend_ids = BTreeSet::new();
        for transaction in [&first, &second] {
            let row = transaction
                .query_one_raw(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "SELECT
                         current_setting('lock_timeout')::interval = $1::interval AS configured,
                         pg_backend_pid() AS backend_id",
                    [format!("{}ms", config.postgres.database_lock_timeout.as_millis()).into()],
                ))
                .await
                .expect("serving lock timeout should be readable")
                .expect("serving lock timeout query should return one row");
            assert!(
                row.try_get::<bool>("", "configured")
                    .expect("serving lock timeout assertion should decode"),
                "{plane} physical sessions must enforce the configured lock timeout"
            );
            backend_ids.insert(
                row.try_get::<i32>("", "backend_id")
                    .expect("serving backend ID should decode"),
            );
        }
        assert_eq!(
            backend_ids.len(),
            2,
            "{plane} must verify two physical sessions"
        );
        first
            .rollback()
            .await
            .expect("first probe should roll back");
        second
            .rollback()
            .await
            .expect("second probe should roll back");
    }
    let runtime_transaction = runtime.begin().await.expect("Runtime slot should acquire");
    let runtime_transaction_two = runtime
        .begin()
        .await
        .expect("second Runtime slot should acquire");
    let control_transaction = timeout(Duration::from_millis(500), control.begin())
        .await
        .expect("Control must not wait for the exhausted Runtime pool")
        .expect("Control slot should acquire");
    assert!(
        timeout(Duration::from_millis(100), runtime.begin())
            .await
            .is_err()
    );
    runtime_transaction
        .rollback()
        .await
        .expect("Runtime transaction should roll back");
    runtime_transaction_two
        .rollback()
        .await
        .expect("second Runtime transaction should roll back");
    control_transaction
        .rollback()
        .await
        .expect("Control transaction should roll back");

    let rolled_back_project = Uuid::new_v4();
    let unit = ProjectUnitOfWork::begin(control)
        .await
        .expect("Unit of Work should begin");
    unit.insert_project_with_audit(
        NewProject {
            id: rolled_back_project,
            public_id: "project_rollback".to_owned(),
            display_name: "Rollback project".to_owned(),
            belongs_to: None,
        },
        Uuid::new_v4(),
    )
    .await
    .expect("representative cross-repository mutation should stage");
    unit.rollback()
        .await
        .expect("Unit of Work should roll back");
    assert!(
        project::Entity::find_by_id(rolled_back_project)
            .one(control)
            .await
            .expect("rollback query should work")
            .is_none()
    );

    let project_id = Uuid::new_v4();
    let key = "create-project-once".to_owned();
    let unit = ProjectUnitOfWork::begin(control)
        .await
        .expect("Unit of Work should begin");
    unit.insert_project_with_audit(
        NewProject {
            id: project_id,
            public_id: "project_committed".to_owned(),
            display_name: "Committed project".to_owned(),
            belongs_to: Some("external-owner".to_owned()),
        },
        Uuid::new_v4(),
    )
    .await
    .expect("Project and audit should stage");
    unit.insert_pending_idempotency(key.clone(), project_id, vec![7; 32])
        .await
        .expect("one-use record should stage");
    unit.commit()
        .await
        .expect("Unit of Work should commit atomically");
    assert_eq!(
        audit_event::Entity::find()
            .all(control)
            .await
            .expect("audit query should work")
            .len(),
        1
    );

    let (left, right) = tokio::join!(
        complete_once(control.clone(), key.clone()),
        complete_once(control.clone(), key)
    );
    assert!(matches!(
        (left, right),
        (
            CompleteIdempotency::Completed,
            CompleteIdempotency::AlreadyCompleted
        ) | (
            CompleteIdempotency::AlreadyCompleted,
            CompleteIdempotency::Completed
        )
    ));

    let egress_policies = PostgresProviderEgressPolicyRepository::new(control.clone());
    let initial_egress = egress_policies
        .get_provider_egress_policy(project_id)
        .await
        .expect("Project trigger should create egress authority atomically");
    assert_eq!(initial_egress.mode, ProviderEgressMode::AllowAll);
    assert!(initial_egress.exact_origins.is_empty());
    assert_eq!(initial_egress.revision, 1);
    let policy_correlation = Uuid::new_v4();
    let exact_policy = ProviderEgressPolicy::new(
        ProviderEgressMode::ExactOrigins,
        vec![
            "https://identity-b.example".to_owned(),
            "https://identity-a.example".to_owned(),
        ],
        false,
    )
    .expect("exact origins should canonicalize");
    let updated_egress = egress_policies
        .update_provider_egress_policy(project_id, exact_policy.clone(), 1, policy_correlation)
        .await
        .expect("current policy revision should update atomically");
    assert_eq!(updated_egress.revision, 2);
    assert_eq!(
        updated_egress.exact_origins,
        ["https://identity-a.example", "https://identity-b.example"].map(str::to_owned)
    );
    assert_eq!(
        egress_policies
            .update_provider_egress_policy(project_id, exact_policy, 1, Uuid::new_v4(),)
            .await
            .expect_err("stale policy revision must not write or audit"),
        ApplicationError::RevisionConflict
    );
    let policy_audit = audit_event::Entity::find()
        .filter(audit_event::Column::ProjectId.eq(project_id))
        .filter(audit_event::Column::Action.eq("provider.egress_policy.updated"))
        .one(control)
        .await
        .expect("policy audit query should work")
        .expect("successful policy update should be audited");
    assert_eq!(policy_audit.correlation_id, policy_correlation);
    assert_eq!(
        policy_audit.safe_context,
        serde_json::json!({"mode":"exact_origins","origin_count":2})
    );
    let preflight_correlation = Uuid::new_v4();
    egress_policies
        .record_oidc_preflight_outcome(project_id, "metadata_rejected", preflight_correlation)
        .await
        .expect("safe preflight outcome should be audited");
    let preflight_audit = audit_event::Entity::find()
        .filter(audit_event::Column::ProjectId.eq(project_id))
        .filter(audit_event::Column::Action.eq("provider.oidc_preflight"))
        .one(control)
        .await
        .expect("preflight audit query should work")
        .expect("preflight should write one safe audit");
    assert_eq!(preflight_audit.outcome, "metadata_rejected");
    assert_eq!(preflight_audit.correlation_id, preflight_correlation);
    assert_eq!(preflight_audit.safe_context, serde_json::json!({}));
    assert_eq!(
        egress_policies
            .record_oidc_preflight_outcome(project_id, "raw_upstream_error", Uuid::new_v4())
            .await
            .expect_err("unreviewed preflight outcome must be rejected"),
        ApplicationError::InvalidInput
    );

    let mut blocker = PgConnection::connect(config.postgres.migration_url.expose())
        .await
        .expect("serving-lock blocker should open");
    sqlx::query("BEGIN")
        .execute(&mut blocker)
        .await
        .expect("serving-lock blocker transaction should begin");
    sqlx::query(
        "SELECT project_id FROM project_provider_egress_policies
          WHERE project_id=$1 FOR UPDATE",
    )
    .bind(project_id)
    .execute(&mut blocker)
    .await
    .expect("serving-lock blocker should own the policy row");
    let database_timeout = control
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "UPDATE project_provider_egress_policies
                SET updated_at=updated_at WHERE project_id=$1",
            [project_id.into()],
        ))
        .await
        .expect_err("serving session lock_timeout must cancel the blocked statement");
    assert_eq!(
        sea_orm_sqlstate(&database_timeout).as_deref(),
        Some("55P03")
    );
    let retry_policy = ProviderEgressPolicy::new(ProviderEgressMode::AllowAll, Vec::new(), false)
        .expect("retry policy should be valid");
    assert_eq!(
        egress_policies
            .update_provider_egress_policy(
                project_id,
                retry_policy.clone(),
                updated_egress.revision,
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::Persistence),
        "database contention is bounded infrastructure failure and is not replayed"
    );
    assert_eq!(
        egress_policies
            .get_provider_egress_policy(project_id)
            .await
            .expect("timed-out transaction should leave authority readable")
            .revision,
        updated_egress.revision
    );
    sqlx::query("ROLLBACK")
        .execute(&mut blocker)
        .await
        .expect("serving-lock blocker should release");
    blocker
        .close()
        .await
        .expect("serving-lock blocker should close");
    let retried = egress_policies
        .update_provider_egress_policy(
            project_id,
            retry_policy,
            updated_egress.revision,
            Uuid::new_v4(),
        )
        .await
        .expect("explicit retry after lock release should commit once");
    assert_eq!(retried.revision, updated_egress.revision + 1);
    assert_eq!(retried.mode, ProviderEgressMode::AllowAll);

    pools
}

#[allow(
    clippy::too_many_lines,
    reason = "the migration journey keeps lock, ownership, history, and compatibility checks together"
)]
async fn migrate_and_verify_main_database(
    admin_url: &str,
    runtime_url: &str,
    control_url: &str,
) -> ServerConfig {
    let mut config = server_config(admin_url, runtime_url, control_url);

    config.postgres.migration_mode = MigrationMode::Verify;
    assert_eq!(
        prepare_schema(&config.postgres)
            .await
            .expect_err("verify must not create absent history"),
        SchemaError::HistoryUnavailable
    );

    config.postgres.migration_mode = MigrationMode::Auto;
    config.postgres.migration_lock_timeout = Duration::from_millis(100);
    let mut lock_connection = PgConnection::connect(admin_url)
        .await
        .expect("lock connection should open");
    let checksum = Crc::<u32>::new(&CRC_32_ISO_HDLC).checksum(b"owlauth_test");
    let lock_id = 0x3d32_ad9e_i64 * i64::from(checksum);
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(lock_id)
        .execute(&mut lock_connection)
        .await
        .expect("migration advisory lock should be held");
    assert_eq!(
        prepare_schema(&config.postgres)
            .await
            .expect_err("bounded migration lock wait must fail"),
        SchemaError::LockTimeout
    );
    lock_connection
        .close()
        .await
        .expect("lock connection should close and release its lock");

    config.postgres.migration_lock_timeout = Duration::from_secs(5);
    let (first, second) = tokio::join!(
        prepare_schema(&config.postgres),
        prepare_schema(&config.postgres)
    );
    first.expect("first concurrent migrator should succeed");
    second.expect("second concurrent migrator should serialize and succeed");

    let mut ownership_connection = PgConnection::connect(admin_url)
        .await
        .expect("ownership query connection should open");
    let schema_owner: String = sqlx::query_scalar(
        "SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = 'public'",
    )
    .fetch_one(&mut ownership_connection)
    .await
    .expect("schema owner should be queryable");
    assert_eq!(schema_owner, "owlauth_owner");
    let table_owners: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT tableowner FROM pg_tables \
         WHERE schemaname = 'public' AND tablename IN (\
             '_sqlx_migrations', 'projects', 'applications', \
             'control_idempotency_records', 'audit_events'\
         )",
    )
    .fetch_all(&mut ownership_connection)
    .await
    .expect("migration-created table owners should be queryable");
    assert_eq!(table_owners, vec!["owlauth_owner".to_owned()]);
    sqlx::query(
        "REVOKE INSERT, UPDATE, DELETE ON _sqlx_migrations \
         FROM owlauth_runtime, owlauth_control",
    )
    .execute(&mut ownership_connection)
    .await
    .expect("serving roles should retain read-only migration history access");
    let history_privileges: (bool, bool) = sqlx::query_as(
        "SELECT \
             has_table_privilege('owlauth_runtime', '_sqlx_migrations', 'SELECT'), \
             has_table_privilege('owlauth_runtime', '_sqlx_migrations', 'INSERT,UPDATE,DELETE')",
    )
    .fetch_one(&mut ownership_connection)
    .await
    .expect("serving history grants should be queryable");
    assert_eq!(history_privileges, (true, false));
    let provider_constraints: Vec<(String, String)> = sqlx::query_as(
        "SELECT conname, pg_get_constraintdef(oid) \
         FROM pg_constraint \
         WHERE conname IN (\
             'provider_configurations_named_adapter_check', \
             'managed_reauthorization_provider_kind_check', \
             'linked_identities_github_numeric_subject_check'\
         ) ORDER BY conname",
    )
    .fetch_all(&mut ownership_connection)
    .await
    .expect("provider-kind constraints should be queryable");
    assert_eq!(provider_constraints.len(), 3);
    assert!(provider_constraints.iter().any(|(name, definition)| {
        name == "provider_configurations_named_adapter_check"
            && definition.contains("accounts.google.com")
            && definition.contains("github.com")
            && definition.contains("NOT managed_profile_enabled")
    }));
    assert!(provider_constraints.iter().any(|(name, definition)| {
        name == "managed_reauthorization_provider_kind_check"
            && definition.contains("'oidc'::text")
            && definition.contains("'google'::text")
            && !definition.contains("'github'::text")
    }));
    assert!(provider_constraints.iter().any(|(name, definition)| {
        name == "linked_identities_github_numeric_subject_check"
            && definition.contains("https://github.com")
            && definition.contains("^[1-9][0-9]{0,19}$")
    }));
    ownership_connection
        .close()
        .await
        .expect("ownership query connection should close");

    verify_url(admin_url, Duration::from_secs(5))
        .await
        .expect("exact serving history should verify without DDL");

    let mut compatibility_connection = PgConnection::connect(admin_url)
        .await
        .expect("compatibility test connection should open");
    sqlx::query(
        "INSERT INTO _sqlx_migrations
             (version,description,success,checksum,execution_time)
         VALUES ($1,'synthetic additive forward migration',TRUE,$2,1)",
    )
    .bind(20_260_806_000_000_i64)
    .bind(vec![73_u8; 48])
    .execute(&mut compatibility_connection)
    .await
    .expect("synthetic forward history should insert");
    verify_url(admin_url, Duration::from_secs(5))
        .await
        .expect("baseline binary should accept its own compatibility floor");
    sqlx::query("UPDATE schema_compatibility SET minimum_binary_schema_level=$1 WHERE singleton")
        .bind(20_260_805_140_001_i64)
        .execute(&mut compatibility_connection)
        .await
        .expect("newer compatibility floor should install");
    assert_eq!(
        verify_url(admin_url, Duration::from_secs(5))
            .await
            .expect_err("newer compatibility floor must reject the baseline binary"),
        SchemaError::IncompatibleHistory
    );
    sqlx::query("UPDATE schema_compatibility SET minimum_binary_schema_level=$1 WHERE singleton")
        .bind(20_260_805_140_000_i64)
        .execute(&mut compatibility_connection)
        .await
        .expect("current compatibility floor should restore");
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version=$1")
        .bind(20_260_806_000_000_i64)
        .execute(&mut compatibility_connection)
        .await
        .expect("synthetic forward history should clean up");
    compatibility_connection
        .close()
        .await
        .expect("compatibility test connection should close");

    config
}

async fn apply_custody_migrations_direct(connection: &mut PgConnection) {
    for migration in [
        include_str!("../../../migrations/20260804000000_key_provider_custody.sql"),
        include_str!("../../../migrations/20260804010000_signing_custody_expansion.sql"),
        include_str!("../../../migrations/20260804020000_provider_custody_expansion.sql"),
        include_str!("../../../migrations/20260804030000_smtp_custody_expansion.sql"),
        include_str!("../../../migrations/20260804040000_webhook_custody_expansion.sql"),
        include_str!("../../../migrations/20260804050000_key_custody_backfill.sql"),
        include_str!("../../../migrations/20260804060000_identity_material_snapshot_backfill.sql"),
        include_str!("../../../migrations/20260804070000_managed_material_snapshot_backfill.sql"),
        include_str!("../../../migrations/20260804080000_deployment_smtp_owner_backfill.sql"),
        include_str!("../../../migrations/20260804090000_key_recovery_index.sql"),
        include_str!("../../../migrations/20260804100000_deployment_smtp_owner_index.sql"),
        include_str!("../../../migrations/20260804110000_webhook_generation_material_index.sql"),
        include_str!("../../../migrations/20260804120000_webhook_cleanup_material_index.sql"),
        include_str!("../../../migrations/20260804130000_webhook_reservation_material_index.sql"),
        include_str!("../../../migrations/20260804140000_custody_unique_constraints.sql"),
        include_str!("../../../migrations/20260804150000_validate_signing_provider_custody.sql"),
        include_str!("../../../migrations/20260804160000_validate_smtp_custody.sql"),
        include_str!("../../../migrations/20260804170000_validate_webhook_custody.sql"),
        include_str!("../../../migrations/20260804180000_deployment_smtp_owner_not_null.sql"),
        include_str!("../../../migrations/20260804190000_protected_material_integrity.sql"),
    ] {
        sqlx::raw_sql(migration)
            .execute(&mut *connection)
            .await
            .expect("ordered custody migration should install");
    }
}

async fn apply_provider_authority_migrations_direct(connection: &mut PgConnection) {
    for migration in [
        include_str!("../../../migrations/20260805000000_provider_onboarding.sql"),
        include_str!("../../../migrations/20260805010000_provider_policy_revision.sql"),
        include_str!("../../../migrations/20260805020000_provider_secret_policy_revision.sql"),
        include_str!("../../../migrations/20260805030000_identity_policy_revision.sql"),
        include_str!(
            "../../../migrations/20260805040000_managed_reauthorization_policy_revision.sql"
        ),
        include_str!("../../../migrations/20260805050000_managed_renewal_policy_revision.sql"),
        include_str!("../../../migrations/20260805060000_login_method_provider_columns.sql"),
        include_str!("../../../migrations/20260805070000_validate_provider_authority.sql"),
        include_str!("../../../migrations/20260805080000_provider_custom_policy_index.sql"),
        include_str!("../../../migrations/20260805090000_provider_authority_functions.sql"),
        include_str!("../../../migrations/20260805100000_login_method_provider_contract.sql"),
    ] {
        sqlx::raw_sql(migration)
            .execute(&mut *connection)
            .await
            .expect("ordered provider-authority migration should install");
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the legacy upgrade journey preserves the ordered partial migrations and bridge assertions"
)]
async fn verify_legacy_upgrade_journey(crash_window_url: &str) {
    let mut crash_window = PgConnection::connect(crash_window_url)
        .await
        .expect("crash-window migration connection should open");
    sqlx::raw_sql(include_str!(
        "../../../migrations/20260803000000_initial.sql"
    ))
    .execute(&mut crash_window)
    .await
    .expect("pre-TS-003 schema should install");
    let crash_project_id = Uuid::new_v4();
    let crash_provider_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO projects
         (id,public_id,status,metadata_revision,security_revision)
         VALUES ($1,'project_crash_window','active',1,1)",
    )
    .bind(crash_project_id)
    .execute(&mut crash_window)
    .await
    .expect("pre-TS-003 crash Project should insert");
    sqlx::query(
        "INSERT INTO provider_configurations
         (id,project_id,provider_key,kind,adapter_kind,display_name,issuer,client_id,
          callback_url,status,revision)
         VALUES ($1,$2,'crash-window','oidc','oidc','Crash window',
                 'https://crash-window.example/','crash-client',
                 'https://identity.example/runtime/projects/crash/auth/callback/crash-window',
                 'provisioning',1)",
    )
    .bind(crash_provider_id)
    .bind(crash_project_id)
    .execute(&mut crash_window)
    .await
    .expect("pre-TS-003 provisioning provider should insert");
    sqlx::query(
        "INSERT INTO provider_secret_operations
         (id,project_id,provider_id,operation_alias,request_digest,state,
          expected_project_revision,expected_provider_revision)
         VALUES ($1,$2,$3,'crash-window-operation-12345678',$4,'prepared',1,1)",
    )
    .bind(Uuid::new_v4())
    .bind(crash_project_id)
    .bind(crash_provider_id)
    .bind(vec![44_u8; 32])
    .execute(&mut crash_window)
    .await
    .expect("pre-TS-003 prepared provider operation should insert");
    apply_custody_migrations_direct(&mut crash_window).await;
    let crash_authority: String =
        sqlx::query_scalar("SELECT mode FROM custody_cutover_authority WHERE singleton")
            .fetch_one(&mut crash_window)
            .await
            .expect("crash-window custody authority should exist");
    assert_eq!(
        crash_authority, "legacy",
        "a prepared provider operation is authoritative legacy inventory even before its file effect"
    );
    let crash_google_provider_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO provider_configurations
         (id,project_id,provider_key,kind,adapter_kind,display_name,issuer,client_id,
          callback_url,status,revision)
         VALUES ($1,$2,'google','oidc','google','Google',
                 'https://accounts.google.com','google-client',
                 'https://identity.example/runtime/projects/crash/auth/callback/google',
                 'provisioning',1)",
    )
    .bind(crash_google_provider_id)
    .bind(crash_project_id)
    .execute(&mut crash_window)
    .await
    .expect("pre-Block-F named provider should insert");
    let legacy_reserved_google_id = Uuid::new_v4();
    let legacy_reserved_github_id = Uuid::new_v4();
    sqlx::query("ALTER TABLE provider_configurations ALTER COLUMN adapter_kind DROP NOT NULL")
        .execute(&mut crash_window)
        .await
        .expect("simulate supported pre-discriminator provider inventory");
    sqlx::query("SET session_replication_role='replica'")
        .execute(&mut crash_window)
        .await
        .expect("disable current compatibility trigger for legacy NULL fixture");
    for (id, key, issuer) in [
        (
            legacy_reserved_google_id,
            "legacy-google-root",
            crate::domain::GOOGLE_ISSUER,
        ),
        (
            legacy_reserved_github_id,
            "legacy-github-root",
            crate::domain::GITHUB_ISSUER,
        ),
    ] {
        sqlx::query(
            "INSERT INTO provider_configurations
             (id,project_id,provider_key,kind,adapter_kind,display_name,issuer,client_id,
              callback_url,status,revision)
             VALUES ($1,$2,$3,'oidc',NULL,'Legacy reserved root',$4,'legacy-client',
                     'https://identity.example/runtime/projects/crash/auth/callback/legacy',
                     'provisioning',1)",
        )
        .bind(id)
        .bind(crash_project_id)
        .bind(key)
        .bind(issuer)
        .execute(&mut crash_window)
        .await
        .expect("pre-discriminator reserved-root provider should insert");
    }
    sqlx::query("SET session_replication_role='origin'")
        .execute(&mut crash_window)
        .await
        .expect("restore compatibility trigger after legacy NULL fixture");
    apply_provider_authority_migrations_direct(&mut crash_window).await;
    let crash_database = Database::connect(crash_window_url)
        .await
        .expect("legacy bridge SeaORM connection should open");
    let crash_egress = PostgresProviderEgressPolicyRepository::new(crash_database.clone());
    assert!(
        crash_egress
            .legacy_provider_policy_bridge_pending()
            .await
            .expect("legacy bridge authority should be readable")
    );
    assert_eq!(
        crash_egress
            .bridge_legacy_provider_policy(
                ProviderEgressPolicy::new(ProviderEgressMode::AllowAll, Vec::new(), false)
                    .expect("allow-all policy should be valid"),
            )
            .await
            .expect_err("legacy bridge must require explicit legacy origins"),
        ApplicationError::InvalidInput
    );
    let legacy_policy = ProviderEgressPolicy::new(
        ProviderEgressMode::ExactOrigins,
        vec!["https://legacy-provider.example".to_owned()],
        false,
    )
    .expect("legacy exact-origin input should be valid");
    crash_egress
        .bridge_legacy_provider_policy(legacy_policy.clone())
        .await
        .expect("legacy Project authority should bridge");
    assert!(
        !crash_egress
            .legacy_provider_policy_bridge_pending()
            .await
            .expect("completed bridge authority should be readable")
    );
    let bridged_policy = crash_egress
        .get_provider_egress_policy(crash_project_id)
        .await
        .expect("legacy Project should receive exact-origin authority");
    assert_eq!(bridged_policy.mode, ProviderEgressMode::ExactOrigins);
    assert_eq!(
        bridged_policy.exact_origins,
        ["https://legacy-provider.example".to_owned()]
    );
    assert_eq!(bridged_policy.revision, 1);
    let bridged_operation_revision: Option<i64> = sqlx::query_scalar(
        "SELECT egress_policy_revision FROM provider_secret_operations
          WHERE project_id=$1 AND provider_id=$2",
    )
    .bind(crash_project_id)
    .bind(crash_provider_id)
    .fetch_one(&mut crash_window)
    .await
    .expect("prepared provider operation authority should be queryable");
    assert_eq!(bridged_operation_revision, Some(1));
    let recovery = PostgresProvisioningAdapter::new(
        crash_database.clone(),
        url::Url::parse("https://identity.example/runtime/").expect("recovery Runtime base"),
        Vec::new(),
        Duration::from_secs(1),
        Duration::from_mins(5),
    )
    .provider_recovery(crash_project_id, crash_provider_id)
    .await
    .expect("bridged prepared Custom OIDC operation should be recoverable");
    assert_eq!(recovery.kind, ProviderKind::Oidc);
    assert_eq!(recovery.egress_policy_revision, Some(1));
    let bridged_provider_revisions: Vec<(Uuid, Option<String>, Option<i64>)> = sqlx::query_as(
        "SELECT id,adapter_kind,onboarding_policy_revision
           FROM provider_configurations WHERE project_id=$1 ORDER BY id",
    )
    .bind(crash_project_id)
    .fetch_all(&mut crash_window)
    .await
    .expect("bridged provider authority should be queryable");
    assert!(
        bridged_provider_revisions
            .iter()
            .any(|(id, kind, revision)| {
                *id == crash_provider_id && kind.as_deref() == Some("oidc") && *revision == Some(1)
            })
    );
    assert!(
        bridged_provider_revisions
            .iter()
            .any(|(id, kind, revision)| {
                *id == crash_google_provider_id
                    && kind.as_deref() == Some("google")
                    && revision.is_none()
            })
    );
    for reserved_id in [legacy_reserved_google_id, legacy_reserved_github_id] {
        let (_, adapter_kind, revision) = bridged_provider_revisions
            .iter()
            .find(|(id, _, _)| *id == reserved_id)
            .expect("legacy reserved-root provider should remain inventoried");
        assert!(adapter_kind.is_none());
        assert!(revision.is_none());
    }
    assert_eq!(
        super::provider_row::effective_provider_kind("oidc", None, crate::domain::GOOGLE_ISSUER,),
        Err(ApplicationError::Integrity)
    );
    for reserved_id in [legacy_reserved_google_id, legacy_reserved_github_id] {
        sqlx::query(
            "UPDATE provider_configurations
                SET managed_profile_enabled=managed_profile_enabled
              WHERE project_id=$1 AND id=$2",
        )
        .bind(crash_project_id)
        .bind(reserved_id)
        .execute(&mut crash_window)
        .await
        .expect("unrelated update must preserve unavailable legacy adapter authority");
        let adapter_kind: Option<String> = sqlx::query_scalar(
            "SELECT adapter_kind FROM provider_configurations
              WHERE project_id=$1 AND id=$2",
        )
        .bind(crash_project_id)
        .bind(reserved_id)
        .fetch_one(&mut crash_window)
        .await
        .expect("post-update legacy adapter authority should be readable");
        assert!(adapter_kind.is_none());
    }
    sqlx::query(
        "ALTER TABLE managed_provider_reauthorization_interactions
         DISABLE TRIGGER managed_reauthorization_capture_original_authority",
    )
    .execute(&mut crash_window)
    .await
    .expect("isolate provider-kind compatibility trigger");
    let managed_reauthorization_error = sqlx::query(
        "INSERT INTO managed_provider_reauthorization_interactions
            (id,project_id,provider_configuration_id)
         VALUES ($1,$2,$3)",
    )
    .bind(Uuid::new_v4())
    .bind(crash_project_id)
    .bind(legacy_reserved_google_id)
    .execute(&mut crash_window)
    .await
    .expect_err("legacy reserved-root provider must not acquire managed authority");
    sqlx::query(
        "ALTER TABLE managed_provider_reauthorization_interactions
         ENABLE TRIGGER managed_reauthorization_capture_original_authority",
    )
    .execute(&mut crash_window)
    .await
    .expect("restore managed reauthorization authority trigger");
    let sqlx::Error::Database(managed_reauthorization_error) = managed_reauthorization_error else {
        panic!("managed reauthorization rejection must be a database constraint error");
    };
    assert_eq!(
        managed_reauthorization_error.code().as_deref(),
        Some("23514")
    );
    assert_eq!(
        managed_reauthorization_error.message(),
        "provider does not support managed reauthorization"
    );
    crash_egress
        .bridge_legacy_provider_policy(legacy_policy)
        .await
        .expect("completed bridge replay should be idempotent");
    crash_database
        .close()
        .await
        .expect("legacy bridge SeaORM connection should close");
    crash_window
        .close()
        .await
        .expect("crash-window migration connection should close");
}

#[allow(
    clippy::too_many_lines,
    reason = "the Client journey keeps PostgreSQL lock evidence, one-time credentials, pagination, telemetry, and listener isolation together"
)]
async fn verify_client_key_and_listener_journeys(
    project: &ProjectRecord,
    config: &ServerConfig,
    pools: &DatabasePools,
    admin_url: &str,
) {
    const FIRST_INCARNATION: Uuid = Uuid::from_u128(0xc11e_0001);
    const SECOND_INCARNATION: Uuid = Uuid::from_u128(0xc11e_0002);
    let client = pools.client.as_ref().expect("Client pool should exist");
    let readiness_adapter = Arc::new(PostgresClientDigestReadinessAdapter::new(client.clone()));
    let short_readiness = ClientDigestReadinessService::new(
        readiness_adapter.clone(),
        config.client_process_id.clone(),
        FIRST_INCARNATION,
        [1],
        config.required_client_process_ids.clone(),
        Duration::from_millis(50),
    )
    .expect("short Client readiness should compose");
    short_readiness
        .claim()
        .await
        .expect("first Client incarnation should claim readiness");

    let ring = SoftwareClientKeyRing::new(
        config
            .instance_id
            .clone()
            .expect("Client key digest deployment context"),
        1,
        ClientKeyDigestMaterial::new([b'Z'; 32]),
        BTreeMap::new(),
    )
    .expect("test Client key ring should compose");
    let lifecycle = ClientKeyLifecycleService::new(
        Arc::new(
            PostgresClientKeyRepository::new(
                pools.control.as_ref().expect("Control pool").clone(),
                config.required_client_process_ids.clone(),
            )
            .expect("Client key repository should compose"),
        ),
        Arc::new(ring.issuer()),
        Arc::new(Sha256RequestDigester),
        Arc::new(SystemClock),
    );

    // Hold the exact incarnation parent while create waits. The readiness lease expires during
    // that wait, so clock_timestamp() must reject it after the lock is released rather than using
    // the transaction's stale start time.
    let mut blocker = PgConnection::connect(admin_url)
        .await
        .expect("Client readiness blocker should connect");
    sqlx::query("BEGIN")
        .execute(&mut blocker)
        .await
        .expect("Client readiness blocker should begin");
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut blocker)
        .await
        .expect("Client readiness blocker pid");
    sqlx::query(
        "SELECT process_id FROM client_process_incarnations
          WHERE process_id=$1 FOR UPDATE",
    )
    .bind(&config.client_process_id)
    .fetch_one(&mut blocker)
    .await
    .expect("Client incarnation parent should lock");
    let lifecycle_for_expiry = lifecycle.clone();
    let project_id = project.id;
    let mut expired_create = tokio::spawn(async move {
        lifecycle_for_expiry
            .create_project_client_key(CreateProjectClientKey {
                project_id,
                label: "expires while waiting".to_owned(),
                idempotency_key: "client-key-expired-wait-12345678".to_owned(),
                correlation_id: Uuid::new_v4(),
            })
            .await
    });
    let mut observer = PgConnection::connect(admin_url)
        .await
        .expect("Client lock observer should connect");
    wait_for_sqlx_backend_blocked_by(&mut observer, blocker_pid, "Client key create").await;
    sqlx::query("SELECT pg_sleep(0.075)")
        .execute(&mut observer)
        .await
        .expect("database wall clock should advance beyond the Client readiness lease");
    let lease_expired: bool = sqlx::query_scalar(
        "SELECT lease_expires_at <= clock_timestamp()
           FROM client_key_digest_readiness WHERE process_id=$1",
    )
    .bind(&config.client_process_id)
    .fetch_one(&mut observer)
    .await
    .expect("Client readiness lease expiry should be observable");
    assert!(
        lease_expired,
        "Client readiness fixture lease must be expired"
    );
    sqlx::query("COMMIT")
        .execute(&mut blocker)
        .await
        .expect("Client readiness blocker should commit");
    assert_eq!(
        timeout(Duration::from_secs(2), &mut expired_create)
            .await
            .expect("expired Client create should complete")
            .expect("expired Client create task should not panic")
            .expect_err("expired verifier evidence must fail closed"),
        ApplicationError::ClientVerifierUnavailable
    );
    blocker.close().await.expect("Client blocker should close");
    observer
        .close()
        .await
        .expect("Client observer should close");

    let first_readiness = ClientDigestReadinessService::new(
        readiness_adapter.clone(),
        config.client_process_id.clone(),
        FIRST_INCARNATION,
        [1],
        config.required_client_process_ids.clone(),
        Duration::from_secs(5),
    )
    .expect("first Client readiness should compose");
    first_readiness
        .claim()
        .await
        .expect("first Client readiness should recover");
    let first_created = lifecycle
        .create_project_client_key(CreateProjectClientKey {
            project_id: project.id,
            label: "primary backend".to_owned(),
            idempotency_key: "client-key-primary-12345678".to_owned(),
            correlation_id: Uuid::new_v4(),
        })
        .await
        .expect("Project client key should be created");
    let CreateProjectClientKeyResult::Created {
        metadata: primary_key,
        credential,
    } = first_created
    else {
        panic!("first Project client key must reveal its credential once");
    };
    let credential = credential.expose().to_owned();
    let replay = lifecycle
        .create_project_client_key(CreateProjectClientKey {
            project_id: project.id,
            label: "primary backend".to_owned(),
            idempotency_key: "client-key-primary-12345678".to_owned(),
            correlation_id: Uuid::new_v4(),
        })
        .await
        .expect("same Client create should replay");
    assert!(matches!(
        replay,
        CreateProjectClientKeyResult::ReplayWithoutSecret { ref metadata }
            if metadata.id == primary_key.id
    ));
    assert!(primary_key.credential_acknowledged_at.is_none());
    assert_eq!(
        lifecycle
            .create_project_client_key(CreateProjectClientKey {
                project_id: project.id,
                label: "blocked before delivery acknowledgement".to_owned(),
                idempotency_key: "client-key-blocked-unacknowledged-12345678".to_owned(),
                correlation_id: Uuid::new_v4(),
            })
            .await
            .expect_err("an active unacknowledged credential must block replacement"),
        ApplicationError::InvalidTransition
    );
    let acknowledge_command = AcknowledgeProjectClientKeyDelivery {
        project_id: project.id,
        key_id: primary_key.id,
        expected_revision: primary_key.revision,
        idempotency_key: "client-key-primary-acknowledge-12345678".to_owned(),
        correlation_id: Uuid::new_v4(),
    };
    let primary_key = lifecycle
        .acknowledge_project_client_key_delivery(acknowledge_command.clone())
        .await
        .expect("primary Client credential delivery should be acknowledged");
    assert_eq!(primary_key.revision, 2);
    assert!(primary_key.credential_acknowledged_at.is_some());
    assert_eq!(
        lifecycle
            .acknowledge_project_client_key_delivery(acknowledge_command)
            .await
            .expect("delivery acknowledgement replay should be idempotent"),
        primary_key
    );

    let second_readiness = ClientDigestReadinessService::new(
        readiness_adapter,
        config.client_process_id.clone(),
        SECOND_INCARNATION,
        [1],
        config.required_client_process_ids.clone(),
        Duration::from_secs(5),
    )
    .expect("replacement Client readiness should compose");
    let lifecycle_for_interleave = lifecycle.clone();
    let replacement_create = async move {
        lifecycle_for_interleave
            .create_project_client_key(CreateProjectClientKey {
                project_id: project.id,
                label: "replacement interleave".to_owned(),
                idempotency_key: "client-key-replacement-12345678".to_owned(),
                correlation_id: Uuid::new_v4(),
            })
            .await
    };
    let (replacement_claim, replacement_key) = timeout(Duration::from_secs(2), async {
        tokio::join!(second_readiness.claim(), replacement_create)
    })
    .await
    .expect("claim/create interleaving must not deadlock");
    replacement_claim.expect("replacement incarnation should claim");
    match replacement_key {
        Ok(CreateProjectClientKeyResult::Created { metadata, .. }) => {
            lifecycle
                .acknowledge_project_client_key_delivery(AcknowledgeProjectClientKeyDelivery {
                    project_id: project.id,
                    key_id: metadata.id,
                    expected_revision: metadata.revision,
                    idempotency_key: "client-key-replacement-acknowledge-12345678".to_owned(),
                    correlation_id: Uuid::new_v4(),
                })
                .await
                .expect(
                    "an interleaved successful create must be acknowledged before another create",
                );
        }
        Err(ApplicationError::ClientVerifierUnavailable) => {}
        other => panic!("unexpected interleaved Client create result: {other:?}"),
    }
    let post_replacement_key = match lifecycle
        .create_project_client_key(CreateProjectClientKey {
            project_id: project.id,
            label: "post-replacement verifier".to_owned(),
            idempotency_key: "client-key-post-replacement-12345678".to_owned(),
            correlation_id: Uuid::new_v4(),
        })
        .await
        .expect("create must succeed against the replacement incarnation")
    {
        CreateProjectClientKeyResult::Created { metadata, .. } => metadata,
        CreateProjectClientKeyResult::ReplayWithoutSecret { .. } => {
            panic!("fresh post-replacement create cannot replay")
        }
    };
    assert_eq!(
        first_readiness.renew().await,
        Err(ApplicationError::Disabled),
        "a predecessor incarnation cannot renew after replacement"
    );

    // Seed one materialized directory graph through the same constraints used by Runtime. This
    // gives the real Client listener positive user/projection reads while email/token misses prove
    // the non-enumerating JSON shapes without introducing a second ad hoc projection path.
    let client_application_id = Uuid::new_v4();
    let client_user_id = Uuid::new_v4();
    let client_binding_id = Uuid::new_v4();
    let client_projection_id = Uuid::new_v4();
    let mut graph = PgConnection::connect(admin_url)
        .await
        .expect("Client directory fixture should connect");
    sqlx::query(
        "INSERT INTO email_identity_alias_authority(
             singleton,revision,write_version,target_version,accepted_versions)
         VALUES(TRUE,1,1,1,'[1]'::jsonb) ON CONFLICT(singleton) DO NOTHING",
    )
    .execute(&mut graph)
    .await
    .expect("Client email alias authority should initialize");
    sqlx::query(
        "INSERT INTO applications(
             id,project_id,public_id,display_name,application_type,status,revision,
             metadata_revision,security_revision,created_at,updated_at)
         VALUES($1,$2,'app_client01','Client directory app','web','active',1,1,1,
                transaction_timestamp(),transaction_timestamp())",
    )
    .bind(client_application_id)
    .bind(project.id)
    .execute(&mut graph)
    .await
    .expect("Client directory Application should insert");
    let client_provider_id = Uuid::new_v4();
    let client_identity_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO provider_configurations(
             id,project_id,provider_key,kind,display_name,issuer,client_id,callback_url,
             secret_ref,status,revision)
         VALUES($1,$2,'oidc-client-directory','oidc','Client directory provider',
                'https://client-directory.example.test','client-directory',
                'https://runtime.example.test/callback','client_directory_secret','active',1)",
    )
    .bind(client_provider_id)
    .bind(project.id)
    .execute(&mut graph)
    .await
    .expect("Client directory provider should insert");
    sqlx::query("BEGIN")
        .execute(&mut graph)
        .await
        .expect("Client identity fixture should begin");
    sqlx::query(
        "INSERT INTO project_users(
             id,project_id,public_id,status,user_revision,security_revision,
             base_profile_digest,display_name,created_at,updated_at)
         VALUES($1,$2,'usr_client01','active',7,1,$3,'Client User',
                transaction_timestamp(),transaction_timestamp())",
    )
    .bind(client_user_id)
    .bind(project.id)
    .bind(vec![71_u8; 32])
    .execute(&mut graph)
    .await
    .expect("Client directory user should insert");
    sqlx::query(
        "INSERT INTO linked_identities(
             id,project_id,user_id,created_via_provider_configuration_id,issuer,subject,
             status,identity_revision,display_name,observed_at,created_at,updated_at)
         VALUES($1,$2,$3,$4,'https://client-directory.example.test','client-user-subject',
                'active',1,'Client User',transaction_timestamp(),transaction_timestamp(),
                transaction_timestamp())",
    )
    .bind(client_identity_id)
    .bind(project.id)
    .bind(client_user_id)
    .bind(client_provider_id)
    .execute(&mut graph)
    .await
    .expect("Client directory identity should insert");
    sqlx::query("UPDATE project_users SET primary_profile_identity_id=$2 WHERE id=$1")
        .bind(client_user_id)
        .bind(client_identity_id)
        .execute(&mut graph)
        .await
        .expect("Client directory primary identity should update");
    sqlx::query("COMMIT")
        .execute(&mut graph)
        .await
        .expect("Client identity fixture should commit");

    let email_config = config
        .email_identity_protection
        .as_ref()
        .expect("Client email digest configuration");
    let email_protector: Arc<dyn RuntimeProtector> = Arc::new(
        SoftwareRuntimeProtector::new(
            config
                .instance_id
                .clone()
                .expect("Client email deployment context"),
            email_config.active_version,
            RuntimeKeyMaterial::new(
                email_config.active.digest_key.expose_copy(),
                email_config.active.protection_key.expose_copy(),
            ),
            BTreeMap::new(),
        )
        .expect("Client email digest protector should compose"),
    );
    let email_digester = RuntimeClientEmailLookupDigester::new(
        email_protector,
        BTreeSet::from([email_config.active_version]),
    )
    .expect("Client email lookup digester should compose");
    let known_email_digest = email_digester
        .digest_candidates(project.id, "known@example.test")
        .expect("known email digest candidate")
        .into_iter()
        .next()
        .expect("active email digest candidate");
    let client_email_identity_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO email_identities(
             id,project_id,user_id,status,identity_revision,canonicalization_version,
             address_ciphertext,address_key_version,verified_at)
         VALUES($1,$2,$3,'active',1,1,$4,1,transaction_timestamp())",
    )
    .bind(client_email_identity_id)
    .bind(project.id)
    .bind(client_user_id)
    .bind(vec![81_u8; 41])
    .execute(&mut graph)
    .await
    .expect("secondary Client email identity should insert");
    sqlx::query(
        "INSERT INTO email_identity_aliases(
             project_id,identity_id,canonicalization_version,digest_key_version,lookup_digest)
         VALUES($1,$2,1,$3,$4)",
    )
    .bind(project.id)
    .bind(client_email_identity_id)
    .bind(known_email_digest.key_version)
    .bind(known_email_digest.value.to_vec())
    .execute(&mut graph)
    .await
    .expect("Client email lookup alias should insert");

    sqlx::query(
        "INSERT INTO application_user_bindings(
             id,project_id,application_id,user_id,status,binding_revision,created_at,updated_at)
         VALUES($1,$2,$3,$4,'active',1,transaction_timestamp(),transaction_timestamp())",
    )
    .bind(client_binding_id)
    .bind(project.id)
    .bind(client_application_id)
    .bind(client_user_id)
    .execute(&mut graph)
    .await
    .expect("Client directory binding should insert");
    let user = project_user::Entity::find_by_id(client_user_id)
        .one(client)
        .await
        .expect("Client directory user query")
        .expect("Client directory user exists");
    let (projection_document, projection_digest) =
        super::projection::projection_material(&user, 13, 1, 1)
            .expect("Client directory projection should materialize");
    sqlx::query(
        "INSERT INTO application_user_projections(
             id,project_id,binding_id,application_id,user_id,schema_name,projection_revision,
             source_user_revision,project_policy_revision,application_policy_revision,
             canonical_digest,source_base_profile_digest,document,created_at,updated_at)
         VALUES($1,$2,$3,$4,$5,'owlauth.user.v1',13,7,1,1,$6,$7,$8,$9,$9 + interval '5 minutes')",
    )
    .bind(client_projection_id)
    .bind(project.id)
    .bind(client_binding_id)
    .bind(client_application_id)
    .bind(client_user_id)
    .bind(projection_digest)
    .bind(user.base_profile_digest)
    .bind(projection_document)
    .bind(user.updated_at)
    .execute(&mut graph)
    .await
    .expect("Client directory projection should insert");
    graph
        .close()
        .await
        .expect("Client directory fixture should close");

    let providers = crate::composition::bundled_software_providers(config)
        .expect("validated bundled provider configuration");
    let capabilities = build_http_capabilities(
        config,
        Some(pools),
        Uuid::from_u128(1),
        SECOND_INCARNATION,
        &providers,
    );
    let mut routers = build_routers_with_capabilities(config, capabilities);
    routers.mark_ready();
    let runtime = routers.runtime.take().expect("Runtime router");
    let client_router = routers.client.take().expect("Client router");
    let control = routers.control.take().expect("Control router");
    let client_path = format!("/v1/projects/{}/users", project.public_id);
    let client_authorization = format!("Bearer {credential}");
    let successful = client_router
        .clone()
        .oneshot(
            Request::get(&client_path)
                .header(header::AUTHORIZATION, &client_authorization)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("real Client request should complete");
    assert_eq!(successful.status(), StatusCode::OK);
    let successful_json: serde_json::Value = serde_json::from_slice(
        &to_bytes(successful.into_body(), 4096)
            .await
            .expect("bounded Client list"),
    )
    .expect("Client list should be JSON");
    assert_eq!(successful_json["items"].as_array().map(Vec::len), Some(1));
    assert_eq!(successful_json["items"][0]["user_id"], "usr_client01");
    assert_eq!(successful_json["items"][0]["user_revision"], 7);
    assert_eq!(successful_json["next_cursor"], serde_json::Value::Null);

    // The first observation is normally floored before this freshly created key's created_at.
    // Real PostgreSQL must clamp it to created_at rather than violating the lifecycle constraint,
    // and the detached bounded task must eventually publish that first-use signal.
    let mut telemetry = PgConnection::connect(admin_url)
        .await
        .expect("Client telemetry observer should connect");
    let mut observed_usage = None;
    for _ in 0..120 {
        let row: (bool, bool) = sqlx::query_as(
            "SELECT last_used_at IS NOT NULL,COALESCE(last_used_at >= created_at,FALSE)
               FROM project_client_keys WHERE id=$1",
        )
        .bind(primary_key.id)
        .fetch_one(&mut telemetry)
        .await
        .expect("Client telemetry state should be readable");
        if row.0 {
            observed_usage = Some(row);
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(observed_usage, Some((true, true)));
    telemetry
        .close()
        .await
        .expect("Client telemetry observer should close");

    let exact_user = client_router
        .clone()
        .oneshot(
            Request::get(format!("{client_path}/usr_client01"))
                .header(header::AUTHORIZATION, &client_authorization)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("exact Client user read should complete");
    assert_eq!(exact_user.status(), StatusCode::OK);
    let exact_user: serde_json::Value = serde_json::from_slice(
        &to_bytes(exact_user.into_body(), 4096)
            .await
            .expect("bounded exact Client user"),
    )
    .expect("exact Client user should be JSON");
    assert_eq!(exact_user["user_revision"], 7);

    let email_miss = client_router
        .clone()
        .oneshot(
            Request::post(format!("/v1/projects/{}/users/lookup", project.public_id))
                .header(header::AUTHORIZATION, &client_authorization)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"email":"missing@example.test"}"#))
                .unwrap(),
        )
        .await
        .expect("Client email miss should complete");
    assert_eq!(email_miss.status(), StatusCode::OK);
    let email_miss: serde_json::Value = serde_json::from_slice(
        &to_bytes(email_miss.into_body(), 4096)
            .await
            .expect("bounded Client email miss"),
    )
    .expect("Client email miss should be JSON");
    assert_eq!(email_miss, serde_json::json!({"user": null}));

    let email_hit = client_router
        .clone()
        .oneshot(
            Request::post(format!("/v1/projects/{}/users/lookup", project.public_id))
                .header(header::AUTHORIZATION, &client_authorization)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"email":"known@example.test"}"#))
                .unwrap(),
        )
        .await
        .expect("Client email hit should complete");
    assert_eq!(email_hit.status(), StatusCode::OK);
    let email_hit: serde_json::Value = serde_json::from_slice(
        &to_bytes(email_hit.into_body(), 4096)
            .await
            .expect("bounded Client email hit"),
    )
    .expect("Client email hit should be JSON");
    assert_eq!(email_hit["user"]["user_id"], "usr_client01");
    assert_eq!(email_hit["user"]["user_revision"], 7);
    assert_eq!(email_hit["user"]["verified_email"], serde_json::Value::Null);

    let projection = client_router
        .clone()
        .oneshot(
            Request::get(format!(
                "/v1/projects/{}/applications/app_client01/users/usr_client01",
                project.public_id
            ))
            .header(header::AUTHORIZATION, &client_authorization)
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .expect("Client projection read should complete");
    assert_eq!(projection.status(), StatusCode::OK);
    let projection: serde_json::Value = serde_json::from_slice(
        &to_bytes(projection.into_body(), 8192)
            .await
            .expect("bounded Client projection"),
    )
    .expect("Client projection should be JSON");
    assert_eq!(projection["user_revision"], 7);
    assert_eq!(projection["projection_revision"], 13);
    assert_eq!(projection["user_id"], "usr_client01");

    // Exercise the public maximum page and the (created_at,id) UUID tie-breaker with more than one
    // page of real Project users. The expected order comes from the authoritative PostgreSQL tuple,
    // not from insertion or public-ID order.
    let page_user_ids = (0..101).map(|_| Uuid::new_v4()).collect::<Vec<_>>();
    let page_user_public_ids = (0..101)
        .map(|index| format!("usr_page_{index:03}"))
        .collect::<Vec<_>>();
    let page_identity_ids = (0..101).map(|_| Uuid::new_v4()).collect::<Vec<_>>();
    let mut page_fixture = PgConnection::connect(admin_url)
        .await
        .expect("Client pagination fixture should connect");
    sqlx::query("BEGIN")
        .execute(&mut page_fixture)
        .await
        .expect("Client pagination fixture should begin");
    sqlx::query(
        "INSERT INTO project_users(
             id,project_id,public_id,status,user_revision,security_revision,
             base_profile_digest,display_name,created_at,updated_at)
         SELECT seed.id,$3,seed.public_id,'active',1,1,$4,seed.public_id,
                transaction_timestamp(),transaction_timestamp()
           FROM UNNEST($1::uuid[],$2::text[]) AS seed(id,public_id)",
    )
    .bind(&page_user_ids)
    .bind(&page_user_public_ids)
    .bind(project.id)
    .bind(vec![91_u8; 32])
    .execute(&mut page_fixture)
    .await
    .expect("Client pagination users should insert");
    sqlx::query(
        "INSERT INTO linked_identities(
             id,project_id,user_id,created_via_provider_configuration_id,issuer,subject,
             status,identity_revision,display_name,observed_at,created_at,updated_at)
         SELECT seed.identity_id,$4,seed.user_id,$5,
                'https://client-directory.example.test',seed.public_id || '-subject',
                'active',1,seed.public_id,transaction_timestamp(),transaction_timestamp(),
                transaction_timestamp()
           FROM UNNEST($1::uuid[],$2::uuid[],$3::text[])
                AS seed(identity_id,user_id,public_id)",
    )
    .bind(&page_identity_ids)
    .bind(&page_user_ids)
    .bind(&page_user_public_ids)
    .bind(project.id)
    .bind(client_provider_id)
    .execute(&mut page_fixture)
    .await
    .expect("Client pagination identities should insert");
    sqlx::query(
        "UPDATE project_users owner
            SET primary_profile_identity_id=seed.identity_id
           FROM UNNEST($1::uuid[],$2::uuid[]) AS seed(user_id,identity_id)
          WHERE owner.project_id=$3 AND owner.id=seed.user_id",
    )
    .bind(&page_user_ids)
    .bind(&page_identity_ids)
    .bind(project.id)
    .execute(&mut page_fixture)
    .await
    .expect("Client pagination primary identities should update");
    sqlx::query("COMMIT")
        .execute(&mut page_fixture)
        .await
        .expect("Client pagination fixture should commit");
    let expected_user_order = sqlx::query_scalar::<_, String>(
        "SELECT public_id FROM project_users
          WHERE project_id=$1 ORDER BY created_at,id",
    )
    .bind(project.id)
    .fetch_all(&mut page_fixture)
    .await
    .expect("Client pagination expected order should load");
    page_fixture
        .close()
        .await
        .expect("Client pagination fixture should close");

    let first_page = client_router
        .clone()
        .oneshot(
            Request::get(format!("{client_path}?limit=100"))
                .header(header::AUTHORIZATION, &client_authorization)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("first Client user page should complete");
    assert_eq!(first_page.status(), StatusCode::OK);
    let first_page: serde_json::Value = serde_json::from_slice(
        &to_bytes(first_page.into_body(), 1_048_576)
            .await
            .expect("bounded first Client user page"),
    )
    .expect("first Client user page should be JSON");
    let cursor = first_page["next_cursor"]
        .as_str()
        .expect("full Client page must provide a cursor");
    let second_page = client_router
        .clone()
        .oneshot(
            Request::get(format!("{client_path}?limit=100&cursor={cursor}"))
                .header(header::AUTHORIZATION, &client_authorization)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("second Client user page should complete");
    assert_eq!(second_page.status(), StatusCode::OK);
    let second_page: serde_json::Value = serde_json::from_slice(
        &to_bytes(second_page.into_body(), 1_048_576)
            .await
            .expect("bounded second Client user page"),
    )
    .expect("second Client user page should be JSON");
    assert_eq!(second_page["next_cursor"], serde_json::Value::Null);
    let traversed_user_order = first_page["items"]
        .as_array()
        .expect("first Client page items")
        .iter()
        .chain(
            second_page["items"]
                .as_array()
                .expect("second Client page items"),
        )
        .map(|user| user["user_id"].as_str().expect("Client user ID").to_owned())
        .collect::<Vec<_>>();
    assert_eq!(traversed_user_order, expected_user_order);
    assert_eq!(
        traversed_user_order.iter().collect::<BTreeSet<_>>().len(),
        traversed_user_order.len(),
        "Client user keyset traversal must not overlap"
    );

    let inactive = client_router
        .clone()
        .oneshot(
            Request::post(format!(
                "/v1/projects/{}/tokens/introspect",
                project.public_id
            ))
            .header(header::AUTHORIZATION, &client_authorization)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"token":"not-a-token"}"#))
            .unwrap(),
        )
        .await
        .expect("Client inactive introspection should complete");
    assert_eq!(inactive.status(), StatusCode::OK);
    let inactive: serde_json::Value = serde_json::from_slice(
        &to_bytes(inactive.into_body(), 4096)
            .await
            .expect("bounded inactive introspection"),
    )
    .expect("inactive introspection should be JSON");
    assert_eq!(inactive, serde_json::json!({"active": false}));

    for rejected in [
        format!("Bearer owl_ctrl_v1_{}", "A".repeat(43)),
        format!("Bearer owl_pk_v1_{}", "A".repeat(43)),
    ] {
        let response = client_router
            .clone()
            .oneshot(
                Request::get(&client_path)
                    .header(header::AUTHORIZATION, rejected)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("foreign credential on Client should complete");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let wrong_project = client_router
        .clone()
        .oneshot(
            Request::get("/v1/projects/not-the-owner/users")
                .header(header::AUTHORIZATION, &client_authorization)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("wrong-Project Client request should complete");
    assert_eq!(wrong_project.status(), StatusCode::UNAUTHORIZED);

    let control_with_client_key = control
        .clone()
        .oneshot(
            Request::get("/v1/projects")
                .header(header::AUTHORIZATION, &client_authorization)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("Client key on Control should complete");
    assert_eq!(control_with_client_key.status(), StatusCode::UNAUTHORIZED);
    let control_with_operator = control
        .oneshot(
            Request::get("/v1/projects")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer owl_ctrl_v1_{}", "A".repeat(43)),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("operator key on Control should complete");
    assert_eq!(control_with_operator.status(), StatusCode::OK);
    for authorization in [
        client_authorization.clone(),
        format!("Bearer owl_ctrl_v1_{}", "A".repeat(43)),
    ] {
        let runtime_response = runtime
            .clone()
            .oneshot(
                Request::get(format!(
                    "/v1/projects/{}/auth/config?application_id=missing",
                    project.public_id
                ))
                .header(header::AUTHORIZATION, authorization)
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .expect("credential on public Runtime should complete");
        assert_eq!(runtime_response.status(), StatusCode::BAD_REQUEST);
    }

    // Race one final authenticated read against revocation. Either side may serialize first, but
    // revocation must be terminal and every later request must fail without lifecycle resurrection.
    let client_for_race = client_router.clone();
    let path_for_race = client_path.clone();
    let authorization_for_race = client_authorization.clone();
    let lifecycle_for_revoke = lifecycle.clone();
    let primary_for_revoke = primary_key.clone();
    let (raced_read, revoked) = tokio::join!(
        client_for_race.oneshot(
            Request::get(path_for_race)
                .header(header::AUTHORIZATION, authorization_for_race)
                .body(Body::empty())
                .unwrap(),
        ),
        lifecycle_for_revoke.revoke_project_client_key(RevokeProjectClientKey {
            project_id: project.id,
            key_id: primary_for_revoke.id,
            expected_revision: primary_for_revoke.revision,
            idempotency_key: "client-key-revoke-12345678".to_owned(),
            correlation_id: Uuid::new_v4(),
        })
    );
    assert!(matches!(
        raced_read
            .expect("raced Client read should complete")
            .status(),
        StatusCode::OK | StatusCode::UNAUTHORIZED
    ));
    let revoked = revoked.expect("Client key revocation should commit");
    assert_eq!(revoked.revision, primary_key.revision + 1);
    let denied_after_revoke = client_router
        .oneshot(
            Request::get(&client_path)
                .header(header::AUTHORIZATION, client_authorization)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("revoked Client request should complete");
    assert_eq!(denied_after_revoke.status(), StatusCode::UNAUTHORIZED);
    tokio::time::sleep(Duration::from_millis(150)).await;
    let terminal: (String, i64) = sqlx::query_as(
        "SELECT status,revision FROM project_client_keys WHERE project_id=$1 AND id=$2",
    )
    .bind(project.id)
    .bind(primary_key.id)
    .fetch_one(
        &mut PgConnection::connect(admin_url)
            .await
            .expect("terminal query connection"),
    )
    .await
    .expect("revoked Client key should remain queryable");
    assert_eq!(terminal, ("revoked".to_owned(), primary_key.revision + 1));

    // Inventory includes terminal history and uses immutable (created_at, id) keyset pagination.
    let mut inventory_connection = PgConnection::connect(admin_url)
        .await
        .expect("Client inventory fixture should connect");
    for index in 0_u128..101 {
        let id = Uuid::from_u128(0xc11e_1000 + index);
        let public_key_id = URL_SAFE_NO_PAD.encode(id.as_bytes());
        sqlx::query(
            "INSERT INTO project_client_keys(
                 id,project_id,public_key_id,label,status,digest_key_version,
                 credential_digest,display_prefix,revision,created_at,revoked_at)
             VALUES($1,$2,$3,$4,'revoked',1,$5,$6,2,
                    transaction_timestamp(),transaction_timestamp())",
        )
        .bind(id)
        .bind(project.id)
        .bind(&public_key_id)
        .bind(format!("inventory {index}"))
        .bind(vec![
            u8::try_from(index % 255).expect("bounded fixture byte");
            32
        ])
        .bind(format!("owl_client_v1.{public_key_id}"))
        .execute(&mut inventory_connection)
        .await
        .expect("terminal Client inventory row should insert");
    }
    inventory_connection
        .close()
        .await
        .expect("Client inventory fixture should close");
    let (first_page, cursor, active_unacknowledged_key) = lifecycle
        .list_project_client_keys(project.id, None, Some(100))
        .await
        .expect("first Client inventory page");
    assert_eq!(first_page.len(), 100);
    assert_eq!(
        active_unacknowledged_key
            .as_ref()
            .map(|key| (key.id, key.credential_acknowledged_at)),
        Some((post_replacement_key.id, None)),
        "the bounded delivery gate must expose the unacknowledged key outside this history page"
    );
    let cursor = cursor.expect("more than 100 Client keys require a cursor");
    let (second_page, final_cursor, active_unacknowledged_key) = lifecycle
        .list_project_client_keys(project.id, Some(&cursor), Some(100))
        .await
        .expect("second Client inventory page");
    assert!(second_page.len() >= 3);
    assert_eq!(
        active_unacknowledged_key.as_ref().map(|key| key.id),
        Some(post_replacement_key.id),
        "the delivery gate authority is independent of cursor position"
    );
    assert!(final_cursor.is_none());
    let first_ids = first_page.iter().map(|key| key.id).collect::<BTreeSet<_>>();
    assert!(second_page.iter().all(|key| !first_ids.contains(&key.id)));
}

#[allow(
    clippy::too_many_lines,
    reason = "one container preserves the ordered shared fixtures across named PostgreSQL capability journeys"
)]
#[tokio::test]
async fn postgres_capability_journeys_are_real() {
    let wait = WaitFor::log(LogWaitStrategy::stderr(
        "database system is ready to accept connections",
    ));
    let container = match GenericImage::new("postgres", "17-bookworm")
        .with_exposed_port(POSTGRES_PORT.tcp())
        .with_wait_for(wait)
        .with_env_var("POSTGRES_DB", "owlauth_test")
        .with_env_var("POSTGRES_USER", "owlauth")
        .with_env_var("POSTGRES_PASSWORD", "owlauth_test")
        .start()
        .await
    {
        Ok(container) => container,
        Err(error) => {
            if !unavailable_or_fail(error) {
                return;
            }
            unreachable!();
        }
    };
    let host = container
        .get_host()
        .await
        .expect("host should be available");
    let port = container
        .get_host_port_ipv4(POSTGRES_PORT)
        .await
        .expect("mapped port should be available");
    let url = format!("postgres://owlauth:owlauth_test@{host}:{port}/owlauth_test");
    let mut owner_setup = PgConnection::connect(&url)
        .await
        .expect("owner setup connection should open");
    for statement in [
        "CREATE ROLE owlauth_owner NOLOGIN",
        "CREATE ROLE owlauth_runtime LOGIN PASSWORD 'runtime_test'",
        "CREATE ROLE owlauth_control LOGIN PASSWORD 'control_test'",
        "GRANT owlauth_owner TO owlauth",
        "ALTER SCHEMA public OWNER TO owlauth_owner",
        "GRANT USAGE ON SCHEMA public TO owlauth_runtime, owlauth_control",
        "ALTER DEFAULT PRIVILEGES FOR ROLE owlauth_owner IN SCHEMA public \
         GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO owlauth_runtime, owlauth_control",
        "ALTER DEFAULT PRIVILEGES FOR ROLE owlauth_owner IN SCHEMA public \
         GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO owlauth_runtime, owlauth_control",
    ] {
        sqlx::query(statement)
            .execute(&mut owner_setup)
            .await
            .expect("owner and serving-role setup should succeed");
    }
    sqlx::query("CREATE DATABASE owlauth_crash_window")
        .execute(&mut owner_setup)
        .await
        .expect("crash-window migration database should be created");
    owner_setup
        .close()
        .await
        .expect("owner setup connection should close");

    let crash_window_url =
        format!("postgres://owlauth:owlauth_test@{host}:{port}/owlauth_crash_window");
    verify_legacy_upgrade_journey(&crash_window_url).await;

    let runtime_url = format!("postgres://owlauth_runtime:runtime_test@{host}:{port}/owlauth_test");
    let control_url = format!("postgres://owlauth_control:control_test@{host}:{port}/owlauth_test");
    let config = migrate_and_verify_main_database(&url, &runtime_url, &control_url).await;

    let pools = verify_pools_unit_of_work_and_egress(&config).await;
    let runtime = pools.runtime.as_ref().expect("Runtime pool should exist");
    let control = pools.control.as_ref().expect("Control pool should exist");

    let store_root = env::temp_dir().join(format!("owlauth-provisioning-test-{}", Uuid::new_v4()));
    let signer_root = store_root.join("signers");
    let secret_root = store_root.join("secrets");
    let signer_store = EncryptedFileStore::new(signer_root.clone(), [11; 32]).unwrap();
    let secret_store = EncryptedFileStore::new(secret_root.clone(), [12; 32]).unwrap();
    let provisioning = ProvisioningService::new(
        Arc::new(PostgresProvisioningAdapter::new(
            control.clone(),
            url::Url::parse("https://identity.example/runtime/").unwrap(),
            vec![
                "runtime-test-process".to_owned(),
                "runtime-secondary-process".to_owned(),
            ],
            Duration::from_millis(10),
            Duration::from_secs(1),
        )),
        ProvisioningInfrastructure::new(
            signer_store.clone(),
            secret_store.clone(),
            SystemClock,
            SystemEntropy,
            Sha256RequestDigester,
            false,
        ),
    );
    runtime
        .execute_raw(sea_orm::Statement::from_string(
            sea_orm::DbBackend::Postgres,
            "INSERT INTO runtime_process_incarnations (process_id,process_incarnation,started_at)
             VALUES ('runtime-test-process','00000000-0000-0000-0000-000000000001',transaction_timestamp()),
                    ('runtime-secondary-process','00000000-0000-0000-0000-000000000002',transaction_timestamp()),
                    ('runtime-unexpected-process','00000000-0000-0000-0000-000000000003',transaction_timestamp())"
                .to_owned(),
        ))
        .await
        .expect("seed exact Runtime incarnations");
    // Keep required Runtime leases alive across this test's lock-order scenarios. The
    // unexpected Runtime's stale lease is exercised through explicit expiry below.
    let required_runtime_lease_ttl = Duration::from_secs(10);
    let readiness = ReadinessService::new(Arc::new(PostgresReadinessAdapter::new(
        runtime.clone(),
        "runtime-test-process".to_owned(),
        Uuid::from_u128(1),
        vec![
            "runtime-test-process".to_owned(),
            "runtime-secondary-process".to_owned(),
        ],
        required_runtime_lease_ttl,
    )));
    let secondary_readiness = ReadinessService::new(Arc::new(PostgresReadinessAdapter::new(
        runtime.clone(),
        "runtime-secondary-process".to_owned(),
        Uuid::from_u128(2),
        vec![
            "runtime-test-process".to_owned(),
            "runtime-secondary-process".to_owned(),
        ],
        required_runtime_lease_ttl,
    )));
    let unexpected_readiness = ReadinessService::new(Arc::new(PostgresReadinessAdapter::new(
        runtime.clone(),
        "runtime-unexpected-process".to_owned(),
        Uuid::from_u128(3),
        vec![
            "runtime-test-process".to_owned(),
            "runtime-secondary-process".to_owned(),
        ],
        Duration::from_mins(1),
    )));

    let created_project = provisioning
        .create_project(
            CreateProject {
                display_name: "Production project".to_owned(),
                belongs_to: Some("customer-42".to_owned()),
                idempotency_key: "project-create-12345678".to_owned(),
            },
            Uuid::new_v4(),
        )
        .await
        .expect("Project creation should commit");
    let replayed_project = provisioning
        .create_project(
            CreateProject {
                display_name: "Production project".to_owned(),
                belongs_to: Some("customer-42".to_owned()),
                idempotency_key: "project-create-12345678".to_owned(),
            },
            Uuid::new_v4(),
        )
        .await
        .expect("same idempotent Project request should replay");
    assert_eq!(created_project, replayed_project);

    let custody_project = provisioning
        .create_project(
            CreateProject {
                display_name: "Protected custody project".to_owned(),
                belongs_to: None,
                idempotency_key: "project-custody-12345678".to_owned(),
            },
            Uuid::new_v4(),
        )
        .await
        .expect("custody Project creation should commit");
    let custody_provider_id =
        ProviderId::new("software").expect("software provider ID should parse");
    let custody_format = ProviderFormatVersion::new(1).expect("software format should be non-zero");
    let software_custody = SoftwareCustodyProvider::new(custody_provider_id.clone(), [31; 32])
        .expect("software custody should initialize");
    let custody_adapter = Arc::new(
        PostgresProvisioningAdapter::new(
            control.clone(),
            url::Url::parse("https://identity.example/runtime/").unwrap(),
            vec!["runtime-test-process".to_owned()],
            Duration::from_millis(10),
            Duration::from_secs(1),
        )
        .with_custody(
            "test-deployment",
            custody_provider_id.clone(),
            custody_format,
        )
        .expect("custody adapter should compose"),
    );
    verify_provisioning_lock_timeout(custody_adapter.clone(), control, &url, &custody_project)
        .await;
    let custody_provisioning = ProvisioningService::new(
        custody_adapter.clone(),
        ProvisioningInfrastructure::new(
            signer_store.clone(),
            secret_store.clone(),
            SystemClock,
            SystemEntropy,
            Sha256RequestDigester,
            false,
        )
        .with_signing_provisioner(software_custody.clone())
        .with_secret_sealer(software_custody.clone()),
    );
    let material_repository = ProtectedMaterialRepository::new(control.clone(), "test-deployment")
        .expect("material repository should compose");
    let inventory_before_pending = material_repository
        .material_inventory_revision()
        .await
        .expect("material inventory revision should be readable");
    let pending_secret_material_id = Uuid::new_v4();
    material_repository
        .reserve_project(
            custody_project.id,
            pending_secret_material_id,
            MaterialOwnerKind::ProviderSecret,
            Uuid::new_v4(),
            1,
            MaterialKind::ConfigurationSecret,
            MaterialPurpose::ProviderClientSecret,
            custody_provider_id.clone(),
            custody_format,
        )
        .await
        .expect("pending configuration-secret material should reserve");
    let inventory_after_reserve = material_repository
        .material_inventory_revision()
        .await
        .expect("reserved inventory revision should be readable");
    assert!(inventory_after_reserve > inventory_before_pending);
    material_repository
        .erase_project(
            custody_project.id,
            pending_secret_material_id,
            time::OffsetDateTime::now_utc(),
        )
        .await
        .expect("a never-finalized secret reservation should become an erased tombstone");
    let erased_pending_secret = protected_material::Entity::find_by_id(pending_secret_material_id)
        .one(control)
        .await
        .expect("erased pending-secret query should work")
        .expect("erased pending-secret tombstone should remain");
    assert_eq!(erased_pending_secret.state, "erased");
    assert!(erased_pending_secret.safe_fingerprint.is_none());
    assert!(
        material_repository
            .material_inventory_revision()
            .await
            .expect("erased inventory revision should be readable")
            > inventory_after_reserve
    );
    let late_finalize = control
        .begin()
        .await
        .expect("late finalize transaction should open");
    assert_eq!(
        finalize_pending_material(
            &late_finalize,
            pending_secret_material_id,
            Some(custody_project.id),
            vec![7; 32],
            Some(vec![8; 32]),
            time::OffsetDateTime::now_utc(),
        )
        .await,
        Err(ApplicationError::IdempotencyConflict),
        "late sealing cannot resurrect an erased pending reservation"
    );
    late_finalize
        .rollback()
        .await
        .expect("late finalize transaction should roll back");

    let ownerless_signing_material_id = Uuid::new_v4();
    material_repository
        .reserve_project(
            custody_project.id,
            ownerless_signing_material_id,
            MaterialOwnerKind::SigningKey,
            Uuid::new_v4(),
            1,
            MaterialKind::SigningKey,
            MaterialPurpose::SigningSeed,
            custody_provider_id.clone(),
            custody_format,
        )
        .await
        .expect("pending signing material should reserve before its external effect");
    assert_eq!(
        material_repository
            .erase_project(
                custody_project.id,
                ownerless_signing_material_id,
                time::OffsetDateTime::now_utc(),
            )
            .await,
        Err(ApplicationError::Persistence),
        "ownerless signing material cannot bypass typed-owner integrity during erasure"
    );
    assert_eq!(
        protected_material::Entity::find_by_id(ownerless_signing_material_id)
            .one(control)
            .await
            .expect("ownerless signing material query should work")
            .expect("failed erasure should roll back")
            .state,
        "pending"
    );

    let lock_order_material_id = Uuid::new_v4();
    material_repository
        .reserve_project(
            custody_project.id,
            lock_order_material_id,
            MaterialOwnerKind::ProviderSecret,
            Uuid::new_v4(),
            1,
            MaterialKind::ConfigurationSecret,
            MaterialPurpose::ProviderClientSecret,
            custody_provider_id.clone(),
            custody_format,
        )
        .await
        .expect("lock-order material should reserve");
    let inventory_blocker = control
        .begin()
        .await
        .expect("inventory blocker should begin");
    lock_material_inventory(&inventory_blocker)
        .await
        .expect("inventory blocker should lock authority first");
    let inventory_blocker_pid = inventory_blocker
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT pg_backend_pid() AS pid",
        ))
        .await
        .expect("inventory blocker PID query should work")
        .expect("inventory blocker PID should exist")
        .try_get::<i32>("", "pid")
        .expect("inventory blocker PID should decode");
    let erasing_database = sea_orm::Database::connect(&control_url)
        .await
        .expect("independent erasure pool should open");
    let erasing_repository =
        ProtectedMaterialRepository::new(erasing_database.clone(), "test-deployment")
            .expect("independent erasure repository should compose");
    let erasing_project_id = custody_project.id;
    let erase_task = tokio::spawn(async move {
        erasing_repository
            .erase_project(
                erasing_project_id,
                lock_order_material_id,
                time::OffsetDateTime::now_utc(),
            )
            .await
    });
    let mut lock_order_observer = PgConnection::connect(&control_url)
        .await
        .expect("lock-order observer should open");
    wait_for_sqlx_backend_blocked_by(
        &mut lock_order_observer,
        inventory_blocker_pid,
        "protected-material erasure authority-first lock",
    )
    .await;
    lock_order_observer
        .close()
        .await
        .expect("lock-order observer should close");
    timeout(
        Duration::from_secs(2),
        protected_material::Entity::find_by_id(lock_order_material_id)
            .lock_exclusive()
            .one(&inventory_blocker),
    )
    .await
    .expect("authority-first erasure must not hold material while waiting for authority")
    .expect("lock-order material query should work")
    .expect("lock-order material should exist");
    inventory_blocker
        .commit()
        .await
        .expect("inventory blocker should release authority and material together");
    timeout(Duration::from_secs(2), erase_task)
        .await
        .expect("blocked erasure should finish after authority release")
        .expect("erasure task should not panic")
        .expect("authority-first erasure should commit without deadlock");
    erasing_database
        .close()
        .await
        .expect("independent erasure pool should close");

    let rotated_provider_id =
        ProviderId::new("software-rotated").expect("rotated provider ID should parse");
    let rotated_custody = SoftwareCustodyProvider::new(rotated_provider_id.clone(), [32; 32])
        .expect("rotated software custody should initialize");
    let rotation_project = provisioning
        .create_project(
            CreateProject {
                display_name: "Configuration custody rotation".to_owned(),
                belongs_to: None,
                idempotency_key: "project-secret-rotation-12345678".to_owned(),
            },
            Uuid::new_v4(),
        )
        .await
        .expect("secret rotation Project should commit");
    let rotation_command = CreateProvider {
        kind: ProviderKind::Oidc,
        provider_key: "rotation-provider".to_owned(),
        display_name: "Rotation provider".to_owned(),
        issuer: "https://rotation-provider.example/".to_owned(),
        client_id: "rotation-client".to_owned(),
        client_secret: zeroize::Zeroizing::new("rotation-secret".to_owned()),
        managed_profile_enabled: false,
        idempotency_key: "provider-secret-rotation-12345678".to_owned(),
        expected_project_revision: rotation_project.metadata_revision,
        egress_policy_revision: Some(1),
    };
    let missing_historical_service = ProvisioningService::new(
        custody_adapter.clone(),
        ProvisioningInfrastructure::new(
            signer_store.clone(),
            secret_store.clone(),
            SystemClock,
            SystemEntropy,
            Sha256RequestDigester,
            false,
        )
        .with_provider_capabilities(
            BTreeMap::new(),
            BTreeMap::from([(
                rotated_provider_id.clone(),
                Arc::new(rotated_custody.clone()) as Arc<dyn ConfigurationSecretSealer>,
            )]),
        ),
    );
    assert_eq!(
        missing_historical_service
            .create_provider(
                rotation_project.id,
                rotation_command.clone(),
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::Integrity),
        "a prepared reservation must fail closed when its stored provider is absent"
    );
    let rotated_adapter = Arc::new(
        PostgresProvisioningAdapter::new(
            control.clone(),
            url::Url::parse("https://identity.example/runtime/").unwrap(),
            vec!["runtime-test-process".to_owned()],
            Duration::from_millis(10),
            Duration::from_secs(1),
        )
        .with_custody(
            "test-deployment",
            rotated_provider_id.clone(),
            custody_format,
        )
        .expect("rotated custody adapter should compose"),
    );
    let retained_sealers = BTreeMap::from([
        (
            custody_provider_id.clone(),
            Arc::new(software_custody.clone()) as Arc<dyn ConfigurationSecretSealer>,
        ),
        (
            rotated_provider_id.clone(),
            Arc::new(rotated_custody.clone()) as Arc<dyn ConfigurationSecretSealer>,
        ),
    ]);
    let rotated_service = ProvisioningService::new(
        rotated_adapter.clone(),
        ProvisioningInfrastructure::new(
            signer_store.clone(),
            secret_store.clone(),
            SystemClock,
            SystemEntropy,
            Sha256RequestDigester,
            false,
        )
        .with_provider_capabilities(BTreeMap::new(), retained_sealers),
    );
    let rotated_result = rotated_service
        .create_provider(
            rotation_project.id,
            rotation_command.clone(),
            Uuid::new_v4(),
        )
        .await
        .expect("retained historical sealer should resume the old reservation");
    assert_eq!(
        rotated_service
            .create_provider(rotation_project.id, rotation_command, Uuid::new_v4(),)
            .await
            .expect("completed provider creation should replay after active rotation"),
        rotated_result
    );
    let rotated_owner = provider_configuration::Entity::find_by_id(rotated_result.id)
        .one(control)
        .await
        .expect("rotated provider owner query should work")
        .expect("rotated provider owner should exist");
    let rotated_material = protected_material::Entity::find_by_id(
        rotated_owner
            .secret_material_id
            .expect("rotated provider should reference protected material"),
    )
    .one(control)
    .await
    .expect("rotated provider material query should work")
    .expect("rotated provider material should exist");
    assert_eq!(
        rotated_material.provider_id,
        custody_provider_id.as_str(),
        "historical recovery must use the provider tuple stored by prepare, not the new active provider"
    );

    let stateless_operation_alias = "stateless-recovery-key-12345678".to_owned();
    let stateless_digester = Sha256RequestDigester;
    let stateless_request_digest = stateless_digester
        .digest_json(&serde_json::json!({
            "project_id": custody_project.id,
            "algorithm": "EdDSA",
            "purpose": "application_tokens",
        }))
        .expect("stateless signing request should be canonical");
    let stateless_alias_digest =
        stateless_digester.digest_bytes(stateless_operation_alias.as_bytes());
    let stateless_signer_ref = format!(
        "signer_{}_{}",
        custody_project.id.simple(),
        URL_SAFE_NO_PAD.encode(&stateless_alias_digest[..16])
    );
    let stateless_recovery = custody_adapter
        .prepare_signing_key(
            custody_project.id,
            stateless_operation_alias,
            stateless_signer_ref,
            custody_project.metadata_revision,
            stateless_request_digest,
        )
        .await
        .expect("stateless recovery key should prepare");
    let submitted_at = time::OffsetDateTime::now_utc();
    assert!(matches!(
        custody_adapter
            .claim_signing_provider_action(
                custody_project.id,
                &stateless_recovery,
                submitted_at,
                submitted_at + time::Duration::seconds(30),
            )
            .await
            .expect("stateless provision should be submitted before the simulated crash"),
        SigningProviderAction::Provision(_)
    ));
    let submitted_operation =
        key_provisioning_operation::Entity::find_by_id(stateless_recovery.operation_id)
            .one(control)
            .await
            .expect("submitted stateless operation query should work")
            .expect("submitted stateless operation should exist");
    assert_eq!(submitted_operation.state, "submitted");
    assert!(submitted_operation.material_id.is_some());
    let mut expired_submission = submitted_operation.into_active_model();
    expired_submission.provider_lease_expires_at = Set(Some(
        time::OffsetDateTime::now_utc() - time::Duration::seconds(1),
    ));
    expired_submission
        .update(control)
        .await
        .expect("simulated crash lease should expire before reconciliation");
    let recovered_stateless_key = custody_provisioning
        .reconcile_signing_key(
            custody_project.id,
            stateless_recovery.key_id,
            custody_project.metadata_revision,
            Uuid::new_v4(),
        )
        .await
        .expect("inspect absence should reset and freshly provision the stateless handle");
    assert_eq!(recovered_stateless_key.id, stateless_recovery.key_id);
    let recovered_operation =
        key_provisioning_operation::Entity::find_by_id(stateless_recovery.operation_id)
            .one(control)
            .await
            .expect("recovered stateless operation query should work")
            .expect("recovered stateless operation should exist");
    assert_eq!(recovered_operation.state, "completed");
    let recovered_material = protected_material::Entity::find_by_id(
        recovered_operation
            .material_id
            .expect("recovered stateless operation should retain its reservation"),
    )
    .one(control)
    .await
    .expect("recovered stateless material query should work")
    .expect("recovered stateless material should exist");
    assert_eq!(recovered_material.state, "live");
    assert!(recovered_material.opaque_value.is_some());

    let protected_signing_key = custody_provisioning
        .provision_signing_key(
            custody_project.id,
            "signing-custody-12345678".to_owned(),
            custody_project.metadata_revision,
            Uuid::new_v4(),
        )
        .await
        .expect("signing handle, public key, and owner should commit before publication");
    let protected_signing_owner = project_signing_key::Entity::find_by_id(protected_signing_key.id)
        .one(control)
        .await
        .expect("protected signing owner query should work")
        .expect("protected signing owner should exist");
    let signing_material_id = protected_signing_owner
        .signer_material_id
        .expect("protected signing key should reference one material");
    let signing_material = protected_material::Entity::find_by_id(signing_material_id)
        .one(control)
        .await
        .expect("protected signing material query should work")
        .expect("protected signing material should exist");
    assert_eq!(signing_material.state, "live");
    assert_eq!(signing_material.owner_kind, "signing_key");
    assert_eq!(signing_material.owner_id, protected_signing_key.id);
    assert!(signing_material.safe_fingerprint.is_none());
    assert!(signing_material.opaque_value.is_some());
    let completed_signing_operation = key_provisioning_operation::Entity::find()
        .filter(key_provisioning_operation::Column::ProjectId.eq(custody_project.id))
        .filter(key_provisioning_operation::Column::KeyId.eq(protected_signing_key.id))
        .one(control)
        .await
        .expect("completed signing operation query should work")
        .expect("completed signing operation should exist");
    let prepared_completed_signing = PreparedSigningKey {
        operation_id: completed_signing_operation.id,
        ring_id: completed_signing_operation.ring_id,
        key_id: completed_signing_operation.key_id,
        kid: protected_signing_owner.kid.clone(),
        signer_ref: protected_signing_owner.signer_ref.clone(),
        request_digest: completed_signing_operation.request_digest.clone(),
        state: ProvisioningOperationState::Completed,
    };
    let committed_public_key_bytes = URL_SAFE_NO_PAD
        .decode(
            protected_signing_owner
                .public_jwk
                .get("x")
                .and_then(serde_json::Value::as_str)
                .expect("committed signing JWK should contain x"),
        )
        .expect("committed signing public key should decode");
    custody_adapter
        .record_protected_signing_key_material(
            custody_project.id,
            &prepared_completed_signing,
            custody_project.metadata_revision,
            SigningProviderLease {
                token: Uuid::new_v4(),
            },
            ProvisionedProtectedSigningMaterial {
                material_id: signing_material_id,
                handle: OpaqueHandle::new(
                    signing_material
                        .opaque_value
                        .clone()
                        .expect("committed signing handle should exist"),
                )
                .expect("committed signing handle should parse"),
                public_key: SigningPublicKey::new(
                    SigningAlgorithm::Ed25519,
                    committed_public_key_bytes.clone(),
                )
                .expect("committed public key should parse"),
            },
            protected_signing_owner.public_jwk.clone(),
            time::OffsetDateTime::now_utc(),
        )
        .await
        .expect("a late byte-identical response is a pure authenticated replay");
    assert_eq!(
        custody_adapter
            .record_protected_signing_key_material(
                custody_project.id,
                &prepared_completed_signing,
                custody_project.metadata_revision,
                SigningProviderLease {
                    token: Uuid::new_v4(),
                },
                ProvisionedProtectedSigningMaterial {
                    material_id: signing_material_id,
                    handle: OpaqueHandle::new(vec![91; 48])
                        .expect("mismatched handle fixture should parse"),
                    public_key: SigningPublicKey::new(
                        SigningAlgorithm::Ed25519,
                        committed_public_key_bytes,
                    )
                    .expect("committed public key should parse"),
                },
                protected_signing_owner.public_jwk.clone(),
                time::OffsetDateTime::now_utc(),
            )
            .await,
        Err(ApplicationError::Integrity),
        "a stale terminal response with another handle must never bypass the lease fence"
    );
    let unchanged_signing_material = protected_material::Entity::find_by_id(signing_material_id)
        .one(control)
        .await
        .expect("unchanged signing material query should work")
        .expect("unchanged signing material should exist");
    assert_eq!(unchanged_signing_material, signing_material);

    let disabled_cleanup_project = provisioning
        .create_project(
            CreateProject {
                display_name: "Disabled stored signing cleanup".to_owned(),
                belongs_to: None,
                idempotency_key: "project-disabled-stored-cleanup-12345678".to_owned(),
            },
            Uuid::new_v4(),
        )
        .await
        .expect("disabled-cleanup Project should commit");
    let stored_cleanup_key = custody_provisioning
        .provision_signing_key(
            disabled_cleanup_project.id,
            "disabled-stored-cleanup-key-12345678".to_owned(),
            disabled_cleanup_project.metadata_revision,
            Uuid::new_v4(),
        )
        .await
        .expect("disabled-cleanup key should initially publish");
    let stored_cleanup_owner = project_signing_key::Entity::find_by_id(stored_cleanup_key.id)
        .one(control)
        .await
        .expect("disabled-cleanup key query should work")
        .expect("disabled-cleanup key should exist");
    let stored_cleanup_material_id = stored_cleanup_owner
        .signer_material_id
        .expect("disabled-cleanup key should own material");
    let stored_cleanup_operation = key_provisioning_operation::Entity::find()
        .filter(key_provisioning_operation::Column::ProjectId.eq(disabled_cleanup_project.id))
        .filter(key_provisioning_operation::Column::KeyId.eq(stored_cleanup_key.id))
        .one(control)
        .await
        .expect("stored-before-publish operation query should work")
        .expect("stored-before-publish operation should exist");
    let mut stored_operation = stored_cleanup_operation.clone().into_active_model();
    stored_operation.state = Set("stored".to_owned());
    stored_operation.completed_at = Set(None);
    stored_operation
        .update(control)
        .await
        .expect("stored-before-publish fixture should update the operation");
    let mut provisioning_owner = stored_cleanup_owner.into_active_model();
    provisioning_owner.state = Set("provisioning".to_owned());
    provisioning_owner.published_at = Set(None);
    provisioning_owner
        .update(control)
        .await
        .expect("stored-before-publish fixture should update the key");
    let disabled_cleanup_project_model = project::Entity::find_by_id(disabled_cleanup_project.id)
        .one(control)
        .await
        .expect("disabled-cleanup Project query should work")
        .expect("disabled-cleanup Project should exist");
    let mut disabled_project = disabled_cleanup_project_model.into_active_model();
    disabled_project.status = Set("disabled".to_owned());
    disabled_project
        .update(control)
        .await
        .expect("stored-before-publish Project should be disabled");
    let abandoned_stored_key = custody_provisioning
        .revoke_signing_key(
            disabled_cleanup_project.id,
            stored_cleanup_key.id,
            stored_cleanup_key.ring_revision,
            Uuid::new_v4(),
        )
        .await
        .expect("disabled Project must retain emergency revoke and cleanup authority");
    assert_eq!(abandoned_stored_key.state, "abandoned");
    let queued_stored_operation =
        key_provisioning_operation::Entity::find_by_id(stored_cleanup_operation.id)
            .one(control)
            .await
            .expect("queued stored operation query should work")
            .expect("queued stored operation should exist");
    assert_eq!(queued_stored_operation.state, "cleanup_pending");
    let cleaned_stored_key = custody_provisioning
        .reconcile_signing_key(
            disabled_cleanup_project.id,
            stored_cleanup_key.id,
            disabled_cleanup_project.metadata_revision,
            Uuid::new_v4(),
        )
        .await
        .expect("disabled Project cleanup should remain recoverable");
    assert_eq!(cleaned_stored_key.state, "abandoned");
    let erased_stored_material = protected_material::Entity::find_by_id(stored_cleanup_material_id)
        .one(control)
        .await
        .expect("cleaned stored material query should work")
        .expect("cleaned stored material tombstone should remain durable");
    assert_eq!(erased_stored_material.state, "erased");
    assert!(erased_stored_material.opaque_value.is_none());

    let remote_provider_id = ProviderId::new("remote-test").unwrap();
    let remote_format = ProviderFormatVersion::new(1).unwrap();
    let ambiguous_project = provisioning
        .create_project(
            CreateProject {
                display_name: "Ambiguous remote signing".to_owned(),
                belongs_to: None,
                idempotency_key: "project-remote-ambiguous-12345678".to_owned(),
            },
            Uuid::new_v4(),
        )
        .await
        .expect("remote signing Project should commit");
    let ambiguous_state = Arc::new(Mutex::new(RemoteSigningState {
        ambiguous_provision_once: true,
        ..Default::default()
    }));
    let ambiguous_remote =
        StatefulRemoteSigningProvider::new(remote_provider_id.clone(), ambiguous_state.clone());
    let ambiguous_adapter = Arc::new(
        PostgresProvisioningAdapter::new(
            control.clone(),
            url::Url::parse("https://identity.example/runtime/").unwrap(),
            vec!["runtime-test-process".to_owned()],
            Duration::from_millis(10),
            Duration::from_secs(1),
        )
        .with_provider_custody(
            "test-deployment",
            remote_provider_id.clone(),
            remote_format,
            custody_provider_id.clone(),
            custody_format,
        )
        .expect("remote custody adapter should compose"),
    );
    let ambiguous_service = ProvisioningService::new(
        ambiguous_adapter.clone(),
        ProvisioningInfrastructure::new(
            signer_store.clone(),
            secret_store.clone(),
            SystemClock,
            SystemEntropy,
            Sha256RequestDigester,
            false,
        )
        .with_signing_provisioner(ambiguous_remote.clone()),
    );
    assert_eq!(
        ambiguous_service
            .provision_signing_key(
                ambiguous_project.id,
                "remote-ambiguous-key-12345678".to_owned(),
                ambiguous_project.metadata_revision,
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::ExternalStore),
        "an ambiguous provider effect must remain submitted for inspection"
    );
    let ambiguous_operation = key_provisioning_operation::Entity::find()
        .filter(key_provisioning_operation::Column::ProjectId.eq(ambiguous_project.id))
        .one(control)
        .await
        .expect("ambiguous operation query should work")
        .expect("ambiguous operation should remain durable");
    assert_eq!(ambiguous_operation.state, "submitted");
    assert!(ambiguous_operation.provider_lease_token.is_none());
    assert_expired_signing_provider_lease_is_fenced(
        control,
        &ambiguous_adapter,
        ambiguous_project.id,
        &ambiguous_operation,
    )
    .await;
    let rotated_adapter = PostgresProvisioningAdapter::new(
        control.clone(),
        url::Url::parse("https://identity.example/runtime/").unwrap(),
        vec!["runtime-test-process".to_owned()],
        Duration::from_millis(10),
        Duration::from_secs(1),
    )
    .with_provider_custody(
        "test-deployment",
        custody_provider_id.clone(),
        custody_format,
        custody_provider_id.clone(),
        custody_format,
    )
    .expect("rotated custody adapter should compose");
    let absent_historical_service = ProvisioningService::new(
        Arc::new(rotated_adapter.clone()),
        ProvisioningInfrastructure::new(
            signer_store.clone(),
            secret_store.clone(),
            SystemClock,
            SystemEntropy,
            Sha256RequestDigester,
            false,
        )
        .with_signing_provisioner(software_custody.clone()),
    );
    assert_eq!(
        absent_historical_service
            .provision_signing_key(
                ambiguous_project.id,
                "remote-ambiguous-key-12345678".to_owned(),
                ambiguous_project.metadata_revision,
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::Integrity),
        "an absent historical provisioner must fail closed without changing the operation"
    );
    let historical_provisioners: BTreeMap<ProviderId, Arc<dyn SigningKeyProvisioner>> =
        BTreeMap::from([
            (
                custody_provider_id.clone(),
                Arc::new(software_custody.clone()) as Arc<dyn SigningKeyProvisioner>,
            ),
            (
                ProviderId::new("remote-test").unwrap(),
                Arc::new(ambiguous_remote.clone()) as Arc<dyn SigningKeyProvisioner>,
            ),
        ]);
    let rotated_service = ProvisioningService::new(
        Arc::new(rotated_adapter),
        ProvisioningInfrastructure::new(
            signer_store.clone(),
            secret_store.clone(),
            SystemClock,
            SystemEntropy,
            Sha256RequestDigester,
            false,
        )
        .with_provider_capabilities(
            historical_provisioners,
            BTreeMap::from([(
                custody_provider_id.clone(),
                Arc::new(software_custody.clone()) as Arc<dyn ConfigurationSecretSealer>,
            )]),
        ),
    );
    let reconciled_remote_key = rotated_service
        .provision_signing_key(
            ambiguous_project.id,
            "remote-ambiguous-key-12345678".to_owned(),
            ambiguous_project.metadata_revision,
            Uuid::new_v4(),
        )
        .await
        .expect("rotation should dispatch inspection to the retained historical provider");
    assert_eq!(reconciled_remote_key.state, "published");
    let reconciled_remote_operation =
        key_provisioning_operation::Entity::find_by_id(ambiguous_operation.id)
            .one(control)
            .await
            .expect("reconciled remote operation query should work")
            .expect("reconciled remote operation should remain durable");
    assert_eq!(reconciled_remote_operation.provider_lease_generation, 3);
    assert_eq!(reconciled_remote_operation.attempt_count, 3);
    {
        let state = ambiguous_state.lock().unwrap();
        assert_eq!(state.provision_calls, 1);
        assert_eq!(state.inspect_calls, 1);
        assert_eq!(state.destroy_calls, 0);
    }
    let reconciled_remote_owner = project_signing_key::Entity::find_by_id(reconciled_remote_key.id)
        .one(control)
        .await
        .expect("reconciled remote owner query should work")
        .expect("reconciled remote owner should exist");
    let reconciled_material_id = reconciled_remote_owner
        .signer_material_id
        .expect("reconciled remote key should own material");
    let reconciled_operation = key_provisioning_operation::Entity::find()
        .filter(key_provisioning_operation::Column::ProjectId.eq(ambiguous_project.id))
        .filter(key_provisioning_operation::Column::KeyId.eq(reconciled_remote_key.id))
        .one(control)
        .await
        .expect("reconciled remote operation query should work")
        .expect("reconciled remote operation should exist");
    let mut stored_operation = reconciled_operation.clone().into_active_model();
    stored_operation.state = Set("stored".to_owned());
    stored_operation.completed_at = Set(None);
    stored_operation
        .update(control)
        .await
        .expect("remote stored-cleanup operation fixture should persist");
    let mut provisioning_owner = reconciled_remote_owner.into_active_model();
    provisioning_owner.state = Set("provisioning".to_owned());
    provisioning_owner.published_at = Set(None);
    provisioning_owner
        .update(control)
        .await
        .expect("remote stored-cleanup owner fixture should persist");
    ambiguous_service
        .revoke_signing_key(
            ambiguous_project.id,
            reconciled_remote_key.id,
            reconciled_remote_key.ring_revision,
            Uuid::new_v4(),
        )
        .await
        .expect("stored remote key should queue explicit cleanup");
    let original_remote_object = ambiguous_state
        .lock()
        .unwrap()
        .object
        .clone()
        .expect("stored remote object should exist");
    ambiguous_state.lock().unwrap().object = Some((vec![99; 48], vec![99; 32]));
    assert_eq!(
        ambiguous_service
            .reconcile_signing_key(
                ambiguous_project.id,
                reconciled_remote_key.id,
                ambiguous_project.metadata_revision,
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::Integrity),
        "cleanup must not destroy an inspected object that differs from committed handle or public key"
    );
    let mismatched_cleanup =
        key_provisioning_operation::Entity::find_by_id(reconciled_operation.id)
            .one(control)
            .await
            .expect("mismatched cleanup query should work")
            .expect("mismatched cleanup should remain durable");
    assert_eq!(mismatched_cleanup.state, "cleanup_blocked");
    assert_eq!(
        mismatched_cleanup.last_retry_classification.as_deref(),
        Some("never")
    );
    assert_eq!(ambiguous_state.lock().unwrap().destroy_calls, 0);
    ambiguous_state.lock().unwrap().object = Some(original_remote_object);
    ambiguous_service
        .reconcile_signing_key(
            ambiguous_project.id,
            reconciled_remote_key.id,
            ambiguous_project.metadata_revision,
            Uuid::new_v4(),
        )
        .await
        .expect("explicit reconcile should clean the repaired matching remote object");
    let erased_reconciled_material = protected_material::Entity::find_by_id(reconciled_material_id)
        .one(control)
        .await
        .expect("reconciled material query should work")
        .expect("reconciled material tombstone should remain durable");
    assert_eq!(erased_reconciled_material.state, "erased");
    assert!(erased_reconciled_material.opaque_value.is_none());
    {
        let state = ambiguous_state.lock().unwrap();
        assert_eq!(state.destroy_calls, 1);
        assert!(state.object.is_none());
    }

    let failed_project = provisioning
        .create_project(
            CreateProject {
                display_name: "Definitively absent remote signing".to_owned(),
                belongs_to: None,
                idempotency_key: "project-remote-absent-12345678".to_owned(),
            },
            Uuid::new_v4(),
        )
        .await
        .expect("definitive-absence Project should commit");
    let failed_state = Arc::new(Mutex::new(RemoteSigningState {
        provision_failure_once: Some((ProviderErrorClass::Unavailable, RetryClassification::Never)),
        ..Default::default()
    }));
    let failed_remote =
        StatefulRemoteSigningProvider::new(remote_provider_id.clone(), failed_state.clone());
    let failed_adapter = PostgresProvisioningAdapter::new(
        control.clone(),
        url::Url::parse("https://identity.example/runtime/").unwrap(),
        vec!["runtime-test-process".to_owned()],
        Duration::from_millis(10),
        Duration::from_secs(1),
    )
    .with_provider_custody(
        "test-deployment",
        remote_provider_id.clone(),
        remote_format,
        custody_provider_id.clone(),
        custody_format,
    )
    .expect("definitive-absence custody adapter should compose");
    let failed_service = ProvisioningService::new(
        Arc::new(failed_adapter),
        ProvisioningInfrastructure::new(
            signer_store.clone(),
            secret_store.clone(),
            SystemClock,
            SystemEntropy,
            Sha256RequestDigester,
            false,
        )
        .with_signing_provisioner(failed_remote),
    );
    assert_eq!(
        failed_service
            .provision_signing_key(
                failed_project.id,
                "remote-definitive-absence-12345678".to_owned(),
                failed_project.metadata_revision,
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::ExternalStore),
        "a Never result remains submitted until inspection proves absence"
    );
    let failed_operation = key_provisioning_operation::Entity::find()
        .filter(key_provisioning_operation::Column::ProjectId.eq(failed_project.id))
        .one(control)
        .await
        .expect("definitive-absence operation query should work")
        .expect("definitive-absence operation should exist");
    assert_eq!(failed_operation.state, "submitted");
    assert_eq!(
        failed_operation.last_retry_classification.as_deref(),
        Some("never")
    );
    assert_eq!(
        failed_service
            .reconcile_signing_key(
                failed_project.id,
                failed_operation.key_id,
                failed_project.metadata_revision,
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::InvalidTransition),
        "definitive inspection absence should terminalize provider retries"
    );
    let failed_operation = key_provisioning_operation::Entity::find_by_id(failed_operation.id)
        .one(control)
        .await
        .expect("failed operation query should work")
        .expect("failed operation should remain durable");
    assert_eq!(failed_operation.state, "failed");
    let failed_key = failed_service
        .list_signing_keys(failed_project.id)
        .await
        .expect("failed key should remain explicitly manageable")
        .into_iter()
        .find(|key| key.id == failed_operation.key_id)
        .expect("failed key should remain listable");
    let abandoned_failed_key = failed_service
        .revoke_signing_key(
            failed_project.id,
            failed_key.id,
            failed_key.ring_revision,
            Uuid::new_v4(),
        )
        .await
        .expect("definitively absent failed operation should support explicit abandonment");
    assert_eq!(abandoned_failed_key.state, "abandoned");
    let abandoned_failed_operation =
        key_provisioning_operation::Entity::find_by_id(failed_operation.id)
            .one(control)
            .await
            .expect("abandoned failed operation query should work")
            .expect("abandoned failed operation should remain durable");
    assert_eq!(abandoned_failed_operation.state, "abandoned");
    let erased_failed_material = protected_material::Entity::find_by_id(
        failed_operation
            .material_id
            .expect("failed operation should own pending material"),
    )
    .one(control)
    .await
    .expect("failed material query should work")
    .expect("failed material tombstone should remain durable");
    assert_eq!(erased_failed_material.state, "erased");
    assert!(erased_failed_material.opaque_value.is_none());
    {
        let state = failed_state.lock().unwrap();
        assert_eq!(state.provision_calls, 1);
        assert_eq!(state.inspect_calls, 1);
        assert_eq!(state.destroy_calls, 0);
        assert!(state.object.is_none());
    }

    let cleanup_project = provisioning
        .create_project(
            CreateProject {
                display_name: "Remote signing cleanup".to_owned(),
                belongs_to: None,
                idempotency_key: "project-remote-cleanup-12345678".to_owned(),
            },
            Uuid::new_v4(),
        )
        .await
        .expect("cleanup Project should commit");
    let cleanup_state = Arc::new(Mutex::new(RemoteSigningState {
        destroy_failure_once: Some((ProviderErrorClass::Unavailable, RetryClassification::Never)),
        ..Default::default()
    }));
    let cleanup_remote =
        StatefulRemoteSigningProvider::new(remote_provider_id.clone(), cleanup_state.clone())
            .with_revision_bump(control.clone(), cleanup_project.id);
    let cleanup_adapter = PostgresProvisioningAdapter::new(
        control.clone(),
        url::Url::parse("https://identity.example/runtime/").unwrap(),
        vec!["runtime-test-process".to_owned()],
        Duration::from_millis(10),
        Duration::from_secs(1),
    )
    .with_provider_custody(
        "test-deployment",
        remote_provider_id.clone(),
        remote_format,
        custody_provider_id.clone(),
        custody_format,
    )
    .expect("cleanup custody adapter should compose");
    let cleanup_service = ProvisioningService::new(
        Arc::new(cleanup_adapter),
        ProvisioningInfrastructure::new(
            signer_store.clone(),
            secret_store.clone(),
            SystemClock,
            SystemEntropy,
            Sha256RequestDigester,
            false,
        )
        .with_signing_provisioner(cleanup_remote.clone()),
    );
    assert_eq!(
        cleanup_service
            .provision_signing_key(
                cleanup_project.id,
                "remote-cleanup-key-12345678".to_owned(),
                cleanup_project.metadata_revision,
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::RevisionConflict),
        "a post-effect authorization change should durably queue cleanup"
    );
    let cleanup_operation = key_provisioning_operation::Entity::find()
        .filter(key_provisioning_operation::Column::ProjectId.eq(cleanup_project.id))
        .one(control)
        .await
        .expect("cleanup operation query should work")
        .expect("cleanup operation should remain durable");
    assert_eq!(cleanup_operation.state, "cleanup_pending");
    let cleanup_key = cleanup_service
        .list_signing_keys(cleanup_project.id)
        .await
        .expect("cleanup key should remain listable")
        .into_iter()
        .find(|key| key.id == cleanup_operation.key_id)
        .expect("cleanup key should remain present");
    let cleanup_key = cleanup_service
        .revoke_signing_key(
            cleanup_project.id,
            cleanup_key.id,
            cleanup_key.ring_revision,
            Uuid::new_v4(),
        )
        .await
        .expect("explicit abandonment must preserve remote cleanup intent");
    assert_eq!(cleanup_key.state, "abandoned");
    let cleanup_operation = key_provisioning_operation::Entity::find_by_id(cleanup_operation.id)
        .one(control)
        .await
        .expect("abandoned cleanup operation query should work")
        .expect("abandoned cleanup operation should remain durable");
    assert_eq!(cleanup_operation.state, "cleanup_pending");
    assert_eq!(
        cleanup_service
            .reconcile_signing_key(
                cleanup_project.id,
                cleanup_operation.key_id,
                cleanup_project.metadata_revision + 1,
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::ExternalStore),
        "a Never destroy failure must durably block automatic cleanup retries"
    );
    let cleanup_operation = key_provisioning_operation::Entity::find_by_id(cleanup_operation.id)
        .one(control)
        .await
        .expect("blocked cleanup query should work")
        .expect("blocked cleanup should remain durable");
    assert_eq!(cleanup_operation.state, "cleanup_blocked");
    assert_eq!(
        cleanup_operation.last_retry_classification.as_deref(),
        Some("never")
    );
    let rotated_cleanup_adapter = PostgresProvisioningAdapter::new(
        control.clone(),
        url::Url::parse("https://identity.example/runtime/").unwrap(),
        vec!["runtime-test-process".to_owned()],
        Duration::from_millis(10),
        Duration::from_secs(1),
    )
    .with_provider_custody(
        "test-deployment",
        rotated_provider_id.clone(),
        custody_format,
        custody_provider_id.clone(),
        custody_format,
    )
    .expect("rotated cleanup custody adapter should compose");
    let rotated_cleanup_service = ProvisioningService::new(
        Arc::new(rotated_cleanup_adapter),
        ProvisioningInfrastructure::new(
            signer_store.clone(),
            secret_store.clone(),
            SystemClock,
            SystemEntropy,
            Sha256RequestDigester,
            false,
        )
        .with_provider_capabilities(
            BTreeMap::from([
                (
                    remote_provider_id.clone(),
                    Arc::new(cleanup_remote.clone()) as Arc<dyn SigningKeyProvisioner>,
                ),
                (
                    rotated_provider_id.clone(),
                    Arc::new(rotated_custody.clone()) as Arc<dyn SigningKeyProvisioner>,
                ),
            ]),
            BTreeMap::new(),
        ),
    );
    let abandoned_remote_key = rotated_cleanup_service
        .reconcile_signing_key(
            cleanup_project.id,
            cleanup_operation.key_id,
            cleanup_project.metadata_revision + 1,
            Uuid::new_v4(),
        )
        .await
        .expect("explicit reconcile should route cleanup through the retained historical provider");
    assert_eq!(abandoned_remote_key.state, "abandoned");
    let completed_cleanup_operation =
        key_provisioning_operation::Entity::find_by_id(cleanup_operation.id)
            .one(control)
            .await
            .expect("completed cleanup operation query should work")
            .expect("completed cleanup operation should retain a tombstone");
    assert_eq!(completed_cleanup_operation.state, "abandoned");
    assert_eq!(completed_cleanup_operation.provider_lease_generation, 3);
    assert_eq!(completed_cleanup_operation.destroy_attempt_count, 2);
    assert!(completed_cleanup_operation.destroyed_at.is_some());
    let completed_cleanup_material = protected_material::Entity::find_by_id(
        completed_cleanup_operation
            .material_id
            .expect("cleanup operation should retain material identity"),
    )
    .one(control)
    .await
    .expect("completed cleanup material query should work")
    .expect("completed cleanup material should retain a tombstone");
    assert_eq!(completed_cleanup_material.state, "erased");
    assert!(completed_cleanup_material.opaque_value.is_none());
    assert_eq!(completed_cleanup_material.owner_id, abandoned_remote_key.id);
    {
        let state = cleanup_state.lock().unwrap();
        assert_eq!(state.provision_calls, 1);
        assert_eq!(state.inspect_calls, 2);
        assert_eq!(state.destroy_calls, 2);
        assert!(state.object.is_none());
    }

    let protected_provider_command = CreateProvider {
        kind: ProviderKind::Oidc,
        provider_key: "custody-workforce".to_owned(),
        display_name: "Protected OIDC".to_owned(),
        issuer: "https://accounts.example/".to_owned(),
        client_id: "protected-client".to_owned(),
        client_secret: zeroize::Zeroizing::new("protected-secret".to_owned()),
        managed_profile_enabled: false,
        idempotency_key: "provider-custody-12345678".to_owned(),
        expected_project_revision: custody_project.metadata_revision,
        egress_policy_revision: Some(1),
    };
    let protected_provider = custody_provisioning
        .create_provider(
            custody_project.id,
            protected_provider_command.clone(),
            Uuid::new_v4(),
        )
        .await
        .expect("provider envelope and owner should finalize atomically");
    let protected_owner = provider_configuration::Entity::find_by_id(protected_provider.id)
        .one(control)
        .await
        .expect("protected provider owner query should work")
        .expect("protected provider owner should exist");
    assert!(protected_owner.secret_ref.is_none());
    let material_id = protected_owner
        .secret_material_id
        .expect("protected provider should reference one material");
    let committed_material = protected_material::Entity::find_by_id(material_id)
        .one(control)
        .await
        .expect("protected material query should work")
        .expect("protected material should exist");
    assert_eq!(committed_material.state, "live");
    assert_eq!(committed_material.owner_id, protected_provider.id);
    assert_eq!(committed_material.owner_kind, "provider_secret");
    assert_eq!(committed_material.provider_id, "software");
    assert_eq!(
        committed_material.safe_fingerprint.as_ref().map(Vec::len),
        Some(32)
    );
    assert!(
        !committed_material
            .opaque_value
            .as_deref()
            .expect("live protected material has an envelope")
            .windows("protected-secret".len())
            .any(|window| window == b"protected-secret")
    );
    assert_eq!(
        custody_provisioning
            .create_provider(
                custody_project.id,
                protected_provider_command.clone(),
                Uuid::new_v4(),
            )
            .await
            .expect("same protected secret should replay by fingerprint"),
        protected_provider
    );
    let mut conflicting_protected_provider = protected_provider_command;
    conflicting_protected_provider.client_secret =
        zeroize::Zeroizing::new("different-protected-secret".to_owned());
    assert_eq!(
        custody_provisioning
            .create_provider(
                custody_project.id,
                conflicting_protected_provider,
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::IdempotencyConflict)
    );

    let smtp_repository = PostgresEmailControlRepository::new(control.clone())
        .with_custody("test-deployment", custody_provider_id, custody_format)
        .expect("protected SMTP repository should compose");
    let smtp_control = EmailControlService::new(
        Arc::new(smtp_repository),
        Arc::new(secret_store.clone()),
        Arc::new(SystemClock),
        Arc::new(Sha256RequestDigester),
    )
    .with_secret_sealer(software_custody.clone());
    let deployment_smtp_command = ReconcileDeploymentSmtpGeneration {
        generation: 37,
        host: "smtp.default.example.com".to_owned(),
        port: 465,
        tls_mode: SmtpControlTlsMode::ImplicitTls,
        sender_address: "login@default.example.com".to_owned(),
        expected_safe_fingerprint: None,
        explicitly_allowed_private_ips: Vec::new(),
        credential: zeroize::Zeroizing::new(
            r#"{"username":"default-mailer","password":"protected-default-password"}"#.to_owned(),
        ),
        idempotency_key: "deployment-smtp-custody-12345678".to_owned(),
        correlation_id: Uuid::new_v4(),
    };
    let protected_deployment_smtp = smtp_control
        .reconcile_deployment_smtp(deployment_smtp_command.clone())
        .await
        .expect("deployment SMTP envelope and owner should finalize atomically");
    assert_eq!(protected_deployment_smtp.generation, 37);
    assert_ne!(protected_deployment_smtp.safe_fingerprint, [0; 32]);
    assert_eq!(
        smtp_control
            .reconcile_deployment_smtp(deployment_smtp_command.clone())
            .await
            .expect("same deployment SMTP credential should replay by fingerprint"),
        protected_deployment_smtp
    );
    let mut conflicting_deployment_smtp = deployment_smtp_command;
    conflicting_deployment_smtp.credential = zeroize::Zeroizing::new(
        r#"{"username":"default-mailer","password":"different-password"}"#.to_owned(),
    );
    assert_eq!(
        smtp_control
            .reconcile_deployment_smtp(conflicting_deployment_smtp)
            .await,
        Err(ApplicationError::IdempotencyConflict)
    );
    let deployment_material = control
        .query_one_raw(sea_orm::Statement::from_sql_and_values(
            sea_orm::DbBackend::Postgres,
            "SELECT material.id,material.project_id,material.owner_kind,material.owner_id,
                    material.generation,material.state,material.opaque_value
               FROM deployment_smtp_generations smtp
               JOIN protected_materials material ON material.id=smtp.credential_material_id
              WHERE smtp.generation=$1",
            [37.into()],
        ))
        .await
        .expect("protected deployment SMTP material query should work")
        .expect("protected deployment SMTP material should exist");
    let deployment_material_id = deployment_material
        .try_get::<Uuid>("", "id")
        .expect("deployment material ID should decode");
    assert!(
        deployment_material
            .try_get::<Option<Uuid>>("", "project_id")
            .expect("deployment scope should decode")
            .is_none()
    );
    assert_eq!(
        deployment_material
            .try_get::<String>("", "owner_kind")
            .expect("owner kind should decode"),
        "deployment_smtp"
    );
    assert_eq!(
        deployment_material
            .try_get::<i64>("", "generation")
            .expect("generation should decode"),
        37
    );
    assert_eq!(
        deployment_material
            .try_get::<String>("", "state")
            .expect("material state should decode"),
        "live"
    );
    assert!(
        !deployment_material
            .try_get::<Vec<u8>>("", "opaque_value")
            .expect("envelope should decode")
            .windows("protected-default-password".len())
            .any(|window| window == b"protected-default-password")
    );

    let protected_smtp_command = CreateSmtpConfiguration {
        host: "smtp.example.com".to_owned(),
        port: 465,
        tls_mode: SmtpControlTlsMode::ImplicitTls,
        sender_address: "sender@example.com".to_owned(),
        sender_name: Some("OwlAuth".to_owned()),
        reply_to: None,
        credential: zeroize::Zeroizing::new(
            r#"{"username":"mailer","password":"protected-password"}"#.to_owned(),
        ),
        idempotency_key: "smtp-custody-12345678".to_owned(),
        expected_project_security_revision: custody_project.security_revision,
        correlation_id: Uuid::new_v4(),
    };
    let protected_smtp = smtp_control
        .create_smtp(custody_project.id, protected_smtp_command.clone())
        .await
        .expect("SMTP envelope and exact owner should finalize atomically");
    assert_eq!(
        protected_smtp.safe_fingerprint.map(|value| value.len()),
        Some(32)
    );
    let smtp_owner = control
        .query_one_raw(sea_orm::Statement::from_sql_and_values(
            sea_orm::DbBackend::Postgres,
            "SELECT credential_material_id FROM project_smtp_configurations WHERE id=$1",
            [protected_smtp.id.into()],
        ))
        .await
        .expect("protected SMTP owner query should work")
        .expect("protected SMTP owner should exist");
    let smtp_material_id = smtp_owner
        .try_get::<Uuid>("", "credential_material_id")
        .expect("protected SMTP owner should reference one material");
    let smtp_material = protected_material::Entity::find_by_id(smtp_material_id)
        .one(control)
        .await
        .expect("protected SMTP material query should work")
        .expect("protected SMTP material should exist");
    assert_eq!(smtp_material.state, "live");
    assert_eq!(smtp_material.owner_kind, "project_smtp");
    assert_eq!(smtp_material.owner_id, protected_smtp.id);
    assert!(
        !smtp_material
            .opaque_value
            .as_deref()
            .expect("live SMTP material has an envelope")
            .windows("protected-password".len())
            .any(|window| window == b"protected-password")
    );
    assert_eq!(
        smtp_control
            .create_smtp(custody_project.id, protected_smtp_command.clone())
            .await
            .expect("same protected SMTP credential should replay by fingerprint"),
        protected_smtp
    );
    let mut conflicting_smtp = protected_smtp_command;
    conflicting_smtp.credential = zeroize::Zeroizing::new(
        r#"{"username":"mailer","password":"different-password"}"#.to_owned(),
    );
    assert_eq!(
        smtp_control
            .create_smtp(custody_project.id, conflicting_smtp)
            .await,
        Err(ApplicationError::IdempotencyConflict)
    );

    let smtp_test_key = "smtp-test-custody-12345678".to_owned();
    let protected_smtp_test = smtp_control
        .test_smtp(
            custody_project.id,
            protected_smtp.id,
            "recipient@example.com",
            protected_smtp.revision,
            smtp_test_key.clone(),
            Uuid::new_v4(),
        )
        .await
        .expect("SMTP test recipient should seal before enqueue");
    assert_eq!(
        protected_smtp_test.state,
        crate::application::SmtpTestState::Pending
    );
    let smtp_test_owner = control
        .query_one_raw(sea_orm::Statement::from_sql_and_values(
            sea_orm::DbBackend::Postgres,
            "SELECT recipient_material_id,credential_material_id
             FROM project_smtp_test_operations WHERE id=$1",
            [protected_smtp_test.id.into()],
        ))
        .await
        .expect("protected SMTP test owner query should work")
        .expect("protected SMTP test owner should exist");
    let recipient_material_id = smtp_test_owner
        .try_get::<Uuid>("", "recipient_material_id")
        .expect("SMTP test should reference recipient material");
    assert_eq!(
        smtp_test_owner
            .try_get::<Uuid>("", "credential_material_id")
            .expect("SMTP test should snapshot credential material"),
        smtp_material_id
    );
    let recipient_material = protected_material::Entity::find_by_id(recipient_material_id)
        .one(control)
        .await
        .expect("protected recipient material query should work")
        .expect("protected recipient material should exist");
    assert_eq!(recipient_material.state, "live");
    assert_eq!(recipient_material.owner_kind, "smtp_test_recipient");
    assert_eq!(recipient_material.owner_id, protected_smtp_test.id);
    let protected_runtime_custody = PostgresProtectedRuntimeCustody::new(
        runtime.clone(),
        "test-deployment",
        ProviderId::new("software").unwrap(),
        software_custody.clone(),
        software_custody.clone(),
    )
    .expect("protected Runtime SMTP custody should compose");
    let readiness_repository = ProtectedMaterialRepository::new(runtime.clone(), "test-deployment")
        .expect("readiness inventory should compose");
    let readiness_candidates = readiness_repository
        .runtime_readiness_page(None, 256)
        .await
        .expect("every live protected material should have an authoritative owner");
    assert!(!readiness_candidates.is_empty());
    for candidate in readiness_candidates {
        protected_runtime_custody
            .authenticate_readiness_candidate(candidate)
            .await
            .expect("the configured custody root should authenticate every live material");
    }
    let wrong_root = SoftwareCustodyProvider::new(ProviderId::new("software").unwrap(), [32; 32])
        .expect("wrong-root provider should initialize");
    let wrong_runtime_custody = PostgresProtectedRuntimeCustody::new(
        runtime.clone(),
        "test-deployment",
        ProviderId::new("software").unwrap(),
        wrong_root.clone(),
        wrong_root,
    )
    .expect("wrong-root Runtime composition is structurally valid");
    let mut rejected_wrong_root = false;
    for candidate in readiness_repository
        .runtime_readiness_page(None, 256)
        .await
        .expect("readiness inventory should remain readable")
    {
        if wrong_runtime_custody
            .authenticate_readiness_candidate(candidate)
            .await
            .is_err()
        {
            rejected_wrong_root = true;
            break;
        }
    }
    assert!(
        rejected_wrong_root,
        "startup authentication must reject a structurally registered provider with the wrong root"
    );
    let opened_deployment_smtp = SmtpCredentialResolver::resolve_checked(
        &protected_runtime_custody,
        &deployment_material_id.to_string(),
        &protected_deployment_smtp.safe_fingerprint,
    )
    .await
    .expect("Runtime should open the exact deployment SMTP material");
    assert!(
        opened_deployment_smtp
            .windows("protected-default-password".len())
            .any(|window| window == b"protected-default-password")
    );
    let expected_smtp_fingerprint = protected_smtp
        .safe_fingerprint
        .expect("finalized SMTP configuration has a safe fingerprint");
    let opened_smtp = SmtpCredentialResolver::resolve_checked(
        &protected_runtime_custody,
        &smtp_material_id.to_string(),
        &expected_smtp_fingerprint,
    )
    .await
    .expect("Runtime should open the exact protected SMTP generation");
    assert!(
        opened_smtp
            .windows("protected-password".len())
            .any(|window| { window == b"protected-password" })
    );
    assert_eq!(
        SmtpCredentialResolver::resolve(
            &protected_runtime_custody,
            &recipient_material_id.to_string(),
        )
        .await
        .expect("Runtime should open the exact SMTP-test recipient")
        .as_slice(),
        b"recipient@example.com"
    );
    assert_eq!(
        smtp_control
            .test_smtp(
                custody_project.id,
                protected_smtp.id,
                "recipient@example.com",
                protected_smtp.revision,
                smtp_test_key.clone(),
                Uuid::new_v4(),
            )
            .await
            .expect("same SMTP test recipient should replay by fingerprint"),
        protected_smtp_test
    );
    assert_eq!(
        smtp_control
            .test_smtp(
                custody_project.id,
                protected_smtp.id,
                "other-recipient@example.com",
                protected_smtp.revision,
                smtp_test_key,
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::IdempotencyConflict)
    );

    let concurrent_project = CreateProject {
        display_name: "Concurrent project".to_owned(),
        belongs_to: None,
        idempotency_key: "project-concurrent-same-12345678".to_owned(),
    };
    let (concurrent_project_left, concurrent_project_right) = tokio::join!(
        provisioning.create_project(concurrent_project.clone(), Uuid::new_v4()),
        provisioning.create_project(concurrent_project, Uuid::new_v4()),
    );
    assert_eq!(
        concurrent_project_left.expect("one concurrent Project create should commit"),
        concurrent_project_right.expect("same-key Project create should replay")
    );

    let (conflicting_project_left, conflicting_project_right) = tokio::join!(
        provisioning.create_project(
            CreateProject {
                display_name: "Concurrent project left".to_owned(),
                belongs_to: None,
                idempotency_key: "project-concurrent-conflict-12345678".to_owned(),
            },
            Uuid::new_v4(),
        ),
        provisioning.create_project(
            CreateProject {
                display_name: "Concurrent project right".to_owned(),
                belongs_to: None,
                idempotency_key: "project-concurrent-conflict-12345678".to_owned(),
            },
            Uuid::new_v4(),
        ),
    );
    assert!(matches!(
        (&conflicting_project_left, &conflicting_project_right),
        (Ok(_), Err(ApplicationError::IdempotencyConflict))
            | (Err(ApplicationError::IdempotencyConflict), Ok(_))
    ));

    verify_listenerless_custody_import(
        custody_project.clone(),
        config.clone(),
        control,
        provisioning.clone(),
        signer_store.clone(),
        secret_store.clone(),
        secret_root.clone(),
        software_custody.clone(),
    )
    .await;

    let (created_project, key_fence_project_id) =
        verify_project_and_external_effect_revision_fences(
            created_project,
            &provisioning,
            &store_root,
            control,
        )
        .await;

    verify_client_key_and_listener_journeys(&created_project, &config, &pools, &url).await;

    let created_project_id = Box::pin(verify_application_and_publication_journeys(
        created_project,
        key_fence_project_id,
        provisioning.clone(),
        control,
        &config,
        &pools,
        readiness.clone(),
        secondary_readiness.clone(),
        unexpected_readiness.clone(),
        signer_store.clone(),
        secret_store.clone(),
        signer_root.clone(),
        &url,
        control_url.clone(),
    ))
    .await;

    verify_capacity_and_replay_limits(&control_url).await;
    verify_terminal_custody_authority_fence(control, &url, created_project_id).await;

    std::fs::remove_dir_all(store_root).expect("temporary encrypted stores should clean up");
    pools.close().await;
}
