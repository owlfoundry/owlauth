use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
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
    OpaqueHandle, ProviderError, ProviderErrorClass, ProviderFormatVersion, ProviderFormatVersions,
    ProviderId, ProvisionSigningKeyRequest, ProvisionedSigningKey, RetryClassification,
    SigningAlgorithm, SigningKeyProvisioner, SigningProviderCapabilities, SigningPublicKey,
};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, DbBackend, EntityTrait,
    IntoActiveModel, QueryFilter, QuerySelect, Statement, TransactionTrait,
};
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
        custody::SoftwareCustodyProvider,
        migrations::{SchemaError, prepare_schema, verify_url},
        postgres::{
            custody::ProtectedMaterialRepository,
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
            server_api::RuntimeServerEmailLookupDigester,
            server_key::PostgresServerKeyRepository,
            server_readiness::PostgresServerDigestReadinessAdapter,
            unit_of_work::ProjectUnitOfWork,
        },
        protected_runtime::PostgresProtectedRuntimeCustody,
        runtime_security::{RuntimeKeyMaterial, SoftwareRuntimeProtector},
        server_key_security::{ServerKeyDigestMaterial, SoftwareServerKeyRing},
        system::{Sha256RequestDigester, SystemClock},
    },
    application::{
        AcknowledgeProjectServerKeyDelivery, ApplicationError, ApplicationProvisioningPort,
        CompleteIdempotency, ConfigurationSecretSealers, CreateApplication, CreateProject,
        CreateProjectServerKey, CreateProjectServerKeyResult, CreateProvider,
        CreateSmtpConfiguration, EmailControlService, EmailIdentityLookupDigester, NewProject,
        PreparedSigningKey, ProjectProvisioningPort, ProjectRecord, ProviderEgressPolicyPort,
        ProvisionedProtectedSigningMaterial, ProvisioningInfrastructure,
        ProvisioningOperationState, ProvisioningService, ReadinessService,
        ReconcileDeploymentSmtpGeneration, ReplaceApplicationConfiguration, RequestDigester,
        RevokeProjectServerKey, RuntimeProtector, ServerDigestReadinessService,
        ServerKeyLifecycleService, SigningKeyProvisioningPort, SigningProviderAction,
        SigningProviderCall, SigningProviderLease, SmtpControlTlsMode, SmtpCredentialResolver,
        UpdateProject, UpdateProjectPolicy,
    },
    composition::build_http_capabilities,
    config::{MigrationMode, ProcessMode, ServerConfig},
    domain::{ApplicationType, ProviderEgressMode, ProviderEgressPolicy, ProviderKind},
    http::{build_routers_with_auth_incarnation, build_routers_with_capabilities},
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
    project_disable: Option<(DatabaseConnection, Uuid, Arc<AtomicBool>)>,
}

impl StatefulRemoteSigningProvider {
    fn new(provider_id: ProviderId, state: Arc<Mutex<RemoteSigningState>>) -> Self {
        Self {
            provider_id,
            state,
            project_disable: None,
        }
    }

    fn with_project_disable(mut self, database: DatabaseConnection, project_id: Uuid) -> Self {
        self.project_disable = Some((database, project_id, Arc::new(AtomicBool::new(false))));
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
        if let Some((database, project_id, disabled)) = &self.project_disable
            && !disabled.swap(true, Ordering::SeqCst)
        {
            let project = project::Entity::find_by_id(*project_id)
                .one(database)
                .await
                .map_err(|_| {
                    ProviderError::new(
                        ProviderErrorClass::Unavailable,
                        RetryClassification::Reconcile,
                    )
                })?
                .ok_or_else(|| {
                    ProviderError::new(
                        ProviderErrorClass::Unavailable,
                        RetryClassification::Reconcile,
                    )
                })?;
            let mut project = project.into_active_model();
            project.status = Set("disabled".to_owned());
            project.update(database).await.map_err(|_| {
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
        signer_material_id: operation.material_id,
        request_digest: operation.request_digest.clone(),
        state: ProvisioningOperationState::Submitted,
    };
    let now = time::OffsetDateTime::now_utc();
    let mut due_operation = operation.clone().into_active_model();
    due_operation.next_attempt_at = Set(Some(now - time::Duration::seconds(1)));
    due_operation.provider_lease_token = Set(None);
    due_operation.provider_lease_expires_at = Set(None);
    due_operation
        .update(database)
        .await
        .expect("submitted operation should be due before the lease-fencing fixture");
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
                lease,
                ProvisionedProtectedSigningMaterial {
                    material_id: operation.material_id,
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
            "OWLAUTH_MIGRATION_OWNER_ROLE".to_owned(),
            "owlauth_owner".to_owned(),
        ),
        (
            "OWLAUTH_DATABASE_LOCK_TIMEOUT_MS".to_owned(),
            "250".to_owned(),
        ),
        ("OWLAUTH_POSTGRES_URL".to_owned(), runtime_url.to_owned()),
        (
            "OWLAUTH_AUTH_PROCESS_ID".to_owned(),
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
            "OWLAUTH_REQUIRED_AUTH_PROCESS_IDS".to_owned(),
            "runtime-test-process".to_owned(),
        ),
        (
            "OWLAUTH_SERVER_KEY_DIGEST_KEY_VERSION".to_owned(),
            "1".to_owned(),
        ),
        (
            "OWLAUTH_SERVER_KEY_DIGEST_KEY".to_owned(),
            "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo".to_owned(),
        ),
        (
            "OWLAUTH_RUNTIME_POSTGRES_URL".to_owned(),
            runtime_url.to_owned(),
        ),
        (
            "OWLAUTH_SERVER_POSTGRES_URL".to_owned(),
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
    assert!(ProcessMode::Auth.has_auth());
    assert!(!ProcessMode::Auth.has_control());
    assert!(!ProcessMode::Control.has_auth());
    assert!(ProcessMode::Control.has_control());
    assert!(ProcessMode::All.has_auth());
    assert!(ProcessMode::All.has_control());
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
    admin_url: &str,
    control_url: String,
) -> Uuid {
    let reservation_revision = created_project.metadata_revision;
    let created_project = provisioning
        .update_project(
            created_project.id,
            UpdateProject {
                display_name: "Production project configured".to_owned(),
                belongs_to: created_project.belongs_to.clone(),
                expected_metadata_revision: reservation_revision,
            },
            Uuid::new_v4(),
        )
        .await
        .expect("Project metadata should change while its initial signing reservation is pending");
    assert_eq!(created_project.metadata_revision, reservation_revision + 1);

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

    let initial_operation = key_provisioning_operation::Entity::find()
        .filter(key_provisioning_operation::Column::ProjectId.eq(created_project.id))
        .one(control)
        .await
        .expect("initial key operation should be queryable")
        .expect("Project creation should persist its initial key operation");
    let initial_operation_alias = initial_operation.operation_alias.clone();
    let initial_expected_project_revision = initial_operation.expected_project_revision;
    assert_eq!(initial_expected_project_revision, reservation_revision);
    provisioning
        .reconcile_signing_key_lifecycle(100)
        .await
        .expect("maintenance should continue an accepted initial signing reservation after metadata changes");
    let signing_key = provisioning
        .list_signing_keys(created_project.id)
        .await
        .expect("initial signing key should be queryable after maintenance")
        .into_iter()
        .find(|key| key.id == initial_operation.key_id)
        .expect("initial signing maintenance should retain its exact key");
    assert_eq!(signing_key.state, "published");
    let operation = key_provisioning_operation::Entity::find_by_id(initial_operation.id)
        .one(control)
        .await
        .expect("key operation should be queryable")
        .expect("key operation should be durable");
    let mut operation_active = operation.into_active_model();
    operation_active.state = Set("stored".to_owned());
    operation_active.expected_ring_revision = Set(signing_key.ring_revision);
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
    let restarted_provisioning = provisioning.clone();
    let signing_key = restarted_provisioning
        .provision_signing_key(
            created_project.id,
            initial_operation_alias.clone(),
            initial_expected_project_revision,
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
        "UPDATE auth_process_incarnations SET process_incarnation=$2
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
            "UPDATE auth_process_incarnations SET process_incarnation=$2
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
        "UPDATE auth_process_incarnations SET process_incarnation=$2
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
        .expect("every required Auth process should observe the revision");
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
    assert!(
        policy_before_reduction.browser_session_reuse,
        "new Projects should allow explicit browser-session reuse by default"
    );
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
    let replayed_signing_key = restarted_provisioning
        .provision_signing_key(
            created_project.id,
            initial_operation_alias,
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

    let mut routers = build_routers_with_auth_incarnation(config, Some(pools), Uuid::from_u128(1));
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
    reason = "one bounded journey verifies capacity races and completed replay semantics"
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
    )
    .with_custody(
        "test-deployment",
        ProviderId::new("software").expect("capacity custody provider ID"),
        ProviderFormatVersion::new(1).expect("capacity custody format"),
    )
    .expect("capacity adapter should compose with protected custody");
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
        (Ok(created), Err(ApplicationError::CapacityExceeded)) => (created, left_project_command),
        (Err(ApplicationError::CapacityExceeded), Ok(created)) => (created, right_project_command),
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
        Err(ApplicationError::CapacityExceeded)
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
            (Ok(created), Err(ApplicationError::CapacityExceeded)) => {
                (created, left_application_command)
            }
            (Err(ApplicationError::CapacityExceeded), Ok(created)) => {
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
    let mut observer = PgConnection::connect(blocker_url)
        .await
        .expect("provisioning lock observer should open before the bounded wait begins");
    let subject = tokio::spawn(async move {
        SigningKeyProvisioningPort::prepare_signing_key(
            adapter.as_ref(),
            project_id,
            subject_alias,
            expected_revision,
            vec![91; 32],
        )
        .await
    });
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
    reason = "the migration journey keeps lock, ownership, and history checks together"
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
             'managed_reauthorization_provider_kind_check', \
             'linked_identities_github_numeric_subject_check'\
         ) ORDER BY conname",
    )
    .fetch_all(&mut ownership_connection)
    .await
    .expect("provider-kind constraints should be queryable");
    assert_eq!(provider_constraints.len(), 2);
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

    let mut history_connection = PgConnection::connect(admin_url)
        .await
        .expect("history strictness test connection should open");
    sqlx::query(
        "INSERT INTO _sqlx_migrations
             (version,description,success,checksum,execution_time)
         VALUES ($1,'synthetic unexpected migration',TRUE,$2,1)",
    )
    .bind(20_260_806_999_999_i64)
    .bind(vec![73_u8; 48])
    .execute(&mut history_connection)
    .await
    .expect("synthetic unexpected history should insert");
    assert_eq!(
        verify_url(admin_url, Duration::from_secs(5))
            .await
            .expect_err("any unexpected migration must reject this binary"),
        SchemaError::IncompatibleHistory
    );
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version=$1")
        .bind(20_260_806_999_999_i64)
        .execute(&mut history_connection)
        .await
        .expect("synthetic unexpected history should clean up");
    history_connection
        .close()
        .await
        .expect("history strictness test connection should close");

    config
}

#[allow(
    clippy::too_many_lines,
    reason = "the PostgreSQL server-key and listener capability journey is intentionally end-to-end"
)]
async fn verify_server_key_and_listener_journeys(
    project: &ProjectRecord,
    client_provider_id: Uuid,
    config: &ServerConfig,
    pools: &DatabasePools,
    admin_url: &str,
) {
    const FIRST_INCARNATION: Uuid = Uuid::from_u128(0xc11e_0001);
    const SECOND_INCARNATION: Uuid = Uuid::from_u128(0xc11e_0002);
    let client = pools.server.as_ref().expect("Server pool should exist");
    client
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO auth_process_incarnations(process_id,process_incarnation,started_at)
             VALUES($1,$2,transaction_timestamp())
             ON CONFLICT(process_id) DO UPDATE SET
               process_incarnation=EXCLUDED.process_incarnation,
               started_at=EXCLUDED.started_at",
            [
                config.auth_process_id.clone().into(),
                FIRST_INCARNATION.into(),
            ],
        ))
        .await
        .expect("first Auth incarnation should be claimed before Server readiness");
    let readiness_adapter = Arc::new(PostgresServerDigestReadinessAdapter::new(client.clone()));
    let short_readiness = ServerDigestReadinessService::new(
        readiness_adapter.clone(),
        config.auth_process_id.clone(),
        FIRST_INCARNATION,
        [1],
        config.required_auth_process_ids.clone(),
        Duration::from_millis(50),
    )
    .expect("short Server readiness should compose");
    short_readiness
        .claim()
        .await
        .expect("first Auth incarnation should claim Server readiness");

    let ring = SoftwareServerKeyRing::new(
        config
            .instance_id
            .clone()
            .expect("Server key digest deployment context"),
        1,
        ServerKeyDigestMaterial::new([b'Z'; 32]),
        BTreeMap::new(),
    )
    .expect("test Server key ring should compose");
    let lifecycle = ServerKeyLifecycleService::new(
        Arc::new(
            PostgresServerKeyRepository::new(
                pools.control.as_ref().expect("Control pool").clone(),
                config.required_auth_process_ids.clone(),
            )
            .expect("Server key repository should compose"),
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
        .expect("Server readiness blocker should connect");
    sqlx::query("BEGIN")
        .execute(&mut blocker)
        .await
        .expect("Server readiness blocker should begin");
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut blocker)
        .await
        .expect("Server readiness blocker pid");
    sqlx::query(
        "SELECT process_id FROM auth_process_incarnations
          WHERE process_id=$1 FOR UPDATE",
    )
    .bind(&config.auth_process_id)
    .fetch_one(&mut blocker)
    .await
    .expect("Auth incarnation parent should lock");
    let lifecycle_for_expiry = lifecycle.clone();
    let project_id = project.id;
    let mut expired_create = tokio::spawn(async move {
        lifecycle_for_expiry
            .create_project_server_key(CreateProjectServerKey {
                project_id,
                label: "expires while waiting".to_owned(),
                idempotency_key: "server-key-expired-wait-12345678".to_owned(),
                correlation_id: Uuid::new_v4(),
            })
            .await
    });
    let mut observer = PgConnection::connect(admin_url)
        .await
        .expect("Client lock observer should connect");
    wait_for_sqlx_backend_blocked_by(&mut observer, blocker_pid, "Server key create").await;
    sqlx::query("SELECT pg_sleep(0.075)")
        .execute(&mut observer)
        .await
        .expect("database wall clock should advance beyond the Server readiness lease");
    let lease_expired: bool = sqlx::query_scalar(
        "SELECT lease_expires_at <= clock_timestamp()
           FROM server_key_digest_readiness WHERE process_id=$1",
    )
    .bind(&config.auth_process_id)
    .fetch_one(&mut observer)
    .await
    .expect("Server readiness lease expiry should be observable");
    assert!(
        lease_expired,
        "Server readiness fixture lease must be expired"
    );
    sqlx::query("COMMIT")
        .execute(&mut blocker)
        .await
        .expect("Server readiness blocker should commit");
    assert_eq!(
        timeout(Duration::from_secs(2), &mut expired_create)
            .await
            .expect("expired server-key create should complete")
            .expect("expired server-key create task should not panic")
            .expect_err("expired verifier evidence must fail closed"),
        ApplicationError::ServerVerifierUnavailable
    );
    blocker
        .close()
        .await
        .expect("Server readiness blocker should close");
    observer
        .close()
        .await
        .expect("Server readiness observer should close");

    let first_readiness = ServerDigestReadinessService::new(
        readiness_adapter.clone(),
        config.auth_process_id.clone(),
        FIRST_INCARNATION,
        [1],
        config.required_auth_process_ids.clone(),
        Duration::from_secs(5),
    )
    .expect("first Server readiness should compose");
    first_readiness
        .claim()
        .await
        .expect("first Server readiness should recover");
    let first_created = lifecycle
        .create_project_server_key(CreateProjectServerKey {
            project_id: project.id,
            label: "primary backend".to_owned(),
            idempotency_key: "server-key-primary-12345678".to_owned(),
            correlation_id: Uuid::new_v4(),
        })
        .await
        .expect("Project server key should be created");
    let CreateProjectServerKeyResult::Created {
        metadata: primary_key,
        credential,
    } = first_created
    else {
        panic!("first Project server key must reveal its credential once");
    };
    let credential = credential.expose().to_owned();
    let replay = lifecycle
        .create_project_server_key(CreateProjectServerKey {
            project_id: project.id,
            label: "primary backend".to_owned(),
            idempotency_key: "server-key-primary-12345678".to_owned(),
            correlation_id: Uuid::new_v4(),
        })
        .await
        .expect("same server-key create should replay");
    assert!(matches!(
        replay,
        CreateProjectServerKeyResult::ReplayWithoutSecret { ref metadata }
            if metadata.id == primary_key.id
    ));
    assert!(primary_key.credential_acknowledged_at.is_none());
    assert_eq!(
        lifecycle
            .create_project_server_key(CreateProjectServerKey {
                project_id: project.id,
                label: "blocked before delivery acknowledgement".to_owned(),
                idempotency_key: "server-key-blocked-unacknowledged-12345678".to_owned(),
                correlation_id: Uuid::new_v4(),
            })
            .await
            .expect_err("an active unacknowledged credential must block replacement"),
        ApplicationError::InvalidTransition
    );
    let acknowledge_command = AcknowledgeProjectServerKeyDelivery {
        project_id: project.id,
        key_id: primary_key.id,
        expected_revision: primary_key.revision,
        idempotency_key: "server-key-primary-acknowledge-12345678".to_owned(),
        correlation_id: Uuid::new_v4(),
    };
    let primary_key = lifecycle
        .acknowledge_project_server_key_delivery(acknowledge_command.clone())
        .await
        .expect("primary Server credential delivery should be acknowledged");
    assert_eq!(primary_key.revision, 2);
    assert!(primary_key.credential_acknowledged_at.is_some());
    assert_eq!(
        lifecycle
            .acknowledge_project_server_key_delivery(acknowledge_command)
            .await
            .expect("delivery acknowledgement replay should be idempotent"),
        primary_key
    );

    client
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "UPDATE auth_process_incarnations
                SET process_incarnation=$2,started_at=transaction_timestamp()
              WHERE process_id=$1",
            [
                config.auth_process_id.clone().into(),
                SECOND_INCARNATION.into(),
            ],
        ))
        .await
        .expect("replacement Auth incarnation should fence its predecessor");
    assert_eq!(
        first_readiness
            .claim()
            .await
            .expect_err("delayed predecessor readiness must not reclaim the Auth process ID"),
        ApplicationError::Disabled
    );
    let current_incarnation = client
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT process_incarnation FROM auth_process_incarnations WHERE process_id=$1",
            [config.auth_process_id.clone().into()],
        ))
        .await
        .expect("current Auth incarnation query should complete")
        .expect("current Auth incarnation should exist")
        .try_get::<Uuid>("", "process_incarnation")
        .expect("current Auth incarnation should be a UUID");
    assert_eq!(current_incarnation, SECOND_INCARNATION);

    let second_readiness = ServerDigestReadinessService::new(
        readiness_adapter,
        config.auth_process_id.clone(),
        SECOND_INCARNATION,
        [1],
        config.required_auth_process_ids.clone(),
        Duration::from_secs(5),
    )
    .expect("replacement Server readiness should compose");
    let lifecycle_for_interleave = lifecycle.clone();
    let replacement_create = async move {
        lifecycle_for_interleave
            .create_project_server_key(CreateProjectServerKey {
                project_id: project.id,
                label: "replacement interleave".to_owned(),
                idempotency_key: "server-key-replacement-12345678".to_owned(),
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
        Ok(CreateProjectServerKeyResult::Created { metadata, .. }) => {
            lifecycle
                .acknowledge_project_server_key_delivery(AcknowledgeProjectServerKeyDelivery {
                    project_id: project.id,
                    key_id: metadata.id,
                    expected_revision: metadata.revision,
                    idempotency_key: "server-key-replacement-acknowledge-12345678".to_owned(),
                    correlation_id: Uuid::new_v4(),
                })
                .await
                .expect(
                    "an interleaved successful create must be acknowledged before another create",
                );
        }
        Err(ApplicationError::ServerVerifierUnavailable) => {}
        other => panic!("unexpected interleaved server-key create result: {other:?}"),
    }
    let post_replacement_key = match lifecycle
        .create_project_server_key(CreateProjectServerKey {
            project_id: project.id,
            label: "post-replacement verifier".to_owned(),
            idempotency_key: "server-key-post-replacement-12345678".to_owned(),
            correlation_id: Uuid::new_v4(),
        })
        .await
        .expect("create must succeed against the replacement incarnation")
    {
        CreateProjectServerKeyResult::Created { metadata, .. } => metadata,
        CreateProjectServerKeyResult::ReplayWithoutSecret { .. } => {
            panic!("fresh post-replacement create cannot replay")
        }
    };
    assert_eq!(
        first_readiness.renew().await,
        Err(ApplicationError::Disabled),
        "a predecessor incarnation cannot renew after replacement"
    );

    // Seed one materialized directory graph through the same constraints used by Runtime. This
    // gives the real Server API surface positive user/projection reads while email/token misses prove
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
    let client_identity_id = Uuid::new_v4();
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
    let client_source_profile_digest =
        session_authority::base_profile_digest(Some("Client User"), None, None, None)
            .expect("Client directory source profile should canonicalize");
    sqlx::query(
        "INSERT INTO linked_identities(
             id,project_id,user_id,created_via_provider_configuration_id,issuer,subject,
             status,identity_revision,display_name,source_profile_digest,
             observed_at,created_at,updated_at)
         VALUES($1,$2,$3,$4,'https://client-directory.example.test','client-user-subject',
                'active',1,'Client User',$5,transaction_timestamp(),transaction_timestamp(),
                transaction_timestamp())",
    )
    .bind(client_identity_id)
    .bind(project.id)
    .bind(client_user_id)
    .bind(client_provider_id)
    .bind(client_source_profile_digest)
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
    let email_digester = RuntimeServerEmailLookupDigester::new(
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
        super::projection::projection_material(&user, 13)
            .expect("Client directory projection should materialize");
    sqlx::query(
        "INSERT INTO application_user_projections(
             id,project_id,binding_id,application_id,user_id,schema_name,projection_revision,
             source_user_revision,canonical_digest,source_base_profile_digest,document,
             created_at,updated_at)
         VALUES($1,$2,$3,$4,$5,'owlauth.user.v1',13,7,$6,$7,$8,$9,$9 + interval '5 minutes')",
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
    let capabilities = build_http_capabilities(config, Some(pools), SECOND_INCARNATION, &providers);
    let mut routers = build_routers_with_capabilities(config, capabilities);
    routers.mark_ready();
    let runtime = routers.runtime.take().expect("Runtime router");
    let server_router = routers.server.take().expect("Server API router");
    let control = routers.control.take().expect("Control router");
    let client_path = format!("/v1/projects/{}/users", project.public_id);
    let client_authorization = format!("Bearer {credential}");
    let control_authorization = format!("Bearer owl_ctrl_v1_{}", "A".repeat(43));
    let control_user_path = format!("/v1/projects/{}/users", project.id);

    let control_filtered = control
        .clone()
        .oneshot(
            Request::get(format!(
                "{control_user_path}?status=active&search=cLiEnT&identity_kind=provider&provider_key=client-directory&sort=created_oldest&limit=25"
            ))
            .header(header::AUTHORIZATION, &control_authorization)
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .expect("filtered Control user directory should complete");
    assert_eq!(control_filtered.status(), StatusCode::OK);
    let control_filtered: serde_json::Value = serde_json::from_slice(
        &to_bytes(control_filtered.into_body(), 8192)
            .await
            .expect("bounded filtered Control directory"),
    )
    .expect("filtered Control directory should be JSON");
    assert_eq!(control_filtered["items"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        control_filtered["items"][0]["id"],
        client_user_id.to_string()
    );
    assert_eq!(control_filtered["items"][0]["public_id"], "usr_client01");

    let control_email_filtered = control
        .clone()
        .oneshot(
            Request::get(format!(
                "{control_user_path}?identity_kind=email&search=USR_CLIENT&limit=25"
            ))
            .header(header::AUTHORIZATION, &control_authorization)
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .expect("email-filtered Control user directory should complete");
    assert_eq!(control_email_filtered.status(), StatusCode::OK);
    let control_email_filtered: serde_json::Value = serde_json::from_slice(
        &to_bytes(control_email_filtered.into_body(), 8192)
            .await
            .expect("bounded email-filtered Control directory"),
    )
    .expect("email-filtered Control directory should be JSON");
    assert_eq!(
        control_email_filtered["items"][0]["id"],
        client_user_id.to_string()
    );

    let control_unknown_provider = control
        .clone()
        .oneshot(
            Request::get(format!(
                "{control_user_path}?identity_kind=provider&provider_key=missing-provider"
            ))
            .header(header::AUTHORIZATION, &control_authorization)
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .expect("unknown-provider Control user directory should complete");
    assert_eq!(control_unknown_provider.status(), StatusCode::OK);
    let control_unknown_provider: serde_json::Value = serde_json::from_slice(
        &to_bytes(control_unknown_provider.into_body(), 8192)
            .await
            .expect("bounded unknown-provider Control directory"),
    )
    .expect("unknown-provider Control directory should be JSON");
    assert_eq!(control_unknown_provider["items"], serde_json::json!([]));

    for (email, expected_user) in [
        ("known@EXAMPLE.TEST", Some(client_user_id)),
        ("missing@example.test", None),
    ] {
        let response = control
            .clone()
            .oneshot(
                Request::post(format!("{control_user_path}/lookup"))
                    .header(header::AUTHORIZATION, &control_authorization)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::json!({"email": email}).to_string()))
                    .unwrap(),
            )
            .await
            .expect("exact Control email lookup should complete");
        assert_eq!(response.status(), StatusCode::OK);
        let response: serde_json::Value = serde_json::from_slice(
            &to_bytes(response.into_body(), 8192)
                .await
                .expect("bounded exact Control email lookup"),
        )
        .expect("exact Control email lookup should be JSON");
        match expected_user {
            Some(user_id) => {
                assert_eq!(response["user"]["id"], user_id.to_string());
                assert!(response["user"].get("email").is_none());
            }
            None => assert_eq!(response, serde_json::json!({"user": null})),
        }
    }

    let successful = server_router
        .clone()
        .oneshot(
            Request::get(&client_path)
                .header(header::AUTHORIZATION, &client_authorization)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("real Server API request should complete");
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
               FROM project_server_keys WHERE id=$1",
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

    let exact_user = server_router
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

    let email_miss = server_router
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

    let email_hit = server_router
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

    // The same lookup must remain email-free when the matched identity becomes primary. Its
    // deliberately non-decryptable fixture ciphertext proves this read path never asks durable
    // email custody for an address; ordinary user reads retain their separate email capability.
    let mut primary_email_fixture = PgConnection::connect(admin_url)
        .await
        .expect("primary-email Server lookup fixture should connect");
    sqlx::query(
        "UPDATE project_users
            SET primary_source_kind='email',primary_profile_identity_id=NULL,
                primary_email_identity_id=$2
          WHERE id=$1",
    )
    .bind(client_user_id)
    .bind(client_email_identity_id)
    .execute(&mut primary_email_fixture)
    .await
    .expect("Client email identity should become primary");
    let primary_email_hit = server_router
        .clone()
        .oneshot(
            Request::post(format!("/v1/projects/{}/users/lookup", project.public_id))
                .header(header::AUTHORIZATION, &client_authorization)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"email":"known@example.test"}"#))
                .unwrap(),
        )
        .await
        .expect("primary-email Server lookup should complete");
    assert_eq!(primary_email_hit.status(), StatusCode::OK);
    let primary_email_hit: serde_json::Value = serde_json::from_slice(
        &to_bytes(primary_email_hit.into_body(), 4096)
            .await
            .expect("bounded primary-email Server lookup"),
    )
    .expect("primary-email Server lookup should be JSON");
    assert_eq!(primary_email_hit["user"]["user_id"], "usr_client01");
    assert_eq!(
        primary_email_hit["user"]["verified_email"],
        serde_json::Value::Null
    );
    sqlx::query(
        "UPDATE project_users
            SET primary_source_kind='provider',primary_profile_identity_id=$2,
                primary_email_identity_id=NULL
          WHERE id=$1",
    )
    .bind(client_user_id)
    .bind(client_identity_id)
    .execute(&mut primary_email_fixture)
    .await
    .expect("Client provider identity should be restored as primary");
    primary_email_fixture
        .close()
        .await
        .expect("primary-email Server lookup fixture should close");

    let projection = server_router
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
    let page_source_profile_digests = page_user_public_ids
        .iter()
        .map(|public_id| {
            session_authority::base_profile_digest(Some(public_id.as_str()), None, None, None)
                .expect("Client pagination source profile should canonicalize")
        })
        .collect::<Vec<_>>();
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
             status,identity_revision,source_profile_digest,display_name,observed_at,created_at,updated_at)
         SELECT seed.identity_id,$4,seed.user_id,$5,
                'https://client-directory.example.test',seed.public_id || '-subject',
                'active',1,seed.source_profile_digest,seed.public_id,
                transaction_timestamp(),transaction_timestamp(),transaction_timestamp()
           FROM UNNEST($1::uuid[],$2::uuid[],$3::text[],$6::bytea[])
                AS seed(identity_id,user_id,public_id,source_profile_digest)",
    )
    .bind(&page_identity_ids)
    .bind(&page_user_ids)
    .bind(&page_user_public_ids)
    .bind(project.id)
    .bind(client_provider_id)
    .bind(&page_source_profile_digests)
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

    let mut control_page_order = page_user_ids
        .iter()
        .copied()
        .zip(page_user_public_ids.iter().cloned())
        .collect::<Vec<_>>();
    control_page_order.sort_by_key(|(id, _)| *id);
    for (sort, expected) in [
        (
            "created_oldest",
            control_page_order
                .iter()
                .map(|(_, public_id)| public_id.clone())
                .collect::<Vec<_>>(),
        ),
        (
            "created_newest",
            control_page_order
                .iter()
                .rev()
                .map(|(_, public_id)| public_id.clone())
                .collect::<Vec<_>>(),
        ),
    ] {
        let first = control
            .clone()
            .oneshot(
                Request::get(format!(
                    "{control_user_path}?search=usr_page_&sort={sort}&limit=2"
                ))
                .header(header::AUTHORIZATION, &control_authorization)
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .expect("first sorted Control directory page should complete");
        assert_eq!(first.status(), StatusCode::OK);
        let first: serde_json::Value = serde_json::from_slice(
            &to_bytes(first.into_body(), 8192)
                .await
                .expect("bounded first sorted Control directory page"),
        )
        .expect("first sorted Control directory page should be JSON");
        let first_ids = first["items"]
            .as_array()
            .expect("first sorted Control items")
            .iter()
            .map(|user| user["public_id"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(first_ids, expected[..2]);
        let cursor = first["next_cursor"]
            .as_str()
            .expect("full sorted Control page should provide a cursor");

        let second = control
            .clone()
            .oneshot(
                Request::get(format!(
                    "{control_user_path}?search=usr_page_&sort={sort}&cursor={cursor}&limit=2"
                ))
                .header(header::AUTHORIZATION, &control_authorization)
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .expect("second sorted Control directory page should complete");
        assert_eq!(second.status(), StatusCode::OK);
        let second: serde_json::Value = serde_json::from_slice(
            &to_bytes(second.into_body(), 8192)
                .await
                .expect("bounded second sorted Control directory page"),
        )
        .expect("second sorted Control directory page should be JSON");
        let second_ids = second["items"]
            .as_array()
            .expect("second sorted Control items")
            .iter()
            .map(|user| user["public_id"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(second_ids, expected[2..4]);
        assert!(
            first_ids
                .iter()
                .all(|public_id| !second_ids.contains(public_id))
        );
    }

    let first_page = server_router
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
    let second_page = server_router
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

    let inactive = server_router
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
        let response = server_router
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
    let wrong_project = server_router
        .clone()
        .oneshot(
            Request::get("/v1/projects/not-the-owner/users")
                .header(header::AUTHORIZATION, &client_authorization)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("wrong-Project Server API request should complete");
    assert_eq!(wrong_project.status(), StatusCode::UNAUTHORIZED);

    let control_with_server_key = control
        .clone()
        .oneshot(
            Request::get("/v1/projects")
                .header(header::AUTHORIZATION, &client_authorization)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("Server key on Control should complete");
    assert_eq!(control_with_server_key.status(), StatusCode::UNAUTHORIZED);
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
    let client_for_race = server_router.clone();
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
        lifecycle_for_revoke.revoke_project_server_key(RevokeProjectServerKey {
            project_id: project.id,
            key_id: primary_for_revoke.id,
            expected_revision: primary_for_revoke.revision,
            idempotency_key: "server-key-revoke-12345678".to_owned(),
            correlation_id: Uuid::new_v4(),
        })
    );
    assert!(matches!(
        raced_read
            .expect("raced Client read should complete")
            .status(),
        StatusCode::OK | StatusCode::UNAUTHORIZED
    ));
    let revoked = revoked.expect("Server key revocation should commit");
    assert_eq!(revoked.revision, primary_key.revision + 1);
    let denied_after_revoke = server_router
        .oneshot(
            Request::get(&client_path)
                .header(header::AUTHORIZATION, client_authorization)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("revoked Server API request should complete");
    assert_eq!(denied_after_revoke.status(), StatusCode::UNAUTHORIZED);
    tokio::time::sleep(Duration::from_millis(150)).await;
    let terminal: (String, i64) = sqlx::query_as(
        "SELECT status,revision FROM project_server_keys WHERE project_id=$1 AND id=$2",
    )
    .bind(project.id)
    .bind(primary_key.id)
    .fetch_one(
        &mut PgConnection::connect(admin_url)
            .await
            .expect("terminal query connection"),
    )
    .await
    .expect("revoked Server key should remain queryable");
    assert_eq!(terminal, ("revoked".to_owned(), primary_key.revision + 1));

    // Inventory includes terminal history and uses immutable (created_at, id) keyset pagination.
    let mut inventory_connection = PgConnection::connect(admin_url)
        .await
        .expect("Client inventory fixture should connect");
    for index in 0_u128..101 {
        let id = Uuid::from_u128(0xc11e_1000 + index);
        let public_key_id = URL_SAFE_NO_PAD.encode(id.as_bytes());
        sqlx::query(
            "INSERT INTO project_server_keys(
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
        .bind(format!("owl_server_v1.{public_key_id}"))
        .execute(&mut inventory_connection)
        .await
        .expect("terminal Client inventory row should insert");
    }
    inventory_connection
        .close()
        .await
        .expect("Client inventory fixture should close");
    let (first_page, cursor, active_unacknowledged_key) = lifecycle
        .list_project_server_keys(project.id, None, Some(100))
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
    let cursor = cursor.expect("more than 100 Server keys require a cursor");
    let (second_page, final_cursor, active_unacknowledged_key) = lifecycle
        .list_project_server_keys(project.id, Some(&cursor), Some(100))
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

    // This ordered container continues with Runtime operations created for the primary Auth
    // incarnation. Restore that shared process identity after proving Server API replacement;
    // the predecessor Server readiness lease remains stale and cannot authorize new work.
    client
        .execute_raw(sea_orm::Statement::from_sql_and_values(
            sea_orm::DbBackend::Postgres,
            "UPDATE auth_process_incarnations SET process_incarnation=$1 WHERE process_id=$2",
            vec![
                Uuid::from_u128(1).into(),
                config.auth_process_id.clone().into(),
            ],
        ))
        .await
        .expect("restore the primary Auth incarnation for the remaining ordered journeys");
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
    let runtime_url = format!("postgres://owlauth_runtime:runtime_test@{host}:{port}/owlauth_test");
    let control_url = format!("postgres://owlauth_control:control_test@{host}:{port}/owlauth_test");
    let config = migrate_and_verify_main_database(&url, &runtime_url, &control_url).await;

    let pools = verify_pools_unit_of_work_and_egress(&config).await;
    let runtime = pools.runtime.as_ref().expect("Runtime pool should exist");
    let control = pools.control.as_ref().expect("Control pool should exist");

    let invalid_pending_owner = control
        .begin()
        .await
        .expect("pending-owner integrity transaction should begin");
    invalid_pending_owner
        .execute_raw(Statement::from_string(
            DbBackend::Postgres,
            "INSERT INTO projects(
                 id,public_id,status,metadata_revision,security_revision,display_name)
             VALUES(
                 '10000000-0000-0000-0000-000000000001',
                 'pending_owner_integrity_probe','active',1,1,'Pending owner probe')"
                .to_owned(),
        ))
        .await
        .expect("pending-owner probe Project should insert");
    invalid_pending_owner
        .execute_raw(Statement::from_string(
            DbBackend::Postgres,
            "INSERT INTO protected_materials(
                 id,scope_kind,project_id,owner_kind,owner_id,generation,material_kind,
                 provider_id,provider_format_version,context_version,context_digest,state)
             VALUES(
                 '10000000-0000-0000-0000-000000000002','project',
                 '10000000-0000-0000-0000-000000000001','provider_secret',
                 '10000000-0000-0000-0000-000000000003',1,'configuration_secret',
                 'software',1,1,decode(repeat('00',32),'hex'),'pending')"
                .to_owned(),
        ))
        .await
        .expect("the deferred trigger should allow statement-local owner ordering");
    assert!(
        invalid_pending_owner.commit().await.is_err(),
        "a committed pending material must reference its exact typed owner tuple"
    );

    let custody_provider_id =
        ProviderId::new("software").expect("software provider ID should parse");
    let custody_format = ProviderFormatVersion::new(1).expect("software format should be non-zero");
    let software_custody = SoftwareCustodyProvider::new(custody_provider_id.clone(), [31; 32])
        .expect("software custody should initialize");
    let custody_adapter = Arc::new(
        PostgresProvisioningAdapter::new(
            control.clone(),
            url::Url::parse("https://identity.example/runtime/").unwrap(),
            vec![
                "runtime-test-process".to_owned(),
                "runtime-secondary-process".to_owned(),
            ],
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
    let provisioning = ProvisioningService::new(
        custody_adapter.clone(),
        ProvisioningInfrastructure::new_protected(
            SystemClock,
            Sha256RequestDigester,
            false,
            BTreeMap::from([(
                custody_provider_id.clone(),
                Arc::new(software_custody.clone()) as Arc<dyn SigningKeyProvisioner>,
            )]),
            BTreeMap::from([(
                custody_provider_id.clone(),
                Arc::new(software_custody.clone()) as Arc<dyn ConfigurationSecretSealer>,
            )]),
        ),
    );
    runtime
        .execute_raw(sea_orm::Statement::from_string(
            sea_orm::DbBackend::Postgres,
            "INSERT INTO auth_process_incarnations (process_id,process_incarnation,started_at)
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

    let custody_provisioning = provisioning.clone();
    let custody_project = custody_provisioning
        .create_project(
            CreateProject {
                display_name: "Protected custody project".to_owned(),
                belongs_to: None,
                idempotency_key: "project-custody-12345678".to_owned(),
            },
            Uuid::new_v4(),
        )
        .await
        .expect("custody Project creation should atomically reserve its initial signing key");
    verify_provisioning_lock_timeout(custody_adapter.clone(), control, &url, &custody_project)
        .await;

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
        ProvisioningInfrastructure::new_protected(
            SystemClock,
            Sha256RequestDigester,
            false,
            BTreeMap::new(),
            BTreeMap::new(),
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
        ProvisioningInfrastructure::new_protected(
            SystemClock,
            Sha256RequestDigester,
            false,
            BTreeMap::new(),
            BTreeMap::new(),
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
    let rotated_material = protected_material::Entity::find_by_id(rotated_owner.secret_material_id)
        .one(control)
        .await
        .expect("rotated provider material query should work")
        .expect("rotated provider material should exist");
    assert_eq!(
        rotated_material.provider_id,
        custody_provider_id.as_str(),
        "historical recovery must use the provider tuple stored by prepare, not the new active provider"
    );

    let stateless_operation_alias = format!("signing_initial_{}", custody_project.id.simple());
    let stateless_digester = Sha256RequestDigester;
    let stateless_request_digest = stateless_digester
        .digest_json(&serde_json::json!({
            "project_id": custody_project.id,
            "algorithm": "EdDSA",
            "purpose": "application_tokens",
        }))
        .expect("stateless signing request should be canonical");
    let stateless_recovery = custody_adapter
        .prepare_signing_key(
            custody_project.id,
            stateless_operation_alias,
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
    let stateless_operation_alias = submitted_operation.operation_alias.clone();
    let mut expired_submission = submitted_operation.into_active_model();
    expired_submission.provider_lease_expires_at = Set(Some(
        time::OffsetDateTime::now_utc() - time::Duration::seconds(1),
    ));
    expired_submission
        .update(control)
        .await
        .expect("simulated crash lease should expire before reconciliation");
    let recovered_stateless_key = custody_provisioning
        .provision_signing_key(
            custody_project.id,
            stateless_operation_alias,
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
    let recovered_material =
        protected_material::Entity::find_by_id(recovered_operation.material_id)
            .one(control)
            .await
            .expect("recovered stateless material query should work")
            .expect("recovered stateless material should exist");
    assert_eq!(recovered_material.state, "live");
    assert!(recovered_material.opaque_value.is_some());

    let protected_signing_key = recovered_stateless_key;
    let protected_signing_owner = project_signing_key::Entity::find_by_id(protected_signing_key.id)
        .one(control)
        .await
        .expect("protected signing owner query should work")
        .expect("protected signing owner should exist");
    let signing_material_id = protected_signing_owner.signer_material_id;
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
        signer_material_id: signing_material_id,
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

    let disabled_cleanup_project = custody_provisioning
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
            format!("signing_initial_{}", disabled_cleanup_project.id.simple()),
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
    let stored_cleanup_material_id = stored_cleanup_owner.signer_material_id;
    let stored_cleanup_operation = key_provisioning_operation::Entity::find()
        .filter(key_provisioning_operation::Column::ProjectId.eq(disabled_cleanup_project.id))
        .filter(key_provisioning_operation::Column::KeyId.eq(stored_cleanup_key.id))
        .one(control)
        .await
        .expect("stored-before-publish operation query should work")
        .expect("stored-before-publish operation should exist");
    let mut stored_operation = stored_cleanup_operation.clone().into_active_model();
    stored_operation.state = Set("stored".to_owned());
    stored_operation.expected_ring_revision = Set(stored_cleanup_key.ring_revision);
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
    assert_eq!(
        custody_provisioning
            .provision_signing_key(
                disabled_cleanup_project.id,
                stored_cleanup_operation.operation_alias.clone(),
                disabled_cleanup_project.metadata_revision,
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::Disabled),
        "disabled stored material must enter cleanup instead of remaining publishable"
    );
    let disabled_stored_operation =
        key_provisioning_operation::Entity::find_by_id(stored_cleanup_operation.id)
            .one(control)
            .await
            .expect("disabled stored operation query should work")
            .expect("disabled stored operation should remain durable");
    assert_eq!(disabled_stored_operation.state, "cleanup_pending");
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
        .provision_signing_key(
            disabled_cleanup_project.id,
            queued_stored_operation.operation_alias.clone(),
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

    let stale_ring_project = custody_provisioning
        .create_project(
            CreateProject {
                display_name: "Stale ring stored signing cleanup".to_owned(),
                belongs_to: None,
                idempotency_key: "project-stale-ring-signing-cleanup-12345678".to_owned(),
            },
            Uuid::new_v4(),
        )
        .await
        .expect("stale-ring Project should commit");
    let stale_ring_key = custody_provisioning
        .provision_signing_key(
            stale_ring_project.id,
            format!("signing_initial_{}", stale_ring_project.id.simple()),
            stale_ring_project.metadata_revision,
            Uuid::new_v4(),
        )
        .await
        .expect("stale-ring key should initially publish");
    let stale_ring_operation = key_provisioning_operation::Entity::find()
        .filter(key_provisioning_operation::Column::ProjectId.eq(stale_ring_project.id))
        .one(control)
        .await
        .expect("stale-ring operation query should work")
        .expect("stale-ring operation should exist");
    let mut stale_operation = stale_ring_operation.clone().into_active_model();
    stale_operation.state = Set("stored".to_owned());
    stale_operation.completed_at = Set(None);
    stale_operation
        .update(control)
        .await
        .expect("stale-ring stored operation fixture should persist");
    let stale_owner = project_signing_key::Entity::find_by_id(stale_ring_key.id)
        .one(control)
        .await
        .expect("stale-ring key query should work")
        .expect("stale-ring key should exist");
    let stale_material_id = stale_owner.signer_material_id;
    let mut stale_owner = stale_owner.into_active_model();
    stale_owner.state = Set("provisioning".to_owned());
    stale_owner
        .update(control)
        .await
        .expect("stale-ring provisioning key fixture should persist");
    assert_eq!(
        custody_provisioning
            .provision_signing_key(
                stale_ring_project.id,
                stale_ring_operation.operation_alias.clone(),
                stale_ring_project.metadata_revision,
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::RevisionConflict),
        "stored material captured at a stale ring revision must queue cleanup"
    );
    let stale_ring_operation =
        key_provisioning_operation::Entity::find_by_id(stale_ring_operation.id)
            .one(control)
            .await
            .expect("stale-ring cleanup operation query should work")
            .expect("stale-ring cleanup operation should remain durable");
    assert_eq!(stale_ring_operation.state, "cleanup_pending");
    let abandoned_stale_key = custody_provisioning
        .revoke_signing_key(
            stale_ring_project.id,
            stale_ring_key.id,
            stale_ring_key.ring_revision,
            Uuid::new_v4(),
        )
        .await
        .expect("stale-ring candidate should remain cancellable");
    assert_eq!(abandoned_stale_key.state, "abandoned");
    custody_provisioning
        .provision_signing_key(
            stale_ring_project.id,
            stale_ring_operation.operation_alias,
            stale_ring_project.metadata_revision,
            Uuid::new_v4(),
        )
        .await
        .expect("stale-ring provider material should be destroyed");
    let erased_stale_material = protected_material::Entity::find_by_id(stale_material_id)
        .one(control)
        .await
        .expect("stale-ring material query should work")
        .expect("stale-ring material tombstone should remain durable");
    assert_eq!(erased_stale_material.state, "erased");
    assert!(erased_stale_material.opaque_value.is_none());

    let remote_provider_id = ProviderId::new("remote-test").unwrap();
    let remote_format = ProviderFormatVersion::new(1).unwrap();
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
        ProvisioningInfrastructure::new_protected(
            SystemClock,
            Sha256RequestDigester,
            false,
            BTreeMap::new(),
            BTreeMap::new(),
        )
        .with_signing_provisioner(ambiguous_remote.clone()),
    );
    let ambiguous_project = ambiguous_service
        .create_project(
            CreateProject {
                display_name: "Ambiguous remote signing".to_owned(),
                belongs_to: None,
                idempotency_key: "project-remote-ambiguous-12345678".to_owned(),
            },
            Uuid::new_v4(),
        )
        .await
        .expect("remote signing Project should atomically reserve its initial key");
    let ambiguous_operation_alias = format!("signing_initial_{}", ambiguous_project.id.simple());
    assert_eq!(
        ambiguous_service
            .provision_signing_key(
                ambiguous_project.id,
                ambiguous_operation_alias.clone(),
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
        ProvisioningInfrastructure::new_protected(
            SystemClock,
            Sha256RequestDigester,
            false,
            BTreeMap::new(),
            BTreeMap::new(),
        )
        .with_signing_provisioner(software_custody.clone()),
    );
    assert_eq!(
        absent_historical_service
            .provision_signing_key(
                ambiguous_project.id,
                ambiguous_operation_alias.clone(),
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
        ProvisioningInfrastructure::new_protected(
            SystemClock,
            Sha256RequestDigester,
            false,
            BTreeMap::new(),
            BTreeMap::new(),
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
            ambiguous_operation_alias.clone(),
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
    let reconciled_material_id = reconciled_remote_owner.signer_material_id;
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
    assert!(
        ambiguous_state.lock().unwrap().object.is_some(),
        "stored remote object should exist"
    );
    ambiguous_state.lock().unwrap().object = Some((vec![99; 48], vec![99; 32]));
    assert_eq!(
        ambiguous_service
            .provision_signing_key(
                ambiguous_project.id,
                reconciled_operation.operation_alias.clone(),
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
    let blocked_material = protected_material::Entity::find_by_id(reconciled_material_id)
        .one(control)
        .await
        .expect("blocked material query should work")
        .expect("blocked material should remain durable");
    assert_eq!(blocked_material.state, "live");
    assert!(blocked_material.opaque_value.is_some());

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
        ProvisioningInfrastructure::new_protected(
            SystemClock,
            Sha256RequestDigester,
            false,
            BTreeMap::new(),
            BTreeMap::new(),
        )
        .with_signing_provisioner(failed_remote),
    );
    let failed_project = failed_service
        .create_project(
            CreateProject {
                display_name: "Definitively absent remote signing".to_owned(),
                belongs_to: None,
                idempotency_key: "project-remote-absent-12345678".to_owned(),
            },
            Uuid::new_v4(),
        )
        .await
        .expect("definitive-absence Project should atomically reserve its initial key");
    assert_eq!(
        failed_service
            .provision_signing_key(
                failed_project.id,
                format!("signing_initial_{}", failed_project.id.simple()),
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
            .provision_signing_key(
                failed_project.id,
                failed_operation.operation_alias.clone(),
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
    let erased_failed_material =
        protected_material::Entity::find_by_id(failed_operation.material_id)
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

    let cleanup_state = Arc::new(Mutex::new(RemoteSigningState {
        destroy_failure_once: Some((ProviderErrorClass::Unavailable, RetryClassification::Never)),
        ..Default::default()
    }));
    let initial_cleanup_remote =
        StatefulRemoteSigningProvider::new(remote_provider_id.clone(), cleanup_state.clone());
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
    let cleanup_bootstrap = ProvisioningService::new(
        Arc::new(cleanup_adapter.clone()),
        ProvisioningInfrastructure::new_protected(
            SystemClock,
            Sha256RequestDigester,
            false,
            BTreeMap::new(),
            BTreeMap::new(),
        )
        .with_signing_provisioner(initial_cleanup_remote.clone()),
    );
    let disabled_before_claim = cleanup_bootstrap
        .create_project(
            CreateProject {
                display_name: "Disabled before signing claim".to_owned(),
                belongs_to: None,
                idempotency_key: "project-disabled-before-signing-claim-12345678".to_owned(),
            },
            Uuid::new_v4(),
        )
        .await
        .expect("pre-claim disable Project should reserve its initial key");
    cleanup_bootstrap
        .disable_project(
            disabled_before_claim.id,
            disabled_before_claim.security_revision,
            Uuid::new_v4(),
        )
        .await
        .expect("pre-claim Project disable should commit");
    assert_eq!(
        cleanup_bootstrap
            .provision_signing_key(
                disabled_before_claim.id,
                format!("signing_initial_{}", disabled_before_claim.id.simple()),
                disabled_before_claim.metadata_revision,
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::Disabled),
        "a disabled Project must not start a previously unclaimed provider effect"
    );
    {
        let state = cleanup_state.lock().unwrap();
        assert_eq!(state.provision_calls, 0);
        assert!(state.object.is_none());
    }
    let abandoned_before_claim = key_provisioning_operation::Entity::find()
        .filter(key_provisioning_operation::Column::ProjectId.eq(disabled_before_claim.id))
        .one(control)
        .await
        .expect("pre-claim operation query should work")
        .expect("pre-claim operation should remain durable");
    assert_eq!(abandoned_before_claim.state, "abandoned");
    let abandoned_before_claim_key =
        project_signing_key::Entity::find_by_id(abandoned_before_claim.key_id)
            .one(control)
            .await
            .expect("pre-claim key query should work")
            .expect("pre-claim key should remain durable");
    assert_eq!(abandoned_before_claim_key.state, "abandoned");

    let cleanup_project = cleanup_bootstrap
        .create_project(
            CreateProject {
                display_name: "Remote signing cleanup".to_owned(),
                belongs_to: None,
                idempotency_key: "project-remote-cleanup-12345678".to_owned(),
            },
            Uuid::new_v4(),
        )
        .await
        .expect("cleanup Project should atomically reserve its initial key");
    let cleanup_remote =
        initial_cleanup_remote.with_project_disable(control.clone(), cleanup_project.id);
    let cleanup_service = ProvisioningService::new(
        Arc::new(cleanup_adapter),
        ProvisioningInfrastructure::new_protected(
            SystemClock,
            Sha256RequestDigester,
            false,
            BTreeMap::new(),
            BTreeMap::new(),
        )
        .with_signing_provisioner(cleanup_remote.clone()),
    );
    assert_eq!(
        cleanup_service
            .provision_signing_key(
                cleanup_project.id,
                format!("signing_initial_{}", cleanup_project.id.simple()),
                cleanup_project.metadata_revision,
                Uuid::new_v4(),
            )
            .await,
        Err(ApplicationError::Disabled),
        "a post-effect Project disable should durably queue cleanup"
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
            .provision_signing_key(
                cleanup_project.id,
                cleanup_operation.operation_alias.clone(),
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
    let material_id = protected_owner.secret_material_id;
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
    let smtp_control = EmailControlService::new_protected(
        Arc::new(smtp_repository),
        ConfigurationSecretSealers::single(software_custody.clone()),
        Arc::new(SystemClock),
        Arc::new(Sha256RequestDigester),
    );
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
        if candidate.material.reservation.provider_id.as_str() == "software" {
            protected_runtime_custody
                .authenticate_readiness_candidate(candidate)
                .await
                .expect(
                    "the matching configured custody root should authenticate its live material",
                );
        } else {
            assert_eq!(
                protected_runtime_custody
                    .authenticate_readiness_candidate(candidate)
                    .await,
                Err(ApplicationError::Disabled),
                "a Runtime custody provider must reject material owned by another provider"
            );
        }
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
        if candidate.material.reservation.provider_id.as_str() == "software"
            && wrong_runtime_custody
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
        deployment_material_id,
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
        smtp_material_id,
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
        SmtpCredentialResolver::resolve(&protected_runtime_custody, recipient_material_id,)
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

    let constraint_project = provisioning
        .create_project(
            CreateProject {
                display_name: "Cross-project constraint fixture".to_owned(),
                belongs_to: None,
                idempotency_key: "cross-project-constraint-12345678".to_owned(),
            },
            Uuid::new_v4(),
        )
        .await
        .expect("cross-Project constraint fixture should commit");
    let key_fence_project_id = constraint_project.id;

    let client_provider = provisioning
        .create_provider(
            created_project.id,
            CreateProvider {
                kind: ProviderKind::Oidc,
                provider_key: "client-directory".to_owned(),
                display_name: "Client directory provider".to_owned(),
                issuer: "https://client-directory.example.test/".to_owned(),
                client_id: "client-directory".to_owned(),
                client_secret: zeroize::Zeroizing::new("client-directory-secret".to_owned()),
                managed_profile_enabled: false,
                idempotency_key: "client-directory-provider-12345678".to_owned(),
                expected_project_revision: created_project.metadata_revision,
                egress_policy_revision: Some(1),
            },
            Uuid::new_v4(),
        )
        .await
        .expect("Client directory provider should use protected custody");
    let created_project = provisioning
        .get_project(created_project.id)
        .await
        .expect("Project should refresh after provider creation");
    verify_server_key_and_listener_journeys(
        &created_project,
        client_provider.id,
        &config,
        &pools,
        &url,
    )
    .await;

    let _created_project_id = Box::pin(verify_application_and_publication_journeys(
        created_project,
        key_fence_project_id,
        provisioning.clone(),
        control,
        &config,
        &pools,
        readiness.clone(),
        secondary_readiness.clone(),
        unexpected_readiness.clone(),
        &url,
        control_url.clone(),
    ))
    .await;

    control
        .execute_raw(Statement::from_string(
            DbBackend::Postgres,
            "UPDATE key_provisioning_operations
             SET maintenance_claimed_at = transaction_timestamp()
             WHERE state IN ('prepared','submitted','stored','cleanup_pending','cleanup_leased')"
                .to_owned(),
        ))
        .await
        .expect("pre-existing signing maintenance rows should move behind the fairness fixture");
    let mut fairness_key_ids = BTreeSet::new();
    for index in 0..35 {
        let project = provisioning
            .create_project(
                CreateProject {
                    display_name: format!("Signing fairness {index}"),
                    belongs_to: None,
                    idempotency_key: format!("signing-fairness-project-{index:02}-12345678"),
                },
                Uuid::new_v4(),
            )
            .await
            .expect("signing fairness Project should atomically create its initial operation");
        let key = provisioning
            .list_signing_keys(project.id)
            .await
            .expect("signing fairness initial key should list")
            .into_iter()
            .next()
            .expect("signing fairness initial key should exist");
        fairness_key_ids.insert(key.id);
    }
    let first_sweep =
        SigningKeyProvisioningPort::signing_key_maintenance_items(custody_adapter.as_ref(), 100)
            .await
            .expect("first signing maintenance sweep should claim a bounded page");
    let first_fairness_ids = first_sweep
        .into_iter()
        .filter_map(|item| match item {
            crate::application::SigningKeyMaintenanceItem::Provision { key_id, .. }
                if fairness_key_ids.contains(&key_id) =>
            {
                Some(key_id)
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(first_fairness_ids.len(), 34);
    let initially_deferred = fairness_key_ids
        .difference(&first_fairness_ids)
        .copied()
        .collect::<BTreeSet<_>>();
    assert_eq!(initially_deferred.len(), 1);
    let second_sweep =
        SigningKeyProvisioningPort::signing_key_maintenance_items(custody_adapter.as_ref(), 100)
            .await
            .expect("second signing maintenance sweep should rotate the persistent cursor");
    assert!(second_sweep.into_iter().any(|item| matches!(
        item,
        crate::application::SigningKeyMaintenanceItem::Provision { key_id, .. }
            if initially_deferred.contains(&key_id)
    )));

    verify_capacity_and_replay_limits(&control_url).await;

    pools.close().await;
}
