mod http_capabilities;

use std::collections::BTreeMap;
use std::{future::Future, sync::Arc, time::Duration};

use owlauth_key_provider::{ProviderFormatVersion, ProviderId};

use axum::Router;
use owlauth_types::FEDERATED_PROJECT_AUTH_AVAILABLE;
use sea_orm::{ConnectionTrait, DbBackend, Statement};
use thiserror::Error;
use tokio::{net::TcpListener, sync::watch, task::JoinSet, time::timeout};
use uuid::Uuid;

use crate::{
    adapters::{
        custody::SoftwareCustodyProvider,
        migrations::{SchemaError, prepare_schema},
        postgres::{
            DatabasePools, create_pools, custody::ProtectedMaterialRepository,
            email::PostgresPasswordlessEmailRepository,
            projection::PostgresProjectionEmailKeyAuthority,
        },
        protected_runtime::PostgresProtectedRuntimeCustody,
        runtime_security::{
            RuntimeKeyMaterial, SoftwareProjectionVerifiedEmailProtector, SoftwareRuntimeProtector,
        },
    },
    application::{
        DeploymentSmtpDesiredStatus, DeploymentSmtpGeneration, DeploymentSmtpRegistry,
        ManagedConnectionService, RuntimeAuthService, SmtpCredentialResolver, SmtpTlsMode,
        WebhookWorker,
    },
    config::{DeploymentSmtpStatus, ListenerConfig, PlaneMode, ServerConfig},
    http::{PlaneRouters, build_routers_with_capabilities},
    providers::{ActiveProvider, ProviderRegistrations},
};

pub(crate) use http_capabilities::{
    ClientHttpCapabilities, ControlHttpCapabilities, HttpCapabilities, RuntimeHttpCapabilities,
    build_http_capabilities,
};
#[cfg(test)]
pub(crate) use http_capabilities::{
    build_managed_reauthorization_service, build_managed_reauthorization_target_issuer,
    build_managed_reauthorization_target_verifier,
};

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SchemaFailure {
    #[error("connection")]
    Connection,
    #[error("migration execution")]
    Migration,
    #[error("lock timeout")]
    LockTimeout,
    #[error("statement timeout")]
    StatementTimeout,
    #[error("whole-run deadline")]
    Deadline,
    #[error("history unavailable")]
    HistoryUnavailable,
    #[error("dirty history")]
    DirtyHistory,
    #[error("incompatible history")]
    IncompatibleHistory,
}

impl From<SchemaError> for SchemaFailure {
    fn from(error: SchemaError) -> Self {
        match error {
            SchemaError::Connection => Self::Connection,
            SchemaError::Migration => Self::Migration,
            SchemaError::LockTimeout => Self::LockTimeout,
            SchemaError::StatementTimeout => Self::StatementTimeout,
            SchemaError::Deadline => Self::Deadline,
            SchemaError::HistoryUnavailable => Self::HistoryUnavailable,
            SchemaError::DirtyHistory => Self::DirtyHistory,
            SchemaError::IncompatibleHistory => Self::IncompatibleHistory,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ServerError {
    #[error("provider capabilities could not be composed safely")]
    ProviderComposition,
    #[error("PostgreSQL schema preparation failed: {0}")]
    Schema(SchemaFailure),
    #[error("PostgreSQL serving pools could not be prepared")]
    DatabasePools,
    #[error("stored material requires an unavailable provider capability")]
    ProviderReadiness,
    #[error("Runtime process incarnation could not be claimed")]
    RuntimeIncarnation,
    #[error("Client digest readiness could not be claimed")]
    ClientDigestReadiness,
    #[error("email protection inventory could not be reconciled")]
    EmailProtection,
    #[error("projection verified-email key authority could not be reconciled")]
    ProjectionEmailProtection,
    #[error("deployment SMTP generation did not reconcile exactly")]
    DeploymentSmtp,
    #[error("Project SMTP Runtime readiness inventory could not be persisted")]
    ProjectSmtpReadiness,
    #[error("a configured listener could not bind")]
    Bind,
    #[error("a listener stopped unexpectedly")]
    Serve,
    #[error("shutdown signal handling failed")]
    ShutdownSignal,
    #[error("graceful shutdown deadline elapsed")]
    ShutdownTimeout,
}

/// Runs the selected production-shaped composition root through bounded shutdown.
///
/// Schema preparation and all selected pool checks complete before any listener binds.
/// In `all` mode all three sockets bind before any begins serving.
///
/// # Errors
///
/// Returns a bounded startup, serving, or shutdown failure without dependency details.
pub async fn run(config: ServerConfig) -> Result<(), ServerError> {
    let providers = bundled_software_providers(&config)?;
    run_with_providers(config, providers).await
}

/// Runs `OwlAuth` with an explicit immutable set of statically linked provider capabilities.
///
/// Custom composition never falls back to the bundled software provider. The complete capability
/// set is validated for the selected process plane before schema or serving-pool work begins.
///
/// # Errors
///
/// Returns a provider-composition or bounded startup, serving, or shutdown failure.
#[allow(
    clippy::too_many_lines,
    reason = "top-level startup keeps each fail-closed reconciliation and shutdown boundary visible"
)]
pub async fn run_with_providers(
    config: ServerConfig,
    providers: ProviderRegistrations,
) -> Result<(), ServerError> {
    providers
        .validate_for_mode(config.mode)
        .map_err(|_| ServerError::ProviderComposition)?;
    let providers = Arc::new(providers);
    prepare_schema(&config.postgres)
        .await
        .map_err(|error| ServerError::Schema(error.into()))?;
    let pools = create_pools(&config)
        .await
        .map_err(|_| ServerError::DatabasePools)?;
    if let Err(error) = validate_provider_readiness(&config, &pools, &providers).await {
        pools.close().await;
        return Err(error);
    }
    // One startup incarnation is claimed once, then shared by reconciliation and every Runtime
    // serving/claim path. No delayed startup phase may reclaim the stable process identity.
    let runtime_incarnation = Uuid::new_v4();
    let client_incarnation = Uuid::new_v4();
    claim_runtime_incarnation(&config, &pools, runtime_incarnation)
        .await
        .map_err(|_| ServerError::RuntimeIncarnation)?;
    let email_protection_maintenance =
        reconcile_email_protection(&config, &pools, runtime_incarnation)
            .await
            .map_err(|_| ServerError::EmailProtection)?;
    let projection_email_maintenance =
        reconcile_projection_email_protection(&config, &pools, runtime_incarnation)
            .await
            .map_err(|_| ServerError::ProjectionEmailProtection)?;
    reconcile_deployment_smtp(&config, &pools, runtime_incarnation, &providers)
        .await
        .map_err(|_| ServerError::DeploymentSmtp)?;
    let project_smtp_readiness =
        reconcile_project_smtp_readiness(&config, &pools, runtime_incarnation, &providers)
            .await
            .map_err(|_| ServerError::ProjectSmtpReadiness)?;
    let capabilities = build_http_capabilities(
        &config,
        Some(&pools),
        runtime_incarnation,
        client_incarnation,
        providers.as_ref(),
    );
    let client_digest_readiness = capabilities
        .client
        .as_ref()
        .and_then(|client| client.readiness.clone());
    let signing_lifecycle = capabilities
        .control
        .as_ref()
        .and_then(|control| control.provisioning.clone());
    let signing_observation = capabilities
        .runtime
        .as_ref()
        .and_then(|runtime| runtime.readiness.clone());
    let mut routers = build_routers_with_capabilities(&config, capabilities);
    if let Some(managed) = routers.managed_sync.as_deref() {
        match managed.restore_key_state().await {
            Ok(true) => {}
            Ok(false) => tracing::warn!(
                event = "managed_sync_key_degraded",
                "managed provider workers are suppressed until credential keys are restored"
            ),
            Err(_) => tracing::warn!(
                event = "managed_restore_failed",
                "managed provider restore is degraded; Runtime authority remains available"
            ),
        }
    }

    if let Some(readiness) = client_digest_readiness.as_deref()
        && readiness.claim().await.is_err()
    {
        pools.close().await;
        return Err(ServerError::ClientDigestReadiness);
    }

    let runtime_listener = match bind_selected(config.mode.has_runtime(), config.runtime.bind).await
    {
        Ok(listener) => listener,
        Err(error) => {
            pools.close().await;
            return Err(error);
        }
    };
    let client_listener = match bind_selected(config.mode.has_client(), config.client.bind).await {
        Ok(listener) => listener,
        Err(error) => {
            pools.close().await;
            return Err(error);
        }
    };
    let control_listener = match bind_selected(config.mode.has_control(), config.control.bind).await
    {
        Ok(listener) => listener,
        Err(error) => {
            pools.close().await;
            return Err(error);
        }
    };

    let client_digest_readiness_maintenance =
        client_digest_readiness.map(spawn_client_digest_readiness_renewal);
    let signing_lifecycle_maintenance = signing_lifecycle.map(spawn_signing_lifecycle_maintenance);
    let signing_observation_maintenance =
        signing_observation.map(spawn_signing_observation_maintenance);

    routers.mark_ready();
    if config.mode.has_runtime() {
        log_listener_ready("Runtime", &config.runtime, "auth/");
    }
    if config.mode.has_client() {
        log_listener_ready("Client", &config.client, "ready");
    }
    if config.mode.has_control() {
        log_listener_ready("Control", &config.control, "console/");
    }
    tracing::info!(
        event = "server_ready",
        mode = ?config.mode,
        "selected OwlAuth listeners are ready"
    );

    let result = serve_until_shutdown(
        &mut routers,
        runtime_listener,
        client_listener,
        control_listener,
        config.shutdown_timeout,
    )
    .await;
    if let Some(maintenance) = client_digest_readiness_maintenance {
        maintenance.abort();
        let _ = maintenance.await;
    }
    if let Some(maintenance) = signing_lifecycle_maintenance {
        maintenance.abort();
        let _ = maintenance.await;
    }
    if let Some(maintenance) = signing_observation_maintenance {
        maintenance.abort();
        let _ = maintenance.await;
    }
    if let Some(maintenance) = email_protection_maintenance {
        maintenance.abort();
        let _ = maintenance.await;
    }
    if let Some(maintenance) = projection_email_maintenance {
        maintenance.abort();
        let _ = maintenance.await;
    }
    if let Some(maintenance) = project_smtp_readiness {
        maintenance.abort();
        let _ = maintenance.await;
    }
    pools.close().await;
    result
}

fn spawn_signing_lifecycle_maintenance(
    provisioning: Arc<crate::application::ProvisioningService>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if let Err(error) = provisioning.reconcile_signing_key_lifecycle(100).await {
                tracing::warn!(
                    event = "signing_key_lifecycle_reconciliation_pending",
                    error = ?error,
                    "signing key lifecycle reconciliation failed closed and will retry"
                );
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
}

fn spawn_signing_observation_maintenance(
    readiness: Arc<crate::application::ReadinessService>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if let Err(error) = readiness.observe_signing_revisions(100).await {
                tracing::warn!(
                    event = "signing_key_revision_observation_pending",
                    error = ?error,
                    "Runtime signing revision observation failed closed and will retry"
                );
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
}

fn spawn_client_digest_readiness_renewal(
    readiness: Arc<crate::application::ClientDigestReadinessService>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let interval = readiness.renewal_interval();
        loop {
            tokio::time::sleep(interval).await;
            match readiness.renew().await {
                Ok(()) => {}
                Err(crate::application::ApplicationError::Persistence) => {
                    // The service marks the local observation unhealthy before returning. Keep
                    // retrying the same exact incarnation so a transient database outage can
                    // recover without ever claiming readiness during the failed interval.
                    tracing::error!(
                        event = "client_digest_readiness_renewal_failed",
                        "Client digest readiness renewal failed closed; retrying"
                    );
                }
                Err(error) => {
                    tracing::error!(
                        event = "client_digest_readiness_renewal_stopped",
                        error = %error,
                        "Client digest readiness renewal stopped after a terminal failure"
                    );
                    return;
                }
            }
        }
    })
}

pub(crate) fn bundled_software_providers(
    config: &ServerConfig,
) -> Result<ProviderRegistrations, ServerError> {
    // Client verification owns no signing or secret-custody role. A Client-only binary must not
    // require Control/Runtime provisioning keys merely to construct an intentionally empty
    // provider registry.
    if !config.mode.has_control() && !config.mode.has_runtime() {
        return Ok(ProviderRegistrations::new());
    }
    let provisioning = config
        .provisioning
        .as_ref()
        .ok_or(ServerError::ProviderComposition)?;
    let provider_id = ProviderId::new("software").map_err(|_| ServerError::ProviderComposition)?;
    let format_version =
        ProviderFormatVersion::new(1).map_err(|_| ServerError::ProviderComposition)?;
    let software = Arc::new(
        SoftwareCustodyProvider::new(
            provider_id.clone(),
            provisioning
                .software_custody_key
                .as_ref()
                .ok_or(ServerError::ProviderComposition)?
                .expose_copy(),
        )
        .map_err(|_| ServerError::ProviderComposition)?,
    );
    let mut providers = ProviderRegistrations::new();
    if config.mode.has_control() {
        providers
            .register_signing_provisioner(provider_id.clone(), software.clone())
            .and_then(|providers| {
                providers.register_secret_sealer(provider_id.clone(), software.clone())
            })
            .map_err(|_| ServerError::ProviderComposition)?;
        providers
            .select_active_signing_provider(ActiveProvider::new(
                provider_id.clone(),
                format_version,
            ))
            .select_active_secret_provider(ActiveProvider::new(
                provider_id.clone(),
                format_version,
            ));
    }
    if config.mode.has_runtime() {
        providers
            .register_runtime_signer(provider_id.clone(), software.clone())
            .and_then(|providers| providers.register_secret_opener(provider_id, software.clone()))
            .map_err(|_| ServerError::ProviderComposition)?;
    }
    Ok(providers)
}

pub(crate) async fn validate_provider_readiness(
    config: &ServerConfig,
    pools: &DatabasePools,
    providers: &ProviderRegistrations,
) -> Result<(), ServerError> {
    if !config.mode.has_control() && !config.mode.has_runtime() {
        return Ok(());
    }
    let database = pools
        .runtime
        .as_ref()
        .or(pools.control.as_ref())
        .ok_or(ServerError::ProviderReadiness)?;
    let deployment_id = config
        .instance_id
        .as_deref()
        .ok_or(ServerError::ProviderReadiness)?;
    let materials = ProtectedMaterialRepository::new(database.clone(), deployment_id)
        .map_err(|_| ServerError::ProviderReadiness)?;
    if !config.mode.has_runtime() {
        return Ok(());
    }
    let custody = PostgresProtectedRuntimeCustody::from_registrations(
        database.clone(),
        deployment_id,
        providers,
    )
    .map_err(|_| ServerError::ProviderReadiness)?;
    for _ in 0..3 {
        let inventory_revision = materials
            .material_inventory_revision()
            .await
            .map_err(|_| ServerError::ProviderReadiness)?;
        let scan_result =
            authenticate_runtime_provider_inventory(&materials, providers, &custody).await;
        let current_revision = materials
            .material_inventory_revision()
            .await
            .map_err(|_| ServerError::ProviderReadiness)?;
        if current_revision != inventory_revision {
            continue;
        }
        scan_result?;
        return Ok(());
    }
    Err(ServerError::ProviderReadiness)
}

async fn authenticate_runtime_provider_inventory(
    materials: &ProtectedMaterialRepository,
    providers: &ProviderRegistrations,
    custody: &PostgresProtectedRuntimeCustody,
) -> Result<(), ServerError> {
    let required = materials
        .required_runtime_capabilities()
        .await
        .map_err(|_| ServerError::ProviderReadiness)?;
    if required.iter().any(|capability| {
        !providers.supports_runtime_material(
            &capability.provider_id,
            capability.provider_format_version,
            capability.material_kind,
        )
    }) {
        return Err(ServerError::ProviderReadiness);
    }
    let mut after = None;
    loop {
        let candidates = materials
            .runtime_readiness_page(after, 128)
            .await
            .map_err(|_| ServerError::ProviderReadiness)?;
        if candidates.is_empty() {
            return Ok(());
        }
        for candidate in candidates {
            after = Some(candidate.material.reservation.id);
            custody
                .authenticate_readiness_candidate(candidate)
                .await
                .map_err(|_| ServerError::ProviderReadiness)?;
        }
    }
}

fn email_protection_failure_class(error: crate::application::ApplicationError) -> &'static str {
    match error {
        crate::application::ApplicationError::Persistence => "persistence",
        crate::application::ApplicationError::Integrity => "integrity",
        _ => "key_unavailable",
    }
}

fn lease_duration_from_config(
    config: &ServerConfig,
) -> Result<time::Duration, crate::application::ApplicationError> {
    let seconds = config
        .publication_lease_ttl
        .as_secs()
        .max(5)
        .saturating_mul(2);
    Ok(time::Duration::seconds(i64::try_from(seconds).map_err(
        |_| crate::application::ApplicationError::Integrity,
    )?))
}

async fn claim_runtime_incarnation(
    config: &ServerConfig,
    pools: &DatabasePools,
    runtime_incarnation: Uuid,
) -> Result<(), crate::application::ApplicationError> {
    if !config.mode.has_runtime() {
        return Ok(());
    }
    let database = pools
        .runtime
        .as_ref()
        .ok_or(crate::application::ApplicationError::Persistence)?;
    PostgresPasswordlessEmailRepository::new_with_runtime_identity(
        database.clone(),
        config.runtime_process_id.clone(),
        runtime_incarnation,
        config.required_runtime_process_ids.clone(),
        lease_duration_from_config(config)?,
    )
    .claim_runtime_incarnation(time::OffsetDateTime::now_utc())
    .await
}

fn should_reconcile_email_protection(mode: PlaneMode, configured: bool) -> bool {
    mode.has_runtime() && configured
}

#[allow(
    clippy::too_many_lines,
    reason = "startup and retry paths keep scoped readiness transitions and key-maintenance inputs together"
)]
async fn reconcile_email_protection(
    config: &ServerConfig,
    pools: &DatabasePools,
    runtime_incarnation: Uuid,
) -> Result<Option<tokio::task::JoinHandle<()>>, crate::application::ApplicationError> {
    if !should_reconcile_email_protection(config.mode, config.email_identity_protection.is_some()) {
        return Ok(None);
    }
    let protection = config
        .email_identity_protection
        .as_ref()
        .ok_or(crate::application::ApplicationError::Integrity)?;
    let database = pools
        .runtime
        .as_ref()
        .or(pools.control.as_ref())
        .ok_or(crate::application::ApplicationError::Persistence)?;
    let short_term = config
        .runtime_protection
        .as_ref()
        .ok_or(crate::application::ApplicationError::Integrity)?;
    let mut short_term_readable_versions = short_term.retained.keys().copied().collect::<Vec<_>>();
    short_term_readable_versions.push(short_term.active_version);
    let mut email_identity_readable_versions =
        protection.retained.keys().copied().collect::<Vec<_>>();
    email_identity_readable_versions.push(protection.active_version);
    let active = RuntimeKeyMaterial::new(
        protection.active.digest_key.expose_copy(),
        protection.active.protection_key.expose_copy(),
    );
    let retained = protection
        .retained
        .iter()
        .map(|(version, keys)| {
            (
                *version,
                RuntimeKeyMaterial::new(
                    keys.digest_key.expose_copy(),
                    keys.protection_key.expose_copy(),
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let protector = SoftwareRuntimeProtector::new(
        config
            .instance_id
            .clone()
            .ok_or(crate::application::ApplicationError::Integrity)?,
        protection.active_version,
        active,
        retained,
    )?;
    let repository = PostgresPasswordlessEmailRepository::new_with_runtime_identity(
        database.clone(),
        config.runtime_process_id.clone(),
        runtime_incarnation,
        config.required_runtime_process_ids.clone(),
        lease_duration_from_config(config)?,
    );
    // Startup performs at most one bounded batch. A durable authority keeps identity alias
    // writes on the old version until every configured Runtime process has observed the staged
    // version and the operator explicitly requests cutover.
    let now = time::OffsetDateTime::now_utc();
    let lease_duration = time::Duration::seconds(
        i64::try_from(config.publication_lease_ttl.as_secs())
            .map_err(|_| crate::application::ApplicationError::Integrity)?,
    );
    let initial = async {
        repository
            .rewrap_durable_email_identities(
                &protector,
                100,
                &config.runtime_process_id,
                &config.required_runtime_process_ids,
                now + lease_duration,
                protection.identity_alias_cutover_version == Some(protection.active_version),
                protection.identity_alias_retire_version == Some(protection.active_version),
                now,
            )
            .await?;
        repository
            .reconcile_protection_inventory(
                &short_term_readable_versions,
                &email_identity_readable_versions,
                now,
            )
            .await
            .map(|_| ())
    }
    .await;
    let (initial_ready, initial_failure) = match initial {
        Ok(()) => (true, None),
        Err(error) => {
            tracing::error!(
                event = "email_protection_scoped_unavailable",
                error = ?error,
                "durable email PII reconciliation is unavailable; unrelated listeners will continue"
            );
            (false, Some(email_protection_failure_class(error)))
        }
    };
    if let Err(error) = repository
        .record_email_protection_readiness(initial_ready, initial_failure, now)
        .await
    {
        tracing::error!(
            event = "email_protection_readiness_persist_failed",
            error = ?error,
            "email protection reconciliation status could not be persisted"
        );
    }
    let maintenance_repository = repository.clone();
    let maintenance_protector = protector.clone();
    let maintenance_process_id = config.runtime_process_id.clone();
    let required_process_ids = config.required_runtime_process_ids.clone();
    let cutover_requested =
        protection.identity_alias_cutover_version == Some(protection.active_version);
    let retirement_requested =
        protection.identity_alias_retire_version == Some(protection.active_version);
    let maintenance_short_term_readable_versions = short_term_readable_versions;
    let maintenance_email_identity_readable_versions = email_identity_readable_versions;
    Ok(Some(tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let now = time::OffsetDateTime::now_utc();
            let result = async {
                maintenance_repository
                    .rewrap_durable_email_identities(
                        &maintenance_protector,
                        100,
                        &maintenance_process_id,
                        &required_process_ids,
                        now + lease_duration,
                        cutover_requested,
                        retirement_requested,
                        now,
                    )
                    .await?;
                maintenance_repository
                    .reconcile_protection_inventory(
                        &maintenance_short_term_readable_versions,
                        &maintenance_email_identity_readable_versions,
                        now,
                    )
                    .await
                    .map(|_| ())
            }
            .await;
            match result {
                Ok(()) => {
                    let _ = maintenance_repository
                        .record_email_protection_readiness(true, None, now)
                        .await;
                }
                Err(error) => {
                    let failure_class = email_protection_failure_class(error);
                    let _ = maintenance_repository
                        .record_email_protection_readiness(false, Some(failure_class), now)
                        .await;
                    tracing::error!(
                        event = "email_identity_alias_maintenance_failed",
                        error = ?error,
                        "bounded email identity rewrap/cutover maintenance will retry"
                    );
                    tokio::time::sleep(Duration::from_secs(4)).await;
                }
            }
        }
    })))
}

fn projection_email_protector(
    config: &ServerConfig,
) -> Result<SoftwareProjectionVerifiedEmailProtector, crate::application::ApplicationError> {
    let protection = &config.projection_email_protection;
    let retained = protection
        .retained
        .iter()
        .map(|(version, key)| (*version, key.expose_copy()))
        .collect::<BTreeMap<_, _>>();
    SoftwareProjectionVerifiedEmailProtector::new(
        config
            .instance_id
            .clone()
            .ok_or(crate::application::ApplicationError::Integrity)?,
        protection.active_version,
        protection.active_key.expose_copy(),
        retained,
    )
}

#[derive(Clone)]
struct ProjectionEmailMaintenance {
    authority: PostgresProjectionEmailKeyAuthority,
    protector: SoftwareProjectionVerifiedEmailProtector,
    process_id: String,
    runtime_incarnation: Uuid,
    required_process_ids: Vec<String>,
    lease: time::Duration,
    retention: time::Duration,
    cutover: Option<i32>,
    retirement: Option<i32>,
}

impl ProjectionEmailMaintenance {
    async fn observe(&self) -> Result<(), crate::application::ApplicationError> {
        self.authority
            .observe_runtime(
                &self.process_id,
                self.runtime_incarnation,
                &self.protector,
                self.lease,
            )
            .await
    }

    async fn reconcile(&self) -> Result<(), crate::application::ApplicationError> {
        self.authority
            .reconcile(
                &self.required_process_ids,
                &self.protector,
                self.cutover,
                self.retirement,
                self.retention,
            )
            .await
    }

    async fn maintain(
        &self,
    ) -> (
        Result<(), crate::application::ApplicationError>,
        Result<u64, crate::application::ApplicationError>,
    ) {
        // Rewrap remains independent of lifecycle reconciliation so a blocked retirement cannot
        // prevent the mutable storage inventory from converging.
        let reconciliation = self.reconcile().await;
        let rewrap = self
            .authority
            .rewrap_projection_email_batch(&self.protector, 100)
            .await;
        (reconciliation, rewrap)
    }
}

fn log_projection_email_maintenance(
    reconciliation: Result<(), crate::application::ApplicationError>,
    rewrap: Result<u64, crate::application::ApplicationError>,
) {
    if reconciliation.is_ok() && rewrap.is_ok() {
        return;
    }
    let unexpected = [reconciliation.as_ref().err(), rewrap.as_ref().err()]
        .into_iter()
        .flatten()
        .any(|error| !matches!(error, crate::application::ApplicationError::Disabled));
    if unexpected {
        tracing::warn!(
            event = "projection_email_key_reconciliation_pending",
            reconciliation_error = ?reconciliation.as_ref().err(),
            rewrap_error = ?rewrap.as_ref().err(),
            "projection verified-email key lifecycle failed closed and will retry"
        );
    } else {
        tracing::debug!(
            event = "projection_email_key_reconciliation_pending",
            "projection verified-email key lifecycle is waiting on bounded convergence"
        );
    }
}

async fn reconcile_projection_email_protection(
    config: &ServerConfig,
    pools: &DatabasePools,
    runtime_incarnation: Uuid,
) -> Result<Option<tokio::task::JoinHandle<()>>, crate::application::ApplicationError> {
    if !config.mode.has_runtime() {
        return Ok(None);
    }
    let database = pools
        .runtime
        .as_ref()
        .ok_or(crate::application::ApplicationError::Persistence)?;
    let lease_seconds = config
        .publication_lease_ttl
        .as_secs()
        .max(5)
        .saturating_mul(2);
    let maintenance = ProjectionEmailMaintenance {
        authority: PostgresProjectionEmailKeyAuthority::new(database.clone()),
        protector: projection_email_protector(config)?,
        process_id: config.runtime_process_id.clone(),
        runtime_incarnation,
        required_process_ids: config.required_runtime_process_ids.clone(),
        lease: time::Duration::seconds(
            i64::try_from(lease_seconds)
                .map_err(|_| crate::application::ApplicationError::Integrity)?,
        ),
        retention: time::Duration::try_from(config.key_propagation_delay)
            .map_err(|_| crate::application::ApplicationError::Integrity)?,
        cutover: config.projection_email_protection.cutover_version,
        retirement: config.projection_email_protection.retire_version,
    };
    let first = maintenance.reconcile().await;
    if first.is_err() && maintenance.cutover.is_none() && maintenance.retirement.is_none() {
        first?;
    }
    maintenance.observe().await?;
    let (reconciliation, rewrap) = maintenance.maintain().await;
    log_projection_email_maintenance(reconciliation, rewrap);

    Ok(Some(tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            if let Err(error) = maintenance.observe().await {
                tracing::warn!(
                    event = "projection_email_key_reconciliation_pending",
                    error = ?error,
                    "projection verified-email observation failed closed and will retry"
                );
                continue;
            }
            let (reconciliation, rewrap) = maintenance.maintain().await;
            log_projection_email_maintenance(reconciliation, rewrap);
        }
    })))
}

fn allows_unsealed_deployment_smtp_bootstrap(
    mode: PlaneMode,
    status: DeploymentSmtpStatus,
) -> bool {
    mode == PlaneMode::All && status == DeploymentSmtpStatus::Reconciled
}

async fn reconcile_deployment_smtp(
    config: &ServerConfig,
    pools: &DatabasePools,
    runtime_incarnation: Uuid,
    providers: &ProviderRegistrations,
) -> Result<(), crate::application::ApplicationError> {
    if !config.mode.has_runtime() {
        return Ok(());
    }
    let database = pools
        .runtime
        .as_ref()
        .ok_or(crate::application::ApplicationError::Persistence)?;
    let registry = PostgresPasswordlessEmailRepository::new_with_runtime_identity(
        database.clone(),
        config.runtime_process_id.clone(),
        runtime_incarnation,
        config.required_runtime_process_ids.clone(),
        lease_duration_from_config(config)?,
    );
    let Some(configured) = config.deployment_smtp.as_ref() else {
        return registry.assert_no_active_deployment_smtp().await;
    };
    let Some(safe_fingerprint) = configured.safe_fingerprint else {
        if allows_unsealed_deployment_smtp_bootstrap(config.mode, configured.status) {
            // Combined topology may bind Control once with non-active metadata so the ordinary
            // authenticated API can seal the first credential generation. Runtime-only processes
            // never own that bootstrap capability, and an already-active database generation
            // still fails closed here.
            return registry.assert_no_active_deployment_smtp().await;
        }
        return Err(crate::application::ApplicationError::Integrity);
    };
    let material_row = database
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT credential_material_id FROM deployment_smtp_generations WHERE generation=$1",
            [configured.generation.into()],
        ))
        .await
        .map_err(|_| crate::application::ApplicationError::Persistence)?
        .ok_or(crate::application::ApplicationError::NotFound)?;
    let credential_material_id = material_row
        .try_get::<Uuid>("", "credential_material_id")
        .map_err(|_| crate::application::ApplicationError::Integrity)?;
    let generation = DeploymentSmtpGeneration {
        generation: configured.generation,
        desired_status: match configured.status {
            DeploymentSmtpStatus::Reconciled => DeploymentSmtpDesiredStatus::Reconciled,
            DeploymentSmtpStatus::Active => DeploymentSmtpDesiredStatus::Active,
            DeploymentSmtpStatus::Disabled => DeploymentSmtpDesiredStatus::Disabled,
            DeploymentSmtpStatus::Compromised => DeploymentSmtpDesiredStatus::Compromised,
        },
        host: configured.host.clone(),
        port: configured.port,
        tls_mode: match configured.tls_mode.as_str() {
            "implicit_tls" => SmtpTlsMode::ImplicitTls,
            "starttls_required" => SmtpTlsMode::StartTlsRequired,
            _ => return Err(crate::application::ApplicationError::Integrity),
        },
        sender_address: configured.sender_address.clone(),
        credential_material_id,
        safe_fingerprint,
        explicitly_allowed_private_ips: configured.explicitly_allowed_private_ips.clone(),
    };
    if matches!(
        generation.desired_status,
        DeploymentSmtpDesiredStatus::Reconciled | DeploymentSmtpDesiredStatus::Active
    ) {
        let row = database
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT credential_material_id,safe_fingerprint
                   FROM deployment_smtp_generations WHERE generation=$1",
                [generation.generation.into()],
            ))
            .await
            .map_err(|_| crate::application::ApplicationError::Persistence)?
            .ok_or(crate::application::ApplicationError::NotFound)?;
        let material_id = row
            .try_get::<Uuid>("", "credential_material_id")
            .map_err(|_| crate::application::ApplicationError::Integrity)?;
        let fingerprint = row
            .try_get::<Option<Vec<u8>>>("", "safe_fingerprint")
            .map_err(|_| crate::application::ApplicationError::Persistence)?
            .ok_or(crate::application::ApplicationError::Integrity)?;
        if fingerprint.as_slice() != generation.safe_fingerprint {
            return Err(crate::application::ApplicationError::Integrity);
        }
        let custody = PostgresProtectedRuntimeCustody::from_registrations(
            database.clone(),
            config
                .instance_id
                .as_deref()
                .ok_or(crate::application::ApplicationError::Integrity)?,
            providers,
        )?;
        SmtpCredentialResolver::resolve_checked(
            &custody,
            material_id,
            &generation.safe_fingerprint,
        )
        .await?;
    }
    registry
        .reconcile_deployment_smtp(&generation, time::OffsetDateTime::now_utc())
        .await
}

async fn reconcile_project_smtp_readiness(
    config: &ServerConfig,
    pools: &DatabasePools,
    runtime_incarnation: Uuid,
    providers: &ProviderRegistrations,
) -> Result<Option<tokio::task::JoinHandle<()>>, crate::application::ApplicationError> {
    if !config.mode.has_runtime() {
        return Ok(None);
    }
    let database = pools
        .runtime
        .as_ref()
        .ok_or(crate::application::ApplicationError::Persistence)?;
    let resolver: Arc<dyn SmtpCredentialResolver> =
        Arc::new(PostgresProtectedRuntimeCustody::from_registrations(
            database.clone(),
            config
                .instance_id
                .as_deref()
                .ok_or(crate::application::ApplicationError::Integrity)?,
            providers,
        )?);
    let repository = PostgresPasswordlessEmailRepository::new_with_runtime_identity(
        database.clone(),
        config.runtime_process_id.clone(),
        runtime_incarnation,
        config.required_runtime_process_ids.clone(),
        lease_duration_from_config(config)?,
    );
    reconcile_project_smtp_readiness_restore(
        &repository,
        resolver.as_ref(),
        time::OffsetDateTime::now_utc(),
    )
    .await?;
    Ok(Some(tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            if let Err(error) = reconcile_project_smtp_readiness_batch(
                &repository,
                resolver.as_ref(),
                time::OffsetDateTime::now_utc(),
            )
            .await
            {
                tracing::warn!(
                    event = "project_smtp_readiness_reconciliation_failed",
                    error = ?error,
                    "bounded Project SMTP readiness reconciliation will retry"
                );
            }
        }
    })))
}

pub(crate) async fn reconcile_project_smtp_readiness_restore(
    repository: &PostgresPasswordlessEmailRepository,
    resolver: &dyn SmtpCredentialResolver,
    restore_epoch: time::OffsetDateTime,
) -> Result<usize, crate::application::ApplicationError> {
    // Stale ready observations are removed from authority before page one. Process loss at any
    // boundary is therefore fail-closed, and one fixed epoch makes each successfully recorded
    // row leave the bounded inventory until all eligible generations have been checked.
    repository
        .fail_close_project_smtp_restore_inventory(restore_epoch)
        .await?;
    let mut total = 0_usize;
    loop {
        let observed = reconcile_project_smtp_readiness_batch_before(
            repository,
            resolver,
            restore_epoch,
            restore_epoch,
        )
        .await?;
        total = total.saturating_add(observed);
        if observed == 0 {
            return Ok(total);
        }
    }
}

pub(crate) async fn reconcile_project_smtp_readiness_batch(
    repository: &PostgresPasswordlessEmailRepository,
    resolver: &dyn SmtpCredentialResolver,
    now: time::OffsetDateTime,
) -> Result<(), crate::application::ApplicationError> {
    reconcile_project_smtp_readiness_batch_before(repository, resolver, now, now)
        .await
        .map(|_| ())
}

async fn reconcile_project_smtp_readiness_batch_before(
    repository: &PostgresPasswordlessEmailRepository,
    resolver: &dyn SmtpCredentialResolver,
    now: time::OffsetDateTime,
    restore_epoch: time::OffsetDateTime,
) -> Result<usize, crate::application::ApplicationError> {
    let candidates = repository
        .project_smtp_readiness_candidates_before(now, restore_epoch, 100)
        .await?;
    let observed = candidates.len();
    let mut ready = 0_u32;
    let mut unavailable = 0_u32;
    for candidate in candidates {
        let readable = resolver
            .resolve_checked(
                candidate.credential_material_id,
                &candidate.safe_fingerprint,
            )
            .await
            .is_ok();
        repository
            .record_project_smtp_readiness(&candidate, readable, now)
            .await?;
        if readable {
            ready = ready.saturating_add(1);
        } else {
            unavailable = unavailable.saturating_add(1);
        }
    }
    if observed == 0 {
        tracing::debug!(
            event = "project_smtp_readiness_reconciled",
            ready,
            unavailable,
            "bounded Project SMTP readiness inventory completed without candidates"
        );
    } else {
        tracing::info!(
            event = "project_smtp_readiness_reconciled",
            ready,
            unavailable,
            "bounded Project SMTP readiness inventory completed"
        );
    }
    Ok(observed)
}

fn log_listener_ready(plane: &'static str, listener: &ListenerConfig, open_path: &str) {
    let open_url = listener
        .external_base
        .join(open_path)
        .unwrap_or_else(|_| listener.external_base.clone());
    tracing::info!(
        event = "listener_ready",
        plane,
        bind_address = %listener.bind,
        base_url = %listener.external_base,
        open_url = %open_url,
        "{plane} listening at {}; open {}",
        listener.external_base,
        open_url
    );
}

async fn bind_selected(
    selected: bool,
    address: std::net::SocketAddr,
) -> Result<Option<TcpListener>, ServerError> {
    if !selected {
        return Ok(None);
    }
    TcpListener::bind(address)
        .await
        .map(Some)
        .map_err(|_| ServerError::Bind)
}

async fn serve_until_shutdown(
    routers: &mut PlaneRouters,
    runtime_listener: Option<TcpListener>,
    client_listener: Option<TcpListener>,
    control_listener: Option<TcpListener>,
    shutdown_timeout: Duration,
) -> Result<(), ServerError> {
    let (shutdown_sender, shutdown_receiver) = watch::channel(false);
    let selection = runtime_worker_selection(
        routers.runtime_auth.is_some(),
        routers.managed_sync.is_some(),
        routers.webhook_delivery.is_some(),
    );
    let runtime_auth = routers.runtime_auth.clone();
    let runtime_workers = spawn_runtime_worker_tasks(
        selection,
        runtime_auth
            .clone()
            .map(|service| run_mail_worker(service, shutdown_receiver.clone())),
        runtime_auth
            .filter(|_| selection.provider_recovery)
            .map(|service| run_provider_recovery_worker(service, shutdown_receiver.clone())),
        routers
            .managed_sync
            .clone()
            .map(|managed| run_managed_workers(managed, shutdown_receiver.clone())),
        routers
            .webhook_delivery
            .clone()
            .map(|worker| run_webhook_worker(worker, shutdown_receiver.clone())),
    );
    let mut servers = JoinSet::new();
    spawn_selected(
        &mut servers,
        runtime_listener,
        routers.runtime.take(),
        shutdown_receiver.clone(),
    );
    spawn_selected(
        &mut servers,
        client_listener,
        routers.client.take(),
        shutdown_receiver.clone(),
    );
    spawn_selected(
        &mut servers,
        control_listener,
        routers.control.take(),
        shutdown_receiver,
    );

    let mut unexpected_stop = false;
    tokio::select! {
        signal = shutdown_signal() => signal?,
        result = servers.join_next() => {
            unexpected_stop = true;
            if !matches!(result, Some(Ok(Ok(())))) {
                tracing::error!(event = "listener_failed", "an OwlAuth listener failed");
            }
        }
    }

    routers.mark_unready();
    let _ = shutdown_sender.send(true);
    tracing::info!(
        event = "server_draining",
        "OwlAuth stopped business admission"
    );

    let runtime_worker_aborts = runtime_workers
        .iter()
        .map(tokio::task::JoinHandle::abort_handle)
        .collect::<Vec<_>>();
    let drained = timeout(shutdown_timeout, async {
        while servers.join_next().await.is_some() {}
        drain_runtime_workers(runtime_workers).await;
    })
    .await;
    if drained.is_err() {
        servers.abort_all();
        for worker in runtime_worker_aborts {
            worker.abort();
        }
        return Err(ServerError::ShutdownTimeout);
    }
    if unexpected_stop {
        return Err(ServerError::Serve);
    }
    Ok(())
}

const RUNTIME_MAIL_BATCH_BUDGET: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "tests compare independent optional worker composition decisions"
)]
struct RuntimeWorkerSelection {
    mail: bool,
    provider_recovery: bool,
    managed_sync: bool,
    webhook_delivery: bool,
}

#[allow(
    clippy::fn_params_excessive_bools,
    reason = "the pure helper verifies independent optional worker inputs"
)]
const fn runtime_worker_selection(
    runtime_auth_composed: bool,
    managed_sync_composed: bool,
    webhook_delivery_composed: bool,
) -> RuntimeWorkerSelection {
    RuntimeWorkerSelection {
        mail: runtime_auth_composed,
        provider_recovery: FEDERATED_PROJECT_AUTH_AVAILABLE && runtime_auth_composed,
        managed_sync: managed_sync_composed,
        webhook_delivery: webhook_delivery_composed,
    }
}

fn spawn_runtime_worker_tasks<Mail, Recovery, Managed, Webhook>(
    selection: RuntimeWorkerSelection,
    mail: Option<Mail>,
    provider_recovery: Option<Recovery>,
    managed_sync: Option<Managed>,
    webhook_delivery: Option<Webhook>,
) -> Vec<tokio::task::JoinHandle<()>>
where
    Mail: Future<Output = ()> + Send + 'static,
    Recovery: Future<Output = ()> + Send + 'static,
    Managed: Future<Output = ()> + Send + 'static,
    Webhook: Future<Output = ()> + Send + 'static,
{
    assert_eq!(selection.mail, mail.is_some());
    assert_eq!(selection.provider_recovery, provider_recovery.is_some());
    assert_eq!(selection.managed_sync, managed_sync.is_some());
    assert_eq!(selection.webhook_delivery, webhook_delivery.is_some());
    mail.into_iter()
        .map(tokio::spawn)
        .chain(provider_recovery.into_iter().map(tokio::spawn))
        .chain(managed_sync.into_iter().map(tokio::spawn))
        .chain(webhook_delivery.into_iter().map(tokio::spawn))
        .collect()
}

async fn drain_runtime_workers(workers: Vec<tokio::task::JoinHandle<()>>) {
    for worker in workers {
        let _ = worker.await;
    }
}

async fn run_mail_worker(service: Arc<RuntimeAuthService>, mut shutdown: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            _ = interval.tick() => {
                let mail_batch_started = tokio::time::Instant::now();
                for _ in 0..10 {
                    match service.run_mail_once().await {
                        Ok(true) => {}
                        Ok(false) => break,
                        Err(error) => {
                            tracing::warn!(event = "mail_worker_failed", error = ?error, "Runtime mail worker did not complete");
                            break;
                        }
                    }
                    if mail_batch_started.elapsed() >= RUNTIME_MAIL_BATCH_BUDGET {
                        break;
                    }
                }
            }
        }
    }
}

async fn run_provider_recovery_worker(
    service: Arc<RuntimeAuthService>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            _ = interval.tick() => {
                if service
                    .recover_abandoned_exchanges(time::Duration::minutes(2), 100)
                    .await
                    .is_err()
                {
                    tracing::warn!(
                        event = "provider_exchange_recovery_failed",
                        "Runtime provider-exchange recovery did not complete"
                    );
                }
            }
        }
    }
}

async fn run_managed_workers(
    managed: Arc<ManagedConnectionService>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            _ = interval.tick() => {
                if managed.cleanup_unreadable_interactions(256).await.is_err() {
                    tracing::warn!(
                        event = "managed_reauthorization_key_cleanup_failed",
                        "bounded unreadable managed-reauthorization cleanup did not complete"
                    );
                }
                let readiness = managed.refresh_key_readiness().await;
                if readiness.is_err() || !managed.managed_claims_ready() {
                    tracing::warn!(
                        event = "managed_sync_key_degraded",
                        "managed claims remain suppressed while credential keys are unreadable"
                    );
                    continue;
                }
                let worker_id = uuid::Uuid::new_v4();
                let provider_operation_lease = managed.provider_operation_lease();
                for _ in 0..16 {
                    let rewrap = managed
                        .rewrap_one(worker_id, provider_operation_lease)
                        .await;
                    let revocation = managed
                        .revoke_one(worker_id, provider_operation_lease)
                        .await;
                    let renewal = managed
                        .renew_one(worker_id, provider_operation_lease)
                        .await;
                    if matches!(rewrap, Ok(false))
                        && matches!(renewal, Ok(false))
                        && matches!(revocation, Ok(false))
                    {
                        break;
                    }
                    if rewrap.is_err() || renewal.is_err() || revocation.is_err() {
                        tracing::warn!(
                            event = "managed_provider_sync_failed",
                            "a bounded managed provider synchronization iteration failed"
                        );
                        break;
                    }
                }
            }
        }
    }
}

async fn run_webhook_worker(worker: Arc<WebhookWorker>, mut shutdown: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(Duration::from_millis(250));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            _ = interval.tick() => {
                let started = tokio::time::Instant::now();
                for _ in 0..16 {
                    match worker.run_once().await {
                        Ok(true) => {}
                        Ok(false) => break,
                        Err(error) => {
                            tracing::warn!(
                                event = "webhook_delivery_worker_failed",
                                error = ?error,
                                "a bounded webhook delivery attempt did not complete"
                            );
                            break;
                        }
                    }
                    if started.elapsed() >= Duration::from_secs(1) {
                        break;
                    }
                }
            }
        }
    }
}

fn spawn_selected(
    servers: &mut JoinSet<Result<(), std::io::Error>>,
    listener: Option<TcpListener>,
    router: Option<Router>,
    mut shutdown: watch::Receiver<bool>,
) {
    let (Some(listener), Some(router)) = (listener, router) else {
        return;
    };
    servers.spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            while !*shutdown.borrow() {
                if shutdown.changed().await.is_err() {
                    break;
                }
            }
        })
        .await
    });
}

#[cfg(unix)]
async fn shutdown_signal() -> Result<(), ServerError> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| ServerError::ShutdownSignal)?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result.map_err(|_| ServerError::ShutdownSignal),
        signal = terminate.recv() => signal.ok_or(ServerError::ShutdownSignal).map(drop),
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() -> Result<(), ServerError> {
    tokio::signal::ctrl_c()
        .await
        .map_err(|_| ServerError::ShutdownSignal)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use tokio::sync::Notify;

    use super::*;

    struct DropSignal(Arc<AtomicUsize>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn only_control_capable_reconciled_smtp_can_bootstrap_without_a_fingerprint() {
        assert!(allows_unsealed_deployment_smtp_bootstrap(
            PlaneMode::All,
            DeploymentSmtpStatus::Reconciled
        ));
        for mode in [PlaneMode::Runtime, PlaneMode::Control] {
            assert!(!allows_unsealed_deployment_smtp_bootstrap(
                mode,
                DeploymentSmtpStatus::Reconciled
            ));
        }
        for status in [
            DeploymentSmtpStatus::Active,
            DeploymentSmtpStatus::Disabled,
            DeploymentSmtpStatus::Compromised,
        ] {
            assert!(!allows_unsealed_deployment_smtp_bootstrap(
                PlaneMode::All,
                status
            ));
        }
    }

    #[test]
    fn control_only_never_runs_runtime_email_protection_reconciliation() {
        assert!(!should_reconcile_email_protection(PlaneMode::Control, true));
        assert!(!should_reconcile_email_protection(
            PlaneMode::Runtime,
            false
        ));
        assert!(should_reconcile_email_protection(PlaneMode::Runtime, true));
        assert!(should_reconcile_email_protection(PlaneMode::All, true));
    }

    #[test]
    fn runtime_worker_ownership_is_independent_across_optional_capabilities() {
        const { assert!(FEDERATED_PROJECT_AUTH_AVAILABLE) };
        assert_eq!(
            runtime_worker_selection(false, false, false),
            RuntimeWorkerSelection {
                mail: false,
                provider_recovery: false,
                managed_sync: false,
                webhook_delivery: false,
            }
        );
        assert_eq!(
            runtime_worker_selection(true, false, false),
            RuntimeWorkerSelection {
                mail: true,
                provider_recovery: true,
                managed_sync: false,
                webhook_delivery: false,
            }
        );
        assert_eq!(
            runtime_worker_selection(false, true, true),
            RuntimeWorkerSelection {
                mail: false,
                provider_recovery: false,
                managed_sync: true,
                webhook_delivery: true,
            }
        );
    }

    #[tokio::test]
    async fn runtime_worker_supervisor_isolates_progress_and_aborts_a_blocked_owner() {
        let (shutdown_sender, shutdown_receiver) = watch::channel(false);
        let started = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let mail_stopped = Arc::new(AtomicBool::new(false));
        let recovery_stopped = Arc::new(AtomicBool::new(false));
        let all_started = Arc::new(Notify::new());

        let worker = |mut shutdown: watch::Receiver<bool>, stopped: Arc<AtomicBool>| {
            let started = Arc::clone(&started);
            let dropped = Arc::clone(&dropped);
            let all_started = Arc::clone(&all_started);
            async move {
                let _drop_signal = DropSignal(dropped);
                if started.fetch_add(1, Ordering::SeqCst) + 1 == 3 {
                    all_started.notify_one();
                }
                while !*shutdown.borrow() {
                    if shutdown.changed().await.is_err() {
                        break;
                    }
                }
                stopped.store(true, Ordering::SeqCst);
            }
        };
        let managed_started = Arc::clone(&started);
        let managed_dropped = Arc::clone(&dropped);
        let managed_all_started = Arc::clone(&all_started);
        let workers = spawn_runtime_worker_tasks(
            runtime_worker_selection(true, true, false),
            Some(worker(shutdown_receiver.clone(), Arc::clone(&mail_stopped))),
            Some(worker(
                shutdown_receiver.clone(),
                Arc::clone(&recovery_stopped),
            )),
            Some(async move {
                let _drop_signal = DropSignal(managed_dropped);
                if managed_started.fetch_add(1, Ordering::SeqCst) + 1 == 3 {
                    managed_all_started.notify_one();
                }
                std::future::pending::<()>().await;
            }),
            None::<std::future::Ready<()>>,
        );
        assert_eq!(workers.len(), 3);
        tokio::time::timeout(Duration::from_secs(1), all_started.notified())
            .await
            .expect("all independently owned workers must start while managed work blocks");
        assert_eq!(started.load(Ordering::SeqCst), 3);

        let aborts = workers
            .iter()
            .map(tokio::task::JoinHandle::abort_handle)
            .collect::<Vec<_>>();
        shutdown_sender.send(true).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), drain_runtime_workers(workers))
                .await
                .is_err(),
            "the blocked managed owner must consume the shared drain deadline"
        );
        assert!(mail_stopped.load(Ordering::SeqCst));
        assert!(recovery_stopped.load(Ordering::SeqCst));
        for abort in aborts {
            abort.abort();
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            while dropped.load(Ordering::SeqCst) != 3 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("timeout abortion must drop every independently spawned worker future");
    }
}
