mod http_capabilities;

use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use owlauth_key_provider::{ProviderFormatVersion, ProviderId};

use axum::{Router, serve::Listener};
use owlauth_types::FEDERATED_PROJECT_AUTH_AVAILABLE;
use sea_orm::{ConnectionTrait, DbBackend, Statement};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore, watch},
    task::JoinSet,
    time::timeout,
};
use uuid::Uuid;

use crate::{
    adapters::{
        custody::SoftwareCustodyProvider,
        migrations::{SchemaError, prepare_schema},
        postgres::{
            DatabasePools, create_pools, custody::ProtectedMaterialRepository,
            email::PostgresPasswordlessEmailRepository,
        },
        protected_runtime::PostgresProtectedRuntimeCustody,
    },
    application::{
        DeploymentSmtpDesiredStatus, DeploymentSmtpGeneration, DeploymentSmtpRegistry,
        ManagedConnectionService, RuntimeAuthService, SmtpCredentialResolver, SmtpTlsMode,
        WebhookWorker,
    },
    config::{DeploymentSmtpStatus, ListenerConfig, ProcessMode, ServerConfig},
    http::{PlaneRouters, build_routers_with_capabilities},
    providers::{ActiveProvider, ProviderRegistrations},
};

pub(crate) use http_capabilities::{
    ControlHttpCapabilities, HttpCapabilities, RuntimeHttpCapabilities, ServerHttpCapabilities,
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
    #[error("deployment SMTP generation did not reconcile exactly")]
    DeploymentSmtp,
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
/// In `all` mode the Auth and Control sockets both bind before either begins serving.
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
    tracing::info!(
        event = "server_starting",
        mode = ?config.mode,
        "OwlAuth startup began"
    );
    providers
        .validate_for_mode(config.mode)
        .map_err(|_| ServerError::ProviderComposition)?;
    let providers = Arc::new(providers);
    prepare_schema(&config.postgres)
        .await
        .map_err(|error| ServerError::Schema(error.into()))?;
    tracing::debug!(
        event = "startup_phase_completed",
        phase = "schema",
        "schema is ready"
    );
    let pools = create_pools(&config)
        .await
        .map_err(|_| ServerError::DatabasePools)?;
    tracing::debug!(
        event = "startup_phase_completed",
        phase = "database_pools",
        "serving pools are ready"
    );
    if let Err(error) = validate_provider_readiness(&config, &pools, &providers).await {
        pools.close().await;
        return Err(error);
    }
    tracing::debug!(
        event = "startup_phase_completed",
        phase = "provider_readiness",
        "provider capabilities are ready"
    );
    // Runtime workers use one ephemeral startup incarnation for lease ownership. It is never
    // registered as deployment topology and naturally becomes stale when its leases expire.
    let worker_incarnation = Uuid::new_v4();
    reconcile_deployment_smtp(&config, &pools, &providers)
        .await
        .map_err(|_| ServerError::DeploymentSmtp)?;
    tracing::debug!(
        event = "startup_phase_completed",
        phase = "deployment_smtp",
        "deployment SMTP authority is reconciled"
    );
    let capabilities = build_http_capabilities(
        &config,
        Some(&pools),
        worker_incarnation,
        providers.as_ref(),
    );
    let signing_lifecycle = capabilities
        .control
        .as_ref()
        .and_then(|control| control.provisioning.clone());
    let mut routers = build_routers_with_capabilities(&config, capabilities);
    tracing::debug!(
        event = "startup_phase_completed",
        phase = "http_composition",
        "plane routers and capabilities are composed"
    );
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

    let auth_listener = match bind_selected(config.mode.has_auth(), config.auth.bind).await {
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

    tracing::debug!(
        event = "startup_phase_completed",
        phase = "listener_bind",
        "selected listener sockets are bound"
    );
    let signing_lifecycle_maintenance = signing_lifecycle.map(spawn_signing_lifecycle_maintenance);

    routers.mark_ready();
    if config.mode.has_auth() {
        log_listener_ready("Auth", &config.auth, "auth/");
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
        PlaneListeners {
            auth: PlaneListener {
                socket: auth_listener,
                max_connections: config.auth.http.max_connections,
            },
            control: PlaneListener {
                socket: control_listener,
                max_connections: config.control.http.max_connections,
            },
        },
        config.shutdown_timeout,
    )
    .await;
    if let Some(maintenance) = signing_lifecycle_maintenance {
        maintenance.abort();
        let _ = maintenance.await;
    }
    pools.close().await;
    match &result {
        Ok(()) => tracing::info!(event = "server_stopped", "OwlAuth shutdown completed"),
        Err(error) => tracing::error!(
            event = "server_stopped",
            error = ?error,
            "OwlAuth stopped with an operational failure"
        ),
    }
    result
}

fn spawn_signing_lifecycle_maintenance(
    provisioning: Arc<crate::application::ProvisioningService>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match provisioning.reconcile_signing_key_lifecycle(100).await {
                Ok(progressed) if progressed > 0 => tracing::debug!(
                    event = "signing_key_lifecycle_reconciled",
                    progressed,
                    "signing key lifecycle maintenance made progress"
                ),
                Ok(_) => {}
                Err(error) => tracing::warn!(
                    event = "signing_key_lifecycle_reconciliation_pending",
                    error = ?error,
                    "signing key lifecycle reconciliation failed closed and will retry"
                ),
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
}

pub(crate) fn bundled_software_providers(
    config: &ServerConfig,
) -> Result<ProviderRegistrations, ServerError> {
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
    if config.mode.has_auth() {
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
    if !config.mode.has_control() && !config.mode.has_auth() {
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
    if !config.mode.has_auth() {
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

fn allows_unsealed_deployment_smtp_bootstrap(
    mode: ProcessMode,
    status: DeploymentSmtpStatus,
) -> bool {
    mode == ProcessMode::All && status == DeploymentSmtpStatus::Reconciled
}

async fn reconcile_deployment_smtp(
    config: &ServerConfig,
    pools: &DatabasePools,
    providers: &ProviderRegistrations,
) -> Result<(), crate::application::ApplicationError> {
    if !config.mode.has_auth() {
        return Ok(());
    }
    let database = pools
        .runtime
        .as_ref()
        .ok_or(crate::application::ApplicationError::Persistence)?;
    let registry = PostgresPasswordlessEmailRepository::new(database.clone());
    let Some(configured) = config.deployment_smtp.as_ref() else {
        return registry.assert_no_active_deployment_smtp().await;
    };
    let Some(safe_fingerprint) = configured.safe_fingerprint else {
        if allows_unsealed_deployment_smtp_bootstrap(config.mode, configured.status) {
            // Combined topology may bind Control once with non-active metadata so the ordinary
            // authenticated API can seal the first credential generation. Auth-only processes
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

struct PlaneListener {
    socket: Option<TcpListener>,
    max_connections: usize,
}

struct PlaneListeners {
    auth: PlaneListener,
    control: PlaneListener,
}

async fn serve_until_shutdown(
    routers: &mut PlaneRouters,
    listeners: PlaneListeners,
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
        listeners.auth.socket,
        routers.auth.take(),
        listeners.auth.max_connections,
        shutdown_receiver.clone(),
    );
    spawn_selected(
        &mut servers,
        listeners.control.socket,
        routers.control.take(),
        listeners.control.max_connections,
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
        "OwlAuth stopped accepting business requests"
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

struct ConnectionLimitedListener {
    listener: TcpListener,
    permits: Arc<Semaphore>,
}

struct ConnectionPermitStream {
    stream: TcpStream,
    _permit: OwnedSemaphorePermit,
}

impl ConnectionLimitedListener {
    fn new(listener: TcpListener, max_connections: usize) -> Self {
        Self {
            listener,
            permits: Arc::new(Semaphore::new(max_connections)),
        }
    }
}

impl Listener for ConnectionLimitedListener {
    type Io = ConnectionPermitStream;
    type Addr = std::net::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        let permit = Arc::clone(&self.permits)
            .acquire_owned()
            .await
            .expect("the listener connection semaphore remains open");
        let (stream, address) = Listener::accept(&mut self.listener).await;
        (
            ConnectionPermitStream {
                stream,
                _permit: permit,
            },
            address,
        )
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}

impl AsyncRead for ConnectionPermitStream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(context, buffer)
    }
}

impl AsyncWrite for ConnectionPermitStream {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_write(context, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(context)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(context)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_write_vectored(context, buffers)
    }
}

fn spawn_selected(
    servers: &mut JoinSet<Result<(), std::io::Error>>,
    listener: Option<TcpListener>,
    router: Option<Router>,
    max_connections: usize,
    mut shutdown: watch::Receiver<bool>,
) {
    let (Some(listener), Some(router)) = (listener, router) else {
        return;
    };
    servers.spawn(async move {
        axum::serve(
            ConnectionLimitedListener::new(listener, max_connections),
            router,
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
            ProcessMode::All,
            DeploymentSmtpStatus::Reconciled
        ));
        for mode in [ProcessMode::Auth, ProcessMode::Control] {
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
                ProcessMode::All,
                status
            ));
        }
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
    async fn connection_limit_holds_a_permit_for_the_transport_lifetime() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut listener = ConnectionLimitedListener::new(listener, 1);

        let first_client = TcpStream::connect(address).await.unwrap();
        let (first_connection, first_peer) = Listener::accept(&mut listener).await;
        assert_eq!(first_peer.ip(), first_client.local_addr().unwrap().ip());

        let _second_client = TcpStream::connect(address).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), Listener::accept(&mut listener))
                .await
                .is_err(),
            "a second connection must remain in the listen backlog while capacity is occupied"
        );

        drop(first_connection);
        tokio::time::timeout(Duration::from_secs(1), Listener::accept(&mut listener))
            .await
            .expect("dropping the accepted IO must release listener capacity");
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
