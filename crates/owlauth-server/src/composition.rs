use std::collections::BTreeMap;
use std::{future::Future, sync::Arc, time::Duration};

use axum::Router;
use owlauth_types::FEDERATED_PROJECT_AUTH_AVAILABLE;
use thiserror::Error;
use tokio::{net::TcpListener, sync::watch, task::JoinSet, time::timeout};
use uuid::Uuid;

use crate::{
    adapters::{
        migrations::prepare_schema,
        postgres::{
            DatabasePools, create_pools, email::PostgresPasswordlessEmailRepository,
            projection::PostgresProjectionEmailKeyAuthority,
        },
        runtime_security::{
            EncryptedFileProviderSecretResolver, RuntimeKeyMaterial,
            SoftwareProjectionVerifiedEmailProtector, SoftwareRuntimeProtector,
        },
        software_store::EncryptedFileStore,
    },
    application::{
        ConfigurationSecretStore, DeploymentSmtpDesiredStatus, DeploymentSmtpGeneration,
        DeploymentSmtpRegistry, ManagedConnectionService, ProjectionExpansionWorker,
        RuntimeAuthService, SmtpCredentialResolver, SmtpTlsMode, WebhookWorker,
    },
    config::{DeploymentSmtpStatus, PlaneMode, ServerConfig},
    http::{PlaneRouters, build_routers_with_runtime_incarnation},
};

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ServerError {
    #[error("PostgreSQL schema preparation failed")]
    Schema,
    #[error("PostgreSQL serving pools could not be prepared")]
    DatabasePools,
    #[error("Runtime process incarnation could not be claimed")]
    RuntimeIncarnation,
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
/// In `all` mode both sockets bind before either begins serving.
///
/// # Errors
///
/// Returns a bounded startup, serving, or shutdown failure without dependency details.
pub async fn run(config: ServerConfig) -> Result<(), ServerError> {
    prepare_schema(&config.postgres)
        .await
        .map_err(|_| ServerError::Schema)?;
    let pools = create_pools(&config)
        .await
        .map_err(|_| ServerError::DatabasePools)?;
    // One startup incarnation is claimed once, then shared by reconciliation and every Runtime
    // serving/claim path. No delayed startup phase may reclaim the stable process identity.
    let runtime_incarnation = Uuid::new_v4();
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
    reconcile_deployment_smtp(&config, &pools, runtime_incarnation)
        .await
        .map_err(|_| ServerError::DeploymentSmtp)?;
    let project_smtp_readiness =
        reconcile_project_smtp_readiness(&config, &pools, runtime_incarnation)
            .await
            .map_err(|_| ServerError::ProjectSmtpReadiness)?;
    let mut routers =
        build_routers_with_runtime_incarnation(&config, Some(&pools), runtime_incarnation);
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

    let runtime_listener = match bind_selected(config.mode.has_runtime(), config.runtime.bind).await
    {
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

    routers.mark_ready();
    tracing::info!(
        event = "server_ready",
        mode = ?config.mode,
        "selected OwlAuth listeners are ready"
    );

    let result = serve_until_shutdown(
        &mut routers,
        runtime_listener,
        control_listener,
        config.shutdown_timeout,
    )
    .await;
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
    SoftwareProjectionVerifiedEmailProtector::new(
        config
            .instance_id
            .clone()
            .ok_or(crate::application::ApplicationError::Integrity)?,
        protection.active_version,
        active,
        retained,
    )
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
    let authority = PostgresProjectionEmailKeyAuthority::new(database.clone());
    let protector = projection_email_protector(config)?;
    let lease = time::Duration::seconds(
        i64::try_from(
            config
                .publication_lease_ttl
                .as_secs()
                .max(5)
                .saturating_mul(2),
        )
        .map_err(|_| crate::application::ApplicationError::Integrity)?,
    );
    let retention = time::Duration::try_from(config.key_propagation_delay)
        .map_err(|_| crate::application::ApplicationError::Integrity)?;
    let cutover = config.projection_email_protection.cutover_version;
    let retirement = config.projection_email_protection.retire_version;
    let first = authority
        .reconcile(
            &config.required_runtime_process_ids,
            &protector,
            cutover,
            retirement,
            retention,
        )
        .await;
    if first.is_err() && cutover.is_none() && retirement.is_none() {
        first?;
    }
    authority
        .observe_runtime(
            &config.runtime_process_id,
            runtime_incarnation,
            &protector,
            lease,
        )
        .await?;
    let _ = authority
        .reconcile(
            &config.required_runtime_process_ids,
            &protector,
            cutover,
            retirement,
            retention,
        )
        .await;

    let process_id = config.runtime_process_id.clone();
    let required = config.required_runtime_process_ids.clone();
    Ok(Some(tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let result = async {
                authority
                    .observe_runtime(&process_id, runtime_incarnation, &protector, lease)
                    .await?;
                authority
                    .reconcile(&required, &protector, cutover, retirement, retention)
                    .await
            }
            .await;
            if result.is_err() {
                tracing::warn!(
                    event = "projection_email_key_reconciliation_pending",
                    "projection verified-email key lifecycle remains fail-closed and will retry"
                );
            }
        }
    })))
}

async fn reconcile_deployment_smtp(
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
        credential_ref: configured.credential_ref.clone(),
        safe_fingerprint: configured.safe_fingerprint,
        explicitly_allowed_private_ips: configured.explicitly_allowed_private_ips.clone(),
    };
    if config.mode.has_runtime()
        && matches!(
            configured.status,
            DeploymentSmtpStatus::Reconciled | DeploymentSmtpStatus::Active
        )
    {
        let provisioning = config
            .provisioning
            .as_ref()
            .ok_or(crate::application::ApplicationError::Integrity)?;
        let store = EncryptedFileStore::new(
            provisioning.configuration_secret_store_root.clone(),
            provisioning.configuration_secret_store_key.expose_copy(),
        )
        .map_err(|_| crate::application::ApplicationError::ExternalStore)?;
        store
            .ensure_readable(configured.credential_ref.clone())
            .await?;
        let resolver = EncryptedFileProviderSecretResolver::new(store.clone());
        let credential = resolver.resolve(&configured.credential_ref).await?;
        if store.request_fingerprint(credential.as_slice()) != configured.safe_fingerprint {
            return Err(crate::application::ApplicationError::Integrity);
        }
    }
    registry
        .reconcile_deployment_smtp(&generation, time::OffsetDateTime::now_utc())
        .await
}

async fn reconcile_project_smtp_readiness(
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
    let provisioning = config
        .provisioning
        .as_ref()
        .ok_or(crate::application::ApplicationError::Integrity)?;
    let store = EncryptedFileStore::new(
        provisioning.configuration_secret_store_root.clone(),
        provisioning.configuration_secret_store_key.expose_copy(),
    )
    .map_err(|_| crate::application::ApplicationError::ExternalStore)?;
    let resolver = EncryptedFileProviderSecretResolver::new(store.clone());
    let repository = PostgresPasswordlessEmailRepository::new_with_runtime_identity(
        database.clone(),
        config.runtime_process_id.clone(),
        runtime_incarnation,
        config.required_runtime_process_ids.clone(),
        lease_duration_from_config(config)?,
    );
    reconcile_project_smtp_readiness_restore(
        &repository,
        &resolver,
        &store,
        time::OffsetDateTime::now_utc(),
    )
    .await?;
    Ok(Some(tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            if let Err(error) = reconcile_project_smtp_readiness_batch(
                &repository,
                &resolver,
                &store,
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
    resolver: &EncryptedFileProviderSecretResolver,
    store: &EncryptedFileStore,
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
            store,
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
    resolver: &EncryptedFileProviderSecretResolver,
    store: &EncryptedFileStore,
    now: time::OffsetDateTime,
) -> Result<(), crate::application::ApplicationError> {
    reconcile_project_smtp_readiness_batch_before(repository, resolver, store, now, now)
        .await
        .map(|_| ())
}

async fn reconcile_project_smtp_readiness_batch_before(
    repository: &PostgresPasswordlessEmailRepository,
    resolver: &EncryptedFileProviderSecretResolver,
    store: &EncryptedFileStore,
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
        let readable = match resolver.resolve(&candidate.credential_ref).await {
            Ok(credential) => {
                store.request_fingerprint(credential.as_slice()) == candidate.safe_fingerprint
            }
            Err(_) => false,
        };
        repository
            .record_project_smtp_readiness(&candidate, readable, now)
            .await?;
        if readable {
            ready = ready.saturating_add(1);
        } else {
            unavailable = unavailable.saturating_add(1);
        }
    }
    tracing::info!(
        event = "project_smtp_readiness_reconciled",
        ready,
        unavailable,
        "bounded Project SMTP readiness inventory completed"
    );
    Ok(observed)
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
    control_listener: Option<TcpListener>,
    shutdown_timeout: Duration,
) -> Result<(), ServerError> {
    let (shutdown_sender, shutdown_receiver) = watch::channel(false);
    let selection = runtime_worker_selection(
        routers.runtime_auth.is_some(),
        routers.managed_sync.is_some(),
        routers.projection_expansion.is_some(),
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
            .projection_expansion
            .clone()
            .map(|worker| run_projection_expansion_worker(worker, shutdown_receiver.clone())),
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
    projection_expansion: bool,
    webhook_delivery: bool,
}

#[allow(
    clippy::fn_params_excessive_bools,
    reason = "the pure helper verifies independent optional worker inputs"
)]
const fn runtime_worker_selection(
    runtime_auth_composed: bool,
    managed_sync_composed: bool,
    projection_expansion_composed: bool,
    webhook_delivery_composed: bool,
) -> RuntimeWorkerSelection {
    RuntimeWorkerSelection {
        mail: runtime_auth_composed,
        provider_recovery: FEDERATED_PROJECT_AUTH_AVAILABLE && runtime_auth_composed,
        managed_sync: managed_sync_composed,
        projection_expansion: projection_expansion_composed,
        webhook_delivery: webhook_delivery_composed,
    }
}

fn spawn_runtime_worker_tasks<Mail, Recovery, Managed, Projection, Webhook>(
    selection: RuntimeWorkerSelection,
    mail: Option<Mail>,
    provider_recovery: Option<Recovery>,
    managed_sync: Option<Managed>,
    projection_expansion: Option<Projection>,
    webhook_delivery: Option<Webhook>,
) -> Vec<tokio::task::JoinHandle<()>>
where
    Mail: Future<Output = ()> + Send + 'static,
    Recovery: Future<Output = ()> + Send + 'static,
    Managed: Future<Output = ()> + Send + 'static,
    Projection: Future<Output = ()> + Send + 'static,
    Webhook: Future<Output = ()> + Send + 'static,
{
    assert_eq!(selection.mail, mail.is_some());
    assert_eq!(selection.provider_recovery, provider_recovery.is_some());
    assert_eq!(selection.managed_sync, managed_sync.is_some());
    assert_eq!(
        selection.projection_expansion,
        projection_expansion.is_some()
    );
    assert_eq!(selection.webhook_delivery, webhook_delivery.is_some());
    mail.into_iter()
        .map(tokio::spawn)
        .chain(provider_recovery.into_iter().map(tokio::spawn))
        .chain(managed_sync.into_iter().map(tokio::spawn))
        .chain(projection_expansion.into_iter().map(tokio::spawn))
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

async fn run_projection_expansion_worker(
    worker: Arc<ProjectionExpansionWorker>,
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
                let started = tokio::time::Instant::now();
                for _ in 0..4 {
                    match worker.run_once().await {
                        Ok(true) => {}
                        Ok(false) => break,
                        Err(error) => {
                            tracing::warn!(
                                event = "projection_expansion_worker_failed",
                                error = ?error,
                                "a bounded projection expansion batch did not complete"
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
            runtime_worker_selection(false, false, false, false),
            RuntimeWorkerSelection {
                mail: false,
                provider_recovery: false,
                managed_sync: false,
                projection_expansion: false,
                webhook_delivery: false,
            }
        );
        assert_eq!(
            runtime_worker_selection(true, false, false, false),
            RuntimeWorkerSelection {
                mail: true,
                provider_recovery: true,
                managed_sync: false,
                projection_expansion: false,
                webhook_delivery: false,
            }
        );
        assert_eq!(
            runtime_worker_selection(false, true, true, true),
            RuntimeWorkerSelection {
                mail: false,
                provider_recovery: false,
                managed_sync: true,
                projection_expansion: true,
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
            runtime_worker_selection(true, true, false, false),
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
