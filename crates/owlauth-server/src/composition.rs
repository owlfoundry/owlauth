use std::{sync::Arc, time::Duration};

use axum::Router;
use owlauth_types::FEDERATED_PROJECT_AUTH_AVAILABLE;
use thiserror::Error;
use tokio::{net::TcpListener, sync::watch, task::JoinSet, time::timeout};

use crate::{
    adapters::{migrations::prepare_schema, postgres::create_pools},
    application::RuntimeAuthService,
    config::ServerConfig,
    http::{PlaneRouters, build_routers},
};

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ServerError {
    #[error("PostgreSQL schema preparation failed")]
    Schema,
    #[error("PostgreSQL serving pools could not be prepared")]
    DatabasePools,
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
    let mut routers = build_routers(&config, Some(&pools));

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
    pools.close().await;
    result
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
    let recovery_worker = if should_spawn_provider_recovery(routers.runtime_auth.is_some()) {
        routers
            .runtime_auth
            .clone()
            .map(|service| tokio::spawn(run_runtime_recovery(service, shutdown_receiver.clone())))
    } else {
        None
    };
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

    let recovery_abort = recovery_worker
        .as_ref()
        .map(tokio::task::JoinHandle::abort_handle);
    let drained = timeout(shutdown_timeout, async {
        while servers.join_next().await.is_some() {}
        if let Some(worker) = recovery_worker {
            let _ = worker.await;
        }
    })
    .await;
    if drained.is_err() {
        servers.abort_all();
        if let Some(worker) = recovery_abort {
            worker.abort();
        }
        return Err(ServerError::ShutdownTimeout);
    }
    if unexpected_stop {
        return Err(ServerError::Serve);
    }
    Ok(())
}

const fn should_spawn_provider_recovery(runtime_auth_composed: bool) -> bool {
    FEDERATED_PROJECT_AUTH_AVAILABLE && runtime_auth_composed
}

async fn run_runtime_recovery(
    service: Arc<RuntimeAuthService>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
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

async fn shutdown_signal() -> Result<(), ServerError> {
    tokio::signal::ctrl_c()
        .await
        .map_err(|_| ServerError::ShutdownSignal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_recovery_runs_only_when_runtime_auth_is_composed() {
        const { assert!(FEDERATED_PROJECT_AUTH_AVAILABLE) };
        assert!(!should_spawn_provider_recovery(false));
        assert!(should_spawn_provider_recovery(true));
    }
}
