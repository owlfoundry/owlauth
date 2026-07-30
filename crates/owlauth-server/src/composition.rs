use std::time::Duration;

use axum::Router;
use thiserror::Error;
use tokio::{net::TcpListener, sync::watch, task::JoinSet, time::timeout};

use crate::{
    adapters::{migrations::prepare_schema, postgres::create_pools},
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

    let drained = timeout(shutdown_timeout, async {
        while servers.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        servers.abort_all();
        return Err(ServerError::ShutdownTimeout);
    }
    if unexpected_stop {
        return Err(ServerError::Serve);
    }
    Ok(())
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
        axum::serve(listener, router)
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
