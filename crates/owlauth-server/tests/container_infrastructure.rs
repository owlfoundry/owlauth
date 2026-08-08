use std::env;

use sqlx::postgres::PgPoolOptions;
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
};
const POSTGRES_PORT: u16 = 5432;

fn docker_is_required() -> bool {
    env::var("OWLAUTH_REQUIRE_DOCKER").is_ok_and(|value| value == "1")
}

fn unavailable_or_fail<T>(dependency: &str, error: impl std::fmt::Display) -> Option<T> {
    assert!(
        !docker_is_required(),
        "{dependency} test container is required but failed to start: {error}"
    );

    eprintln!("skipping container infrastructure test: {dependency} unavailable: {error}");
    None
}

async fn start_postgres() -> Option<ContainerAsync<GenericImage>> {
    match GenericImage::new("postgres", "17-bookworm")
        .with_exposed_port(POSTGRES_PORT.tcp())
        .with_wait_for(WaitFor::message_on_stderr(
            "database system is ready to accept connections",
        ))
        .with_env_var("POSTGRES_DB", "owlauth_test")
        .with_env_var("POSTGRES_USER", "owlauth")
        .with_env_var("POSTGRES_PASSWORD", "owlauth_test")
        .start()
        .await
    {
        Ok(container) => Some(container),
        Err(error) => unavailable_or_fail("PostgreSQL", error),
    }
}

#[tokio::test]
async fn postgres_container_is_reachable() {
    let Some(postgres) = start_postgres().await else {
        return;
    };

    let postgres_host = postgres
        .get_host()
        .await
        .expect("PostgreSQL host should be available");
    let postgres_port = postgres
        .get_host_port_ipv4(POSTGRES_PORT)
        .await
        .expect("PostgreSQL mapped port should be available");
    let postgres_url =
        format!("postgres://owlauth:owlauth_test@{postgres_host}:{postgres_port}/owlauth_test");
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&postgres_url)
        .await
        .expect("PostgreSQL should accept a SQLx connection");
    let answer: i32 = sqlx::query_scalar("SELECT 42")
        .fetch_one(&pool)
        .await
        .expect("PostgreSQL should execute a query");
    assert_eq!(answer, 42);
    pool.close().await;
}
