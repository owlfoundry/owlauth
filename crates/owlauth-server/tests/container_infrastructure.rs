use std::env;

use sqlx::postgres::PgPoolOptions;
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const POSTGRES_PORT: u16 = 5432;
const REDIS_PORT: u16 = 6379;

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

async fn start_redis() -> Option<ContainerAsync<GenericImage>> {
    match GenericImage::new("redis", "8-bookworm")
        .with_exposed_port(REDIS_PORT.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
        .start()
        .await
    {
        Ok(container) => Some(container),
        Err(error) => unavailable_or_fail("Redis", error),
    }
}

#[tokio::test]
async fn postgres_and_redis_containers_are_reachable() {
    let Some(postgres) = start_postgres().await else {
        return;
    };
    let Some(redis) = start_redis().await else {
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

    let redis_host = redis
        .get_host()
        .await
        .expect("Redis host should be available");
    let redis_port = redis
        .get_host_port_ipv4(REDIS_PORT)
        .await
        .expect("Redis mapped port should be available");
    let redis_host = redis_host.to_string();
    let mut stream = tokio::net::TcpStream::connect((redis_host.as_str(), redis_port))
        .await
        .expect("Redis should accept a TCP connection");
    stream
        .write_all(b"*1\r\n$4\r\nPING\r\n")
        .await
        .expect("Redis PING should be writable");
    let mut response = [0_u8; 7];
    stream
        .read_exact(&mut response)
        .await
        .expect("Redis PONG should be readable");
    assert_eq!(&response, b"+PONG\r\n");
}
