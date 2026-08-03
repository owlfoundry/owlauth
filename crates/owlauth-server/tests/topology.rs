use std::{
    env, fs,
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::Duration,
};

use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
};
use tokio::time::sleep;
use uuid::Uuid;

const POSTGRES_PORT: u16 = 5432;
const OPERATOR_KEY: &str = "owl_ctrl_v1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const DIGEST_KEY: &str = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM";
const ADMISSION_DIGEST_KEY: &str = "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU";
const PROTECTION_KEY: &str = "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ";
const MANAGED_REAUTHORIZATION_DIGEST_KEY: &str = "CgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgo";
const MANAGED_REAUTHORIZATION_PROTECTION_KEY: &str = "CwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCws";
const IDENTITY_MUTATION_EVIDENCE_DIGEST_KEY: &str = "EBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBA";
const IDENTITY_MUTATION_EVIDENCE_PROTECTION_KEY: &str =
    "ERERERERERERERERERERERERERERERERERERERERERE";
const PROJECTION_EMAIL_DIGEST_KEY: &str = "RkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkY";
const PROJECTION_EMAIL_PROTECTION_KEY: &str = "R0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0c";
const MANAGED_CREDENTIAL_KEY: &str = "BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgY";
const SIGNER_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
const SECRET_KEY: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI";

type Environment = Vec<(String, String)>;

fn docker_is_required() -> bool {
    env::var("OWLAUTH_REQUIRE_DOCKER").is_ok_and(|value| value == "1")
}

fn unavailable_or_fail<T>(error: impl std::fmt::Display) -> Option<T> {
    assert!(
        !docker_is_required(),
        "PostgreSQL topology test container is required but failed to start: {error}"
    );
    eprintln!("skipping topology test: Docker unavailable: {error}");
    None
}

async fn start_postgres() -> Option<ContainerAsync<GenericImage>> {
    match GenericImage::new("postgres", "17-bookworm")
        .with_exposed_port(POSTGRES_PORT.tcp())
        .with_wait_for(WaitFor::message_on_stderr(
            "database system is ready to accept connections",
        ))
        .with_env_var("POSTGRES_DB", "owlauth_topology")
        .with_env_var("POSTGRES_USER", "owlauth")
        .with_env_var("POSTGRES_PASSWORD", "owlauth_topology")
        .start()
        .await
    {
        Ok(container) => Some(container),
        Err(error) => unavailable_or_fail(error),
    }
}

struct TemporaryStores {
    root: PathBuf,
}

impl TemporaryStores {
    fn new() -> Self {
        let root = env::temp_dir().join(format!("owlauth-topology-{}", Uuid::new_v4()));
        fs::create_dir_all(root.join("signers")).expect("signer test directory should be created");
        fs::create_dir_all(root.join("secrets")).expect("secret test directory should be created");
        Self { root }
    }

    fn common_environment(&self, postgres_url: &str) -> Environment {
        vec![
            ("OWLAUTH_INSTANCE_ID".to_owned(), "topology-test".to_owned()),
            ("OWLAUTH_POSTGRES_URL".to_owned(), postgres_url.to_owned()),
            (
                "OWLAUTH_SIGNER_STORE_ROOT".to_owned(),
                self.root.join("signers").display().to_string(),
            ),
            ("OWLAUTH_SIGNER_STORE_KEY".to_owned(), SIGNER_KEY.to_owned()),
            (
                "OWLAUTH_CONFIGURATION_SECRET_STORE_ROOT".to_owned(),
                self.root.join("secrets").display().to_string(),
            ),
            (
                "OWLAUTH_CONFIGURATION_SECRET_STORE_KEY".to_owned(),
                SECRET_KEY.to_owned(),
            ),
            (
                "OWLAUTH_DATABASE_CONNECT_TIMEOUT_MS".to_owned(),
                "5000".to_owned(),
            ),
            ("OWLAUTH_SHUTDOWN_TIMEOUT_MS".to_owned(), "1000".to_owned()),
            (
                "OWLAUTH_MANAGED_REAUTHORIZATION_KEY_VERSION".to_owned(),
                "1".to_owned(),
            ),
            (
                "OWLAUTH_MANAGED_REAUTHORIZATION_DIGEST_KEY".to_owned(),
                MANAGED_REAUTHORIZATION_DIGEST_KEY.to_owned(),
            ),
            (
                "OWLAUTH_MANAGED_REAUTHORIZATION_PROTECTION_KEY".to_owned(),
                MANAGED_REAUTHORIZATION_PROTECTION_KEY.to_owned(),
            ),
            (
                "OWLAUTH_IDENTITY_MUTATION_EVIDENCE_KEY_VERSION".to_owned(),
                "1".to_owned(),
            ),
            (
                "OWLAUTH_IDENTITY_MUTATION_EVIDENCE_DIGEST_KEY".to_owned(),
                IDENTITY_MUTATION_EVIDENCE_DIGEST_KEY.to_owned(),
            ),
            (
                "OWLAUTH_IDENTITY_MUTATION_EVIDENCE_PROTECTION_KEY".to_owned(),
                IDENTITY_MUTATION_EVIDENCE_PROTECTION_KEY.to_owned(),
            ),
            (
                "OWLAUTH_PROJECTION_EMAIL_KEY_VERSION".to_owned(),
                "1".to_owned(),
            ),
            (
                "OWLAUTH_PROJECTION_EMAIL_DIGEST_KEY".to_owned(),
                PROJECTION_EMAIL_DIGEST_KEY.to_owned(),
            ),
            (
                "OWLAUTH_PROJECTION_EMAIL_PROTECTION_KEY".to_owned(),
                PROJECTION_EMAIL_PROTECTION_KEY.to_owned(),
            ),
        ]
    }
}

impl Drop for TemporaryStores {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct ServerProcess {
    child: Child,
}

impl ServerProcess {
    fn spawn(environment: &Environment) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_owlauth-server"));
        for (key, _) in
            env::vars_os().filter(|(key, _)| key.to_string_lossy().starts_with("OWLAUTH_"))
        {
            command.env_remove(key);
        }
        let child = command
            .envs(environment.iter().map(|(key, value)| (key, value)))
            .env("RUST_LOG", "error")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("OwlAuth topology process should start");
        Self { child }
    }

    fn terminate(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }

    async fn terminate_gracefully(&mut self) {
        if self.child.try_wait().ok().flatten().is_some() {
            return;
        }
        #[cfg(unix)]
        assert!(
            Command::new("kill")
                .args(["-TERM", &self.child.id().to_string()])
                .status()
                .is_ok_and(|status| status.success()),
            "OwlAuth topology process should accept SIGTERM"
        );
        #[cfg(not(unix))]
        self.child
            .kill()
            .expect("OwlAuth topology process should accept termination");
        for _ in 0..200 {
            if let Some(status) = self
                .child
                .try_wait()
                .expect("topology process status should be readable")
            {
                assert!(
                    status.success(),
                    "graceful shutdown should exit successfully"
                );
                return;
            }
            sleep(Duration::from_millis(25)).await;
        }
        panic!("OwlAuth topology process exceeded its graceful shutdown bound");
    }

    async fn wait_for_exit(&mut self) -> std::process::ExitStatus {
        for _ in 0..200 {
            if let Some(status) = self
                .child
                .try_wait()
                .expect("topology process status should be readable")
            {
                return status;
            }
            sleep(Duration::from_millis(25)).await;
        }
        panic!("OwlAuth topology process did not exit after invalid configuration");
    }
}

impl Drop for ServerProcess {
    fn drop(&mut self) {
        self.terminate();
    }
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback port should be allocated");
    listener
        .local_addr()
        .expect("loopback address should resolve")
        .port()
}

fn control_environment(common: &Environment, port: u16) -> Environment {
    let mut result = common.clone();
    result.extend([
        ("OWLAUTH_MODE".to_owned(), "control".to_owned()),
        (
            "OWLAUTH_CONTROL_ADDR".to_owned(),
            format!("127.0.0.1:{port}"),
        ),
        (
            "OWLAUTH_CONTROL_BASE_URL".to_owned(),
            format!("http://127.0.0.1:{port}/"),
        ),
        (
            "OWLAUTH_CONTROL_API_KEY".to_owned(),
            OPERATOR_KEY.to_owned(),
        ),
        (
            "OWLAUTH_REQUIRED_RUNTIME_PROCESS_IDS".to_owned(),
            "topology-runtime".to_owned(),
        ),
    ]);
    result
}

fn assert_control_key_custody(environment: &Environment) {
    assert!(
        environment
            .iter()
            .all(|(key, _)| !key.starts_with("OWLAUTH_RUNTIME_KEY_")
                && key != "OWLAUTH_RUNTIME_DIGEST_KEY"
                && key != "OWLAUTH_RUNTIME_PROTECTION_KEY"),
        "split Control receives no generic Runtime protection roots"
    );
    assert!(
        environment
            .iter()
            .any(|(key, _)| key == "OWLAUTH_MANAGED_REAUTHORIZATION_KEY_VERSION"),
        "split Control receives the purpose-limited target issuer"
    );
}

fn runtime_environment(common: &Environment, port: u16) -> Environment {
    let mut result = common.clone();
    result.extend([
        ("OWLAUTH_MODE".to_owned(), "runtime".to_owned()),
        ("OWLAUTH_RUNTIME_KEY_VERSION".to_owned(), "1".to_owned()),
        (
            "OWLAUTH_RUNTIME_DIGEST_KEY".to_owned(),
            DIGEST_KEY.to_owned(),
        ),
        (
            "OWLAUTH_RUNTIME_PROTECTION_KEY".to_owned(),
            PROTECTION_KEY.to_owned(),
        ),
        (
            "OWLAUTH_MANAGED_CREDENTIAL_KEY_VERSION".to_owned(),
            "1".to_owned(),
        ),
        (
            "OWLAUTH_MANAGED_CREDENTIAL_KEY".to_owned(),
            MANAGED_CREDENTIAL_KEY.to_owned(),
        ),
        (
            "OWLAUTH_RUNTIME_ADDR".to_owned(),
            format!("127.0.0.1:{port}"),
        ),
        (
            "OWLAUTH_RUNTIME_BASE_URL".to_owned(),
            format!("http://127.0.0.1:{port}/"),
        ),
        (
            "OWLAUTH_RUNTIME_PROCESS_ID".to_owned(),
            "topology-runtime".to_owned(),
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
            "OWLAUTH_ADMISSION_DIGEST_KEY".to_owned(),
            ADMISSION_DIGEST_KEY.to_owned(),
        ),
        (
            "OWLAUTH_PROVIDER_ALLOWED_ORIGINS".to_owned(),
            "https://accounts.example/".to_owned(),
        ),
    ]);
    result
}

fn combined_environment(common: &Environment, runtime_port: u16, control_port: u16) -> Environment {
    let mut result = runtime_environment(common, runtime_port);
    result.extend([
        ("OWLAUTH_MODE".to_owned(), "all".to_owned()),
        (
            "OWLAUTH_CONTROL_ADDR".to_owned(),
            format!("127.0.0.1:{control_port}"),
        ),
        (
            "OWLAUTH_CONTROL_BASE_URL".to_owned(),
            format!("http://127.0.0.1:{control_port}/"),
        ),
        (
            "OWLAUTH_CONTROL_API_KEY".to_owned(),
            OPERATOR_KEY.to_owned(),
        ),
    ]);
    result
}

async fn wait_for_ready(client: &Client, base: &str, process: &mut ServerProcess) {
    for _ in 0..1_200 {
        assert!(
            process
                .child
                .try_wait()
                .expect("topology process status should be readable")
                .is_none(),
            "OwlAuth topology process exited before readiness"
        );
        if client
            .get(format!("{base}ready"))
            .send()
            .await
            .is_ok_and(|response| response.status() == StatusCode::OK)
        {
            return;
        }
        sleep(Duration::from_millis(25)).await;
    }
    panic!("OwlAuth topology process did not become ready");
}

struct ProjectIdentity {
    id: String,
    public_id: String,
    metadata_revision: i64,
}

async fn create_project(client: &Client, control_base: &str, suffix: &str) -> ProjectIdentity {
    let response = client
        .post(format!("{control_base}v1/projects"))
        .bearer_auth(OPERATOR_KEY)
        .header("Idempotency-Key", format!("topology-{suffix}-project"))
        .header("Content-Type", "application/json")
        .body(
            serde_json::to_vec(&json!({
                "display_name": format!("Topology {suffix}"),
                "belongs_to": null
            }))
            .expect("project request should serialize"),
        )
        .send()
        .await
        .expect("Control project creation should respond");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response
        .bytes()
        .await
        .expect("project response body should be readable");
    let project = serde_json::from_slice::<Value>(&body).expect("project response should be JSON");
    ProjectIdentity {
        id: project["id"]
            .as_str()
            .expect("project response should contain id")
            .to_owned(),
        public_id: project["public_id"]
            .as_str()
            .expect("project response should contain public_id")
            .to_owned(),
        metadata_revision: project["metadata_revision"]
            .as_i64()
            .expect("project response should contain metadata_revision"),
    }
}

async fn provision_signing_key(
    client: &Client,
    control_base: &str,
    project: &ProjectIdentity,
    suffix: &str,
) {
    let response = client
        .post(format!(
            "{control_base}v1/projects/{}/signing-keys",
            project.id
        ))
        .bearer_auth(OPERATOR_KEY)
        .header("Idempotency-Key", format!("topology-{suffix}-signer"))
        .header("Content-Type", "application/json")
        .body(
            serde_json::to_vec(&json!({
                "expected_project_revision": project.metadata_revision
            }))
            .expect("signing-key request should serialize"),
        )
        .send()
        .await
        .expect("Control signing-key provisioning should respond");
    assert_eq!(response.status(), StatusCode::OK);
}

async fn assert_runtime_reads_project(client: &Client, runtime_base: &str, public_id: &str) {
    let response = client
        .get(format!(
            "{runtime_base}projects/{public_id}/.well-known/jwks.json"
        ))
        .send()
        .await
        .expect("Runtime JWKS should respond");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response
        .bytes()
        .await
        .expect("JWKS response body should be readable");
    assert_eq!(
        serde_json::from_slice::<Value>(&body).expect("JWKS response should be JSON")["keys"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
}

async fn assert_control_reads_project(client: &Client, control_base: &str, public_id: &str) {
    let response = client
        .get(format!("{control_base}v1/projects"))
        .bearer_auth(OPERATOR_KEY)
        .send()
        .await
        .expect("Control project list should respond");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response
        .bytes()
        .await
        .expect("project list body should be readable");
    let body = serde_json::from_slice::<Value>(&bytes).expect("project list should be JSON");
    assert!(body["items"].as_array().is_some_and(|items| {
        items
            .iter()
            .any(|project| project["public_id"] == public_id)
    }));
}

async fn create_secondary_database(postgres_url: &str) {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(postgres_url)
        .await
        .expect("PostgreSQL administration connection should open");
    sqlx::query("CREATE DATABASE owlauth_other")
        .execute(&pool)
        .await
        .expect("secondary topology database should be created");
    pool.close().await;
}

fn database_url(host: &str, port: u16, database: &str) -> String {
    format!("postgresql://owlauth:owlauth_topology@{host}:{port}/{database}")
}

#[tokio::test]
async fn combined_and_split_topologies_share_authority_and_isolate_plane_outages() {
    let Some(postgres) = start_postgres().await else {
        return;
    };
    let host = postgres
        .get_host()
        .await
        .expect("PostgreSQL host should be available")
        .to_string();
    let port = postgres
        .get_host_port_ipv4(POSTGRES_PORT)
        .await
        .expect("PostgreSQL port should be available");
    let primary_url = database_url(&host, port, "owlauth_topology");
    let stores = TemporaryStores::new();
    let common = stores.common_environment(&primary_url);
    let client = Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .expect("HTTP client should build");

    let combined_runtime_port = free_port();
    let combined_control_port = free_port();
    let combined_runtime_base = format!("http://127.0.0.1:{combined_runtime_port}/");
    let combined_control_base = format!("http://127.0.0.1:{combined_control_port}/");
    let mut combined = ServerProcess::spawn(&combined_environment(
        &common,
        combined_runtime_port,
        combined_control_port,
    ));
    wait_for_ready(&client, &combined_runtime_base, &mut combined).await;
    wait_for_ready(&client, &combined_control_base, &mut combined).await;
    let combined_project = create_project(&client, &combined_control_base, "combined").await;
    provision_signing_key(
        &client,
        &combined_control_base,
        &combined_project,
        "combined",
    )
    .await;
    assert_runtime_reads_project(&client, &combined_runtime_base, &combined_project.public_id)
        .await;
    combined.terminate_gracefully().await;

    let runtime_port = free_port();
    let control_port = free_port();
    let runtime_base = format!("http://127.0.0.1:{runtime_port}/");
    let control_base = format!("http://127.0.0.1:{control_port}/");
    let mut runtime = ServerProcess::spawn(&runtime_environment(&common, runtime_port));
    let control_configuration = control_environment(&common, control_port);
    assert_control_key_custody(&control_configuration);
    let mut control = ServerProcess::spawn(&control_configuration);
    wait_for_ready(&client, &runtime_base, &mut runtime).await;
    wait_for_ready(&client, &control_base, &mut control).await;
    let split_project = create_project(&client, &control_base, "split").await;
    provision_signing_key(&client, &control_base, &split_project, "split").await;
    assert_runtime_reads_project(&client, &runtime_base, &split_project.public_id).await;

    control.terminate();
    assert_runtime_reads_project(&client, &runtime_base, &split_project.public_id).await;

    let mut verify_control_configuration = control_configuration.clone();
    verify_control_configuration.push(("OWLAUTH_MIGRATION_MODE".to_owned(), "verify".to_owned()));
    let mut restarted_control = ServerProcess::spawn(&verify_control_configuration);
    wait_for_ready(&client, &control_base, &mut restarted_control).await;
    assert_control_reads_project(&client, &control_base, &split_project.public_id).await;
    runtime.terminate();
    assert_control_reads_project(&client, &control_base, &split_project.public_id).await;

    let mut verify_runtime_configuration = runtime_environment(&common, runtime_port);
    verify_runtime_configuration.push(("OWLAUTH_MIGRATION_MODE".to_owned(), "verify".to_owned()));
    let mut restarted_runtime = ServerProcess::spawn(&verify_runtime_configuration);
    wait_for_ready(&client, &runtime_base, &mut restarted_runtime).await;
    assert_runtime_reads_project(&client, &runtime_base, &split_project.public_id).await;
    restarted_runtime.terminate_gracefully().await;

    create_secondary_database(&primary_url).await;
    let secondary_url = database_url(&host, port, "owlauth_other");
    let secondary_common = stores.common_environment(&secondary_url);
    let secondary_control_port = free_port();
    let secondary_control_base = format!("http://127.0.0.1:{secondary_control_port}/");
    let mut secondary_control = ServerProcess::spawn(&control_environment(
        &secondary_common,
        secondary_control_port,
    ));
    wait_for_ready(&client, &secondary_control_base, &mut secondary_control).await;
    secondary_control.terminate();

    for override_key in [
        "OWLAUTH_RUNTIME_POSTGRES_URL",
        "OWLAUTH_CONTROL_POSTGRES_URL",
        "OWLAUTH_MIGRATION_POSTGRES_URL",
    ] {
        let mismatch_runtime_port = free_port();
        let mismatch_control_port = free_port();
        let mut mismatch_environment =
            combined_environment(&common, mismatch_runtime_port, mismatch_control_port);
        mismatch_environment.push((override_key.to_owned(), secondary_url.clone()));
        let mut mismatch = ServerProcess::spawn(&mismatch_environment);
        assert!(
            !mismatch.wait_for_exit().await.success(),
            "{override_key} must not select an independently migrated database"
        );
        TcpListener::bind(("127.0.0.1", mismatch_runtime_port))
            .expect("invalid database authority must fail before Runtime binds");
        TcpListener::bind(("127.0.0.1", mismatch_control_port))
            .expect("invalid database authority must fail before Control binds");
    }
}
