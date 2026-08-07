use std::{
    collections::{BTreeMap, BTreeSet},
    env, fmt,
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
    path::PathBuf,
    str::FromStr,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use owlauth_types::FEDERATED_PROJECT_AUTH_AVAILABLE;
use serde::{
    Deserialize,
    de::{Error as _, MapAccess, Visitor},
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

use crate::domain::{CanonicalEmail, MAX_ACCESS_TOKEN_LIFETIME_SECONDS};

const CONTROL_KEY_PREFIX: &str = "owl_ctrl_v1_";
const CONTROL_KEY_SECRET_LENGTH: usize = 43;
const MAX_PUBLICATION_LEASE_TTL: Duration = Duration::from_millis(43_200_999);
const MAX_KEY_PROPAGATION_DELAY: Duration = Duration::from_hours(24);
const MAX_SIGNING_VERIFICATION_RETENTION: Duration = Duration::from_hours(24);
const MAX_AUTH_PROCESSES: usize = 64;
const MIN_DATABASE_LOCK_TIMEOUT: Duration = Duration::from_millis(10);
const MAX_DATABASE_LOCK_TIMEOUT: Duration = Duration::from_mins(1);
const MIN_MIGRATION_LOCK_TIMEOUT: Duration = Duration::from_millis(10);
const MAX_MIGRATION_LOCK_TIMEOUT: Duration = Duration::from_mins(5);
const MIN_MIGRATION_STATEMENT_TIMEOUT: Duration = Duration::from_millis(100);
const MAX_MIGRATION_STATEMENT_TIMEOUT: Duration = Duration::from_hours(1);
const MIN_MIGRATION_DEADLINE: Duration = Duration::from_secs(1);
const MAX_MIGRATION_DEADLINE: Duration = Duration::from_hours(24);

const KNOWN_ENVIRONMENT_KEYS: &[&str] = &[
    "OWLAUTH_MODE",
    "OWLAUTH_INSTANCE_ID",
    "OWLAUTH_AUTH_ADDR",
    "OWLAUTH_AUTH_BASE_URL",
    "OWLAUTH_CONTROL_ADDR",
    "OWLAUTH_CONTROL_BASE_URL",
    "OWLAUTH_CONTROL_API_KEY",
    "OWLAUTH_SERVER_KEY_DIGEST_KEY_VERSION",
    "OWLAUTH_SERVER_KEY_DIGEST_KEY",
    "OWLAUTH_SERVER_KEY_DIGEST_RETAINED_KEYS",
    "OWLAUTH_AUTH_PROCESS_ID",
    "OWLAUTH_REQUIRED_AUTH_PROCESS_IDS",
    "OWLAUTH_SERVER_DIGEST_READINESS_LEASE_TTL_MS",
    "OWLAUTH_CONTROL_MCP_ENABLED",
    "OWLAUTH_CONTROL_MCP_MAX_REQUEST_BYTES",
    "OWLAUTH_CONTROL_MCP_REQUEST_TIMEOUT_MS",
    "OWLAUTH_CONTROL_MCP_MAX_CONCURRENT_REQUESTS",
    "OWLAUTH_CONTROL_MCP_MAX_REQUESTS_PER_SECOND",
    "OWLAUTH_CONTROL_MCP_MAX_RESULT_BYTES",
    "OWLAUTH_SOFTWARE_CUSTODY_KEY",
    "OWLAUTH_RUNTIME_KEY_VERSION",
    "OWLAUTH_RUNTIME_DIGEST_KEY",
    "OWLAUTH_RUNTIME_PROTECTION_KEY",
    "OWLAUTH_RUNTIME_RETAINED_KEYS",
    "OWLAUTH_EMAIL_IDENTITY_KEY_VERSION",
    "OWLAUTH_EMAIL_IDENTITY_DIGEST_KEY",
    "OWLAUTH_EMAIL_IDENTITY_PROTECTION_KEY",
    "OWLAUTH_EMAIL_IDENTITY_RETAINED_KEYS",
    "OWLAUTH_EMAIL_IDENTITY_ALIAS_CUTOVER_VERSION",
    "OWLAUTH_EMAIL_IDENTITY_ALIAS_RETIRE_VERSION",
    "OWLAUTH_PROJECTION_EMAIL_KEY_VERSION",
    "OWLAUTH_PROJECTION_EMAIL_PROTECTION_KEY",
    "OWLAUTH_PROJECTION_EMAIL_RETAINED_KEYS",
    "OWLAUTH_PROJECTION_EMAIL_CUTOVER_VERSION",
    "OWLAUTH_PROJECTION_EMAIL_RETIRE_VERSION",
    "OWLAUTH_SMTP_EXTRA_ROOT_CERT_DER_FILE",
    "OWLAUTH_WEBHOOK_EXTRA_ROOT_CERT_DER_FILE",
    "OWLAUTH_MANAGED_REAUTHORIZATION_KEY_VERSION",
    "OWLAUTH_MANAGED_REAUTHORIZATION_DIGEST_KEY",
    "OWLAUTH_MANAGED_REAUTHORIZATION_PROTECTION_KEY",
    "OWLAUTH_MANAGED_REAUTHORIZATION_RETAINED_KEYS",
    "OWLAUTH_IDENTITY_MUTATION_EVIDENCE_KEY_VERSION",
    "OWLAUTH_IDENTITY_MUTATION_EVIDENCE_DIGEST_KEY",
    "OWLAUTH_IDENTITY_MUTATION_EVIDENCE_PROTECTION_KEY",
    "OWLAUTH_IDENTITY_MUTATION_EVIDENCE_RETAINED_KEYS",
    "OWLAUTH_MANAGED_CREDENTIAL_KEY_VERSION",
    "OWLAUTH_MANAGED_CREDENTIAL_KEY",
    "OWLAUTH_MANAGED_CREDENTIAL_RETAINED_KEYS",
    "OWLAUTH_PROVIDER_ALLOW_HTTP_LOOPBACK",
    "OWLAUTH_ADMISSION_REDIS_URL",
    "OWLAUTH_ADMISSION_DIGEST_KEY",
    "OWLAUTH_ADMISSION_NAMESPACE",
    "OWLAUTH_ADMISSION_REDIS_TIMEOUT_MS",
    "OWLAUTH_AUTH_MAX_PROCESSES",
    "OWLAUTH_REQUIRED_AUTH_PROCESS_IDS",
    "OWLAUTH_DEPLOYMENT_SMTP_GENERATION",
    "OWLAUTH_DEPLOYMENT_SMTP_STATUS",
    "OWLAUTH_DEPLOYMENT_SMTP_HOST",
    "OWLAUTH_DEPLOYMENT_SMTP_PORT",
    "OWLAUTH_DEPLOYMENT_SMTP_TLS_MODE",
    "OWLAUTH_DEPLOYMENT_SMTP_SENDER_ADDRESS",
    "OWLAUTH_DEPLOYMENT_SMTP_SAFE_FINGERPRINT",
    "OWLAUTH_DEPLOYMENT_SMTP_ALLOWED_PRIVATE_IPS",
    "OWLAUTH_WEBHOOK_ALLOWED_PRIVATE_IPS",
    "OWLAUTH_PUBLICATION_LEASE_TTL_MS",
    "OWLAUTH_KEY_PROPAGATION_DELAY_MS",
    "OWLAUTH_SIGNING_VERIFICATION_RETENTION_MS",
    "OWLAUTH_POSTGRES_URL",
    "OWLAUTH_RUNTIME_POSTGRES_URL",
    "OWLAUTH_SERVER_POSTGRES_URL",
    "OWLAUTH_CONTROL_POSTGRES_URL",
    "OWLAUTH_MIGRATION_POSTGRES_URL",
    "OWLAUTH_MIGRATION_MODE",
    "OWLAUTH_MIGRATION_OWNER_ROLE",
    "OWLAUTH_DATABASE_CONNECT_TIMEOUT_MS",
    "OWLAUTH_DATABASE_LOCK_TIMEOUT_MS",
    "OWLAUTH_MIGRATION_LOCK_TIMEOUT_MS",
    "OWLAUTH_MIGRATION_STATEMENT_TIMEOUT_MS",
    "OWLAUTH_MIGRATION_DEADLINE_MS",
    "OWLAUTH_RUNTIME_DATABASE_MAX_CONNECTIONS",
    "OWLAUTH_SERVER_DATABASE_MAX_CONNECTIONS",
    "OWLAUTH_CONTROL_DATABASE_MAX_CONNECTIONS",
    "OWLAUTH_AUTH_REQUEST_TIMEOUT_MS",
    "OWLAUTH_AUTH_MAX_REQUEST_BYTES",
    "OWLAUTH_AUTH_MAX_IN_FLIGHT_REQUESTS",
    "OWLAUTH_AUTH_MAX_CONNECTIONS",
    "OWLAUTH_AUTH_MAX_HEADER_COUNT",
    "OWLAUTH_AUTH_MAX_HEADER_BYTES",
    "OWLAUTH_AUTH_MAX_URI_BYTES",
    "OWLAUTH_CONTROL_REQUEST_TIMEOUT_MS",
    "OWLAUTH_CONTROL_MAX_REQUEST_BYTES",
    "OWLAUTH_CONTROL_MAX_IN_FLIGHT_REQUESTS",
    "OWLAUTH_CONTROL_MAX_CONNECTIONS",
    "OWLAUTH_CONTROL_MAX_HEADER_COUNT",
    "OWLAUTH_CONTROL_MAX_HEADER_BYTES",
    "OWLAUTH_CONTROL_MAX_URI_BYTES",
    "OWLAUTH_SHUTDOWN_TIMEOUT_MS",
];

/// Process composition mode.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ProcessMode {
    /// Compose both the Auth and Control endpoints.
    All,
    /// Compose the Auth endpoint, including its isolated Runtime and Server API surfaces.
    #[default]
    Auth,
    /// Compose only the Control endpoint.
    Control,
}

impl ProcessMode {
    #[must_use]
    pub const fn has_auth(self) -> bool {
        matches!(self, Self::All | Self::Auth)
    }

    #[must_use]
    pub const fn has_control(self) -> bool {
        matches!(self, Self::All | Self::Control)
    }
}

impl FromStr for ProcessMode {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "all" => Ok(Self::All),
            "auth" => Ok(Self::Auth),
            "control" => Ok(Self::Control),
            _ => Err(ConfigError::InvalidValue {
                key: "OWLAUTH_MODE",
                reason: "must be `all`, `auth`, or `control`".to_owned(),
            }),
        }
    }
}

/// Startup migration behavior.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MigrationMode {
    /// Apply this binary's exact pending migrations before serving.
    #[default]
    Auto,
    /// Perform a DDL-free exact history check.
    Verify,
}

impl FromStr for MigrationMode {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "auto" => Ok(Self::Auto),
            "verify" => Ok(Self::Verify),
            _ => Err(ConfigError::InvalidValue {
                key: "OWLAUTH_MIGRATION_MODE",
                reason: "must be `auto` or `verify`".to_owned(),
            }),
        }
    }
}

/// Immutable secret text whose debug output is always redacted.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretString(String);

impl SecretString {
    fn new(value: String) -> Self {
        Self(value)
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString([REDACTED])")
    }
}

/// Canonical deployment operator API key.
#[derive(Clone, Eq, PartialEq)]
pub struct OperatorApiKey(SecretString);

impl OperatorApiKey {
    fn parse(value: String) -> Result<Self, ConfigError> {
        let expected_length = CONTROL_KEY_PREFIX.len() + CONTROL_KEY_SECRET_LENGTH;
        let valid = value.len() == expected_length
            && value.starts_with(CONTROL_KEY_PREFIX)
            && value[CONTROL_KEY_PREFIX.len()..]
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'));
        if !valid {
            return Err(ConfigError::InvalidValue {
                key: "OWLAUTH_CONTROL_API_KEY",
                reason: "must be `owl_ctrl_v1_` followed by 43 unpadded base64url characters"
                    .to_owned(),
            });
        }
        Ok(Self(SecretString::new(value)))
    }

    pub(crate) fn matches(&self, candidate: &[u8]) -> bool {
        let expected = self.0.expose().as_bytes();
        expected.len() == candidate.len() && bool::from(expected.ct_eq(candidate))
    }
}

impl fmt::Debug for OperatorApiKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OperatorApiKey([REDACTED])")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpBudgetConfig {
    pub request_timeout: Duration,
    pub max_request_bytes: usize,
    pub max_in_flight_requests: usize,
    pub max_connections: usize,
    pub max_header_count: usize,
    pub max_header_bytes: usize,
    pub max_uri_bytes: usize,
}

#[derive(Clone, Debug)]
pub struct ListenerConfig {
    pub bind: SocketAddr,
    pub external_base: Url,
    pub http: HttpBudgetConfig,
}

/// Bounded, explicitly enabled remote Streamable HTTP MCP configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpHttpConfig {
    pub enabled: bool,
    pub max_request_bytes: usize,
    pub request_timeout: Duration,
    pub max_concurrent_requests: usize,
    pub max_requests_per_second: usize,
    pub max_result_bytes: usize,
}

#[derive(Clone, Debug)]
pub struct PostgresConfig {
    pub serving_url: SecretString,
    pub runtime_url: SecretString,
    pub server_url: SecretString,
    pub control_url: SecretString,
    pub migration_url: SecretString,
    pub migration_mode: MigrationMode,
    pub migration_owner_role: Option<String>,
    pub connect_timeout: Duration,
    pub database_lock_timeout: Duration,
    pub migration_lock_timeout: Duration,
    pub migration_statement_timeout: Duration,
    pub migration_deadline: Duration,
}

#[derive(Clone)]
pub struct StoreMasterKey(Zeroizing<[u8; 32]>);

impl StoreMasterKey {
    fn parse(key: &'static str, value: String) -> Result<Self, ConfigError> {
        let decoded = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| ConfigError::InvalidValue {
                key,
                reason: "must be exactly 32 bytes encoded as unpadded base64url".to_owned(),
            })?;
        let bytes: [u8; 32] = decoded.try_into().map_err(|_| ConfigError::InvalidValue {
            key,
            reason: "must be exactly 32 bytes encoded as unpadded base64url".to_owned(),
        })?;
        Ok(Self(Zeroizing::new(bytes)))
    }

    pub(crate) fn expose_copy(&self) -> [u8; 32] {
        *self.0
    }
}

impl fmt::Debug for StoreMasterKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StoreMasterKey([REDACTED])")
    }
}

#[derive(Clone, Debug)]
pub struct ProvisioningConfig {
    pub software_custody_key: Option<StoreMasterKey>,
}

#[derive(Clone, Debug)]
pub struct RuntimeKeyConfig {
    pub digest_key: StoreMasterKey,
    pub protection_key: StoreMasterKey,
}

#[derive(Clone, Debug)]
pub struct RuntimeProtectionConfig {
    pub active_version: i32,
    pub active: RuntimeKeyConfig,
    pub retained: BTreeMap<i32, RuntimeKeyConfig>,
}

#[derive(Clone, Debug)]
pub struct EmailIdentityProtectionConfig {
    pub active_version: i32,
    pub identity_alias_cutover_version: Option<i32>,
    pub identity_alias_retire_version: Option<i32>,
    pub active: RuntimeKeyConfig,
    pub retained: BTreeMap<i32, RuntimeKeyConfig>,
}

#[derive(Clone, Debug)]
pub struct ProjectionEmailProtectionConfig {
    pub active_version: i32,
    pub cutover_version: Option<i32>,
    pub retire_version: Option<i32>,
    pub active_key: StoreMasterKey,
    pub retained: BTreeMap<i32, StoreMasterKey>,
}

#[derive(Clone, Debug)]
pub struct ManagedCredentialProtectionConfig {
    pub active_version: i32,
    pub active_key: StoreMasterKey,
    pub retained: BTreeMap<i32, StoreMasterKey>,
}

#[derive(Clone, Debug)]
pub struct ServerKeyDigestConfig {
    pub active_version: i32,
    pub active_key: StoreMasterKey,
    pub retained: BTreeMap<i32, StoreMasterKey>,
}

#[derive(Clone, Debug)]
pub struct AdmissionConfig {
    pub redis_url: Option<SecretString>,
    pub digest_key: StoreMasterKey,
    pub namespace: String,
    pub redis_timeout: Duration,
    pub auth_maximum_processes: Option<NonZeroU32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeploymentSmtpStatus {
    Reconciled,
    Active,
    Disabled,
    Compromised,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeploymentSmtpConfig {
    pub generation: i32,
    pub status: DeploymentSmtpStatus,
    pub host: String,
    pub port: u16,
    pub tls_mode: String,
    pub sender_address: String,
    pub safe_fingerprint: Option<[u8; 32]>,
    pub explicitly_allowed_private_ips: Vec<IpAddr>,
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub mode: ProcessMode,
    pub instance_id: Option<String>,
    pub auth: ListenerConfig,
    pub control: ListenerConfig,
    pub runtime_database_max_connections: NonZeroU32,
    pub server_database_max_connections: NonZeroU32,
    pub control_database_max_connections: NonZeroU32,
    pub control_api_key: Option<OperatorApiKey>,
    pub control_mcp: McpHttpConfig,
    pub provisioning: Option<ProvisioningConfig>,
    pub runtime_protection: Option<RuntimeProtectionConfig>,
    pub email_identity_protection: Option<EmailIdentityProtectionConfig>,
    pub projection_email_protection: ProjectionEmailProtectionConfig,
    pub smtp_extra_root_cert_der: Option<Vec<u8>>,
    pub webhook_extra_root_cert_der: Option<Vec<u8>>,
    pub managed_reauthorization_target_protection: RuntimeProtectionConfig,
    /// Dedicated cross-plane candidate-evidence ring. Both planes receive only narrow facades;
    /// Control never loads the generic Runtime protection ring.
    pub identity_mutation_evidence_protection: RuntimeProtectionConfig,
    pub managed_credential_protection: Option<ManagedCredentialProtectionConfig>,
    pub server_key_digest: Option<ServerKeyDigestConfig>,
    pub provider_allow_http_loopback: bool,
    pub auth_process_id: String,
    pub required_auth_process_ids: Vec<String>,
    pub server_digest_readiness_lease_ttl: Duration,
    pub admission: Option<AdmissionConfig>,
    pub deployment_smtp: Option<DeploymentSmtpConfig>,
    pub webhook_allowed_private_ips: Vec<IpAddr>,
    pub publication_lease_ttl: Duration,
    pub key_propagation_delay: Duration,
    pub signing_verification_retention: Duration,
    pub postgres: PostgresConfig,
    pub shutdown_timeout: Duration,
}

impl ServerConfig {
    /// Reads and validates the complete `OwlAuth` environment configuration.
    ///
    /// Unknown `OWLAUTH_*` variables are rejected. Auth-only mode loads the configured
    /// `PostgreSQL` custody provider authority required for Project authentication, but deliberately
    /// does not load the Control operator credential.
    ///
    /// # Errors
    ///
    /// Returns a bounded configuration error before any listener is bound.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_env_with_requirements(true)
    }

    /// Reads the core server environment without requiring the bundled software custody root.
    ///
    /// Custom binaries use this parser, parse their own bounded vendor configuration separately,
    /// and pass statically linked capabilities to `run_with_providers`.
    ///
    /// # Errors
    ///
    /// Returns a bounded core configuration error before any listener is bound.
    pub fn from_env_for_custom_providers() -> Result<Self, ConfigError> {
        Self::from_env_with_requirements(false)
    }

    fn from_env_with_requirements(require_software_custody: bool) -> Result<Self, ConfigError> {
        let mut values = BTreeMap::new();
        for (key, value) in env::vars_os() {
            let Some(key) = key.to_str() else {
                continue;
            };
            if !key.starts_with("OWLAUTH_") {
                continue;
            }
            let value = value.into_string().map_err(|_| ConfigError::InvalidValue {
                key: "environment",
                reason: format!("{key} is not valid UTF-8"),
            })?;
            values.insert(key.to_owned(), value);
        }
        Self::from_values_with_requirements(&values, require_software_custody)
    }

    #[cfg(test)]
    pub(crate) fn from_values_for_test(
        values: &BTreeMap<String, String>,
    ) -> Result<Self, ConfigError> {
        Self::from_values(values)
    }

    #[cfg(test)]
    fn from_values(values: &BTreeMap<String, String>) -> Result<Self, ConfigError> {
        Self::from_values_with_requirements(values, true)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one linear parser preserves strict whole-environment validation"
    )]
    fn from_values_with_requirements(
        values: &BTreeMap<String, String>,
        require_software_custody: bool,
    ) -> Result<Self, ConfigError> {
        reject_unknown_keys(values)?;

        let mode = optional(values, "OWLAUTH_MODE").unwrap_or("auth").parse()?;
        let auth = ListenerConfig {
            bind: parse_value(
                values,
                "OWLAUTH_AUTH_ADDR",
                "127.0.0.1:8080",
                "must be an IP socket address",
            )?,
            external_base: parse_external_base(
                "OWLAUTH_AUTH_BASE_URL",
                optional(values, "OWLAUTH_AUTH_BASE_URL").unwrap_or("http://127.0.0.1:8080/"),
            )?,
            http: parse_http_budget(values, HttpBudgetPlane::Auth)?,
        };
        let control = ListenerConfig {
            bind: parse_value(
                values,
                "OWLAUTH_CONTROL_ADDR",
                "127.0.0.1:8081",
                "must be an IP socket address",
            )?,
            external_base: parse_external_base(
                "OWLAUTH_CONTROL_BASE_URL",
                optional(values, "OWLAUTH_CONTROL_BASE_URL").unwrap_or("http://127.0.0.1:8081/"),
            )?,
            http: parse_http_budget(values, HttpBudgetPlane::Control)?,
        };
        let runtime_database_max_connections =
            parse_nonzero_u32(values, "OWLAUTH_RUNTIME_DATABASE_MAX_CONNECTIONS", 20)?;
        let server_database_max_connections =
            parse_nonzero_u32(values, "OWLAUTH_SERVER_DATABASE_MAX_CONNECTIONS", 10)?;
        let control_database_max_connections =
            parse_nonzero_u32(values, "OWLAUTH_CONTROL_DATABASE_MAX_CONNECTIONS", 5)?;
        validate_external_bases(&auth.external_base, &control.external_base)?;

        let (instance_id, control_api_key) = parse_control_identity(mode, values)?;
        let control_mcp = parse_control_mcp(mode, values)?;
        validate_control_mcp_listener(&control_mcp, &control)?;
        let provisioning = parse_provisioning(mode, values, require_software_custody)?;
        let runtime_protection = parse_runtime_protection(mode, values)?;
        let email_identity_protection = parse_email_identity_protection(mode, values)?;
        let projection_email_protection = parse_projection_email_protection(values)?;
        let smtp_extra_root_cert_der = if mode.has_auth() {
            optional(values, "OWLAUTH_SMTP_EXTRA_ROOT_CERT_DER_FILE")
                .map(PathBuf::from)
                .map(|path| {
                    if !path.is_absolute() {
                        return Err(ConfigError::InvalidValue {
                            key: "OWLAUTH_SMTP_EXTRA_ROOT_CERT_DER_FILE",
                            reason: "must be an absolute path to one DER certificate".to_owned(),
                        });
                    }
                    let bytes = std::fs::read(path).map_err(|_| ConfigError::InvalidValue {
                        key: "OWLAUTH_SMTP_EXTRA_ROOT_CERT_DER_FILE",
                        reason: "must be a readable DER certificate".to_owned(),
                    })?;
                    if bytes.is_empty() || bytes.len() > 65_536 {
                        return Err(ConfigError::InvalidValue {
                            key: "OWLAUTH_SMTP_EXTRA_ROOT_CERT_DER_FILE",
                            reason: "must contain one bounded DER certificate".to_owned(),
                        });
                    }
                    let mut roots = rustls::RootCertStore::empty();
                    roots
                        .add(rustls::pki_types::CertificateDer::from(bytes.clone()))
                        .map_err(|_| ConfigError::InvalidValue {
                            key: "OWLAUTH_SMTP_EXTRA_ROOT_CERT_DER_FILE",
                            reason: "must contain one valid DER trust anchor".to_owned(),
                        })?;
                    Ok(bytes)
                })
                .transpose()?
        } else {
            None
        };
        let webhook_extra_root_cert_der = if mode.has_auth() {
            optional(values, "OWLAUTH_WEBHOOK_EXTRA_ROOT_CERT_DER_FILE")
                .map(PathBuf::from)
                .map(|path| {
                    if !path.is_absolute() {
                        return Err(ConfigError::InvalidValue {
                            key: "OWLAUTH_WEBHOOK_EXTRA_ROOT_CERT_DER_FILE",
                            reason: "must be an absolute path to one DER certificate".to_owned(),
                        });
                    }
                    let bytes = std::fs::read(path).map_err(|_| ConfigError::InvalidValue {
                        key: "OWLAUTH_WEBHOOK_EXTRA_ROOT_CERT_DER_FILE",
                        reason: "must be a readable DER certificate".to_owned(),
                    })?;
                    if bytes.is_empty() || bytes.len() > 65_536 {
                        return Err(ConfigError::InvalidValue {
                            key: "OWLAUTH_WEBHOOK_EXTRA_ROOT_CERT_DER_FILE",
                            reason: "must contain one bounded DER certificate".to_owned(),
                        });
                    }
                    let mut roots = rustls::RootCertStore::empty();
                    roots
                        .add(rustls::pki_types::CertificateDer::from(bytes.clone()))
                        .map_err(|_| ConfigError::InvalidValue {
                            key: "OWLAUTH_WEBHOOK_EXTRA_ROOT_CERT_DER_FILE",
                            reason: "must contain one valid DER trust anchor".to_owned(),
                        })?;
                    Ok(bytes)
                })
                .transpose()?
        } else {
            None
        };
        let managed_reauthorization_target_protection =
            parse_managed_reauthorization_target_protection(values)?;
        let identity_mutation_evidence_protection =
            parse_identity_mutation_evidence_protection(values)?;
        let managed_credential_protection = parse_managed_credential_protection(mode, values)?;
        let server_key_digest = parse_server_key_digest(mode, values)?;
        let provider_allow_http_loopback =
            parse_boolean(values, "OWLAUTH_PROVIDER_ALLOW_HTTP_LOOPBACK", false)?;
        let configured_auth_process_id = optional(values, "OWLAUTH_AUTH_PROCESS_ID")
            .map(validate_process_id)
            .transpose()?;
        if mode.has_auth() && configured_auth_process_id.is_none() {
            return Err(ConfigError::Missing("OWLAUTH_AUTH_PROCESS_ID"));
        }
        let auth_process_id = configured_auth_process_id.unwrap_or_default();
        let required_auth_process_ids = match optional(values, "OWLAUTH_REQUIRED_AUTH_PROCESS_IDS")
        {
            Some(configured) => {
                let ids = configured
                    .split(',')
                    .map(validate_process_id)
                    .collect::<Result<Vec<_>, _>>()?;
                if ids.is_empty()
                    || ids.iter().collect::<std::collections::BTreeSet<_>>().len() != ids.len()
                {
                    return Err(ConfigError::InvalidValue {
                        key: "OWLAUTH_REQUIRED_AUTH_PROCESS_IDS",
                        reason: "must contain unique comma-separated process IDs".to_owned(),
                    });
                }
                ids
            }
            None if mode == ProcessMode::Control => {
                return Err(ConfigError::Missing("OWLAUTH_REQUIRED_AUTH_PROCESS_IDS"));
            }
            None if mode.has_auth() => vec![auth_process_id.clone()],
            None => Vec::new(),
        };
        if required_auth_process_ids.len() > MAX_AUTH_PROCESSES {
            return Err(ConfigError::InvalidValue {
                key: "OWLAUTH_REQUIRED_AUTH_PROCESS_IDS",
                reason: format!("must contain at most {MAX_AUTH_PROCESSES} process IDs"),
            });
        }
        if mode.has_auth()
            && !required_auth_process_ids
                .iter()
                .any(|process_id| process_id == &auth_process_id)
        {
            return Err(ConfigError::InvalidValue {
                key: "OWLAUTH_REQUIRED_AUTH_PROCESS_IDS",
                reason: "must include this Auth process's OWLAUTH_AUTH_PROCESS_ID".to_owned(),
            });
        }
        let server_digest_readiness_lease_ttl = parse_millis(
            values,
            "OWLAUTH_SERVER_DIGEST_READINESS_LEASE_TTL_MS",
            30_000,
        )?;
        if (mode.has_auth() || mode.has_control())
            && (server_digest_readiness_lease_ttl < Duration::from_secs(1)
                || server_digest_readiness_lease_ttl > Duration::from_mins(5))
        {
            return Err(ConfigError::InvalidValue {
                key: "OWLAUTH_SERVER_DIGEST_READINESS_LEASE_TTL_MS",
                reason: "must be between 1000 and 300000 milliseconds".to_owned(),
            });
        }
        let deployment_smtp = parse_deployment_smtp(values)?;
        let webhook_allowed_private_ips = parse_allowed_private_ips(
            "OWLAUTH_WEBHOOK_ALLOWED_PRIVATE_IPS",
            optional(values, "OWLAUTH_WEBHOOK_ALLOWED_PRIVATE_IPS"),
        )?;
        let admission = parse_admission(
            mode,
            values,
            instance_id
                .as_deref()
                .expect("validated configuration always has an instance ID"),
            required_auth_process_ids.len(),
        )?;
        validate_protection_root_separation(
            runtime_protection.as_ref(),
            email_identity_protection.as_ref(),
            &projection_email_protection,
            &managed_reauthorization_target_protection,
            &identity_mutation_evidence_protection,
            managed_credential_protection.as_ref(),
            server_key_digest.as_ref(),
            provisioning.as_ref(),
            admission.as_ref(),
        )?;

        let serving_url = required(values, "OWLAUTH_POSTGRES_URL")?;
        let runtime_url = optional(values, "OWLAUTH_RUNTIME_POSTGRES_URL")
            .unwrap_or(&serving_url)
            .to_owned();
        let server_url = optional(values, "OWLAUTH_SERVER_POSTGRES_URL")
            .unwrap_or(&serving_url)
            .to_owned();
        let control_url = optional(values, "OWLAUTH_CONTROL_POSTGRES_URL")
            .unwrap_or(&serving_url)
            .to_owned();
        let migration_url = optional(values, "OWLAUTH_MIGRATION_POSTGRES_URL")
            .unwrap_or(&serving_url)
            .to_owned();
        validate_database_authority(&serving_url, &runtime_url, "OWLAUTH_RUNTIME_POSTGRES_URL")?;
        validate_database_authority(&serving_url, &server_url, "OWLAUTH_SERVER_POSTGRES_URL")?;
        validate_database_authority(&serving_url, &control_url, "OWLAUTH_CONTROL_POSTGRES_URL")?;
        validate_database_authority(
            &serving_url,
            &migration_url,
            "OWLAUTH_MIGRATION_POSTGRES_URL",
        )?;

        let migration_owner_role = optional(values, "OWLAUTH_MIGRATION_OWNER_ROLE")
            .map(validate_role)
            .transpose()?;
        let database_lock_timeout = parse_bounded_millis(
            values,
            "OWLAUTH_DATABASE_LOCK_TIMEOUT_MS",
            5_000,
            MIN_DATABASE_LOCK_TIMEOUT,
            MAX_DATABASE_LOCK_TIMEOUT,
        )?;
        let migration_lock_timeout = parse_bounded_millis(
            values,
            "OWLAUTH_MIGRATION_LOCK_TIMEOUT_MS",
            30_000,
            MIN_MIGRATION_LOCK_TIMEOUT,
            MAX_MIGRATION_LOCK_TIMEOUT,
        )?;
        let migration_statement_timeout = parse_bounded_millis(
            values,
            "OWLAUTH_MIGRATION_STATEMENT_TIMEOUT_MS",
            300_000,
            MIN_MIGRATION_STATEMENT_TIMEOUT,
            MAX_MIGRATION_STATEMENT_TIMEOUT,
        )?;
        let migration_deadline = parse_bounded_millis(
            values,
            "OWLAUTH_MIGRATION_DEADLINE_MS",
            1_800_000,
            MIN_MIGRATION_DEADLINE,
            MAX_MIGRATION_DEADLINE,
        )?;
        if migration_deadline <= migration_lock_timeout
            || migration_deadline <= migration_statement_timeout
        {
            return Err(ConfigError::InvalidValue {
                key: "OWLAUTH_MIGRATION_DEADLINE_MS",
                reason: "must be greater than both migration timeout settings".to_owned(),
            });
        }
        let publication_lease_ttl =
            parse_millis(values, "OWLAUTH_PUBLICATION_LEASE_TTL_MS", 30_000)?;
        if publication_lease_ttl > MAX_PUBLICATION_LEASE_TTL {
            return Err(ConfigError::InvalidValue {
                key: "OWLAUTH_PUBLICATION_LEASE_TTL_MS",
                reason:
                    "must derive a projection authority lease no longer than 86400000 milliseconds"
                        .to_owned(),
            });
        }
        let key_propagation_delay =
            parse_millis(values, "OWLAUTH_KEY_PROPAGATION_DELAY_MS", 2_000)?;
        if key_propagation_delay > MAX_KEY_PROPAGATION_DELAY {
            return Err(ConfigError::InvalidValue {
                key: "OWLAUTH_KEY_PROPAGATION_DELAY_MS",
                reason: "must not exceed 86400000 milliseconds".to_owned(),
            });
        }
        let signing_verification_retention = parse_millis(
            values,
            "OWLAUTH_SIGNING_VERIFICATION_RETENTION_MS",
            1_200_000,
        )?;
        if signing_verification_retention > MAX_SIGNING_VERIFICATION_RETENTION {
            return Err(ConfigError::InvalidValue {
                key: "OWLAUTH_SIGNING_VERIFICATION_RETENTION_MS",
                reason: "must not exceed 86400000 milliseconds".to_owned(),
            });
        }
        let maximum_token_lifetime = Duration::from_secs(
            u64::try_from(MAX_ACCESS_TOKEN_LIFETIME_SECONDS)
                .expect("the access-token lifetime maximum is positive"),
        );
        let required_verification_overlap = maximum_token_lifetime
            .checked_add(signing_verification_retention)
            .and_then(|retention| retention.checked_add(key_propagation_delay));
        if required_verification_overlap
            .and_then(|retention| time::Duration::try_from(retention).ok())
            .is_none()
        {
            return Err(ConfigError::InvalidValue {
                key: "OWLAUTH_SIGNING_VERIFICATION_RETENTION_MS",
                reason: "is too large to form the required verification overlap".to_owned(),
            });
        }

        Ok(Self {
            mode,
            instance_id,
            auth,
            control,
            runtime_database_max_connections,
            server_database_max_connections,
            control_database_max_connections,
            control_api_key,
            control_mcp,
            provisioning,
            runtime_protection,
            email_identity_protection,
            projection_email_protection,
            smtp_extra_root_cert_der,
            webhook_extra_root_cert_der,
            managed_reauthorization_target_protection,
            identity_mutation_evidence_protection,
            managed_credential_protection,
            server_key_digest,
            provider_allow_http_loopback,
            auth_process_id,
            required_auth_process_ids,
            server_digest_readiness_lease_ttl,
            admission,
            deployment_smtp,
            webhook_allowed_private_ips,
            publication_lease_ttl,
            key_propagation_delay,
            signing_verification_retention,
            postgres: PostgresConfig {
                serving_url: SecretString::new(serving_url),
                runtime_url: SecretString::new(runtime_url),
                server_url: SecretString::new(server_url),
                control_url: SecretString::new(control_url),
                migration_url: SecretString::new(migration_url),
                migration_mode: optional(values, "OWLAUTH_MIGRATION_MODE")
                    .unwrap_or("auto")
                    .parse()?,
                migration_owner_role,
                connect_timeout: parse_millis(
                    values,
                    "OWLAUTH_DATABASE_CONNECT_TIMEOUT_MS",
                    5_000,
                )?,
                database_lock_timeout,
                migration_lock_timeout,
                migration_statement_timeout,
                migration_deadline,
            },
            shutdown_timeout: parse_millis(values, "OWLAUTH_SHUTDOWN_TIMEOUT_MS", 10_000)?,
        })
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ConfigError {
    #[error("missing required environment variable {0}")]
    Missing(&'static str),
    #[error("unknown OwlAuth environment variable {0}")]
    Unknown(String),
    #[error("invalid {key}: {reason}")]
    InvalidValue { key: &'static str, reason: String },
    #[error("configured PostgreSQL URLs must identify one server and database authority ({0})")]
    DatabaseAuthority(&'static str),
    #[error("Auth and Control bases on one origin must be disjoint non-root paths")]
    SharedOriginBases,
}

fn optional<'a>(values: &'a BTreeMap<String, String>, key: &str) -> Option<&'a str> {
    values.get(key).map(String::as_str)
}

fn required(values: &BTreeMap<String, String>, key: &'static str) -> Result<String, ConfigError> {
    match optional(values, key) {
        Some(value) if !value.is_empty() => Ok(value.to_owned()),
        _ => Err(ConfigError::Missing(key)),
    }
}

fn reject_unknown_keys(values: &BTreeMap<String, String>) -> Result<(), ConfigError> {
    let known: BTreeSet<_> = KNOWN_ENVIRONMENT_KEYS.iter().copied().collect();
    if let Some(key) = values.keys().find(|key| !known.contains(key.as_str())) {
        return Err(ConfigError::Unknown(key.clone()));
    }
    Ok(())
}

fn parse_deployment_smtp(
    values: &BTreeMap<String, String>,
) -> Result<Option<DeploymentSmtpConfig>, ConfigError> {
    const REQUIRED_KEYS: [&str; 6] = [
        "OWLAUTH_DEPLOYMENT_SMTP_GENERATION",
        "OWLAUTH_DEPLOYMENT_SMTP_STATUS",
        "OWLAUTH_DEPLOYMENT_SMTP_HOST",
        "OWLAUTH_DEPLOYMENT_SMTP_PORT",
        "OWLAUTH_DEPLOYMENT_SMTP_TLS_MODE",
        "OWLAUTH_DEPLOYMENT_SMTP_SENDER_ADDRESS",
    ];
    let present = REQUIRED_KEYS
        .iter()
        .filter(|key| values.contains_key(**key))
        .count();
    let fingerprint_present = values.contains_key("OWLAUTH_DEPLOYMENT_SMTP_SAFE_FINGERPRINT");
    if present == 0 && !fingerprint_present {
        return Ok(None);
    }
    if present != REQUIRED_KEYS.len() {
        return Err(ConfigError::InvalidValue {
            key: "OWLAUTH_DEPLOYMENT_SMTP_GENERATION",
            reason: "deployment SMTP configuration must supply every generation metadata field"
                .to_owned(),
        });
    }
    let generation: i32 = required(values, "OWLAUTH_DEPLOYMENT_SMTP_GENERATION")?
        .parse()
        .map_err(|_| ConfigError::InvalidValue {
            key: "OWLAUTH_DEPLOYMENT_SMTP_GENERATION",
            reason: "must be a positive 32-bit generation".to_owned(),
        })?;
    if generation <= 0 {
        return Err(ConfigError::InvalidValue {
            key: "OWLAUTH_DEPLOYMENT_SMTP_GENERATION",
            reason: "must be a positive 32-bit generation".to_owned(),
        });
    }
    let status =
        parse_deployment_smtp_status(&required(values, "OWLAUTH_DEPLOYMENT_SMTP_STATUS")?)?;
    let host = normalize_deployment_smtp_host(&required(values, "OWLAUTH_DEPLOYMENT_SMTP_HOST")?)?;
    let port: u16 = required(values, "OWLAUTH_DEPLOYMENT_SMTP_PORT")?
        .parse()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| ConfigError::InvalidValue {
            key: "OWLAUTH_DEPLOYMENT_SMTP_PORT",
            reason: "must be a non-zero TCP port".to_owned(),
        })?;
    let tls_mode = required(values, "OWLAUTH_DEPLOYMENT_SMTP_TLS_MODE")?;
    if !matches!(tls_mode.as_str(), "implicit_tls" | "starttls_required") {
        return Err(ConfigError::InvalidValue {
            key: "OWLAUTH_DEPLOYMENT_SMTP_TLS_MODE",
            reason: "must be implicit_tls or starttls_required".to_owned(),
        });
    }
    let sender_address =
        CanonicalEmail::parse_v1(&required(values, "OWLAUTH_DEPLOYMENT_SMTP_SENDER_ADDRESS")?)
            .map_err(|_| ConfigError::InvalidValue {
                key: "OWLAUTH_DEPLOYMENT_SMTP_SENDER_ADDRESS",
                reason: "must be a canonicalizable email address".to_owned(),
            })?
            .expose()
            .to_owned();
    let safe_fingerprint = optional(values, "OWLAUTH_DEPLOYMENT_SMTP_SAFE_FINGERPRINT")
        .map(parse_deployment_smtp_fingerprint)
        .transpose()?;
    if status != DeploymentSmtpStatus::Reconciled && safe_fingerprint.is_none() {
        return Err(ConfigError::Missing(
            "OWLAUTH_DEPLOYMENT_SMTP_SAFE_FINGERPRINT",
        ));
    }
    let explicitly_allowed_private_ips = parse_deployment_smtp_private_ips(optional(
        values,
        "OWLAUTH_DEPLOYMENT_SMTP_ALLOWED_PRIVATE_IPS",
    ))?;
    Ok(Some(DeploymentSmtpConfig {
        generation,
        status,
        host,
        port,
        tls_mode,
        sender_address,
        safe_fingerprint,
        explicitly_allowed_private_ips,
    }))
}

fn parse_deployment_smtp_private_ips(value: Option<&str>) -> Result<Vec<IpAddr>, ConfigError> {
    parse_allowed_private_ips("OWLAUTH_DEPLOYMENT_SMTP_ALLOWED_PRIVATE_IPS", value)
}

fn parse_allowed_private_ips(
    key: &'static str,
    value: Option<&str>,
) -> Result<Vec<IpAddr>, ConfigError> {
    let mut addresses = value
        .unwrap_or_default()
        .split(',')
        .filter(|value| !value.is_empty())
        .map(str::parse::<IpAddr>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ConfigError::InvalidValue {
            key,
            reason: "must be a comma-separated list of IP literals".to_owned(),
        })?;
    addresses.sort_unstable();
    addresses.dedup();
    crate::application::validate_private_relay_allowlist(&addresses).map_err(|_| {
        ConfigError::InvalidValue {
            key,
            reason: "must contain at most 16 explicitly overridable private addresses".to_owned(),
        }
    })?;
    Ok(addresses)
}

fn parse_deployment_smtp_status(value: &str) -> Result<DeploymentSmtpStatus, ConfigError> {
    match value {
        "reconciled" => Ok(DeploymentSmtpStatus::Reconciled),
        "active" => Ok(DeploymentSmtpStatus::Active),
        "disabled" => Ok(DeploymentSmtpStatus::Disabled),
        "compromised" => Ok(DeploymentSmtpStatus::Compromised),
        _ => Err(ConfigError::InvalidValue {
            key: "OWLAUTH_DEPLOYMENT_SMTP_STATUS",
            reason: "must be reconciled, active, disabled, or compromised".to_owned(),
        }),
    }
}

fn normalize_deployment_smtp_host(value: &str) -> Result<String, ConfigError> {
    let host = value.trim().to_ascii_lowercase();
    let invalid_label = host.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    });
    if host.is_empty()
        || host.len() > 253
        || host.parse::<std::net::IpAddr>().is_ok()
        || invalid_label
    {
        return Err(ConfigError::InvalidValue {
            key: "OWLAUTH_DEPLOYMENT_SMTP_HOST",
            reason: "must be a bounded DNS hostname rather than an IP literal".to_owned(),
        });
    }
    Ok(host)
}

fn parse_deployment_smtp_fingerprint(value: &str) -> Result<[u8; 32], ConfigError> {
    let invalid = || ConfigError::InvalidValue {
        key: "OWLAUTH_DEPLOYMENT_SMTP_SAFE_FINGERPRINT",
        reason: "must be exactly 32 bytes encoded as hexadecimal".to_owned(),
    };
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid());
    }
    let mut fingerprint = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        fingerprint[index] = u8::from_str_radix(
            std::str::from_utf8(chunk).expect("hexadecimal is UTF-8"),
            16,
        )
        .map_err(|_| invalid())?;
    }
    Ok(fingerprint)
}

fn parse_admission(
    mode: ProcessMode,
    values: &BTreeMap<String, String>,
    instance_id: &str,
    auth_roster_size: usize,
) -> Result<Option<AdmissionConfig>, ConfigError> {
    if !mode.has_auth() {
        return Ok(None);
    }
    let digest_key = StoreMasterKey::parse(
        "OWLAUTH_ADMISSION_DIGEST_KEY",
        required(values, "OWLAUTH_ADMISSION_DIGEST_KEY")?,
    )?;
    let redis_url = optional(values, "OWLAUTH_ADMISSION_REDIS_URL")
        .map(|value| {
            let invalid_reason = || ConfigError::InvalidValue {
                key: "OWLAUTH_ADMISSION_REDIS_URL",
                reason: "must be an absolute redis or rediss URL with an optional numeric database path and no query or fragment".to_owned(),
            };
            let parsed = Url::parse(value).map_err(|_| invalid_reason())?;
            let database_path_is_valid = matches!(parsed.path(), "" | "/")
                || parsed.path().strip_prefix('/').is_some_and(|database| {
                    !database.is_empty()
                        && database.bytes().all(|byte| byte.is_ascii_digit())
                        && database.parse::<u32>().is_ok()
                });
            if !matches!(parsed.scheme(), "redis" | "rediss")
                || parsed.host_str().is_none()
                || parsed.query().is_some()
                || parsed.fragment().is_some()
                || !database_path_is_valid
            {
                return Err(invalid_reason());
            }
            Ok(SecretString::new(value.to_owned()))
        })
        .transpose()?;
    let namespace = if let Some(value) = optional(values, "OWLAUTH_ADMISSION_NAMESPACE") {
        validate_admission_namespace(value)?
    } else {
        let digest = Sha256::digest(instance_id.as_bytes());
        format!("owl_{}", URL_SAFE_NO_PAD.encode(&digest[..12]))
    };
    let redis_timeout = parse_millis(values, "OWLAUTH_ADMISSION_REDIS_TIMEOUT_MS", 100)?;
    if !(Duration::from_millis(10)..=Duration::from_secs(2)).contains(&redis_timeout) {
        return Err(ConfigError::InvalidValue {
            key: "OWLAUTH_ADMISSION_REDIS_TIMEOUT_MS",
            reason: "must be between 10 and 2000 milliseconds".to_owned(),
        });
    }
    let auth_maximum_processes = parse_admission_maximum_processes(
        values,
        "OWLAUTH_AUTH_MAX_PROCESSES",
        "Auth",
        auth_roster_size,
    )?;
    Ok(Some(AdmissionConfig {
        redis_url,
        digest_key,
        namespace,
        redis_timeout,
        auth_maximum_processes: Some(auth_maximum_processes),
    }))
}

fn parse_admission_maximum_processes(
    values: &BTreeMap<String, String>,
    key: &'static str,
    plane: &str,
    roster_size: usize,
) -> Result<NonZeroU32, ConfigError> {
    let reason = || format!("must be between the required {plane} roster size and 64");
    let default_processes = u32::try_from(roster_size).map_err(|_| ConfigError::InvalidValue {
        key,
        reason: reason(),
    })?;
    let maximum_processes = parse_nonzero_u32(values, key, default_processes)?;
    if usize::try_from(maximum_processes.get()).unwrap_or(usize::MAX) > MAX_AUTH_PROCESSES
        || usize::try_from(maximum_processes.get()).unwrap_or(usize::MAX) < roster_size
    {
        return Err(ConfigError::InvalidValue {
            key,
            reason: reason(),
        });
    }
    Ok(maximum_processes)
}

fn validate_admission_namespace(value: &str) -> Result<String, ConfigError> {
    if !(1..=64).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(ConfigError::InvalidValue {
            key: "OWLAUTH_ADMISSION_NAMESPACE",
            reason: "must be 1 to 64 alphanumeric, underscore, or hyphen characters".to_owned(),
        });
    }
    Ok(value.to_owned())
}

fn parse_control_identity(
    mode: ProcessMode,
    values: &BTreeMap<String, String>,
) -> Result<(Option<String>, Option<OperatorApiKey>), ConfigError> {
    let instance_id = validate_instance_id(required(values, "OWLAUTH_INSTANCE_ID")?)?;
    let control_api_key = if mode.has_control() {
        Some(OperatorApiKey::parse(required(
            values,
            "OWLAUTH_CONTROL_API_KEY",
        )?)?)
    } else {
        None
    };
    Ok((Some(instance_id), control_api_key))
}

fn parse_control_mcp(
    mode: ProcessMode,
    values: &BTreeMap<String, String>,
) -> Result<McpHttpConfig, ConfigError> {
    let enabled = parse_boolean(values, "OWLAUTH_CONTROL_MCP_ENABLED", false)?;
    if enabled && !mode.has_control() {
        return Err(ConfigError::InvalidValue {
            key: "OWLAUTH_CONTROL_MCP_ENABLED",
            reason: "requires `OWLAUTH_MODE=control` or `OWLAUTH_MODE=all`".to_owned(),
        });
    }
    let request_timeout = parse_millis(values, "OWLAUTH_CONTROL_MCP_REQUEST_TIMEOUT_MS", 10_000)?;
    if request_timeout > Duration::from_mins(1) {
        return Err(ConfigError::InvalidValue {
            key: "OWLAUTH_CONTROL_MCP_REQUEST_TIMEOUT_MS",
            reason: "must not exceed 60000 milliseconds".to_owned(),
        });
    }
    Ok(McpHttpConfig {
        enabled,
        max_request_bytes: parse_bounded_usize(
            values,
            "OWLAUTH_CONTROL_MCP_MAX_REQUEST_BYTES",
            65_536,
            1_048_576,
        )?,
        request_timeout,
        max_concurrent_requests: parse_bounded_usize(
            values,
            "OWLAUTH_CONTROL_MCP_MAX_CONCURRENT_REQUESTS",
            16,
            64,
        )?,
        max_requests_per_second: parse_bounded_usize(
            values,
            "OWLAUTH_CONTROL_MCP_MAX_REQUESTS_PER_SECOND",
            64,
            1_024,
        )?,
        max_result_bytes: parse_bounded_usize(
            values,
            "OWLAUTH_CONTROL_MCP_MAX_RESULT_BYTES",
            65_536,
            1_048_576,
        )?,
    })
}

fn validate_control_mcp_listener(
    config: &McpHttpConfig,
    listener: &ListenerConfig,
) -> Result<(), ConfigError> {
    if !config.enabled || listener.external_base.scheme() == "https" {
        return Ok(());
    }
    let external_loopback = match listener.external_base.host() {
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        Some(url::Host::Domain(_)) | None => false,
    };
    if !external_loopback {
        return Err(ConfigError::InvalidValue {
            key: "OWLAUTH_CONTROL_BASE_URL",
            reason: "must use HTTPS when remote MCP is enabled, except for an exact loopback IP"
                .to_owned(),
        });
    }
    if !listener.bind.ip().is_loopback() {
        return Err(ConfigError::InvalidValue {
            key: "OWLAUTH_CONTROL_ADDR",
            reason: "must bind to an exact loopback IP when remote MCP uses development HTTP"
                .to_owned(),
        });
    }
    Ok(())
}

fn parse_provisioning(
    mode: ProcessMode,
    values: &BTreeMap<String, String>,
    require_software_custody: bool,
) -> Result<Option<ProvisioningConfig>, ConfigError> {
    let runtime_needs_stores = mode.has_auth() && FEDERATED_PROJECT_AUTH_AVAILABLE;
    if !mode.has_control() && !runtime_needs_stores {
        return Ok(None);
    }
    let software_custody_key = match optional(values, "OWLAUTH_SOFTWARE_CUSTODY_KEY") {
        Some(value) => Some(StoreMasterKey::parse(
            "OWLAUTH_SOFTWARE_CUSTODY_KEY",
            value.to_owned(),
        )?),
        None if require_software_custody => {
            return Err(ConfigError::Missing("OWLAUTH_SOFTWARE_CUSTODY_KEY"));
        }
        None => None,
    };
    Ok(Some(ProvisioningConfig {
        software_custody_key,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SerializedRuntimeKeyConfig {
    digest_key: String,
    protection_key: String,
}

struct UniqueVersionedKeys(BTreeMap<i32, String>);

impl<'de> Deserialize<'de> for UniqueVersionedKeys {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct UniqueVersionedKeysVisitor;

        impl<'de> Visitor<'de> for UniqueVersionedKeysVisitor {
            type Value = UniqueVersionedKeys;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON object with unique integer key versions")
            }

            fn visit_map<M>(self, mut entries: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut keys = BTreeMap::new();
                while let Some((version, key)) = entries.next_entry::<i32, String>()? {
                    if keys.insert(version, key).is_some() {
                        return Err(M::Error::custom("duplicate key version"));
                    }
                }
                Ok(UniqueVersionedKeys(keys))
            }
        }

        deserializer.deserialize_map(UniqueVersionedKeysVisitor)
    }
}

fn parse_runtime_protection(
    mode: ProcessMode,
    values: &BTreeMap<String, String>,
) -> Result<Option<RuntimeProtectionConfig>, ConfigError> {
    if !mode.has_auth() {
        // Control-only composition deliberately does not parse or retain generic Runtime roots.
        // Deployments may still share a broader environment template without expanding custody.
        return Ok(None);
    }
    let (active_version, active, retained) = parse_protection_ring(
        values,
        "OWLAUTH_RUNTIME_KEY_VERSION",
        "OWLAUTH_RUNTIME_DIGEST_KEY",
        "OWLAUTH_RUNTIME_PROTECTION_KEY",
        "OWLAUTH_RUNTIME_RETAINED_KEYS",
    )?;
    Ok(Some(RuntimeProtectionConfig {
        active_version,
        active,
        retained,
    }))
}

fn parse_email_identity_protection(
    _mode: ProcessMode,
    values: &BTreeMap<String, String>,
) -> Result<Option<EmailIdentityProtectionConfig>, ConfigError> {
    const EMAIL_IDENTITY_KEYS: [&str; 6] = [
        "OWLAUTH_EMAIL_IDENTITY_KEY_VERSION",
        "OWLAUTH_EMAIL_IDENTITY_DIGEST_KEY",
        "OWLAUTH_EMAIL_IDENTITY_PROTECTION_KEY",
        "OWLAUTH_EMAIL_IDENTITY_RETAINED_KEYS",
        "OWLAUTH_EMAIL_IDENTITY_ALIAS_CUTOVER_VERSION",
        "OWLAUTH_EMAIL_IDENTITY_ALIAS_RETIRE_VERSION",
    ];
    let configured = EMAIL_IDENTITY_KEYS
        .iter()
        .any(|key| values.contains_key(*key));
    // Control loads this ring only behind an exact-context decrypt-only durable-address reader;
    // Runtime additionally owns lookup, write, and rewrap authority. Absence remains a scoped
    // fail-closed state for verified-email materialization.
    // Absence is an intentional capability-scoped fail-closed state. Runtime still composes
    // provider/session capabilities, while no email readiness lease can be published.
    if !configured {
        return Ok(None);
    }
    if optional(values, "OWLAUTH_EMAIL_IDENTITY_ALIAS_CUTOVER_VERSION").is_some()
        && optional(values, "OWLAUTH_EMAIL_IDENTITY_ALIAS_RETIRE_VERSION").is_some()
    {
        return Err(ConfigError::InvalidValue {
            key: "OWLAUTH_EMAIL_IDENTITY_ALIAS_RETIRE_VERSION",
            reason: "cannot be set in the same rollout as OWLAUTH_EMAIL_IDENTITY_ALIAS_CUTOVER_VERSION; retirement requires a later retire-only rollout after post-cutover observation".to_owned(),
        });
    }
    let (active_version, active, retained) = parse_protection_ring(
        values,
        "OWLAUTH_EMAIL_IDENTITY_KEY_VERSION",
        "OWLAUTH_EMAIL_IDENTITY_DIGEST_KEY",
        "OWLAUTH_EMAIL_IDENTITY_PROTECTION_KEY",
        "OWLAUTH_EMAIL_IDENTITY_RETAINED_KEYS",
    )?;
    let parse_authorization = |key: &'static str| {
        optional(values, key)
            .map(|value| {
                value
                    .parse::<i32>()
                    .ok()
                    .filter(|version| *version == active_version)
                    .ok_or_else(|| ConfigError::InvalidValue {
                        key,
                        reason: format!("must equal OWLAUTH_EMAIL_IDENTITY_KEY_VERSION ({active_version}) when explicitly set"),
                    })
            })
            .transpose()
    };
    Ok(Some(EmailIdentityProtectionConfig {
        active_version,
        identity_alias_cutover_version: parse_authorization(
            "OWLAUTH_EMAIL_IDENTITY_ALIAS_CUTOVER_VERSION",
        )?,
        identity_alias_retire_version: parse_authorization(
            "OWLAUTH_EMAIL_IDENTITY_ALIAS_RETIRE_VERSION",
        )?,
        active,
        retained,
    }))
}

fn parse_projection_email_protection(
    values: &BTreeMap<String, String>,
) -> Result<ProjectionEmailProtectionConfig, ConfigError> {
    if optional(values, "OWLAUTH_PROJECTION_EMAIL_CUTOVER_VERSION").is_some()
        && optional(values, "OWLAUTH_PROJECTION_EMAIL_RETIRE_VERSION").is_some()
    {
        return Err(ConfigError::InvalidValue {
            key: "OWLAUTH_PROJECTION_EMAIL_RETIRE_VERSION",
            reason: "cutover and retirement require separate rollouts".to_owned(),
        });
    }
    let active_version = required(values, "OWLAUTH_PROJECTION_EMAIL_KEY_VERSION")?
        .parse::<i32>()
        .ok()
        .filter(|version| *version > 0)
        .ok_or_else(|| ConfigError::InvalidValue {
            key: "OWLAUTH_PROJECTION_EMAIL_KEY_VERSION",
            reason: "must be a positive integer".to_owned(),
        })?;
    let active_key = StoreMasterKey::parse(
        "OWLAUTH_PROJECTION_EMAIL_PROTECTION_KEY",
        required(values, "OWLAUTH_PROJECTION_EMAIL_PROTECTION_KEY")?,
    )?;
    let retained = serde_json::from_str::<UniqueVersionedKeys>(
        optional(values, "OWLAUTH_PROJECTION_EMAIL_RETAINED_KEYS").unwrap_or("{}"),
    )
    .map_err(|_| ConfigError::InvalidValue {
        key: "OWLAUTH_PROJECTION_EMAIL_RETAINED_KEYS",
        reason: "must be a JSON object keyed by unique positive key versions".to_owned(),
    })?
    .0
    .into_iter()
    .map(|(version, key)| {
        if version <= 0 || version == active_version {
            return Err(ConfigError::InvalidValue {
                key: "OWLAUTH_PROJECTION_EMAIL_RETAINED_KEYS",
                reason: "versions must be positive and must not repeat the active version"
                    .to_owned(),
            });
        }
        Ok((
            version,
            StoreMasterKey::parse("OWLAUTH_PROJECTION_EMAIL_RETAINED_KEYS", key)?,
        ))
    })
    .collect::<Result<BTreeMap<_, _>, _>>()?;
    if retained.len() > 15 {
        return Err(ConfigError::InvalidValue {
            key: "OWLAUTH_PROJECTION_EMAIL_RETAINED_KEYS",
            reason: "at most 15 retained versions are supported".to_owned(),
        });
    }
    let parse_authorization = |key: &'static str| {
        optional(values, key)
            .map(|value| {
                value
                    .parse::<i32>()
                    .ok()
                    .filter(|version| *version > 0)
                    .ok_or_else(|| ConfigError::InvalidValue {
                        key,
                        reason: "must be a positive configured key version".to_owned(),
                    })
            })
            .transpose()
    };
    Ok(ProjectionEmailProtectionConfig {
        active_version,
        cutover_version: parse_authorization("OWLAUTH_PROJECTION_EMAIL_CUTOVER_VERSION")?,
        retire_version: parse_authorization("OWLAUTH_PROJECTION_EMAIL_RETIRE_VERSION")?,
        active_key,
        retained,
    })
}

fn parse_protection_ring(
    values: &BTreeMap<String, String>,
    version_key: &'static str,
    digest_key: &'static str,
    protection_key: &'static str,
    retained_key: &'static str,
) -> Result<(i32, RuntimeKeyConfig, BTreeMap<i32, RuntimeKeyConfig>), ConfigError> {
    let active_version = required(values, version_key)?
        .parse::<i32>()
        .ok()
        .filter(|version| *version > 0)
        .ok_or_else(|| ConfigError::InvalidValue {
            key: version_key,
            reason: "must be a positive integer".to_owned(),
        })?;
    let active = parse_runtime_key(
        digest_key,
        required(values, digest_key)?,
        protection_key,
        required(values, protection_key)?,
    )?;
    let serialized = optional(values, retained_key).unwrap_or("{}");
    let retained = serde_json::from_str::<BTreeMap<i32, SerializedRuntimeKeyConfig>>(serialized)
        .map_err(|_| ConfigError::InvalidValue {
            key: retained_key,
            reason: "must be a JSON object keyed by unique positive key versions".to_owned(),
        })?
        .into_iter()
        .map(|(version, key)| {
            if version <= 0 || version == active_version {
                return Err(ConfigError::InvalidValue {
                    key: retained_key,
                    reason: "versions must be positive and must not repeat the active version"
                        .to_owned(),
                });
            }
            Ok((
                version,
                parse_runtime_key(
                    digest_key,
                    key.digest_key,
                    protection_key,
                    key.protection_key,
                )?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    if retained.len() > 15 {
        return Err(ConfigError::InvalidValue {
            key: retained_key,
            reason: "at most 15 retained versions are supported alongside the active version"
                .to_owned(),
        });
    }
    Ok((active_version, active, retained))
}

fn parse_identity_mutation_evidence_protection(
    values: &BTreeMap<String, String>,
) -> Result<RuntimeProtectionConfig, ConfigError> {
    let (active_version, active, retained) = parse_protection_ring(
        values,
        "OWLAUTH_IDENTITY_MUTATION_EVIDENCE_KEY_VERSION",
        "OWLAUTH_IDENTITY_MUTATION_EVIDENCE_DIGEST_KEY",
        "OWLAUTH_IDENTITY_MUTATION_EVIDENCE_PROTECTION_KEY",
        "OWLAUTH_IDENTITY_MUTATION_EVIDENCE_RETAINED_KEYS",
    )?;
    Ok(RuntimeProtectionConfig {
        active_version,
        active,
        retained,
    })
}

fn parse_managed_reauthorization_target_protection(
    values: &BTreeMap<String, String>,
) -> Result<RuntimeProtectionConfig, ConfigError> {
    let active_version = required(values, "OWLAUTH_MANAGED_REAUTHORIZATION_KEY_VERSION")?
        .parse::<i32>()
        .map_err(|_| ConfigError::InvalidValue {
            key: "OWLAUTH_MANAGED_REAUTHORIZATION_KEY_VERSION",
            reason: "must be a positive integer".to_owned(),
        })?;
    if active_version <= 0 {
        return Err(ConfigError::InvalidValue {
            key: "OWLAUTH_MANAGED_REAUTHORIZATION_KEY_VERSION",
            reason: "must be a positive integer".to_owned(),
        });
    }
    let active = parse_managed_reauthorization_target_key(
        required(values, "OWLAUTH_MANAGED_REAUTHORIZATION_DIGEST_KEY")?,
        required(values, "OWLAUTH_MANAGED_REAUTHORIZATION_PROTECTION_KEY")?,
    )?;
    let serialized =
        optional(values, "OWLAUTH_MANAGED_REAUTHORIZATION_RETAINED_KEYS").unwrap_or("{}");
    let retained = serde_json::from_str::<BTreeMap<i32, SerializedRuntimeKeyConfig>>(serialized)
        .map_err(|_| ConfigError::InvalidValue {
            key: "OWLAUTH_MANAGED_REAUTHORIZATION_RETAINED_KEYS",
            reason: "must be a JSON object keyed by unique positive key versions".to_owned(),
        })?
        .into_iter()
        .map(|(version, key)| {
            if version <= 0 || version == active_version {
                return Err(ConfigError::InvalidValue {
                    key: "OWLAUTH_MANAGED_REAUTHORIZATION_RETAINED_KEYS",
                    reason: "versions must be positive and must not repeat the active version"
                        .to_owned(),
                });
            }
            Ok((
                version,
                parse_managed_reauthorization_target_key(key.digest_key, key.protection_key)?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    Ok(RuntimeProtectionConfig {
        active_version,
        active,
        retained,
    })
}

fn parse_managed_reauthorization_target_key(
    digest_key: String,
    protection_key: String,
) -> Result<RuntimeKeyConfig, ConfigError> {
    let digest_key =
        StoreMasterKey::parse("OWLAUTH_MANAGED_REAUTHORIZATION_DIGEST_KEY", digest_key)?;
    let protection_key = StoreMasterKey::parse(
        "OWLAUTH_MANAGED_REAUTHORIZATION_PROTECTION_KEY",
        protection_key,
    )?;
    if digest_key.0.as_ref() == protection_key.0.as_ref() {
        return Err(ConfigError::InvalidValue {
            key: "OWLAUTH_MANAGED_REAUTHORIZATION_PROTECTION_KEY",
            reason: "must be separate from the managed reauthorization digest key".to_owned(),
        });
    }
    Ok(RuntimeKeyConfig {
        digest_key,
        protection_key,
    })
}

fn parse_runtime_key(
    digest_key_name: &'static str,
    digest_key: String,
    protection_key_name: &'static str,
    protection_key: String,
) -> Result<RuntimeKeyConfig, ConfigError> {
    let digest_key = StoreMasterKey::parse(digest_key_name, digest_key)?;
    let protection_key = StoreMasterKey::parse(protection_key_name, protection_key)?;
    if digest_key.0.as_ref() == protection_key.0.as_ref() {
        return Err(ConfigError::InvalidValue {
            key: protection_key_name,
            reason: "must be separate from the corresponding digest key".to_owned(),
        });
    }
    Ok(RuntimeKeyConfig {
        digest_key,
        protection_key,
    })
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "global root-separation validation must enumerate every independently configured authority and retained root"
)]
fn validate_protection_root_separation(
    runtime: Option<&RuntimeProtectionConfig>,
    email_identity: Option<&EmailIdentityProtectionConfig>,
    projection_email: &ProjectionEmailProtectionConfig,
    managed_target: &RuntimeProtectionConfig,
    identity_evidence: &RuntimeProtectionConfig,
    managed_credential: Option<&ManagedCredentialProtectionConfig>,
    server_key_digest: Option<&ServerKeyDigestConfig>,
    provisioning: Option<&ProvisioningConfig>,
    admission: Option<&AdmissionConfig>,
) -> Result<(), ConfigError> {
    let mut fingerprints = BTreeSet::new();
    let mut insert = |material: &[u8], key: &'static str| {
        let fingerprint: [u8; 32] = Sha256::digest(material).into();
        if fingerprints.insert(fingerprint) {
            Ok(())
        } else {
            Err(ConfigError::InvalidValue {
                key,
                reason: "every active and retained protection root across all plane authorities must be distinct"
                    .to_owned(),
            })
        }
    };

    if let Some(runtime) = runtime {
        for key in std::iter::once(&runtime.active).chain(runtime.retained.values()) {
            insert(key.digest_key.0.as_ref(), "OWLAUTH_RUNTIME_PROTECTION_KEY")?;
            insert(
                key.protection_key.0.as_ref(),
                "OWLAUTH_RUNTIME_PROTECTION_KEY",
            )?;
        }
    }
    if let Some(email_identity) = email_identity {
        for key in std::iter::once(&email_identity.active).chain(email_identity.retained.values()) {
            insert(
                key.digest_key.0.as_ref(),
                "OWLAUTH_EMAIL_IDENTITY_PROTECTION_KEY",
            )?;
            insert(
                key.protection_key.0.as_ref(),
                "OWLAUTH_EMAIL_IDENTITY_PROTECTION_KEY",
            )?;
        }
    }
    for key in
        std::iter::once(&projection_email.active_key).chain(projection_email.retained.values())
    {
        insert(key.0.as_ref(), "OWLAUTH_PROJECTION_EMAIL_PROTECTION_KEY")?;
    }
    if let Some(managed_credential) = managed_credential {
        for key in std::iter::once(&managed_credential.active_key)
            .chain(managed_credential.retained.values())
        {
            insert(key.0.as_ref(), "OWLAUTH_MANAGED_CREDENTIAL_KEY")?;
        }
    }
    if let Some(server_key_digest) = server_key_digest {
        for key in std::iter::once(&server_key_digest.active_key)
            .chain(server_key_digest.retained.values())
        {
            insert(key.0.as_ref(), "OWLAUTH_SERVER_KEY_DIGEST_KEY")?;
        }
    }
    for key in std::iter::once(&managed_target.active).chain(managed_target.retained.values()) {
        insert(
            key.digest_key.0.as_ref(),
            "OWLAUTH_MANAGED_REAUTHORIZATION_DIGEST_KEY",
        )?;
        insert(
            key.protection_key.0.as_ref(),
            "OWLAUTH_MANAGED_REAUTHORIZATION_PROTECTION_KEY",
        )?;
    }
    for key in std::iter::once(&identity_evidence.active).chain(identity_evidence.retained.values())
    {
        insert(
            key.digest_key.0.as_ref(),
            "OWLAUTH_IDENTITY_MUTATION_EVIDENCE_DIGEST_KEY",
        )?;
        insert(
            key.protection_key.0.as_ref(),
            "OWLAUTH_IDENTITY_MUTATION_EVIDENCE_PROTECTION_KEY",
        )?;
    }
    if let Some(provisioning) = provisioning
        && let Some(software_custody_key) = &provisioning.software_custody_key
    {
        insert(
            software_custody_key.0.as_ref(),
            "OWLAUTH_SOFTWARE_CUSTODY_KEY",
        )?;
    }
    if let Some(admission) = admission {
        insert(
            admission.digest_key.0.as_ref(),
            "OWLAUTH_ADMISSION_DIGEST_KEY",
        )?;
    }
    Ok(())
}

fn parse_server_key_digest(
    mode: ProcessMode,
    values: &BTreeMap<String, String>,
) -> Result<Option<ServerKeyDigestConfig>, ConfigError> {
    if !mode.has_auth() && !mode.has_control() {
        return Ok(None);
    }
    let active_version = required(values, "OWLAUTH_SERVER_KEY_DIGEST_KEY_VERSION")?
        .parse::<i32>()
        .ok()
        .filter(|version| *version > 0)
        .ok_or_else(|| ConfigError::InvalidValue {
            key: "OWLAUTH_SERVER_KEY_DIGEST_KEY_VERSION",
            reason: "must be a positive integer".to_owned(),
        })?;
    let active_key = StoreMasterKey::parse(
        "OWLAUTH_SERVER_KEY_DIGEST_KEY",
        required(values, "OWLAUTH_SERVER_KEY_DIGEST_KEY")?,
    )?;
    let retained = serde_json::from_str::<BTreeMap<i32, String>>(
        optional(values, "OWLAUTH_SERVER_KEY_DIGEST_RETAINED_KEYS").unwrap_or("{}"),
    )
    .map_err(|_| ConfigError::InvalidValue {
        key: "OWLAUTH_SERVER_KEY_DIGEST_RETAINED_KEYS",
        reason: "must be a JSON object keyed by unique positive key versions".to_owned(),
    })?
    .into_iter()
    .map(|(version, value)| {
        if version <= 0 || version == active_version {
            return Err(ConfigError::InvalidValue {
                key: "OWLAUTH_SERVER_KEY_DIGEST_RETAINED_KEYS",
                reason: "versions must be positive and must not repeat the active version"
                    .to_owned(),
            });
        }
        Ok((
            version,
            StoreMasterKey::parse("OWLAUTH_SERVER_KEY_DIGEST_RETAINED_KEYS", value)?,
        ))
    })
    .collect::<Result<BTreeMap<_, _>, _>>()?;
    if retained.len() > 31 {
        return Err(ConfigError::InvalidValue {
            key: "OWLAUTH_SERVER_KEY_DIGEST_RETAINED_KEYS",
            reason: "at most 31 retained versions are supported".to_owned(),
        });
    }
    Ok(Some(ServerKeyDigestConfig {
        active_version,
        active_key,
        retained,
    }))
}

fn parse_managed_credential_protection(
    mode: ProcessMode,
    values: &BTreeMap<String, String>,
) -> Result<Option<ManagedCredentialProtectionConfig>, ConfigError> {
    let required_for_runtime = mode.has_auth() && FEDERATED_PROJECT_AUTH_AVAILABLE;
    if !required_for_runtime {
        return Ok(None);
    }
    let active_version = required(values, "OWLAUTH_MANAGED_CREDENTIAL_KEY_VERSION")?
        .parse::<i32>()
        .map_err(|_| ConfigError::InvalidValue {
            key: "OWLAUTH_MANAGED_CREDENTIAL_KEY_VERSION",
            reason: "must be a positive integer".to_owned(),
        })?;
    if active_version <= 0 {
        return Err(ConfigError::InvalidValue {
            key: "OWLAUTH_MANAGED_CREDENTIAL_KEY_VERSION",
            reason: "must be a positive integer".to_owned(),
        });
    }
    let active_key = StoreMasterKey::parse(
        "OWLAUTH_MANAGED_CREDENTIAL_KEY",
        required(values, "OWLAUTH_MANAGED_CREDENTIAL_KEY")?,
    )?;
    let serialized = optional(values, "OWLAUTH_MANAGED_CREDENTIAL_RETAINED_KEYS").unwrap_or("{}");
    let retained = serde_json::from_str::<BTreeMap<i32, String>>(serialized)
        .map_err(|_| ConfigError::InvalidValue {
            key: "OWLAUTH_MANAGED_CREDENTIAL_RETAINED_KEYS",
            reason: "must be a JSON object keyed by unique positive key versions".to_owned(),
        })?
        .into_iter()
        .map(|(version, key)| {
            if version <= 0 || version == active_version {
                return Err(ConfigError::InvalidValue {
                    key: "OWLAUTH_MANAGED_CREDENTIAL_RETAINED_KEYS",
                    reason: "versions must be positive and must not repeat the active version"
                        .to_owned(),
                });
            }
            Ok((
                version,
                StoreMasterKey::parse("OWLAUTH_MANAGED_CREDENTIAL_RETAINED_KEYS", key)?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    Ok(Some(ManagedCredentialProtectionConfig {
        active_version,
        active_key,
        retained,
    }))
}

fn parse_boolean(
    values: &BTreeMap<String, String>,
    key: &'static str,
    default: bool,
) -> Result<bool, ConfigError> {
    match optional(values, key) {
        None => Ok(default),
        Some("true") => Ok(true),
        Some("false") => Ok(false),
        Some(_) => Err(ConfigError::InvalidValue {
            key,
            reason: "must be `true` or `false`".to_owned(),
        }),
    }
}

fn validate_process_id(value: &str) -> Result<String, ConfigError> {
    if !(1..=128).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(ConfigError::InvalidValue {
            key: "OWLAUTH_AUTH_PROCESS_ID",
            reason: "must be 1 to 128 URL-safe opaque ASCII characters".to_owned(),
        });
    }
    Ok(value.to_owned())
}

fn validate_instance_id(value: String) -> Result<String, ConfigError> {
    if value.len() > 128 || value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(ConfigError::InvalidValue {
            key: "OWLAUTH_INSTANCE_ID",
            reason: "must be 1 to 128 opaque printable ASCII characters".to_owned(),
        });
    }
    Ok(value)
}

fn parse_value<T>(
    values: &BTreeMap<String, String>,
    key: &'static str,
    default: &str,
    reason: &str,
) -> Result<T, ConfigError>
where
    T: FromStr,
{
    optional(values, key)
        .unwrap_or(default)
        .parse()
        .map_err(|_| ConfigError::InvalidValue {
            key,
            reason: reason.to_owned(),
        })
}

fn parse_nonzero_u32(
    values: &BTreeMap<String, String>,
    key: &'static str,
    default: u32,
) -> Result<NonZeroU32, ConfigError> {
    let value = optional(values, key)
        .map(str::parse)
        .transpose()
        .map_err(|_| ConfigError::InvalidValue {
            key,
            reason: "must be a positive integer".to_owned(),
        })?
        .unwrap_or(default);
    NonZeroU32::new(value).ok_or_else(|| ConfigError::InvalidValue {
        key,
        reason: "must be greater than zero".to_owned(),
    })
}

#[derive(Clone, Copy)]
enum HttpBudgetPlane {
    Auth,
    Control,
}

fn parse_http_budget(
    values: &BTreeMap<String, String>,
    plane: HttpBudgetPlane,
) -> Result<HttpBudgetConfig, ConfigError> {
    let (timeout, body, in_flight, connections, header_count, header_bytes, uri_bytes, defaults) =
        match plane {
            HttpBudgetPlane::Auth => (
                "OWLAUTH_AUTH_REQUEST_TIMEOUT_MS",
                "OWLAUTH_AUTH_MAX_REQUEST_BYTES",
                "OWLAUTH_AUTH_MAX_IN_FLIGHT_REQUESTS",
                "OWLAUTH_AUTH_MAX_CONNECTIONS",
                "OWLAUTH_AUTH_MAX_HEADER_COUNT",
                "OWLAUTH_AUTH_MAX_HEADER_BYTES",
                "OWLAUTH_AUTH_MAX_URI_BYTES",
                (256, 512),
            ),
            HttpBudgetPlane::Control => (
                "OWLAUTH_CONTROL_REQUEST_TIMEOUT_MS",
                "OWLAUTH_CONTROL_MAX_REQUEST_BYTES",
                "OWLAUTH_CONTROL_MAX_IN_FLIGHT_REQUESTS",
                "OWLAUTH_CONTROL_MAX_CONNECTIONS",
                "OWLAUTH_CONTROL_MAX_HEADER_COUNT",
                "OWLAUTH_CONTROL_MAX_HEADER_BYTES",
                "OWLAUTH_CONTROL_MAX_URI_BYTES",
                (64, 128),
            ),
        };
    Ok(HttpBudgetConfig {
        request_timeout: parse_bounded_millis(
            values,
            timeout,
            10_000,
            Duration::from_millis(10),
            Duration::from_mins(1),
        )?,
        max_request_bytes: parse_bounded_usize(values, body, 1_048_576, 16_777_216)?,
        max_in_flight_requests: parse_bounded_usize(values, in_flight, defaults.0, 4096)?,
        max_connections: parse_bounded_usize(values, connections, defaults.1, 8192)?,
        max_header_count: parse_bounded_usize(values, header_count, 128, 512)?,
        max_header_bytes: parse_bounded_usize(values, header_bytes, 65_536, 262_144)?,
        max_uri_bytes: parse_bounded_usize(values, uri_bytes, 8_192, 65_536)?,
    })
}

fn parse_bounded_usize(
    values: &BTreeMap<String, String>,
    key: &'static str,
    default: usize,
    maximum: usize,
) -> Result<usize, ConfigError> {
    let value: usize = parse_value(
        values,
        key,
        &default.to_string(),
        "must be a positive integer",
    )?;
    if value == 0 || value > maximum {
        return Err(ConfigError::InvalidValue {
            key,
            reason: format!("must be between 1 and {maximum}"),
        });
    }
    Ok(value)
}

fn parse_millis(
    values: &BTreeMap<String, String>,
    key: &'static str,
    default: u64,
) -> Result<Duration, ConfigError> {
    let milliseconds: u64 = parse_value(
        values,
        key,
        &default.to_string(),
        "must be a positive integer number of milliseconds",
    )?;
    if milliseconds == 0 {
        return Err(ConfigError::InvalidValue {
            key,
            reason: "must be greater than zero".to_owned(),
        });
    }
    Ok(Duration::from_millis(milliseconds))
}

fn parse_bounded_millis(
    values: &BTreeMap<String, String>,
    key: &'static str,
    default: u64,
    minimum: Duration,
    maximum: Duration,
) -> Result<Duration, ConfigError> {
    let duration = parse_millis(values, key, default)?;
    if !(minimum..=maximum).contains(&duration) {
        return Err(ConfigError::InvalidValue {
            key,
            reason: format!(
                "must be between {} and {} milliseconds",
                minimum.as_millis(),
                maximum.as_millis()
            ),
        });
    }
    Ok(duration)
}

fn parse_external_base(key: &'static str, value: &str) -> Result<Url, ConfigError> {
    let url = Url::parse(value).map_err(|error| ConfigError::InvalidValue {
        key,
        reason: format!("must be an absolute HTTP(S) URL: {error}"),
    })?;
    let valid = matches!(url.scheme(), "http" | "https")
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && url.path().starts_with('/')
        && url.path().ends_with('/')
        && !value.contains('%')
        && !value.contains('\\');
    if !valid {
        return Err(ConfigError::InvalidValue {
            key,
            reason: "must be an absolute HTTP(S) origin plus canonical trailing-slash path"
                .to_owned(),
        });
    }
    Ok(url)
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn validate_external_bases(auth: &Url, control: &Url) -> Result<(), ConfigError> {
    if same_origin(auth, control) {
        let auth_path = auth.path();
        let control_path = control.path();
        if auth_path == "/"
            || control_path == "/"
            || auth_path.starts_with(control_path)
            || control_path.starts_with(auth_path)
        {
            return Err(ConfigError::SharedOriginBases);
        }
    }
    Ok(())
}

fn database_authority(
    value: &str,
    key: &'static str,
) -> Result<(String, String, u16, String), ConfigError> {
    let url = Url::parse(value).map_err(|error| ConfigError::InvalidValue {
        key,
        reason: format!("must be a PostgreSQL URL: {error}"),
    })?;
    if !matches!(url.scheme(), "postgres" | "postgresql")
        || url.host_str().is_none()
        || url.fragment().is_some()
        || url.path().len() <= 1
    {
        return Err(ConfigError::InvalidValue {
            key,
            reason: "must identify one PostgreSQL host, port, and database without a fragment"
                .to_owned(),
        });
    }
    Ok((
        "postgresql".to_owned(),
        url.host_str()
            .expect("host checked above")
            .to_ascii_lowercase(),
        url.port().unwrap_or(5432),
        url.path().to_owned(),
    ))
}

fn validate_database_authority(
    serving: &str,
    candidate: &str,
    candidate_key: &'static str,
) -> Result<(), ConfigError> {
    let expected = database_authority(serving, "OWLAUTH_POSTGRES_URL")?;
    let actual = database_authority(candidate, candidate_key)?;
    if expected != actual {
        return Err(ConfigError::DatabaseAuthority(candidate_key));
    }
    Ok(())
}

fn validate_role(value: &str) -> Result<String, ConfigError> {
    let mut bytes = value.bytes();
    let first = bytes.next();
    let valid = first.is_some_and(|byte| byte == b'_' || byte.is_ascii_lowercase())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_lowercase() || byte.is_ascii_digit());
    if !valid || value.len() > 63 {
        return Err(ConfigError::InvalidValue {
            key: "OWLAUTH_MIGRATION_OWNER_ROLE",
            reason: "must be a lowercase PostgreSQL identifier of at most 63 bytes".to_owned(),
        });
    }
    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    fn auth_values() -> BTreeMap<String, String> {
        values(&[
            (
                "OWLAUTH_POSTGRES_URL",
                "postgres://runtime:secret@database.example/owlauth",
            ),
            ("OWLAUTH_INSTANCE_ID", "test-deployment"),
            ("OWLAUTH_AUTH_PROCESS_ID", "test-auth"),
            ("OWLAUTH_REQUIRED_AUTH_PROCESS_IDS", "test-auth"),
            ("OWLAUTH_SERVER_KEY_DIGEST_KEY_VERSION", "1"),
            (
                "OWLAUTH_SERVER_KEY_DIGEST_KEY",
                "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo",
            ),
            ("OWLAUTH_RUNTIME_KEY_VERSION", "2"),
            ("OWLAUTH_MANAGED_REAUTHORIZATION_KEY_VERSION", "2"),
            (
                "OWLAUTH_MANAGED_REAUTHORIZATION_DIGEST_KEY",
                "CgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgo",
            ),
            (
                "OWLAUTH_MANAGED_REAUTHORIZATION_PROTECTION_KEY",
                "CwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCws",
            ),
            ("OWLAUTH_IDENTITY_MUTATION_EVIDENCE_KEY_VERSION", "1"),
            (
                "OWLAUTH_IDENTITY_MUTATION_EVIDENCE_DIGEST_KEY",
                "EBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBA",
            ),
            (
                "OWLAUTH_IDENTITY_MUTATION_EVIDENCE_PROTECTION_KEY",
                "ERERERERERERERERERERERERERERERERERERERERERE",
            ),
            (
                "OWLAUTH_RUNTIME_DIGEST_KEY",
                "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM",
            ),
            (
                "OWLAUTH_RUNTIME_PROTECTION_KEY",
                "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ",
            ),
            ("OWLAUTH_EMAIL_IDENTITY_KEY_VERSION", "2"),
            (
                "OWLAUTH_EMAIL_IDENTITY_DIGEST_KEY",
                "PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0",
            ),
            (
                "OWLAUTH_EMAIL_IDENTITY_PROTECTION_KEY",
                "Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4",
            ),
            ("OWLAUTH_PROJECTION_EMAIL_KEY_VERSION", "1"),
            (
                "OWLAUTH_PROJECTION_EMAIL_PROTECTION_KEY",
                "R0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0c",
            ),
            ("OWLAUTH_MANAGED_CREDENTIAL_KEY_VERSION", "1"),
            (
                "OWLAUTH_MANAGED_CREDENTIAL_KEY",
                "BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgY",
            ),
            (
                "OWLAUTH_ADMISSION_DIGEST_KEY",
                "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU",
            ),
        ])
    }

    fn control_store_values() -> BTreeMap<String, String> {
        values(&[(
            "OWLAUTH_SOFTWARE_CUSTODY_KEY",
            "Hh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4",
        )])
    }

    #[test]
    fn listener_http_budgets_are_independent_bounded_and_use_only_plane_keys() {
        let mut input = auth_values();
        input.extend(control_store_values());
        input.extend(values(&[
            ("OWLAUTH_AUTH_REQUEST_TIMEOUT_MS", "101"),
            ("OWLAUTH_AUTH_MAX_REQUEST_BYTES", "1001"),
            ("OWLAUTH_AUTH_MAX_IN_FLIGHT_REQUESTS", "11"),
            ("OWLAUTH_AUTH_MAX_CONNECTIONS", "21"),
            ("OWLAUTH_AUTH_MAX_HEADER_COUNT", "31"),
            ("OWLAUTH_AUTH_MAX_HEADER_BYTES", "10001"),
            ("OWLAUTH_AUTH_MAX_URI_BYTES", "2001"),
            ("OWLAUTH_CONTROL_REQUEST_TIMEOUT_MS", "103"),
            ("OWLAUTH_CONTROL_MAX_REQUEST_BYTES", "1003"),
            ("OWLAUTH_CONTROL_MAX_IN_FLIGHT_REQUESTS", "13"),
            ("OWLAUTH_CONTROL_MAX_CONNECTIONS", "23"),
            ("OWLAUTH_CONTROL_MAX_HEADER_COUNT", "33"),
            ("OWLAUTH_CONTROL_MAX_HEADER_BYTES", "10003"),
            ("OWLAUTH_CONTROL_MAX_URI_BYTES", "2003"),
        ]));
        let configured = ServerConfig::from_values(&input).expect("independent listener budgets");
        assert_eq!(
            configured.auth.http.request_timeout,
            Duration::from_millis(101)
        );
        assert_eq!(configured.auth.http.max_request_bytes, 1001);
        assert_eq!(configured.auth.http.max_in_flight_requests, 11);
        assert_eq!(configured.auth.http.max_connections, 21);
        assert_eq!(configured.auth.http.max_header_count, 31);
        assert_eq!(configured.auth.http.max_header_bytes, 10001);
        assert_eq!(configured.auth.http.max_uri_bytes, 2001);
        assert_eq!(
            configured.control.http.request_timeout,
            Duration::from_millis(103)
        );
        assert_eq!(configured.control.http.max_connections, 23);

        for (key, invalid) in [
            ("OWLAUTH_AUTH_REQUEST_TIMEOUT_MS", "9"),
            ("OWLAUTH_AUTH_MAX_REQUEST_BYTES", "0"),
            ("OWLAUTH_CONTROL_MAX_IN_FLIGHT_REQUESTS", "4097"),
            ("OWLAUTH_AUTH_MAX_CONNECTIONS", "8193"),
            ("OWLAUTH_AUTH_MAX_HEADER_COUNT", "513"),
            ("OWLAUTH_CONTROL_MAX_HEADER_BYTES", "262145"),
            ("OWLAUTH_AUTH_MAX_URI_BYTES", "65537"),
        ] {
            let mut rejected = input.clone();
            rejected.insert(key.to_owned(), invalid.to_owned());
            assert!(matches!(
                ServerConfig::from_values(&rejected),
                Err(ConfigError::InvalidValue { key: rejected_key, .. }) if rejected_key == key
            ));
        }

        for removed in [
            "OWLAUTH_REQUEST_TIMEOUT_MS",
            "OWLAUTH_MAX_REQUEST_BYTES",
            "OWLAUTH_RUNTIME_ADDR",
            "OWLAUTH_RUNTIME_BASE_URL",
            "OWLAUTH_CLIENT_ADDR",
            "OWLAUTH_CLIENT_BASE_URL",
            "OWLAUTH_CLIENT_REQUEST_TIMEOUT_MS",
        ] {
            let mut rejected = input.clone();
            rejected.insert(removed.to_owned(), "1000".to_owned());
            assert!(matches!(
                ServerConfig::from_values(&rejected),
                Err(ConfigError::Unknown(key)) if key == removed
            ));
        }
    }

    #[test]
    fn database_lock_and_migration_timeouts_are_bounded_and_independent() {
        let mut input = auth_values();
        input.extend(control_store_values());
        let config = ServerConfig::from_values(&input).expect("default database timeout model");
        assert_eq!(
            config.postgres.database_lock_timeout,
            Duration::from_secs(5)
        );
        assert_eq!(
            config.postgres.migration_lock_timeout,
            Duration::from_secs(30)
        );
        assert_eq!(
            config.postgres.migration_statement_timeout,
            Duration::from_mins(5)
        );
        assert_eq!(config.postgres.migration_deadline, Duration::from_mins(30));
        assert!(!format!("{:?}", config.postgres).contains("runtime:secret"));

        for (key, value) in [
            ("OWLAUTH_DATABASE_LOCK_TIMEOUT_MS", "9"),
            ("OWLAUTH_DATABASE_LOCK_TIMEOUT_MS", "60001"),
            ("OWLAUTH_MIGRATION_LOCK_TIMEOUT_MS", "9"),
            ("OWLAUTH_MIGRATION_LOCK_TIMEOUT_MS", "300001"),
            ("OWLAUTH_MIGRATION_STATEMENT_TIMEOUT_MS", "99"),
            ("OWLAUTH_MIGRATION_STATEMENT_TIMEOUT_MS", "3600001"),
            ("OWLAUTH_MIGRATION_DEADLINE_MS", "999"),
            ("OWLAUTH_MIGRATION_DEADLINE_MS", "86400001"),
        ] {
            let mut invalid = input.clone();
            invalid.insert(key.to_owned(), value.to_owned());
            assert!(matches!(
                ServerConfig::from_values(&invalid),
                Err(ConfigError::InvalidValue { key: actual, .. }) if actual == key
            ));
        }

        let mut ordered = input.clone();
        ordered.insert(
            "OWLAUTH_MIGRATION_STATEMENT_TIMEOUT_MS".to_owned(),
            "1000".to_owned(),
        );
        ordered.insert(
            "OWLAUTH_MIGRATION_DEADLINE_MS".to_owned(),
            "1000".to_owned(),
        );
        assert!(matches!(
            ServerConfig::from_values(&ordered),
            Err(ConfigError::InvalidValue {
                key: "OWLAUTH_MIGRATION_DEADLINE_MS",
                ..
            })
        ));

        for (key, value) in [
            ("OWLAUTH_DATABASE_LOCK_TIMEOUT_MS", "60000"),
            ("OWLAUTH_MIGRATION_LOCK_TIMEOUT_MS", "300000"),
            ("OWLAUTH_MIGRATION_STATEMENT_TIMEOUT_MS", "3600000"),
            ("OWLAUTH_MIGRATION_DEADLINE_MS", "3600001"),
        ] {
            input.insert(key.to_owned(), value.to_owned());
        }
        let maximums = ServerConfig::from_values(&input).expect("bounded timeout maxima");
        assert_eq!(
            maximums.postgres.database_lock_timeout,
            MAX_DATABASE_LOCK_TIMEOUT
        );
        assert_eq!(
            maximums.postgres.migration_lock_timeout,
            MAX_MIGRATION_LOCK_TIMEOUT
        );
        assert_eq!(
            maximums.postgres.migration_statement_timeout,
            MAX_MIGRATION_STATEMENT_TIMEOUT
        );
    }

    #[test]
    fn deployment_smtp_registry_is_all_or_none_and_private_allowlist_is_bounded() {
        let mut input = values(&[
            ("OWLAUTH_DEPLOYMENT_SMTP_GENERATION", "7"),
            ("OWLAUTH_DEPLOYMENT_SMTP_STATUS", "active"),
            ("OWLAUTH_DEPLOYMENT_SMTP_HOST", "smtp.example.test"),
            ("OWLAUTH_DEPLOYMENT_SMTP_PORT", "465"),
            ("OWLAUTH_DEPLOYMENT_SMTP_TLS_MODE", "implicit_tls"),
            (
                "OWLAUTH_DEPLOYMENT_SMTP_SENDER_ADDRESS",
                "login@example.test",
            ),
            (
                "OWLAUTH_DEPLOYMENT_SMTP_SAFE_FINGERPRINT",
                "1111111111111111111111111111111111111111111111111111111111111111",
            ),
            (
                "OWLAUTH_DEPLOYMENT_SMTP_ALLOWED_PRIVATE_IPS",
                "10.0.0.8,100.64.0.8,fc00::8",
            ),
        ]);
        let configured = parse_deployment_smtp(&input)
            .expect("deployment SMTP config")
            .expect("configured generation");
        assert_eq!(configured.explicitly_allowed_private_ips.len(), 3);
        assert!(configured.safe_fingerprint.is_some());

        input.insert(
            "OWLAUTH_DEPLOYMENT_SMTP_STATUS".to_owned(),
            "reconciled".to_owned(),
        );
        input.remove("OWLAUTH_DEPLOYMENT_SMTP_SAFE_FINGERPRINT");
        assert!(
            parse_deployment_smtp(&input)
                .expect("pre-seal reconciled deployment SMTP config")
                .expect("configured generation")
                .safe_fingerprint
                .is_none()
        );
        input.insert(
            "OWLAUTH_DEPLOYMENT_SMTP_STATUS".to_owned(),
            "active".to_owned(),
        );
        assert!(parse_deployment_smtp(&input).is_err());
        input.insert(
            "OWLAUTH_DEPLOYMENT_SMTP_SAFE_FINGERPRINT".to_owned(),
            "1111111111111111111111111111111111111111111111111111111111111111".to_owned(),
        );

        let maximum_allowlist = (1..=16)
            .map(|suffix| format!("10.0.0.{suffix}"))
            .collect::<Vec<_>>()
            .join(",");
        input.insert(
            "OWLAUTH_DEPLOYMENT_SMTP_ALLOWED_PRIVATE_IPS".to_owned(),
            maximum_allowlist.clone(),
        );
        let configured = parse_deployment_smtp(&input)
            .expect("maximum private relay allowlist")
            .expect("configured generation");
        assert_eq!(configured.explicitly_allowed_private_ips.len(), 16);
        input.insert(
            "OWLAUTH_DEPLOYMENT_SMTP_ALLOWED_PRIVATE_IPS".to_owned(),
            format!("{maximum_allowlist},10.0.0.17"),
        );
        assert!(parse_deployment_smtp(&input).is_err());

        input.insert(
            "OWLAUTH_DEPLOYMENT_SMTP_ALLOWED_PRIVATE_IPS".to_owned(),
            "169.254.169.254".to_owned(),
        );
        assert!(parse_deployment_smtp(&input).is_err());
        input.remove("OWLAUTH_DEPLOYMENT_SMTP_ALLOWED_PRIVATE_IPS");
        input.remove("OWLAUTH_DEPLOYMENT_SMTP_HOST");
        assert!(parse_deployment_smtp(&input).is_err());
    }

    #[test]
    fn webhook_private_allowlist_is_exact_bounded_and_fail_closed() {
        let mut input = auth_values();
        input.extend(control_store_values());
        input.insert(
            "OWLAUTH_WEBHOOK_ALLOWED_PRIVATE_IPS".to_owned(),
            "10.0.0.8,fc00::8,10.0.0.8".to_owned(),
        );
        let config = ServerConfig::from_values(&input).expect("valid exact webhook allowlist");
        assert_eq!(
            config.webhook_allowed_private_ips,
            ["10.0.0.8", "fc00::8"].map(|value| value.parse::<IpAddr>().unwrap())
        );

        input.insert(
            "OWLAUTH_WEBHOOK_ALLOWED_PRIVATE_IPS".to_owned(),
            "169.254.169.254".to_owned(),
        );
        assert!(matches!(
            ServerConfig::from_values(&input),
            Err(ConfigError::InvalidValue {
                key: "OWLAUTH_WEBHOOK_ALLOWED_PRIVATE_IPS",
                ..
            })
        ));
    }

    #[test]
    fn publication_lease_ttl_cannot_exceed_projection_authority_bound() {
        let mut input = auth_values();
        input.extend(control_store_values());
        input.insert(
            "OWLAUTH_PUBLICATION_LEASE_TTL_MS".to_owned(),
            "43201000".to_owned(),
        );
        assert!(matches!(
            ServerConfig::from_values(&input),
            Err(ConfigError::InvalidValue {
                key: "OWLAUTH_PUBLICATION_LEASE_TTL_MS",
                ..
            })
        ));

        input.insert(
            "OWLAUTH_PUBLICATION_LEASE_TTL_MS".to_owned(),
            "43200999".to_owned(),
        );
        assert_eq!(
            ServerConfig::from_values(&input)
                .expect("maximum publication TTL must derive an exact one-day projection lease")
                .publication_lease_ttl,
            MAX_PUBLICATION_LEASE_TTL
        );
    }

    #[test]
    fn runtime_key_inventory_cannot_exceed_email_alias_bound() {
        let mut input = auth_values();
        let retained = (10..26)
            .map(|version| {
                (
                    version.to_string(),
                    serde_json::json!({
                        "digest_key": "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM",
                        "protection_key": "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ"
                    }),
                )
            })
            .collect::<serde_json::Map<_, _>>();
        input.insert(
            "OWLAUTH_RUNTIME_RETAINED_KEYS".to_owned(),
            serde_json::Value::Object(retained).to_string(),
        );
        assert!(matches!(
            parse_runtime_protection(ProcessMode::Auth, &input),
            Err(ConfigError::InvalidValue {
                key: "OWLAUTH_RUNTIME_RETAINED_KEYS",
                ..
            })
        ));
    }

    #[test]
    fn alias_cutover_and_retirement_cannot_be_pre_authorized_together() {
        let mut input = auth_values();
        input.insert(
            "OWLAUTH_EMAIL_IDENTITY_ALIAS_CUTOVER_VERSION".to_owned(),
            "2".to_owned(),
        );
        input.insert(
            "OWLAUTH_EMAIL_IDENTITY_ALIAS_RETIRE_VERSION".to_owned(),
            "2".to_owned(),
        );
        for mode in [ProcessMode::Auth, ProcessMode::All] {
            assert!(matches!(
                parse_email_identity_protection(mode, &input),
                Err(ConfigError::InvalidValue {
                    key: "OWLAUTH_EMAIL_IDENTITY_ALIAS_RETIRE_VERSION",
                    ..
                })
            ));
        }
    }

    #[test]
    fn alias_retirement_configuration_is_distinct_and_active_version_bound() {
        let mut input = auth_values();
        input.insert(
            "OWLAUTH_EMAIL_IDENTITY_ALIAS_RETIRE_VERSION".to_owned(),
            "1".to_owned(),
        );
        assert!(matches!(
            parse_email_identity_protection(ProcessMode::Auth, &input),
            Err(ConfigError::InvalidValue {
                key: "OWLAUTH_EMAIL_IDENTITY_ALIAS_RETIRE_VERSION",
                ..
            })
        ));
        input.insert(
            "OWLAUTH_EMAIL_IDENTITY_ALIAS_RETIRE_VERSION".to_owned(),
            "2".to_owned(),
        );
        let protection = parse_email_identity_protection(ProcessMode::Auth, &input)
            .expect("valid retirement authorization")
            .expect("email identity protection");
        assert_eq!(protection.identity_alias_cutover_version, None);
        assert_eq!(protection.identity_alias_retire_version, Some(2));
    }

    #[test]
    fn missing_email_identity_ring_is_scoped_and_control_loads_only_the_narrow_source_ring() {
        let mut runtime = auth_values();
        for key in [
            "OWLAUTH_EMAIL_IDENTITY_KEY_VERSION",
            "OWLAUTH_EMAIL_IDENTITY_DIGEST_KEY",
            "OWLAUTH_EMAIL_IDENTITY_PROTECTION_KEY",
        ] {
            runtime.remove(key);
        }
        runtime.extend(control_store_values());
        let configured = ServerConfig::from_values(&runtime)
            .expect("provider/session Runtime remains composable without long-term email keys");
        assert!(configured.email_identity_protection.is_none());

        let source = auth_values();
        let control = BTreeMap::from([
            (
                "OWLAUTH_EMAIL_IDENTITY_KEY_VERSION".to_owned(),
                source["OWLAUTH_EMAIL_IDENTITY_KEY_VERSION"].clone(),
            ),
            (
                "OWLAUTH_EMAIL_IDENTITY_DIGEST_KEY".to_owned(),
                source["OWLAUTH_EMAIL_IDENTITY_DIGEST_KEY"].clone(),
            ),
            (
                "OWLAUTH_EMAIL_IDENTITY_PROTECTION_KEY".to_owned(),
                source["OWLAUTH_EMAIL_IDENTITY_PROTECTION_KEY"].clone(),
            ),
        ]);
        assert!(
            parse_email_identity_protection(ProcessMode::Control, &control)
                .expect("Control exact source-reader ring")
                .is_some()
        );
    }

    #[test]
    fn auth_mode_loads_provider_authority_without_control_credentials() {
        const { assert!(FEDERATED_PROJECT_AUTH_AVAILABLE) };
        assert!(ServerConfig::from_values(&auth_values()).is_err());

        let mut input = auth_values();
        input.extend(control_store_values());
        input.insert(
            "OWLAUTH_CONTROL_API_KEY".to_owned(),
            "this value must not be loaded".to_owned(),
        );
        let config = ServerConfig::from_values(&input)
            .expect("Runtime auth requires the bundled software provider root");
        assert_eq!(config.mode, ProcessMode::Auth);
        assert!(config.control_api_key.is_none());
        assert!(config.provisioning.is_some());
        let debug = format!("{config:?}");
        assert!(!debug.contains("this value"));
        assert!(!debug.contains("AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM"));
    }

    #[test]
    fn custom_provider_parser_does_not_require_the_bundled_software_root() {
        let mut input = auth_values();
        input.extend(control_store_values());
        input.remove("OWLAUTH_SOFTWARE_CUSTODY_KEY");
        assert!(ServerConfig::from_values(&input).is_err());
        let config = ServerConfig::from_values_with_requirements(&input, false)
            .expect("custom provider composition owns its provider configuration");
        assert!(
            config
                .provisioning
                .expect("provider composition remains available")
                .software_custody_key
                .is_none()
        );
    }

    #[test]
    fn managed_credential_ring_is_runtime_only_distinct_and_rotation_aware() {
        let mut input = auth_values();
        input.extend(control_store_values());
        let config =
            ServerConfig::from_values(&input).expect("dedicated managed ring should parse");
        let ring = config
            .managed_credential_protection
            .as_ref()
            .expect("Runtime managed capability owns a dedicated ring");
        assert_eq!(ring.active_version, 1);
        assert!(ring.retained.is_empty());
        assert!(!format!("{config:?}").contains("BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgY"));

        input.insert(
            "OWLAUTH_MANAGED_CREDENTIAL_KEY".to_owned(),
            "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ".to_owned(),
        );
        assert!(matches!(
            ServerConfig::from_values(&input),
            Err(ConfigError::InvalidValue {
                key: "OWLAUTH_MANAGED_CREDENTIAL_KEY",
                ..
            })
        ));
        input.insert(
            "OWLAUTH_MANAGED_CREDENTIAL_KEY".to_owned(),
            "BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgY".to_owned(),
        );
        input.insert(
            "OWLAUTH_RUNTIME_RETAINED_KEYS".to_owned(),
            r#"{"1":{"digest_key":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc","protection_key":"CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg"}}"#
                .to_owned(),
        );
        input.insert(
            "OWLAUTH_MANAGED_CREDENTIAL_RETAINED_KEYS".to_owned(),
            r#"{"2":"CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg"}"#.to_owned(),
        );
        assert!(matches!(
            ServerConfig::from_values(&input),
            Err(ConfigError::InvalidValue {
                key: "OWLAUTH_MANAGED_CREDENTIAL_KEY",
                ..
            })
        ));
        input.insert(
            "OWLAUTH_MANAGED_CREDENTIAL_RETAINED_KEYS".to_owned(),
            r#"{"2":"CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk"}"#.to_owned(),
        );
        let rotated =
            ServerConfig::from_values(&input).expect("distinct retained ring should parse");
        assert_eq!(
            rotated
                .managed_credential_protection
                .expect("managed ring")
                .retained
                .keys()
                .copied()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([2])
        );
    }

    #[test]
    fn every_runtime_protection_root_is_unique_across_active_and_retained_rings() {
        let mut email_retained_aliases_managed_active = auth_values();
        email_retained_aliases_managed_active.extend(control_store_values());
        email_retained_aliases_managed_active.insert(
            "OWLAUTH_EMAIL_IDENTITY_RETAINED_KEYS".to_owned(),
            r#"{"1":{"digest_key":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc","protection_key":"BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgY"}}"#
                .to_owned(),
        );
        assert!(matches!(
            ServerConfig::from_values(&email_retained_aliases_managed_active),
            Err(ConfigError::InvalidValue {
                key: "OWLAUTH_MANAGED_CREDENTIAL_KEY",
                ..
            })
        ));

        let mut managed_retained_aliases_email_active = auth_values();
        managed_retained_aliases_email_active.extend(control_store_values());
        managed_retained_aliases_email_active.insert(
            "OWLAUTH_MANAGED_CREDENTIAL_RETAINED_KEYS".to_owned(),
            r#"{"2":"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0"}"#.to_owned(),
        );
        assert!(matches!(
            ServerConfig::from_values(&managed_retained_aliases_email_active),
            Err(ConfigError::InvalidValue {
                key: "OWLAUTH_MANAGED_CREDENTIAL_KEY",
                ..
            })
        ));

        let mut target_retained_aliases_email_active = auth_values();
        target_retained_aliases_email_active.extend(control_store_values());
        target_retained_aliases_email_active.insert(
            "OWLAUTH_MANAGED_REAUTHORIZATION_RETAINED_KEYS".to_owned(),
            r#"{"1":{"digest_key":"DAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw","protection_key":"Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4"}}"#
                .to_owned(),
        );
        assert!(matches!(
            ServerConfig::from_values(&target_retained_aliases_email_active),
            Err(ConfigError::InvalidValue {
                key: "OWLAUTH_MANAGED_REAUTHORIZATION_PROTECTION_KEY",
                ..
            })
        ));

        let mut email_retained_aliases_target_active = auth_values();
        email_retained_aliases_target_active.extend(control_store_values());
        email_retained_aliases_target_active.insert(
            "OWLAUTH_EMAIL_IDENTITY_RETAINED_KEYS".to_owned(),
            r#"{"1":{"digest_key":"CgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgo","protection_key":"DQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0"}}"#
                .to_owned(),
        );
        assert!(matches!(
            ServerConfig::from_values(&email_retained_aliases_target_active),
            Err(ConfigError::InvalidValue {
                key: "OWLAUTH_MANAGED_REAUTHORIZATION_DIGEST_KEY",
                ..
            })
        ));
    }

    #[test]
    fn identity_mutation_evidence_ring_is_required_rotatable_redacted_and_globally_separate() {
        let mut input = auth_values();
        input.extend(control_store_values());
        input.insert(
            "OWLAUTH_CONTROL_API_KEY".to_owned(),
            format!("owl_ctrl_v1_{}", "A".repeat(43)),
        );
        input.insert(
            "OWLAUTH_IDENTITY_MUTATION_EVIDENCE_RETAINED_KEYS".to_owned(),
            r#"{"2":{"digest_key":"EhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhI","protection_key":"ExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExM"}}"#
                .to_owned(),
        );
        for mode in [ProcessMode::Auth, ProcessMode::Control, ProcessMode::All] {
            input.insert(
                "OWLAUTH_MODE".to_owned(),
                match mode {
                    ProcessMode::Auth => "auth",
                    ProcessMode::Control => "control",
                    ProcessMode::All => "all",
                }
                .to_owned(),
            );
            input.insert(
                "OWLAUTH_REQUIRED_AUTH_PROCESS_IDS".to_owned(),
                if mode == ProcessMode::Control {
                    "auth-a"
                } else {
                    "test-auth"
                }
                .to_owned(),
            );
            let config = ServerConfig::from_values(&input)
                .expect("every serving mode requires the dedicated evidence ring");
            assert_eq!(
                config.identity_mutation_evidence_protection.active_version,
                1
            );
            assert_eq!(
                config
                    .identity_mutation_evidence_protection
                    .retained
                    .keys()
                    .copied()
                    .collect::<BTreeSet<_>>(),
                BTreeSet::from([2])
            );
            let debug = format!("{config:?}");
            assert!(!debug.contains("EBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBA"));
            assert!(!debug.contains("ERERERERERERERERERERERERERERERERERERERERERE"));
        }

        input.remove("OWLAUTH_IDENTITY_MUTATION_EVIDENCE_DIGEST_KEY");
        assert!(matches!(
            ServerConfig::from_values(&input),
            Err(ConfigError::Missing(
                "OWLAUTH_IDENTITY_MUTATION_EVIDENCE_DIGEST_KEY"
            ))
        ));
        input.insert(
            "OWLAUTH_IDENTITY_MUTATION_EVIDENCE_DIGEST_KEY".to_owned(),
            "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM".to_owned(),
        );
        assert!(matches!(
            ServerConfig::from_values(&input),
            Err(ConfigError::InvalidValue {
                key: "OWLAUTH_IDENTITY_MUTATION_EVIDENCE_DIGEST_KEY",
                ..
            })
        ));
    }

    #[test]
    fn projection_email_ring_accepts_only_aead_keys() {
        let mut input = auth_values();
        input.extend(control_store_values());
        input.insert(
            "OWLAUTH_PROJECTION_EMAIL_RETAINED_KEYS".to_owned(),
            r#"{"2":"SEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEg"}"#.to_owned(),
        );
        let config = ServerConfig::from_values(&input).expect("AEAD-only projection ring parses");
        assert_eq!(
            config
                .projection_email_protection
                .retained
                .keys()
                .copied()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([2])
        );

        for invalid in [
            r#"{"2":{"digest_key":"SEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEg","protection_key":"SUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUk"}}"#,
            r#"{"2":"SEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEg","2":"SUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUk"}"#,
        ] {
            input.insert(
                "OWLAUTH_PROJECTION_EMAIL_RETAINED_KEYS".to_owned(),
                invalid.to_owned(),
            );
            assert!(matches!(
                ServerConfig::from_values(&input),
                Err(ConfigError::InvalidValue {
                    key: "OWLAUTH_PROJECTION_EMAIL_RETAINED_KEYS",
                    ..
                })
            ));
        }
    }

    #[test]
    fn projection_roots_are_separate_from_admission_and_provisioning_roots() {
        let families = [
            (
                "OWLAUTH_SOFTWARE_CUSTODY_KEY",
                "Hh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4",
            ),
            (
                "OWLAUTH_ADMISSION_DIGEST_KEY",
                "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU",
            ),
        ];
        for (family_key, family_material) in families {
            let mut active_alias = auth_values();
            active_alias.extend(control_store_values());
            active_alias.insert(
                "OWLAUTH_PROJECTION_EMAIL_PROTECTION_KEY".to_owned(),
                family_material.to_owned(),
            );
            assert!(matches!(
                ServerConfig::from_values(&active_alias),
                Err(ConfigError::InvalidValue { key, .. }) if key == family_key
            ));

            let mut retained_alias = auth_values();
            retained_alias.extend(control_store_values());
            retained_alias.insert(
                "OWLAUTH_PROJECTION_EMAIL_RETAINED_KEYS".to_owned(),
                format!(r#"{{"2":"{family_material}"}}"#),
            );
            assert!(matches!(
                ServerConfig::from_values(&retained_alias),
                Err(ConfigError::InvalidValue { key, .. }) if key == family_key
            ));
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one matrix proves dedicated target-ring rotation and every fail-closed alias case"
    )]
    fn managed_reauthorization_target_ring_is_dedicated_rotatable_and_fail_closed() {
        let mut input = auth_values();
        input.extend(control_store_values());
        input.insert(
            "OWLAUTH_MANAGED_REAUTHORIZATION_RETAINED_KEYS".to_owned(),
            r#"{"1":{"digest_key":"DAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw","protection_key":"DQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0"}}"#
                .to_owned(),
        );
        let rotated = ServerConfig::from_values(&input).expect("dedicated target rotation parses");
        assert_eq!(
            rotated
                .managed_reauthorization_target_protection
                .retained
                .keys()
                .copied()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([1])
        );

        input.insert(
            "OWLAUTH_MANAGED_REAUTHORIZATION_DIGEST_KEY".to_owned(),
            "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM".to_owned(),
        );
        assert!(matches!(
            ServerConfig::from_values(&input),
            Err(ConfigError::InvalidValue {
                key: "OWLAUTH_MANAGED_REAUTHORIZATION_DIGEST_KEY",
                ..
            })
        ));

        let mut managed_alias = auth_values();
        managed_alias.extend(control_store_values());
        managed_alias.insert(
            "OWLAUTH_MANAGED_REAUTHORIZATION_PROTECTION_KEY".to_owned(),
            "BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgY".to_owned(),
        );
        assert!(matches!(
            ServerConfig::from_values(&managed_alias),
            Err(ConfigError::InvalidValue {
                key: "OWLAUTH_MANAGED_REAUTHORIZATION_PROTECTION_KEY",
                ..
            })
        ));
        managed_alias.insert(
            "OWLAUTH_MANAGED_REAUTHORIZATION_PROTECTION_KEY".to_owned(),
            "Dg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4".to_owned(),
        );
        managed_alias.insert(
            "OWLAUTH_MANAGED_CREDENTIAL_RETAINED_KEYS".to_owned(),
            r#"{"3":"Dg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4"}"#.to_owned(),
        );
        assert!(matches!(
            ServerConfig::from_values(&managed_alias),
            Err(ConfigError::InvalidValue {
                key: "OWLAUTH_MANAGED_REAUTHORIZATION_PROTECTION_KEY",
                ..
            })
        ));

        let mut admission_alias = auth_values();
        admission_alias.extend(control_store_values());
        admission_alias.insert(
            "OWLAUTH_ADMISSION_DIGEST_KEY".to_owned(),
            "CgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgo".to_owned(),
        );
        assert!(matches!(
            ServerConfig::from_values(&admission_alias),
            Err(ConfigError::InvalidValue {
                key: "OWLAUTH_ADMISSION_DIGEST_KEY",
                ..
            })
        ));

        let mut control = auth_values();
        control.extend(control_store_values());
        control.insert("OWLAUTH_MODE".to_owned(), "control".to_owned());
        control.insert(
            "OWLAUTH_CONTROL_API_KEY".to_owned(),
            "owl_ctrl_v1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
        );
        control.insert(
            "OWLAUTH_REQUIRED_AUTH_PROCESS_IDS".to_owned(),
            "auth-a".to_owned(),
        );
        control.remove("OWLAUTH_AUTH_PROCESS_ID");
        for key in [
            "OWLAUTH_RUNTIME_KEY_VERSION",
            "OWLAUTH_RUNTIME_DIGEST_KEY",
            "OWLAUTH_RUNTIME_PROTECTION_KEY",
            "OWLAUTH_RUNTIME_RETAINED_KEYS",
            "OWLAUTH_EMAIL_IDENTITY_KEY_VERSION",
            "OWLAUTH_EMAIL_IDENTITY_DIGEST_KEY",
            "OWLAUTH_EMAIL_IDENTITY_PROTECTION_KEY",
            "OWLAUTH_EMAIL_IDENTITY_RETAINED_KEYS",
            "OWLAUTH_EMAIL_IDENTITY_ALIAS_CUTOVER_VERSION",
            "OWLAUTH_EMAIL_IDENTITY_ALIAS_RETIRE_VERSION",
        ] {
            control.remove(key);
        }
        let control = ServerConfig::from_values(&control)
            .expect("Control-only requires the dedicated issuer but no generic Runtime roots");
        assert!(control.runtime_protection.is_none());
        assert_eq!(
            control
                .managed_reauthorization_target_protection
                .active_version,
            2
        );
    }

    #[test]
    fn runtime_admission_configuration_is_bounded_and_redacted() {
        let mut input = auth_values();
        input.extend(control_store_values());
        input.insert(
            "OWLAUTH_ADMISSION_REDIS_URL".to_owned(),
            "rediss://admission-user:admission-secret@redis.example/0".to_owned(),
        );
        input.insert(
            "OWLAUTH_ADMISSION_NAMESPACE".to_owned(),
            "deployment_a".to_owned(),
        );
        input.insert("OWLAUTH_AUTH_MAX_PROCESSES".to_owned(), "4".to_owned());
        let config = ServerConfig::from_values(&input).expect("admission config should parse");
        let admission = config.admission.as_ref().expect("Runtime has admission");
        assert_eq!(admission.namespace, "deployment_a");
        assert_eq!(
            admission
                .auth_maximum_processes
                .expect("Runtime bound is configured")
                .get(),
            4
        );
        let debug = format!("{config:?}");
        assert!(!debug.contains("admission-secret"));
        assert!(!debug.contains("BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU"));

        input.insert(
            "OWLAUTH_ADMISSION_REDIS_URL".to_owned(),
            "https://redis.example/".to_owned(),
        );
        assert!(matches!(
            ServerConfig::from_values(&input),
            Err(ConfigError::InvalidValue {
                key: "OWLAUTH_ADMISSION_REDIS_URL",
                ..
            })
        ));

        input.insert(
            "OWLAUTH_ADMISSION_REDIS_URL".to_owned(),
            "redis://redis.example/not-a-database?unsafe=true".to_owned(),
        );
        assert!(matches!(
            ServerConfig::from_values(&input),
            Err(ConfigError::InvalidValue {
                key: "OWLAUTH_ADMISSION_REDIS_URL",
                ..
            })
        ));

        input.insert(
            "OWLAUTH_ADMISSION_REDIS_URL".to_owned(),
            "redis://redis.example/0".to_owned(),
        );
        input.insert(
            "OWLAUTH_ADMISSION_DIGEST_KEY".to_owned(),
            "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM".to_owned(),
        );
        assert!(matches!(
            ServerConfig::from_values(&input),
            Err(ConfigError::InvalidValue {
                key: "OWLAUTH_ADMISSION_DIGEST_KEY",
                ..
            })
        ));
        input.insert(
            "OWLAUTH_ADMISSION_DIGEST_KEY".to_owned(),
            "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU".to_owned(),
        );
        input.insert(
            "OWLAUTH_REQUIRED_AUTH_PROCESS_IDS".to_owned(),
            "test-auth,auth-b,auth-c,auth-d,auth-e".to_owned(),
        );
        assert!(matches!(
            ServerConfig::from_values(&input),
            Err(ConfigError::InvalidValue {
                key: "OWLAUTH_AUTH_MAX_PROCESSES",
                ..
            })
        ));
    }

    #[test]
    fn control_roster_is_bounded_before_capability_composition() {
        let mut input = auth_values();
        input.extend(control_store_values());
        input.insert("OWLAUTH_MODE".to_owned(), "control".to_owned());
        input.insert(
            "OWLAUTH_CONTROL_API_KEY".to_owned(),
            "owl_ctrl_v1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
        );
        input.remove("OWLAUTH_AUTH_PROCESS_ID");
        input.insert(
            "OWLAUTH_REQUIRED_AUTH_PROCESS_IDS".to_owned(),
            (0..=MAX_AUTH_PROCESSES)
                .map(|index| format!("auth-{index}"))
                .collect::<Vec<_>>()
                .join(","),
        );

        assert!(matches!(
            ServerConfig::from_values(&input),
            Err(ConfigError::InvalidValue {
                key: "OWLAUTH_REQUIRED_AUTH_PROCESS_IDS",
                ..
            })
        ));
    }

    #[test]
    fn admission_process_bound_covers_the_auth_roster() {
        let mut input = values(&[
            (
                "OWLAUTH_ADMISSION_DIGEST_KEY",
                "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU",
            ),
            ("OWLAUTH_AUTH_MAX_PROCESSES", "64"),
        ]);
        let admission = parse_admission(ProcessMode::All, &input, "deployment-a", 2)
            .expect("Auth process bound should parse")
            .expect("All mode has admission");
        assert_eq!(
            admission
                .auth_maximum_processes
                .expect("Auth bound is configured")
                .get(),
            64
        );

        input.insert("OWLAUTH_AUTH_MAX_PROCESSES".to_owned(), "1".to_owned());
        assert!(matches!(
            parse_admission(ProcessMode::All, &input, "deployment-a", 2),
            Err(ConfigError::InvalidValue {
                key: "OWLAUTH_AUTH_MAX_PROCESSES",
                ..
            })
        ));
    }

    #[test]
    fn provider_http_loopback_policy_is_an_explicit_boolean() {
        let mut input = auth_values();
        input.extend(control_store_values());
        let config = ServerConfig::from_values(&input)
            .expect("provider HTTP loopback is disabled by default");
        assert!(!config.provider_allow_http_loopback);

        input.insert(
            "OWLAUTH_PROVIDER_ALLOW_HTTP_LOOPBACK".to_owned(),
            "true".to_owned(),
        );
        let config = ServerConfig::from_values(&input)
            .expect("explicit development policy enables loopback HTTP");
        assert!(config.provider_allow_http_loopback);

        input.insert(
            "OWLAUTH_PROVIDER_ALLOW_HTTP_LOOPBACK".to_owned(),
            "yes".to_owned(),
        );
        assert!(matches!(
            ServerConfig::from_values(&input),
            Err(ConfigError::InvalidValue {
                key: "OWLAUTH_PROVIDER_ALLOW_HTTP_LOOPBACK",
                ..
            })
        ));
    }

    #[test]
    fn control_and_all_modes_retain_provisioning_stores() {
        for mode in ["control", "all"] {
            let mut input = auth_values();
            input.extend(control_store_values());
            input.insert("OWLAUTH_MODE".to_owned(), mode.to_owned());
            input.insert(
                "OWLAUTH_CONTROL_API_KEY".to_owned(),
                format!(
                    "{CONTROL_KEY_PREFIX}{}",
                    "A".repeat(CONTROL_KEY_SECRET_LENGTH)
                ),
            );
            if mode == "control" {
                for key in [
                    "OWLAUTH_EMAIL_IDENTITY_KEY_VERSION",
                    "OWLAUTH_EMAIL_IDENTITY_DIGEST_KEY",
                    "OWLAUTH_EMAIL_IDENTITY_PROTECTION_KEY",
                ] {
                    input.remove(key);
                }
                input.insert(
                    "OWLAUTH_REQUIRED_AUTH_PROCESS_IDS".to_owned(),
                    "auth-a".to_owned(),
                );
            }
            let config = ServerConfig::from_values(&input)
                .expect("Control composition must retain provisioning stores");
            assert!(config.provisioning.is_some(), "mode {mode}");
            if mode == "control" {
                assert!(
                    config.runtime_protection.is_none(),
                    "Control-only must not parse or retain generic Runtime roots"
                );
                assert!(
                    config.managed_credential_protection.is_none(),
                    "Control-only must not receive managed credential custody"
                );
            } else {
                assert!(config.runtime_protection.is_some());
                assert!(config.managed_credential_protection.is_some());
            }
            assert_eq!(
                config
                    .managed_reauthorization_target_protection
                    .active_version,
                2,
                "every serving plane receives only the dedicated target capability"
            );
        }
    }

    #[test]
    fn control_requires_exact_canonical_key() {
        let mut input = auth_values();
        input.insert("OWLAUTH_MODE".to_owned(), "control".to_owned());
        input.insert(
            "OWLAUTH_REQUIRED_AUTH_PROCESS_IDS".to_owned(),
            "auth-a".to_owned(),
        );
        input.remove("OWLAUTH_AUTH_PROCESS_ID");
        for key in [
            "OWLAUTH_EMAIL_IDENTITY_KEY_VERSION",
            "OWLAUTH_EMAIL_IDENTITY_DIGEST_KEY",
            "OWLAUTH_EMAIL_IDENTITY_PROTECTION_KEY",
        ] {
            input.remove(key);
        }
        assert_eq!(
            ServerConfig::from_values(&input).expect_err("missing key must fail"),
            ConfigError::Missing("OWLAUTH_CONTROL_API_KEY")
        );

        input.insert(
            "OWLAUTH_CONTROL_API_KEY".to_owned(),
            format!(
                "{CONTROL_KEY_PREFIX}{}",
                "A".repeat(CONTROL_KEY_SECRET_LENGTH)
            ),
        );
        input.insert(
            "OWLAUTH_INSTANCE_ID".to_owned(),
            "test-deployment".to_owned(),
        );
        input.extend(control_store_values());
        let config = ServerConfig::from_values(&input).expect("canonical key should parse");
        let key = config.control_api_key.expect("Control key should load");
        assert!(key.matches(format!("{CONTROL_KEY_PREFIX}{}", "A".repeat(43)).as_bytes()));
        assert!(!key.matches(format!("{CONTROL_KEY_PREFIX}{}", "B".repeat(43)).as_bytes()));
        assert!(!format!("{key:?}").contains("owl_ctrl"));
    }

    #[test]
    fn control_mcp_is_explicit_control_only_and_bounded() {
        let disabled = parse_control_mcp(ProcessMode::Control, &BTreeMap::new())
            .expect("disabled MCP defaults are valid");
        assert!(!disabled.enabled);
        assert_eq!(disabled.max_request_bytes, 65_536);
        assert_eq!(disabled.max_concurrent_requests, 16);
        assert_eq!(disabled.max_requests_per_second, 64);
        assert_eq!(disabled.max_result_bytes, 65_536);

        let mut values = BTreeMap::from([
            ("OWLAUTH_CONTROL_MCP_ENABLED".to_owned(), "true".to_owned()),
            (
                "OWLAUTH_CONTROL_MCP_MAX_REQUEST_BYTES".to_owned(),
                "32768".to_owned(),
            ),
            (
                "OWLAUTH_CONTROL_MCP_REQUEST_TIMEOUT_MS".to_owned(),
                "5000".to_owned(),
            ),
            (
                "OWLAUTH_CONTROL_MCP_MAX_CONCURRENT_REQUESTS".to_owned(),
                "8".to_owned(),
            ),
            (
                "OWLAUTH_CONTROL_MCP_MAX_REQUESTS_PER_SECOND".to_owned(),
                "32".to_owned(),
            ),
            (
                "OWLAUTH_CONTROL_MCP_MAX_RESULT_BYTES".to_owned(),
                "49152".to_owned(),
            ),
        ]);
        let enabled = parse_control_mcp(ProcessMode::Control, &values)
            .expect("bounded Control MCP configuration is valid");
        assert!(enabled.enabled);
        assert_eq!(enabled.max_request_bytes, 32_768);
        assert_eq!(enabled.request_timeout, Duration::from_secs(5));
        assert_eq!(enabled.max_concurrent_requests, 8);
        assert_eq!(enabled.max_requests_per_second, 32);
        assert_eq!(enabled.max_result_bytes, 49_152);
        let listener = |bind, external_base| ListenerConfig {
            bind,
            external_base: Url::parse(external_base).unwrap(),
            http: parse_http_budget(&BTreeMap::new(), HttpBudgetPlane::Control).unwrap(),
        };
        validate_control_mcp_listener(
            &enabled,
            &listener("127.0.0.1:8081".parse().unwrap(), "http://127.0.0.1:8081/"),
        )
        .expect("exact loopback development may use HTTP");
        validate_control_mcp_listener(
            &enabled,
            &listener("0.0.0.0:8081".parse().unwrap(), "https://control.example/"),
        )
        .expect("remote MCP accepts HTTPS");
        assert!(matches!(
            validate_control_mcp_listener(
                &enabled,
                &listener("127.0.0.1:8081".parse().unwrap(), "http://control.example/"),
            ),
            Err(ConfigError::InvalidValue {
                key: "OWLAUTH_CONTROL_BASE_URL",
                ..
            })
        ));
        assert!(matches!(
            validate_control_mcp_listener(
                &enabled,
                &listener("0.0.0.0:8081".parse().unwrap(), "http://127.0.0.1:8081/"),
            ),
            Err(ConfigError::InvalidValue {
                key: "OWLAUTH_CONTROL_ADDR",
                ..
            })
        ));

        assert!(matches!(
            parse_control_mcp(ProcessMode::Auth, &values),
            Err(ConfigError::InvalidValue {
                key: "OWLAUTH_CONTROL_MCP_ENABLED",
                ..
            })
        ));
        values.insert(
            "OWLAUTH_CONTROL_MCP_MAX_CONCURRENT_REQUESTS".to_owned(),
            "65".to_owned(),
        );
        assert!(matches!(
            parse_control_mcp(ProcessMode::Control, &values),
            Err(ConfigError::InvalidValue {
                key: "OWLAUTH_CONTROL_MCP_MAX_CONCURRENT_REQUESTS",
                ..
            })
        ));
    }

    #[test]
    fn rejects_unknown_values_and_independent_database_authorities() {
        let mut input = auth_values();
        input.insert("OWLAUTH_TYPO".to_owned(), "value".to_owned());
        assert!(matches!(
            ServerConfig::from_values(&input),
            Err(ConfigError::Unknown(key)) if key == "OWLAUTH_TYPO"
        ));

        let mut input = auth_values();
        input.extend(control_store_values());
        input.insert(
            "OWLAUTH_RUNTIME_POSTGRES_URL".to_owned(),
            "postgres://runtime:secret@other.example/owlauth".to_owned(),
        );
        assert!(matches!(
            ServerConfig::from_values(&input),
            Err(ConfigError::DatabaseAuthority(
                "OWLAUTH_RUNTIME_POSTGRES_URL"
            ))
        ));

        let mut input = auth_values();
        input.extend(control_store_values());
        input.insert(
            "OWLAUTH_RUNTIME_POSTGRES_URL".to_owned(),
            "postgres://runtime:secret@database.example/owlauth?sslmode=verify-full".to_owned(),
        );
        ServerConfig::from_values(&input)
            .expect("connection options must not change database authority");
    }

    #[test]
    fn auth_process_must_be_present_in_its_required_roster() {
        let mut input = auth_values();
        input.extend(control_store_values());
        input.insert(
            "OWLAUTH_REQUIRED_AUTH_PROCESS_IDS".to_owned(),
            "other-auth".to_owned(),
        );
        assert!(matches!(
            ServerConfig::from_values(&input),
            Err(ConfigError::InvalidValue {
                key: "OWLAUTH_REQUIRED_AUTH_PROCESS_IDS",
                ..
            })
        ));

        input.insert(
            "OWLAUTH_REQUIRED_AUTH_PROCESS_IDS".to_owned(),
            "test-auth,other-auth".to_owned(),
        );
        let config = ServerConfig::from_values(&input)
            .expect("an Auth process may require itself and additional roster members");
        assert_eq!(
            config.required_auth_process_ids,
            ["test-auth", "other-auth"]
        );
    }

    #[test]
    fn rejects_propagation_delay_beyond_the_upgrade_safety_bound() {
        let mut input = auth_values();
        input.extend(control_store_values());
        input.insert(
            "OWLAUTH_KEY_PROPAGATION_DELAY_MS".to_owned(),
            "86400001".to_owned(),
        );
        assert!(matches!(
            ServerConfig::from_values(&input),
            Err(ConfigError::InvalidValue {
                key: "OWLAUTH_KEY_PROPAGATION_DELAY_MS",
                ..
            })
        ));
    }

    #[test]
    fn rejects_verification_retention_beyond_the_safety_bound() {
        let mut input = auth_values();
        input.extend(control_store_values());
        input.insert(
            "OWLAUTH_SIGNING_VERIFICATION_RETENTION_MS".to_owned(),
            "86400001".to_owned(),
        );
        assert!(matches!(
            ServerConfig::from_values(&input),
            Err(ConfigError::InvalidValue {
                key: "OWLAUTH_SIGNING_VERIFICATION_RETENTION_MS",
                ..
            })
        ));
    }

    #[test]
    fn validates_shared_origin_base_partition() {
        let mut input = auth_values();
        input.extend(control_store_values());
        input.extend(values(&[
            ("OWLAUTH_MODE", "all"),
            ("OWLAUTH_INSTANCE_ID", "test-deployment"),
            (
                "OWLAUTH_CONTROL_API_KEY",
                "owl_ctrl_v1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ),
            ("OWLAUTH_AUTH_BASE_URL", "https://identity.example/auth/"),
            (
                "OWLAUTH_CONTROL_BASE_URL",
                "https://identity.example/control/",
            ),
        ]));
        ServerConfig::from_values(&input).expect("disjoint bases should parse");

        let mut encoded = input.clone();
        encoded.insert(
            "OWLAUTH_CONTROL_BASE_URL".to_owned(),
            "https://identity.example/%63ontrol/".to_owned(),
        );
        assert!(matches!(
            ServerConfig::from_values(&encoded),
            Err(ConfigError::InvalidValue {
                key: "OWLAUTH_CONTROL_BASE_URL",
                ..
            })
        ));

        for mode in ["all", "auth", "control"] {
            let mut overlapping = input.clone();
            overlapping.insert("OWLAUTH_MODE".to_owned(), mode.to_owned());
            overlapping.insert(
                "OWLAUTH_CONTROL_BASE_URL".to_owned(),
                "https://identity.example/auth/control/".to_owned(),
            );
            assert_eq!(
                ServerConfig::from_values(&overlapping)
                    .expect_err("overlap must fail in every process mode"),
                ConfigError::SharedOriginBases
            );
        }
    }
}
