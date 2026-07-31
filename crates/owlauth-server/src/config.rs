use std::{
    collections::{BTreeMap, BTreeSet},
    env, fmt,
    net::SocketAddr,
    num::NonZeroU32,
    path::PathBuf,
    str::FromStr,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use owlauth_types::FEDERATED_PROJECT_AUTH_AVAILABLE;
use serde::Deserialize;
use subtle::ConstantTimeEq;
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

use crate::domain::MAX_ACCESS_TOKEN_LIFETIME_SECONDS;

const CONTROL_KEY_PREFIX: &str = "owl_ctrl_v1_";
const CONTROL_KEY_SECRET_LENGTH: usize = 43;
const MAX_KEY_PROPAGATION_DELAY: Duration = Duration::from_hours(24);
const MAX_SIGNING_VERIFICATION_RETENTION: Duration = Duration::from_hours(24);

const KNOWN_ENVIRONMENT_KEYS: &[&str] = &[
    "OWLAUTH_MODE",
    "OWLAUTH_INSTANCE_ID",
    "OWLAUTH_RUNTIME_ADDR",
    "OWLAUTH_RUNTIME_BASE_URL",
    "OWLAUTH_CONTROL_ADDR",
    "OWLAUTH_CONTROL_BASE_URL",
    "OWLAUTH_CONTROL_API_KEY",
    "OWLAUTH_SIGNER_STORE_ROOT",
    "OWLAUTH_SIGNER_STORE_KEY",
    "OWLAUTH_CONFIGURATION_SECRET_STORE_ROOT",
    "OWLAUTH_CONFIGURATION_SECRET_STORE_KEY",
    "OWLAUTH_RUNTIME_KEY_VERSION",
    "OWLAUTH_RUNTIME_DIGEST_KEY",
    "OWLAUTH_RUNTIME_PROTECTION_KEY",
    "OWLAUTH_RUNTIME_RETAINED_KEYS",
    "OWLAUTH_PROVIDER_ALLOWED_ORIGINS",
    "OWLAUTH_RUNTIME_PROCESS_ID",
    "OWLAUTH_REQUIRED_RUNTIME_PROCESS_IDS",
    "OWLAUTH_PUBLICATION_LEASE_TTL_MS",
    "OWLAUTH_KEY_PROPAGATION_DELAY_MS",
    "OWLAUTH_SIGNING_VERIFICATION_RETENTION_MS",
    "OWLAUTH_POSTGRES_URL",
    "OWLAUTH_RUNTIME_POSTGRES_URL",
    "OWLAUTH_CONTROL_POSTGRES_URL",
    "OWLAUTH_MIGRATION_POSTGRES_URL",
    "OWLAUTH_MIGRATION_MODE",
    "OWLAUTH_MIGRATION_OWNER_ROLE",
    "OWLAUTH_DATABASE_CONNECT_TIMEOUT_MS",
    "OWLAUTH_MIGRATION_LOCK_TIMEOUT_MS",
    "OWLAUTH_RUNTIME_DATABASE_MAX_CONNECTIONS",
    "OWLAUTH_CONTROL_DATABASE_MAX_CONNECTIONS",
    "OWLAUTH_REQUEST_TIMEOUT_MS",
    "OWLAUTH_MAX_REQUEST_BYTES",
    "OWLAUTH_SHUTDOWN_TIMEOUT_MS",
];

/// Process composition mode.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PlaneMode {
    /// Compose both isolated listeners.
    All,
    /// Compose only the Runtime listener.
    #[default]
    Runtime,
    /// Compose only the Control listener.
    Control,
}

impl PlaneMode {
    #[must_use]
    pub const fn has_runtime(self) -> bool {
        matches!(self, Self::All | Self::Runtime)
    }

    #[must_use]
    pub const fn has_control(self) -> bool {
        matches!(self, Self::All | Self::Control)
    }
}

impl FromStr for PlaneMode {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "all" => Ok(Self::All),
            "runtime" => Ok(Self::Runtime),
            "control" => Ok(Self::Control),
            _ => Err(ConfigError::InvalidValue {
                key: "OWLAUTH_MODE",
                reason: "must be `all`, `runtime`, or `control`".to_owned(),
            }),
        }
    }
}

/// Startup migration behavior.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MigrationMode {
    /// Apply compatible pending migrations before serving.
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

#[derive(Clone, Debug)]
pub struct ListenerConfig {
    pub bind: SocketAddr,
    pub external_base: Url,
    pub database_max_connections: NonZeroU32,
}

#[derive(Clone, Debug)]
pub struct PostgresConfig {
    pub serving_url: SecretString,
    pub runtime_url: SecretString,
    pub control_url: SecretString,
    pub migration_url: SecretString,
    pub migration_mode: MigrationMode,
    pub migration_owner_role: Option<String>,
    pub connect_timeout: Duration,
    pub migration_lock_timeout: Duration,
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
    pub signer_store_root: PathBuf,
    pub signer_store_key: StoreMasterKey,
    pub configuration_secret_store_root: PathBuf,
    pub configuration_secret_store_key: StoreMasterKey,
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
pub struct ServerConfig {
    pub mode: PlaneMode,
    pub instance_id: Option<String>,
    pub runtime: ListenerConfig,
    pub control: ListenerConfig,
    pub control_api_key: Option<OperatorApiKey>,
    pub provisioning: Option<ProvisioningConfig>,
    pub runtime_protection: Option<RuntimeProtectionConfig>,
    pub provider_allowed_origins: Vec<String>,
    pub runtime_process_id: String,
    pub required_runtime_process_ids: Vec<String>,
    pub publication_lease_ttl: Duration,
    pub key_propagation_delay: Duration,
    pub signing_verification_retention: Duration,
    pub postgres: PostgresConfig,
    pub request_timeout: Duration,
    pub max_request_bytes: usize,
    pub shutdown_timeout: Duration,
}

impl ServerConfig {
    /// Reads and validates the complete `OwlAuth` environment configuration.
    ///
    /// Unknown `OWLAUTH_*` variables are rejected. Runtime-only mode deliberately does
    /// not read Control operator or provisioning-store secrets while federated Project
    /// authentication is unavailable.
    ///
    /// # Errors
    ///
    /// Returns a bounded configuration error before any listener is bound.
    pub fn from_env() -> Result<Self, ConfigError> {
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
        Self::from_values(&values)
    }

    #[cfg(test)]
    pub(crate) fn from_values_for_test(
        values: &BTreeMap<String, String>,
    ) -> Result<Self, ConfigError> {
        Self::from_values(values)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one linear parser preserves strict whole-environment validation"
    )]
    fn from_values(values: &BTreeMap<String, String>) -> Result<Self, ConfigError> {
        reject_unknown_keys(values)?;

        let mode = optional(values, "OWLAUTH_MODE")
            .unwrap_or("runtime")
            .parse()?;
        let runtime = ListenerConfig {
            bind: parse_value(
                values,
                "OWLAUTH_RUNTIME_ADDR",
                "127.0.0.1:8080",
                "must be an IP socket address",
            )?,
            external_base: parse_external_base(
                "OWLAUTH_RUNTIME_BASE_URL",
                optional(values, "OWLAUTH_RUNTIME_BASE_URL").unwrap_or("http://127.0.0.1:8080/"),
            )?,
            database_max_connections: parse_nonzero_u32(
                values,
                "OWLAUTH_RUNTIME_DATABASE_MAX_CONNECTIONS",
                20,
            )?,
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
            database_max_connections: parse_nonzero_u32(
                values,
                "OWLAUTH_CONTROL_DATABASE_MAX_CONNECTIONS",
                5,
            )?,
        };
        validate_external_bases(&runtime.external_base, &control.external_base)?;

        let (instance_id, control_api_key) = parse_control_identity(mode, values)?;
        let provisioning = parse_provisioning(mode, values)?;
        let runtime_protection = parse_runtime_protection(mode, values)?;
        let provider_allowed_origins = parse_provider_allowed_origins(mode, values)?;
        let configured_runtime_process_id = optional(values, "OWLAUTH_RUNTIME_PROCESS_ID")
            .map(validate_process_id)
            .transpose()?;
        if mode.has_runtime() && configured_runtime_process_id.is_none() {
            return Err(ConfigError::Missing("OWLAUTH_RUNTIME_PROCESS_ID"));
        }
        let runtime_process_id = configured_runtime_process_id.unwrap_or_default();
        let required_runtime_process_ids =
            match optional(values, "OWLAUTH_REQUIRED_RUNTIME_PROCESS_IDS") {
                Some(configured) => {
                    let ids = configured
                        .split(',')
                        .map(validate_process_id)
                        .collect::<Result<Vec<_>, _>>()?;
                    if ids.is_empty()
                        || ids.iter().collect::<std::collections::BTreeSet<_>>().len() != ids.len()
                    {
                        return Err(ConfigError::InvalidValue {
                            key: "OWLAUTH_REQUIRED_RUNTIME_PROCESS_IDS",
                            reason: "must contain unique comma-separated process IDs".to_owned(),
                        });
                    }
                    ids
                }
                None if mode == PlaneMode::Control => {
                    return Err(ConfigError::Missing("OWLAUTH_REQUIRED_RUNTIME_PROCESS_IDS"));
                }
                None => vec![runtime_process_id.clone()],
            };
        if mode.has_runtime()
            && !required_runtime_process_ids
                .iter()
                .any(|process_id| process_id == &runtime_process_id)
        {
            return Err(ConfigError::InvalidValue {
                key: "OWLAUTH_REQUIRED_RUNTIME_PROCESS_IDS",
                reason: "must include this Runtime process's OWLAUTH_RUNTIME_PROCESS_ID".to_owned(),
            });
        }

        let serving_url = required(values, "OWLAUTH_POSTGRES_URL")?;
        let runtime_url = optional(values, "OWLAUTH_RUNTIME_POSTGRES_URL")
            .unwrap_or(&serving_url)
            .to_owned();
        let control_url = optional(values, "OWLAUTH_CONTROL_POSTGRES_URL")
            .unwrap_or(&serving_url)
            .to_owned();
        let migration_url = optional(values, "OWLAUTH_MIGRATION_POSTGRES_URL")
            .unwrap_or(&serving_url)
            .to_owned();
        validate_database_authority(&serving_url, &runtime_url, "OWLAUTH_RUNTIME_POSTGRES_URL")?;
        validate_database_authority(&serving_url, &control_url, "OWLAUTH_CONTROL_POSTGRES_URL")?;
        validate_database_authority(
            &serving_url,
            &migration_url,
            "OWLAUTH_MIGRATION_POSTGRES_URL",
        )?;

        let migration_owner_role = optional(values, "OWLAUTH_MIGRATION_OWNER_ROLE")
            .map(validate_role)
            .transpose()?;
        let publication_lease_ttl =
            parse_millis(values, "OWLAUTH_PUBLICATION_LEASE_TTL_MS", 30_000)?;
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
            runtime,
            control,
            control_api_key,
            provisioning,
            runtime_protection,
            provider_allowed_origins,
            runtime_process_id,
            required_runtime_process_ids,
            publication_lease_ttl,
            key_propagation_delay,
            signing_verification_retention,
            postgres: PostgresConfig {
                serving_url: SecretString::new(serving_url),
                runtime_url: SecretString::new(runtime_url),
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
                migration_lock_timeout: parse_millis(
                    values,
                    "OWLAUTH_MIGRATION_LOCK_TIMEOUT_MS",
                    30_000,
                )?,
            },
            request_timeout: parse_millis(values, "OWLAUTH_REQUEST_TIMEOUT_MS", 10_000)?,
            max_request_bytes: parse_value(
                values,
                "OWLAUTH_MAX_REQUEST_BYTES",
                "1048576",
                "must be a positive byte count",
            )?,
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
    #[error("Runtime and Control bases on one origin must be disjoint non-root paths")]
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

fn parse_control_identity(
    mode: PlaneMode,
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

fn parse_provisioning(
    mode: PlaneMode,
    values: &BTreeMap<String, String>,
) -> Result<Option<ProvisioningConfig>, ConfigError> {
    let runtime_needs_stores = mode.has_runtime() && FEDERATED_PROJECT_AUTH_AVAILABLE;
    if !mode.has_control() && !runtime_needs_stores {
        return Ok(None);
    }
    let signer_store_root = parse_store_root(
        "OWLAUTH_SIGNER_STORE_ROOT",
        required(values, "OWLAUTH_SIGNER_STORE_ROOT")?,
    )?;
    let configuration_secret_store_root = parse_store_root(
        "OWLAUTH_CONFIGURATION_SECRET_STORE_ROOT",
        required(values, "OWLAUTH_CONFIGURATION_SECRET_STORE_ROOT")?,
    )?;
    if signer_store_root == configuration_secret_store_root {
        return Err(ConfigError::InvalidValue {
            key: "OWLAUTH_CONFIGURATION_SECRET_STORE_ROOT",
            reason: "must be separate from the signer store root".to_owned(),
        });
    }
    let signer_store_key = StoreMasterKey::parse(
        "OWLAUTH_SIGNER_STORE_KEY",
        required(values, "OWLAUTH_SIGNER_STORE_KEY")?,
    )?;
    let configuration_secret_store_key = StoreMasterKey::parse(
        "OWLAUTH_CONFIGURATION_SECRET_STORE_KEY",
        required(values, "OWLAUTH_CONFIGURATION_SECRET_STORE_KEY")?,
    )?;
    if signer_store_key.0.as_ref() == configuration_secret_store_key.0.as_ref() {
        return Err(ConfigError::InvalidValue {
            key: "OWLAUTH_CONFIGURATION_SECRET_STORE_KEY",
            reason: "must be separate from the signer store wrapping key".to_owned(),
        });
    }
    Ok(Some(ProvisioningConfig {
        signer_store_root,
        signer_store_key,
        configuration_secret_store_root,
        configuration_secret_store_key,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SerializedRuntimeKeyConfig {
    digest_key: String,
    protection_key: String,
}

fn parse_runtime_protection(
    mode: PlaneMode,
    values: &BTreeMap<String, String>,
) -> Result<Option<RuntimeProtectionConfig>, ConfigError> {
    if !mode.has_runtime() {
        return Ok(None);
    }
    let active_version = required(values, "OWLAUTH_RUNTIME_KEY_VERSION")?
        .parse::<i32>()
        .map_err(|_| ConfigError::InvalidValue {
            key: "OWLAUTH_RUNTIME_KEY_VERSION",
            reason: "must be a positive integer".to_owned(),
        })?;
    if active_version <= 0 {
        return Err(ConfigError::InvalidValue {
            key: "OWLAUTH_RUNTIME_KEY_VERSION",
            reason: "must be a positive integer".to_owned(),
        });
    }
    let active = parse_runtime_key(
        required(values, "OWLAUTH_RUNTIME_DIGEST_KEY")?,
        required(values, "OWLAUTH_RUNTIME_PROTECTION_KEY")?,
    )?;
    let serialized = optional(values, "OWLAUTH_RUNTIME_RETAINED_KEYS").unwrap_or("{}");
    let retained = serde_json::from_str::<BTreeMap<i32, SerializedRuntimeKeyConfig>>(serialized)
        .map_err(|_| ConfigError::InvalidValue {
            key: "OWLAUTH_RUNTIME_RETAINED_KEYS",
            reason: "must be a JSON object keyed by unique positive key versions".to_owned(),
        })?
        .into_iter()
        .map(|(version, key)| {
            if version <= 0 || version == active_version {
                return Err(ConfigError::InvalidValue {
                    key: "OWLAUTH_RUNTIME_RETAINED_KEYS",
                    reason: "versions must be positive and must not repeat the active version"
                        .to_owned(),
                });
            }
            Ok((
                version,
                parse_runtime_key(key.digest_key, key.protection_key)?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    Ok(Some(RuntimeProtectionConfig {
        active_version,
        active,
        retained,
    }))
}

fn parse_runtime_key(
    digest_key: String,
    protection_key: String,
) -> Result<RuntimeKeyConfig, ConfigError> {
    let digest_key = StoreMasterKey::parse("OWLAUTH_RUNTIME_DIGEST_KEY", digest_key)?;
    let protection_key = StoreMasterKey::parse("OWLAUTH_RUNTIME_PROTECTION_KEY", protection_key)?;
    if digest_key.0.as_ref() == protection_key.0.as_ref() {
        return Err(ConfigError::InvalidValue {
            key: "OWLAUTH_RUNTIME_PROTECTION_KEY",
            reason: "must be separate from the Runtime digest key".to_owned(),
        });
    }
    Ok(RuntimeKeyConfig {
        digest_key,
        protection_key,
    })
}

fn parse_provider_allowed_origins(
    mode: PlaneMode,
    values: &BTreeMap<String, String>,
) -> Result<Vec<String>, ConfigError> {
    if !mode.has_runtime() {
        return Ok(Vec::new());
    }
    let configured = required(values, "OWLAUTH_PROVIDER_ALLOWED_ORIGINS")?;
    let origins = configured
        .split(',')
        .map(|value| {
            let url = Url::parse(value).map_err(|_| ConfigError::InvalidValue {
                key: "OWLAUTH_PROVIDER_ALLOWED_ORIGINS",
                reason: "must contain comma-separated canonical HTTPS origins".to_owned(),
            })?;
            if url.scheme() != "https"
                || url.username() != ""
                || url.password().is_some()
                || url.host_str().is_none()
                || url.path() != "/"
                || url.query().is_some()
                || url.fragment().is_some()
                || url.as_str() != value
            {
                return Err(ConfigError::InvalidValue {
                    key: "OWLAUTH_PROVIDER_ALLOWED_ORIGINS",
                    reason: "must contain comma-separated canonical HTTPS origins".to_owned(),
                });
            }
            Ok(value.to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if origins.is_empty() || origins.iter().collect::<BTreeSet<_>>().len() != origins.len() {
        return Err(ConfigError::InvalidValue {
            key: "OWLAUTH_PROVIDER_ALLOWED_ORIGINS",
            reason: "must contain unique canonical HTTPS origins".to_owned(),
        });
    }
    Ok(origins)
}

fn parse_store_root(key: &'static str, value: String) -> Result<PathBuf, ConfigError> {
    let path = PathBuf::from(value);
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(ConfigError::InvalidValue {
            key,
            reason: "must be an absolute path without parent traversal".to_owned(),
        });
    }
    Ok(path)
}

fn validate_process_id(value: &str) -> Result<String, ConfigError> {
    if !(1..=128).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(ConfigError::InvalidValue {
            key: "OWLAUTH_RUNTIME_PROCESS_ID",
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

fn validate_external_bases(runtime: &Url, control: &Url) -> Result<(), ConfigError> {
    if same_origin(runtime, control) {
        let runtime_path = runtime.path();
        let control_path = control.path();
        if runtime_path == "/"
            || control_path == "/"
            || runtime_path.starts_with(control_path)
            || control_path.starts_with(runtime_path)
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

    fn runtime_values() -> BTreeMap<String, String> {
        values(&[
            (
                "OWLAUTH_POSTGRES_URL",
                "postgres://runtime:secret@database.example/owlauth",
            ),
            ("OWLAUTH_INSTANCE_ID", "test-deployment"),
            ("OWLAUTH_RUNTIME_PROCESS_ID", "test-runtime"),
            ("OWLAUTH_RUNTIME_KEY_VERSION", "2"),
            (
                "OWLAUTH_PROVIDER_ALLOWED_ORIGINS",
                "https://accounts.example/",
            ),
            (
                "OWLAUTH_RUNTIME_DIGEST_KEY",
                "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM",
            ),
            (
                "OWLAUTH_RUNTIME_PROTECTION_KEY",
                "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ",
            ),
        ])
    }

    fn control_store_values() -> BTreeMap<String, String> {
        values(&[
            ("OWLAUTH_SIGNER_STORE_ROOT", "/tmp/owlauth-test-signers"),
            (
                "OWLAUTH_SIGNER_STORE_KEY",
                "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
            ),
            (
                "OWLAUTH_CONFIGURATION_SECRET_STORE_ROOT",
                "/tmp/owlauth-test-configuration-secrets",
            ),
            (
                "OWLAUTH_CONFIGURATION_SECRET_STORE_KEY",
                "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI",
            ),
        ])
    }

    #[test]
    fn runtime_mode_does_not_require_or_load_control_secrets() {
        const { assert!(!FEDERATED_PROJECT_AUTH_AVAILABLE) };
        let config =
            ServerConfig::from_values(&runtime_values()).expect("Runtime config should parse");
        assert_eq!(config.mode, PlaneMode::Runtime);
        assert!(config.control_api_key.is_none());
        assert!(config.provisioning.is_none());

        let mut ignored = runtime_values();
        ignored.extend(values(&[
            ("OWLAUTH_CONTROL_API_KEY", "this value must not be loaded"),
            ("OWLAUTH_SIGNER_STORE_ROOT", "not-an-absolute-path"),
            ("OWLAUTH_SIGNER_STORE_KEY", "not-base64"),
            (
                "OWLAUTH_CONFIGURATION_SECRET_STORE_ROOT",
                "also-not-an-absolute-path",
            ),
            ("OWLAUTH_CONFIGURATION_SECRET_STORE_KEY", "also-not-base64"),
        ]));
        let config = ServerConfig::from_values(&ignored)
            .expect("Runtime must ignore unavailable Control capabilities");
        assert!(config.control_api_key.is_none());
        assert!(config.provisioning.is_none());
        let debug = format!("{config:?}");
        assert!(!debug.contains("this value"));
        assert!(!debug.contains("not-base64"));
        assert!(!debug.contains("AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM"));
    }

    #[test]
    fn control_and_all_modes_retain_provisioning_stores() {
        for mode in ["control", "all"] {
            let mut input = runtime_values();
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
                input.insert(
                    "OWLAUTH_REQUIRED_RUNTIME_PROCESS_IDS".to_owned(),
                    "runtime-a".to_owned(),
                );
            }
            let config = ServerConfig::from_values(&input)
                .expect("Control composition must retain provisioning stores");
            assert!(config.provisioning.is_some(), "mode {mode}");
        }
    }

    #[test]
    fn control_requires_exact_canonical_key() {
        let mut input = runtime_values();
        input.insert("OWLAUTH_MODE".to_owned(), "control".to_owned());
        input.insert(
            "OWLAUTH_REQUIRED_RUNTIME_PROCESS_IDS".to_owned(),
            "runtime-a".to_owned(),
        );
        input.remove("OWLAUTH_RUNTIME_PROCESS_ID");
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
    fn rejects_unknown_values_and_independent_database_authorities() {
        let mut input = runtime_values();
        input.insert("OWLAUTH_TYPO".to_owned(), "value".to_owned());
        assert!(matches!(
            ServerConfig::from_values(&input),
            Err(ConfigError::Unknown(key)) if key == "OWLAUTH_TYPO"
        ));

        let mut input = runtime_values();
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

        let mut input = runtime_values();
        input.insert(
            "OWLAUTH_RUNTIME_POSTGRES_URL".to_owned(),
            "postgres://runtime:secret@database.example/owlauth?sslmode=verify-full".to_owned(),
        );
        ServerConfig::from_values(&input)
            .expect("connection options must not change database authority");
    }

    #[test]
    fn runtime_process_must_be_present_in_its_required_roster() {
        let mut input = runtime_values();
        input.insert(
            "OWLAUTH_REQUIRED_RUNTIME_PROCESS_IDS".to_owned(),
            "other-runtime".to_owned(),
        );
        assert!(matches!(
            ServerConfig::from_values(&input),
            Err(ConfigError::InvalidValue {
                key: "OWLAUTH_REQUIRED_RUNTIME_PROCESS_IDS",
                ..
            })
        ));

        input.insert(
            "OWLAUTH_REQUIRED_RUNTIME_PROCESS_IDS".to_owned(),
            "test-runtime,other-runtime".to_owned(),
        );
        let config = ServerConfig::from_values(&input)
            .expect("a Runtime process may require itself and additional roster members");
        assert_eq!(
            config.required_runtime_process_ids,
            ["test-runtime", "other-runtime"]
        );
    }

    #[test]
    fn rejects_propagation_delay_beyond_the_upgrade_safety_bound() {
        let mut input = runtime_values();
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
        let mut input = runtime_values();
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
        let mut input = runtime_values();
        input.extend(control_store_values());
        input.extend(values(&[
            ("OWLAUTH_MODE", "all"),
            ("OWLAUTH_INSTANCE_ID", "test-deployment"),
            (
                "OWLAUTH_CONTROL_API_KEY",
                "owl_ctrl_v1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ),
            ("OWLAUTH_RUNTIME_BASE_URL", "https://identity.example/auth/"),
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

        for mode in ["all", "runtime", "control"] {
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
