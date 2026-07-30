use std::{
    collections::BTreeMap,
    env, fs,
    io::{Read, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use reqwest::{
    blocking::{Client, Response},
    header::{ACCEPT, CONTENT_TYPE},
    redirect::Policy,
};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use thiserror::Error;
use url::{Host, Url};

const STORE_SCHEMA_VERSION: u32 = 1;
const MAX_DESCRIPTOR_BYTES: u64 = 64 * 1024;
const MAX_STORE_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Product {
    OwlauthServer,
    OwlauthSaas,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum CredentialClass {
    OperatorApiKey,
    SaasApiKey,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDescriptor {
    schema_version: String,
    product: Product,
    instance_id: String,
    api_base_url: String,
    api_versions: Vec<String>,
    credential_class: CredentialClass,
    mcp_url: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct Descriptor {
    schema_version: String,
    product: Product,
    instance_id: String,
    api_base_url: String,
    api_versions: Vec<String>,
    credential_class: CredentialClass,
    #[serde(skip_serializing_if = "Option::is_none")]
    mcp_url: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    endpoint: String,
    product: Product,
    instance_id: String,
    api_base_url: String,
    api_versions: Vec<String>,
    credential_class: CredentialClass,
    credential_environment: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    mcp_url: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProfileStore {
    schema_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    current_profile: Option<String>,
    profiles: BTreeMap<String, Profile>,
}

impl Default for ProfileStore {
    fn default() -> Self {
        Self {
            schema_version: STORE_SCHEMA_VERSION,
            current_profile: None,
            profiles: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SystemCapabilities {
    product: String,
    project_auth: bool,
}

#[derive(Serialize)]
struct Inspection<'a> {
    name: &'a str,
    current: bool,
    profile: &'a Profile,
}

#[derive(Serialize)]
struct RebindPreview<'a> {
    old: &'a Profile,
    new: &'a Descriptor,
}

#[derive(Debug, Error)]
pub enum RemoteError {
    #[error("invalid profile name; use 1-64 ASCII letters, digits, '.', '_', or '-'")]
    InvalidProfileName,
    #[error("invalid endpoint: {0}")]
    InvalidEndpoint(&'static str),
    #[error("endpoint discovery request failed")]
    DiscoveryTransport,
    #[error("endpoint discovery returned HTTP status {0}")]
    DiscoveryStatus(u16),
    #[error("endpoint discovery returned an invalid content type")]
    DiscoveryContentType,
    #[error("endpoint descriptor is too large")]
    DescriptorTooLarge,
    #[error("endpoint descriptor is malformed or unsupported")]
    InvalidDescriptor,
    #[error("profile {0} already exists; use `profile rebind` for an explicit identity change")]
    ProfileExists(String),
    #[error("profile {0} does not exist")]
    ProfileMissing(String),
    #[error("no profile is selected; pass --profile or run `owlauth profile use NAME`")]
    NoSelectedProfile,
    #[error("discovered endpoint identity no longer matches profile {0}; use `profile rebind`")]
    IdentityChanged(String),
    #[error("refusing to save discovery without explicit --yes confirmation")]
    ConfirmationRequired,
    #[error("invalid credential environment variable name")]
    InvalidCredentialEnvironment,
    #[error("credential environment variable {0} is missing")]
    MissingCredential(String),
    #[error("credential does not match the discovered product")]
    WrongCredentialClass,
    #[error("command is not supported by the discovered product")]
    UnsupportedCommand,
    #[error("remote API request failed")]
    ApiTransport,
    #[error("remote API returned HTTP status {0}")]
    ApiStatus(u16),
    #[error("remote API returned a malformed response")]
    InvalidApiResponse,
    #[error("profile storage is unavailable or invalid")]
    ProfileStorage,
}

pub fn add_profile(
    name: &str,
    endpoint: &str,
    credential_environment: Option<&str>,
    confirmed: bool,
) -> Result<(), RemoteError> {
    validate_profile_name(name)?;
    let endpoint = validate_endpoint(endpoint)?;
    let descriptor = discover(&endpoint)?;
    print_json(&descriptor)?;
    if !confirmed {
        return Err(RemoteError::ConfirmationRequired);
    }

    let path = store_path()?;
    let mut store = load_store(&path)?;
    if store.profiles.contains_key(name) {
        return Err(RemoteError::ProfileExists(name.to_owned()));
    }
    let profile = profile_from_descriptor(&endpoint, descriptor, credential_environment)?;
    store.profiles.insert(name.to_owned(), profile);
    if store.current_profile.is_none() {
        store.current_profile = Some(name.to_owned());
    }
    save_store(&path, &store)
}

pub fn inspect_profile(name: Option<&str>) -> Result<(), RemoteError> {
    let store = load_store(&store_path()?)?;
    let (name, profile) = select_profile(&store, name)?;
    print_json(&Inspection {
        name,
        current: store.current_profile.as_deref() == Some(name),
        profile,
    })
}

pub fn use_profile(name: &str) -> Result<(), RemoteError> {
    validate_profile_name(name)?;
    let path = store_path()?;
    let mut store = load_store(&path)?;
    let profile = store
        .profiles
        .get(name)
        .ok_or_else(|| RemoteError::ProfileMissing(name.to_owned()))?;
    validate_current_identity(name, profile)?;
    store.current_profile = Some(name.to_owned());
    save_store(&path, &store)
}

pub fn rebind_profile(
    name: &str,
    endpoint: &str,
    credential_environment: Option<&str>,
    confirmed: bool,
) -> Result<(), RemoteError> {
    validate_profile_name(name)?;
    let endpoint = validate_endpoint(endpoint)?;
    let descriptor = discover(&endpoint)?;
    let path = store_path()?;
    let mut store = load_store(&path)?;
    let old = store
        .profiles
        .get(name)
        .ok_or_else(|| RemoteError::ProfileMissing(name.to_owned()))?;
    print_json(&RebindPreview {
        old,
        new: &descriptor,
    })?;
    if !confirmed {
        return Err(RemoteError::ConfirmationRequired);
    }
    let profile = profile_from_descriptor(&endpoint, descriptor, credential_environment)?;
    store.profiles.insert(name.to_owned(), profile);
    save_store(&path, &store)
}

pub fn check_profile(name: Option<&str>) -> Result<(), RemoteError> {
    let store = load_store(&store_path()?)?;
    let (name, profile) = select_profile(&store, name)?;
    let descriptor = validate_current_identity(name, profile)?;
    print_json(&descriptor)
}

pub fn system(profile_name: Option<&str>) -> Result<(), RemoteError> {
    let store = load_store(&store_path()?)?;
    let (name, profile) = select_profile(&store, profile_name)?;
    let descriptor = validate_current_identity(name, profile)?;
    match descriptor.product {
        Product::OwlauthServer => ServerClient::new(profile, &descriptor)?.system(),
        Product::OwlauthSaas => SaasClient::system(),
    }
}

struct ServerClient {
    client: Client,
    api_base: Url,
    credential: String,
}

impl ServerClient {
    fn new(profile: &Profile, descriptor: &Descriptor) -> Result<Self, RemoteError> {
        debug_assert_eq!(descriptor.product, Product::OwlauthServer);
        let credential = read_credential(profile)?;
        if !is_operator_key(&credential) {
            return Err(RemoteError::WrongCredentialClass);
        }
        Ok(Self {
            client: http_client()?,
            api_base: Url::parse(&descriptor.api_base_url)
                .map_err(|_| RemoteError::InvalidDescriptor)?,
            credential,
        })
    }

    fn system(self) -> Result<(), RemoteError> {
        let url = self
            .api_base
            .join("system")
            .map_err(|_| RemoteError::InvalidDescriptor)?;
        let response = self
            .client
            .get(url)
            .bearer_auth(&self.credential)
            .header(ACCEPT, "application/json")
            .send()
            .map_err(|_| RemoteError::ApiTransport)?;
        let bytes = read_json_response(response, MAX_DESCRIPTOR_BYTES, false)?;
        let capabilities: SystemCapabilities =
            serde_json::from_slice(&bytes).map_err(|_| RemoteError::InvalidApiResponse)?;
        if capabilities.product != "owlauth-server" {
            return Err(RemoteError::InvalidApiResponse);
        }
        print_json(&capabilities)
    }
}

struct SaasClient;

impl SaasClient {
    fn system() -> Result<(), RemoteError> {
        Err(RemoteError::UnsupportedCommand)
    }
}

fn profile_from_descriptor(
    endpoint: &Url,
    descriptor: Descriptor,
    credential_environment: Option<&str>,
) -> Result<Profile, RemoteError> {
    let default_environment = match descriptor.credential_class {
        CredentialClass::OperatorApiKey => "OWLAUTH_CONTROL_API_KEY",
        CredentialClass::SaasApiKey => "OWLAUTH_SAAS_API_KEY",
    };
    let credential_environment = credential_environment.unwrap_or(default_environment);
    validate_credential_environment(credential_environment)?;
    Ok(Profile {
        endpoint: endpoint.to_string(),
        product: descriptor.product,
        instance_id: descriptor.instance_id,
        api_base_url: descriptor.api_base_url,
        api_versions: descriptor.api_versions,
        credential_class: descriptor.credential_class,
        credential_environment: credential_environment.to_owned(),
        mcp_url: descriptor.mcp_url,
    })
}

fn validate_current_identity(name: &str, profile: &Profile) -> Result<Descriptor, RemoteError> {
    let endpoint = validate_endpoint(&profile.endpoint)?;
    let descriptor = discover(&endpoint)?;
    let matches = descriptor.product == profile.product
        && descriptor.instance_id == profile.instance_id
        && descriptor.api_base_url == profile.api_base_url
        && descriptor.credential_class == profile.credential_class;
    if !matches {
        return Err(RemoteError::IdentityChanged(name.to_owned()));
    }
    Ok(descriptor)
}

fn discover(endpoint: &Url) -> Result<Descriptor, RemoteError> {
    let url = endpoint
        .join(".well-known/owlauth")
        .map_err(|_| RemoteError::InvalidDescriptor)?;
    let response = http_client()?
        .get(url)
        .header(ACCEPT, "application/json")
        .send()
        .map_err(|_| RemoteError::DiscoveryTransport)?;
    let bytes = read_json_response(response, MAX_DESCRIPTOR_BYTES, true)?;
    let raw: RawDescriptor =
        serde_json::from_slice(&bytes).map_err(|_| RemoteError::InvalidDescriptor)?;
    validate_descriptor(endpoint, raw)
}

fn http_client() -> Result<Client, RemoteError> {
    Client::builder()
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .user_agent(concat!("owlauth-cli/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|_| RemoteError::DiscoveryTransport)
}

fn read_json_response(
    response: Response,
    limit: u64,
    discovery: bool,
) -> Result<Vec<u8>, RemoteError> {
    let status = response.status();
    if status.as_u16() != 200 {
        return Err(if discovery {
            RemoteError::DiscoveryStatus(status.as_u16())
        } else {
            RemoteError::ApiStatus(status.as_u16())
        });
    }
    let json_content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"));
    if !json_content_type {
        return Err(if discovery {
            RemoteError::DiscoveryContentType
        } else {
            RemoteError::InvalidApiResponse
        });
    }
    if response
        .content_length()
        .is_some_and(|length| length > limit)
    {
        return Err(RemoteError::DescriptorTooLarge);
    }
    let mut bytes = Vec::new();
    response
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| {
            if discovery {
                RemoteError::DiscoveryTransport
            } else {
                RemoteError::ApiTransport
            }
        })?;
    if bytes.len() as u64 > limit {
        return Err(RemoteError::DescriptorTooLarge);
    }
    Ok(bytes)
}

fn validate_descriptor(endpoint: &Url, raw: RawDescriptor) -> Result<Descriptor, RemoteError> {
    if raw.schema_version != "1"
        || raw.instance_id.is_empty()
        || raw.instance_id.len() > 128
        || !raw.instance_id.bytes().all(|byte| byte.is_ascii_graphic())
        || raw.api_versions.is_empty()
        || raw.api_versions.len() > 8
        || !raw.api_versions.iter().any(|version| version == "v1")
        || raw.api_versions.iter().any(|version| {
            version.is_empty()
                || version.len() > 16
                || !version.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
        || !matches!(
            (raw.product, raw.credential_class),
            (Product::OwlauthServer, CredentialClass::OperatorApiKey)
                | (Product::OwlauthSaas, CredentialClass::SaasApiKey)
        )
    {
        return Err(RemoteError::InvalidDescriptor);
    }
    let api_base = validate_descriptor_url(endpoint, &raw.api_base_url, true)?;
    let mcp_url = raw
        .mcp_url
        .as_deref()
        .map(|value| validate_descriptor_url(endpoint, value, false))
        .transpose()?;
    Ok(Descriptor {
        schema_version: raw.schema_version,
        product: raw.product,
        instance_id: raw.instance_id,
        api_base_url: api_base.to_string(),
        api_versions: raw.api_versions,
        credential_class: raw.credential_class,
        mcp_url: mcp_url.map(|url| url.to_string()),
    })
}

fn validate_endpoint(value: &str) -> Result<Url, RemoteError> {
    if value.contains('%') || value.contains('\\') {
        return Err(RemoteError::InvalidEndpoint(
            "ambiguous encoding is not allowed",
        ));
    }
    let url = Url::parse(value).map_err(|_| RemoteError::InvalidEndpoint("must be a URL"))?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
        || url.host().is_none()
        || !(url.scheme() == "https" || (url.scheme() == "http" && is_loopback(&url)))
    {
        return Err(RemoteError::InvalidEndpoint(
            "must be an HTTPS origin (HTTP is allowed only on loopback)",
        ));
    }
    Ok(url)
}

fn validate_descriptor_url(
    endpoint: &Url,
    value: &str,
    trailing_slash: bool,
) -> Result<Url, RemoteError> {
    if value.contains('%') || value.contains('\\') {
        return Err(RemoteError::InvalidDescriptor);
    }
    let url = Url::parse(value).map_err(|_| RemoteError::InvalidDescriptor)?;
    if url.as_str() != value
        || !same_origin(endpoint, &url)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || (trailing_slash && !url.path().ends_with('/'))
    {
        return Err(RemoteError::InvalidDescriptor);
    }
    Ok(url)
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(address)) => IpAddr::V4(address).is_loopback(),
        Some(Host::Ipv6(address)) => IpAddr::V6(address).is_loopback(),
        None => false,
    }
}

fn validate_profile_name(name: &str) -> Result<(), RemoteError> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(RemoteError::InvalidProfileName);
    }
    Ok(())
}

fn validate_credential_environment(name: &str) -> Result<(), RemoteError> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(RemoteError::InvalidCredentialEnvironment);
    }
    Ok(())
}

fn read_credential(profile: &Profile) -> Result<String, RemoteError> {
    env::var(&profile.credential_environment)
        .map_err(|_| RemoteError::MissingCredential(profile.credential_environment.clone()))
}

fn is_operator_key(value: &str) -> bool {
    value.len() == "owl_ctrl_v1_".len() + 43
        && value.starts_with("owl_ctrl_v1_")
        && value["owl_ctrl_v1_".len()..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn select_profile<'a>(
    store: &'a ProfileStore,
    requested: Option<&str>,
) -> Result<(&'a str, &'a Profile), RemoteError> {
    let name = requested
        .or(store.current_profile.as_deref())
        .ok_or(RemoteError::NoSelectedProfile)?;
    let (stored_name, profile) = store
        .profiles
        .get_key_value(name)
        .ok_or_else(|| RemoteError::ProfileMissing(name.to_owned()))?;
    Ok((stored_name.as_str(), profile))
}

fn store_path() -> Result<PathBuf, RemoteError> {
    if let Some(directory) = env::var_os("OWLAUTH_CONFIG_DIR") {
        return Ok(PathBuf::from(directory).join("profiles.json"));
    }
    #[cfg(windows)]
    let base = env::var_os("APPDATA").map(PathBuf::from);
    #[cfg(not(windows))]
    let base = env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")));
    base.map(|directory| directory.join("owlauth/profiles.json"))
        .ok_or(RemoteError::ProfileStorage)
}

fn load_store(path: &Path) -> Result<ProfileStore, RemoteError> {
    if !path.exists() {
        return Ok(ProfileStore::default());
    }
    let metadata = fs::metadata(path).map_err(|_| RemoteError::ProfileStorage)?;
    if !metadata.is_file() || metadata.len() > MAX_STORE_BYTES {
        return Err(RemoteError::ProfileStorage);
    }
    let bytes = fs::read(path).map_err(|_| RemoteError::ProfileStorage)?;
    let store: ProfileStore =
        serde_json::from_slice(&bytes).map_err(|_| RemoteError::ProfileStorage)?;
    if store.schema_version != STORE_SCHEMA_VERSION
        || store
            .current_profile
            .as_ref()
            .is_some_and(|name| !store.profiles.contains_key(name))
        || store.profiles.iter().any(|(name, profile)| {
            validate_profile_name(name).is_err()
                || validate_endpoint(&profile.endpoint).is_err()
                || validate_credential_environment(&profile.credential_environment).is_err()
        })
    {
        return Err(RemoteError::ProfileStorage);
    }
    Ok(store)
}

fn save_store(path: &Path, store: &ProfileStore) -> Result<(), RemoteError> {
    let parent = path.parent().ok_or(RemoteError::ProfileStorage)?;
    fs::create_dir_all(parent).map_err(|_| RemoteError::ProfileStorage)?;
    let mut temporary = NamedTempFile::new_in(parent).map_err(|_| RemoteError::ProfileStorage)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| RemoteError::ProfileStorage)?;
    }
    serde_json::to_writer_pretty(&mut temporary, store).map_err(|_| RemoteError::ProfileStorage)?;
    temporary
        .write_all(b"\n")
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|_| RemoteError::ProfileStorage)?;
    temporary
        .persist(path)
        .map_err(|_| RemoteError::ProfileStorage)?;
    Ok(())
}

fn print_json(value: &impl Serialize) -> Result<(), RemoteError> {
    let mut output =
        serde_json::to_string_pretty(value).map_err(|_| RemoteError::ProfileStorage)?;
    output.push('\n');
    std::io::stdout()
        .write_all(output.as_bytes())
        .map_err(|_| RemoteError::ProfileStorage)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_policy_allows_only_https_or_loopback_origins() {
        assert!(validate_endpoint("https://admin.example.com").is_ok());
        assert!(validate_endpoint("http://127.0.0.1:8081").is_ok());
        assert!(validate_endpoint("http://[::1]:8081/").is_ok());
        assert!(validate_endpoint("http://admin.example.com").is_err());
        assert!(validate_endpoint("https://admin.example.com/control/").is_err());
        assert!(validate_endpoint("https://user@admin.example.com/").is_err());
    }

    #[test]
    fn descriptor_rejects_cross_product_credentials_and_cross_origin_urls() {
        let endpoint = validate_endpoint("https://admin.example.com").unwrap();
        let valid = RawDescriptor {
            schema_version: "1".to_owned(),
            product: Product::OwlauthServer,
            instance_id: "deployment-1".to_owned(),
            api_base_url: "https://admin.example.com/v1/".to_owned(),
            api_versions: vec!["v1".to_owned()],
            credential_class: CredentialClass::OperatorApiKey,
            mcp_url: None,
        };
        assert!(validate_descriptor(&endpoint, valid).is_ok());

        let wrong_pair = RawDescriptor {
            schema_version: "1".to_owned(),
            product: Product::OwlauthSaas,
            instance_id: "deployment-1".to_owned(),
            api_base_url: "https://admin.example.com/v1/".to_owned(),
            api_versions: vec!["v1".to_owned()],
            credential_class: CredentialClass::OperatorApiKey,
            mcp_url: None,
        };
        assert!(validate_descriptor(&endpoint, wrong_pair).is_err());

        let cross_origin = RawDescriptor {
            schema_version: "1".to_owned(),
            product: Product::OwlauthServer,
            instance_id: "deployment-1".to_owned(),
            api_base_url: "https://other.example.com/v1/".to_owned(),
            api_versions: vec!["v1".to_owned()],
            credential_class: CredentialClass::OperatorApiKey,
            mcp_url: None,
        };
        assert!(validate_descriptor(&endpoint, cross_origin).is_err());

        let noncanonical = RawDescriptor {
            schema_version: "1".to_owned(),
            product: Product::OwlauthServer,
            instance_id: "deployment-1".to_owned(),
            api_base_url: "https://admin.example.com:443/v1/".to_owned(),
            api_versions: vec!["v1".to_owned()],
            credential_class: CredentialClass::OperatorApiKey,
            mcp_url: None,
        };
        assert!(validate_descriptor(&endpoint, noncanonical).is_err());
    }

    #[test]
    fn operator_key_recognition_is_exact() {
        assert!(is_operator_key(&format!("owl_ctrl_v1_{}", "A".repeat(43))));
        assert!(!is_operator_key(&format!("owl_saas_v1_{}", "A".repeat(43))));
        assert!(!is_operator_key(&format!("owl_ctrl_v1_{}", "A".repeat(42))));
    }
}
