use std::{
    collections::BTreeMap,
    env, fs,
    io::{Read, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use reqwest::{
    Method,
    blocking::{Client, Response},
    header::{ACCEPT, CONTENT_TYPE},
    redirect::Policy,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tempfile::NamedTempFile;
use thiserror::Error;
use url::{Host, Url};
use zeroize::{Zeroize, Zeroizing};

const STORE_SCHEMA_VERSION: u32 = 1;
const MAX_DESCRIPTOR_BYTES: u64 = 64 * 1024;
const MAX_API_RESPONSE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_STORE_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Product {
    OwlauthServer,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum CredentialClass {
    OperatorApiKey,
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
    proposed_credential_environment: &'a str,
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
    #[error(
        "rebind requires a credential environment reference different from the existing profile"
    )]
    ReusedCredentialEnvironment,
    #[error("credential environment variable {0} is missing")]
    MissingCredential(String),
    #[error("credential does not match the discovered product")]
    WrongCredentialClass,
    #[error(
        "write-only resource secret must not reuse the operator credential or its environment reference"
    )]
    OperatorCredentialReuse,
    #[error("command is not supported by the discovered product")]
    UnsupportedCommand,
    #[error("remote API request failed")]
    ApiTransport,
    #[error("remote API returned HTTP {status}: {code}: {detail} (request {request_id})")]
    ApiProblem {
        status: u16,
        code: String,
        detail: String,
        request_id: String,
    },
    #[error("remote API returned HTTP status {0} without a valid problem response")]
    ApiStatus(u16),
    #[error("remote API response exceeds its reviewed bound")]
    ApiResponseTooLarge,
    #[error("remote API returned a malformed response")]
    InvalidApiResponse,
    #[error("resource identifier must be a canonical lowercase hyphenated UUID")]
    InvalidResourceId,
    #[error("idempotency key must be 8-128 ASCII letters, digits, '_' or '-'")]
    InvalidIdempotencyKey,
    #[error("history limit must be between 1 and 100")]
    InvalidHistoryLimit,
    #[error("Custom OIDC requires --issuer; named provider presets forbid --issuer")]
    InvalidProviderVariant,
    #[error("this operation requires explicit --yes confirmation")]
    OperationConfirmationRequired,
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
    credential_environment: &str,
    confirmed: bool,
) -> Result<(), RemoteError> {
    rebind_profile_at(
        &store_path()?,
        name,
        endpoint,
        credential_environment,
        confirmed,
    )
}

fn rebind_profile_at(
    path: &Path,
    name: &str,
    endpoint: &str,
    credential_environment: &str,
    confirmed: bool,
) -> Result<(), RemoteError> {
    validate_profile_name(name)?;
    validate_credential_environment(credential_environment)?;
    let mut store = load_store(path)?;
    let old = store
        .profiles
        .get(name)
        .ok_or_else(|| RemoteError::ProfileMissing(name.to_owned()))?;
    validate_new_credential_environment(old, credential_environment)?;
    let endpoint = validate_endpoint(endpoint)?;
    let descriptor = discover(&endpoint)?;
    print_json(&RebindPreview {
        old,
        new: &descriptor,
        proposed_credential_environment: credential_environment,
    })?;
    if !confirmed {
        return Err(RemoteError::ConfirmationRequired);
    }
    let profile = profile_from_descriptor(&endpoint, descriptor, Some(credential_environment))?;
    store.profiles.insert(name.to_owned(), profile);
    save_store(path, &store)
}

pub fn check_profile(name: Option<&str>) -> Result<(), RemoteError> {
    let store = load_store(&store_path()?)?;
    let (name, profile) = select_profile(&store, name)?;
    let descriptor = validate_current_identity(name, profile)?;
    print_json(&descriptor)
}

pub fn system(profile_name: Option<&str>) -> Result<(), RemoteError> {
    let client = authenticated_server(profile_name)?;
    let capabilities: owlauth_types::control::SystemCapabilities = client.get("system")?;
    if capabilities.product != "owlauth-server" {
        return Err(RemoteError::InvalidApiResponse);
    }
    print_json(&capabilities)
}

pub(crate) struct StoredProfile {
    name: String,
    profile: Profile,
}

struct ValidatedSelfHostedProfile {
    profile: Profile,
    descriptor: Descriptor,
}

pub(crate) struct AuthenticatedServerClient {
    client: Client,
    api_base: Url,
    credential_environment: String,
    credential: String,
}

impl StoredProfile {
    fn load(profile_name: Option<&str>) -> Result<Self, RemoteError> {
        let store = load_store(&store_path()?)?;
        let (name, profile) = select_profile(&store, profile_name)?;
        Ok(Self {
            name: name.to_owned(),
            profile: profile.clone(),
        })
    }

    fn validate_self_hosted(self) -> Result<ValidatedSelfHostedProfile, RemoteError> {
        let descriptor = validate_current_identity(&self.name, &self.profile)?;
        if descriptor.product != Product::OwlauthServer {
            return Err(RemoteError::UnsupportedCommand);
        }
        Ok(ValidatedSelfHostedProfile {
            profile: self.profile,
            descriptor,
        })
    }
}

impl ValidatedSelfHostedProfile {
    fn authenticate(self) -> Result<AuthenticatedServerClient, RemoteError> {
        let credential = read_credential(&self.profile)?;
        authenticate_validated_profile(self.profile, &self.descriptor, credential)
    }
}

fn authenticate_validated_profile(
    profile: Profile,
    descriptor: &Descriptor,
    mut credential: String,
) -> Result<AuthenticatedServerClient, RemoteError> {
    if !is_operator_key(&credential) {
        credential.zeroize();
        return Err(RemoteError::WrongCredentialClass);
    }
    let client = match http_client() {
        Ok(client) => client,
        Err(error) => {
            credential.zeroize();
            return Err(error);
        }
    };
    let Ok(api_base) = Url::parse(&descriptor.api_base_url) else {
        credential.zeroize();
        return Err(RemoteError::InvalidDescriptor);
    };
    let client = AuthenticatedServerClient {
        client,
        api_base,
        credential_environment: profile.credential_environment,
        credential,
    };
    let capabilities: owlauth_types::control::SystemCapabilities = client.get("system")?;
    if capabilities.product != "owlauth-server" {
        return Err(RemoteError::InvalidApiResponse);
    }
    Ok(client)
}

pub(crate) fn authenticated_server(
    profile_name: Option<&str>,
) -> Result<AuthenticatedServerClient, RemoteError> {
    authenticated_server_snapshot(StoredProfile::load(profile_name)?)
}

pub(crate) fn authenticated_server_snapshot(
    stored: StoredProfile,
) -> Result<AuthenticatedServerClient, RemoteError> {
    stored.validate_self_hosted()?.authenticate()
}

impl AuthenticatedServerClient {
    #[cfg(test)]
    pub(crate) fn for_transport_test(api_base: Url) -> Self {
        Self {
            client: http_client().expect("test HTTP client"),
            api_base,
            credential_environment: "TEST_OPERATOR_KEY".to_owned(),
            credential: format!("owl_ctrl_v1_{}", "A".repeat(43)),
        }
    }

    pub(crate) fn read_write_only_secret(&self, name: &str) -> Result<String, RemoteError> {
        if name == self.credential_environment {
            return Err(RemoteError::OperatorCredentialReuse);
        }
        let mut value = read_secret_environment(name)?;
        if let Err(error) =
            validate_write_only_secret(&self.credential_environment, &self.credential, name, &value)
        {
            value.zeroize();
            return Err(error);
        }
        Ok(value)
    }

    pub(crate) fn get<T: DeserializeOwned>(&self, relative: &str) -> Result<T, RemoteError> {
        let response = self
            .request(Method::GET, relative)?
            .send()
            .map_err(|_| RemoteError::ApiTransport)?;
        decode_api_response(response)
    }

    pub(crate) fn get_with_query<T: DeserializeOwned>(
        &self,
        relative: &str,
        query: &[(&str, String)],
    ) -> Result<T, RemoteError> {
        let mut url = self.relative_url(relative)?;
        {
            let mut pairs = url.query_pairs_mut();
            for (name, value) in query {
                pairs.append_pair(name, value);
            }
        }
        let response = self
            .client
            .get(url)
            .bearer_auth(&self.credential)
            .header(ACCEPT, "application/json")
            .send()
            .map_err(|_| RemoteError::ApiTransport)?;
        decode_api_response(response)
    }

    pub(crate) fn send<B: Serialize, T: DeserializeOwned>(
        &self,
        method: Method,
        relative: &str,
        body: &B,
        idempotency_key: Option<&str>,
    ) -> Result<T, RemoteError> {
        let mut request = self.request(method, relative)?.json(body);
        if let Some(key) = idempotency_key {
            validate_idempotency_key(key)?;
            request = request.header("Idempotency-Key", key);
        }
        let response = request.send().map_err(|_| RemoteError::ApiTransport)?;
        decode_api_response(response)
    }

    fn request(
        &self,
        method: Method,
        relative: &str,
    ) -> Result<reqwest::blocking::RequestBuilder, RemoteError> {
        Ok(self
            .client
            .request(method, self.relative_url(relative)?)
            .bearer_auth(&self.credential)
            .header(ACCEPT, "application/json"))
    }

    fn relative_url(&self, relative: &str) -> Result<Url, RemoteError> {
        if relative.is_empty()
            || relative.starts_with('/')
            || relative.contains('%')
            || relative.contains('\\')
            || relative.contains('?')
            || relative.contains('#')
            || relative
                .split('/')
                .any(|segment| matches!(segment, "." | ".."))
        {
            return Err(RemoteError::InvalidApiResponse);
        }
        self.api_base
            .join(relative)
            .map_err(|_| RemoteError::InvalidDescriptor)
    }
}

impl Drop for AuthenticatedServerClient {
    fn drop(&mut self) {
        self.credential.zeroize();
    }
}

fn profile_from_descriptor(
    endpoint: &Url,
    descriptor: Descriptor,
    credential_environment: Option<&str>,
) -> Result<Profile, RemoteError> {
    let default_environment = match descriptor.credential_class {
        CredentialClass::OperatorApiKey => "OWLAUTH_CONTROL_API_KEY",
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
        && descriptor.api_versions == profile.api_versions
        && descriptor.credential_class == profile.credential_class
        && descriptor.mcp_url == profile.mcp_url;
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

fn decode_api_response<T: DeserializeOwned>(response: Response) -> Result<T, RemoteError> {
    let status = response.status();
    let status_code = status.as_u16();
    let json_content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"));
    if !json_content_type {
        return Err(if status.is_success() {
            RemoteError::InvalidApiResponse
        } else {
            RemoteError::ApiStatus(status_code)
        });
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_API_RESPONSE_BYTES)
    {
        return Err(RemoteError::ApiResponseTooLarge);
    }
    // Control responses can contain one-time credentials. Keep the raw response buffer under
    // zeroizing ownership even though most decoded response models are secret-free.
    let mut bytes = Zeroizing::new(Vec::new());
    response
        .take(MAX_API_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| RemoteError::ApiTransport)?;
    if bytes.len() as u64 > MAX_API_RESPONSE_BYTES {
        return Err(RemoteError::ApiResponseTooLarge);
    }
    if status.is_success() {
        return serde_json::from_slice(&bytes).map_err(|_| RemoteError::InvalidApiResponse);
    }
    let problem: owlauth_types::control::ProblemDetails =
        serde_json::from_slice(&bytes).map_err(|_| RemoteError::ApiStatus(status_code))?;
    if problem.status != status_code
        || problem.code.is_empty()
        || problem.code.len() > 128
        || problem.detail.is_empty()
        || problem.detail.len() > 1024
        || problem.request_id.is_empty()
        || problem.request_id.len() > 128
    {
        return Err(RemoteError::ApiStatus(status_code));
    }
    Err(RemoteError::ApiProblem {
        status: status_code,
        code: problem.code,
        detail: problem.detail,
        request_id: problem.request_id,
    })
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

fn validate_new_credential_environment(old: &Profile, proposed: &str) -> Result<(), RemoteError> {
    validate_credential_environment(proposed)?;
    if old.credential_environment == proposed {
        return Err(RemoteError::ReusedCredentialEnvironment);
    }
    Ok(())
}

pub(crate) fn validate_credential_environment(name: &str) -> Result<(), RemoteError> {
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
    read_secret_environment(&profile.credential_environment)
}

fn read_secret_environment(name: &str) -> Result<String, RemoteError> {
    validate_credential_environment(name)?;
    env::var(name).map_err(|_| RemoteError::MissingCredential(name.to_owned()))
}

fn validate_write_only_secret(
    operator_environment: &str,
    operator_credential: &str,
    requested_environment: &str,
    value: &str,
) -> Result<(), RemoteError> {
    if requested_environment == operator_environment || value == operator_credential {
        return Err(RemoteError::OperatorCredentialReuse);
    }
    Ok(())
}

pub(crate) fn validate_resource_id(value: &str) -> Result<(), RemoteError> {
    let parsed = uuid::Uuid::parse_str(value).map_err(|_| RemoteError::InvalidResourceId)?;
    if parsed.to_string() != value {
        return Err(RemoteError::InvalidResourceId);
    }
    Ok(())
}

pub(crate) fn validate_idempotency_key(value: &str) -> Result<(), RemoteError> {
    if value.len() < 8
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(RemoteError::InvalidIdempotencyKey);
    }
    Ok(())
}

pub(crate) fn require_confirmation<S: Serialize + ?Sized>(
    confirmed: bool,
    profile_name: Option<&str>,
    operation: &str,
    target: &str,
    effect: &S,
) -> Result<StoredProfile, RemoteError> {
    if !confirmed {
        return Err(RemoteError::OperationConfirmationRequired);
    }
    let stored = StoredProfile::load(profile_name)?;
    let preview = confirmation_preview(&stored, operation, target, effect);
    eprintln!(
        "{}",
        serde_json::to_string(&preview).map_err(|_| RemoteError::ProfileStorage)?
    );
    Ok(stored)
}

fn confirmation_preview<S: Serialize + ?Sized>(
    stored: &StoredProfile,
    operation: &str,
    target: &str,
    effect: &S,
) -> serde_json::Value {
    serde_json::json!({
        "confirmation": {
            "profile": stored.name,
            "endpoint": stored.profile.endpoint,
            "instance_id": stored.profile.instance_id,
            "operation": operation,
            "target": target,
            "effect": effect,
        }
    })
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

pub(crate) fn print_json(value: &impl Serialize) -> Result<(), RemoteError> {
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
    fn store_load_rejects_unknown_and_crossed_profile_kinds_without_rewriting() {
        for (product, credential_class) in [
            ("owlauth-sever", "operator-api-key"),
            ("owlauth-server", "operator-key"),
            ("owlauth-saas", "saas-api-key"),
            ("owlauth-saas", "operator-api-key"),
            ("owlauth-server", "saas-api-key"),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("profiles.json");
            let original = serde_json::to_vec_pretty(&serde_json::json!({
                "schema_version": STORE_SCHEMA_VERSION,
                "current_profile": "broken",
                "profiles": {
                    "broken": {
                        "endpoint": "https://admin.example/",
                        "product": product,
                        "instance_id": "instance",
                        "api_base_url": "https://admin.example/v1/",
                        "api_versions": ["v1"],
                        "credential_class": credential_class,
                        "credential_environment": "OPERATOR_KEY"
                    }
                }
            }))
            .unwrap();
            fs::write(&path, &original).unwrap();

            assert!(matches!(
                load_store(&path),
                Err(RemoteError::ProfileStorage)
            ));
            assert_eq!(fs::read(path).unwrap(), original);
        }
    }

    #[test]
    fn store_load_rejects_non_current_schema_and_unknown_fields() {
        let base = serde_json::json!({
            "schema_version": STORE_SCHEMA_VERSION,
            "current_profile": "server",
            "profiles": {
                "server": test_profile("http://127.0.0.1:8081/", "SERVER_OPERATOR_KEY")
            }
        });
        let mut unsupported_version = base.clone();
        unsupported_version["schema_version"] = serde_json::json!(STORE_SCHEMA_VERSION + 1);
        let mut unknown_store_field = base.clone();
        unknown_store_field["obsolete"] = serde_json::json!(true);
        let mut unknown_profile_field = base;
        unknown_profile_field["profiles"]["server"]["obsolete"] = serde_json::json!(true);

        for document in [
            unsupported_version,
            unknown_store_field,
            unknown_profile_field,
        ] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("profiles.json");
            let original = serde_json::to_vec_pretty(&document).unwrap();
            fs::write(&path, &original).unwrap();

            assert!(matches!(
                load_store(&path),
                Err(RemoteError::ProfileStorage)
            ));
            assert_eq!(fs::read(path).unwrap(), original);
        }
    }

    #[test]
    fn store_load_rejects_duplicate_profile_fields() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("profiles.json");
        let document = br#"{
          "schema_version": 1,
          "current_profile": "server",
          "profiles": {
            "server": {
              "endpoint": "https://first.example/",
              "endpoint": "https://second.example/",
              "product": "owlauth-server",
              "instance_id": "instance",
              "api_base_url": "https://first.example/v1/",
              "api_versions": ["v1"],
              "credential_class": "operator-api-key",
              "credential_environment": "OPERATOR_KEY"
            }
          }
        }"#;
        fs::write(&path, document).unwrap();

        assert!(matches!(
            load_store(&path),
            Err(RemoteError::ProfileStorage)
        ));
        assert_eq!(fs::read(path).unwrap(), document);
    }

    #[test]
    fn descriptor_rejects_cross_origin_and_noncanonical_urls() {
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
        assert!(!is_operator_key(&format!("owl_ctrl_v1_{}", "A".repeat(42))));
    }

    #[test]
    fn confirmation_preview_binds_the_exact_redacted_command_summary() {
        let stored = StoredProfile {
            name: "production".to_owned(),
            profile: Profile {
                endpoint: "https://control.example/".to_owned(),
                product: Product::OwlauthServer,
                instance_id: "deployment-1".to_owned(),
                api_base_url: "https://control.example/v1/".to_owned(),
                api_versions: vec!["v1".to_owned()],
                credential_class: CredentialClass::OperatorApiKey,
                credential_environment: "OWLAUTH_CONTROL_API_KEY".to_owned(),
                mcp_url: Some("https://control.example/mcp".to_owned()),
            },
        };
        let first = confirmation_preview(
            &stored,
            "project-user.disable",
            "projects/project/users/user/disable",
            &serde_json::json!({
                "effect": "disable the Project user and revoke its authority",
                "expected_security_revision": 7,
            }),
        );
        let second = confirmation_preview(
            &stored,
            "project-user.disable",
            "projects/project/users/user/disable",
            &serde_json::json!({
                "effect": "disable the Project user and revoke its authority",
                "expected_security_revision": 8,
            }),
        );
        assert_ne!(first, second);
        assert_eq!(
            first["confirmation"]["effect"]["effect"],
            "disable the Project user and revoke its authority"
        );
        assert_eq!(
            first["confirmation"]["effect"]["expected_security_revision"],
            7
        );
        let encoded = first.to_string();
        assert!(!encoded.contains("OWLAUTH_CONTROL_API_KEY"));
        assert!(!encoded.contains("owl_ctrl_v1_"));
    }

    #[test]
    fn system_capabilities_match_the_public_control_contract() {
        let response = serde_json::to_vec(&owlauth_types::control::get_system()).unwrap();
        let capabilities: owlauth_types::control::SystemCapabilities =
            serde_json::from_slice(&response).unwrap();

        assert_eq!(capabilities.product, "owlauth-server");
        assert!(capabilities.provisioning);
        assert!(capabilities.login_readiness);
        assert!(capabilities.federated_project_auth);
    }

    #[test]
    fn rebind_requires_a_distinct_reference_and_previews_it_without_reading_env() {
        let profile = test_profile("http://127.0.0.1:1/", "OLD_OPERATOR_KEY");
        assert!(matches!(
            validate_new_credential_environment(&profile, "OLD_OPERATOR_KEY"),
            Err(RemoteError::ReusedCredentialEnvironment)
        ));
        validate_new_credential_environment(&profile, "NEW_OPERATOR_KEY").unwrap();
        let descriptor = Descriptor {
            schema_version: "1".to_owned(),
            product: Product::OwlauthServer,
            instance_id: "new-instance".to_owned(),
            api_base_url: "https://admin.example.com/v1/".to_owned(),
            api_versions: vec!["v1".to_owned()],
            credential_class: CredentialClass::OperatorApiKey,
            mcp_url: None,
        };
        let preview = serde_json::to_value(RebindPreview {
            old: &profile,
            new: &descriptor,
            proposed_credential_environment: "NEW_OPERATOR_KEY",
        })
        .unwrap();
        assert_eq!(
            preview["proposed_credential_environment"],
            "NEW_OPERATOR_KEY"
        );
    }

    #[test]
    fn confirmed_rebind_replaces_only_the_pin_and_new_reference_without_env_access() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("profiles.json");
        let mut store = ProfileStore::default();
        store.profiles.insert(
            "local".to_owned(),
            test_profile("http://127.0.0.1:1/", "ABSENT_OLD_OPERATOR_KEY"),
        );
        store.current_profile = Some("local".to_owned());
        save_store(&path, &store).unwrap();
        let (endpoint, server) = one_response_server(
            200,
            serde_json::json!({
                "schema_version": "1",
                "product": "owlauth-server",
                "instance_id": "new-instance",
                "api_base_url": "PLACEHOLDER",
                "api_versions": ["v1"],
                "credential_class": "operator-api-key",
                "mcp_url": null
            }),
            true,
        );
        rebind_profile_at(&path, "local", &endpoint, "ABSENT_NEW_OPERATOR_KEY", true).unwrap();
        server.join().unwrap();
        let rebound = load_store(&path).unwrap();
        let profile = &rebound.profiles["local"];
        assert_eq!(profile.instance_id, "new-instance");
        assert_eq!(profile.credential_environment, "ABSENT_NEW_OPERATOR_KEY");
    }

    #[test]
    fn rejected_operator_credential_stops_at_system_handshake_before_resource_secrets() {
        let (origin, server) = one_response_server(401, serde_json::json!({}), false);
        let mut profile = test_profile(&origin, "TEST_OPERATOR_KEY");
        profile.api_base_url = format!("{origin}v1/");
        let descriptor = Descriptor {
            schema_version: "1".to_owned(),
            product: Product::OwlauthServer,
            instance_id: profile.instance_id.clone(),
            api_base_url: profile.api_base_url.clone(),
            api_versions: vec!["v1".to_owned()],
            credential_class: CredentialClass::OperatorApiKey,
            mcp_url: None,
        };
        let rejected = authenticate_validated_profile(
            profile,
            &descriptor,
            format!("owl_ctrl_v1_{}", "Z".repeat(43)),
        );
        assert!(matches!(rejected, Err(RemoteError::ApiStatus(401))));
        let request = server.join().unwrap();
        assert!(request.starts_with("GET /v1/system HTTP/1.1"));
        assert!(!request.contains("client_secret"));
        assert!(!request.contains("webhook"));
    }

    #[test]
    fn write_only_resource_secrets_cannot_alias_the_operator_credential() {
        let operator = format!("owl_ctrl_v1_{}", "A".repeat(43));
        assert!(matches!(
            validate_write_only_secret("OPERATOR_KEY", &operator, "OPERATOR_KEY", "other"),
            Err(RemoteError::OperatorCredentialReuse)
        ));
        assert!(matches!(
            validate_write_only_secret("OPERATOR_KEY", &operator, "PROVIDER_SECRET", &operator),
            Err(RemoteError::OperatorCredentialReuse)
        ));
        validate_write_only_secret("OPERATOR_KEY", &operator, "PROVIDER_SECRET", "different")
            .unwrap();
    }

    #[test]
    fn canonical_resource_and_idempotency_validation_is_exact() {
        assert!(validate_resource_id("11111111-1111-4111-8111-111111111111").is_ok());
        assert!(validate_resource_id("11111111111141118111111111111111").is_err());
        assert!(validate_resource_id("11111111-1111-4111-8111-AAAAAAAAAAAA").is_err());
        assert!(validate_idempotency_key("project_create_1").is_ok());
        assert!(validate_idempotency_key("short").is_err());
        assert!(validate_idempotency_key("contains.dot").is_err());
    }

    #[test]
    fn confirmation_snapshot_remains_bound_after_profile_replacement() {
        let (endpoint, server) = one_response_server(
            200,
            serde_json::json!({
                "schema_version": "1",
                "product": "owlauth-server",
                "instance_id": "pinned-instance",
                "api_base_url": "PLACEHOLDER",
                "api_versions": ["v1"],
                "credential_class": "operator-api-key",
                "mcp_url": null
            }),
            true,
        );
        let mut store = ProfileStore::default();
        store.profiles.insert(
            "local".to_owned(),
            test_profile(&endpoint, "SNAPSHOT_OPERATOR_KEY"),
        );
        let (name, profile) = select_profile(&store, Some("local")).unwrap();
        let snapshot = StoredProfile {
            name: name.to_owned(),
            profile: profile.clone(),
        };
        store.profiles.insert(
            "local".to_owned(),
            test_profile("http://127.0.0.1:1/", "REPLACEMENT_OPERATOR_KEY"),
        );

        let validated = snapshot
            .validate_self_hosted()
            .expect("owned confirmation snapshot still validates its original deployment");
        assert_eq!(validated.profile.endpoint, endpoint);
        assert_eq!(
            validated.profile.credential_environment,
            "SNAPSHOT_OPERATOR_KEY"
        );
        server.join().unwrap();
    }

    #[test]
    fn changed_descriptor_fails_before_the_missing_credential_can_be_read() {
        let (endpoint, server) = one_response_server(
            200,
            serde_json::json!({
                "schema_version": "1",
                "product": "owlauth-server",
                "instance_id": "changed-instance",
                "api_base_url": "PLACEHOLDER",
                "api_versions": ["v1"],
                "credential_class": "operator-api-key",
                "mcp_url": null
            }),
            true,
        );
        let mut profile = test_profile(&endpoint, "ENVIRONMENT_THAT_DOES_NOT_EXIST");
        profile.api_base_url = format!("{endpoint}v1/");
        let stored = StoredProfile {
            name: "local".to_owned(),
            profile,
        };
        assert!(matches!(
            stored.validate_self_hosted(),
            Err(RemoteError::IdentityChanged(name)) if name == "local"
        ));
        server.join().unwrap();
    }

    #[test]
    fn typed_client_uses_relative_api_base_and_decodes_bounded_problem() {
        let problem = serde_json::json!({
            "type": "about:blank",
            "code": "revision_conflict",
            "title": "Conflict",
            "status": 409,
            "detail": "The expected revision is stale.",
            "request_id": "request-1"
        });
        let (origin, server) = one_response_server(409, problem, false);
        let client = AuthenticatedServerClient {
            client: http_client().unwrap(),
            api_base: Url::parse(&format!("{origin}control/v1/")).unwrap(),
            credential_environment: "OPERATOR_KEY".to_owned(),
            credential: format!("owl_ctrl_v1_{}", "A".repeat(43)),
        };
        let result: Result<owlauth_types::control::Project, RemoteError> =
            client.get("projects/11111111-1111-4111-8111-111111111111");
        assert!(matches!(
            result,
            Err(RemoteError::ApiProblem {
                status: 409,
                code,
                request_id,
                ..
            }) if code == "revision_conflict" && request_id == "request-1"
        ));
        let request = server.join().unwrap();
        assert!(
            request.starts_with(
                "GET /control/v1/projects/11111111-1111-4111-8111-111111111111 HTTP/1.1"
            )
        );
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: bearer owl_ctrl_v1_")
        );
    }

    fn test_profile(endpoint: &str, credential_environment: &str) -> Profile {
        Profile {
            endpoint: endpoint.to_owned(),
            product: Product::OwlauthServer,
            instance_id: "pinned-instance".to_owned(),
            api_base_url: format!("{endpoint}v1/"),
            api_versions: vec!["v1".to_owned()],
            credential_class: CredentialClass::OperatorApiKey,
            credential_environment: credential_environment.to_owned(),
            mcp_url: None,
        }
    }

    fn one_response_server(
        status: u16,
        mut body: serde_json::Value,
        descriptor: bool,
    ) -> (String, std::thread::JoinHandle<String>) {
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}/", listener.local_addr().unwrap());
        if descriptor {
            body["api_base_url"] = serde_json::Value::String(format!("{origin}v1/"));
        }
        let encoded = serde_json::to_vec(&body).unwrap();
        let reason = if status == 200 { "OK" } else { "Conflict" };
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let read = stream.read(&mut buffer).unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            write!(
                stream,
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                encoded.len()
            )
            .unwrap();
            stream.write_all(&encoded).unwrap();
            String::from_utf8(request).unwrap()
        });
        (origin, server)
    }
}
