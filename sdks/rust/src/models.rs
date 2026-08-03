use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};
use zeroize::Zeroizing;

fn deserialize_required_nullable<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)
}

macro_rules! secret_string {
    ($name:ident, $label:literal) => {
        pub struct $name(Zeroizing<String>);

        impl $name {
            pub(crate) fn new(value: String) -> Self {
                Self(Zeroizing::new(value))
            }

            /// Deliberately exposes the raw credential for an explicit protocol operation.
            #[must_use]
            pub fn expose(&self) -> &str {
                self.0.as_str()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!($label, "([REDACTED])"))
            }
        }
    };
}

secret_string!(AccessToken, "AccessToken");
secret_string!(RefreshToken, "RefreshToken");

/// Public provider presentation returned by Runtime.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct PublicProvider {
    pub key: String,
    pub display_name: String,
    pub kind: String,
}

/// Public Project/Application login configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the public wire contract exposes orthogonal current capability facts"
)]
pub struct PublicConfiguration {
    pub project_public_id: String,
    pub project_display_name: String,
    pub application_public_id: String,
    pub application_display_name: String,
    pub publishable_keys: Vec<String>,
    pub providers: Vec<PublicProvider>,
    pub email_available: bool,
    pub email_otp_enabled: bool,
    pub email_magic_link_enabled: bool,
    pub login_available: bool,
}

/// One public Project signing key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct PublicJwk {
    pub kty: String,
    pub crv: String,
    pub alg: String,
    #[serde(rename = "use")]
    pub key_use: String,
    pub kid: String,
    pub x: String,
}

/// Project JWKS plus authoritative revision metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct JwksDocument {
    pub keys: Vec<PublicJwk>,
    pub revision: i64,
    pub signing_epoch: i64,
}

/// Deterministic bounded Application user projection.
#[derive(Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct UserProjection {
    pub user_id: String,
    pub user_revision: i64,
    pub projection_schema: String,
    pub projection_revision: i64,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub display_name: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub picture_url: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub locale: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub verified_email: Option<String>,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

impl fmt::Debug for UserProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UserProjection")
            .field("user_id", &self.user_id)
            .field("user_revision", &self.user_revision)
            .field("projection_schema", &self.projection_schema)
            .field("projection_revision", &self.projection_revision)
            .field("profile", &"[REDACTED]")
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

/// Explicit caller-held login state. Debug output never reveals PKCE or state material.
pub struct PendingLogin {
    pub(crate) schema_version: u8,
    pub(crate) runtime_origin: String,
    pub(crate) project_id: String,
    pub(crate) application_id: String,
    pub(crate) redirect_uri: String,
    pub(crate) verifier: Zeroizing<String>,
    pub(crate) state: Zeroizing<String>,
    pub(crate) created_at: i64,
    pub(crate) expires_at: i64,
}

impl PendingLogin {
    #[must_use]
    pub const fn schema_version(&self) -> u8 {
        self.schema_version
    }

    #[must_use]
    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    #[must_use]
    pub fn application_id(&self) -> &str {
        &self.application_id
    }

    #[must_use]
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    #[must_use]
    pub const fn created_at(&self) -> i64 {
        self.created_at
    }

    #[must_use]
    pub const fn expires_at(&self) -> i64 {
        self.expires_at
    }
}

impl fmt::Debug for PendingLogin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingLogin")
            .field("schema_version", &self.schema_version)
            .field("runtime_origin", &self.runtime_origin)
            .field("project_id", &self.project_id)
            .field("application_id", &self.application_id)
            .field("redirect_uri", &"[REDACTED]")
            .field("verifier", &"[REDACTED]")
            .field("state", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Login start output. The SDK does not navigate to `hosted_url`.
pub struct LoginStart {
    pub hosted_url: String,
    pub pending: PendingLogin,
}

impl fmt::Debug for LoginStart {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoginStart")
            .field("hosted_url", &"[REDACTED]")
            .field("pending", &self.pending)
            .finish()
    }
}

/// Locally validated one-attempt callback material.
pub struct ValidatedCallback {
    pub(crate) handoff: Zeroizing<String>,
    pub(crate) verifier: Zeroizing<String>,
}

impl fmt::Debug for ValidatedCallback {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ValidatedCallback([REDACTED])")
    }
}

/// Atomic access/refresh generation returned by Runtime.
pub struct CredentialPair {
    project_id: String,
    application_id: String,
    user_id: String,
    session_id: String,
    refresh_generation: i64,
    access_token: AccessToken,
    refresh_token: RefreshToken,
    token_type: String,
    expires_in: i64,
    projection: UserProjection,
    projection_revision: i64,
    session_expires_at: String,
}

impl CredentialPair {
    #[must_use]
    pub fn project_id(&self) -> &str {
        &self.project_id
    }
    #[must_use]
    pub fn application_id(&self) -> &str {
        &self.application_id
    }
    #[must_use]
    pub fn user_id(&self) -> &str {
        &self.user_id
    }
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
    #[must_use]
    pub const fn refresh_generation(&self) -> i64 {
        self.refresh_generation
    }
    #[must_use]
    pub const fn access_token(&self) -> &AccessToken {
        &self.access_token
    }
    #[must_use]
    pub const fn refresh_token(&self) -> &RefreshToken {
        &self.refresh_token
    }
    #[must_use]
    pub fn token_type(&self) -> &str {
        &self.token_type
    }
    #[must_use]
    pub const fn expires_in(&self) -> i64 {
        self.expires_in
    }
    #[must_use]
    pub const fn projection(&self) -> &UserProjection {
        &self.projection
    }
    #[must_use]
    pub const fn projection_revision(&self) -> i64 {
        self.projection_revision
    }
    #[must_use]
    pub fn session_expires_at(&self) -> &str {
        &self.session_expires_at
    }

    pub(crate) fn from_wire(value: CredentialPairWire) -> Self {
        Self {
            project_id: value.project_id,
            application_id: value.application_id,
            user_id: value.user_id,
            session_id: value.session_id,
            refresh_generation: value.refresh_generation,
            access_token: AccessToken::new(value.access_token),
            refresh_token: RefreshToken::new(value.refresh_token),
            token_type: value.token_type,
            expires_in: value.expires_in,
            projection: value.projection,
            projection_revision: value.projection_revision,
            session_expires_at: value.session_expires_at,
        }
    }
}

impl fmt::Debug for CredentialPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialPair")
            .field("project_id", &self.project_id)
            .field("application_id", &self.application_id)
            .field("user_id", &self.user_id)
            .field("session_id", &self.session_id)
            .field("refresh_generation", &self.refresh_generation)
            .field("access_token", &self.access_token)
            .field("refresh_token", &self.refresh_token)
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("projection", &"[REDACTED]")
            .field("projection_revision", &self.projection_revision)
            .field("session_expires_at", &self.session_expires_at)
            .finish()
    }
}

/// Current Project user and Application session view.
#[derive(Clone, Deserialize, PartialEq)]
pub struct CurrentUser {
    pub project_id: String,
    pub application_id: String,
    pub user_id: String,
    pub projection: UserProjection,
    pub projection_revision: i64,
    pub authenticated_at: String,
    pub session_expires_at: String,
}

impl fmt::Debug for CurrentUser {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CurrentUser")
            .field("project_id", &self.project_id)
            .field("application_id", &self.application_id)
            .field("user_id", &self.user_id)
            .field("projection", &"[REDACTED]")
            .field("projection_revision", &self.projection_revision)
            .field("authenticated_at", &self.authenticated_at)
            .field("session_expires_at", &self.session_expires_at)
            .finish()
    }
}

/// Project browser logout target. The SDK never navigates to it.
#[derive(Clone, Deserialize, Eq, PartialEq)]
pub struct BrowserLogoutPreparation {
    pub hosted_url: String,
    pub expires_at: String,
}

impl fmt::Debug for BrowserLogoutPreparation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserLogoutPreparation")
            .field("hosted_url", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Serialize)]
pub(crate) struct LoginStartRequest<'a> {
    pub application_id: &'a str,
    pub publishable_key: &'a str,
    pub redirect_uri: &'a str,
    pub pkce_challenge: &'a str,
    pub state: &'a str,
    pub presentation_hint: Option<&'a str>,
}

#[derive(Deserialize)]
pub(crate) struct LoginStartResponse {
    pub hosted_url: String,
    pub expires_at: String,
}

#[derive(Serialize)]
pub(crate) struct HandoffRequest<'a> {
    pub application_id: &'a str,
    pub publishable_key: &'a str,
    pub handoff: &'a str,
    pub pkce_verifier: &'a str,
}

#[derive(Serialize)]
pub(crate) struct RefreshRequest<'a> {
    pub application_id: &'a str,
    pub publishable_key: &'a str,
    pub refresh_token: &'a str,
}

#[derive(Deserialize)]
pub(crate) struct CredentialPairWire {
    pub project_id: String,
    pub application_id: String,
    pub user_id: String,
    pub session_id: String,
    pub refresh_generation: i64,
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub projection: UserProjection,
    pub projection_revision: i64,
    pub session_expires_at: String,
}

#[derive(Deserialize)]
pub(crate) struct CompletionResponse {
    pub completed: bool,
}

#[derive(Deserialize)]
pub(crate) struct RuntimeErrorWire {
    pub code: String,
    pub message: String,
    pub request_id: String,
}
