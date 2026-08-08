use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};
use utoipa::openapi::{
    RefOr,
    schema::{ObjectBuilder, Schema, SchemaType, Type},
    security::{Http, HttpAuthScheme, SecurityScheme},
};
use utoipa::{Modify, OpenApi, ToSchema};

use crate::health::HealthResponse;

fn deserialize_required_nullable<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)
}

fn deserialize_active_false<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    let value = bool::deserialize(deserializer)?;
    if value {
        return Err(serde::de::Error::custom("active must be false"));
    }
    Ok(false)
}

fn deserialize_active_true<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    let value = bool::deserialize(deserializer)?;
    if !value {
        return Err(serde::de::Error::custom("active must be true"));
    }
    Ok(true)
}

fn false_schema() -> RefOr<Schema> {
    ObjectBuilder::new()
        .schema_type(SchemaType::Type(Type::Boolean))
        .enum_values(Some([false]))
        .into()
}

fn true_schema() -> RefOr<Schema> {
    ObjectBuilder::new()
        .schema_type(SchemaType::Type(Type::Boolean))
        .enum_values(Some([true]))
        .into()
}

/// Stable Server API error codes. Authentication failures intentionally collapse to one code.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ServerErrorCode {
    InvalidRequest,
    InvalidCredential,
    NotFound,
    Conflict,
    RequestTimeout,
    TemporarilyUnavailable,
    InternalError,
}

/// Complete JSON error envelope for the isolated Server API.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ServerError {
    pub code: ServerErrorCode,
    #[schema(max_length = 256)]
    pub message: String,
    #[schema(max_length = 128)]
    pub request_id: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ServerUserStatus {
    Active,
    Disabled,
    Merged,
}

/// Project-owned user read model exposed to one authenticated customer backend.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ServerUser {
    #[schema(max_length = 96)]
    pub user_id: String,
    #[schema(max_length = 96)]
    pub project_id: String,
    pub status: ServerUserStatus,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    #[schema(max_length = 128, required = true)]
    pub display_name: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    #[schema(max_length = 2048, required = true)]
    pub picture_url: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    #[schema(max_length = 320, required = true)]
    pub verified_email: Option<String>,
    #[schema(minimum = 1)]
    pub user_revision: i64,
    #[schema(max_length = 64)]
    pub created_at: String,
    #[schema(max_length = 64)]
    pub updated_at: String,
}

/// One deterministic keyset page ordered by immutable `(created_at, user_id)`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ServerUserList {
    #[schema(max_items = 100)]
    pub items: Vec<ServerUser>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    #[schema(max_length = 64, required = true)]
    pub next_cursor: Option<String>,
}

/// Exact normalized-email lookup body. Email is never carried in a URL.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct LookupServerUserRequest {
    #[schema(min_length = 3, max_length = 320)]
    pub email: String,
}

/// Non-enumerating zero-or-one result inside the already authenticated Project.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct LookupServerUserResponse {
    #[serde(deserialize_with = "deserialize_required_nullable_user")]
    #[schema(required = true)]
    pub user: Option<ServerUser>,
}

fn deserialize_required_nullable_user<'de, D>(
    deserializer: D,
) -> Result<Option<ServerUser>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<ServerUser>::deserialize(deserializer)
}

/// Existing materialized Application projection; Server never performs an ad hoc reprojection.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ServerApplicationUserProjection {
    #[schema(max_length = 96)]
    pub project_id: String,
    #[schema(max_length = 96)]
    pub application_id: String,
    #[schema(max_length = 96)]
    pub user_id: String,
    #[schema(max_length = 64)]
    pub projection_schema: String,
    #[schema(minimum = 1)]
    pub user_revision: i64,
    #[schema(minimum = 1)]
    pub projection_revision: i64,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    #[schema(max_length = 128, required = true)]
    pub display_name: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    #[schema(max_length = 2048, required = true)]
    pub picture_url: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    #[schema(max_length = 35, required = true)]
    pub locale: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    #[schema(max_length = 320, required = true)]
    pub verified_email: Option<String>,
    #[schema(max_length = 32)]
    pub status: String,
    #[schema(max_length = 64)]
    pub created_at: String,
    #[schema(max_length = 64)]
    pub updated_at: String,
}

/// Bounded online introspection input. The token is write-only and always redacted in `Debug`.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct IntrospectProjectTokenRequest {
    #[schema(min_length = 1, max_length = 16384, write_only)]
    pub token: String,
    #[schema(max_length = 96)]
    pub expected_application_id: Option<String>,
}

impl fmt::Debug for IntrospectProjectTokenRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IntrospectProjectTokenRequest")
            .field("token", &"[REDACTED]")
            .field("expected_application_id", &self.expected_application_id)
            .finish()
    }
}

impl Drop for IntrospectProjectTokenRequest {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.token);
    }
}

/// Exact inactive introspection response. No denial reason or resource identity is disclosed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct InactiveProjectToken {
    #[serde(deserialize_with = "deserialize_active_false")]
    #[schema(schema_with = false_schema)]
    pub active: bool,
}

/// Current online authority for one active Project access token.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ActiveProjectToken {
    #[serde(deserialize_with = "deserialize_active_true")]
    #[schema(schema_with = true_schema)]
    pub active: bool,
    #[schema(max_length = 96)]
    pub project_id: String,
    #[schema(max_length = 96)]
    pub application_id: String,
    #[schema(max_length = 96)]
    pub user_id: String,
    #[schema(max_length = 64)]
    pub session_id: String,
    #[schema(max_length = 32)]
    pub token_type: String,
    #[schema(max_length = 64)]
    pub issued_at: String,
    #[schema(max_length = 64)]
    pub expires_at: String,
    #[schema(minimum = 1)]
    pub user_revision: i64,
    #[schema(minimum = 1)]
    pub session_revision: i64,
    #[schema(minimum = 1)]
    pub application_revision: i64,
    pub projection: ServerApplicationUserProjection,
}

/// Non-enumerating introspection union. Invalid or inactive authority is always the inactive arm.
#[allow(
    clippy::large_enum_variant,
    reason = "the public untagged HTTP union keeps its reviewed schema and avoids boxed wire models"
)]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
#[serde(untagged)]
pub enum ProjectTokenIntrospectionResponse {
    Active(ActiveProjectToken),
    Inactive(InactiveProjectToken),
}

#[utoipa::path(
    get,
    path = "/v1/projects/{project_id}/users",
    params(
        ("project_id" = String, Path, max_length = 96),
        ("cursor" = Option<String>, Query, max_length = 64),
        ("limit" = Option<usize>, Query, minimum = 1, maximum = 100)
    ),
    responses(
        (status = 200, body = ServerUserList),
        (status = 400, body = ServerError),
        (status = 401, description = "Missing or invalid Project server key", body = ServerError, headers(("WWW-Authenticate" = String, description = "Required Bearer authentication challenge"))),
                (status = 503, body = ServerError)
    ),
    security(("project_server_key" = []))
)]
#[doc(hidden)]
pub fn list_project_users() {}

#[utoipa::path(
    post,
    path = "/v1/projects/{project_id}/users/lookup",
    params(("project_id" = String, Path, max_length = 96)),
    request_body = LookupServerUserRequest,
    responses(
        (status = 200, body = LookupServerUserResponse),
        (status = 400, body = ServerError),
        (status = 401, description = "Missing or invalid Project server key", body = ServerError, headers(("WWW-Authenticate" = String, description = "Required Bearer authentication challenge"))),
                (status = 503, body = ServerError)
    ),
    security(("project_server_key" = []))
)]
#[doc(hidden)]
pub fn lookup_project_user() {}

#[utoipa::path(
    get,
    path = "/v1/projects/{project_id}/users/{user_id}",
    params(
        ("project_id" = String, Path, max_length = 96),
        ("user_id" = String, Path, max_length = 96)
    ),
    responses(
        (status = 200, body = ServerUser),
        (status = 400, body = ServerError),
        (status = 401, description = "Missing or invalid Project server key", body = ServerError, headers(("WWW-Authenticate" = String, description = "Required Bearer authentication challenge"))),
        (status = 404, body = ServerError),
                (status = 503, body = ServerError)
    ),
    security(("project_server_key" = []))
)]
#[doc(hidden)]
pub fn get_project_user() {}

#[utoipa::path(
    get,
    path = "/v1/projects/{project_id}/applications/{application_id}/users/{user_id}",
    params(
        ("project_id" = String, Path, max_length = 96),
        ("application_id" = String, Path, max_length = 96),
        ("user_id" = String, Path, max_length = 96)
    ),
    responses(
        (status = 200, body = ServerApplicationUserProjection),
        (status = 400, body = ServerError),
        (status = 401, description = "Missing or invalid Project server key", body = ServerError, headers(("WWW-Authenticate" = String, description = "Required Bearer authentication challenge"))),
        (status = 404, body = ServerError),
        (status = 409, body = ServerError),
                (status = 503, body = ServerError)
    ),
    security(("project_server_key" = []))
)]
#[doc(hidden)]
pub fn get_application_user_projection() {}

#[utoipa::path(
    post,
    path = "/v1/projects/{project_id}/tokens/introspect",
    params(("project_id" = String, Path, max_length = 96)),
    request_body = IntrospectProjectTokenRequest,
    responses(
        (status = 200, body = ProjectTokenIntrospectionResponse),
        (status = 400, body = ServerError),
        (status = 401, description = "Missing or invalid Project server key", body = ServerError, headers(("WWW-Authenticate" = String, description = "Required Bearer authentication challenge"))),
                (status = 503, body = ServerError)
    ),
    security(("project_server_key" = []))
)]
#[doc(hidden)]
pub fn introspect_project_token() {}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "OwlAuth Server API",
        description = "Project-scoped customer backend Server API"
    ),
    paths(
        crate::health::get_liveness,
        crate::health::get_readiness,
        list_project_users,
        lookup_project_user,
        get_project_user,
        get_application_user_projection,
        introspect_project_token
    ),
    components(schemas(
        HealthResponse,
        ServerErrorCode,
        ServerError,
        ServerUserStatus,
        ServerUser,
        ServerUserList,
        LookupServerUserRequest,
        LookupServerUserResponse,
        ServerApplicationUserProjection,
        IntrospectProjectTokenRequest,
        InactiveProjectToken,
        ActiveProjectToken,
        ProjectTokenIntrospectionResponse
    )),
    modifiers(&ServerSecurity)
)]
struct ServerApiDoc;

struct ServerSecurity;

impl Modify for ServerSecurity {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        openapi
            .components
            .get_or_insert_default()
            .add_security_scheme(
                "project_server_key",
                SecurityScheme::Http(Http::new(HttpAuthScheme::Bearer)),
            );
    }
}

/// Generates the complete Server-plane `OpenAPI` document.
#[must_use]
pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut document = ServerApiDoc::openapi();
    crate::add_response_to_operations(&mut document, "408", |_| {
        crate::json_error_response(
            "The request exceeded the Server listener time budget",
            "ServerError",
            "application/json",
        )
    });
    document
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_bearing_request_debug_is_redacted() {
        let request = IntrospectProjectTokenRequest {
            token: "secret-access-token".to_owned(),
            expected_application_id: Some("app_1".to_owned()),
        };
        let debug = format!("{request:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("secret-access-token"));
    }

    #[test]
    fn request_and_response_models_reject_unknown_fields() {
        assert!(
            serde_json::from_value::<LookupServerUserRequest>(serde_json::json!({
                "email": "person@example.com",
                "prefix": true
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<InactiveProjectToken>(serde_json::json!({
                "active": false,
                "reason": "revoked"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<InactiveProjectToken>(serde_json::json!({"active": true}))
                .is_err()
        );
        let mut active = serde_json::json!({
            "active": false,
            "project_id": "project",
            "application_id": "application",
            "user_id": "user",
            "session_id": "00000000-0000-0000-0000-000000000001",
            "token_type": "Bearer",
            "issued_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-01-01T01:00:00Z",
            "user_revision": 1,
            "session_revision": 1,
            "application_revision": 1,
            "projection": {
                "project_id": "project",
                "application_id": "application",
                "user_id": "user",
                "projection_schema": "owlauth.user.v1",
                "user_revision": 1,
                "projection_revision": 1,
                "display_name": null,
                "picture_url": null,
                "locale": null,
                "verified_email": null,
                "status": "active",
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z"
            }
        });
        assert!(serde_json::from_value::<ActiveProjectToken>(active.clone()).is_err());
        active["active"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ActiveProjectToken>(active).is_ok());
    }
}
