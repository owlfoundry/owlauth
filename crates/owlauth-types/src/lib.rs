#![forbid(unsafe_code)]

//! Stable public HTTP contracts for `OwlAuth`'s isolated Runtime and Control planes.

pub mod control;
mod control_resources;
pub mod export;
pub mod health;
pub mod runtime;

pub use health::HealthResponse;

/// Compile-time availability of the complete federated Project Auth surface.
pub const FEDERATED_PROJECT_AUTH_AVAILABLE: bool = true;

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use crate::{control, export, runtime};

    #[test]
    fn generated_documents_are_plane_pure_and_versioned() {
        let runtime =
            serde_json::to_value(runtime::openapi()).expect("Runtime OpenAPI should serialize");
        let control =
            serde_json::to_value(control::openapi()).expect("Control OpenAPI should serialize");

        assert_eq!(runtime["info"]["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(control["info"]["version"], env!("CARGO_PKG_VERSION"));
        assert!(runtime["paths"]["/health"].is_object());
        assert!(runtime["paths"]["/ready"].is_object());
        assert!(runtime["paths"].get("/v1/system").is_none());
        assert!(runtime["paths"]["/v1/projects/{project_public_id}/auth/config"].is_object());
        assert!(
            runtime["paths"]["/projects/{project_public_id}/.well-known/jwks.json"].is_object()
        );
        for required in [
            "/v1/projects/{project_public_id}/auth/login/start",
            "/auth/interactions/{interaction}",
            "/v1/projects/{project_public_id}/auth/interactions/{interaction}/method",
            "/v1/projects/{project_public_id}/auth/interactions/{interaction}/session/reuse",
            "/projects/{project_public_id}/auth/callback/{provider_key}",
            "/v1/projects/{project_public_id}/auth/handoff/exchange",
            "/v1/projects/{project_public_id}/auth/sessions/refresh",
            "/v1/projects/{project_public_id}/auth/users/me",
            "/v1/projects/{project_public_id}/auth/sessions/logout",
            "/v1/projects/{project_public_id}/auth/browser-logout/prepare",
            "/auth/browser-logout/{preparation}",
            "/v1/projects/{project_public_id}/auth/browser-logout/{preparation}/confirm",
        ] {
            assert!(
                runtime["paths"][required].is_object(),
                "federated authentication path is missing from Runtime OpenAPI: {required}"
            );
        }
        assert!(runtime["paths"].get("/v1/projects").is_none());
        assert!(
            runtime["components"]["schemas"]
                .get("CreateProviderRequest")
                .is_none()
        );

        assert!(control["paths"]["/v1/system"].is_object());
        let capabilities = &control["components"]["schemas"]["SystemCapabilities"];
        assert!(capabilities["properties"].get("project_auth").is_none());
        assert!(capabilities["properties"]["provisioning"].is_object());
        assert!(capabilities["properties"]["login_readiness"].is_object());
        assert!(capabilities["properties"]["federated_project_auth"].is_object());
        let advertised = control::get_system();
        assert!(advertised.provisioning);
        assert!(advertised.login_readiness);
        assert!(advertised.federated_project_auth);
        assert!(control["paths"]["/v1/projects"].is_object());
        assert!(
            control["paths"]["/v1/projects/{project_id}/signing-keys/{key_id}/reconcile"]
                .is_object()
        );
        assert!(
            control["paths"]["/v1/projects/{project_id}/providers/{provider_id}/reconcile"]
                .is_object()
        );
        assert!(
            control["paths"]
                .get("/v1/projects/{project_public_id}/auth/config")
                .is_none()
        );
        assert!(
            control["paths"]
                .get("/projects/{project_public_id}/.well-known/jwks.json")
                .is_none()
        );
        assert!(control["components"]["securitySchemes"]["operator_api_key"].is_object());
        assert_eq!(
            control["components"]["schemas"]["CreateProviderRequest"]["properties"]["client_secret"]
                ["writeOnly"],
            true
        );
        assert!(
            control["components"]["schemas"]["CreateProviderRequest"]["required"]
                .as_array()
                .is_some_and(|required| !required.iter().any(|field| field == "kind"))
        );
        assert_eq!(
            control["components"]["schemas"]["ReconcileProviderRequest"]["properties"]["client_secret"]
                ["writeOnly"],
            true
        );
    }

    #[test]
    fn every_runtime_rate_limit_response_requires_integer_retry_after_seconds() {
        let runtime: Value = serde_json::from_str(
            &export::to_pretty_json(export::OpenApiPlane::Runtime)
                .expect("Runtime OpenAPI should serialize"),
        )
        .expect("exported Runtime OpenAPI should be JSON");
        let operations = [
            ("/v1/projects/{project_public_id}/auth/config", "get"),
            ("/projects/{project_public_id}/.well-known/jwks.json", "get"),
            ("/v1/projects/{project_public_id}/auth/login/start", "post"),
            ("/auth/interactions/{interaction}", "get"),
            (
                "/v1/projects/{project_public_id}/auth/interactions/{interaction}/method",
                "post",
            ),
            (
                "/v1/projects/{project_public_id}/auth/interactions/{interaction}/session/reuse",
                "post",
            ),
            (
                "/projects/{project_public_id}/auth/callback/{provider_key}",
                "get",
            ),
            (
                "/v1/projects/{project_public_id}/auth/handoff/exchange",
                "post",
            ),
            (
                "/v1/projects/{project_public_id}/auth/sessions/refresh",
                "post",
            ),
            ("/v1/projects/{project_public_id}/auth/users/me", "get"),
            (
                "/v1/projects/{project_public_id}/auth/sessions/logout",
                "post",
            ),
            (
                "/v1/projects/{project_public_id}/auth/browser-logout/prepare",
                "post",
            ),
            ("/auth/browser-logout/{preparation}", "get"),
            (
                "/v1/projects/{project_public_id}/auth/browser-logout/{preparation}/confirm",
                "post",
            ),
        ];

        for (path, method) in operations {
            let response = &runtime["paths"][path][method]["responses"]["429"];
            assert!(
                response.is_object(),
                "429 response missing for {method} {path}"
            );
            let retry_after = &response["headers"]["Retry-After"];
            assert_eq!(
                retry_after["schema"]["type"], "integer",
                "Retry-After must be integer seconds for {method} {path}"
            );
            assert_eq!(
                retry_after["required"], true,
                "Retry-After must be required for {method} {path}"
            );
            assert!(
                retry_after["description"]
                    .as_str()
                    .is_some_and(|description| description.contains("Required")
                        && description.contains("whole seconds")),
                "Retry-After must be documented as required whole seconds for {method} {path}"
            );
        }
    }

    #[test]
    fn public_contracts_are_bounded_and_reject_private_jwk_members() {
        let runtime =
            serde_json::to_value(runtime::openapi()).expect("Runtime OpenAPI should serialize");
        let control =
            serde_json::to_value(control::openapi()).expect("Control OpenAPI should serialize");

        assert_eq!(
            control["components"]["schemas"]["ApplicationType"]["enum"],
            serde_json::json!(["web", "native"])
        );
        assert_eq!(
            control["components"]["schemas"]["UpdateProjectPolicyRequest"]["properties"]["access_token_lifetime_seconds"]
                ["minimum"],
            60
        );
        assert_eq!(
            runtime["components"]["schemas"]["PublicApplicationConfig"]["properties"]["providers"]
                ["maxItems"],
            50
        );
        assert!(
            serde_json::from_value::<runtime::PublicJwk>(serde_json::json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "use": "sig",
                "kid": "key-1",
                "x": "public-value",
                "d": "private-value"
            }))
            .is_err()
        );
    }

    #[test]
    fn separate_exports_are_deterministic() {
        for plane in [export::OpenApiPlane::Runtime, export::OpenApiPlane::Control] {
            let first = export::to_pretty_json(plane).expect("OpenAPI should serialize");
            let second = export::to_pretty_json(plane).expect("OpenAPI should serialize");
            assert_eq!(first, second);

            let parsed: Value = serde_json::from_str(&first).expect("OpenAPI should be JSON");
            assert_eq!(parsed["openapi"], "3.1.0");
        }
    }
}
