#![forbid(unsafe_code)]

//! Stable public HTTP contracts for `OwlAuth`'s isolated Runtime, Server, and Control planes.

pub mod control;
mod control_resources;
pub mod export;
pub mod health;
pub mod runtime;
pub mod server;

pub use health::HealthResponse;

/// Compile-time availability of the complete federated Project Auth surface.
pub const FEDERATED_PROJECT_AUTH_AVAILABLE: bool = true;

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use crate::{control, export, runtime, server};

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one contract test keeps complete cross-plane path and component isolation visible"
    )]
    fn generated_documents_are_plane_pure_and_versioned() {
        let runtime =
            serde_json::to_value(runtime::openapi()).expect("Runtime OpenAPI should serialize");
        let server =
            serde_json::to_value(server::openapi()).expect("Server OpenAPI should serialize");
        let control =
            serde_json::to_value(control::openapi()).expect("Control OpenAPI should serialize");

        assert_eq!(runtime["info"]["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(server["info"]["version"], env!("CARGO_PKG_VERSION"));
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
        for forbidden_schema in [
            "CreateProviderRequest",
            "NamedProviderPreflightRequest",
            "OidcPreflightRequest",
        ] {
            assert!(
                runtime["components"]["schemas"]
                    .get(forbidden_schema)
                    .is_none()
            );
        }
        assert!(
            runtime["components"]["schemas"]
                .get("IntrospectProjectTokenRequest")
                .is_none()
        );

        for path in [
            "/health",
            "/ready",
            "/v1/projects/{project_id}/users",
            "/v1/projects/{project_id}/users/lookup",
            "/v1/projects/{project_id}/users/{user_id}",
            "/v1/projects/{project_id}/applications/{application_id}/users/{user_id}",
            "/v1/projects/{project_id}/tokens/introspect",
        ] {
            assert!(
                server["paths"][path].is_object(),
                "missing Server path: {path}"
            );
        }
        assert!(server["components"]["securitySchemes"]["project_server_key"].is_object());
        assert!(server["paths"].get("/v1/system").is_none());
        assert!(
            server["paths"]
                .get("/v1/projects/{project_public_id}/auth/config")
                .is_none()
        );
        for forbidden_schema in [
            "CreateProviderRequest",
            "NamedProviderPreflightRequest",
            "OidcPreflightRequest",
            "PublicApplicationConfig",
            "RefreshSessionRequest",
            "ProjectServerKey",
        ] {
            assert!(
                server["components"]["schemas"]
                    .get(forbidden_schema)
                    .is_none(),
                "Server OpenAPI leaked {forbidden_schema}"
            );
        }

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
        let signing_key_collection = &control["paths"]["/v1/projects/{project_id}/signing-keys"];
        assert!(signing_key_collection["get"].is_object());
        assert!(signing_key_collection.get("post").is_none());
        assert!(
            control["paths"]["/v1/projects/{project_id}/signing-keys/rotate"]["post"].is_object()
        );
        for removed_path in [
            "/v1/projects/{project_id}/signing-keys/{key_id}/reconcile",
            "/v1/projects/{project_id}/signing-keys/{key_id}/activate",
            "/v1/projects/{project_id}/signing-keys/{key_id}/retire",
        ] {
            assert!(
                control["paths"].get(removed_path).is_none(),
                "removed signing-key path leaked into Control OpenAPI: {removed_path}"
            );
        }
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
        for (path, request_schema) in [
            (
                "/v1/projects/{project_id}/providers/oidc/preflight",
                "OidcPreflightRequest",
            ),
            (
                "/v1/projects/{project_id}/providers/named/preflight",
                "NamedProviderPreflightRequest",
            ),
        ] {
            assert!(control["paths"][path]["post"].is_object());
            let properties = &control["components"]["schemas"][request_schema]["properties"];
            assert!(properties["provider_key"].is_object());
            assert!(properties.get("client_secret").is_none());
            assert!(properties.get("callback_url").is_none());
        }
        for result_schema in ["OidcPreflightResult", "NamedProviderPreflightResult"] {
            let properties = &control["components"]["schemas"][result_schema]["properties"];
            assert!(properties["callback_url"].is_object());
            assert!(properties["callback_guidance"].is_object());
        }
        assert_eq!(
            control["components"]["schemas"]["CreateProviderRequest"]["properties"]["client_secret"]
                ["writeOnly"],
            true
        );
        assert!(
            control["components"]["schemas"]["CreateProviderRequest"]["required"]
                .as_array()
                .is_some_and(|required| required.iter().any(|field| field == "kind"))
        );
        assert_eq!(
            control["components"]["schemas"]["ReconcileProviderRequest"]["properties"]["client_secret"]
                ["writeOnly"],
            true
        );
    }

    #[test]
    fn control_operation_inventory_and_exceptional_responses_are_exact() {
        let control = serde_json::to_value(control::openapi()).expect("Control OpenAPI serializes");
        for (path, methods) in [
            ("/v1/projects", &["get", "post"][..]),
            ("/v1/projects/{project_id}", &["get", "patch"]),
            ("/v1/projects/{project_id}/applications", &["get", "post"]),
            (
                "/v1/projects/{project_id}/applications/{application_id}",
                &["get", "patch"],
            ),
            (
                "/v1/projects/{project_id}/applications/{application_id}/webhook-endpoints",
                &["get", "post"],
            ),
            (
                "/v1/projects/{project_id}/applications/{application_id}/webhook-endpoints/{endpoint_id}",
                &["get", "put"],
            ),
            ("/v1/projects/{project_id}/server-keys", &["get", "post"]),
            ("/v1/projects/{project_id}/email-method", &["get", "put"]),
            ("/v1/projects/{project_id}/policy", &["get", "put"]),
            (
                "/v1/projects/{project_id}/provider-egress-policy",
                &["get", "put"],
            ),
            ("/v1/projects/{project_id}/providers", &["get", "post"]),
            (
                "/v1/projects/{project_id}/providers/{provider_id}/assignments/{application_id}",
                &["put"],
            ),
            (
                "/v1/projects/{project_id}/smtp-configurations",
                &["get", "post"],
            ),
            ("/v1/system/smtp-default-generations", &["get", "post"]),
        ] {
            let path_item = &control["paths"][path];
            for method in methods {
                assert!(
                    path_item[method].is_object(),
                    "missing Control operation {method} {path}"
                );
            }
        }

        for path in [
            "/v1/projects/{project_id}/providers/oidc/preflight",
            "/v1/projects/{project_id}/providers/named/preflight",
        ] {
            assert!(control["paths"][path]["post"]["responses"]["422"].is_object());
        }
        let smtp_test = &control["paths"]["/v1/projects/{project_id}/smtp-configurations/{smtp_id}/test"]
            ["post"];
        assert!(smtp_test["responses"].get("200").is_none());
        let accepted = &smtp_test["responses"]["202"];
        assert_eq!(accepted["headers"]["Location"]["schema"]["type"], "string");
        assert!(
            accepted["headers"]["Location"]["description"]
                .as_str()
                .is_some_and(|description| description.contains("Exact Control path"))
        );

        for path in [
            "/v1/projects/{project_id}/users/{user_id}/managed-provider-connections/{connection_id}/reauthorizations",
            "/v1/projects/{project_id}/identity-mutation-intents",
        ] {
            let responses = &control["paths"][path]["post"]["responses"];
            assert!(responses["200"].is_object(), "{path} must describe replay");
            assert_eq!(
                responses["201"]["headers"]["Location"]["schema"]["type"],
                "string"
            );
        }
        assert_eq!(
            control["paths"]["/v1/projects/{project_id}/server-keys"]["post"]["responses"]["201"]["headers"]
                ["Location"]["schema"]["type"],
            "string"
        );
        assert!(
            control["paths"]["/v1/projects/{project_id}/applications/{application_id}/webhook-deliveries/{delivery_id}"]["get"].is_object()
        );
        let replay = &control["paths"]["/v1/projects/{project_id}/applications/{application_id}/webhook-deliveries/{delivery_id}/replay"]
            ["post"]["responses"];
        assert!(replay.get("200").is_none());
        assert_eq!(
            replay["201"]["headers"]["Location"]["schema"]["type"],
            "string"
        );
    }

    #[test]
    fn runtime_pending_email_and_hosted_document_contracts_are_minimal() {
        let runtime = serde_json::to_value(runtime::openapi()).expect("Runtime OpenAPI serializes");
        let pending = &runtime["components"]["schemas"]["HostedPendingEmailChallenge"];
        let properties = pending["properties"]
            .as_object()
            .expect("pending properties");
        assert_eq!(
            properties
                .keys()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>(),
            ["challenge_id", "expires_at", "generation", "proof_modes"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        );
        for forbidden in [
            "email",
            "address",
            "account",
            "delivery",
            "otp",
            "magic_proof",
            "smtp",
        ] {
            assert!(properties.get(forbidden).is_none());
        }
        assert!(
            runtime["components"]["schemas"]["HostedInteractionResponse"]["properties"]
                ["pending_email_challenge"]
                .is_object()
        );
        for path in [
            "/auth/interactions/{interaction}",
            "/auth/email/confirm/{challenge_id}",
            "/auth/browser-logout/{preparation}",
            "/auth/managed-reauthorizations/{interaction}",
            "/auth/identity-mutations/{intent}",
            "/auth/identity-mutations/email/confirm/{challenge_id}",
        ] {
            assert_eq!(
                runtime["paths"][path]["get"]["responses"]["200"]["content"]["text/html"]["schema"]
                    ["type"],
                "string",
                "Hosted document must declare text/html for {path}"
            );
        }
        for excluded in ["/auth/", "/auth/assets/{asset}"] {
            assert!(runtime["paths"].get(excluded).is_none());
        }
    }

    #[test]
    fn every_runtime_rate_limit_response_requires_integer_retry_after_seconds() {
        let runtime: Value = serde_json::from_str(
            &export::to_pretty_json(export::OpenApiPlane::Runtime)
                .expect("Runtime OpenAPI should serialize"),
        )
        .expect("exported Runtime OpenAPI should be JSON");
        let paths = runtime["paths"]
            .as_object()
            .expect("Runtime paths should be an object");
        let mut checked = 0;
        for (path, path_item) in paths {
            let Some(methods) = path_item.as_object() else {
                continue;
            };
            for (method, operation) in methods {
                let response = &operation["responses"]["429"];
                if !response.is_object() {
                    continue;
                }
                checked += 1;
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
        assert!(
            checked >= 20,
            "Runtime rate-limit inventory unexpectedly shrank"
        );
    }

    #[test]
    fn every_server_rate_limit_response_requires_integer_retry_after_seconds() {
        let server: Value = serde_json::from_str(
            &export::to_pretty_json(export::OpenApiPlane::Server)
                .expect("Server OpenAPI should serialize"),
        )
        .expect("exported Server OpenAPI should be JSON");
        let operations = [
            ("/v1/projects/{project_id}/users", "get"),
            ("/v1/projects/{project_id}/users/lookup", "post"),
            ("/v1/projects/{project_id}/users/{user_id}", "get"),
            (
                "/v1/projects/{project_id}/applications/{application_id}/users/{user_id}",
                "get",
            ),
            ("/v1/projects/{project_id}/tokens/introspect", "post"),
        ];
        for (path, method) in operations {
            let retry_after =
                &server["paths"][path][method]["responses"]["429"]["headers"]["Retry-After"];
            assert_eq!(retry_after["schema"]["type"], "integer");
            assert_eq!(retry_after["required"], true);
            assert!(
                retry_after["description"]
                    .as_str()
                    .is_some_and(|description| description.contains("Required")
                        && description.contains("whole seconds"))
            );
        }
    }

    #[test]
    fn server_auth_projection_and_introspection_contract_is_exact() {
        let server: Value = serde_json::from_str(
            &export::to_pretty_json(export::OpenApiPlane::Server)
                .expect("Server OpenAPI should serialize"),
        )
        .expect("exported Server OpenAPI should be JSON");
        let operations = [
            ("/v1/projects/{project_id}/users", "get"),
            ("/v1/projects/{project_id}/users/lookup", "post"),
            ("/v1/projects/{project_id}/users/{user_id}", "get"),
            (
                "/v1/projects/{project_id}/applications/{application_id}/users/{user_id}",
                "get",
            ),
            ("/v1/projects/{project_id}/tokens/introspect", "post"),
        ];
        for (path, method) in operations {
            let challenge =
                &server["paths"][path][method]["responses"]["401"]["headers"]["WWW-Authenticate"];
            assert_eq!(challenge["required"], true, "{method} {path}");
            assert_eq!(challenge["schema"]["type"], "string", "{method} {path}");
        }

        let schemas = &server["components"]["schemas"];
        assert_eq!(
            schemas["InactiveProjectToken"]["properties"]["active"]["const"],
            false
        );
        assert_eq!(
            schemas["ActiveProjectToken"]["properties"]["active"]["const"],
            true
        );
        assert!(
            schemas["ServerApplicationUserProjection"]["required"]
                .as_array()
                .is_some_and(|required| required.iter().any(|field| field == "user_revision"))
        );
        assert_eq!(
            schemas["ServerApplicationUserProjection"]["properties"]["user_revision"]["minimum"],
            1
        );
        assert!(
            schemas["ServerUserList"]["required"]
                .as_array()
                .is_some_and(|required| required.iter().any(|field| field == "next_cursor"))
        );
        assert_eq!(
            schemas["ServerUserList"]["properties"]["next_cursor"]["maxLength"],
            64
        );

        let parameters = server["paths"]["/v1/projects/{project_id}/users"]["get"]["parameters"]
            .as_array()
            .expect("Server list parameters");
        let parameter = |name: &str| {
            parameters
                .iter()
                .find(|parameter| parameter["name"] == name)
                .unwrap_or_else(|| panic!("missing Server parameter {name}"))
        };
        assert_eq!(parameter("project_id")["schema"]["maxLength"], 96);
        assert_eq!(parameter("cursor")["schema"]["maxLength"], 64);
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
        for plane in [
            export::OpenApiPlane::Runtime,
            export::OpenApiPlane::Server,
            export::OpenApiPlane::Control,
        ] {
            let first = export::to_pretty_json(plane).expect("OpenAPI should serialize");
            let second = export::to_pretty_json(plane).expect("OpenAPI should serialize");
            assert_eq!(first, second);

            let parsed: Value = serde_json::from_str(&first).expect("OpenAPI should be JSON");
            assert_eq!(parsed["openapi"], "3.1.0");
        }
    }
}
