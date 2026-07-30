/**
 * Generated from target/openapi/runtime.json by openapi-typescript.
 * Do not edit by hand.
 */

export interface paths {
    "/health": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["get_liveness"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/projects/{project_public_id}/.well-known/jwks.json": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["get_project_jwks"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/ready": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["get_readiness"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/projects/{project_public_id}/auth/config": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["get_public_application_config"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
}
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        /** @description Minimal response returned by listener liveness and readiness probes. */
        HealthResponse: {
            /** @description Stable probe status. Successful probes return `ok`. */
            status: string;
        };
        /** @enum {string} */
        JwkCurve: "Ed25519";
        /** @enum {string} */
        JwkKeyType: "OKP";
        JwksDocument: {
            keys: components["schemas"]["PublicJwk"][];
            /** Format: int64 */
            revision: number;
            /** Format: int64 */
            signing_epoch: number;
        };
        /** @enum {string} */
        JwkUse: "sig";
        /** @enum {string} */
        ProviderKind: "oidc";
        PublicApplicationConfig: {
            application_display_name: string;
            application_public_id: string;
            login_available: boolean;
            project_display_name: string;
            project_public_id: string;
            providers: components["schemas"]["PublicProvider"][];
            publishable_keys: string[];
        };
        PublicJwk: {
            alg: components["schemas"]["SigningAlgorithm"];
            crv: components["schemas"]["JwkCurve"];
            kid: string;
            kty: components["schemas"]["JwkKeyType"];
            use: components["schemas"]["JwkUse"];
            x: string;
        };
        PublicProvider: {
            display_name: string;
            key: string;
            kind: components["schemas"]["ProviderKind"];
        };
        RuntimeError: {
            code: string;
            message: string;
            request_id: string;
        };
        /** @enum {string} */
        SigningAlgorithm: "EdDSA";
    };
    responses: never;
    parameters: never;
    requestBodies: never;
    headers: never;
    pathItems: never;
}
export type $defs = Record<string, never>;
export interface operations {
    get_liveness: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The listener event loop is responsive */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HealthResponse"];
                };
            };
        };
    };
    get_project_jwks: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                project_public_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Project verification key set */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["JwksDocument"];
                };
            };
            /** @description Credentials are not accepted on public Runtime endpoints */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
            /** @description Public Project or key ring not found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
            /** @description Runtime authority unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
        };
    };
    get_readiness: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The listener can admit business traffic */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HealthResponse"];
                };
            };
            /** @description A listener-critical dependency is unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HealthResponse"];
                };
            };
        };
    };
    get_public_application_config: {
        parameters: {
            query: {
                application_id: string;
            };
            header?: never;
            path: {
                project_public_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Exact public application configuration */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PublicApplicationConfig"];
                };
            };
            /** @description Invalid request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
            /** @description Public Project or Application not found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
            /** @description Runtime authority unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
        };
    };
}
