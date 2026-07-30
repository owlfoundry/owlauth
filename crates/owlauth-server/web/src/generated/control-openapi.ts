/**
 * Generated from target/openapi/control.json by openapi-typescript.
 * Do not edit by hand.
 */

export interface paths {
    "/.well-known/owlauth": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["get_service_descriptor"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
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
    "/v1/system": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["get_system"];
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
        /** @description Side-effect-free origin-root descriptor used before credential selection. */
        ServiceDescriptor: {
            /** @description Canonical same-origin Control API base with a trailing slash. */
            api_base_url: string;
            /** @description Supported API versions. */
            api_versions: string[];
            /** @description Credential class accepted by the selected product. */
            credential_class: string;
            /** @description Stable public deployment identity. */
            instance_id: string;
            /** @description Canonical same-origin remote MCP URL when enabled. */
            mcp_url?: string | null;
            /** @description Exact product identity. */
            product: string;
            /** @description Descriptor schema version. */
            schema_version: string;
        };
        /** @description Bounded capabilities returned after Control operator authentication. */
        SystemCapabilities: {
            /** @description Product identifier for this Control endpoint. */
            product: string;
            /** @description Whether Project Auth business operations are implemented. */
            project_auth: boolean;
        };
    };
    responses: never;
    parameters: never;
    requestBodies: never;
    headers: never;
    pathItems: never;
}
export type $defs = Record<string, never>;
export interface operations {
    get_service_descriptor: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Public OwlAuth endpoint descriptor */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ServiceDescriptor"];
                };
            };
        };
    };
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
    get_system: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Authenticated deployment capabilities */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SystemCapabilities"];
                };
            };
            /** @description Missing or invalid operator API key */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
        };
    };
}
