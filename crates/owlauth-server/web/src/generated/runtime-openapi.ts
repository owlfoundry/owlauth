/**
 * Generated from target/openapi/runtime.json by openapi-typescript.
 * Do not edit by hand.
 */

export interface paths {
    "/auth/browser-logout/{preparation}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["get_browser_logout"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/auth/interactions/{interaction}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["get_hosted_interaction"];
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
    "/projects/{project_public_id}/auth/callback/{provider_key}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["complete_provider_callback"];
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
    "/v1/projects/{project_public_id}/auth/browser-logout/{preparation}/confirm": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["confirm_browser_logout"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/projects/{project_public_id}/auth/browser-logout/prepare": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["prepare_browser_logout"];
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
    "/v1/projects/{project_public_id}/auth/handoff/exchange": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["exchange_handoff"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/projects/{project_public_id}/auth/interactions/{interaction}/method": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["select_provider"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/projects/{project_public_id}/auth/interactions/{interaction}/session/reuse": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["confirm_session_reuse"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/projects/{project_public_id}/auth/login/start": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["start_login"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/projects/{project_public_id}/auth/sessions/logout": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["logout_application_session"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/projects/{project_public_id}/auth/sessions/refresh": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["refresh_session"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/projects/{project_public_id}/auth/users/me": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["get_current_user"];
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
        BrowserLogoutPreparationResponse: {
            expires_at: string;
            hosted_url: string;
        };
        BrowserLogoutResponse: {
            csrf: string;
            expires_at: string;
            project_id: string;
            /** Format: int64 */
            revision: number;
        };
        CompletionResponse: {
            completed: boolean;
        };
        ConfirmBrowserLogoutRequest: {
            csrf: string;
            /** Format: int64 */
            expected_revision: number;
        };
        ConfirmSessionReuseRequest: {
            csrf: string;
            /** Format: int64 */
            expected_revision: number;
        };
        CredentialPairResponse: {
            access_token: string;
            application_id: string;
            /** Format: int64 */
            expires_in: number;
            project_id: string;
            projection: components["schemas"]["UserProjection"];
            /** Format: int64 */
            projection_revision: number;
            /** Format: int64 */
            refresh_generation: number;
            refresh_token: string;
            session_expires_at: string;
            session_id: string;
            token_type: string;
            user_id: string;
        };
        CurrentUserResponse: {
            application_id: string;
            authenticated_at: string;
            project_id: string;
            projection: components["schemas"]["UserProjection"];
            /** Format: int64 */
            projection_revision: number;
            session_expires_at: string;
            user_id: string;
        };
        HandoffExchangeRequest: {
            application_id: string;
            handoff: string;
            pkce_verifier: string;
            publishable_key: string;
        };
        /** @description Minimal response returned by listener liveness and readiness probes. */
        HealthResponse: {
            /** @description Stable probe status. Successful probes return `ok`. */
            status: string;
        };
        /** @enum {string} */
        HostedApplicationType: "web" | "native";
        HostedInteractionResponse: {
            application_display_name: string;
            application_id: string;
            application_type: components["schemas"]["HostedApplicationType"];
            csrf: string;
            expires_at: string;
            presentation_hint?: string | null;
            project_display_name: string;
            project_id: string;
            providers: components["schemas"]["HostedProvider"][];
            /** Format: int64 */
            revision: number;
            session_reuse_available: boolean;
            status: components["schemas"]["HostedInteractionStatus"];
        };
        /** @enum {string} */
        HostedInteractionStatus: "awaiting_method_selection" | "provider_authorization_started" | "provider_exchange_in_progress" | "authenticated" | "handoff_issued" | "completed" | "failed" | "expired";
        HostedProvider: {
            display_name: string;
            key: string;
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
        LoginStartRequest: {
            application_id: string;
            pkce_challenge: string;
            presentation_hint?: string | null;
            publishable_key: string;
            redirect_uri: string;
            state: string;
        };
        LoginStartResponse: {
            expires_at: string;
            hosted_url: string;
        };
        NavigationResponse: {
            url: string;
        };
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
        RefreshRequest: {
            application_id: string;
            publishable_key: string;
            refresh_token: string;
        };
        RuntimeError: {
            code: string;
            message: string;
            request_id: string;
        };
        SelectProviderRequest: {
            csrf: string;
            /** Format: int64 */
            expected_revision: number;
            provider_key: string;
        };
        /** @enum {string} */
        SigningAlgorithm: "EdDSA";
        UserProjection: {
            created_at: string;
            display_name?: string | null;
            picture_url?: string | null;
            /** Format: int64 */
            projection_revision: number;
            projection_schema: string;
            status: string;
            updated_at: string;
            user_id: string;
            /** Format: int64 */
            user_revision: number;
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
    get_browser_logout: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                preparation: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Hosted browser-logout confirmation HTML */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
            429: {
                headers: {
                    /** @description Required delay in whole seconds before retrying */
                    "Retry-After": number;
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
        };
    };
    get_hosted_interaction: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                interaction: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Hosted Authentication HTML */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
            429: {
                headers: {
                    /** @description Required delay in whole seconds before retrying */
                    "Retry-After": number;
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
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
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["JwksDocument"];
                };
            };
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
            429: {
                headers: {
                    /** @description Required delay in whole seconds before retrying */
                    "Retry-After": number;
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
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
    complete_provider_callback: {
        parameters: {
            query: {
                code: string;
                state: string;
            };
            header?: never;
            path: {
                project_public_id: string;
                provider_key: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Redirect to the exact stored Application callback */
            303: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
            429: {
                headers: {
                    /** @description Required delay in whole seconds before retrying */
                    "Retry-After": number;
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
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
    confirm_browser_logout: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                preparation: string;
                project_public_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ConfirmBrowserLogoutRequest"];
            };
        };
        responses: {
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CompletionResponse"];
                };
            };
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
            429: {
                headers: {
                    /** @description Required delay in whole seconds before retrying */
                    "Retry-After": number;
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
        };
    };
    prepare_browser_logout: {
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
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["BrowserLogoutPreparationResponse"];
                };
            };
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
            429: {
                headers: {
                    /** @description Required delay in whole seconds before retrying */
                    "Retry-After": number;
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
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
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PublicApplicationConfig"];
                };
            };
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
            429: {
                headers: {
                    /** @description Required delay in whole seconds before retrying */
                    "Retry-After": number;
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
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
    exchange_handoff: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                project_public_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["HandoffExchangeRequest"];
            };
        };
        responses: {
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CredentialPairResponse"];
                };
            };
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
            429: {
                headers: {
                    /** @description Required delay in whole seconds before retrying */
                    "Retry-After": number;
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
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
    select_provider: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                interaction: string;
                project_public_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["SelectProviderRequest"];
            };
        };
        responses: {
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["NavigationResponse"];
                };
            };
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
            429: {
                headers: {
                    /** @description Required delay in whole seconds before retrying */
                    "Retry-After": number;
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
        };
    };
    confirm_session_reuse: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                interaction: string;
                project_public_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ConfirmSessionReuseRequest"];
            };
        };
        responses: {
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["NavigationResponse"];
                };
            };
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
            429: {
                headers: {
                    /** @description Required delay in whole seconds before retrying */
                    "Retry-After": number;
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
        };
    };
    start_login: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                project_public_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["LoginStartRequest"];
            };
        };
        responses: {
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["LoginStartResponse"];
                };
            };
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
            429: {
                headers: {
                    /** @description Required delay in whole seconds before retrying */
                    "Retry-After": number;
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
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
    logout_application_session: {
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
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CompletionResponse"];
                };
            };
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
            429: {
                headers: {
                    /** @description Required delay in whole seconds before retrying */
                    "Retry-After": number;
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
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
    refresh_session: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                project_public_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RefreshRequest"];
            };
        };
        responses: {
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CredentialPairResponse"];
                };
            };
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
            429: {
                headers: {
                    /** @description Required delay in whole seconds before retrying */
                    "Retry-After": number;
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
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
    get_current_user: {
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
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CurrentUserResponse"];
                };
            };
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
            429: {
                headers: {
                    /** @description Required delay in whole seconds before retrying */
                    "Retry-After": number;
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
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
