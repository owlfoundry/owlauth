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
    "/auth/email/confirm/{challenge_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["get_email_magic_confirmation"];
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
    "/v1/projects/{project_public_id}/auth/email/magic/confirm": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["confirm_email_magic"];
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
    "/v1/projects/{project_public_id}/auth/identity-mutations/{intent}/confirm": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["confirm_identity_mutation"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/projects/{project_public_id}/auth/identity-mutations/{intent}/proofs/{proof_slot}/email/challenges": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["begin_identity_mutation_email_challenge"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/projects/{project_public_id}/auth/identity-mutations/{intent}/proofs/{proof_slot}/email/link/verify": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["verify_identity_mutation_email_link"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/projects/{project_public_id}/auth/identity-mutations/{intent}/proofs/{proof_slot}/email/otp/verify": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["verify_identity_mutation_email_otp"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/projects/{project_public_id}/auth/identity-mutations/{intent}/proofs/{proof_slot}/method": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["select_identity_mutation_method"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/projects/{project_public_id}/auth/interactions/{interaction}/email/challenges": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["begin_email_challenge"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/projects/{project_public_id}/auth/interactions/{interaction}/email/otp/verify": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["verify_email_otp"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/projects/{project_public_id}/auth/interactions/{interaction}/email/resend": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["resend_email_challenge"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/projects/{project_public_id}/auth/interactions/{interaction}/email/select": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["select_email"];
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
    "/v1/projects/{project_public_id}/auth/managed-reauthorizations/{interaction}/start": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["start_managed_reauthorization"];
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
        BeginEmailChallengeRequest: {
            csrf: string;
            email: string;
            /** Format: int64 */
            expected_revision: number;
        };
        BeginIdentityMutationEmailChallengeRequest: {
            csrf: string;
            email: string;
            /** Format: int64 */
            expected_revision: number;
        };
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
        ConfirmEmailMagicRequest: {
            challenge_id: string;
            csrf: string;
            /** Format: int64 */
            expected_revision: number;
            /** Format: int32 */
            generation: number;
            proof: string;
            transaction_id: string;
        };
        ConfirmHostedIdentityMutationRequest: {
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
        EmailChallengeAcceptedResponse: {
            accepted: boolean;
            challenge_id: string;
            expires_at: string;
            /** Format: int32 */
            generation: number;
            proof_modes: components["schemas"]["EmailProofMode"][];
            /** Format: int64 */
            revision: number;
        };
        /** @enum {string} */
        EmailProofMode: "otp" | "magic_link";
        EmailProofResponse: {
            application_type?: null | components["schemas"]["HostedApplicationType"];
            completed: boolean;
            redirect_url?: string | null;
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
        HostedIdentityMutationResponse: {
            /** Format: int64 */
            revision: number;
            status: components["schemas"]["HostedIdentityMutationStatus"];
        };
        /** @enum {string} */
        HostedIdentityMutationStatus: "pending_proof" | "ready" | "expired" | "cancelled";
        HostedInteractionResponse: {
            application_display_name: string;
            application_id: string;
            application_type: components["schemas"]["HostedApplicationType"];
            csrf: string;
            email_available: boolean;
            email_proof_modes: components["schemas"]["EmailProofMode"][];
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
        HostedInteractionStatus: "awaiting_method_selection" | "email_address_entry" | "email_challenge_pending" | "provider_authorization_started" | "provider_exchange_in_progress" | "authenticated" | "handoff_issued" | "completed" | "failed" | "expired";
        HostedProvider: {
            display_name: string;
            key: string;
            kind: components["schemas"]["ProviderKind"];
        };
        /** @enum {string} */
        IdentityKind: "provider" | "email";
        IdentityMutationEmailChallengeResponse: {
            accepted: boolean;
            challenge_id: string;
            expires_at: string;
            /** Format: int32 */
            generation: number;
            proof_modes: components["schemas"]["EmailProofMode"][];
            /** Format: int64 */
            revision: number;
        };
        /** @enum {string} */
        IdentityMutationMethodKind: "provider" | "email";
        IdentityMutationMethodResponse: {
            /** @enum {string} */
            method_kind: "provider";
            result: components["schemas"]["NavigationResponse"];
        } | {
            /** @enum {string} */
            method_kind: "email";
            result: components["schemas"]["IdentityMutationProofStateResponse"];
        };
        /** @enum {string} */
        IdentityMutationProofState: "email_address_entry" | "email_challenge_pending" | "provider_authorization_started" | "provider_exchange_in_progress" | "proved" | "expired";
        IdentityMutationProofStateResponse: {
            /** Format: int64 */
            revision: number;
            state: components["schemas"]["IdentityMutationProofState"];
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
        ProviderKind: "oidc" | "google" | "github";
        PublicApplicationConfig: {
            application_display_name: string;
            application_public_id: string;
            /** @description True only while this Runtime can complete the durable email flow. */
            email_available: boolean;
            email_magic_link_enabled: boolean;
            email_otp_enabled: boolean;
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
        SelectEmailRequest: {
            csrf: string;
            /** Format: int64 */
            expected_revision: number;
        };
        SelectIdentityMutationMethodRequest: {
            csrf: string;
            /** Format: int64 */
            expected_revision: number;
            /** @description Assertion of the immutable method selected by Control for this exact proof slot. */
            method_kind: components["schemas"]["IdentityMutationMethodKind"];
        };
        SelectProviderRequest: {
            csrf: string;
            /** Format: int64 */
            expected_revision: number;
            provider_key: string;
        };
        /** @enum {string} */
        SigningAlgorithm: "EdDSA";
        StartManagedReauthorizationRequest: {
            csrf: string;
            /** Format: int64 */
            expected_revision: number;
        };
        UserProjection: {
            created_at: string;
            display_name: string | null;
            locale: string | null;
            picture_url: string | null;
            /** Format: int64 */
            projection_revision: number;
            projection_schema: string;
            status: string;
            updated_at: string;
            user_id: string;
            /** Format: int64 */
            user_revision: number;
            verified_email: string | null;
        };
        VerifyEmailOtpRequest: {
            challenge_id: string;
            csrf: string;
            /** Format: int64 */
            expected_revision: number;
            /** Format: int32 */
            generation: number;
            otp: string;
        };
        VerifyIdentityMutationEmailLinkRequest: {
            challenge_id: string;
            csrf: string;
            /** Format: int64 */
            expected_revision: number;
            /** Format: int32 */
            generation: number;
            token: string;
        };
        VerifyIdentityMutationEmailOtpRequest: {
            challenge_id: string;
            csrf: string;
            /** Format: int64 */
            expected_revision: number;
            /** Format: int32 */
            generation: number;
            otp: string;
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
    get_email_magic_confirmation: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                challenge_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Generic fragment-only magic-link confirmation shell */
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
            429: {
                headers: {
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
    confirm_email_magic: {
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
                "application/json": components["schemas"]["ConfirmEmailMagicRequest"];
            };
        };
        responses: {
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["EmailProofResponse"];
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
    confirm_identity_mutation: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                intent: string;
                project_public_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ConfirmHostedIdentityMutationRequest"];
            };
        };
        responses: {
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HostedIdentityMutationResponse"];
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
    begin_identity_mutation_email_challenge: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                intent: string;
                project_public_id: string;
                proof_slot: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["BeginIdentityMutationEmailChallengeRequest"];
            };
        };
        responses: {
            202: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["IdentityMutationEmailChallengeResponse"];
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
    verify_identity_mutation_email_link: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                intent: string;
                project_public_id: string;
                proof_slot: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["VerifyIdentityMutationEmailLinkRequest"];
            };
        };
        responses: {
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["IdentityMutationProofStateResponse"];
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
    verify_identity_mutation_email_otp: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                intent: string;
                project_public_id: string;
                proof_slot: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["VerifyIdentityMutationEmailOtpRequest"];
            };
        };
        responses: {
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["IdentityMutationProofStateResponse"];
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
    select_identity_mutation_method: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                intent: string;
                project_public_id: string;
                proof_slot: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["SelectIdentityMutationMethodRequest"];
            };
        };
        responses: {
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["IdentityMutationMethodResponse"];
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
    begin_email_challenge: {
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
                "application/json": components["schemas"]["BeginEmailChallengeRequest"];
            };
        };
        responses: {
            202: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["EmailChallengeAcceptedResponse"];
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
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
        };
    };
    verify_email_otp: {
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
                "application/json": components["schemas"]["VerifyEmailOtpRequest"];
            };
        };
        responses: {
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["EmailProofResponse"];
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
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
        };
    };
    resend_email_challenge: {
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
                "application/json": components["schemas"]["BeginEmailChallengeRequest"];
            };
        };
        responses: {
            202: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["EmailChallengeAcceptedResponse"];
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
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuntimeError"];
                };
            };
        };
    };
    select_email: {
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
                "application/json": components["schemas"]["SelectEmailRequest"];
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
    start_managed_reauthorization: {
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
                "application/json": components["schemas"]["StartManagedReauthorizationRequest"];
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
