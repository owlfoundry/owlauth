# 03 — Runtime transport

## Current status

All three Beta official SDKs implement the Runtime Project Auth network operations described here through their platform-appropriate injectable transports. The TypeScript package uses one Web-standard core in Node.js and supported browsers. The matrices below are normative; an existing Beta implementation is not conformant evidence until its source, shared corpus, exact artifact, and real-server lanes all pass them.

## TypeScript runtime portability

The TypeScript protocol client is published once as `@owlauth/client`. Its portable runtime path uses Web-standard `fetch`, `URL`, `AbortSignal`, and Web Crypto APIs shared by the declared browser and Node.js support matrices; it does not require Node-only modules, browser globals, environment auto-detection, or an `@owlauth/client/browser` entry point.

This portability covers protocol API execution only. The package does not navigate, mutate browser history, select browser storage, install framework hooks, or manage an Application session. Browser support is claimed only after the same published artifact passes real browser bundling, CORS, crypto, cancellation, callback parsing, and real-Runtime tests in the declared matrix.

## URL and connection policy

A client validates one absolute Runtime base URL at construction. HTTPS is mandatory by default outside an explicit loopback development policy. URL joining preserves a configured path prefix and prevents endpoint paths, provider-returned values, redirects, or headers from changing authority unexpectedly. Base and Runtime-returned URLs reject raw backslashes, percent-encoded separators, percent-encoded dot segments, and percent-encoded percent signs that could otherwise be normalized into another path or decoded a second time.

TLS certificate and hostname verification remain enabled through each platform's transport. A general “disable verification” option is not a normal public API. Custom trust roots and proxy/environment inheritance are explicit only on platforms whose transport exposes them; browser execution uses the user agent's trust and proxy policy and does not emulate unavailable controls through Node-only shims. Redirect behavior is documented everywhere because it changes trust boundaries.

Every transport enforces origin separation, an overall deadline/cancellation boundary, bounded parsed response data, and no credential-bearing cross-origin redirect. A non-sensitive user agent, raw header limits, separate connect/read deadlines, connection-pool limits, decompression controls, custom roots, and proxy policy are configured only where the platform exposes them. Each release documents and tests this platform capability matrix rather than claiming browser control over user-agent-managed behavior. Runtime and Control base URLs are distinct; the default SDK never redirects or falls through to a Control listener.

## Project-qualified request behavior

Every public operation defines:

- Runtime method/path and accepted success statuses;
- configured Project/Application binding;
- credential placement and content type;
- operation replay/idempotency classification;
- cancellation and deadline behavior;
- maximum response assumptions;
- stable semantic error mapping.

`project_id`, `application_id`, and a publishable key may appear where the public Runtime contract specifies. They remain identifiers, not secrets. Project access tokens use reviewed authorization-header placement. A Project server key is a separate customer-backend credential and never enters SDK configuration, headers, request models, transport hooks, or examples. Refresh tokens, handoff tickets, PKCE verifiers, browser cookies, and management credentials never appear in URLs. The only front-channel value returned to an Application redirect is the protocol-defined short-lived handoff result plus bounded Application state.

Transport does not send Project server keys, provider credentials, or provider tokens: OwlAuth Client and Runtime own their separate caller boundaries.

## Claimed operation matrix

The following table is normative for the initial SDK surface. An accepted success status is exact, not an arbitrary `2xx` range. Every success and Runtime error response is JSON and is subject to the common decoded-body bound below.

| Operation ID                    | Method and path                                                     | Request parameters/body                  | Credential placement                           | Exact success |
| ------------------------------- | ------------------------------------------------------------------- | ---------------------------------------- | ---------------------------------------------- | ------------- |
| `get_public_application_config` | `GET /v1/projects/{project_public_id}/auth/config`                  | required `application_id` query; no body | none                                           | `200`         |
| `get_project_jwks`              | `GET /projects/{project_public_id}/.well-known/jwks.json`           | no body                                  | none                                           | `200`         |
| `start_login`                   | `POST /v1/projects/{project_public_id}/auth/login/start`            | required JSON `LoginStartRequest`        | publishable key in JSON                        | `201`         |
| `exchange_handoff`              | `POST /v1/projects/{project_public_id}/auth/handoff/exchange`       | required JSON `HandoffExchangeRequest`   | publishable key, handoff, and verifier in JSON | `200`         |
| `refresh_session`               | `POST /v1/projects/{project_public_id}/auth/sessions/refresh`       | required JSON `RefreshRequest`           | publishable key and refresh token in JSON      | `200`         |
| `get_current_user`              | `GET /v1/projects/{project_public_id}/auth/users/me`                | no body                                  | Project access token as Bearer                 | `200`         |
| `logout_application_session`    | `POST /v1/projects/{project_public_id}/auth/sessions/logout`        | no body and no invented `{}`             | Project access token as Bearer                 | `200`         |
| `prepare_browser_logout`        | `POST /v1/projects/{project_public_id}/auth/browser-logout/prepare` | no body and no invented `{}`             | Project access token as Bearer                 | `201`         |

The accepted Runtime error statuses are also exact and come from the selected normalized contract:

| Operation ID                    | Exact Runtime error statuses |
| ------------------------------- | ---------------------------- |
| `get_public_application_config` | `400`, `404`, `429`, `503`   |
| `get_project_jwks`              | `404`, `429`, `503`          |
| `start_login`                   | `400`, `404`, `429`, `503`   |
| `exchange_handoff`              | `400`, `409`, `429`, `503`   |
| `refresh_session`               | `400`, `409`, `429`, `503`   |
| `get_current_user`              | `401`, `429`, `503`          |
| `logout_application_session`    | `401`, `429`, `503`          |
| `prepare_browser_logout`        | `401`, `429`, `503`          |

A status outside the operation's exact success and error sets is an invalid response even if it carries a syntactically valid Runtime error envelope. It is `Protocol` for reads and `Indeterminate` with the operation's quarantine action after a possibly dispatched sensitive mutation.

For requests with a JSON body, `Content-Type` is `application/json`; body fields and bounds come from the normalized OpenAPI 3.1 schema and unknown request fields are never added. Bodyless operations do not send a JSON placeholder or claim a content type for a body that is absent.

For responses:

- the maximum decoded body is 65,536 bytes for every claimed success or error; a larger declared or observed body fails before parsing, and a transport should stop reading once the bound is exceeded;
- a non-empty body and media type `application/json` are required; media-type matching is ASCII case-insensitive and permits parameters such as `charset=utf-8`;
- redirects are never followed and are not successes, including same-origin redirects;
- malformed JSON, an empty body, an unexpected exact status, a wrong media type, or a structurally invalid success is a `Protocol` failure for reads; after a possibly dispatched sensitive mutation it is `Indeterminate` with the operation's quarantine action because Runtime may already have committed;
- unknown object fields follow the selected schema exactly: objects with `additionalProperties: false` reject them, while open response objects ignore bounded additive fields and never re-export them as trusted data; an unknown value of a safety-relevant enum is a protocol failure until the contract, adapters, and shared cases explicitly support it;
- an unknown Runtime error code is retained only as a bounded safe code and receives the conservative mapping in spec 05; and
- `request_id` is exposed as optional allowlisted metadata even though the current Runtime schema emits it, so clients remain safe when an intermediary or compatible older response omits it.

## Redirect behavior

Low-level API requests do not automatically follow redirects across origins. Generic login initiation returns the OwlAuth Hosted Authentication interaction target as data; only the Application or an external platform integration may navigate to it. The SDK does not select a provider. A provider authorization request is created only after the browser-bound Hosted UI commits an explicit same-origin method-selection transition; its upstream URL is never adopted as the SDK's API origin and never receives Project session credentials.

The final Application redirect is processed by the Application/SDK handoff boundary, not followed as an HTTP API redirect. Exact redirect registration and callback binding remain Runtime authority.

## Retry and ambiguous outcomes

Automatic retry is disabled for one-use or state-changing Project Auth operations unless replay safety is explicitly proven.

A request may be retried automatically only when:

1. the operation is classified as safe/replayable (for example, public configuration or Project JWKS retrieval);
2. no caller cancellation/deadline has occurred;
3. bounded backoff safely honors the single required decimal-seconds `Retry-After` value on a valid `429` response;
4. credentials are never repeated to another authority;
5. the retry cannot consume a handoff or rotate/revoke a session twice.

Handoff exchange and strict refresh rotation are never blindly replayed after timeout, cancellation, disconnect, or another ambiguous outcome. The SDK returns an `Indeterminate` semantic error and requires reconciliation or reauthentication according to spec 04. Login-start retry also creates a new explicit transaction rather than guessing whether an earlier one exists.

Logout may be designed as idempotent by the Runtime contract, but the SDK must not assume this without an operation-specific guarantee.

## Cancellation and concurrency

TypeScript accepts `AbortSignal`; Python exposes a transport-specific cancellation boundary; Rust exposes an explicit cancellation future through operation options when the caller needs an SDK semantic result. Dropping a Python call or Rust future/task is outside the returned-error channel and the Application conservatively treats a sensitive dispatched operation as indeterminate. Cancellation stops local waiting but does not assert that Runtime did not commit an exchange, refresh, or logout.

Client instances document thread/task safety. Raw transport is stateless except for connection management. Pending PKCE state and access/refresh credentials are explicit caller-held values. Refresh serialization and durable atomic replacement belong to the Application or an external stateful integration layer and remain Project/Application scoped; the core transport does not imply a process-wide session coordinator.

The initial platform capability matrix is:

| Capability                | TypeScript browser                                 | TypeScript Node.js                         | Python                                           | Rust                                                                                             |
| ------------------------- | -------------------------------------------------- | ------------------------------------------ | ------------------------------------------------ | ------------------------------------------------------------------------------------------------ |
| Overall deadline          | SDK timer plus `AbortSignal`                       | SDK timer plus `AbortSignal`               | explicit timeout passed to transport             | explicit deadline passed to async transport                                                      |
| Caller cancellation       | `AbortSignal`                                      | `AbortSignal`                              | transport-specific; no false core claim          | explicit operation cancellation or transport failure; dropped futures are caller-owned ambiguity |
| Redirect refusal          | Fetch `redirect: error`; user-agent policy applies | Fetch `redirect: error`                    | selected transport must not follow API redirects | selected transport must not follow API redirects                                                 |
| Trust roots/proxy         | user agent owned                                   | runtime/transport owned; no core override  | transport/platform owned                         | transport/platform owned                                                                         |
| Decompression and pooling | user agent owned                                   | runtime owned                              | transport owned                                  | transport owned                                                                                  |
| Request phase             | before dispatch versus possibly dispatched         | before dispatch versus possibly dispatched | transport failure reports dispatch phase         | transport failure reports dispatch phase                                                         |

An unavailable platform control is documented as unavailable, not emulated by changing the public protocol or by importing a platform-specific implementation into the shared TypeScript core.

## Error responses

Transport parses only bounded reviewed Runtime error fields. Raw bodies, arbitrary headers, URLs, provider diagnostics, or HTTP-library error strings do not become public messages. Correlation IDs and retry metadata are retained only under the allowlist in spec 05.

A response whose Project/Application/session identity contradicts the active client context is a protocol violation, not a new context to accept.

## Testability

Transport depends on a narrow injectable interface so tests can provide deterministic responses without network access. Such tests are unit/contract tests, never end-to-end tests. Security and interoperability claims eventually require a real OwlAuth Runtime process and real HTTP/TLS behavior.

## Acceptance criteria

- Shared tests cover URL/path-prefix handling, HTTPS policy, Runtime/Control separation, redirect refusal, bounded parsed data, overall deadlines, cancellation, and redaction; platform-specific tests cover only transport controls that platform exposes.
- Project/Application context cannot be changed by a response or redirect.
- Retry tests prove no automatic replay of handoff exchange or refresh rotation.
- HTTP-library errors map to the stable taxonomy rather than leaking as public API.
- The same `@owlauth/client` artifact passes the declared Node.js and browser transport matrices without Node-only code in its browser closure.
- Real-server tests exercise every transport capability claimed by a release.
