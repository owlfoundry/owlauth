# 03 — Runtime transport

## Current status

No official SDK currently sends a network request. These rules apply when Runtime Project Auth transport is introduced.

## TypeScript runtime portability

The TypeScript protocol client is published once as `@owlauth/client`. Its portable runtime path uses Web-standard `fetch`, `URL`, `AbortSignal`, and Web Crypto APIs shared by the declared browser and Node.js support matrices; it does not require Node-only modules, browser globals, environment auto-detection, or an `@owlauth/client/browser` entry point.

This portability covers protocol API execution only. The package does not navigate, mutate browser history, select browser storage, install framework hooks, or manage an Application session. Browser support is claimed only after the same published artifact passes real browser bundling, CORS, crypto, cancellation, callback parsing, and real-Runtime tests in the declared matrix.

## URL and connection policy

A client validates one absolute Runtime base URL at construction. HTTPS is mandatory by default outside an explicit loopback development policy. URL joining preserves a configured path prefix and prevents endpoint paths, provider-returned values, redirects, or headers from changing authority unexpectedly.

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

`project_id`, `application_id`, and a publishable key may appear where the public Runtime contract specifies. They remain identifiers, not secrets. Project access tokens use reviewed authorization-header placement. Refresh tokens, handoff tickets, PKCE verifiers, browser cookies, and management credentials never appear in URLs. The only front-channel value returned to an Application redirect is the protocol-defined short-lived handoff result plus bounded Application state.

Transport does not send provider credentials or provider tokens: OwlAuth Runtime owns upstream-provider interaction.

## Redirect behavior

Low-level API requests do not automatically follow redirects across origins. Login initiation returns a provider authorization URL as data; only the Application or an external platform integration may navigate to it. A provider authorization URL is not adopted as the SDK's API origin and never receives Project session credentials.

The final Application redirect is processed by the Application/SDK handoff boundary, not followed as an HTTP API redirect. Exact redirect registration and callback binding remain Runtime authority.

## Retry and ambiguous outcomes

Automatic retry is disabled for one-use or state-changing Project Auth operations unless replay safety is explicitly proven.

A request may be retried automatically only when:

1. the operation is classified as safe/replayable (for example, public configuration or Project JWKS retrieval);
2. no caller cancellation/deadline has occurred;
3. bounded backoff safely honors reviewed `Retry-After` guidance;
4. credentials are never repeated to another authority;
5. the retry cannot consume a handoff or rotate/revoke a session twice.

Handoff exchange and strict refresh rotation are never blindly replayed after timeout, cancellation, disconnect, or another ambiguous outcome. The SDK returns an `Indeterminate` semantic error and requires reconciliation or reauthentication according to spec 04. Login-start retry also creates a new explicit transaction rather than guessing whether an earlier one exists.

Logout may be designed as idempotent by the Runtime contract, but the SDK must not assume this without an operation-specific guarantee.

## Cancellation and concurrency

TypeScript accepts `AbortSignal`; Python and Rust expose their selected idiomatic cancellation/deadline mechanisms. Cancellation stops local waiting but does not assert that Runtime did not commit an exchange, refresh, or logout.

Client instances document thread/task safety. Raw transport is stateless except for connection management. Pending PKCE state and access/refresh credentials are explicit caller-held values. Refresh serialization and durable atomic replacement belong to the Application or an external stateful integration layer and remain Project/Application scoped; the core transport does not imply a process-wide session coordinator.

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
