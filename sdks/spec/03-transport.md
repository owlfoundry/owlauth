# 03 — Transport

## Status

No SDK currently sends network requests. The following rules apply when transport is introduced.

## URL and connection policy

The client validates an absolute base URL at construction. HTTPS is the production default. Any plain-HTTP allowance is explicit and limited to loopback/development policy. URL joining MUST preserve configured path prefixes and prevent endpoint paths or redirects from switching authority unexpectedly.

TLS certificate and hostname verification are enabled by default. Custom trust roots are explicit; a global “disable verification” convenience MUST NOT be a normal option. Proxy behavior, environment inheritance, and redirect following are documented because they alter trust boundaries.

Transport sets an identifiable, non-sensitive user agent and supported content types. It applies bounded response bodies, header limits where the HTTP stack permits, connect/read/overall deadlines, and connection-pool limits. Decompression has output bounds.

## Request behavior

Public methods define:

- HTTP method/path and accepted success statuses;
- authentication placement;
- encoding and content type;
- idempotency/replay classification;
- cancellation and timeout behavior;
- maximum response assumptions;
- semantic error mapping.

Authorization headers, cookies, codes, verifiers, tokens, and client secrets MUST never appear in URL query parameters unless the adopted protocol explicitly requires a front-channel value; bearer credentials always use reviewed header/body placement.

## Retries and ambiguous outcomes

Retries are disabled by default for one-use or state-changing OAuth exchanges. A request may be automatically retried only when all of these hold:

1. its operation is classified as safe/replayable;
2. no application-visible cancellation/deadline has occurred;
3. backoff is bounded and honors server guidance such as `Retry-After` safely;
4. retry does not cross an origin or repeat exposed credential material to a different authority.

Authorization-code exchange and refresh rotation MUST NOT be blindly replayed after an ambiguous network outcome. The SDK returns a semantic indeterminate/transport result and lets server state or the lifecycle coordinator determine safe recovery.

## Cancellation and concurrency

TypeScript accepts `AbortSignal`; Python and Rust expose idiomatic cancellation/deadline mechanisms chosen by their implementations. Cancellation stops waiting but does not claim the server did not execute. Client instances document thread/task safety. Shared mutable token state is coordinated outside the raw transport.

## Testability

Transport depends on a narrow injectable interface so unit and conformance tests can provide deterministic responses without real network access. Test doubles MUST be called mocks/fakes, not end-to-end tests. Security and interoperability eventually require a real TLS/HTTP-capable stack against a real OwlAuth server.

## Acceptance criteria

- Cross-language tests cover URL normalization, path prefixes, redirect refusal, limits, timeouts, cancellation, and redaction.
- Retry tests prove no automatic replay for code exchange or refresh rotation.
- HTTP-library errors do not leak directly as the stable public taxonomy.
- Real-server tests, once available, exercise proxy/TLS assumptions supported by release documentation.
