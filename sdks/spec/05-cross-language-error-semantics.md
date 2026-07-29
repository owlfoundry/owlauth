# 05 — Cross-language Project Auth error semantics

## Goal

Applications need the same decision-relevant Runtime meaning in every official SDK without depending on HTTP-library exceptions, upstream-provider diagnostics, or unsafe response bodies. Errors are typed, preserve stable reviewed fields, and chain only redacted causes where idiomatic.

## Stable taxonomy

| Category | Meaning | Typical Application action |
| --- | --- | --- |
| `Configuration` | invalid local Runtime URL, Project/Application identifiers, deadline, store, or unsupported option | fix configuration; no request or credential reuse |
| `Protocol` | malformed/unexpected Runtime response, context mismatch, or unsupported contract | stop; diagnose server/SDK compatibility |
| `Login` | login cannot start or the upstream-provider interaction completed with a safe normalized failure | restart login or choose another enabled provider |
| `Handoff` | callback state/ticket/PKCE is invalid, expired, already used, or context-bound elsewhere | discard pending state and start a new login |
| `Authentication` | Project access/session credential is absent, expired, revoked, or no longer valid | clear affected local state and reauthenticate |
| `Session` | current-user/logout/session operation cannot complete under current Project/Application state | reauthenticate, correct mode, or stop according to code |
| `Refresh` | refresh family is expired, revoked, replayed, or definitively unusable | clear the family and reauthenticate; never retry consumed material |
| `RateLimited` | Runtime admission policy rejected the request | honor bounded reviewed retry guidance |
| `Transport` | DNS/TLS/connectivity/I/O failure without a definite Runtime response | retry only when operation policy proves safety |
| `Timeout` | deadline elapsed; server effect may be unknown | treat one-use operations as ambiguous |
| `Cancelled` | caller stopped waiting; server effect may be unknown | Application selects recovery under operation policy |
| `Indeterminate` | outcome of handoff, refresh, logout, or another sensitive mutation cannot be known safely | quarantine/clear uncertain state and reauthenticate or reconcile; never blind replay |

Validation/not-found/conflict subclasses may be added when the real Runtime contract requires them. Cross-language review is required before taxonomy changes.

There is no downstream generic `OAuth` error category. Upstream OAuth/OIDC failures are normalized by Runtime into safe Project Auth login errors. SDKs neither expose provider tokens nor require Applications to branch on provider-specific wire diagnostics.

## Required fields

Every public error exposes:

- a stable category and machine code;
- a safe human message;
- optional allowlisted correlation/request ID;
- retry classification: `never`, `safe_after_delay`, or `application_decision`;
- operation context that does not contain credentials or hidden resource existence.

HTTP status may aid diagnostics but is not the sole classifier. Unknown Runtime error codes remain inspectable through a forward-compatible representation and map to a conservative category/retry policy rather than failing deserialization or becoming retryable by default.

An error may identify the configured Project/Application only when that data was already public Application configuration. It never reveals whether another Project, Application, user, identity, ticket, session, or token exists.

## Operation-specific mapping

- Local state/PKCE mismatch fails as `Handoff` without sending a request.
- Definitive invalid/expired/consumed handoff fails as `Handoff` and destroys pending material.
- Definitive refresh expiry/revocation/replay fails as `Refresh` and invalidates the local family.
- Timeout/disconnect/cancellation after dispatching handoff exchange or refresh rotation becomes `Indeterminate`, not generic retryable `Transport`.
- Disabled Project/Application/user/session maps to a non-enumerating authentication/session category according to the public Runtime code.
- Provider rejection/unavailability maps to `Login`; raw provider error descriptions are not forwarded.
- A response contradicting configured Project/Application context is `Protocol` and is never adopted.

## Language mapping

- TypeScript exports error classes or a stable discriminant, supports narrowing, and preserves a safe `cause`.
- Python exports an exception hierarchy with stable attributes and secret-free `str`/`repr`.
- Rust exports a non-exhaustive error enum/struct strategy; `Display`, `Debug`, and sources remain redacted.

Names may differ idiomatically, but shared fixtures map each language to the same category, stable code, retry classification, and local credential action.

## Disclosure control

Messages and causes never include:

- authorization headers or cookies;
- provider codes/tokens/errors with unreviewed text;
- handoff tickets, PKCE verifiers, Project access/refresh tokens;
- management credentials or provider secrets;
- raw response bodies or full callback URLs;
- complete user/profile payloads.

Truncation is not redaction. Diagnostic opt-in may expose allowlisted status/header names, timing, operation name, and correlation metadata, but never raw credentials or hidden cross-Project state.

## Acceptance criteria

- Shared conformance cases verify category, code, retry classification, unknown-code behavior, context mismatch, and redaction.
- Equivalent Runtime responses have equivalent semantic outcomes in every language.
- HTTP/provider library implementation details are not required for Application branching.
- Ambiguous handoff/refresh/logout outcomes never become automatically retryable transport errors.
- Public taxonomy changes receive independent SemVer review for every SDK.
