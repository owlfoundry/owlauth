# 05 — Cross-language Project Auth error semantics

## Goal

Applications need the same decision-relevant Runtime meaning in every official SDK without depending on HTTP-library exceptions, upstream-provider diagnostics, or unsafe response bodies. Errors are typed, preserve stable reviewed fields, and chain only redacted causes where idiomatic.

## Stable taxonomy

| Category         | Meaning                                                                                                     | Typical Application action                                                           |
| ---------------- | ----------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| `Configuration`  | invalid local Runtime URL, Project/Application identifiers, deadline, explicit state, or unsupported option | fix configuration; no request or credential reuse                                    |
| `Protocol`       | malformed/unexpected Runtime response, context mismatch, or unsupported contract                            | stop; diagnose server/SDK compatibility                                              |
| `Login`          | login cannot start or the upstream-provider interaction completed with a safe normalized failure            | restart login or choose another enabled provider                                     |
| `Handoff`        | callback state/ticket/PKCE is invalid, expired, already used, or context-bound elsewhere                    | discard pending state and start a new login                                          |
| `Authentication` | Project access/session credential is absent, expired, revoked, or no longer valid                           | clear affected local state and reauthenticate                                        |
| `Session`        | current-user/logout/session operation cannot complete under current Project/Application state               | reauthenticate, correct mode, or stop according to code                              |
| `Refresh`        | refresh family is expired, revoked, replayed, or definitively unusable                                      | clear the family and reauthenticate; never retry consumed material                   |
| `RateLimited`    | an optional SaaS/ingress traffic policy rejected the request before Core authority work                     | honor bounded reviewed retry guidance                                                |
| `Transport`      | DNS/TLS/connectivity/I/O failure without a definite Runtime response                                        | retry only when operation policy proves safety                                       |
| `Timeout`        | deadline elapsed; server effect may be unknown                                                              | treat one-use operations as ambiguous                                                |
| `Cancelled`      | caller stopped waiting; server effect may be unknown                                                        | Application selects recovery under operation policy                                  |
| `Indeterminate`  | outcome of handoff, refresh, logout, or another sensitive mutation cannot be known safely                   | quarantine/clear uncertain state and reauthenticate or reconcile; never blind replay |

Validation/not-found/conflict subclasses may be added when the real Runtime contract requires them. Cross-language review is required before taxonomy changes.

There is no downstream generic `OAuth` error category. Upstream OAuth/OIDC failures are normalized by Runtime into safe Project Auth login errors. SDKs neither expose provider tokens nor require Applications to branch on provider-specific wire diagnostics.

## Required fields

Every public error exposes:

- a stable category and machine code;
- a safe human message;
- optional allowlisted correlation/request ID;
- retry classification: `never`, `safe_after_delay`, or `application_decision`;
- optional bounded `retry_after_seconds`, present only for a valid `429 rate_limited` response with one required decimal-seconds `Retry-After` header;
- operation context that does not contain credentials or hidden resource existence.

HTTP status may aid diagnostics but is not the sole classifier. Unknown Runtime error codes remain inspectable through a forward-compatible representation and map to a conservative category/retry policy rather than failing deserialization or becoming retryable by default.

An error may identify the configured Project/Application only when that data was already public Application configuration. It never reveals whether another Project, Application, user, identity, ticket, session, or token exists.

## Operation-specific mapping

- Local state/PKCE mismatch fails as `Handoff` without sending a request.
- Definitive invalid/expired/consumed handoff fails as `Handoff` and requires the caller to destroy pending material.
- Definitive refresh expiry/revocation/replay fails as `Refresh` and requires the caller to invalidate the local family.
- Timeout/disconnect/cancellation after dispatching handoff exchange or refresh rotation becomes `Indeterminate`, not generic retryable `Transport`.
- A closed Core `408` envelope is accepted only with code `request_timeout`. It maps to `Timeout`, `application_decision`, and no local action for non-sensitive operations; for a dispatched handoff, refresh, Application logout, or browser-logout preparation it maps to `Indeterminate`, `never`, and the existing quarantine action because the listener deadline may expire after authority work begins. A malformed or differently coded `408` follows the invalid-response phase rule.
- Disabled Project/Application/user/session maps to a non-enumerating authentication/session category according to the public Runtime code.
- Provider rejection/unavailability maps to `Login`; raw provider error descriptions are not forwarded.
- A response contradicting configured Project/Application context is `Protocol` and is never adopted.

## Dispatch-phase and local-state decisions

Every transport failure records one of `before_dispatch`, `possibly_dispatched`, or `response_received`. A client must not infer `before_dispatch` merely because its local cancellation completed quickly. When the transport cannot prove that no request bytes were released, the phase is `possibly_dispatched`.

| Operation family           | Before dispatch                                                                 | Possibly dispatched without a definitive response                                       | Definitive Runtime response                                                                  | Invalid success after dispatch                                                |
| -------------------------- | ------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| public config / JWKS       | `Transport`/`Timeout`/`Cancelled`; no state action; safe explicit retry allowed | same conservative transport category; bounded explicit retry allowed                    | map reviewed error; `429` may be `safe_after_delay`                                          | `Protocol`; no state action                                                   |
| login start                | no pending result exists; caller may start explicitly                           | no automatic replay; caller starts a new login transaction with fresh PKCE/state        | `Login` or reviewed category; discard any provisional result                                 | `Protocol`; discard provisional pending material                              |
| handoff exchange           | validated material remains usable only if dispatch was positively prevented     | `Indeterminate`; destroy/quarantine pending; never retry                                | definitive handoff errors discard pending; success returns one credential pair               | `Indeterminate`; quarantine pending because Runtime may have committed        |
| refresh                    | current pair remains usable only if dispatch was positively prevented           | `Indeterminate`; quarantine the entire family; never retry the submitted token          | definitive refresh/authentication error invalidates family; success requires exact successor | `Indeterminate`; quarantine family because Runtime may have rotated it        |
| current user               | safe explicit retry under caller policy; no credential mutation                 | same; cancellation does not invalidate credentials                                      | `401` requires reauthentication; other reviewed errors follow their action                   | `Protocol`; do not replace context or credentials                             |
| Application logout         | credentials remain until caller chooses otherwise                               | `Indeterminate`; quarantine/clear caller credentials; do not claim confirmed revocation | confirmed success clears caller state; definitive auth/session error follows reviewed action | `Indeterminate`; quarantine credentials because revocation may have committed |
| browser-logout preparation | credentials remain until caller chooses otherwise                               | `Indeterminate`; discard unknown preparation and follow caller quarantine policy        | success returns one target as data; definitive errors follow reviewed action                 | `Indeterminate`; never navigate to unvalidated or partial target              |

A valid `408 request_timeout` response is a Core transport-budget result and appears in Runtime OpenAPI for every operation. It does not prove whether a dispatched sensitive operation committed because one deadline covers local concurrency waiting and handler execution. SDKs preserve its safe request ID and HTTP status; they never convert it into `429`, traffic admission, or an automatic replay.

A valid `429 rate_limited` response is an optional SaaS/ingress result produced before OwlAuth Core operation authority is invoked, so it is not ambiguous. It is not part of the self-hosted Core OpenAPI and Core does not emit deployment-wide traffic quotas. It has the exact closed Runtime error envelope plus one decimal-seconds `Retry-After` header in the reviewed `0..=86_400` bound. Public config, JWKS, current-user reads, and a newly initiated login use `safe_after_delay` with no retained sensitive result. Handoff uses `never` plus `discard_pending` because the local one-use validation material was consumed before dispatch. Refresh uses `application_decision` with no invalidation because Runtime proved it did not consume the submitted generation; any explicit retry remains Application-single-flight and is never automatic. Application logout and browser-logout preparation likewise use `application_decision` with no forced credential action. A missing, duplicate/combined, non-decimal, negative, or out-of-bound `Retry-After`, or a malformed/missing `429` error envelope, does not provide this proof and follows the invalid-response phase rule instead.

A structured `5xx` is definitive only when both its status is allowed for that operation and the reviewed Runtime code proves the sensitive mutation did not commit. Otherwise a handoff, refresh, logout, or preparation response received after dispatch is `Indeterminate`, even though an HTTP response exists. Any uncontracted status is an invalid response regardless of whether its body resembles a Runtime error. Raw `5xx` text never supplies proof.

The local action and retry classification are part of the semantic result, not advice reconstructed independently by each language. `Indeterminate` always uses `never` for automatic retry. Safe explicit retries create a new caller decision and still obey bounded `Retry-After`; they are not hidden transport loops.

## Language mapping

- TypeScript exports the same error classes or stable discriminants in supported browsers and Node.js, supports narrowing, and preserves a safe `cause`.
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

- Shared conformance cases verify category, code, retry classification, required caller state action, unknown-code behavior, context mismatch, and redaction.
- Equivalent Runtime responses have equivalent semantic outcomes in every language.
- HTTP/provider library implementation details are not required for Application branching.
- Ambiguous handoff/refresh/logout outcomes never become automatically retryable transport errors.
- Public taxonomy changes receive independent SemVer review for every SDK.
