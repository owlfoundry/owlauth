# 06 — Fixtures, conformance, and end-to-end validation

## Machine-readable attachments

[`fixtures/`](fixtures/) stores reviewed wire examples; [`conformance/`](conformance/) stores language-neutral behavior cases. Attachments use relative paths, stable names, and an explicit `schemaVersion`.

The current corpus is intentionally minimal:

- [`fixtures/health-response.json`](fixtures/health-response.json) contains only `{ "status": "ok" }`;
- [`conformance/cases.json`](conformance/cases.json) asserts only that health response.

It does not describe a public Project/Application configuration, provider login, PKCE, handoff, Project token, refresh, current-user, logout, or error case. It is not a Project Auth conformance suite and does not prove any SDK transport exists.

## Future fixture families

As Runtime capabilities become real, shared attachments should cover:

- bounded public Project/Application auth configuration and provider display keys;
- login-start inputs/results with synthetic exact redirects and S256 challenges;
- successful and failed one-use handoff exchange;
- bounded Project user/session and access/refresh response shapes;
- strict refresh rotation, replay-family revocation, and ambiguous outcomes;
- current-user and Application/Project-browser logout semantics;
- cross-Project/Application mismatch rejection;
- stable Project Auth error codes, retry classification, and redaction.

Fixtures describe public wire/semantic behavior only. They never copy internal rows, provider payloads, secret references, management DTOs, or a generated OpenAPI document.

## Fixture rules

Fixtures are deterministic, minimal, synthetic, and valid under their declared schema. They contain no usable secret, real domain/account, live token, production Project/Application/user identifier, or private endpoint.

Secret/redaction cases use unmistakable non-production sentinels and assert those exact sentinels never appear in formatted output, errors, logs, traces, or snapshots. A fixture may represent a token-shaped value only when its schema marks it synthetic and tests prohibit accidental disclosure.

Each conformance case defines:

- a unique stable name;
- fixture/input reference;
- required capability and minimum corpus schema;
- configured Project/Application context where relevant;
- expected semantic output/error and local credential action.

Corpus schema changes increment `schemaVersion`. Runners explain unsupported required versions instead of silently skipping them.

## Conformance runner responsibilities

Every official SDK loads the same corpus and translates only language binding details. A runner must:

- fail on unknown required fields, missing fixtures, duplicate names, bad references, or unsupported required schema versions;
- report skipped optional capabilities explicitly;
- compare semantic Project Auth outcomes rather than incidental formatting;
- exercise generated Runtime models plus handwritten transport/lifecycle/error layers where applicable;
- assert Project/Application context never changes because of fixture data;
- retain language-specific unit tests for idioms not representable in shared data.

A case passing in one language is not cross-language conformance. Every SDK claiming that capability passes all required cases.

## Validation stages

### Current checks

While SDKs are base-URL-only scaffolds, CI may run package builds, static checks, unit tests, generated OpenAPI checks, JSON attachment validation, and the one health case if a runner exists. These stages must not be called Project Auth conformance or E2E.

Mock/fake transport tests introduced later are unit or contract tests. They may validate failure paths and coordination, but they do not establish interoperability.

### Real-server E2E

Before a package claims a Project Auth capability, CI starts a real `owlauth-server` Runtime with isolated PostgreSQL/Redis/configuration, test keys, one synthetic Project/Application/provider setup, and deterministic non-secret test identities. The official SDK then exercises the claimed flow over real HTTP.

The eventual cross-language matrix covers, as capabilities ship:

- public configuration and Project/Application rejection;
- provider login start and exact redirect behavior through a deterministic test provider adapter;
- PKCE-bound one-use handoff success, mismatch, expiry, and replay;
- Project JWT/session response shape and current-user behavior;
- strict refresh rotation, concurrency, replay-family revocation, and ambiguous response handling;
- Application-only and Project-browser logout;
- Project isolation and disabled Project/Application/user/session behavior;
- stable errors and seeded-secret log scanning.

The same published `@owlauth/client` artifact and public protocol API run in every declared Node.js version and supported browser engine. The browser-direct test Application owns navigation, history cleanup, pending/credential state, refresh serialization, and atomic replacement; those harness behaviors are not attributed to the core SDK. Browser tests also prove that the browser bundle has no Node-only runtime dependency and that real Runtime CORS, Web Crypto, cancellation, callback parsing, and browser-callable protocol operations work without a separate browser package or entry point.

A separate product E2E topology uses a real Application backend for handoff exchange, credential custody, Project JWT verification, refresh, current user, and logout. The browser-direct compatibility matrix and backend-custody product E2E are distinct required evidence when both support claims apply; neither substitutes for the other.

The database and environment are destroyed after the job. A static fixture, mock response, generated-client compile, or health endpoint round trip is never labeled E2E.

## Acceptance criteria

- Every attachment link resolves and every schema version is validated.
- Fixture descriptions state current limited coverage truthfully.
- Required cases produce equivalent results in every claiming SDK.
- TypeScript Node.js and browser jobs exercise one `@owlauth/client` core rather than divergent platform implementations.
- CI names package/unit/contract/conformance/E2E stages accurately.
- Project Auth release claims wait for a real-server test of that capability.
