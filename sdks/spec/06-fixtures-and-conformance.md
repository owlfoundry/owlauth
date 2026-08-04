# 06 — Fixtures, conformance, and end-to-end validation

## Machine-readable attachments

[`fixtures/`](fixtures/) stores reviewed wire examples; [`conformance/`](conformance/) stores language-neutral behavior cases. Attachments use relative paths, stable names, and an explicit `schemaVersion`.

The schema-version 3 corpus contains synthetic reviewed examples for exact public configuration and JWKS parsing, login start, callback inspection, handoff exchange, atomic credential refresh, current user, both logout forms, response framing, transport ambiguity, Runtime error mapping, retry/action semantics, unknown-code conservatism, and redaction. [`conformance/cases.json`](conformance/cases.json) pins the complete required case-name manifest and binds every required case to a canonical operation identifier, configured context, precondition, request phase, response-received fact, evidence level, fixture envelope, and expected semantic outcome. Removing, renaming, duplicating, or replacing a required case fails every runner.

The canonical flat projection schema is exactly `owlauth.user.v1`. Its `display_name`, `picture_url`, `locale`, and `verified_email` keys are always present and nullable: `null` means that the authoritative Application projection has no admitted value, not that an SDK omitted or failed to parse the field. `verified_email` is non-null only when both Project and Application policy admit it. Handoff, refresh, and current-user carry the same projection semantics and repeat its authoritative `projection_revision` only as matching envelope metadata. SDK parsers reject another schema identifier, missing nullable keys, and unknown projection fields.

The corpus exercises public protocol semantics through each language runner. It remains static conformance evidence, not proof of server interoperability; real-server tests below provide that separate evidence.

## Fixture families

Shared attachments cover the stable cross-language semantic core. A fixture envelope describes exactly one reviewed HTTP response, callback attempt sequence, or transport failure. HTTP envelopes include status, headers, bounded JSON, UTF-8 text, raw base64, empty, or repeated-byte body encoding, and any request assertion; callback envelopes include attempts and clock offset; transport-failure envelopes include failure kind and dispatch phase. Language-specific unit suites additionally cover deterministic S256 generation, callback ownership mechanics, concurrency, and runtime idioms that cannot be represented safely in shared data. Real-server suites cover authoritative one-use, refresh-replay, browser, provider, and disablement behavior.

Fixtures describe public wire/semantic behavior only. They never copy internal rows, provider payloads, secret references, management DTOs, or a generated OpenAPI document.

## Fixture rules

Fixtures are deterministic, minimal, synthetic, and valid under their declared schema. They contain no usable secret, real domain/account, live token, production Project/Application/user identifier, or private endpoint.

Secret/redaction cases use unmistakable non-production sentinels and assert those exact sentinels never appear in formatted output, errors, logs, traces, or snapshots. A fixture may represent a token-shaped value only when its schema marks it synthetic and tests prohibit accidental disclosure.

Each conformance case defines:

- a unique stable name and required capability;
- a canonical `operationId` and fixture/input reference;
- a precondition and request phase, including whether a response was received;
- an evidence level and configured Project/Application context where relevant;
- an expected semantic value or error category, code, retry policy, and local action;
- the expected pending-login or credential disposition when one-use state is involved.

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

### Package, unit, and conformance checks

CI runs package builds, static checks, language-specific unit/contract tests, generated OpenAPI checks, strict JSON attachment validation, and every required schema-version 3 shared case. Each runner fails closed on unsupported schema versions or malformed required data. Mock/fake transport tests validate failure paths and coordination but do not establish interoperability.

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
