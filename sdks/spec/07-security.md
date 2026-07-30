# 07 — SDK security

## Threat posture

SDKs run inside Applications that may log, crash, persist state, load plugins, follow redirects, or execute concurrently. They reduce common misuse but cannot secure a compromised Application, establish server-side Project membership, verify backend business authorization, or replace OwlAuth Runtime enforcement.

Current packages do not implement Project Auth and are not production authentication clients.

## Public identifiers versus credentials

`project_id`, `application_id`, and a publishable Application key are public configuration. SDKs may include them in reviewed Runtime requests and diagnostics, but must not describe them as secrets, user credentials, or Control authority.

Sensitive values include:

- PKCE verifiers and pending login state;
- handoff tickets and full Application callback URLs;
- Project access and refresh tokens;
- Runtime/browser session cookies;
- provider callback values returned through Runtime;
- management/provider credentials if accidentally supplied by a caller.

Provider client secrets and provider access/refresh tokens are not SDK inputs or outputs. If encountered, they are rejected/redacted rather than adopted.

## Sensitive-value handling

SDKs must:

- redact sensitive values from strings, debug/inspection, exceptions, logs, traces, metrics, snapshots, and telemetry;
- avoid URLs and command-line arguments for credentials except the protocol-defined short-lived front-channel handoff result;
- minimize copies/lifetime where the language permits without claiming guaranteed erasure in garbage-collected runtimes;
- exclude credentials from examples and fixtures;
- disable body/header logging by default;
- provide allowlist diagnostics instead of a “log everything” mode.

A Project JWT may be decoded only through an API that clearly distinguishes unverified display data from trusted backend validation.

## Project/Application isolation

Pending login, PKCE state, user/session credentials, refresh coordination, persistence records, and cached public configuration are bound to the exact Runtime origin, Project, and Application. SDKs reject attempts to load or use them under another context.

A public identifier in a response cannot change the active context. Cross-Project or cross-Application mismatch is a protocol/security failure and produces no credential migration or resource-existence disclosure.

The Rust SDK must not depend on `owlauth-server`, its internal modules, migrations, persistence adapters, or privileged Control implementation.

## Browser and native boundaries

Application redirects are untrusted input. The core SDK validates an explicitly supplied callback value against explicitly supplied pending state and local context before handoff exchange. The Application or external integration consumes its stored pending state once and removes handoff values from browser history or other platform-visible state before third-party resources can observe them; the core SDK does not read browser globals or mutate navigation/history.

Loopback listeners, custom schemes, universal/app links, browser or native storage, automatic navigation, and framework session bindings each require a platform-specific threat model and tests before support is claimed by the library that implements them. The core SDK does not prescribe `localStorage`, embed a confidential secret, or treat CORS as authentication.

Provider authorization URLs originate from Runtime login start and are used only for explicit navigation. They never become an SDK API base URL and never receive Project session credentials.

## PKCE, handoff, and refresh safety

PKCE verifier/state generation uses the operating-system CSPRNG and S256 only. Verifiers remain local until the single handoff exchange and are never reused.

Handoff tickets and refresh tokens are one-use server credentials. Timeout, cancellation, disconnect, or lost responses are ambiguous; the SDK does not replay automatically. Strict refresh-family reuse can revoke a concurrently issued successor, so the Application or external stateful integration serializes refresh per family and atomically replaces versioned credentials. The core SDK does not claim stateful coordination it does not own.

Availability fallbacks cannot weaken one-use, replay, Project/Application binding, or credential cleanup rules.

## Application-state boundary

The core SDK selects no memory, browser, filesystem, keychain, database, or other credential store. Pending-login and credential values are returned explicitly to the caller. An Application or external integration that retains them defines encryption, access control, concurrency, backup, retention, deletion, and recovery.

Persisted records carry schema version and exact Runtime/Project/Application identity. Updates atomically replace one access/refresh generation. Multi-process stores require compare-and-swap or leases that meet spec 04; optional browser or OS storage is not advertised as universally encrypted or safe.

Logout results distinguish confirmed Runtime revocation from an ambiguous outcome; the caller owns removal or quarantine of local material. Backup/crash/reporting tools are treated as disclosure paths.

## Transport and dependency security

TLS verification is mandatory by default. Redirects cannot leak credentials to another origin. Proxies, custom roots, loopback HTTP, and environment inheritance are explicit.

HTTP clients, generators, cryptographic packages, and transitive dependencies are pinned/locked per ecosystem, scanned for advisories, and updated through review. Generated code is supply-chain input: generator/version/configuration are pinned, output is reproducible, and contract provenance is recorded.

Publication uses least-privilege trusted publishing where available and repository-defined provenance. Every registry artifact includes the BSD license and excludes credentials, local paths, caches, temporary OpenAPI, and unrelated workspace contents.

## Security testing and disclosure

Tests seed recognizable synthetic secrets through success, failure, cancellation, concurrency, formatting, persistence, and telemetry paths, then assert no disclosure. Fuzz/property tests target URLs, callback/handoff inputs, malformed Runtime responses, Project/Application mismatches, unknown enums/errors, and token-shaped data.

Vulnerabilities follow [`SECURITY.md`](../../SECURITY.md). Public issues and SDK exceptions never solicit real credentials.

## Acceptance criteria

- Redaction tests pass in every language, including generated models and chained errors.
- Production defaults reject insecure URLs/TLS and cross-origin credential redirects.
- Stored/pending/session state cannot cross Runtime/Project/Application context.
- Handoff and refresh ambiguity never causes blind replay.
- Published artifacts trace source, dependencies, contract digest, and build job.
- The TypeScript core has no Node-only dependency in its browser closure and no implicit navigation, history, storage, or framework side effects.
- Platform-specific redirect/storage support is documented only by the separate Application integration or library that owns its security review and real tests.
