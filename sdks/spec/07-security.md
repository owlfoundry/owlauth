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

Application redirects are untrusted input. The SDK validates pending state and local context before handoff exchange, consumes local pending state once, and removes handoff values from browser history before third-party resources load where platform integration permits.

Loopback listeners, custom schemes, universal/app links, browser storage, and automatic navigation each require a platform-specific threat model and tests before support is claimed. The general SDK does not prescribe `localStorage`, embed a confidential secret, or treat CORS as authentication.

Provider authorization URLs originate from Runtime login start and are used only for explicit navigation. They never become an SDK API base URL and never receive Project session credentials.

## PKCE, handoff, and refresh safety

PKCE verifier/state generation uses the operating-system CSPRNG and S256 only. Verifiers remain local until the single handoff exchange and are never reused.

Handoff tickets and refresh tokens are one-use server credentials. Timeout, cancellation, disconnect, or lost responses are ambiguous; the SDK does not replay automatically. Strict refresh-family reuse can revoke a concurrently issued successor, so SDKs serialize in-process rotation and require atomic versioned storage for cross-process use.

Availability fallbacks cannot weaken one-use, replay, Project/Application binding, or credential cleanup rules.

## Credential-store boundary

Default state is memory-only unless documented otherwise. An Application-supplied store defines encryption, access control, concurrency, backup, retention, and deletion.

Stored records carry schema version and exact Runtime/Project/Application identity. Updates atomically replace one access/refresh generation. Multi-process stores require compare-and-swap or leases that meet spec 04; optional OS storage is not advertised as universally encrypted or safe.

Logout/local clear APIs distinguish removing local material from confirmed Runtime revocation. Backup/crash/reporting tools are treated as disclosure paths.

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
- Platform-specific redirect/storage support is undocumented until its own security review and real tests pass.
