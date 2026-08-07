# 07 — SDK security

## Threat posture

SDKs run inside Applications that may log, crash, persist state, load plugins, follow redirects, or execute concurrently. They reduce common misuse but cannot secure a compromised Application, establish server-side Project membership, verify backend business authorization, or replace OwlAuth Runtime enforcement.

The current packages implement Beta Runtime Project Auth clients, but they are not production-supported authentication products. They do not own Application navigation, history cleanup, persistence, refresh coordination, framework sessions, or backend authorization, and their guarantees remain limited to the reviewed protocol behaviors and tested Runtime compatibility stated here.

## Public identifiers versus credentials

`project_id`, `application_id`, and a publishable Application key are public configuration. SDKs may include them in reviewed Runtime requests and diagnostics, but must not describe them as secrets, user credentials, or Server API/Control authority.

Sensitive values include:

- PKCE verifiers and pending login state;
- handoff tickets and full Application callback URLs;
- Project access and refresh tokens;
- Runtime/browser session cookies;
- provider callback values returned through Runtime;
- Project server keys and management/provider credentials if accidentally supplied by a caller.

Project server keys, provider client secrets, and provider access/refresh tokens are not SDK inputs or outputs. If encountered, they are rejected/redacted rather than adopted. Candidate qualification binds Python and Rust package code byte-for-byte to the reviewed checkout and binds every normalized TypeScript `dist` member to the tracked reviewed artifact-surface manifest; sampled secret/path markers remain defense in depth, not the purity authority. Any Server API operation—including differently formatted or concatenated paths—therefore changes reviewed code or a reviewed build digest before it can enter a final SDK artifact.

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

The Rust SDK must not depend on `owlauth-server`, its internal modules, migrations, persistence adapters, or privileged Server API/Control implementation.

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

## Qualification and evidence custody

Qualification treats package bytes and evidence as a custody chain, not as interchangeable workspace output:

1. build one component archive and one canonical candidate descriptor;
2. bind the archive SHA-256, package identity/version, source commit, workflow run/attempt, build configuration, Runtime contract digests, claimed operation IDs, and corpus digest;
3. verify archive and descriptor digests at every artifact handoff;
4. install the exact bytes in clean consumers outside the repository rather than importing workspace source;
5. run package matrices and same-server journeys against those consumers;
6. aggregate canonical final evidence only when every required fragment has the same source/run/contract/corpus coordinate and complete observed-operation set;
7. verify the final manifest against the candidate before publishing the same archive bytes.

Canonical parsing and closed field sets prevent an alternate descriptor or manifest shape from weakening the binding. No rebuild occurs after candidate qualification. Non-PR candidate archives, descriptors, and final manifests receive repository provenance attestations where the platform supports them.

Test authority remains compartmentalized. The parent harness alone receives the Control operator and provider credentials used to provision isolated resources; exact-candidate child environments are explicit allowlists that exclude both. The external TypeScript runner receives a browser-driver token for bounded test-only navigation, and each external runner receives a separate loopback fault-proxy token that can arm only three allowlisted post-response disconnects. Those narrow test controls are runner-process inputs, not SDK constructor/method inputs, and no authority token enters candidate metadata, browser snapshots, or final evidence. Each SDK receives a distinct Project/Application assignment and mutable credential family even though all three share one server process topology.

Evidence contains only archive/contract/corpus/source identities, bounded public Project/Application assignments, operation IDs, matrices, and pass status. It never contains tokens, callbacks, cookies, PKCE values, pending state, provider credentials, operator credentials, browser-driver/fault tokens, private keys, or user profiles.

Raw Hosted/provider helpers in the E2E harness exist only to drive user-agent protocol boundaries. They do not become SDK APIs. Likewise, a separate backend-custody product journey proves that product topology; it does not imply that a core SDK owns persistence, confidential credentials, JWT authorization, or framework sessions.

## Security testing and disclosure

Tests seed recognizable synthetic secrets through success, failure, cancellation, concurrency, formatting, persistence, and telemetry paths, then assert no disclosure. Fuzz/property tests target URLs, callback/handoff inputs, malformed Runtime responses, Project/Application mismatches, unknown enums/errors, and token-shaped data.

Vulnerabilities follow [`SECURITY.md`](../../SECURITY.md). Public issues and SDK exceptions never solicit real credentials.

## Acceptance criteria

- Redaction tests pass in every language, including generated models and chained errors.
- Production defaults reject insecure URLs/TLS and cross-origin credential redirects.
- Stored/pending/session state cannot cross Runtime/Project/Application context.
- Handoff and refresh ambiguity never causes blind replay.
- Candidate and final-evidence digests bind the exact archive to source, run/attempt, build configuration, contract/corpus digests, complete claimed/observed operations, and isolated same-server assignments; publication reuses those bytes without rebuilding.
- The TypeScript core has no Node-only dependency in its browser closure and no implicit navigation, history, storage, or framework side effects.
- Platform-specific redirect/storage support is documented only by the separate Application integration or library that owns its security review and real tests.
