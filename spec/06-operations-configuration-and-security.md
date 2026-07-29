# 06 — Process composition, Project keys, and operational security

## Composition modes

One `owlauth-server` artifact supports:

| Mode | Runtime listener | Control listener | Shared core | PostgreSQL schema |
| --- | --- | --- | --- | --- |
| `all` | enabled | enabled | one in-process instance | shared |
| `runtime` | enabled | absent | Runtime capabilities only | shared |
| `control` | absent | enabled | Control capabilities only | shared |

Mode changes adapter composition, exposure, dependency readiness, and database role; it does not change Project/domain semantics.

## Process lifecycle

```mermaid
flowchart TD
    Config[Parse and validate typed configuration] --> Telemetry[Initialize redacted telemetry]
    Telemetry --> Secrets[Resolve secret, signer, and data-protection handles]
    Secrets --> PG[Connect PostgreSQL serving role]
    PG --> Schema[Apply or verify embedded schema using isolated migration capability]
    Schema --> Redis[Connect Redis and select safe degradation policy]
    Redis --> Core[Compose shared core and selected adapters]
    Core --> Bind[Bind selected listeners]
    Bind --> Ready[Evaluate readiness per listener]

    Stop[Shutdown signal] --> Unready[Mark selected listeners unready]
    Unready --> Admission[Stop new business admission]
    Admission --> Drain[Drain bounded in-flight work]
    Drain --> Close[Close adapters and telemetry]
```

No business route reports ready before schema compatibility and plane-critical dependencies. Migration credentials are absent from serving pools and released before listeners bind. Shutdown has a fixed drain bound and preserves transaction semantics.

## Typed configuration

Configuration has one precedence model, rejects unknown fields, and separates global, Runtime, Control, PostgreSQL serving/migration, Redis, secret-store, signer, data-protection, and telemetry sections.

### Global fields

- immutable deployment external Runtime/Control origins;
- Project issuer derivation rule;
- environment/instance namespace;
- selected plane mode;
- protocol lifetime/clock-skew bounds;
- trusted secret/key-provider configuration.

Project/provider/Application policy is authoritative PostgreSQL state, not replicated process configuration.

### Runtime listener fields

- bind address, external origin, TLS/trusted-proxy mode;
- limits, deadlines, concurrency, Project/Application rate policy;
- cookie security and Project namespace behavior;
- public configuration and JWKS cache bounds;
- exact CORS enforcement mode.

### Control listener fields

- distinct bind address/origin;
- TLS and optional mTLS roots;
- accepted management credential classes and Control audience;
- stricter session, step-up, request, and rate policy;
- deny-by-default CORS and private-network assumptions.

### Infrastructure fields

- PostgreSQL serving DSN/secret reference, pool bounds, role, and timeouts;
- optional separate PostgreSQL migration credential reference used only during schema preparation;
- Redis endpoint/TLS/credential reference, namespace, bounds, and deadlines;
- signer provider, Project key namespace, allowed algorithms, and opaque references;
- data-protection provider and retained key versions;
- provider endpoint allowlists and Project secret-store adapter.

Issuer, callback, and redirect decisions never derive from arbitrary `Host`, `Forwarded`, or `X-Forwarded-*`. Proxy headers are honored only from configured trusted proxies.

Secrets enter through protected environment/file descriptors, files, or secret managers. They are not ordinary command-line values, serialized config output, public config, health, panic text, telemetry, or OpenAPI examples.

## Network and resource posture

Runtime and Control require TLS directly or through a declared trusted proxy. Control SHOULD bind privately; network isolation supplements application authentication.

Each listener applies connection/header/body/URI bounds, trusted client-address derivation, correlation, plane rate/concurrency controls, authentication where applicable, and safe response headers before expensive work.

Runtime and Control use separate PostgreSQL pools or quotas. Control list/audit work cannot exhaust capacity reserved for callback, handoff, and refresh transactions. Provider, Redis, signer, and Project-specific expensive operations have independent bounds and circuit state.

CORS is deny-by-default and exact Application-origin based. Provider callbacks and browser redirects are navigation endpoints, not permissive cross-origin APIs.

## Key and secret ownership

| Component | May access | Must not access |
| --- | --- | --- |
| Control | Project key metadata/public JWK, lifecycle command, provider secret reference | exportable private key or provider secret bytes in DTOs |
| Runtime | active Project signer reference, Project verification set, provider secret handle, signing/provider operation | arbitrary Project lifecycle mutation or raw private key bytes |
| PostgreSQL | public JWK, opaque signer/provider references, revisions, lifecycle/provisioning state | private key, provider secret, wrapping key bytes |
| Redis | public Project config/JWKS cache with revision | key/provider authority, secret material, activation locks |
| Signer/KMS | Project-namespaced private material and operation authorization | user/Application policy or routing |
| Secret store | Project provider secret material by opaque reference | Project user/session data |
| Data protector | login-state encryption/decryption material | token signing authority or Project policy |

KMS identities are least-privilege separated: Control provisioning identity creates/manages Project keys; Runtime identity can sign only with authorized active Project key references. Software keys use a dedicated envelope-encrypted store with external wrapping keys.

Transaction data protection uses versioned AEAD keys. Ciphertext authenticated context binds deployment, Project, transaction, and field purpose. Older versions remain decryptable through maximum transaction lifetime plus clock skew, or affected transactions are cancelled before readiness after recovery.

## Project signing-key provisioning

KMS creation/import is an external side effect with durable idempotency:

```mermaid
sequenceDiagram
    actor Operator
    participant Control
    participant PG as PostgreSQL
    participant KMS

    Operator->>Control: Provision Project key + Control idempotency key
    Control->>PG: Insert/lock pending provisioning operation
    PG-->>Control: stable provider operation alias
    Control->>KMS: Create/import using stable Project alias/idempotency identifier
    KMS-->>Control: key reference + public JWK or existing result
    Control->>PG: Finalize key as Published; append state/audit events
    PG-->>Control: committed Project key metadata
```

A retry resolves the same provisioning operation and provider alias. A pending operation can reconcile by querying the stable provider operation reference. Confirmed orphan material is disabled/deleted only through a provider-specific safe cleanup transition; retry never creates an untracked replacement silently.

## Signing-key lifecycle

```mermaid
stateDiagram-v2
    [*] --> Provisioning: durable operation created
    Provisioning --> Published: KMS result and public JWK committed
    Published --> Active: publication condition satisfied
    Active --> Retiring: eligible replacement activated
    Retiring --> Retired: verification retention elapsed
    Provisioning --> Abandoned: reconciled failure
    Published --> Revoked: compromised or abandoned
    Active --> Revoked: emergency compromise
    Retiring --> Revoked: emergency compromise
    Retired --> [*]
    Revoked --> [*]
    Abandoned --> [*]
```

- **Provisioning:** durable idempotent operation exists; no JWKS/signing use.
- **Published:** public JWK is in Project JWKS; key cannot sign.
- **Active:** Runtime can sign for this Project/purpose; exactly one per key ring.
- **Retiring:** no new issuance; public JWK remains until retention cutoff.
- **Retired:** absent from ordinary JWKS and unable to sign; metadata remains for audit/recovery.
- **Revoked:** emergency terminal state with immediate signing denial and token-verification consequences below.

## JWKS publication proof and activation

Each ready Runtime process loads the current Project key-ring revision before serving that Project's JWKS/signing path and writes a short PostgreSQL publication lease containing instance identity, loaded revision, the time that revision was first loaded, and lease expiry. Lease renewal extends expiry without resetting the revision-loaded time. Load balancers route only ready Runtime processes; a new/returning process cannot serve signing/JWKS while stale.

Activation requires all of:

1. key state is `Published` and `published_at` is committed;
2. every non-expired ready Runtime publication lease for the Project key ring has `loaded_revision` at or above the published revision;
3. the propagation interval starts at the latest qualifying revision-loaded time among required Runtime leases, not merely `published_at`, and then spans the maximum Runtime key-cache TTL, externally advertised JWKS cache TTL, and propagation margin;
4. activation holds the exclusive signing-epoch guard and follows one of two atomic branches: initial activation changes the sole eligible `Published` key to `Active` when no active key exists; normal rotation changes the old `Active` key to `Retiring` while the eligible `Published` key becomes `Active`.

If there is no current ready Runtime publication lease, activation fails closed. Redis/local invalidation cannot prove publication.

```mermaid
sequenceDiagram
    participant Control
    participant PG as PostgreSQL
    participant Runtime
    participant Verifier as Application backend/JWKS cache
    participant KMS

    Control->>PG: Commit Project key as Published + key-ring revision
    Runtime->>PG: Load Project public key set
    Runtime-->>Verifier: Serve old + new Project JWKS
    Runtime->>PG: Record loaded revision publication lease
    Verifier-->>Verifier: Cache window elapses
    Control->>PG: Verify leases + duration from latest observation; initial-activate or rotate under epoch guard
    Runtime->>PG: Acquire shared active signing epoch
    Runtime->>KMS: Sign with new Project key
```

Normal retirement sets `verify_not_after` at transition using the maximum Project access-token lifetime, clock skew, JWKS cache retention, and propagation margin. Concurrent issuance uses shared epoch guards; lifecycle transitions use the conflicting exclusive guard, avoiding a per-token hot-row update while preventing issuance after the cutoff.

## Emergency key revocation

Compromise revocation differs from normal retirement:

- Control atomically marks the key `Revoked`, advances only the Project key-ring/signing epoch, removes it from active signing/JWKS publication, and appends audit/state events. Project security/session revisions advance only when incident scope deliberately includes broader Project or session compromise.
- Runtime immediately rejects signing and its own current-user verification for the revoked `kid` after authoritative revision observation.
- All Project access tokens signed by that `kid` are considered invalid. Offline Application backends may continue accepting a cached key until their bounded JWKS cache refresh; OwlAuth cannot promise instantaneous offline revocation.
- Refresh tokens and opaque sessions are not signed by the compromised key and are not automatically revoked unless incident scope includes broader server/session compromise. They cannot mint a new access token without another eligible active key.
- Runtime token issuance continues only when a previously Published key has already satisfied activation conditions and is activated atomically. Otherwise affected Project issuance is unready/fail-closed while public revocation state propagates.
- Project deployments requiring immediate verifier response use an explicitly designed online status check; Redis invalidation is not sufficient.

## Health and readiness

Liveness answers whether the process event loop responds and does not query every dependency.

Runtime readiness requires compatible PostgreSQL state, resolvable Project key/data-protection capabilities for served Projects, and a safe response to Redis availability. Project-specific provider/KMS failures can close only affected capabilities/Projects without exposing detail globally. Control readiness requires PostgreSQL and management-authentication verification; key/provider mutations can return scoped dependency failure.

In `all`, listeners have independent readiness. Control loss does not force Runtime unready when Runtime authority remains usable. Health exposes no versions, Project names/counts, `belongs_to`, DSNs, Redis keys, provider names, key/secret references, migration SQL, or user/Application existence.

## Observability and audit

Structured telemetry contains time, level, stable event name, plane, operation, outcome class, correlation, and bounded latency. Project/Application IDs appear only in controlled fields where operationally required; `belongs_to`, user/provider subjects, URLs, and arbitrary errors are not metric labels.

Redaction occurs before serialization/export. Authorization headers, cookies, protocol query values, bodies, provider codes/tokens, tickets, access/refresh tokens, PKCE, user profiles, provider secrets, management credentials, and private keys are denied fields.

Security audit events append through the shared core and follow spec 04 transaction rules. Control audit queries are scope/Project constrained and cannot recover data that was never recorded.

## Retry and backpressure

Every network call has a deadline shorter than the caller's remaining deadline. Retries are bounded/jittered and occur only for classified transient failures. Non-idempotent external effects require a durable idempotency operation as used by key provisioning.

PostgreSQL/Redis pools, provider exchanges, KMS operations, and per-listener/Project concurrency are bounded independently. Backpressure rejects before unbounded queues form. Detailed dependency outcomes are defined by spec 08.
