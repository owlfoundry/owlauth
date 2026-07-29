# 02 — Shared core, Project domain, and package boundaries

## Dependency rule

Dependencies point inward. Runtime HTTP, Control HTTP, PostgreSQL, Redis, KMS, upstream providers, CLI, MCP, and SDKs are adapters around Project-scoped application and domain policy.

```mermaid
flowchart TB
    RHTTP[Runtime HTTP adapter] --> APP[Application services]
    CHTTP[Control HTTP adapter] --> APP
    MCP[MCP Control adapter] --> APP
    APP --> DOMAIN[Project-scoped domain model]
    APP --> PORTS[Application-owned ports]
    PG[PostgreSQL adapter] --> PORTS
    RC[Redis adapter] --> PORTS
    SIGN[Signer and data-protector adapters] --> PORTS
    UP[Upstream provider adapters] --> PORTS
    CLOCK[Clock and entropy adapters] --> PORTS
```

Domain and application modules MUST NOT import HTTP framework types, OpenAPI types, SQL rows, database drivers, Redis clients, provider SDK payloads, CLI parsing, MCP schemas, or client SDK code. Adapter mappings are explicit.

## Package ownership

### `crates/owlauth-server`

This is the single server package. It owns:

- the `owlauth-server` executable and `all`, `runtime`, and `control` composition roots;
- internal Project/Application/identity/login/session/token/key domain modules;
- application services and Project-bound authorization policy;
- persistence, cache, upstream-provider, signer, data-protection, clock, entropy, and audit ports;
- PostgreSQL and Redis adapters and embedded migrations;
- Runtime HTTP, Control HTTP, MCP, telemetry, health, and process-lifecycle adapters.

Server-only concepts remain internal modules. Logical plane separation does not create separate Cargo packages or duplicated service layers.

### `crates/owlauth-types`

This package owns stable public HTTP DTOs, wire enums, error serialization, endpoint metadata, and OpenAPI derivation. It separates Runtime Project Auth contracts from Control administrative contracts. It does not own domain entities, Project authorization, persistence rows, or provider payloads.

`owlauth-types` MUST NOT depend on the server, CLI, storage drivers, or client SDKs.

### `crates/owlauth-cli`

This package owns the `owlauth` remote Control client experience: argument parsing, safe credential input, confirmation, machine output, and public Control API calls. It MUST NOT link server composition, open PostgreSQL/Redis, invoke domain repositories, load Project keys, or act as a local Control Plane.

The CLI uses a deliberately isolated Control client module. Default Runtime SDK surfaces do not gain administrative operations merely because the CLI and SDK share a transport implementation.

### `sdks/*`

SDKs consume public Runtime Project Auth contracts and language-neutral behavior. They initialize with public `project_id`, `application_id`, and publishable configuration; these values identify the Project/Application but never authorize Control operations.

SDKs have no privileged knowledge of rows or domain types. The Rust SDK receives no additional authority from sharing the implementation language. A Control client, if distributed, remains an explicitly separate module/feature and contract.

## Product dependency graph

```mermaid
flowchart LR
    SERVER[owlauth-server] --> TYPES[owlauth-types]
    SDK[Runtime SDKs] -. Runtime DTO vocabulary .-> TYPES
    CLI[owlauth-cli] --> CCLIENT[Isolated Control client module]
    CCLIENT -. Control DTO vocabulary .-> TYPES

    CLI ~~~ NO1["must not depend on owlauth-server"]
    SDK ~~~ NO2["must not depend on owlauth-server"]
```

Forbidden dependencies apply transitively:

- `owlauth-cli -> owlauth-server`;
- any client SDK or Control client `-> owlauth-server`;
- `owlauth-server -> owlauth-cli | client SDK`;
- `owlauth-types -> owlauth-server | owlauth-cli | client SDK`.

## Project-bound application services

| Service | Representative commands and queries | Plane access |
| --- | --- | --- |
| `ProjectApplicationService` | create/disable Project, read/update metadata, set `belongs_to` | Control |
| `ApplicationConfigurationService` | register/disable Application, manage origins, redirects, publishable key revisions | Control; Runtime reads authoritative state |
| `ProviderConfigurationService` | configure per-Project provider client registrations/secrets and assign them to Applications | Control; Runtime uses active assigned configuration |
| `LoginApplicationService` | begin login, validate provider callback, complete one-use handoff | Runtime |
| `IdentityApplicationService` | resolve/create Project user, link/unlink provider identity, disable/merge user | Runtime and Control with command-specific authorization |
| `SessionApplicationService` | create/validate Project browser session, issue Application session, terminate session | Runtime; Control can revoke through administrative commands |
| `TokenApplicationService` | issue Project access token, rotate refresh family, revoke family | Runtime |
| `ProjectPolicyService` | manage token claims, lifetimes, provider/app admission, and session policy | Control writes; Runtime evaluates |
| `KeyLifecycleService` | provision, publish, activate, retire, and revoke Project signing keys | Control commands; Runtime signs and publishes Project JWKS |
| `ManagementAccessService` | authenticate management principal and authorize Control scope | Control adapters |
| `AuditApplicationService` | append Project/deployment security events and query authorized views | both append; Control queries |

Every Project-bound service method receives a validated `ProjectId` established by the adapter and revalidated against authoritative state. A payload field cannot override the route/actor Project context.

## Domain aggregates and invariants

| Aggregate | Owned invariants |
| --- | --- |
| Project | status, public identifier, token namespace, optional `belongs_to`, revision, isolation boundary |
| Application | Project ownership, type, status, public app identifier, allowed origins, exact post-login redirects |
| Provider configuration | Project ownership, provider issuer/kind, client ID, opaque secret reference, callback identity, revision |
| Project user and linked identities | Project ownership, stable user ID, unique Project/provider issuer/subject, explicit link/merge proof, disabled behavior |
| Login transaction and handoff | Project/Application/browser/provider/redirect/PKCE binding, expiry, one-use completion and exchange |
| Project browser session | Project/user/browser binding, rotation, expiry, and termination; reusable across Applications in one Project |
| Application session and refresh family | Project/Application/user binding, one current generation, strict replay-family revocation |
| Project signing-key ring | Project issuer/purpose, unique `kid`, publish-before-sign lifecycle, verification overlap |
| Management principal | deployment-wide credential class and management scopes; no implicit Project tenancy |
| Audit event | immutable actor/action/Project/target/outcome/correlation semantics without recoverable secrets |

Aggregate boundaries define transaction scope where one aggregate can enforce the rule alone. Cross-aggregate commands use an application-owned unit of work and PostgreSQL constraints; adapters cannot approximate them with unrelated writes.

## Project isolation rule

Every Project-owned table has `project_id` directly or reaches it through a constraint that PostgreSQL can verify. Security-critical queries include Project qualification even when object IDs are globally unique. Composite foreign keys or equivalent constraints prevent a child row from referencing a parent in another Project.

A Runtime request resolves Project and Application before provider, user, session, ticket, or token lookup. A Control request authorizes its management scope and then invokes a Project-bound command. `belongs_to` does not replace either step.

Project disablement cannot transfer child resources to another Project. A disabled Project rejects new login, handoff, refresh, current-user, and signing operations while preserving identifiers and durable state for audit and controlled recovery. The Control model exposes no hard-delete transition for Projects, Applications, providers, or users.

## Ports

Application-owned ports expose semantics rather than vendor APIs:

- `UnitOfWork` and repositories with Project qualification, isolation, conditional mutation, and conflict classification;
- `Signer` and `VerificationKeyDirectory` keyed by Project/key-ring purpose and opaque key references;
- `DataProtector` for integrity-bound encryption of recoverable login state;
- `UpstreamProviderClient` with bounded authorization URL, code exchange, issuer/subject validation, and profile retrieval;
- `Cache` for disposable values and `RateLimiter` for coordinated admission control;
- `Clock` and `EntropySource`;
- `AuditSink` only for events not required in the same PostgreSQL transaction;
- telemetry interfaces accepting redacted, bounded-cardinality fields.

Redis locks, PostgreSQL advisory locks, or process mutexes MUST NOT leak through domain ports as generic correctness primitives. A port describes the atomic business operation that must be preserved.

## Request path

```mermaid
sequenceDiagram
    participant Caller
    participant Adapter as Plane adapter
    participant App as Application service
    participant Domain
    participant Tx as Unit of work
    participant Infra as PostgreSQL / signer / provider

    Caller->>Adapter: untrusted request
    Adapter->>Adapter: bounds + transport authentication + Project/Application resolution
    Adapter->>App: typed command + verified actor/Project context
    App->>Domain: validate policy and state transition
    App->>Tx: execute Project-qualified state change
    Tx->>Infra: constrained operations
    Infra-->>Tx: typed result
    Tx-->>App: committed outcome
    App-->>Adapter: domain result or stable error
    Adapter-->>Caller: surface-specific response
```

## Error ownership

- Domain errors express stable Project/authentication meaning without transport or vendor codes.
- Persistence errors distinguish conflict, not found, unavailable, serialization retry, and integrity failure without exposing SQL or cross-Project existence.
- Provider errors distinguish unavailable, rejected callback, invalid claims, and configuration failure without returning provider tokens.
- Cache failures are explicitly degradable or fail-closed according to spec 08.
- Runtime maps errors to the Project Auth API contract and avoids Project/user enumeration.
- Control maps errors to authenticated administrative problem details.
- CLI, SDK, and MCP map only public errors.
- Unknown failures produce a generic external response and a correlated redacted internal event.
