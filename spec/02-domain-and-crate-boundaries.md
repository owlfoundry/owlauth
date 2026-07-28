# 02 — Domain and crate boundaries

## Dependency rule

Domain policy points inward; adapters point toward it. HTTP, storage, CLI, MCP, and generated SDK concerns MUST NOT become prerequisites for representing core authorization concepts.

## Crate ownership

### `crates/domain`

Owns validated identities, value objects, authorization policy, grant/token lifecycle rules, and use-case-facing domain errors. Domain code MUST NOT depend on Axum or another web framework, SQL/database rows, OpenAPI annotations, CLI parsing, MCP schemas, or public SDKs.

The current crate owns only `UserId`; clients, grants, sessions, consent, scopes, token records, and policy services are not implemented.

### `crates/protocol`

Owns the public HTTP vocabulary: request/response DTOs, wire enums, endpoint metadata, OAuth error serialization, and OpenAPI derivation. It translates between wire values and domain commands/results. Protocol DTOs are not persistence records and MUST NOT contain secret-bearing debug output.

The current crate defines a health response, three OAuth error-code variants, and generated OpenAPI metadata. Their existence does not imply HTTP serving or complete OAuth error coverage.

### `crates/storage`

Owns persistence ports/adapters, database transactions, schema definitions, query mapping, and migration execution. It depends on domain types where useful but MUST NOT own authorization policy or public HTTP shapes. Versioned migration files live in `crates/storage/migrations/` and become embedded build inputs.

The current crate exposes only `UserStore::contains`; there is no database adapter or migration runner yet.

### `crates/server`

Is the composition root and executable. It owns runtime configuration loading, dependency construction, listener lifecycle, routing/adapters, middleware, migration invocation, telemetry wiring, readiness, and shutdown. It MAY depend on all internal crates but SHOULD contain minimal domain logic.

The current binary serves a documented health endpoint or emits OpenAPI JSON. OAuth routes, storage composition, migrations, and production lifecycle behavior remain unimplemented.

## Target request path

```text
untrusted transport
  -> server admission controls and authentication
  -> protocol parsing/validation and DTO mapping
  -> domain use case and current policy decision
  -> storage port/transaction
  -> protocol result/error mapping
  -> bounded, redacted response
```

The same domain use case MAY be invoked by multiple adapters, but transport-specific authentication and output policy remain at the adapter boundary.

## Dependency and visibility constraints

- `domain` MUST NOT import `protocol`, `storage`, or `server`.
- `protocol` MAY import domain concepts for checked conversion but MUST NOT call persistence directly.
- `storage` MAY import domain concepts but MUST NOT import `protocol` or `server`.
- `server` composes implementations and MUST NOT expose internal Rust types as a public wire contract accidentally.
- `sdks/rust` MUST NOT depend on any server workspace crate; being written in Rust grants it no privileged interface.
- Types shared merely for code reuse are not automatically stable. Only documented wire behavior is public.

## Domain modeling rules

Identifiers, redirect URIs, scope sets, timestamps, client authentication method, grant status, and token fingerprints SHOULD become validated types rather than interchangeable strings. State transitions MUST make invalid transitions difficult to represent. Raw token material SHOULD cross as few interfaces as possible and MUST be stored only according to a reviewed credential design.

Domain services consume a transaction or repository abstraction with explicit consistency semantics. A multi-record authorization decision MUST NOT silently span unrelated autocommit operations. Network calls MUST NOT execute while holding a database transaction unless a later specification explicitly justifies it.

## Error ownership

- Domain errors describe stable business meaning without HTTP status codes.
- Storage errors distinguish unavailable/conflict/not-found/corrupt classes without leaking SQL or records.
- Protocol mapping chooses standards-compatible OAuth fields and HTTP status.
- Server middleware handles admission failures, request identifiers, and safe diagnostics.

Unknown internal failures become a generic public error and a correlated, redacted server event.

## Acceptance criteria

- Automated dependency checks prevent forbidden crate edges.
- Domain tests run without network, filesystem, or production database access.
- Public route handlers delegate policy rather than implementing it ad hoc.
- Storage rows and protocol DTOs require explicit mapping.
- The Rust SDK has no internal server dependency.
