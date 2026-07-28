# 02 — Domain and crate boundaries

## Dependency rule

Domain policy points inward; adapters point toward it. HTTP, storage, CLI, MCP, and SDK concerns MUST NOT become prerequisites for representing core authorization concepts. A Rust package boundary is introduced only when it provides real compile-time isolation, publication, or independent reuse; small server-only concepts remain internal modules.

## Package ownership

### `crates/owlauth-types`

Owns the stable public HTTP vocabulary: request/response DTOs, wire enums, endpoint metadata, OAuth error serialization, and OpenAPI derivation. It MUST NOT depend on the server, CLI, storage drivers, or Rust client SDK.

The current package defines a health response, three OAuth error-code variants, and generated OpenAPI metadata. Their existence does not imply complete OAuth behavior. Because these are public Rust types, compatibility changes follow the server release review and the package version follows `owlauth-server`.

### `crates/owlauth-server`

Owns the server library, `owlauth-server` process, and all server-only modules: domain/application policy, persistence ports and adapters, HTTP mapping, runtime configuration, dependency construction, listener lifecycle, migrations, telemetry, readiness, and shutdown.

Server-only modules preserve inward dependency direction even though they share one Cargo package. Domain/application modules MUST NOT import Axum, OpenAPI derivation, database rows, CLI parsing, MCP schemas, or SDKs. Persistence ports belong with the application policy that consumes them; concrete adapters point inward. HTTP and storage modules map explicitly rather than sharing rows or framework types with domain code.

The current package serves `/health` and emits OpenAPI JSON. Functional OAuth policy, storage adapters, migrations, and production lifecycle behavior remain unimplemented.

Versioned migration files live in `crates/owlauth-server/migrations/` and are intended to become embedded build inputs.

### `crates/owlauth-cli`

Owns the `owlauth` command, CLI parsing and presentation, updater behavior, stable machine output where introduced, diagnostics, confirmation, and exit-code mapping. It is a public client surface and MUST NOT depend directly or transitively on `owlauth-server`.

The current CLI implements only version reporting and checksum-verified update from component-specific GitHub Releases. Remote management commands are not implemented. Future remote workflows use documented public APIs, preferably through `owlauth-client`; local recovery behavior requires a separate security and locking design and does not justify linking the full server into the public CLI.

### `sdks/rust`

Owns the independent `owlauth-client` public Rust SDK. It MUST NOT depend on `owlauth-server`. Being written in Rust grants it no privileged interface. It MAY eventually share deliberately stable wire types, but must not consume server-internal modules.

## Product dependency graph

```text
owlauth-server ──> owlauth-types

owlauth-cli       (no server implementation dependency)
owlauth-client    (no server implementation dependency)
```

Allowed future edges include `owlauth-cli -> owlauth-client` and a deliberate `owlauth-client -> owlauth-types` only after compatibility and generated-contract ownership are reviewed.

Forbidden paths are enforced transitively:

```text
owlauth-cli    -X-> owlauth-server
owlauth-client -X-> owlauth-server
owlauth-server -X-> owlauth-cli
owlauth-server -X-> owlauth-client
owlauth-types  -X-> owlauth-server | owlauth-cli | owlauth-client
```

## Target request path

```text
untrusted transport
  -> server admission controls and authentication
  -> public DTO parsing and explicit mapping
  -> internal application use case and current policy decision
  -> internal persistence port/transaction
  -> public result/error mapping
  -> bounded, redacted response
```

The same internal use case MAY be invoked by multiple server-side adapters, but transport-specific authentication and output policy remain at each adapter boundary. A remote CLI call follows the same public server route as any other untrusted client.

## Domain modeling rules

Identifiers, redirect URIs, scope sets, timestamps, client authentication method, grant status, and token fingerprints SHOULD become validated internal types rather than interchangeable strings. State transitions MUST make invalid transitions difficult to represent. Raw token material SHOULD cross as few interfaces as possible and MUST be stored only according to a reviewed credential design.

Domain services consume a transaction or repository abstraction with explicit consistency semantics. A multi-record authorization decision MUST NOT silently span unrelated autocommit operations. Network calls MUST NOT execute while holding a database transaction unless a later specification explicitly justifies it.

## Error ownership

- Internal domain errors describe stable business meaning without HTTP status codes.
- Storage errors distinguish unavailable/conflict/not-found/corrupt classes without leaking SQL or records.
- Public protocol mapping chooses standards-compatible OAuth fields and HTTP status.
- Server middleware handles admission failures, request identifiers, and safe diagnostics.
- CLI and SDK errors map public behavior without exposing server implementation details.

Unknown internal failures become a generic public error and a correlated, redacted server event.

## Acceptance criteria

- Automated dependency checks prevent forbidden product edges.
- Internal domain tests run without network, filesystem, or production database access.
- Public route handlers delegate policy rather than implementing it ad hoc.
- Storage rows and public DTOs require explicit mapping.
- CLI and Rust SDK dependency closures contain no server implementation package.
- New Cargo packages document concrete isolation or publication value rather than mirroring every source module.
