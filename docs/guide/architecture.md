# Architecture

The repository contains one Rust service and three independently versioned clients.

- `crates/server` is the `owlauth` control-plane binary.
- `crates/domain`, `crates/storage`, and `crates/protocol` are internal server boundaries. Storage owns embedded migrations under `crates/storage/migrations/`.
- `sdks/typescript`, `sdks/python`, and `sdks/rust` are public clients.
- `sdks/spec` contains shared fixtures and conformance cases.
- `plugins/owlauth` contains agent integration metadata and skills.

The Rust SDK receives no privileged path dependency on server internals. All SDKs consume the same generated public contract and must implement the same conformance behavior. The generated OpenAPI document is an ephemeral build input and is not committed.

The architecture-first normative design is indexed in the server [`spec/`](https://github.com/owlfoundry/owlauth/tree/main/spec) and cross-language [`sdks/spec/`](https://github.com/owlfoundry/owlauth/tree/main/sdks/spec) directories. Those documents clearly separate the target contract from the current pre-alpha implementation.

Migrations are designed to be embedded into the server and applied automatically before readiness. The current scaffold does not yet implement a database adapter or migration runner.

## Planned command and MCP boundaries

A future CLI may be delivered as its own Rust crate and executable. MCP is planned as a server-side interface rather than a local process bundled into each agent plugin. These interfaces are not part of the current `0.0.1` scaffold.
