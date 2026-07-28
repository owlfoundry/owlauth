# Architecture

The repository contains a Rust server, a separate Rust CLI, public types, and three independently versioned clients.

- `crates/owlauth-server` is the publishable server library and `owlauth-server` process. Server-only domain, storage, HTTP, and composition code remains internal until a real independent boundary exists.
- `crates/owlauth-types` owns reviewed public HTTP DTOs and OpenAPI derivation. It follows the server version.
- `crates/owlauth-cli` produces the `owlauth` command. It uses public interfaces and cannot depend on server implementation code.
- `crates/owlauth-server/migrations` owns migration assets intended for future build-time embedding.
- `sdks/typescript`, `sdks/python`, and `sdks/rust` are public clients.
- `sdks/spec` contains shared fixtures and conformance cases.
- `plugins/owlauth` contains agent integration metadata and skills.

The Rust SDK receives no privileged path dependency on server internals. All SDKs consume the same generated public contract and must implement the same conformance behavior. Generated OpenAPI is an ephemeral build input and is not committed.

The architecture-first normative design is indexed in the server [`spec/`](https://github.com/owlfoundry/owlauth/tree/main/spec) and cross-language [`sdks/spec/`](https://github.com/owlfoundry/owlauth/tree/main/sdks/spec) directories. Those documents separate target contracts from the current pre-alpha implementation.

Migrations are designed to be embedded into the server and applied automatically before readiness. The current scaffold does not yet implement a database adapter or migration runner.

## CLI and MCP boundaries

The `owlauth` CLI currently exposes only release-backed self-update. Future remote operator commands must use documented public server interfaces; the CLI must not link server storage, domain, or composition internals. MCP remains a planned server-side interface rather than a local process bundled into each agent plugin.
