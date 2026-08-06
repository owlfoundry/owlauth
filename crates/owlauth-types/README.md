# owlauth-types

Public HTTP DTO and OpenAPI authority for [OwlAuth](https://github.com/owlfoundry/owlauth).

> OwlAuth and these public contracts are Beta for the delivered self-hosted scope. Pre-1.0 DTOs and operations may change through reviewed releases; generated OpenAPI and exact-artifact SDK evidence do not establish a broad compatibility range or production support commitment.

The crate defines complete, separate OpenAPI 3.1 documents for the implemented Runtime, Client, and Control surfaces. Runtime includes health/readiness, public Project/Application configuration and JWKS, Hosted authentication transitions, handoff, session, user, refresh, logout, and identity flows. Client contains the Project-scoped customer-backend user reads and online token introspection contract. Control includes system inspection plus Project, Application, provider, key, SMTP, identity, user/session, projection, and webhook operations used by the server, Console, and CLI.

MCP protocol messages and hand-designed tool schemas follow the negotiated MCP protocol and are not OpenAPI DTOs generated into this crate.

This crate is the Rust authority for generated public documents and does not compile or depend on `owlauth-server`. It provides no HTTP server or client, domain entities, database rows, or authorization behavior.

Export both current documents from the repository root:

```bash
make openapi
```

Or export one document directly:

```bash
cargo run --package owlauth-types --bin export-openapi -- runtime target/openapi/runtime.json
cargo run --package owlauth-types --bin export-openapi -- client target/openapi/client.json
cargo run --package owlauth-types --bin export-openapi -- control target/openapi/control.json
```

Generated JSON documents are build artifacts and are not committed. Runtime and Control have derived hosted-web type files because those planes own browser surfaces; Client deliberately has none. The hosted files are committed and checked for clean regeneration. See the [HTTP contract specification](../../spec/05-http-contract-and-surface-boundaries.md) for the boundary.

## License

[BSD 3-Clause](LICENSE).
