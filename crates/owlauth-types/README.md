# owlauth-types

Stable public HTTP response and OpenAPI types for [OwlAuth](https://github.com/owlfoundry/owlauth).

The crate currently defines complete, separate OpenAPI 3.1 documents for the implemented Runtime and Control surfaces:

- listener liveness and readiness responses;
- the Runtime Hosted Authentication UI shell routes;
- the authenticated Control system-information endpoint and Management Console shell routes.

Future Project Auth and management DTOs will be added here as their server behavior is implemented. MCP protocol messages and hand-designed tool schemas follow the negotiated MCP protocol and are not OpenAPI DTOs generated into this crate.

This crate is the Rust authority for generated public documents and does not compile or depend on `owlauth-server`. It provides no HTTP server or client, domain entities, database rows, or authorization behavior.

Export both current documents from the repository root:

```bash
make openapi
```

Or export one document directly:

```bash
cargo run --package owlauth-types --bin export-openapi -- runtime target/openapi/runtime.json
cargo run --package owlauth-types --bin export-openapi -- control target/openapi/control.json
```

Generated JSON documents are build artifacts and are not committed. The two derived hosted-web type files are committed and checked for clean regeneration. See the [HTTP contract specification](../../spec/05-http-contract-and-surface-boundaries.md) for the boundary.

## License

[BSD 3-Clause](LICENSE).
