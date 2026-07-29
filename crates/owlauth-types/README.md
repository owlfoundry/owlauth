# owlauth-types

Public HTTP request, response, error, and OpenAPI types for [OwlAuth](https://github.com/owlfoundry/owlauth).

The target contract separates:

- Runtime Project Auth DTOs for public configuration, upstream login initiation, handoff exchange, Project users, sessions, refresh, logout, and public verification keys;
- Control DTOs for Project, Application, provider, user, policy, key, management, and audit administration;
- minimal listener-specific health DTOs.

This crate is the Rust source of generated OpenAPI documents. It does not provide an HTTP server or client, contain domain entities or database rows, or grant authorization merely by exposing a type.

> OwlAuth is pre-alpha. The current crate contains the health response and a small legacy OAuth error-code subset used by the scaffold. It does not yet define the target Runtime and Control contracts.

Generate the current document through the server binary:

```bash
cargo run --package owlauth-server -- --openapi
```

Generated OpenAPI output is not committed. See the [HTTP contract specification](../../spec/05-http-contract-and-surface-boundaries.md) for the target boundary.

## License

[BSD 3-Clause](LICENSE).
