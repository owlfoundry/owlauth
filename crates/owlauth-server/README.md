# owlauth-server

The server library and `owlauth-server` executable for [OwlAuth](https://github.com/owlfoundry/owlauth), a self-hostable Project Auth and identity service.

OwlAuth's target architecture isolates users, linked identities, upstream provider configuration, sessions, tokens, and signing keys by Project. Applications use the Runtime Project Auth API, while operators use a separately exposed and authenticated Control API. OAuth/OIDC is used only to federate with upstream identity providers; OwlAuth is not a general-purpose downstream OAuth/OIDC authorization server.

> OwlAuth is pre-alpha. This crate currently serves only `GET /health` and can print a generated OpenAPI scaffold. Project login, storage, token issuance, Runtime/Control plane composition, and MCP are not implemented. The architecture in the repository [`spec/`](../../spec/README.md) defines target behavior, not current functionality.

## Current commands

Run the scaffold on `127.0.0.1:8080`:

```bash
cargo run --package owlauth-server
```

Set a different bind address with `OWLAUTH_ADDR`:

```bash
OWLAUTH_ADDR=127.0.0.1:9090 cargo run --package owlauth-server
```

Check its health endpoint:

```bash
curl http://127.0.0.1:8080/health
```

Generate the current OpenAPI document from `owlauth-types`:

```bash
cargo run --package owlauth-server -- --openapi
```

Generated OpenAPI documents are build artifacts and are not committed.

## Package boundary

`owlauth-server` owns the single future server artifact and its internal domain, application, persistence, provider, HTTP, MCP, and composition modules. Runtime and Control are logical planes over one shared core, not separate server packages. Public HTTP DTOs and OpenAPI definitions belong to `owlauth-types`; SDKs and the CLI must not depend on this server crate.

Database migration assets live in `migrations/`. The target server embeds and applies compatible pending migrations before readiness, but the current scaffold has no migration runner.

## License

[BSD 3-Clause](LICENSE).
