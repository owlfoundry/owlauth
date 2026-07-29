# owlauth-server

The server library and `owlauth-server` executable for [OwlAuth](https://github.com/owlfoundry/owlauth), a self-hostable Project Auth and identity service.

OwlAuth's target architecture isolates users, provider/email identities, managed profile connections, SMTP, Application projections/webhooks, sessions, tokens, and signing keys by Project. Applications and end users use the Runtime Project Auth API plus its Hosted Authentication UI for upstream federation or passwordless email, while operators use the separately exposed Control API and embedded Management Console. OAuth/OIDC is used only to federate with upstream identity providers; provider credentials remain server-only for bounded profile sync and OwlAuth is not a general-purpose downstream OAuth/OIDC authorization server.

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

Database migration assets live in [`migrations/`](migrations/README.md) under accepted decision [`TS-001`](../../spec/technology/ts-001-postgresql-repositories-and-migrations.md). SeaORM 2 implements ordinary PostgreSQL repositories and SQLx 0.9 embeds startup migrations and compatibility verification.

Hosted-web ownership lives in [`web/`](web/README.md) under accepted decision [`TS-002`](../../spec/technology/ts-002-hosted-web-and-asset-pipeline.md). One private React 19/TypeScript/Vite 8 package in the repository pnpm workspace produces separate Runtime/Control OpenAPI clients, build manifests, and `rust-embed` roots; Node.js remains build-only.

The current scaffold has no persistence adapter, migration runner, hosted authentication UI, or Management Console. The tracked ownership directories do not imply those implementations exist.

## License

[BSD 3-Clause](LICENSE).
