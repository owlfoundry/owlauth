# owlauth-server

The server library and executable for [OwlAuth](https://github.com/owlfoundry/owlauth), a self-hostable authentication and identity service.

> **Beta:** `owlauth-server` is pre-1.0. APIs, configuration, and deployment requirements may change.

## Included

- PostgreSQL-backed Project, Application, user, identity, session, and token authority
- GitHub, Google, custom OIDC, email OTP, and magic-link authentication
- Hosted authentication pages and a management console
- Separate Runtime, Client, and Control listeners
- Project signing-key lifecycle and PostgreSQL protected-material custody
- User projections, signed webhooks, managed profiles, and background workers
- Embedded SQL migrations and deterministic hosted-web assets
- Optional read-only remote MCP tools for Control

OwlAuth uses OAuth/OIDC only for upstream identity federation. It is not a general-purpose downstream OAuth authorization server or provider-token broker.

## Run locally

From the repository root:

```bash
make install
cp .env.example .env
make dev
```

The default development URLs are:

- Hosted authentication: <http://127.0.0.1:8080/auth/>
- Management console: <http://127.0.0.1:8081/console/>
- Client API readiness: <http://127.0.0.1:8082/ready>

The fixed values in `.env.example` are public development credentials. Do not reuse them outside disposable local environments.

## Configuration and operations

OwlAuth rejects unknown `OWLAUTH_*` variables and validates the selected planes before binding listeners. Start with `.env.example`, then use the project documentation for production configuration and operations:

- [Getting started](../../docs/guide/getting-started.md)
- [Architecture and deployment](../../docs/guide/architecture.md)
- [Security](../../docs/guide/security.md)
- [CLI and agent integrations](../../docs/guide/agent-integrations.md)
- [Migration policy](migrations/README.md)

Detailed environment-variable behavior is documented by `.env.example` and the operator guides rather than duplicated here.

## Development

```bash
cargo test --workspace --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
make web-check
make web-build
```

Export the Runtime, Client, and Control OpenAPI documents with:

```bash
make openapi
```

## Package boundary

`owlauth-server` owns the executable and its internal domain, application, persistence, provider, HTTP, migrations, and hosted-web composition. Public HTTP DTOs and OpenAPI definitions live in `owlauth-types`. SDKs and the CLI do not depend on this crate.

The key-provider SPI is published separately as `owlauth-key-provider`.

## License

[BSD 3-Clause](LICENSE)
