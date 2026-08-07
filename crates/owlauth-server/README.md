# owlauth-server

The server library and executable for [OwlAuth](https://github.com/owlfoundry/owlauth), a self-hostable authentication and identity service.

> **Beta:** `owlauth-server` is pre-1.0. APIs, configuration, and deployment requirements may change.

## Included

- PostgreSQL-backed Project, Application, user, identity, session, and token authority
- GitHub, Google, custom OIDC, email OTP, and magic-link authentication
- Hosted authentication pages and a management console
- One Auth listener with isolated Runtime and Server API routers, plus an independent Control listener
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
- Auth readiness: <http://127.0.0.1:8080/ready>

The fixed values in `.env.example` are public development credentials. Do not reuse them outside disposable local environments.

## Configuration and operations

OwlAuth rejects unknown `OWLAUTH_*` variables and validates the selected planes before binding listeners. Start with `.env.example`, then use the project documentation for production configuration and operations:

- [Getting started](../../docs/guide/getting-started.md)
- [Production deployment and operations](../../docs/guide/deployment.md)
- [Architecture](../../docs/guide/architecture.md)
- [Security](../../docs/guide/security.md)
- [CLI and agent integrations](../../docs/guide/agent-integrations.md)
- [Migration policy](migrations/README.md)

### Per-endpoint HTTP budgets

Each listener uses the seven variables below with `ENDPOINT` replaced by `AUTH` or `CONTROL`. They are independent from the separate Runtime, Server API, and Control PostgreSQL pool sizes and from `OWLAUTH_CONTROL_MCP_*` limits.

| Variable                                    | Auth default | Control default | Accepted range |
| ------------------------------------------- | -----------: | --------------: | -------------: |
| `OWLAUTH_<ENDPOINT>_REQUEST_TIMEOUT_MS`     |        10000 |           10000 |       10–60000 |
| `OWLAUTH_<ENDPOINT>_MAX_REQUEST_BYTES`      |      1048576 |         1048576 |     1–16777216 |
| `OWLAUTH_<ENDPOINT>_MAX_IN_FLIGHT_REQUESTS` |          256 |              64 |         1–4096 |
| `OWLAUTH_<ENDPOINT>_MAX_CONNECTIONS`        |          512 |             128 |         1–8192 |
| `OWLAUTH_<ENDPOINT>_MAX_HEADER_COUNT`       |          128 |             128 |          1–512 |
| `OWLAUTH_<ENDPOINT>_MAX_HEADER_BYTES`       |        65536 |           65536 |       1–262144 |
| `OWLAUTH_<ENDPOINT>_MAX_URI_BYTES`          |         8192 |            8192 |        1–65536 |

The Beta-era shared names `OWLAUTH_REQUEST_TIMEOUT_MS` and `OWLAUTH_MAX_REQUEST_BYTES` are removed, not aliases. Unknown `OWLAUTH_*` variables fail startup, so configure each enabled endpoint explicitly. Connection capacity is enforced for the complete accepted transport lifetime; body, deadline, in-flight request, and parsed request-shape bounds are endpoint-local. Runtime and Server API retain distinct authentication, admission, router state, PostgreSQL pools, and readiness inputs inside Auth. Header and URI checks occur after protocol parsing, so the ingress proxy or TLS terminator must also retain bounded parser settings.

Client-address admission uses only the direct transport peer. This release does not trust ambient `Forwarded` or `X-Forwarded-For` headers and exposes no trusted-forwarding mode. See `.env.example` for the complete local values and the [deployment guide](../../docs/guide/deployment.md) for production posture.

## Development

```bash
cargo test --workspace --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
make web-check
make web-build
```

Export the Runtime, Server API, and Control OpenAPI documents with:

```bash
make openapi
```

## Package boundary

`owlauth-server` owns the executable and its internal domain, application, persistence, provider, HTTP, migrations, and hosted-web composition. Public HTTP DTOs and OpenAPI definitions live in `owlauth-types`. SDKs and the CLI do not depend on this crate.

The key-provider SPI is published separately as `owlauth-key-provider`.

## License

[BSD 3-Clause](LICENSE)
