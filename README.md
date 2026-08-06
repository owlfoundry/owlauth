# OwlAuth

OwlAuth is a self-hostable authentication and identity service for applications. It provides hosted sign-in, upstream OIDC providers, passwordless email, sessions, tokens, user management, and SDKs from one deployment.

> **Beta:** OwlAuth is pre-1.0. APIs and deployment requirements may change.

## Features

- Isolated Projects with shared users across related Applications
- GitHub, Google, and custom OIDC sign-in
- Passwordless email with OTP and magic links
- Hosted authentication pages and a management console
- Project-scoped sessions, refresh tokens, JWTs, and signing-key rotation
- User disable/re-enable, identity linking, and managed profile synchronization
- Revisioned user projections and signed webhooks
- TypeScript, Python, and Rust SDKs
- Self-hosted PostgreSQL authority with optional Redis rate limiting

OwlAuth handles authentication. Your application remains responsible for product authorization such as organizations, memberships, roles, billing, and resource access.

## Quick start

Requirements: Rust, Node.js, Python, `uv`, `pnpm`, Docker, and Docker Compose.

```bash
make install
cp .env.example .env
make dev
```

The default development URLs are:

- Hosted authentication: <http://127.0.0.1:8080/auth/>
- Management console: <http://127.0.0.1:8081/console/>
- Client API readiness: <http://127.0.0.1:8082/ready>

The development Control key is the `OWLAUTH_CONTROL_API_KEY` value in `.env`. The example keys are public test values and must not be used outside disposable local environments.

Stop the server with `Ctrl-C`, then remove the development services with:

```bash
make dev-down
```

## Documentation

- [User and deployment documentation](https://owlauth-docs.owlfoundry.org)
- [Getting started](docs/guide/getting-started.md)
- [Architecture](docs/guide/architecture.md)
- [Security](docs/guide/security.md)
- [SDKs](docs/guide/sdks.md)
- [CLI and agent integrations](docs/guide/agent-integrations.md)
- [Building a SaaS with OwlAuth](docs/guide/building-saas.md)
- [Contributing](CONTRIBUTING.md)

Detailed design and protocol decisions live in [`spec/`](spec/README.md) and [`sdks/spec/`](sdks/spec/README.md).

## Development

Run the standard repository checks:

```bash
make check
make test
make build
```

Useful additional targets:

```bash
make web-e2e
make package-check
make test-containers
```

Container-backed Rust tests skip locally when Docker is unavailable; CI requires them.

## CLI

Unix-like systems:

```bash
curl -fsSL https://raw.githubusercontent.com/owlfoundry/owlauth/main/scripts/install.sh | sh
```

Windows PowerShell:

```powershell
irm https://raw.githubusercontent.com/owlfoundry/owlauth/main/scripts/install.ps1 | iex
```

See the [CLI guide](docs/guide/agent-integrations.md) for profiles, authentication, and update behavior.

## Packages

OwlAuth publishes the server and CLI as Rust crates, the server image at `ghcr.io/owlfoundry/owlauth`, and Runtime SDKs for TypeScript, Python, and Rust. See the [documentation](https://owlauth-docs.owlfoundry.org) for current package names and release details.

## License

[BSD 3-Clause](LICENSE)
