# Getting started

This guide helps contributors run and inspect the current pre-alpha implementation. It is not a production deployment guide.

::: warning Current capability
`owlauth-server` provides isolated Runtime and Control listeners over PostgreSQL, automatic or verification-only embedded migrations, strict OIDC Project login, Hosted Authentication, PKCE handoff, Project JWT/session/refresh/logout behavior, provisioning and lifecycle Control APIs, and an embedded Management Console. Three pre-alpha SDKs consume the Runtime protocol. Passwordless email, managed profile synchronization, projection webhooks, SCIM/bulk directory, and remote MCP are not implemented.
:::

## Prerequisites

The repository's pinned development baseline is:

- stable Rust;
- Node.js 22.13 or later for repository tooling;
- pnpm 11.17.0;
- Python 3.11 through 3.14;
- `uv` 0.11.32;
- Docker when building the server image.

The TypeScript SDK package itself supports Node.js 20 or later. Use the versions pinned by the repository lockfiles and package-manager metadata rather than installing ad hoc dependency versions.

## Clone and install dependencies

```bash
git clone https://github.com/owlfoundry/owlauth.git
cd owlauth
make install
```

`make install` fetches locked Rust dependencies and installs the locked Python and pnpm workspaces. It does not provision a Project or start OwlAuth.

## Run repository checks

```bash
make check
make test
make build
make package-check
```

The targets cover formatting and linting, Rust/Python/TypeScript unit tests, package metadata, release and installer checks, documentation, artifacts, and distribution contents. See the repository [`Makefile`](https://github.com/owlfoundry/owlauth/blob/main/Makefile) for the exact commands.

These checks include unit, conformance, package, generated-asset, real PostgreSQL/provider/browser, and product-topology evidence. They do not constitute production certification for a particular deployment.

## Run the development topology

Start the disposable development infrastructure:

```bash
make dev-up
```

OwlAuth rejects unknown `OWLAUTH_*` variables and validates selected-plane database, listener, key-store, Runtime protection, provider egress, admission, and Control credential configuration before binding. Runtime admission requires a stable admission-only digest key, uses optional Redis coordination, and gates every accepted request through a process-bounded local share; set `OWLAUTH_RUNTIME_MAX_PROCESSES` to a conservative deployment maximum rather than the current replica count. The complete variable reference, Redis namespace/deadline settings, and a combined-listener example are maintained in the [`owlauth-server` README](https://github.com/owlfoundry/owlauth/tree/main/crates/owlauth-server#configuration).

For the fastest executable proof of a correctly provisioned topology, run:

```bash
make web-e2e
```

That gate creates isolated PostgreSQL state, starts real Runtime and Control processes, provisions Project Auth resources, uses a controlled OIDC provider through the production adapter, and exercises browser-direct and backend-custody Application journeys. `/health` is liveness only; use `/ready` for selected-plane readiness.

## Generate OpenAPI documents

Reviewed public Rust types in `crates/owlauth-types` generate complete, separate Runtime and Control OpenAPI documents without compiling the server:

```bash
make openapi
```

The files are written to `target/openapi/runtime.json` and `target/openapi/control.json`. Generated OpenAPI is ephemeral; the hosted-web package commits only its derived plane-pure TypeScript contract files.

## Build the container

Build and smoke-test the current server image:

```bash
make docker-build
```

The image runs as a non-root user with `tini` as PID 1 and is smoke-tested through `/health`. Runtime, Control, PostgreSQL, key stores, provider egress, TLS/reverse proxy, backup, and secret configuration remain deployment responsibilities.

Published images use `ghcr.io/owlfoundry/owlauth`:

- `dev` follows `main`;
- a `server-v{version}` release publishes the version and updates `latest`;
- a `build/server/{tag}` branch publishes an isolated `build-{tag}` image for smoke testing.

## Install the CLI

The published CLI currently supports release-backed self-update, not Project administration.

### Unix-like systems

```bash
curl -fsSL https://raw.githubusercontent.com/owlfoundry/owlauth/main/scripts/install.sh | sh
```

### Windows PowerShell

```powershell
irm https://raw.githubusercontent.com/owlfoundry/owlauth/main/scripts/install.ps1 | iex
```

Both installers download a native archive from a `cli-v{version}` GitHub Release and require a matching `SHA256SUMS` entry. The default install directory is `$HOME/.local/bin`; set `OWLAUTH_INSTALL_DIR` to override it and `OWLAUTH_VERSION` to select a version.

```bash
owlauth --version
owlauth update --dry-run
owlauth update
```

Do not expect `project`, `application`, `provider`, `user`, or other Control commands. Those commands require an implemented, authenticated Control API and are intentionally absent.

## Release identities

Components use independent SemVer and tags:

| Component               | Package                           | Tag                     |
| ----------------------- | --------------------------------- | ----------------------- |
| Server and public types | `owlauth-server`, `owlauth-types` | `server-v{version}`     |
| CLI                     | `owlauth-cli`                     | `cli-v{version}`        |
| TypeScript SDK          | `@owlauth/client`                 | `typescript-v{version}` |
| Python SDK              | `owlauth-client`                  | `python-v{version}`     |
| Rust SDK                | `owlauth-client`                  | `rust-v{version}`       |

Tags point at the selected `main` commit; release workflows materialize component versions in isolated workspaces rather than requiring version-bump commits. Matching version numbers do not imply server/SDK compatibility.

## Follow the architecture

The architecture under [`spec/`](https://github.com/owlfoundry/owlauth/tree/main/spec) is normative behavior, not a command reference. Start with [Architecture](/guide/architecture), [Security](/guide/security), and [SDKs](/guide/sdks). Explicitly deferred capabilities remain documented rather than implied by the implemented pre-alpha surface.
