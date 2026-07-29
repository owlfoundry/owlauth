# Getting started

This guide helps contributors run and inspect the **current pre-alpha scaffold**. It is not a deployment guide for the target Project Auth architecture.

::: warning Current capability
Today, `owlauth-server` binds one address and serves only `GET /health`. It can also print its generated OpenAPI document. The `owlauth` CLI provides help, version output, and checksum-verified self-update. Project/Application management, provider login, PostgreSQL/Redis, token issuance, Runtime/Control listeners, automatic migrations, SDK auth flows, and MCP are not implemented.
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

`make install` fetches locked Rust dependencies and installs the locked Python and pnpm workspaces. It does not configure a Project or start an authentication service.

## Run repository checks

```bash
make check
make test
make build
make package-check
```

The targets cover formatting and linting, Rust/Python/TypeScript unit tests, package metadata, release and installer checks, documentation, artifacts, and distribution contents. See the repository [`Makefile`](https://github.com/owlfoundry/owlauth/blob/main/Makefile) for the exact commands.

Passing these checks validates the scaffold and packaging. It does not establish Project Auth interoperability or production readiness.

## Run the current server

```bash
cargo run --locked --package owlauth-server
```

The development binary listens on `127.0.0.1:8080` by default. Override the address with `OWLAUTH_ADDR`:

```bash
OWLAUTH_ADDR=127.0.0.1:9090 cargo run --locked --package owlauth-server
```

In another terminal:

```bash
curl --fail http://127.0.0.1:8080/health
# {"status":"ok"}
```

`/health` reports process health only. There are no Project, Application, provider, login, session, token, Control, or MCP routes to call yet.

## Generate the current OpenAPI document

Reviewed public Rust types in `crates/owlauth-types` generate OpenAPI on demand:

```bash
cargo run --locked --package owlauth-server -- --openapi \
  > /tmp/owlauth-openapi.json
```

The current document describes `/health` and the small scaffold type vocabulary. It does not describe the planned Runtime or Control surface. Generated OpenAPI is an ephemeral build input and must not be committed.

## Build the container

Build and smoke-test the current server image:

```bash
make docker-build
```

The image runs as a non-root user, exposes port `8080`, sets `OWLAUTH_ADDR=0.0.0.0:8080`, and checks `/health`. Those properties describe the scaffold image, not a production topology.

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

| Component | Package | Tag |
| --- | --- | --- |
| Server and public types | `owlauth-server`, `owlauth-types` | `server-v{version}` |
| CLI | `owlauth-cli` | `cli-v{version}` |
| TypeScript SDK | `@owlauth/client` | `typescript-v{version}` |
| Python SDK | `owlauth-client` | `python-v{version}` |
| Rust SDK | `owlauth-client` | `rust-v{version}` |

Tags point at the selected `main` commit; release workflows materialize component versions in isolated workspaces rather than requiring version-bump commits. Matching version numbers do not imply server/SDK compatibility.

## Follow the target design

The architecture under [`spec/`](https://github.com/owlfoundry/owlauth/tree/main/spec) is normative target design, not a command reference. Start with [Architecture](/guide/architecture) to understand the future Project Auth model and [Security](/guide/security) before implementing a surface.
