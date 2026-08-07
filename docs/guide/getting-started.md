# Getting started

This guide helps contributors run and inspect the current Beta implementation. It is not a production deployment guide; use [Deployment](/guide/deployment) before operating a released artifact.

::: warning Current Beta capability
`owlauth-server` provides one Auth listener with isolated Runtime and Server API surfaces plus an independent Control listener over PostgreSQL, automatic or verification-only embedded migrations, OIDC and passwordless-email Project login, Hosted Authentication, PKCE handoff, Project JWT/session/refresh/logout behavior, managed provider connections and bounded profile synchronization, revisioned Application projections with signed durable webhooks, a Project-key backend Server API, provisioning/lifecycle Control APIs, an embedded Management Console, and an optional remote Control MCP endpoint. Three Beta SDKs consume the Runtime protocol; Server API is OpenAPI-only. Pre-1.0 interfaces and deployment requirements may change. Beta is not deployment certification or a production support commitment; operators own hardening, monitoring, upgrades, and tested backup/PITR/restore. SCIM, bulk directory/export, hosted multi-tenant control, and general downstream OAuth-provider behavior are outside the product.
:::

## Prerequisites

The repository's pinned development baseline is:

- stable Rust;
- Node.js 22.13 or later for repository tooling;
- pnpm 11.17.0;
- Python 3.11 through 3.14;
- `uv` 0.11.32;
- Docker Engine/Desktop with Compose v2 when running `make dev`, container-backed tests, or building the server image.

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

These targets cover formatting and linting, Rust/Python/TypeScript unit tests, package metadata, release and installer tooling, documentation, generated assets, and distribution contents. See the repository [`Makefile`](https://github.com/owlfoundry/owlauth/blob/main/Makefile) for the exact commands.

They do not run every CI runtime matrix or the long real PostgreSQL/provider/browser gate. Run `make web-e2e` separately for the local exact-artifact product topology. Neither local command set constitutes production certification for a deployment.

## Run the development topology

Copy the current local template and start Auth and Control with disposable PostgreSQL and Redis:

```bash
cp .env.example .env
make dev
```

Run `make dev-check` for a non-mutating preflight. It reports stale `.env` templates, missing tools,
or an unavailable Docker daemon before any service starts. `make dev` prints directly openable
Auth Hosted UI, Auth readiness, and Control Console URLs once both listeners are ready. Use
`make dev-status`, `make dev-logs`, and `make dev-down` to inspect or stop infrastructure;
`make dev-reset` deletes all local PostgreSQL and Redis data.

OwlAuth rejects unknown `OWLAUTH_*` variables and validates endpoint databases, listeners, key stores, Runtime protection, Server key-digest readiness, provider egress, admission, and Control credentials before binding. Auth and Control independently configure request timeout/body, in-flight requests, accepted connections, headers, and URI bounds; changing one endpoint does not resize the other. Runtime and Server API retain separate admission policies and PostgreSQL pools inside Auth. The old shared `OWLAUTH_REQUEST_TIMEOUT_MS` and `OWLAUTH_MAX_REQUEST_BYTES` names were removed during Beta and now fail as unknown variables. Set `OWLAUTH_AUTH_MAX_PROCESSES` to a conservative maximum Auth replica count rather than the current count. The complete HTTP budget variable table, Redis namespace/deadline settings, and a combined-listener example are maintained in the [`owlauth-server` README](https://github.com/owlfoundry/owlauth/tree/main/crates/owlauth-server#configuration-and-operations).

For the fastest executable proof of a correctly provisioned topology, run:

```bash
make web-e2e
```

The command requires a clean worktree so archive bytes can be bound honestly to `HEAD`. It generates current Runtime contract provenance, builds one TypeScript tarball, Python wheel, and Rust crate, creates digest-bound candidate descriptors, installs the exact candidates into external clean consumers, and then runs Chromium and Firefox. The gate creates isolated PostgreSQL state, starts real Auth and Control processes, provisions distinct Project Auth resources, uses a controlled OIDC provider through the production adapter, and exercises browser-direct, backend-custody, and all three SDK journeys against one server topology. `/health` is liveness only; use `/ready` for selected-plane readiness.

## Generate OpenAPI documents

Reviewed public Rust types in `crates/owlauth-types` generate complete, separate Runtime, Server API, and Control OpenAPI documents without compiling the server:

```bash
make openapi
```

The files are written to `target/openapi/runtime.json`, `target/openapi/server.json`, and `target/openapi/control.json`. Generated OpenAPI is ephemeral; the hosted-web package commits only its derived plane-pure TypeScript contract files.

## Build the container

Build and smoke-test the current server image:

```bash
make docker-build
```

The image runs as a non-root user with `tini` as PID 1 and is smoke-tested through `/health`, `/ready`, and a bounded graceful `SIGTERM` shutdown. Auth, Control, PostgreSQL, key stores, provider egress, TLS/reverse proxy, backup, and secret configuration remain deployment responsibilities. The [deployment guide](/guide/deployment) documents the image defaults, exact configuration boundaries, split topology, probes, upgrades, and recovery checklist.

Published images use `ghcr.io/owlfoundry/owlauth`:

- `dev` follows `main`;
- a `server-v{version}` release publishes the version and updates `latest`;
- a `build/server/{tag}` branch publishes an isolated `build-{tag}` image for smoke testing.

## Install the CLI

The published CLI supports descriptor-pinned self-hosted administration and checksum-verified self-update. It discovers and pins the endpoint product/instance before reading a credential; it does not infer a product from command failures or access OwlAuth storage directly.

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
owlauth profile add local --endpoint https://identity.example --yes
owlauth --profile local system
owlauth --profile local project list
owlauth --profile local application list PROJECT_ID
owlauth --profile local provider list PROJECT_ID
owlauth --profile local signing-key list PROJECT_ID
owlauth --profile local webhook endpoint list PROJECT_ID APPLICATION_ID
owlauth update --dry-run
owlauth update
```

CLI commands use the deployment operator credential and therefore carry full Control authority. Supply it only through an approved prompt, protected descriptor, OS credential store, or secret provider—not ordinary arguments, shell history, or agent context. Audit export remains deferred.

## Release identities

Components use independent SemVer and tags:

| Component                    | Package                                                   | Tag                     |
| ---------------------------- | --------------------------------------------------------- | ----------------------- |
| Server and dependency crates | `owlauth-key-provider`, `owlauth-types`, `owlauth-server` | `server-v{version}`     |
| CLI and exact public types   | `owlauth-types`, `owlauth-cli`                            | `cli-v{version}`        |
| TypeScript SDK               | `@owlauth/client`                                         | `typescript-v{version}` |
| Python SDK                   | `owlauth-client`                                          | `python-v{version}`     |
| Rust SDK                     | `owlauth-client`                                          | `rust-v{version}`       |

Tags point at the selected `main` commit; release workflows materialize component versions in isolated workspaces rather than requiring version-bump commits. Matching version numbers do not imply server/SDK compatibility.

## Follow the architecture

The architecture under [`spec/`](https://github.com/owlfoundry/owlauth/tree/main/spec) is normative behavior, not a command reference. Start with [Architecture](/guide/architecture), [Security](/guide/security), and [SDKs](/guide/sdks). Delivered Beta behavior and explicitly deferred capabilities are stated separately; implementation and exact-artifact evidence do not imply deployment certification or production support.
