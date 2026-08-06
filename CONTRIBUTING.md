# Contributing to OwlAuth

OwlAuth is in Beta for its delivered self-hosted product scope. Open an issue before making a substantial product, protocol, persistence, security-boundary, or package-boundary change. Pre-1.0 interfaces and operational requirements may change, but breaking changes still require explicit review, migration guidance, and release notes.

## Design authority

The repository separates target design from implemented behavior:

- [`spec/`](spec/README.md) defines the normative self-hosted server, Runtime, Client, Control, endpoint-discovered CLI, remote HTTP MCP, storage, security, and hosted-web architecture. [`spec/10-implementation-technology-selections.md`](spec/10-implementation-technology-selections.md) is the concise technology selection register; detailed canonical decision records live under [`spec/technology/`](spec/technology/README.md). Do not add a record for a mature reversible dependency unless it constrains multiple adapters or materially affects architecture or security.
- [`sdks/spec/`](sdks/spec/README.md) defines language-neutral SDK behavior, fixtures, and conformance requirements.
- [`docs/`](docs/index.md) is public user guidance and describes only implemented, released capabilities. It must not present target specifications as shipped behavior, and it must state Beta, pre-1.0, compatibility-evidence, and operator-owned deployment limitations truthfully.
- Rust definitions in [`crates/owlauth-types`](crates/owlauth-types/) are the source of generated public HTTP/OpenAPI contracts.

OwlAuth is Project-scoped authentication infrastructure, not a downstream general-purpose OAuth/OIDC authorization server. OAuth/OIDC integrations are upstream provider adapters.

Plan substantial changes as end-to-end capability slices rather than route or table micro-milestones. Keep behavioral authority and changed tracked boundaries in `spec/`; temporary execution notes belong under the gitignored `local-reference/` directory.

## Repository boundaries

- [`crates/owlauth-server`](crates/owlauth-server/) contains the publishable server library and the `owlauth-server` executable. Server-only domain, storage, and HTTP code remain internal. TS-003 permits only a narrow public provider-aware composition API rather than exposing repositories, routers, rows, or private application errors.
- [`crates/owlauth-types`](crates/owlauth-types/) contains the reviewed public HTTP DTO and OpenAPI authority. Server and CLI releases materialize it at their tag version and publish it before the dependent crate; those two tag families therefore share its crates.io version namespace.
- [`crates/owlauth-key-provider`](crates/owlauth-key-provider/) is the accepted independent public Rust SPI from TS-003. It follows the server version, is published before `owlauth-server`, and contains only bounded provider-neutral values, redacted errors, and role-specific Control provision/seal plus Runtime sign/open capabilities. It must not depend on server, database, HTTP, configuration, or vendor SDK types. The official repository and distribution bundle only the local PostgreSQL-envelope software provider, not any KMS/HSM implementation. Community and deployment providers live in independent crates and are statically composed into custom server binaries; no dynamic-library, directory-scanned, subprocess, or sidecar plugin mechanism exists in v1.
- [`crates/owlauth-cli`](crates/owlauth-cli/) contains one publishable `owlauth` executable for remote administration of a self-hosted deployment. Profiles store an endpoint; origin-root `GET /.well-known/owlauth` discovers and pins the OwlAuth server product, instance, authority, API base, and operator credential class before credential release. Discovery failure or identity change never triggers authenticated probing or fallback. The CLI must not depend on the server implementation, access databases, or bypass server Project checks.
- Database migration assets live under [`crates/owlauth-server/migrations`](crates/owlauth-server/migrations/); the detailed TS-001 selection lives under `spec/technology/`. The accepted stack uses SeaORM 2 for ordinary PostgreSQL repositories and SQLx 0.9 for embedded `auto` and DDL-free `verify` migrations; SeaORM schema sync is forbidden. No published server release contains the current consolidated initial schema. TS-003 deliberately freezes its current checksum as the pre-TS-003 source-deployment bridge baseline; do not edit it. Every later schema change uses an ordered additive migration. All current post-initial migrations are pre-alpha history and may be rewritten for the optimal final sequence before the first release; they provide no old-binary compatibility, and the first post-initial commit advances the floor. The server has the embedded migration runner, checksum-prefix verification with an explicit rolling-compatibility floor, independent serving pools, and private application-owned units of work. Deployment backup scheduling, restore orchestration, and production operations are documentation-only repository concerns. Document consistent PostgreSQL backup plus separately preserved software custody root or custom-provider authority and PostgreSQL backup/PITR/restore best practices; legacy encrypted-file migration is not a repository-owned runtime bridge. Do not add operator scripts, restore tooling, or repository-owned production validation. The server owns only verify-mode restart and fail-closed recovery semantics.
- [`crates/owlauth-server/web`](crates/owlauth-server/web/) is the tracked ownership root for the two embedded browser surfaces. The detailed TS-002 selection lives under `spec/technology/`, while [`spec/12-product-ui-and-interaction-design.md`](spec/12-product-ui-and-interaction-design.md) owns their information architecture, visual system, and interaction patterns. `owlauth-server` owns the Runtime Hosted Authentication UI and the Control Management Console. They retain separate internal listeners and routers. External URLs may use distinct origins, which is recommended, or explicitly configured disjoint non-root paths on one origin; the shared-origin form deliberately shares one browser/XSS trust boundary and path-contains Runtime cookies. The Console accepts the single `OWLAUTH_CONTROL_API_KEY`, keeps it only in active page memory, and uses the ordinary Control API. Accepted TS-002 uses one private React 19/TypeScript/Vite 8 package in the root pnpm workspace but requires independent plane entry graphs, outputs, manifests, generated clients, and `rust-embed` roots with no shared emitted chunks.
- Identity expansion behavior is canonical in [`spec/11-identity-connections-passwordless-email-and-user-sync.md`](spec/11-identity-connections-passwordless-email-and-user-sync.md): v1 renewable provider credentials are generation-fenced PostgreSQL AEAD ciphertext, server-only and least-scope for bounded profile sync, never a downstream token broker; generic login start snapshots allowed methods, Hosted UI selects one method once, and Project browser-session reuse is a separate explicit confirmation racing on the same transaction revision; email OTP and magic links use challenge/outbox-pinned Project or explicit-default SMTP generation and eligibility revisions, newest/one-use proofs, completion-time eligibility revalidation, and no silent email linking; first handoff creates the Application binding and materialized projection, while later policy expansion and `timestamp.event_id.raw_body` signed durable-outbox webhooks use Project-user `user_revision` plus per-binding `projection_revision`, with no retroactive created event and no v1 SCIM or bulk directory.
- [`sdks/`](sdks/) contains independently versioned TypeScript, Python, and Rust protocol clients. SDKs consume generated public contracts plus `sdks/spec/` fixtures and must not depend on server implementation crates. All three official SDKs follow the common language-neutral contract and conformance workflow after the Runtime Project Auth contract is stable. TypeScript publishes one `@owlauth/client` artifact whose Web-standard core is shared by its declared browser and Node.js matrices; the initial scope has no separate browser package or `/browser` entry point. Core SDKs own protocol safety, while Applications or separate integration libraries own navigation, history mutation, persistence, refresh coordination, and framework session state.
- OpenAPI is generated from Rust definitions in `crates/owlauth-types`; generated documents are not committed. Runtime, Client, and Control export as three separate complete documents without compiling `owlauth-server`. The hosted-web package commits only the Runtime and Control `openapi-typescript` type files, must never generate or import Client types, and enforces clean regeneration plus plane-pure imports. Official TypeScript, Python, and Rust SDKs consume only the secret-free Runtime Project Auth contract; OwlAuth publishes Client OpenAPI but no Client API SDK.
- The Rust client crate remains `owlauth-client`. [`plugins/owlauth`](plugins/owlauth/) distributes shared agent skills. The optional remote standards-conformant Streamable HTTP MCP capability belongs to self-hosted Control and uses the operator API key. CLI, plugins, installers, and agent packages must never bundle, launch, download, supervise, or impersonate a local MCP process.

## Documentation and product status

Present the delivered self-hosted server, CLI, hosted-web, and Project Auth SDK scope as Beta and pre-1.0. Beta is not a broad compatibility claim, deployment certification, or production support commitment. Operators own hardening, monitoring, upgrades, and tested PostgreSQL plus required external key/provider-authority backup, PITR, and restore. Public operational docs must describe shipped behavior and state the PostgreSQL custody, backup-authority, and custom-provider limitations precisely.

Format tracked Markdown with the pinned `mdformat` pre-commit hook using `--number`. Keep [`scripts/check-markdown-links.py`](scripts/check-markdown-links.py) as a separate relative-link integrity gate and retain the VitePress build and deployment checks.

## Primary tools

- **Rust:** Cargo on the stable toolchain selected by [`rust-toolchain.toml`](rust-toolchain.toml); use rustfmt and Clippy with warnings denied. Do not claim an MSRV that CI does not test.
- **Python:** Python 3.11-3.14 with the root [`pyproject.toml`](pyproject.toml) and [`uv.lock`](uv.lock) workspace, uv 0.11.32 for locking and environments, Hatchling 1.31.0 for builds, Ruff for lint and formatting, pytest for tests, and Twine for package verification and publication.
- **TypeScript and docs:** Node.js 22.13 or later for pnpm 11.17.0 repository tooling and the root workspace lockfile. The published TypeScript SDK runtime remains compatible with Node.js 20, 22, and 24. Use TypeScript for the SDK, VitePress for docs, and Wrangler for Cloudflare Workers deployment. Hosted web uses React 19, Vite 8, `openapi-typescript`/`openapi-fetch`, CSS Modules, Vitest/Testing Library, Playwright/axe, typed ESLint, and Prettier as selected by TS-002. Keep `npm publish` for npm trusted publishing.
- **Containers:** Docker builds the server image with `tini` as PID 1. Every image must verify the init process and pass the `/health` smoke test before publication to GitHub Container Registry.
- **Automation:** use readable official major tags for GitHub-owned Actions, such as `actions/checkout@v6`; do not replace them with commit hashes. Validate JSON metadata with `jq`. Plugin verification uses the current released Claude Code and Codex versions, pinned exactly after checking npm.

## Local checks

Install the locked development dependencies and use the aggregate targets when their scope is appropriate:

```bash
make install
make check
make test
make build
make package-check
```

Run `make help` for focused package, OpenAPI, hosted-web, container, installer, and documentation targets. Keep local verification proportional to the changed capability and its material risks. Run focused tests plus the relevant package or end-to-end gate; do not reproduce the entire CI matrix by default. Leave unaffected component matrices, release/package checks, plugin validation, documentation deployment, and container-image smoke tests to CI unless their boundary changed, a release is being prepared, CI is being diagnosed, or the user explicitly requests them.

When changing Markdown, run the pinned formatter and the separate link check. Run the VitePress build when public docs or their navigation changed:

```bash
uv run --locked pre-commit run mdformat --files AGENTS.md CONTRIBUTING.md
python3 scripts/check-markdown-links.py
pnpm --filter @owlauth/docs build
```

## Testing and CI

- Keep CI matrices aligned with declared runtime support. Python SDK CI covers 3.11, 3.12, 3.13, and 3.14; TypeScript SDK CI covers Node.js 20, 22, and 24 and, once browser support is claimed, runs the same `@owlauth/client` artifact in the declared browser matrix; Rust CI covers stable.
- CI and release workflows run package-content checks for every registry artifact, including the BSD license text.
- Enforce the Rust product dependency direction in CI: CLI must not reach server; server must not reach client SDK.
- Shared fixtures and conformance cases define cross-language behavioral parity.
- Once real Project Auth behavior exists, add server-backed end-to-end jobs that start OwlAuth and run all three SDK suites against the same instance. Do not add fake E2E tests before the Runtime flows exist.

## Pull request titles and changelog

Pull requests are squash-merged. Their titles are the structured source for component release notes and must use:

```text
<type>(<scope>[+<scope>...])[!]: <summary>
```

Examples:

```text
feat(server): add project handoff exchange
fix(cli): preserve the install directory during update
feat(server+cli): add project diagnostics
fix(typescript+python+rust): normalize handoff errors
feat(all)!: replace the project session response
chore(repo): update CI toolchains
```

Release scopes are `server`, `cli`, `typescript`, `python`, `rust`, and `all`. Internal-only scopes are `repo`, `docs`, `plugin`, and `deps-dev`. Use `+` only for a true cross-component change and `!` for a breaking change. The summary starts lowercase and does not end with a period.

Generated notes classify `security`, `feat`, `fix`, `perf`, `refactor`, `docs`, and `deps`. Internal `chore`, `ci`, `test`, and `style` changes are validated but omitted. Release-facing changes require an explicit component scope. Release workflows generate component-filtered notes before publication and must consume the uploaded notes artifact rather than GitHub-generated notes.

## Releases

Each released component follows independent SemVer. Release tags must point at the current `main` commit and use exactly one of:

- Server and public dependency crates (`owlauth-key-provider`, `owlauth-types`, and `owlauth-server`): `server-v{version}`
- CLI and its exact public types dependency (`owlauth-types` and `owlauth-cli`): `cli-v{version}`
- TypeScript SDK: `typescript-v{version}`
- Python SDK: `python-v{version}`
- Rust SDK: `rust-v{version}`

Committed package manifests, including private workspace packages, use development sentinels rather than the latest release number: Cargo and npm use `0.0.0-dev`, while Python uses the PEP 440 equivalent `0.0.0.dev0`. The tag is the only release-version authority: workflows derive the component and version from it and update every coupled manifest, exact dependency, and lockfile only in their isolated workspaces. Do not commit release-only version bumps.

A server release publishes `owlauth-key-provider`, `owlauth-types`, then `owlauth-server` at the server tag version. A CLI release publishes `owlauth-types` then `owlauth-cli` at the CLI tag version so the CLI crate retains an exact public-types dependency. Consequently, future server and CLI tags form one strictly increasing shared crate version sequence and must not reuse or move backward from any version in either family; release verification reserves that crates.io namespace before publication. The selected version must satisfy the strongest SemVer change among every crate emitted by that tag, including public `owlauth-types` changes. The SDK tag families remain independent. Python release tags currently use stable `X.Y.Z` only so PEP 440 normalization cannot make package metadata differ from the tag. Development sentinels must never be published. Do not reuse, move, or delete a published release tag.

Pushing a valid release tag runs the required checks, generates component-filtered notes, publishes that component, and creates a GitHub Release. Publication must consume the uploaded notes artifact rather than GitHub-generated notes.

Server images are published as `ghcr.io/owlfoundry/owlauth`. A server release publishes its versioned image and updates `latest`; SemVer `+` build-metadata separators are represented as `_` because OCI tags do not allow `+`. A push to `main` updates `dev`. A `build/server/{tag}` branch publishes the isolated test tag `build-{tag}` after image build and health smoke testing. The requested test tag must be one lowercase OCI tag segment; the `build-` registry prefix prevents collisions with release versions, `dev`, and `latest`.

CLI binaries are hosted on GitHub Releases with mandatory `SHA256SUMS`. [`scripts/install.sh`](scripts/install.sh), [`scripts/install.ps1`](scripts/install.ps1), and the built-in `owlauth update` command install only checksum-verified archives. The installers embedded in the CLI must remain byte-for-byte equal to the public scripts.
