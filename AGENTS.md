# Project Guidelines

## Repository boundaries

- `crates/owlauth-server` contains the publishable server library and the `owlauth-server` executable. Server-only domain, storage, HTTP, and composition code remain internal modules until a real independent boundary justifies another package.
- `crates/owlauth-types` contains stable public HTTP DTOs and OpenAPI definitions. It follows the server version and is published before `owlauth-server` during a server release.
- `crates/owlauth-cli` contains one publishable `owlauth` executable for self-hosted and SaaS administration. Profiles store an endpoint but no user-configured product type; origin-root `GET /.well-known/owlauth` discovers and pins product, instance, authority, API base, and credential class before credential release and selects isolated typed clients. Discovery failure/identity change never triggers authenticated probing or fallback. The CLI must not depend on either service implementation, access databases, or bypass server Project checks or SaaS tenant authorization.
- Database migration assets live under `crates/owlauth-server/migrations`; detailed selection `TS-001` lives under `spec/technology/`. The accepted stack uses SeaORM 2 for ordinary PostgreSQL repositories and SQLx 0.9 for embedded `auto`/DDL-free `verify` migrations; SeaORM schema sync is forbidden. The server now has the embedded migration runner, exact history verification, independent serving pools, and an initial private Project Unit of Work; broader domain repositories remain incremental internal implementation. Deployment backup scheduling, restore orchestration, and production operations are outside this repository; documentation identifies the consistent PostgreSQL/external-store/key backup set and PostgreSQL backup/PITR/restore best practices, while the server owns verify-mode restart and fail-closed recovery semantics.
- `crates/owlauth-server/web` is the tracked ownership root for the two embedded browser surfaces; detailed selection `TS-002` lives under `spec/technology/`. `owlauth-server` owns the Runtime Hosted Authentication UI and the Control Management Console. They retain separate internal listeners/routers. External URLs may use distinct origins (recommended) or explicitly configured disjoint non-root paths on one origin; the shared-origin form deliberately shares one browser/XSS trust boundary and path-contains Runtime cookies. The Console accepts the single `OWLAUTH_CONTROL_API_KEY`, keeps it only in active page memory, and uses the ordinary Control API. Accepted TS-002 uses one private React 19/TypeScript/Vite 8 package in the root pnpm workspace but requires independent plane entry graphs, outputs, manifests, generated clients, and `rust-embed` roots with no shared emitted chunks.
- Identity expansion behavior is canonical in `spec/11-identity-connections-passwordless-email-and-user-sync.md`: v1 renewable provider credentials are generation-fenced PostgreSQL AEAD ciphertext, server-only and least-scope for bounded profile sync, never a downstream token broker; generic login start snapshots allowed methods, Hosted UI selects one method once, and Project browser-session reuse is a separate explicit confirmation racing on the same transaction revision; email OTP/magic links use challenge/outbox-pinned Project or explicit-default SMTP generation+eligibility revisions, newest/one-use proofs, completion-time eligibility revalidation, and no silent email linking; first handoff creates the Application binding/materialized projection, while later policy expansion and `timestamp.event_id.raw_body` signed durable-outbox webhooks use Project-user `user_revision` plus per-binding `projection_revision`, with no retroactive created event and no v1 SCIM/bulk directory. `spec/implementation-plan.md` is execution guidance, not behavioral authority.
- Execute the remaining server plan as the substantial end-to-end delivery blocks defined in `spec/implementation-plan.md`, not as route/table micro-milestones. Before starting each block, create or refresh its English detailed execution plan under gitignored `local-reference/`; keep behavioral authority and changed tracked boundaries in `spec/`.
- `spec/saas/` defines a separate multi-tenant SaaS control layer over ordinary OwlAuth deployments. Organization membership, tenant RBAC, customer API keys, billing, entitlements, and cell orchestration remain outside `owlauth-server`; tenants never receive a deployment operator key. The shared CLI dispatches to SaaS only after endpoint discovery, and SaaS exposes its own remote HTTP MCP endpoint authenticated only by SaaS API key.
- `sdks/` contains independently versioned TypeScript, Python, and Rust protocol clients. SDKs consume generated public contracts plus `sdks/spec/` fixtures; they must not depend on server implementation crates. Server delivery through Block D does not depend on SDK design or parity; Block E selects the common language-neutral contract/conformance workflow, converges all three existing clients, and completes SDK documentation after the server contract is stable. TypeScript publishes one `@owlauth/client` artifact whose Web-standard core is shared by its declared browser and Node.js matrices; the initial scope has no separate browser package or `/browser` entry point. Core SDKs own protocol safety, while Applications or separate integration libraries own navigation, history mutation, persistence, refresh coordination, and framework session state.
- `spec/10-implementation-technology-selections.md` is the concise selection register; detailed canonical decision records live under `spec/technology/`. Do not add a record for a mature reversible dependency unless it constrains multiple adapters or materially affects architecture/security.
- OpenAPI is generated from Rust definitions in `crates/owlauth-types`; generated documents are not committed. Runtime and Control export as separate complete documents without compiling `owlauth-server`. The hosted-web package commits only the two derived `openapi-typescript` type files and enforces clean regeneration plus plane-pure imports.
- The Rust client crate remains `owlauth-client`. `plugins/owlauth` distributes shared agent skills. Self-hosted and SaaS MCP are separate remote standards-conformant Streamable HTTP server capabilities using operator and SaaS API keys respectively. CLI, plugins, installers, and agent packages must never bundle, launch, download, supervise, or impersonate a local MCP process.

## Release tags

- Server and public types: `server-v{version}`
- CLI: `cli-v{version}`
- TypeScript SDK: `typescript-v{version}`
- Python SDK: `python-v{version}`
- Rust SDK: `rust-v{version}`

Release tags must point at the current `main` commit. Each component follows independent SemVer; `owlauth-types` follows the server version. The tag is the release version authority: workflows derive the component and version from it and update manifests and lockfiles only in their isolated workspaces. Do not commit release-only version bumps. Python release tags currently use stable `X.Y.Z` only so PEP 440 normalization cannot make package metadata differ from the tag.

Server images are published as `ghcr.io/owlfoundry/owlauth`. A server release publishes its versioned image and updates `latest` (SemVer `+` build-metadata separators are represented as `_` because OCI tags do not allow `+`); a `main` push updates `dev`; a `build/server/{tag}` branch publishes the isolated test tag `build-{tag}`. The requested test tag must be one lowercase OCI tag segment; the `build-` registry prefix prevents collisions with release versions, `dev`, and `latest`.

CLI binaries are hosted on GitHub Releases with mandatory `SHA256SUMS`. `scripts/install.sh`, `scripts/install.ps1`, and the built-in `owlauth update` command install only checksum-verified archives. The installers embedded in the CLI must remain byte-for-byte equal to the public scripts.

## Changelog convention

Squash PR titles are the structured changelog source and use:

```text
<type>(<scope>[+<scope>...])[!]: <summary>
```

Release scopes are `server`, `cli`, `typescript`, `python`, `rust`, and `all`. Internal scopes are `repo`, `docs`, `plugin`, and `deps-dev`. Use `+` for a true cross-component change and `!` for a breaking change. Release workflows generate component-filtered notes before publication and must consume the uploaded notes artifact rather than GitHub-generated notes.

## Primary tools

- Rust: Cargo on the stable toolchain selected by `rust-toolchain.toml`; use `rustfmt` and Clippy with warnings denied. Do not claim an MSRV that CI does not test.
- Python: Python 3.11-3.14 with the root `pyproject.toml`/`uv.lock` workspace, `uv` 0.11.32 for locking and environments, Hatchling 1.31.0 for builds, Ruff for lint/format, pytest for tests, and Twine for package verification/publication.
- TypeScript and docs: Node.js 22.13 or later for pnpm 11.17.0 repository tooling and the root workspace lockfile; the published TypeScript SDK runtime remains compatible with Node.js 20, 22, and 24. Use TypeScript for the SDK, VitePress for docs, and Wrangler for Cloudflare Workers deployment. Hosted web uses React 19, Vite 8, `openapi-typescript`/`openapi-fetch`, CSS Modules, Vitest/Testing Library, Playwright/axe, typed ESLint, and Prettier as selected by TS-002. Keep `npm publish` for npm trusted publishing.
- Containers: Docker builds the server image with `tini` as PID 1; every image must verify the init process and pass the `/health` smoke test before publication to GitHub Container Registry.
- Automation: use readable official major tags for GitHub-owned Actions, such as `actions/checkout@v6`; do not replace them with commit hashes. Validate JSON metadata with `jq`. Plugin verification uses the current released Claude Code and Codex versions, pinned exactly after checking npm.

## Testing

- Keep local verification proportional to the changed capability and its material risks. Run focused tests plus the relevant package or end-to-end gate; do not reproduce the entire CI matrix by default. Leave unaffected component matrices, release/package checks, plugin validation, documentation deployment, and container-image smoke tests to CI unless their boundary changed, a release is being prepared, CI is being diagnosed, or the user explicitly requests them.
- Keep CI matrices aligned with declared runtime support. Python SDK CI covers 3.11, 3.12, 3.13, and 3.14; TypeScript SDK CI covers Node.js 20, 22, and 24 and, once browser support is claimed, runs the same `@owlauth/client` artifact in the declared browser matrix; Rust CI covers stable.
- CI and release workflows run package-content checks for every registry artifact, including the BSD license text.
- Enforce the Rust product dependency direction in CI: CLI must not reach server; server must not reach client SDK.
- Shared fixtures and conformance cases define cross-language behavioral parity.
- Once real Project Auth behavior exists, add server-backed end-to-end jobs that start OwlAuth and run all three SDK suites against the same instance. Do not add fake E2E tests before the Runtime flows exist.
