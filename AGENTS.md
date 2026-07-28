# Project Guidelines

## Repository boundaries

- `crates/` contains the Rust server and its internal components.
- Database migration assets live under `crates/storage/migrations`. The required target is to embed and run them automatically before traffic; the current scaffold does not yet implement the migration runner.
- `sdks/` contains independently versioned TypeScript, Python, and Rust clients.
- OpenAPI is generated from Rust definitions in `crates/protocol`; generated documents are not committed.
- SDKs consume generated public contracts plus `sdks/spec/` fixtures; they must not depend on server-internal crates.
- The server binary/package is `owlauth`; the Rust client crate is `owlauth-client`.
- `plugins/owlauth` distributes shared agent skills. MCP remains a server-side capability; do not bundle a local MCP process until one exists.

## Release branches

- Server: `release/server/{version}`
- TypeScript SDK: `release/sdk/typescript/{version}`
- Python SDK: `release/sdk/python/{version}`
- Rust SDK: `release/sdk/rust/{version}`

Release branches must point at the current `main` commit. Each component follows independent SemVer.

Server images are published as `ghcr.io/owlfoundry/owlauth`. A server release publishes its version tag and updates `latest` (SemVer `+` build-metadata separators are represented as `_` because OCI tags do not allow `+`); a `main` push updates `dev`; a `build/server/{tag}` branch publishes the isolated test tag `build-{tag}`. The requested test tag must be one lowercase OCI tag segment; the `build-` registry prefix prevents collisions with release versions, `dev`, and `latest`.

## Primary tools

- Rust: Cargo on the stable toolchain selected by `rust-toolchain.toml`; use `rustfmt` and Clippy with warnings denied. Do not claim an MSRV that CI does not test.
- Python: Python 3.11-3.14 with the root `pyproject.toml`/`uv.lock` workspace, `uv` 0.11.32 for locking and environments, Hatchling 1.31.0 for builds, Ruff for lint/format, pytest for tests, and Twine for package verification/publication.
- TypeScript and docs: Node.js 22.13 or later for pnpm 11.17.0 repository tooling and the root workspace lockfile; the published TypeScript SDK runtime remains compatible with Node.js 20, 22, and 24. Use TypeScript for the SDK, VitePress for docs, and Wrangler for Cloudflare Workers deployment. Keep `npm publish` for npm trusted publishing.
- Containers: Docker builds the server image with `tini` as PID 1; every image must verify the init process and pass the `/health` smoke test before publication to GitHub Container Registry.
- Automation: GitHub Actions pinned to immutable commit SHAs; validate workflows with `actionlint` and JSON metadata with `jq`. Plugin verification uses the current released Claude Code and Codex versions, pinned exactly after checking npm.

## Testing

- Keep CI matrices aligned with declared runtime support. Python SDK CI covers 3.11, 3.12, 3.13, and 3.14; TypeScript SDK CI covers Node.js 20, 22, and 24; Rust CI covers stable.
- Run package-content checks for every registry artifact, including the BSD license text.
- Shared fixtures and conformance cases define cross-language behavioral parity.
- Once real OAuth behavior exists, add server-backed end-to-end jobs that start OwlAuth and run all three SDK suites against the same instance. Do not add fake E2E tests before the server and flows exist.
