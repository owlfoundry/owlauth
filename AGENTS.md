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

## Primary tools

- Rust: Cargo with the pinned toolchain in `rust-toolchain.toml`; use `rustfmt` and Clippy with warnings denied.
- Python: Python 3.11-3.14, `uv` 0.11.32 for locking and environments, Hatchling 1.31.0 for builds, Ruff for lint/format, pytest for tests, and Twine for package verification/publication.
- TypeScript and docs: Node.js 20 or later with npm lockfiles; TypeScript for the SDK, VitePress for docs, and Wrangler for Cloudflare Workers deployment.
- Automation: GitHub Actions pinned to immutable commit SHAs; validate workflows with `actionlint` and JSON metadata with `jq`.

## Testing

- Keep CI matrices aligned with declared runtime support. Python SDK CI covers 3.11 and 3.14; TypeScript SDK CI covers the oldest and current supported Node.js lines.
- Run package-content checks for every registry artifact, including the BSD license text.
- Shared fixtures and conformance cases define cross-language behavioral parity.
- Once real OAuth behavior exists, add server-backed end-to-end jobs that start OwlAuth and run all three SDK suites against the same instance. Do not add fake E2E tests before the server and flows exist.
