# Project Guidelines

## Repository boundaries

- `crates/owlauth-server` contains the publishable server library and the `owlauth-server` executable. Server-only domain, storage, HTTP, and composition code remain internal modules until a real independent boundary justifies another package.
- `crates/owlauth-types` contains stable public HTTP DTOs and OpenAPI definitions. It follows the server version and is published before `owlauth-server` during a server release.
- `crates/owlauth-cli` contains the publishable CLI package and the `owlauth` executable. It must not depend on `owlauth-server` or bypass server-side authorization.
- Database migration assets live under `crates/owlauth-server/migrations`. The required target is to embed and run them automatically before traffic; the current scaffold does not yet implement the migration runner.
- `sdks/` contains independently versioned TypeScript, Python, and Rust clients. SDKs consume generated public contracts plus `sdks/spec/` fixtures; they must not depend on server implementation crates.
- OpenAPI is generated from Rust definitions in `crates/owlauth-types`; generated documents are not committed.
- The Rust client crate remains `owlauth-client`. `plugins/owlauth` distributes shared agent skills. MCP remains a server-side capability; do not bundle a local MCP process until one exists.

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
- TypeScript and docs: Node.js 22.13 or later for pnpm 11.17.0 repository tooling and the root workspace lockfile; the published TypeScript SDK runtime remains compatible with Node.js 20, 22, and 24. Use TypeScript for the SDK, VitePress for docs, and Wrangler for Cloudflare Workers deployment. Keep `npm publish` for npm trusted publishing.
- Containers: Docker builds the server image with `tini` as PID 1; every image must verify the init process and pass the `/health` smoke test before publication to GitHub Container Registry.
- Automation: use readable official major tags for GitHub-owned Actions, such as `actions/checkout@v6`; do not replace them with commit hashes. Validate workflows with `actionlint` and JSON metadata with `jq`. Plugin verification uses the current released Claude Code and Codex versions, pinned exactly after checking npm.

## Testing

- Keep CI matrices aligned with declared runtime support. Python SDK CI covers 3.11, 3.12, 3.13, and 3.14; TypeScript SDK CI covers Node.js 20, 22, and 24; Rust CI covers stable.
- Run package-content checks for every registry artifact, including the BSD license text.
- Enforce the Rust product dependency direction in CI: CLI must not reach server; server must not reach client SDK.
- Shared fixtures and conformance cases define cross-language behavioral parity.
- Once real Project Auth behavior exists, add server-backed end-to-end jobs that start OwlAuth and run all three SDK suites against the same instance. Do not add fake E2E tests before the Runtime flows exist.

## AnyCap

This project uses [AnyCap](https://anycap.ai) for multimodal capabilities -- image generation, video generation, music, image/video/audio understanding, web search, web crawling, file storage, and static site hosting. When a task requires any of these, prefer AnyCap over other approaches.

AnyCap evolves rapidly. Your knowledge of commands, models, and options may be outdated. Always update and read the anycap-cli skill before using AnyCap:

```bash
npx -y skills update         # update skills to latest version
anycap status                # verify auth and connectivity
```

When something goes wrong or you need a capability that seems missing, submit feedback directly -- this is how the AnyCap team prioritizes fixes and new features:

```bash
anycap feedback --type bug -m "describe the issue" --request-id <id>
anycap feedback --type feature -m "describe the use case"
```
