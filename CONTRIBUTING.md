# Contributing to OwlAuth

OwlAuth is in its initial design and scaffold phase. Open an issue before making a substantial product, protocol, persistence, or package-boundary change.

## Design authority

The repository separates target design from implemented behavior:

- [`spec/`](spec/README.md) defines the normative server, Runtime, Control, CLI, and MCP architecture.
- [`sdks/spec/`](sdks/spec/README.md) defines language-neutral SDK behavior and conformance requirements.
- [`docs/`](docs/index.md) provides user-facing guidance and must state pre-alpha limitations truthfully.
- Rust definitions in `crates/owlauth-types` are the source of generated public HTTP/OpenAPI contracts.

Do not document target behavior as currently available. OwlAuth is Project-scoped authentication infrastructure, not a downstream general-purpose OAuth/OIDC authorization server. OAuth/OIDC integrations are upstream provider adapters.

## Repository boundaries

- Server-only domain, storage, HTTP, and composition code stays inside `crates/owlauth-server` until a real independent package boundary exists.
- `crates/owlauth-types` contains public DTOs and OpenAPI definitions, not domain entities or persistence rows.
- `crates/owlauth-cli` is a remote Control client and must not depend on `owlauth-server` or bypass server-side authorization.
- TypeScript, Python, and Rust SDKs consume public Runtime contracts plus shared fixtures; none may depend on server implementation crates.
- Generated OpenAPI documents and release-only version bumps are not committed.

## Local checks

```bash
make install
make check
make test
make build
make package-check
```

GitHub Actions additionally runs the declared compatibility matrix: Rust stable, Python 3.11-3.14, and Node.js 20, 22, and 24. Repository tooling requires Node.js 22.13 or later because dependencies are installed from the root pnpm 11.17.0 lockfile; the published TypeScript SDK remains runtime-tested on Node.js 20, 22, and 24. Python development dependencies use the root uv 0.11.32 workspace and lockfile.

Run `make help` for focused package, OpenAPI, container, installer, and documentation targets. When changing Markdown links or VitePress content, also run:

```bash
pnpm --dir docs build
```

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

Release scopes are `server`, `cli`, `typescript`, `python`, `rust`, and `all`. Internal-only scopes are `repo`, `docs`, `plugin`, and `deps-dev`. Use `+` only when one pull request changes multiple released components and `!` for a breaking change. The summary starts lowercase and does not end with a period.

Generated notes classify `security`, `feat`, `fix`, `perf`, `refactor`, `docs`, and `deps`. Internal `chore`, `ci`, `test`, and `style` changes are validated but omitted. Release-facing changes require an explicit component scope.

## Releases

Each released component follows independent SemVer. A release tag must point at the current `main` commit and use exactly one of:

- `server-v{version}`
- `cli-v{version}`
- `typescript-v{version}`
- `python-v{version}`
- `rust-v{version}`

`owlauth-types` follows the server version and is published before `owlauth-server`. Python releases currently require stable `X.Y.Z` versions because PEP 440 can normalize SemVer prerelease or build forms into different package metadata.

Pushing a valid release tag runs the required checks, derives the package version from the tag, updates manifests and lockfiles only inside workflow workspaces, generates component-filtered notes, publishes that component, and creates a GitHub Release. Do not reuse, move, or delete a published release tag.

A server release also publishes `ghcr.io/owlfoundry/owlauth:{version}` and updates `latest`. A CLI release publishes checksum-verified native archives and mandatory `SHA256SUMS`.

Server container channels follow these branch rules:

- a push to `main` publishes `ghcr.io/owlfoundry/owlauth:dev`;
- `build/server/{tag}` publishes `ghcr.io/owlfoundry/owlauth:build-{tag}` after image build and health smoke testing;
- the requested test tag must be one lowercase OCI tag segment.
