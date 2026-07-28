# Contributing

OwlAuth is in its initial design phase. Open an issue before making substantial changes.

## Local checks

```bash
make install
make check
make test
make build
make package-check
```

GitHub Actions additionally runs the declared compatibility matrix: Rust stable, Python 3.11-3.14, and Node.js 20, 22, and 24. Repository tooling requires Node.js 22.13 or later because dependencies are installed from the root pnpm 11.17.0 lockfile; the SDK itself is runtime-tested on Node.js 20, 22, and 24. Python development dependencies use the root uv 0.11.32 workspace and lockfile. Run `make help` for focused package, OpenAPI, container, and documentation targets.

## Pull request titles and changelog

Pull requests are squash-merged. Their titles are the structured source for component release notes and must use:

```text
<type>(<scope>[+<scope>...])[!]: <summary>
```

Examples:

```text
feat(server): add authorization endpoint
fix(cli): preserve the install directory during update
feat(server+cli): add health diagnostics
fix(typescript+python+rust): normalize OAuth errors
feat(all)!: replace the token response contract
chore(repo): update CI toolchains
```

Release scopes are `server`, `cli`, `typescript`, `python`, `rust`, and `all`. Internal-only scopes are `repo`, `docs`, `plugin`, and `deps-dev`. Use `+` only when one PR changes multiple released components and `!` for a breaking change. The summary starts lowercase and does not end with a period.

Generated notes classify `security`, `feat`, `fix`, `perf`, `refactor`, `docs`, and `deps`. Internal `chore`, `ci`, `test`, and `style` changes are validated but omitted. Release-facing changes require an explicit component scope.

## Releases

Each component follows independent SemVer. A release branch must point at the current `main` commit and use one of these exact forms:

- `release/server/{version}`
- `release/cli/{version}`
- `release/sdk/typescript/{version}`
- `release/sdk/python/{version}`
- `release/sdk/rust/{version}`

Creating a valid release branch runs all checks, generates component-filtered notes before publication, publishes that component, tags the commit, and creates a GitHub Release. A server release publishes `owlauth-types` followed by `owlauth-server`, publishes `ghcr.io/owlfoundry/owlauth:{version}`, and updates `latest`. A CLI release publishes `owlauth-cli` and checksum-verified native archives for supported Linux, macOS, and Windows targets. Do not reuse a version or move a release branch after publication.

Server container channels use these branch rules:

- a push to `main` publishes `ghcr.io/owlfoundry/owlauth:dev`;
- a branch named `build/server/{tag}` publishes `ghcr.io/owlfoundry/owlauth:build-{tag}` after building and smoke-testing the image;
- requested test tags are a single lowercase OCI tag segment; the registry prefix isolates them from release versions, `dev`, and `latest`.
