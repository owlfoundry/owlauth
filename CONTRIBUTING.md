# Contributing

OwlAuth is in its initial design phase. Open an issue before making substantial changes.

## Local checks

```bash
make install
make check
make test
make build
```

GitHub Actions additionally runs the declared compatibility matrix: Rust stable, Python 3.11-3.14, and Node.js 20, 22, and 24. Repository tooling requires Node.js 22.13 or later because dependencies are installed from the root pnpm 11.17.0 lockfile; the SDK itself is runtime-tested on Node.js 20, 22, and 24. Python development dependencies use the root uv 0.11.32 workspace and lockfile. Run `make help` for focused package, OpenAPI, container, and documentation targets.

## Releases

Each component follows independent SemVer. A release branch must point at the current `main` commit and use one of these exact forms:

- `release/server/{version}`
- `release/sdk/typescript/{version}`
- `release/sdk/python/{version}`
- `release/sdk/rust/{version}`

Creating a valid release branch runs all checks, publishes that component, tags the commit, and creates a GitHub Release. A server release also publishes `ghcr.io/owlfoundry/owlauth:{version}` and updates `latest`; if a SemVer contains `+` build metadata, that separator is represented as `_` in the OCI tag. Do not reuse a version or move a release branch after publication.

Server container channels use these branch rules:

- a push to `main` publishes `ghcr.io/owlfoundry/owlauth:dev`;
- a branch named `build/server/{tag}` publishes `ghcr.io/owlfoundry/owlauth:build-{tag}` after building and smoke-testing the image;
- requested test tags are a single lowercase OCI tag segment; the registry prefix isolates them from release versions, `dev`, and `latest`.
