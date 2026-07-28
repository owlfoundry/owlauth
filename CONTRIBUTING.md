# Contributing

OwlAuth is in its initial design phase. Open an issue before making substantial changes.

## Local checks

```bash
make install
make check
make test
make build
```

GitHub Actions additionally runs the declared compatibility matrix: Rust 1.85 and stable, Python 3.11 and 3.14, and Node.js 20 and 24. Run `make help` for focused package, OpenAPI, and documentation targets.

## Releases

Each component follows independent SemVer. A release branch must point at the current `main` commit and use one of these exact forms:

- `release/server/{version}`
- `release/sdk/typescript/{version}`
- `release/sdk/python/{version}`
- `release/sdk/rust/{version}`

Creating a valid release branch runs all checks, publishes that component, tags the commit, and creates a GitHub Release. Do not reuse a version or move a release branch after publication.
