# Getting started

OwlAuth is currently a pre-alpha project. This page documents repository development rather than a production deployment.

## Prerequisites

- the stable Rust toolchain
- Node.js 22.13 or later for repository tooling (the TypeScript SDK runtime is tested on Node.js 20, 22, and 24)
- pnpm 11.17.0
- Python 3.11 through 3.14
- `uv` 0.11.32 for Python development

## Build and test the server

```bash
git clone git@github.com:owlfoundry/owlauth.git
cd owlauth
cargo test --workspace --all-features
cargo run --package owlauth
```

Build and smoke-test the server container locally with:

```bash
make docker-build
```

Published images use `ghcr.io/owlfoundry/owlauth`: `dev` follows `main`, version tags and `latest` come from server releases, and `build/server/{tag}` branches publish isolated `build-{tag}` test tags.

## Generate OpenAPI

The OpenAPI document is generated from Rust protocol definitions and is intentionally not committed:

```bash
cargo run --package owlauth -- --openapi > /tmp/owlauth-openapi.json
```

The generated document is an ephemeral build input and should not be committed. See the [server specification index](https://github.com/owlfoundry/owlauth/tree/main/spec) for the target architecture and its explicit current-state boundaries.

The container listens on port 8080 and defaults `OWLAUTH_ADDR` to `0.0.0.0:8080`. Production deployment guidance will be expanded when the server has a stable runtime configuration.
