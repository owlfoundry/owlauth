# Getting started

OwlAuth is currently a pre-alpha project. This page documents repository development rather than a production deployment.

## Prerequisites

- the stable Rust toolchain
- Node.js 22.13 or later for repository tooling (the TypeScript SDK runtime is tested on Node.js 20, 22, and 24)
- pnpm 11.17.0
- Python 3.11 through 3.14
- `uv` 0.11.32 for Python development

## Build and test

```bash
git clone git@github.com:owlfoundry/owlauth.git
cd owlauth
cargo test --workspace --all-features
cargo run --package owlauth-server
cargo run --package owlauth-cli -- --version
```

Build and smoke-test the server container locally with:

```bash
make docker-build
```

Published images use `ghcr.io/owlfoundry/owlauth`: `dev` follows `main`, version tags and `latest` come from server releases, and `build/server/{tag}` branches publish isolated `build-{tag}` test tags.

## Install the CLI

```bash
curl -fsSL https://raw.githubusercontent.com/owlfoundry/owlauth/main/scripts/install.sh | sh
owlauth --version
owlauth update --dry-run
```

Windows users can run the PowerShell installer documented in the repository README. Installers and built-in updates require checksum-verified GitHub Release assets.

## Generate OpenAPI

The OpenAPI document is generated from reviewed public Rust types and is intentionally not committed:

```bash
cargo run --package owlauth-server -- --openapi > /tmp/owlauth-openapi.json
```

The generated document is an ephemeral build input. See the [server specification index](https://github.com/owlfoundry/owlauth/tree/main/spec) for the target architecture and explicit current-state boundaries.

The container listens on port 8080 and defaults `OWLAUTH_ADDR` to `0.0.0.0:8080`. Production deployment guidance will be expanded when the server has a stable runtime configuration.
