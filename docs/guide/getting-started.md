# Getting started

OwlAuth is currently a pre-alpha project. This page documents repository development rather than a production deployment.

## Prerequisites

- Rust 1.85 or later
- Node.js 20 or later
- Python 3.11 through 3.14
- `uv` for Python development

## Build and test the server

```bash
git clone git@github.com:owlfoundry/owlauth.git
cd owlauth
cargo test --workspace --all-features
cargo run --package owlauth
```

## Generate OpenAPI

The OpenAPI document is generated from Rust protocol definitions and is intentionally not committed:

```bash
cargo run --package owlauth -- --openapi > /tmp/owlauth-openapi.json
```

The generated document is an ephemeral build input and should not be committed. See the [server specification index](https://github.com/owlfoundry/owlauth/tree/main/spec) for the target architecture and its explicit current-state boundaries.

Production deployment guidance will be added when the server has a stable runtime configuration.
