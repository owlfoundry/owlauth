# OwlAuth

Self-hostable OAuth 2.1 authorization server and user management platform, built in Rust.

OwlAuth is currently a pre-alpha scaffold. The `0.0.1` SDK packages reserve their public names; they do not yet implement OAuth flows.

## Repository layout

```text
.
├── crates
│   ├── server       # `owlauth` server binary
│   ├── domain       # server domain model
│   ├── storage      # persistence boundaries and embedded migrations
│   └── protocol     # server protocol types
├── spec             # normative server architecture specifications
├── docs             # Cloudflare Workers documentation site
├── plugins          # Codex and Claude plugin distribution
└── sdks
    ├── typescript   # npm: `@owlauth/client`
    ├── python       # PyPI: `owlauth-client`, import: `owlauth`
    ├── rust         # crates.io: `owlauth-client`
    └── spec         # shared fixtures and conformance cases
```

The normative server design is indexed in [`spec/`](spec/README.md); the language-neutral SDK design is indexed in [`sdks/spec/`](sdks/spec/README.md). The SDKs share only the public protocol contract. In particular, the Rust SDK does not depend on any internal server crate. OpenAPI is generated from Rust definitions when needed and is not checked into the repository:

```bash
cargo run --package owlauth -- --openapi
```

Database migrations belong under `crates/storage/migrations/`. The target storage design embeds them in the server and applies pending migrations automatically before the server becomes ready; the runner is not implemented in the current scaffold.

## Versioning and releases

The server and each SDK follow independent SemVer:

| Component | Package | Release branch | Tag |
| --- | --- | --- | --- |
| Server | `owlauth` | `release/server/{version}` | `server-v{version}` |
| TypeScript | `@owlauth/client` | `release/sdk/typescript/{version}` | `typescript-v{version}` |
| Python | `owlauth-client` | `release/sdk/python/{version}` | `python-v{version}` |
| Rust | `owlauth-client` | `release/sdk/rust/{version}` | `rust-v{version}` |

See [CONTRIBUTING.md](CONTRIBUTING.md) for local checks and [TODO.md](TODO.md) for maintainer setup.

## License

OwlAuth is licensed under the [BSD 3-Clause License](LICENSE).
