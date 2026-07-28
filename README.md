# OwlAuth

Self-hostable OAuth 2.1 authorization server and user management platform, built in Rust.

OwlAuth is currently a pre-alpha scaffold. The published SDK packages reserve their public names; they do not yet implement OAuth flows.

## Repository layout

```text
.
├── crates
│   ├── owlauth-server  # crates.io package and `owlauth-server` executable
│   ├── owlauth-cli     # crates.io package and `owlauth` executable
│   └── owlauth-types   # public HTTP DTOs and generated OpenAPI authority
├── spec                # normative server and CLI architecture specifications
├── docs                # Cloudflare Workers documentation site
├── plugins             # Codex and Claude plugin distribution
└── sdks
    ├── typescript      # npm: `@owlauth/client`
    ├── python          # PyPI: `owlauth-client`, import: `owlauth`
    ├── rust            # crates.io: `owlauth-client`
    └── spec            # shared fixtures and conformance cases
```

The normative server design is indexed in [`spec/`](spec/README.md); the language-neutral SDK design is indexed in [`sdks/spec/`](sdks/spec/README.md). SDKs share only the public protocol contract and do not depend on the server implementation. OpenAPI is generated when needed and is not checked into the repository:

```bash
cargo run --package owlauth-server -- --openapi
```

Database migrations belong under `crates/owlauth-server/migrations/`. The target storage design embeds them in the server and applies pending migrations automatically before readiness; the runner is not implemented in the current scaffold.

## CLI installation

Unix-like systems:

```bash
curl -fsSL https://raw.githubusercontent.com/owlfoundry/owlauth/main/scripts/install.sh | sh
```

Windows PowerShell:

```powershell
irm https://raw.githubusercontent.com/owlfoundry/owlauth/main/scripts/install.ps1 | iex
```

Both installers download CLI archives from GitHub Releases and require a matching entry in `SHA256SUMS`. The default install directory is `$HOME/.local/bin`; override it with `OWLAUTH_INSTALL_DIR`. Install a pinned version with `OWLAUTH_VERSION=0.0.2`.

The installed CLI updates through the same checksum-verified release path:

```bash
owlauth update
owlauth update --dry-run
owlauth update --version 0.0.2 --force
```

## Versioning and releases

The server, CLI, and each SDK follow independent SemVer. `owlauth-types` follows the server version.

| Component | Package | Release tag |
| --- | --- | --- |
| Server | `owlauth-server`, `owlauth-types` | `server-v{version}` |
| CLI | `owlauth-cli` | `cli-v{version}` |
| TypeScript | `@owlauth/client` | `typescript-v{version}` |
| Python | `owlauth-client` | `python-v{version}` |
| Rust | `owlauth-client` | `rust-v{version}` |

Push a release tag at the current `main` commit. The workflow derives the version from the tag and materializes it in manifests and lockfiles without a version-bump commit.

Server container images are hosted at `ghcr.io/owlfoundry/owlauth`. `main` updates `dev`; a server release publishes its version and updates `latest`; `build/server/{tag}` publishes the isolated, smoke-tested tag `build-{tag}`.

Release notes are generated deterministically from squash PR titles and filtered by component scope. See [CONTRIBUTING.md](CONTRIBUTING.md) for the title and release conventions. Project documentation is published at [owlauth.owlfoundry.org](https://owlauth.owlfoundry.org).

## License

OwlAuth is licensed under the [BSD 3-Clause License](LICENSE).
