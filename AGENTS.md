# OwlAuth repository guide

Start with [`CONTRIBUTING.md`](CONTRIBUTING.md) for repository boundaries, development rules, validation, and release conventions.

## Design and documentation

- [`spec/`](spec/README.md) is the normative authority for the target server, Runtime, Server API, Control, CLI, MCP, storage, security, and hosted-web design. Accepted technology decisions are under [`spec/technology/`](spec/technology/README.md).
- [`sdks/spec/`](sdks/spec/README.md) is the language-neutral authority for official SDK behavior and conformance.
- [`docs/`](docs/index.md) is public user guidance. It describes only capabilities that have been implemented and released; it must not present target specifications as shipped behavior.

## Source map

- [`crates/owlauth-server/`](crates/owlauth-server/) — server library and executable, migrations, Auth Runtime/Server API surfaces, Control surface, and embedded hosted web
- [`crates/owlauth-server/web/`](crates/owlauth-server/web/) — Runtime Hosted Authentication UI and Control Management Console
- [`crates/owlauth-types/`](crates/owlauth-types/) — reviewed public HTTP DTO and OpenAPI authority
- [`crates/owlauth-key-provider/`](crates/owlauth-key-provider/) — provider-neutral key-provider SPI
- [`crates/owlauth-cli/`](crates/owlauth-cli/) — endpoint-discovered remote administration CLI
- [`sdks/`](sdks/) — independently versioned TypeScript, Python, and Rust Runtime clients
- [`plugins/owlauth/`](plugins/owlauth/) — shared agent integration skills

## Non-negotiable boundaries

- Auth is the Project Auth endpoint. Its browser-facing Runtime surface and backend-only Server API surface share one listener and process identity but retain separate routers, credentials, CORS/response policy, readiness, roles, serving pools, and pool bounds. Runtime public SDK configuration contains no Server or Control secret; Server API accepts only Project server keys. Control is the separate operator endpoint used by the Console, CLI, and MCP and accepts only the Control operator key.
- Official TypeScript, Python, and Rust SDKs cover Runtime Project Auth only. Server API has a generated OpenAPI document but no official SDK and must never be imported into hosted-web code.
- Keep Auth and Control listeners independently configurable. Keep Runtime, Server API, and Control internal authority boundaries independently configurable while all three surfaces remain bound to one PostgreSQL server/database authority. The Runtime Hosted Authentication UI and Control Management Console are the only browser surfaces.
- PostgreSQL is the durable authority. Do not add browser credential persistence, file-store fallbacks, unreviewed secret delivery, or dependencies from CLI/SDKs into the server implementation.
- Edit Rust DTOs in `owlauth-types`; regenerate derived OpenAPI/hosted-web contracts rather than hand-editing generated files.
- The PostgreSQL schema has been deployed. Existing migration files are immutable compatibility artifacts: never edit, reorder, squash, or replace them. Every schema change must use a new ordered migration and must be tested both as a clean install and as an upgrade from the deployed migration set.

## Development quick start

```bash
make help
make install
cp .env.example .env
make dev
```

`make dev-check` performs a non-mutating `.env`, toolchain, Docker, and Compose preflight. `make dev` runs that check, rebuilds embedded Runtime and Control assets, starts PostgreSQL, runs Auth and Control, and logs directly openable endpoint URLs. Use `make dev-status`, `make dev-logs`, or `make dev-postgres` while debugging and `make dev-down` when finished. `make dev-reset` deletes all local PostgreSQL data and is intentionally destructive.

Common targets:

- `make format` — format Rust and Python; use `make markdown-check` for Markdown and `make web-check` for hosted-web lint/Prettier/type/tests.
- `make check` — aggregate formatting, Clippy, static SDK/web, docs, installer, release-tooling, and workflow checks.
- `make test` — workspace Rust, Python, hosted-web, and TypeScript SDK tests.
- `make build` — release server/CLI binaries, SDK distributions, embedded web assets, and docs.
- `make package-check` — inspect registry candidates and compile packaged Rust products offline.
- `make openapi` — export `target/openapi/{runtime,server,control}.json`.
- `make web-contracts` / `make web-build` / `make web-verify` — regenerate types, rebuild deterministic assets, and reject drift.
- `make web-e2e` — optionally qualify the exact SDK artifacts locally against real PostgreSQL, Rust, Chromium, and Firefox. It requires a clean committed `HEAD` so candidate bytes are attributable.
- `make test-containers` / `make docker-build` — focused Docker-backed infrastructure or image smoke tests.
- `make docs` / `make docs-build` — serve or build the public documentation.

For security-, persistence-, topology-, or provider-boundary changes, also run:

```bash
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
OWLAUTH_REQUIRE_DOCKER=1 cargo test --workspace --all-features --locked
```

Generated-asset gates compare against Git state. Stage intended generated files before `make web-verify`; commit all intended bytes and ensure `git status --short` is empty before `make web-e2e`.

## Release quick reference

- Committed Cargo/npm manifests stay at `0.0.0-dev`; Python stays at `0.0.0.dev0`. Never commit release-only version bumps and never publish a development sentinel.
- Releases are driven by an immutable tag on the selected reviewed commit: `server-v{version}`, `cli-v{version}`, `typescript-v{version}`, `python-v{version}`, or `rust-v{version}`. `{version}` is SemVer; Python currently permits stable `X.Y.Z` only. A tag remains releasable if `main` advances afterward.
- Server and CLI tags share the `owlauth-types` crates.io version sequence. Their versions normally increase globally; a matching version is allowed only when both tags point to the same commit, with Server published before CLI so CLI reuses the checksum-identical shared crate. Server publishes `owlauth-key-provider` → `owlauth-types` → `owlauth-server`; CLI publishes `owlauth-types` → `owlauth-cli`. SDK versions are independent.
- Before tagging, select a clean reviewed commit that has passed the relevant focused tests plus `make check`, `make test`, and `make package-check`. Run local `make web-e2e` only when its real browser coverage is useful. Create and push one immutable release tag; publishing need not race later changes to `main`. Do not move, reuse, or delete a published tag.
- Release workflows do not rerun full CI. They derive versions in isolated workspaces, build and inspect the registry artifact, generate component-filtered notes, publish packages/artifacts, and create the GitHub Release. Server releases also publish the versioned GHCR image and `latest`; pushes to `main` publish `dev`.
- `scripts/release/prepare_release.py` and `scripts/release/verify-release.sh` are workflow authorities, not a reason to commit materialized versions. Run release mutation tooling only in a disposable worktree when diagnosing automation.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for changelog scopes, SemVer rules, shared-version constraints, image tags, and installer checksum requirements.

## Tooling map

- [`Makefile`](Makefile) — focused development, validation, build, package, docs, and local-service targets
- [`scripts/`](scripts/) — repository, package, release, installer, SDK, and container checks
- [`dev/`](dev/README.md) — local PostgreSQL development service
- [`.github/workflows/`](.github/workflows/) — CI, documentation, image, and component release automation
