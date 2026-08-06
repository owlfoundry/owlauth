# OwlAuth repository guide

Start with [`CONTRIBUTING.md`](CONTRIBUTING.md) for repository boundaries, development rules, validation, and release conventions.

## Design and documentation

- [`spec/`](spec/README.md) is the normative authority for the target server, Runtime, Client, Control, CLI, MCP, storage, security, and hosted-web design. Accepted technology decisions are under [`spec/technology/`](spec/technology/README.md).
- [`sdks/spec/`](sdks/spec/README.md) is the language-neutral authority for official SDK behavior and conformance.
- [`docs/`](docs/index.md) is public user guidance. It describes only capabilities that have been implemented and released; it must not present target specifications as shipped behavior.

## Source map

- [`crates/owlauth-server/`](crates/owlauth-server/) — server library and executable, migrations, Runtime/Client/Control surfaces, and embedded hosted web
- [`crates/owlauth-server/web/`](crates/owlauth-server/web/) — Runtime Hosted Authentication UI and Control Management Console
- [`crates/owlauth-types/`](crates/owlauth-types/) — reviewed public HTTP DTO and OpenAPI authority
- [`crates/owlauth-key-provider/`](crates/owlauth-key-provider/) — provider-neutral key-provider SPI
- [`crates/owlauth-cli/`](crates/owlauth-cli/) — endpoint-discovered remote administration CLI
- [`sdks/`](sdks/) — independently versioned TypeScript, Python, and Rust Runtime clients
- [`plugins/owlauth/`](plugins/owlauth/) — shared agent integration skills

## Tooling map

- [`Makefile`](Makefile) — focused development, validation, build, and package targets
- [`scripts/`](scripts/) — repository, package, release, installer, SDK, and container checks
- [`dev/`](dev/README.md) — local PostgreSQL and Redis development services
- [`.github/workflows/`](.github/workflows/) — CI, documentation, image, and component release automation
