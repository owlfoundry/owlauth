# 08 — Delivery validation and evolution

## Evidence over claims

A feature is implemented only when code is composed into a shipped surface and the relevant tests, security review, documentation, and operational checks pass. A type, OpenAPI operation, fixture, specification, or package reservation alone is not implementation evidence.

## Validation layers

| Layer | Required evidence |
| --- | --- |
| Static | formatting, linting, forbidden dependency checks, unsafe-code policy, dependency/security review |
| Unit | domain invariants, protocol conversion, redaction, SDK handwritten algorithms |
| Contract | deterministic OpenAPI generation/lint/diff; route-to-contract parity |
| Storage | supported real engine, transactions, constraints, migrations, races, interruption/retry |
| Server integration | composed routes, middleware, config, readiness, shutdown, and error mapping |
| Protocol security | redirect/PKCE/code/token negative cases, replay/concurrency, cryptographic boundaries |
| SDK conformance | one language-neutral fixture/case corpus exercised by every SDK |
| End-to-end | real server plus real supported SDKs exercising advertised OAuth behavior |
| Operational | clean install, upgrade, backup/recovery, key rotation, resource bounds, artifact smoke tests |

Tests MUST use deterministic clocks and randomness through test-only boundaries where timing/security state requires it, without weakening production entropy. Security-critical concurrency tests must assert one accepted outcome and safe loser behavior rather than relying on happy-path sequencing.

## Current versus future gates

Current pre-alpha validation can truthfully cover Rust workspace tests, SDK package/unit checks, OpenAPI generation, and the small machine-readable SDK fixture/conformance corpus. It cannot claim OAuth interoperability or server-backed end-to-end coverage because no HTTP OAuth server exists.

Once OAuth behavior is implemented, CI MUST start a real OwlAuth server with isolated storage and keys and run cross-language end-to-end tests through supported flows. Fake transports and generated-model tests remain useful but are not substitutes. Until then, do not add placeholder E2E tests that create false confidence.

## Release gates

A releasable component has:

- a clean build from the tagged source and locked/supported toolchains;
- license, provenance, version, changelog/release notes, and artifact smoke checks;
- no committed generated OpenAPI drift;
- contract and migration compatibility review where affected;
- threat/security review proportional to the change;
- documentation that separates current capability from roadmap;
- successful component-specific validation, including server-backed E2E only when the required server behavior exists.

Server, CLI, and each SDK have independent SemVer and component tags. `owlauth-types` follows the server version and is published before `owlauth-server`. A server change does not force equal CLI or SDK versions, but tested compatibility ranges and coordinated breaking changes must be recorded.

Every release generates deterministic component-filtered notes from validated squash PR titles before any publication. The notes artifact consumed by final publication is the same artifact reviewed during the release gate; GitHub-generated cross-component notes are not mixed in.

A server release publishes the same verified source as the `owlauth-types` and `owlauth-server` crates, native archives, and `ghcr.io/owlfoundry/owlauth:{version}`, then advances the mutable `latest` channel. OCI tags represent a SemVer `+` build-metadata separator as `_` because `+` is not valid in an OCI tag. The `dev` image follows `main`. Explicit `build/server/{tag}` branches provide isolated `build-{tag}` test tags that cannot collide with release channels. Every image is built from its triggering commit and must start successfully and pass `/health` before registry publication.

A CLI release publishes `owlauth-cli` and platform-specific GitHub Release archives with mandatory SHA-256 checksums. Installers fail closed when checksums are absent or invalid. The release matrix and installer target detection remain identical, and every release after the first validates a real update from the preceding CLI version on Linux, macOS, and Windows.

## Evolution rules

Normative changes begin in the owning numbered document and update cross-references rather than duplicating contracts. A proposal that adds a grant, token format, admin surface, CLI command, MCP tool, storage engine, or secret flow includes threat analysis, compatibility, migration, observability, and validation impact.

Released database migrations are immutable. Public protocol breaks receive OpenAPI-aware review and SemVer treatment. Security fixes may intentionally tighten previously accepted behavior; release notes explain impact without exposing exploit detail prematurely.

Specifications are reviewed with implementation. If implementation intentionally differs, either code is corrected or the owning specification changes in the same decision—silent drift is not accepted.

## Production-readiness gate

Production-readiness language requires all advertised flows to pass standards/interoperability suites, adversarial protocol tests, real storage migration/upgrade tests, cross-language E2E, secret-redaction tests, operational recovery exercises, and a threat-model/security review. It also requires maintained deployment and incident-response guidance. Passing compilation or publishing `0.0.x` packages is insufficient.

## Acceptance criteria

- CI names validation layers accurately and never labels mocks as E2E.
- Every normative invariant has an owner and an automated or documented review gate.
- Release evidence is reproducible from a source tag.
- Unimplemented features remain visibly planned in specs and user documentation.
