# 08 — Independent SemVer and releases

## Independent components

The server and each official SDK have separate SemVer, release tags, registry artifacts, and changelogs:

| Component | Package | Tag pattern |
| --- | --- | --- |
| TypeScript | `@owlauth/client` | `typescript-v{version}` |
| Python | distribution `owlauth-client`, import `owlauth` | `python-v{version}` |
| Rust | `owlauth-client` / `owlauth_client` | `rust-v{version}` |

A release in one language MUST NOT require synchronized version bumps in the others. Server and SDK versions do not imply compatibility by numeric equality. Each SDK publishes a tested server contract/version range or compatibility statement.

Current `0.0.1` packages reserve names and expose a minimal base-URL object. Pre-1.0 SemVer allows intentional API iteration but every break is still documented; `0.x` is not permission for silent churn or production-readiness claims.

## Change classification

Normally breaking:

- removing/renaming public symbols or changing required arguments;
- changing sync/async behavior, cancellation, retry, or token persistence semantics;
- narrowing supported server contracts or runtime/toolchain versions;
- changing semantic error categories or exhaustive variants;
- changing default TLS/security behavior in a way that breaks valid secure use (security fixes may justify an explicit break).

Normally additive: new optional configuration, new operation/capability, or new non-exhaustive error detail. Patch changes fix behavior without intentionally changing the documented public contract. Every classification is reviewed in the conventions of that language.

## Release inputs and gates

An SDK release is built from a component tag at the current `main` commit. The tag is the version authority; CI materializes that version in package metadata and lockfiles without a release-only commit. The release includes:

- pinned/locked supported tooling and dependencies;
- the generated-contract provenance/digest used, even though OpenAPI is not committed;
- formatting, lint/type checks, unit and package tests;
- all shared conformance cases for claimed capabilities;
- license/readme/package metadata and registry artifact smoke tests;
- dependency, secret, and artifact inspection;
- release notes including compatibility and security-relevant behavior.

Once OAuth exists, claimed OAuth-capable releases additionally require CI to start a real OwlAuth server and run that SDK plus the cross-language matrix end to end. Until then, package/unit/conformance checks are reported by those names; fake E2E gates MUST NOT be created.

## Compatibility and deprecation

SDKs SHOULD tolerate additive response fields and unknown server error codes according to spec 02/05. They MUST fail clearly when a required capability is unavailable rather than guessing from server version alone. Capability/metadata negotiation, if introduced, becomes part of the public contract.

Deprecations include replacement guidance and persist for a documented period appropriate to the next major release. Security-sensitive behavior may be removed sooner with coordinated advisories and release notes.

## Artifact policy

Registry artifacts contain only intended source/build output, license, and metadata. They MUST NOT contain repository secrets, test credentials, local paths, temporary OpenAPI documents, caches, virtual environments, or unrelated workspace crates. Installation smoke tests use a clean environment and public import/package names.

## Acceptance criteria

- Tag, package metadata, and runtime-reported version agree.
- A release can be traced to source, build, dependencies, and contract digest.
- Compatibility is expressed explicitly, not inferred from matching version numbers.
- Release notes truthfully distinguish scaffold, implemented operations, and production support.
