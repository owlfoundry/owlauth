# 08 — Independent SemVer and releases

## Independently versioned components

The server, CLI, and every official SDK have separate SemVer, tags, artifacts, compatibility statements, and changelogs. For SDKs:

| Component  | Registry identity                                | Tag pattern             |
| ---------- | ------------------------------------------------ | ----------------------- |
| TypeScript | npm `@owlauth/client`                            | `typescript-v{version}` |
| Python     | distribution `owlauth-client`, import `owlauth`  | `python-v{version}`     |
| Rust       | crate `owlauth-client`, library `owlauth_client` | `rust-v{version}`       |

An SDK release never requires synchronized server/CLI/other-SDK versions. Equal version numbers do not imply compatibility. Each SDK release identifies the Runtime Project Auth contract/server range it has actually tested.

Current SDK packages are pre-alpha protocol clients with Project/Application-bound configuration and JWKS retrieval, Hosted login start, PKCE callback/handoff, atomic credential refresh, current-user, and logout operations. Pre-1.0 SemVer permits deliberate iteration but does not permit silent breaking changes or claims of framework session management, persistent storage, navigation, backend JWT verification, or production support.

## TypeScript artifact and integration boundary

The first-party TypeScript protocol client has one npm artifact, version, changelog, and release tag: `@owlauth/client`. Its initial implemented API uses one portable Web-standard core for the declared browser and Node.js matrices. Browser compatibility does not create a separately published package, and the initial scope defines no `@owlauth/client/browser` subpath.

Navigation, history cleanup, persistence, automatic session/refresh management, and framework bindings are not alternate entry points hidden in the core artifact. An Application may implement them directly, and another library may version and publish them independently. Such a library must preserve the core protocol and security contract but does not become an `@owlauth/client` release gate unless explicitly adopted later.

## Capability and compatibility statements

Release notes and package metadata distinguish:

- scaffold-only behavior;
- generated models/low-level operations;
- mock-tested handwritten protocol-safety behavior;
- shared conformance coverage;
- real-server E2E coverage;
- production support, if and when explicitly declared.

Compatibility is expressed by tested Runtime contract digest/range and required capability, not guessed from a server version string alone. An SDK fails clearly when a required Runtime capability is absent.

## Change classification

Normally breaking:

- removing/renaming a public symbol or requiring a new argument;
- changing sync/async, cancellation, retry, or explicit-state custody behavior;
- adding implicit navigation, history, persistence, or session-management behavior to a previously side-effect-free core API;
- changing Project/Application binding or public configuration semantics;
- changing PKCE, handoff ambiguity, strict refresh, current-user, or logout behavior;
- narrowing supported Runtime contracts, language runtimes, or toolchains;
- changing stable error categories or exhaustive variants;
- weakening/strengthening a security default in a way requiring caller changes.

Normally additive:

- an optional configuration field;
- a new Project Auth operation/capability;
- additional forward-compatible response/error detail.

A separately published platform or framework integration follows its own package contract and SemVer. Adding it does not silently change the core package's storage, navigation, or session behavior.

Patch changes correct behavior without intentionally changing the documented public contract. Security fixes may require an explicit breaking release and migration guidance. Each language applies its ecosystem conventions under this shared meaning.

## Release inputs and gates

An SDK release branch/tag points at the current `main` commit under repository release policy. Tag, package metadata, and runtime-reported version agree. Release validation occurs before registry publication and includes:

- pinned/locked supported tools and dependencies;
- exact generated Runtime contract source revision and digest;
- formatting, lint/type checks, unit/package tests;
- the declared Node.js matrix and, once claimed, real browser bundle/runtime tests for the same `@owlauth/client` artifact;
- all shared cases for every claimed capability;
- Project/Application isolation and credential-redaction tests;
- license, README, package metadata, and clean-install smoke tests;
- dependency, secret, and artifact inspection;
- component-specific changelog generated from reviewed PR titles;
- explicit compatibility and implementation-status notes.

A release that claims Project Auth behavior additionally starts a real `owlauth-server` Runtime and passes the corresponding SDK and cross-language E2E cases. Until then, CI labels package/unit/fixture/contract checks accurately; mocks are never promoted to E2E.

## Generated contract coordination

A server contract may change without an immediate SDK release. OpenAPI generation remains ephemeral. When an SDK does release generated changes, provenance records the exact contract and generator; drift review confirms Runtime-only surface and the required handwritten protocol-safety/error updates.

Server changes that are additive may remain compatible with older SDKs under unknown-field/enum policy. Removing or semantically changing a Project Auth operation requires coordinated compatibility/changelog planning but not equal component version numbers.

## Deprecation

Deprecations provide replacement guidance and remain for a documented period appropriate to the next major release. Security-sensitive behavior may be removed sooner with coordinated advisories, explicit release notes, and safe migration instructions.

Deprecated aliases do not weaken Project/Application isolation, PKCE, one-use handoff, refresh replay containment, TLS, or redaction.

## Artifact policy

Registry artifacts contain only intended source/build output, license, README, and metadata. They exclude:

- repository or test credentials;
- local paths, caches, virtual environments, and build workspaces;
- temporary generated OpenAPI documents;
- unrelated SDK/server crates or packages;
- fixtures containing credential-shaped values not explicitly intended and synthetic.

Clean installation verifies the public package/import/crate identity and only implemented examples. Package documentation links the SDK specs and security reporting path.

## Acceptance criteria

- Tag, package metadata, and runtime-reported version agree.
- Every release traces source, build, dependencies, generator, and Runtime contract digest.
- Compatibility is explicit and independent of numeric equality.
- Changelog and README truthfully distinguish scaffold, implemented operations, conformance, E2E, and production support.
- The TypeScript release publishes one `@owlauth/client` artifact and does not imply a browser wrapper through package naming.
- No SDK claims Project Auth capability before real-server validation of that capability.
