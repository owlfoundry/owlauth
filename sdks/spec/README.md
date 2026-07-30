# OwlAuth SDK specifications

This directory defines the language-neutral behavior of the official TypeScript, Python, and Rust SDKs for OwlAuth Project Auth. It allows each package to use idiomatic language APIs while preserving one observable Runtime contract, one security model, and equivalent errors.

OwlAuth brokers authentication to Project-configured upstream providers such as GitHub, Google, or another OIDC provider. Downstream Applications do not act as generic OAuth clients of OwlAuth: they initialize from public Project/Application configuration, begin provider login through OwlAuth Runtime, exchange a short-lived PKCE-bound handoff ticket, and receive an OwlAuth Project user and session credentials.

## Current implementation status

The SDK packages are currently pre-alpha scaffolds and package-name reservations. Their `Client` types only retain a base URL. They do not yet:

- fetch public Project/Application configuration;
- begin an upstream-provider login;
- generate or retain PKCE material;
- exchange a one-use handoff ticket;
- issue, verify, refresh, or persist Project credentials;
- call current-user or logout operations;
- map Runtime errors or send HTTP requests.

The specifications below are target behavior and release acceptance gates, not claims about the current packages.

Reviewed Rust definitions in `crates/owlauth-types` are the source of public Runtime DTOs and generated OpenAPI. OpenAPI is emitted from the exact server revision under test and is not committed. Generated models remain subordinate to the handwritten protocol, transport, isolation, and security rules in this directory.

## Specification map

| Spec                                                                           | Owning concern                                                                                 |
| ------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------- |
| [`01-system-context-and-boundaries.md`](01-system-context-and-boundaries.md)   | SDK role, Project/Application trust boundaries, public surface, and server separation          |
| [`02-generated-contract-and-models.md`](02-generated-contract-and-models.md)   | OpenAPI provenance, generated Runtime models, compatibility, and drift                         |
| [`03-transport.md`](03-transport.md)                                           | Runtime URLs, HTTP behavior, deadlines, retries, cancellation, and testability                 |
| [`04-pkce-and-token-lifecycle.md`](04-pkce-and-token-lifecycle.md)             | Project login initiation, handoff PKCE, Project credentials, refresh, current user, and logout |
| [`05-cross-language-error-semantics.md`](05-cross-language-error-semantics.md) | stable Project Auth errors and language mappings                                               |
| [`06-fixtures-and-conformance.md`](06-fixtures-and-conformance.md)             | shared Project Auth fixtures, conformance runners, and real-server E2E                         |
| [`07-security.md`](07-security.md)                                             | secret handling, browser/native redirects, token storage, isolation, and supply chain          |
| [`08-versioning-and-releases.md`](08-versioning-and-releases.md)               | independent SemVer, compatibility statements, artifacts, and release gates                     |

The normative server architecture is specified in [`../../spec/`](../../spec/), especially the [Project Auth flow](../../spec/03-project-auth-flows-and-security-invariants.md) and [Runtime HTTP contract](../../spec/05-http-contract-and-surface-boundaries.md).

## Shared attachments

- [`fixtures/`](fixtures/) contains reviewed machine-readable wire examples. The current corpus contains only [`health-response.json`](fixtures/health-response.json).
- [`conformance/`](conformance/) contains language-neutral behavior cases. The current [`cases.json`](conformance/cases.json) asserts only the health fixture.

These attachments are not evidence of Project Auth implementation. They use synthetic, non-secret values and explicit schema versions.

## Cross-cutting invariants

1. SDKs are untrusted Runtime clients. OwlAuth remains authoritative for Project, Application, user, provider, handoff, session, refresh, and policy decisions.
2. `project_id`, `application_id`, and a publishable Application key are public identifiers, not secrets, user credentials, or Control authority.
3. Every Project Auth operation remains bound to one Project and, where applicable, one Application. SDK state from one Project/Application cannot be reused for another.
4. SDKs consume only public Runtime wire behavior. They do not import server domain modules, storage adapters, provider payloads, or Control authority. The Rust SDK receives no special access from sharing the implementation language.
5. Generated models and low-level operations may follow OpenAPI. PKCE custody, callback validation, one-use handoff/refresh retry safety, Project/Application isolation, redaction, and semantic errors remain handwritten core behavior.
6. Core SDKs expose explicit protocol values and operations; Applications or separate integration libraries own navigation, history mutation, persistence, refresh serialization, automatic session management, and framework bindings.
7. The TypeScript SDK ships once as `@owlauth/client` and uses one Web-standard core across its declared browser and Node.js matrices. The initial protocol API defines no separate browser package or `/browser` entry point.
8. Handoff tickets, access tokens, refresh tokens, PKCE verifiers, browser/session cookies, provider callback values, and management credentials never appear in default strings, debug output, logs, traces, fixtures, exceptions, or telemetry.
9. Automatic retry is limited to demonstrably replay-safe operations. Ambiguous handoff exchange or refresh rotation is never blindly replayed.
10. Equivalent Runtime responses map to equivalent semantic outcomes in every official SDK.
11. Each SDK versions and ships independently from the server and other SDKs. Numeric version equality never implies compatibility.
12. Package, unit, fixture, and conformance checks remain distinct from future real-server end-to-end tests. A mock or health fixture is not Project Auth E2E.

## Normative language

`MUST`, `MUST NOT`, `SHOULD`, and `MAY` are normative design terms. Language-specific APIs can differ in naming, async model, and type idiom while preserving these observable semantics.
