# OwlAuth SDK specifications

This directory defines the language-neutral behavior of the official TypeScript, Python, and Rust SDKs for OwlAuth Project Auth. It allows each package to use idiomatic language APIs while preserving one observable Runtime contract, one security model, and equivalent errors.

OwlAuth brokers authentication through Project-configured methods, including upstream providers and first-party email proof where enabled. Downstream Applications do not act as generic OAuth clients of OwlAuth: they initialize from public Project/Application configuration, begin one generic Hosted Project login through OwlAuth Runtime, let the browser-bound Hosted UI select an admitted authentication method, exchange a short-lived PKCE-bound handoff ticket, and receive an OwlAuth Project user and session credentials.

## Current implementation status

The SDK packages are Beta, pre-1.0 protocol clients for the implemented Runtime Project Auth surface. They fetch public Project/Application configuration and JWKS, create caller-held PKCE pending state, validate and exchange one-use handoffs, return atomic credential generations, refresh, query current user, prepare browser logout, perform Application logout, and map bounded Runtime/transport failures to stable redacted errors. Their final evidence proves one source commit, Runtime contract, corpus, archive, and runtime coordinate; it is not a broad compatibility range, deployment certification, or production support commitment.

The core SDKs deliberately do not navigate, mutate browser history, persist pending or credential state, coordinate refresh, manage framework sessions, verify access tokens for an Application backend, or expose provider credentials. Applications retain those responsibilities. The specifications below define the release acceptance gates for these implemented operations and their future evolution.

Reviewed Rust definitions in `crates/owlauth-types` are the source of public Runtime DTOs and generated OpenAPI. OpenAPI is emitted from the exact server revision under test and is not committed. The separate Project-client-key-authenticated Client OpenAPI is for customer-owned generated backend clients and is outside every official SDK package. Generated models remain subordinate to the handwritten protocol, transport, isolation, and security rules in this directory.

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

- [`fixtures/`](fixtures/) contains reviewed machine-readable public configuration, credential/projection, and Runtime error examples plus the basic health response.
- [`conformance/`](conformance/) contains required language-neutral context, error, retry/action, atomic credential, and redaction cases in [`cases.json`](conformance/cases.json).

Attachments use synthetic, non-secret values and explicit schema versions. Passing fixture conformance complements but never substitutes for real-server end-to-end evidence.

## Cross-cutting invariants

01. SDKs are untrusted Runtime Project Auth clients. They are not Client API wrappers or customer SaaS frameworks. OwlAuth remains authoritative for Project, Application, user, provider, handoff, session, refresh, and policy decisions.
02. `project_id`, `application_id`, and a publishable Application key are public identifiers, not secrets, user credentials, or Control authority.
03. Every Project Auth operation remains bound to one Project and, where applicable, one Application. SDK state from one Project/Application cannot be reused for another.
04. SDKs consume only public Runtime wire behavior. They never import Client or Control operations/security schemes. They do not import server domain modules, storage adapters, provider payloads, or Control authority. The Rust SDK receives no special access from sharing the implementation language.
05. Generated models and low-level operations may follow OpenAPI. PKCE custody, callback validation, one-use handoff/refresh retry safety, Project/Application isolation, redaction, and semantic errors remain handwritten core behavior.
06. Core SDKs expose explicit protocol values and operations; Applications or separate integration libraries own navigation, history mutation, persistence, refresh serialization, automatic session management, and framework bindings.
07. The TypeScript SDK ships once as `@owlauth/client` and uses one Web-standard Project Auth core across its declared browser and Node.js matrices. Its package name does not refer to the Project client-key-authenticated Client API. The initial protocol API defines no separate browser package or `/browser` entry point.
08. Handoff tickets, access tokens, refresh tokens, PKCE verifiers, browser/session cookies, provider callback values, and management credentials never appear in default strings, debug output, logs, traces, fixtures, exceptions, or telemetry.
09. Automatic retry is limited to demonstrably replay-safe operations. Ambiguous handoff exchange or refresh rotation is never blindly replayed.
10. Equivalent Runtime responses map to equivalent semantic outcomes in every official SDK.
11. Each SDK versions and ships independently from the server and other SDKs. Numeric version equality never implies compatibility.
12. Package, unit, fixture, conformance, and real-server end-to-end checks remain distinct. Contract purity fails if a Client API operation, Project client-key configuration, or `project_client_key` security scheme enters an SDK artifact. A mock or static fixture is not Project Auth E2E.

## Normative language

`MUST`, `MUST NOT`, `SHOULD`, and `MAY` are normative design terms. Language-specific APIs can differ in naming, async model, and type idiom while preserving these observable semantics.
