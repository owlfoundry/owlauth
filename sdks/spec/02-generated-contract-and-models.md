# 02 — Generated Runtime contract and models

## Contract authority

SDK generation consumes an OpenAPI document emitted from the exact OwlAuth server revision under validation:

```bash
cargo run --package owlauth-server -- --openapi > <temporary-build-path>/owlauth-openapi.json
```

The OpenAPI file is derived from reviewed public DTOs in `crates/owlauth-types` and is never committed. CI/release provenance records the source revision, server version, generator version/configuration, and contract digest.

The current server and SDKs remain scaffolds. A generated health operation or model is not evidence that Project Auth login, handoff, session, refresh, current-user, or logout behavior exists.

## Surface separation

The source contract distinguishes:

- Runtime Project Auth DTOs and operations intended for public SDKs;
- Control administrative DTOs intended for a separate privileged client/CLI surface;
- health/diagnostic vocabulary that does not imply authentication support.

Default SDK generation consumes Runtime only. It must not expose Control endpoints, management credentials/scopes, server storage models, provider payloads, key references, or internal health detail merely because one server binary contains those surfaces.

## Generation boundary

Generation may produce:

- public Project/Application configuration models;
- login-start and provider-selection wire models;
- PKCE challenge and handoff-exchange request/response DTOs;
- Project user, session, access-token metadata, refresh, and logout DTOs;
- stable Runtime error wire shapes;
- endpoint path/method declarations and low-level Runtime operations.

Generation must not invent policy for:

- trusted Runtime origin selection;
- PKCE verifier generation/custody;
- one-use handoff and refresh retry behavior;
- Project/Application state isolation;
- language-level errors and redaction.

Those protocol-safety layers remain handwritten in the core SDK and tested. Browser/native navigation, history mutation, credential persistence, cross-process coordination, request interception, and framework state are instead owned by the Application or another integration library; generated code and the core SDK do not select or implement them.

## Model conventions

All language bindings preserve wire distinctions that affect compatibility and security:

- absent versus explicit `null`;
- required versus optional fields;
- exact `project_id`/`application_id` representation;
- unknown enum values under a documented forward-compatibility policy;
- integer, string, URI, and time formats without lossy conversion;
- stable Project Auth error code plus reviewed optional metadata;
- unknown response fields where tolerant reading is intended.

Names may be idiomatic, but mappings are deterministic. Reserved-word escaping and acronym casing are pinned in generator configuration. Generated code never overwrites handwritten protocol-safety/security code.

Project access tokens, refresh tokens, handoff tickets, PKCE verifiers, cookies, and provider callback values use redacted wrappers where language/tooling permits. Default `repr`, `Debug`, object inspection, snapshots, equality diagnostics, and serialization must not expose raw values.

A Project JWT may be carried as an opaque credential by an SDK. Decoding unverified claims for display or scheduling must be explicitly distinguished from cryptographic validation; the Application backend or an explicitly designed verifier validates signature and Project issuer/audience.

## Drift and compatibility

CI regenerates from one ephemeral OpenAPI artifact and either compares checked-in generated source or builds/tests directly from generated output. Unexplained drift fails.

Compatibility review flags at least:

- operation/field removal or rename;
- required-input additions;
- narrowed types or enum behavior;
- changes to Project/Application resolution;
- authentication/credential placement changes;
- handoff, refresh, logout, or retry semantic changes;
- error-code/category changes;
- Runtime/Control surface leakage.

The server and each SDK release independently. Each SDK publishes a tested Runtime contract/server compatibility statement. A new OpenAPI operation is not part of the stable SDK API until generated mapping, required handwritten protocol-safety semantics, tests, and documentation ship together.

## Acceptance criteria

- Generation is reproducible with pinned tools/configuration.
- A clean generation job leaves no OpenAPI file in the source tree.
- The generated default SDK surface contains Runtime Project Auth only.
- Model tests cover omission/null, unknown fields/enums, bounds, Project/Application identifiers, and secret redaction.
- Handwritten code imports generated output through a narrow adapter so the generator can be replaced.
- Release provenance identifies the exact contract digest and server revision.
