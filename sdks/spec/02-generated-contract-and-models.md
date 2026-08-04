# 02 — Generated Runtime contract and models

## Contract authority

The SDK contract pipeline exports OpenAPI 3.1 documents from the exact `owlauth-types` revision under validation:

```bash
cargo run --locked --package owlauth-types --bin export-openapi -- \
  runtime <temporary-build-path>/runtime-openapi.json
cargo run --locked --package owlauth-types --bin export-openapi -- \
  control <temporary-build-path>/control-openapi.json
```

The complete documents are derived from reviewed public DTOs in `crates/owlauth-types`, are generated without compiling `owlauth-server`, and are never committed. `sdks/spec/contract/sdk-surface.json` explicitly selects the Runtime Project Auth operations claimed by the official SDKs. `scripts/sdk-contract.py` recursively selects their wire-relevant operation and component graph, removes non-wire document annotations, writes the reviewed deterministic snapshot `sdks/spec/contract/runtime-project-auth.normalized.json`, and checks it in CI.

The normalized snapshot is a reviewed derivative and drift baseline, not a second server contract. The full Runtime digest is provenance only: an unrelated additive Runtime operation changes provenance but does not silently expand or block the SDK surface. Any selected-surface drift fails CI with an explicit client-review diagnostic until compatibility, all three adapters, shared cases, and documentation are reviewed together. Any claimed Control operation or operator security scheme fails unconditionally.

The Beta SDKs retain handwritten narrow wire adapters and protocol-safety layers rather than generated public clients. This is intentional for the bounded eight-operation surface. Contract extraction proves structural authority; shared fixtures, semantic cases, exact-artifact tests, and real-server journeys prove the behavior that OpenAPI cannot express, including PKCE custody, one-use handoff/refresh behavior, context isolation, ambiguity, and redaction.

## Surface separation

The source contract distinguishes:

- Runtime Project Auth DTOs and operations intended for public SDKs;
- Control administrative DTOs intended for a separate privileged client/CLI surface;
- health/diagnostic vocabulary that does not imply authentication support.

Default SDK generation consumes Runtime only. It must not expose Control endpoints, management credentials/scopes, server storage models, provider payloads, key references, or internal health detail merely because one server binary contains those surfaces.

## Generated-contract and adapter boundary

The selected workflow generates and commits only the language-neutral normalized contract. It does not generate or expose public TypeScript, Python, or Rust clients. Each language keeps a narrow internal adapter that deterministically maps its idiomatic safety types to and from:

- public Project/Application configuration;
- login-start and PKCE-bound handoff requests/responses;
- Project user, credential-pair, refresh, and logout DTOs;
- stable Runtime error wire shapes; and
- exact endpoint method/path/status/content-type declarations.

A future generator may replace an internal wire adapter only if repeated maintenance demonstrates a concrete need. Its output remains private, reproducible, and wrapped by the same public safety API. Generation must not invent policy for:

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

CI exports both ephemeral plane documents, validates per-plane operation uniqueness and the explicit liveness/readiness overlap, recursively normalizes the selected Runtime graph, and byte-compares it with the tracked snapshot. The check also records the source commit, server/types versions, full Runtime digest, claimed-surface digest, policy digest, and normalizer version as ephemeral provenance. Unexplained selected drift fails with instructions to review and update all clients; full-Runtime-only drift remains visible in provenance.

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

- Two clean normalizations are byte-identical with the same claimed-surface digest.
- A clean contract job leaves no complete OpenAPI file in the source tree.
- The policy and normalized default SDK surface contain only the eight reviewed Runtime Project Auth operations and no Control authority.
- Mutation tests cover selected drift, unclaimed additions, missing/duplicate operations, dangling/external references, plane leakage, and management security leakage.
- Adapter/model tests cover omission/null, unknown fields/enums, bounds, Project/Application identifiers, exact request framing, and secret redaction.
- Handwritten protocol code reaches wire models only through the narrow internal adapter boundary.
- Release provenance identifies the full and claimed contract digests, exact source revision, and normalizer/policy versions.
