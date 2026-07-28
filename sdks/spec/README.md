# OwlAuth SDK specifications

This directory is the language-neutral design index for the official TypeScript, Python, and Rust clients. It defines shared observable behavior while allowing idiomatic language APIs and independent releases.

The SDKs are currently `0.0.1` pre-alpha package-name reservations. Their `Client` objects only retain a base URL; they do not send HTTP requests, perform PKCE, exchange or refresh tokens, map server errors, or provide production OAuth behavior. Requirements below are targets and acceptance gates, not claims of implementation.

The server's public wire contract comes from ephemeral OpenAPI generated from Rust definitions in `crates/owlauth-types`; generated OpenAPI is not committed. SDK-specific generated models/transports, when introduced, remain subordinate to these handwritten lifecycle and security rules.

## Specification map

| Spec | Owning concern |
| --- | --- |
| [`01-system-context-and-boundaries.md`](01-system-context-and-boundaries.md) | SDK role, trust model, public surface, and server separation |
| [`02-generated-contract-and-models.md`](02-generated-contract-and-models.md) | OpenAPI input provenance, generated code, model conventions, and drift |
| [`03-transport.md`](03-transport.md) | URLs, HTTP behavior, timeouts, retries, cancellation, and testability |
| [`04-pkce-and-token-lifecycle.md`](04-pkce-and-token-lifecycle.md) | authorization orchestration, PKCE, token refresh, races, and persistence boundaries |
| [`05-cross-language-error-semantics.md`](05-cross-language-error-semantics.md) | stable error taxonomy and language mappings |
| [`06-fixtures-and-conformance.md`](06-fixtures-and-conformance.md) | machine-readable shared inputs, conformance runners, and real-server E2E |
| [`07-security.md`](07-security.md) | secret handling, redirect/browser boundary, logging, storage, and supply chain |
| [`08-versioning-and-releases.md`](08-versioning-and-releases.md) | independent SemVer, compatibility ranges, artifacts, and release gates |

The root server architecture is specified in [`../../spec/`](../../spec/). This README is the ordered SDK navigation map.

## Shared artifacts

- [`fixtures/`](fixtures/) contains machine-readable protocol examples. The current corpus has only [`health-response.json`](fixtures/health-response.json).
- [`conformance/`](conformance/) contains language-neutral cases. The current [`cases.json`](conformance/cases.json) has only a health-response assertion.

These files are attachments to the specifications, not evidence of a complete SDK. They MUST contain synthetic, non-secret data and use explicit schema versions.

## Cross-cutting invariants

1. SDKs are untrusted clients; the server remains authoritative for every security decision.
2. SDKs consume public wire behavior only. The Rust SDK MUST NOT depend on internal OwlAuth server crates.
3. Generated models and low-level operations MAY follow OpenAPI; PKCE, refresh coordination, secure persistence integration, retries, and idiomatic errors remain explicitly designed behavior.
4. Credentials, codes, PKCE verifiers, tokens, cookies, and client secrets MUST NOT appear in default string/debug representations, logs, traces, fixtures, exception messages, or telemetry.
5. Automatic retry MUST be limited to demonstrably safe cases and MUST NOT replay an ambiguous one-use grant or refresh operation.
6. Equivalent server responses map to equivalent semantic error classes in every language.
7. Each SDK versions and ships independently from the server and other SDKs.
8. Current package/unit/conformance checks MUST be distinguished from future real-server, cross-language end-to-end tests. No fake E2E suite should be added before OAuth behavior exists.

## Normative language

`MUST`, `MUST NOT`, `SHOULD`, and `MAY` are normative design terms. Acceptance criteria define when a capability may be claimed. Language-specific APIs can differ in naming and async idiom while preserving these observable semantics.
