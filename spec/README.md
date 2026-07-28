# OwlAuth server specifications

This directory is the architecture-first, normative design index for the OwlAuth server. The documents describe intended boundaries and acceptance conditions; a requirement appearing here does **not** mean it is implemented.

OwlAuth is currently a pre-alpha scaffold. The server serves only a health endpoint (or emits a generated OpenAPI document), `owlauth-types` describes that health operation and a small OAuth error-code set, the CLI provides only checksum-verified self-update, and no OAuth authorization flow is implemented yet. These specifications guide implementation without representing production readiness.

User guides belong in [`docs/`](../docs/). Cross-language client requirements belong in [`sdks/spec/`](../sdks/spec/). Generated OpenAPI output, implementation plans, and test logs do not belong in this directory.

## Specification map

| Spec | Owning concern |
| --- | --- |
| [`01-system-context-and-goals.md`](01-system-context-and-goals.md) | actors, goals, scope, trust boundaries, and current-state baseline |
| [`02-domain-and-crate-boundaries.md`](02-domain-and-crate-boundaries.md) | domain ownership, crate dependency direction, and public/internal boundaries |
| [`03-oauth-protocol-and-security-invariants.md`](03-oauth-protocol-and-security-invariants.md) | OAuth 2.1 profile, protocol invariants, threat controls, and non-goals |
| [`04-storage-and-migrations.md`](04-storage-and-migrations.md) | persistence ownership, transactions, embedded automatic migrations, and recovery |
| [`05-openapi-contract-lifecycle.md`](05-openapi-contract-lifecycle.md) | Rust-authored HTTP contract, generated OpenAPI, compatibility review, and SDK handoff |
| [`06-operations-configuration-and-security.md`](06-operations-configuration-and-security.md) | startup, configuration, secrets, observability, deployment, and operational safety |
| [`07-cli-and-mcp-boundaries.md`](07-cli-and-mcp-boundaries.md) | current updater-only Rust CLI, planned management commands, and server-side MCP boundaries |
| [`08-delivery-validation-and-evolution.md`](08-delivery-validation-and-evolution.md) | test layers, release evidence, compatibility, and specification evolution |

This README is the ordered navigation map. Detailed requirements should have one owning document and be referenced rather than duplicated.

## Authority map

| Concern | Authority |
| --- | --- |
| Server-only identities, authorization concepts, policy, and persistence | Internal modules of `crates/owlauth-server`, as they are implemented |
| Public HTTP shapes and generated API description | Rust definitions in `crates/owlauth-types` |
| Schema migration assets | `crates/owlauth-server/migrations/` |
| Process composition and network serving | `crates/owlauth-server` |
| Public CLI and updater | `crates/owlauth-cli` |
| Language-neutral SDK behavior | [`sdks/spec/`](../sdks/spec/) plus a generated OpenAPI input |
| User-facing guidance | [`docs/`](../docs/) |

Specifications govern intended design. Executable code and tests reveal current implementation. A conflict must be resolved explicitly; documentation must never be used to imply that absent behavior exists.

## Cross-cutting invariants

1. OwlAuth MUST fail closed on malformed, expired, replayed, mismatched, or unauthorized OAuth state.
2. Authorization decisions MUST be made server-side from current authoritative state; SDKs, CLI callers, and MCP clients are untrusted inputs.
3. Secrets, authorization codes, access tokens, refresh tokens, PKCE verifiers, and session credentials MUST NOT appear in ordinary logs, generated contract examples, diagnostics, fixtures, or agent context.
4. External redirects MUST be exact-match validated against registered client metadata, subject only to protocol-defined exceptions adopted explicitly by OwlAuth.
5. Storage migrations MUST live under `crates/owlauth-server/migrations/`, be embedded in the executable, and run automatically before the server accepts requests. Migration failure MUST prevent serving.
6. Public OpenAPI is generated from reviewed Rust protocol definitions when needed and MUST NOT be committed as a generated artifact.
7. Internal crates are not an SDK contract. Every SDK consumes only the public protocol contract and follows independent SemVer.
8. The CLI is a separate Rust client surface and currently implements only verified self-update. Planned MCP support is a server-side adapter; plugins MUST NOT bundle or invent a local authorization server.
9. Network and storage side effects MUST be bounded, observable without disclosing secrets, and assigned explicit timeout and retry semantics.
10. No document or release artifact may claim implemented OAuth behavior or production suitability until validation demonstrates it.

## Normative language and status

`MUST`, `MUST NOT`, `SHOULD`, and `MAY` are normative design terms. Each document separates the **current baseline** from the **target contract**. Acceptance criteria are gates for claiming implementation, not statements that the gate already passes.
