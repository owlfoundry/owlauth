# 01 — System context and goals

## Purpose

OwlAuth is intended to be a self-hostable OAuth 2.1 authorization server and user-management platform. It sits between resource owners, registered OAuth clients, operators, and resource servers. It issues security credentials only after applying protocol validation, authentication, consent, and policy.

## Current baseline

The repository is a pre-alpha scaffold, not an operational authorization server:

- `crates/owlauth-server` binds an HTTP listener, serves only `/health`, and can emit generated OpenAPI JSON.
- `crates/owlauth-types` currently describes `HealthResponse`, three OAuth error codes, and the `/health` OpenAPI operation.
- No domain authorization policy, database adapter, schema, or migration runner is implemented.
- `crates/owlauth-cli` provides version output and checksum-verified GitHub Release updates; it has no management or OAuth commands.
- SDK packages store a base URL but do not send requests or implement OAuth flows.

All flows and surfaces below are targets unless this baseline says otherwise.

## Actors and adjacent systems

| Actor/system | Relationship to OwlAuth | Trust position |
| --- | --- | --- |
| Resource owner | authenticates and grants authorization | browser and supplied data are untrusted |
| OAuth client | initiates authorization and exchanges grants | public/confidential status must be registered and verified |
| Resource server | validates or consumes issued credentials | separate enforcement boundary |
| Operator | configures clients, users, keys, policy, and runtime | privileged but actions remain validated and audited |
| SDK/CLI | convenience clients of public server interfaces | never trusted for authorization decisions |
| MCP client/agent | invokes a future constrained server-side adapter | high-risk, untrusted, and least-privilege |
| Database/key provider | persists state or protects signing material | privileged infrastructure dependency |

## Trust boundaries

1. **Public network boundary:** every request may be hostile. Parsing, size, timeout, origin, and rate controls precede domain effects.
2. **Browser redirect boundary:** front-channel parameters are attacker-controlled. Redirect destinations and transaction state require strict binding.
3. **Credential boundary:** passwords, keys, tokens, codes, and verifiers receive narrower access and stronger redaction than ordinary domain data.
4. **Persistence boundary:** stored state is not assumed internally consistent; constraints and domain validation both apply.
5. **Operator boundary:** administrative capability is authenticated, authorized, scoped, and auditable; deployment access alone is not a protocol shortcut.
6. **Agent boundary:** MCP prompts and tool arguments are untrusted and cannot gain raw secrets or bypass policy.

## Goals

- Implement a standards-led OAuth 2.1 profile with secure defaults and explicit extension adoption.
- Keep domain policy independent of HTTP frameworks, database engines, SDK languages, CLI presentation, and MCP transport.
- Generate a reviewable OpenAPI description from Rust protocol definitions without making generated files authoritative.
- Provide deterministic startup, automatic schema preparation, safe configuration, useful health signals, and redacted observability.
- Allow SDKs to share wire behavior while preserving idiomatic language APIs and independent release cadence.
- Evolve compatibility deliberately through tests, conformance data, migration policy, and SemVer.

## Non-goals for the current scaffold

The current repository does not promise production deployment, multi-tenancy, federation, social login, dynamic client registration, device authorization, token introspection, revocation, OIDC, SCIM, passkeys, an administrative HTTP API, CLI management commands, or MCP tools. Any such capability requires an explicit design and validation update before implementation or documentation can advertise it.

## Process model

The target server is one composed Rust process. Startup constructs configuration, secret/key providers, storage, domain services, and public adapters in dependency order. Migrations complete before listeners become ready. Graceful shutdown stops admission, drains bounded in-flight work, and releases resources. Horizontal coordination, if introduced, must not rely on process-local state for protocol correctness.

## Acceptance criteria

- Architecture diagrams and code dependencies agree with the trust boundaries and crate ownership in spec 02.
- Every exposed operation identifies actor, authorization rule, input bounds, persistent effects, and sensitive data.
- Product documentation labels unimplemented surfaces as planned.
- A runnable server is not called ready until the delivery gates in spec 08 pass.
