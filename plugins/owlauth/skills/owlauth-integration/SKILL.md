---
name: owlauth-integration
description: Integrate applications and developer tooling with OwlAuth Project Auth, select the TypeScript, Python, or Rust client, inspect generated Runtime or Server API contracts, and reason about the endpoint-discovered self-hosted CLI and remote HTTP MCP capabilities. Use for OwlAuth setup, Project/Application integration, upstream provider login, SDK usage, migration, troubleshooting, or agent integration requests.
---

# OwlAuth integration

Treat OwlAuth as Beta until published documentation says otherwise. The delivered self-hosted server includes PostgreSQL authority, an Auth endpoint with isolated Runtime and Server API surfaces plus an independent Control endpoint, Hosted Authentication and Management Console surfaces, GitHub/Google/strict custom OIDC and passwordless-email login, managed provider profile synchronization, Project session/token lifecycles, revisioned projections and signed webhooks, and optional remote Control MCP. The TypeScript, Python, and Rust SDKs implement only the public Runtime protocol while leaving navigation, persistence, refresh coordination, framework sessions, and backend JWT verification to the Application. Customer backends use the separate OpenAPI-only Project-key Server API. The `owlauth` CLI provides endpoint discovery, typed self-hosted administration, system inspection, and checksum-verified self-update. Preserve pre-1.0 and exact-coordinate evidence limits; do not invent deferred interfaces, CLI commands, MCP tools, compatibility ranges, deployment certification, or production support.

## Product model

OwlAuth is Project-scoped authentication and identity infrastructure. One Project isolates its users, linked identities, upstream provider registrations, sessions, tokens, and keys. Multiple Applications in one Project share the user directory and Project token trust. Applications requiring isolated users or token audiences use separate Projects.

OAuth/OIDC exists only between OwlAuth and configured upstream providers such as GitHub or Google. Downstream Applications use OwlAuth's Project Auth API: login initiation, a PKCE-bound one-use handoff ticket, a short-lived Project JWT, an opaque rotating refresh token, current-user operations, and logout. Do not model OwlAuth as a general OAuth/OIDC authorization server for Applications.

## Workflow

1. Determine whether the request concerns Runtime Application integration, backend Server API integration, Control administration, a Runtime SDK, an agent plugin, or a proposed interface.

2. Establish whether the user is asking about implemented behavior or explicitly deferred architecture. State unavailable capabilities precisely.

3. When working from a source checkout, inspect the Rust public types and generate separate current contracts with:

   ```bash
   make openapi
   ```

4. Select the public Runtime client without coupling it to server internals:

   - TypeScript: `@owlauth/client`
   - Python distribution: `owlauth-client`; import: `owlauth`
   - Rust crate: `owlauth-client`; import: `owlauth_client`

   Read [SDK examples](references/sdk-examples.md) when the user needs current protocol setup examples.

5. Validate integrations against `sdks/spec/`, its fixtures, conformance cases, and current package README. Preserve Project/Application binding, exact redirects/origins, PKCE handoff, serialized refresh rotation, backend token verification, redaction, and stable errors.

6. Keep Runtime SDK operations separate from backend-only Client operations and privileged Control operations. Do not imply that the core SDK owns browser navigation, history cleanup, persistence, refresh single-flight, backend sessions, or business authorization.

## Boundaries

- Public `project_id`, `application_id`, and publishable configuration are identifiers, not secrets or Control credentials.
- Do not add a path or package dependency from any SDK or CLI to `owlauth-server`.
- Do not commit generated OpenAPI output. Generate the plane-specific documents from `crates/owlauth-types` with `make openapi` when needed.
- Treat MCP as an optional remote Streamable HTTP Control adapter authenticated by the deployment operator key. The plugin never bundles, launches, downloads, supervises, or impersonates a local MCP process.
- Treat only documented CLI commands as implemented. The CLI discovers and pins the self-hosted server endpoint identity before reading the operator credential; it never guesses identity from an authenticated failure.
- Never request provider client secrets, registry tokens, Project access/refresh tokens, management credentials, signing keys, or Cloudflare credentials in chat. Use secure local prompts, secret stores, or trusted publishing.
- Present the delivered scope as Beta and pre-1.0, never as deployment-certified or production-supported authentication or authorization infrastructure. Operators retain hardening, monitoring, upgrade, backup, PITR, and restore responsibility.
