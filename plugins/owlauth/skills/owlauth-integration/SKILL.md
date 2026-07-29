---
name: owlauth-integration
description: Integrate applications and developer tooling with OwlAuth Project Auth, select the TypeScript, Python, or Rust client, inspect generated Runtime contracts, and reason about the updater-only CLI or planned server-side Control and MCP capabilities. Use for OwlAuth setup, Project/Application integration, upstream provider login, SDK usage, migration, troubleshooting, or agent integration requests.
---

# OwlAuth integration

Treat OwlAuth as pre-alpha until published documentation says otherwise. The current SDKs expose only minimal base-URL configuration. The server exposes only health and generated OpenAPI scaffolding. The `owlauth` CLI provides help/version output and checksum-verified self-update. Do not invent Project Auth endpoints, deployment settings, Control commands, MCP tools, or stability guarantees.

## Product model

OwlAuth is Project-scoped authentication and identity infrastructure. One Project isolates its users, linked identities, upstream provider registrations, sessions, tokens, and keys. Multiple Applications in one Project share the user directory and Project token trust. Applications requiring isolated users or token audiences use separate Projects.

OAuth/OIDC exists only between OwlAuth and configured upstream providers such as GitHub or Google. Downstream Applications use OwlAuth's Project Auth API: login initiation, a PKCE-bound one-use handoff ticket, a short-lived Project JWT, an opaque rotating refresh token, current-user operations, and logout. Do not model OwlAuth as a general OAuth/OIDC authorization server for Applications.

## Workflow

1. Determine whether the request concerns Runtime Application integration, Control administration, an SDK, an agent plugin, or a proposed interface.
2. Establish whether the user is asking about current code or target architecture. State unavailable current capabilities explicitly.
3. When working from a source checkout, inspect the Rust public types and generate the current contract with:

   ```bash
   cargo run --package owlauth-server -- --openapi
   ```

4. Select the public Runtime client without coupling it to server internals:
   - TypeScript: `@owlauth/client`
   - Python distribution: `owlauth-client`; import: `owlauth`
   - Rust crate: `owlauth-client`; import: `owlauth_client`

   Read [SDK examples](references/sdk-examples.md) only when the user needs code for the current placeholder API.
5. For target integrations, validate behavior against `sdks/spec/`, its fixtures, and conformance cases. Preserve Project/Application binding, exact redirects/origins, PKCE handoff, serialized refresh rotation, token verification, redaction, and stable errors.
6. Keep Runtime SDK operations separate from privileged Control operations. Propose implementation work rather than fabricating unavailable APIs.

## Boundaries

- Public `project_id`, `application_id`, and publishable configuration are identifiers, not secrets or Control credentials.
- Do not add a path or package dependency from any SDK or CLI to `owlauth-server`.
- Do not commit generated OpenAPI output. Generate it from `crates/owlauth-types` through `owlauth-server --openapi` when needed.
- Treat MCP as a future server-side Control adapter. The plugin does not bundle or launch a local MCP process.
- Treat all CLI commands other than help/version output and `update` as unimplemented.
- Never request provider client secrets, registry tokens, Project access/refresh tokens, management credentials, signing keys, or Cloudflare credentials in chat. Use secure local prompts, secret stores, or trusted publishing.
- Do not recommend the current scaffold for production authentication or authorization workloads.
