---
name: owlauth-integration
description: Integrate applications and developer tooling with OwlAuth, select the TypeScript, Python, or Rust client, inspect the generated OpenAPI contract, and reason about planned CLI or server-side MCP capabilities. Use for OwlAuth setup, SDK usage, OAuth flow design, migration, troubleshooting, or agent integration requests.
---

# OwlAuth Integration

Treat OwlAuth as pre-alpha until published documentation says otherwise. The `0.0.1` clients reserve package names and expose only minimal client configuration; do not invent OAuth endpoints, deployment settings, CLI commands, MCP tools, or stability guarantees.

## Workflow

1. Determine whether the request concerns the server, an SDK, an agent plugin, or a proposed interface.
2. When working from a source checkout, inspect current Rust protocol definitions and generate the contract with:

   ```bash
   cargo run --package owlauth -- --openapi
   ```

3. Select the public client without coupling it to server internals:
   - TypeScript: `@owlauth/client`
   - Python distribution: `owlauth-client`; import: `owlauth`
   - Rust crate: `owlauth-client`; import: `owlauth_client`

   Read [SDK examples](references/sdk-examples.md) only when the user needs code for the current placeholder API.
4. Validate behavior against `sdks/spec/fixtures` and `sdks/spec/conformance`. Keep PKCE, refresh, and error mapping idiomatic and handwritten in each SDK.
5. State unavailable capabilities plainly and propose implementation work instead of fabricating usage instructions.

## Boundaries

- Do not add a Git path dependency from any SDK to a server-internal Rust crate.
- Do not commit generated OpenAPI output. Generate it from `crates/protocol` when needed.
- Treat MCP as a future server-side interface. The plugin does not bundle or launch a local MCP process.
- Treat a Rust CLI as planned, not implemented. Confirm its package and command names before creating the crate.
- Never request OAuth client secrets, registry tokens, signing keys, or Cloudflare credentials in chat. Use secure local prompts, secret stores, or trusted publishing.
- Do not recommend the current scaffold for production authorization workloads.
