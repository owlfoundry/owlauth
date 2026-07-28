# 07 — Planned Rust CLI and server-side MCP boundaries

## Status

Neither a management CLI nor an MCP server is implemented in the current scaffold. Names, commands, tools, transports, and schemas are therefore not a public promise. Plugin documentation must continue to prevent agents from inventing them.

## Planned Rust CLI

A future CLI SHOULD be delivered as a distinct Rust crate and executable. It is an adapter/client, not an alternate home for domain or storage policy. Remote workflows use documented server interfaces; carefully designed local bootstrap or recovery workflows may compose internal application services only if their deployment and locking model is explicit.

The CLI may eventually support operator/developer tasks such as validated configuration diagnostics, server status, client registration management, key/migration inspection, and safe authorization testing. Each command requires a separate contract before implementation.

CLI invariants:

- secrets are read from a TTY prompt, protected file descriptor, or secret provider—not ordinary arguments or shell history;
- stdout supports deliberate human or machine modes, while diagnostics go to stderr;
- exit codes and machine output are stable and versioned;
- destructive actions require explicit targeting and confirmation, with a non-interactive equivalent that is difficult to trigger accidentally;
- remote TLS verification is on by default; insecure development modes are explicit and noisy;
- output redacts tokens, codes, secrets, cookies, verifiers, and signing material;
- the CLI cannot bypass server-side authorization by constructing internal-looking identifiers.

## Planned server-side MCP adapter

MCP is planned as an interface hosted by OwlAuth, behind the same domain policy and authoritative state as HTTP—not a local process bundled independently into every agent plugin. Deployment may expose an MCP transport only after its authentication and network model is specified.

MCP tools MUST expose narrowly scoped operator workflows, not raw database access, generic HTTP forwarding, arbitrary redirecting, unrestricted shell execution, or token/key export. Tool input is untrusted even when produced by a model. Every tool has bounded schemas, current authorization checks, explicit side effects, timeouts, rate controls, redacted results, and audit events.

High-impact mutations SHOULD use preview/confirm or an equivalent capability-bound two-step flow, with short expiry and revalidation at commit. Prompt text is never authorization. Human approval in a client UI does not replace server-side identity, permission, and freshness checks.

## Separation of surfaces

- CLI and MCP names/schemas are not inferred from HTTP OpenAPI automatically.
- MCP is not included in public SDK generation unless explicitly designed as a public HTTP contract.
- Agent plugins may provide discovery and setup guidance but MUST NOT request, relay, persist, or display credentials in agent context.
- CLI, HTTP, and MCP can share domain use cases; each adapter retains its own authentication, admission, serialization, and output constraints.
- Disabling MCP MUST NOT disable the core HTTP authorization server or require SDK changes.

## Compatibility

CLI machine output and MCP tool schemas require independent compatibility review. Tool removal, renamed arguments, changed confirmation semantics, or altered side effects are breaking even if the underlying domain API is unchanged. Capabilities SHOULD be discoverable without exposing privileged state.

## Acceptance criteria before either surface is advertised

- An accepted command/tool catalog defines actors, permissions, effects, bounds, errors, and audit events.
- Threat-model tests cover prompt injection, confused deputy, stale confirmation, privilege escalation, secret exfiltration, replay, and denial of service.
- End-to-end tests prove server-side policy is identical for equivalent actions across adapters.
- Package/plugin installation contains no hidden server binary or invented local MCP process.
- User guidance clearly labels available versus planned commands and tools.
