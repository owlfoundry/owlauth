# 07 — Rust CLI and planned server-side MCP boundaries

## Current CLI status

`crates/owlauth-cli` is a distinct publishable Rust package. Its executable is `owlauth`; it does not depend on `owlauth-server`. The current pre-alpha command surface is deliberately small:

```text
owlauth --version
owlauth update [--version <SEMVER>] [--dry-run] [--force] [--install-dir <DIRECTORY>]
```

`update` discovers only stable `cli-v*` GitHub Releases, compares SemVer, and runs a release-pinned installer embedded in the current binary. Unix and PowerShell installers download the exact target archive and require a matching SHA-256 entry from the release's `SHA256SUMS`. The Windows updater stages the replacement and waits for the running process to exit before replacing it.

No operator, OAuth, storage, bootstrap, recovery, or local MCP command is currently implemented. Names and behavior for those future commands are not a public promise.

## CLI dependency and release boundary

The CLI is an adapter/client, not an alternate home for domain, storage, or authorization policy. Remote workflows use documented public server interfaces and remain subject to current server-side authentication and authorization.

Required dependency direction:

```text
owlauth-cli -X-> owlauth-server
owlauth-cli --> owlauth-client   # permitted when a real remote command needs it
```

CLI and server follow independent SemVer. A CLI release is triggered by `cli-v{version}` at the current `main` commit; the workflow derives the package version from that tag, publishes the `owlauth-cli` crate, and attaches platform archives, `SHA256SUMS`, and both installers to GitHub Releases. Supported installer targets and release artifacts MUST be identical. A release after the first MUST smoke-test update from the preceding compatible CLI release.

## CLI invariants

Future command implementations retain these requirements:

- secrets are read from a TTY prompt, protected file descriptor, or secret provider—not ordinary arguments or shell history;
- stdout supports deliberate human or machine modes, while diagnostics go to stderr;
- exit codes and machine output are stable and versioned;
- destructive actions require explicit targeting and confirmation, with a non-interactive equivalent that is difficult to trigger accidentally;
- remote TLS verification is on by default; insecure development modes are explicit and noisy;
- output redacts tokens, codes, secrets, cookies, verifiers, and signing material;
- the CLI cannot bypass server-side authorization by constructing internal-looking identifiers;
- installers fail closed when archive download, checksum download, checksum lookup, or digest verification fails;
- update discovery filters component tags and never uses the repository-wide latest release redirect.

A package-manager installation may need to direct users back to that package manager rather than overwriting managed files. Such source detection is required before advertising self-update as universally compatible.

## Planned server-side MCP adapter

MCP is planned as an interface hosted by OwlAuth, behind the same domain policy and authoritative state as HTTP—not a local process bundled independently into every agent plugin. Deployment may expose an MCP transport only after its authentication and network model is specified.

MCP tools MUST expose narrowly scoped operator workflows, not raw database access, generic HTTP forwarding, arbitrary redirecting, unrestricted shell execution, or token/key export. Tool input is untrusted even when produced by a model. Every tool has bounded schemas, current authorization checks, explicit side effects, timeouts, rate controls, redacted results, and audit events.

High-impact mutations SHOULD use preview/confirm or an equivalent capability-bound two-step flow, with short expiry and revalidation at commit. Prompt text is never authorization. Human approval in a client UI does not replace server-side identity, permission, and freshness checks.

## Separation of surfaces

- CLI and MCP names/schemas are not inferred from HTTP OpenAPI automatically.
- MCP is not included in public SDK generation unless explicitly designed as a public HTTP contract.
- Agent plugins may provide discovery and setup guidance but MUST NOT request, relay, persist, or display credentials in agent context.
- CLI, HTTP, and MCP can share internal server use cases only through appropriate adapters; each retains its own authentication, admission, serialization, and output constraints.
- Disabling MCP MUST NOT disable core HTTP authorization or require SDK changes.

## Compatibility

CLI machine output and MCP tool schemas require independent compatibility review. Tool removal, renamed arguments, changed confirmation semantics, altered update asset naming, or changed side effects may be breaking even if the underlying domain API is unchanged. Capabilities SHOULD be discoverable without exposing privileged state.

## Acceptance criteria before management CLI or MCP surfaces are advertised

- An accepted command/tool catalog defines actors, permissions, effects, bounds, errors, and audit events.
- Threat-model tests cover prompt injection, confused deputy, stale confirmation, privilege escalation, secret exfiltration, replay, and denial of service.
- End-to-end tests prove server-side policy is identical for equivalent operations across adapters.
- Package/plugin installation contains no hidden server binary or invented local MCP process.
- User guidance clearly labels available versus planned commands and tools.
