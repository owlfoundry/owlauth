# 07 — SDK security

## Threat posture

SDKs execute inside applications that may log, crash, persist state, load plugins, follow redirects, or run concurrently. They reduce common misuse but cannot make a compromised application safe or replace server enforcement. Current packages do not implement OAuth and are not production authentication clients.

## Sensitive-value handling

Passwords, client secrets, authorization codes, access/refresh tokens, PKCE verifiers, cookies, and pending-transaction state are sensitive. SDKs MUST:

- redact them from string/debug/inspection output, errors, logs, traces, metrics, snapshots, and telemetry;
- avoid URLs and command-line arguments for credential transport except protocol-required front-channel parameters;
- minimize copies and lifetime where each language permits, without claiming guaranteed memory erasure from garbage-collected runtimes;
- exclude them from fixtures and examples;
- never enable body/header logging by default;
- provide allowlist-based diagnostics rather than “log everything” modes.

## Browser and native application boundaries

A browser redirect is untrusted input. SDK state validation follows spec 04 before exchange. Loopback listeners, custom schemes, universal/app links, or browser SDK storage each require a platform-specific threat design before support is claimed. The general SDK MUST NOT prescribe `localStorage` for tokens or embed confidential client secrets in distributed browser/mobile code.

Automatic browser launch is explicit. Authorization URLs should be displayed/logged only with awareness that query values can be sensitive; SDK logs redact the query by default.

## Transport and dependency security

TLS verification is enabled and redirects cannot leak authorization to another origin. Proxy and custom CA behavior are explicit. HTTP stacks, generators, cryptographic dependencies, and transitive packages are pinned/locked according to each ecosystem, scanned for advisories, and updated through reviewed changes.

Generated code is treated as supply-chain input: generator binaries/configuration are pinned, output is reproducible, and contract provenance is recorded. Package publication uses least-privilege trusted publishing where available and produces provenance/signatures according to repository release policy.

## Token-store boundary

Default behavior is memory-only unless documented otherwise. An application-supplied token store receives the minimum values required and defines encryption, access control, concurrency, backup, and deletion semantics. SDKs MUST NOT claim “encrypted storage” merely because an operating-system API is optional. Multi-process stores need atomic compare-and-swap for refresh rotation.

## Security testing and disclosure

Tests seed recognizable fake secrets through success and failure paths, then inspect output, logs, telemetry, and errors for disclosure. Fuzz/property tests cover URL parsing, OAuth callback parameters, malformed responses, and unknown enum/error values. Dependency and artifact scans supplement, not replace, protocol threat testing.

Vulnerabilities follow the repository's [`SECURITY.md`](../../SECURITY.md) private reporting path. Public issue templates and SDK exceptions must not solicit real credentials.

## Acceptance criteria

- Secret-redaction tests pass in every language and on generated models.
- Default transport rejects insecure production URLs/TLS and cross-origin credential redirects.
- Published artifacts are reproducible enough to trace source, dependencies, contract digest, and build job.
- Platform-specific storage/redirect support is not documented until its own security tests and guidance exist.
