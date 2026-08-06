# Security policy

OwlAuth is Beta security-sensitive software and does not yet provide a stable security-support window or production support commitment. The delivered self-hosted scope includes Project login, persistence, sessions and token issuance, isolated Runtime, Client, and Control APIs, hosted web surfaces, an optional remote Control MCP endpoint, and first-party protocol SDKs. Pre-1.0 interfaces, configuration, and operational requirements may change. Operators must independently harden and validate the complete deployment, including TLS/proxy policy, secrets, database roles, egress, observability, upgrades, and a tested PostgreSQL/external-store/key backup, PITR, and restore program.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Report it through [GitHub private vulnerability reporting](https://github.com/owlfoundry/owlauth/security/advisories/new).

Include when possible:

- the affected package, image, version, commit, or endpoint;
- reproduction steps or a minimal proof of concept;
- the expected and observed behavior;
- confidentiality, integrity, or availability impact;
- whether credentials, Project boundaries, Runtime/Client/Control separation, token handling, update verification, or release artifacts are involved;
- any suggested mitigation or disclosure constraints.

Do not include real provider secrets, Project tokens, refresh tokens, Project client keys, management credentials, signing keys, user data, or other third-party secrets. Use synthetic values and redact logs before attaching them.

## Security model

The target security invariants are documented in the [server architecture specifications](spec/README.md), especially the [Project authentication flow](spec/03-project-auth-flows-and-security-invariants.md), [operations and key lifecycle](spec/06-operations-configuration-and-security.md), and [cross-plane resilience](spec/08-consistency-resilience-and-plane-separation.md). SDK handling rules are defined in [`sdks/spec/07-security.md`](sdks/spec/07-security.md).

Those documents define the authoritative security requirements for delivered and future behavior. Neither implementation, repository tests, nor exact-artifact SDK evidence is security certification for a deployment.

## Supported versions

No OwlAuth version currently has a production support commitment. Published Beta packages and images remain pre-1.0, may change incompatibly with explicit release notes, and may receive fixes only through a newer release. A formal supported-version and disclosure policy will be published before a stable production release.
