# Security policy

OwlAuth is pre-release security-sensitive software and does not yet provide a stable security-support window. The current scaffold does not implement Project login, persistence, sessions, token issuance, Control APIs, or MCP and must not be used for production authentication.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Report it through [GitHub private vulnerability reporting](https://github.com/owlfoundry/owlauth/security/advisories/new).

Include when possible:

- the affected package, image, version, commit, or endpoint;
- reproduction steps or a minimal proof of concept;
- the expected and observed behavior;
- confidentiality, integrity, or availability impact;
- whether credentials, Project boundaries, Runtime/Control separation, token handling, update verification, or release artifacts are involved;
- any suggested mitigation or disclosure constraints.

Do not include real provider secrets, Project tokens, refresh tokens, management credentials, signing keys, user data, or other third-party secrets. Use synthetic values and redact logs before attaching them.

## Security model

The target security invariants are documented in the [server architecture specifications](spec/README.md), especially the [Project authentication flow](spec/03-project-auth-flows-and-security-invariants.md), [operations and key lifecycle](spec/06-operations-configuration-and-security.md), and [cross-plane resilience](spec/08-consistency-resilience-and-plane-separation.md). SDK handling rules are defined in [`sdks/spec/07-security.md`](sdks/spec/07-security.md).

Those documents define requirements for future implementation; they are not security certification or a claim that the current pre-alpha scaffold satisfies the complete design.

## Supported versions

No OwlAuth version currently has a production support commitment. Published pre-alpha packages and images may change incompatibly and receive fixes only through a newer release. A formal supported-version and disclosure policy will be published before a stable production release.
