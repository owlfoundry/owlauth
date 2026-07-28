# Security

OwlAuth is security-sensitive pre-release software. Do not use the current scaffold as a production authorization server. The target server invariants are defined in the [OAuth/security specification](https://github.com/owlfoundry/owlauth/blob/main/spec/03-oauth-protocol-and-security-invariants.md), and SDK handling rules are defined in the [SDK security specification](https://github.com/owlfoundry/owlauth/blob/main/sdks/spec/07-security.md); these are design requirements, not claims of current implementation.

Report suspected vulnerabilities through [GitHub private vulnerability reporting](https://github.com/owlfoundry/owlauth/security/advisories/new), not a public issue.

Registry and Cloudflare credentials belong only in GitHub Actions secrets or trusted-publishing identities. Never commit tokens, put them in release branches, or paste them into issues and pull requests.
