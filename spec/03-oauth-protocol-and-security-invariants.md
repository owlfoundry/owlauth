# 03 — OAuth 2.1 protocol and security invariants

## Status and profile

This document defines the intended security floor. OAuth endpoints and flows are **not implemented** in the current scaffold. Before implementation, the project MUST pin the standards and drafts that form its supported OAuth 2.1 profile and maintain an interoperability matrix. It MUST NOT advertise OpenID Connect unless OIDC discovery, identity-token, nonce, signing, and validation behavior receives a separate specification.

## Initial intended flow

The first implemented grant SHOULD be Authorization Code with PKCE. Supporting a flow requires its endpoints, metadata, client rules, errors, tests, and operational controls to be complete together. Password and implicit grants MUST NOT be introduced. Other grants are out of scope until specified.

## Authorization request invariants

- The server MUST validate a registered client and exact redirect URI before user interaction.
- PKCE MUST be required for public clients and SHOULD be required for every authorization-code client. `S256` is the accepted challenge method; `plain` MUST NOT be accepted.
- Requested scopes MUST be syntactically valid and restricted to client/policy allowance.
- Browser transaction state MUST be integrity protected, short lived, one-use, and bound to the initiating request, client, redirect URI, and user interaction.
- User authentication and consent MUST not be inferred from caller-supplied identifiers.
- Authorization errors MUST be returned only to a previously validated redirect URI; otherwise the server renders a local error and does not redirect.
- Client `state` is returned unchanged when the protocol permits but is never interpreted as server authority.

## Authorization code and token invariants

- Codes MUST be high entropy, short lived, single use, and bound to client, redirect URI, granted scopes, and PKCE challenge.
- Code verification and consumption MUST be atomic. Concurrent or replayed exchange fails without issuing multiple token sets.
- Confidential-client authentication MUST use a registered method and constant-time secret comparison where applicable. Credentials MUST NOT be accepted in query strings.
- The token endpoint MUST bind `code_verifier`, client identity, and redirect URI to the original grant.
- Access and refresh tokens MUST have cryptographically strong entropy or reviewed signatures, explicit audience/scope/expiry semantics, and key identifiers where relevant.
- Stored bearer credentials SHOULD be irreversible fingerprints when plaintext recovery is unnecessary.
- Refresh-token rotation MUST define one-use behavior, replay-family response, concurrency handling, and revocation before it is enabled.
- Error responses MUST follow the adopted OAuth profile, use stable machine codes, and omit sensitive diagnostic detail.

## Redirect, browser, and request safety

Redirect URI comparison is exact string matching against registered values, except any narrowly adopted loopback-native rule. Wildcards, substring matching, user-info confusion, and open redirect chaining are forbidden. Issuer and externally visible URLs come from trusted configuration, never an unvalidated `Host` or forwarding header.

State-changing browser operations require CSRF defenses appropriate to their session mechanism. Cookies, if used, require `Secure`, `HttpOnly`, suitable `SameSite`, narrow paths, and rotation. Pages MUST set restrictive CSP and framing policy. Secrets and authorization response values MUST not be loaded through third-party resources or retained in browser history beyond protocol necessity.

Request bodies, headers, parameter counts, and string lengths require bounds. Duplicate parameters, ambiguous encodings, and unsupported content types MUST be rejected consistently. Endpoints receive deadlines and endpoint-specific rate controls without revealing whether a user account exists.

## Cryptography and key lifecycle

Cryptographic algorithms and libraries MUST be reviewed, maintained, and configurable only within a safe allowlist. Randomness comes from the operating system CSPRNG. Key material is loaded through a secret/key-provider boundary, has stable identifiers, supports overlap during rotation, and is never included in logs or OpenAPI examples. Verification can continue for still-valid credentials during a planned rotation window; issuance uses the active key only.

## Logging and audit

Security events record time, operation, outcome, client or user references where policy allows, and correlation ID. They MUST NOT record passwords, client secrets, codes, tokens, refresh-token families in recoverable form, PKCE verifiers, cookies, or full authorization URLs. Audit integrity, access, and retention require operational policy.

## Acceptance criteria

- The supported standards/profile and endpoint set are explicitly versioned.
- Negative tests cover redirect confusion, PKCE downgrade, code replay/races, client mismatch, expiry boundaries, duplicate parameters, and secret redaction.
- Independent interoperability tests exercise every advertised flow.
- A threat-model review and security checklist pass before production-readiness language appears.
