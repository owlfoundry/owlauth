# Security

OwlAuth handles authentication state, provider credentials, sessions, and signing operations. Its target architecture is fail-closed and Project-scoped.

::: danger Pre-alpha
Do not use the current scaffold for production authentication. The safeguards described below are architectural requirements, not implemented assurances. Today the server has only `/health` and OpenAPI generation; it has no Project Auth flow, persistence, token handling, Control API, key provider, or production configuration.
:::

Report suspected vulnerabilities through [GitHub private vulnerability reporting](https://github.com/owlfoundry/owlauth/security/advisories/new), not a public issue. Never include real credentials, tokens, provider callback values, or personal data in a report.

## Security boundaries

### Project boundary

A Project is the identity and token isolation boundary. Every Project-owned row, lookup, lock, uniqueness check, idempotency record, and transaction is qualified by authoritative `project_id`. Globally unique IDs are defense-in-depth, not a substitute.

Applications in one Project share users and Project token trust by design. Applications that need isolation use separate Projects. `belongs_to` metadata does not authorize or isolate anything inside OwlAuth.

### Runtime boundary

Every Runtime request is hostile until bounded, parsed, and resolved to an active Project/Application. Runtime accepts public IDs and publishable keys only as identifiers and abuse-attribution inputs; they never prove user or administrative authority.

### Control boundary

Control has a distinct listener and accepts only the single API key loaded from `OWLAUTH_CONTROL_API_KEY`. A valid Bearer key represents the deployment operator and has full Control authority; every command still resolves the explicit Project and revalidates current target revisions. The key is process configuration, not PostgreSQL state, and Control adapters cannot mutate tables directly.

Public IDs, Project access/refresh tokens, upstream provider credentials, network location, client-certificate identity, and forwarding headers are not Control credentials. Runtime never accepts the operator key.

### Provider and redirect boundary

Provider callbacks and Application redirects are different URL classes. Both are exact registered values. Wildcards, prefix matching, user-info confusion, redirect chaining, and caller-selected callback identities are forbidden.

External Runtime and callback origins derive from trusted configuration, never arbitrary `Host` or forwarding headers. Proxy headers are honored only from configured trusted proxies.

## Login and handoff invariants

The target flow binds Project, Application, provider registration, exact callback, exact Application redirect, Hosted Authentication UI interaction, policy revisions, and PKCE challenge in a short-lived PostgreSQL transaction.

- Application handoff requires PKCE `S256`; omitted or `plain` challenges fail.
- Upstream provider state is high entropy, one-use, and bound to the exact Project/provider transaction.
- Provider code exchange is claimed atomically and is not blindly retried after an ambiguous result.
- Provider issuer/signature/claims and stable subject are validated by a provider-specific adapter.
- Local identity lookup uses Project + provider issuer + provider subject—not email or profile fields.
- Matching email never silently links two users.
- Provider access and refresh tokens are transient, never returned to Applications, and never retained in public profile data.
- The final Application redirect carries only a short-lived, one-use, PKCE-bound handoff ticket.
- Handoff consumption and Application-session creation commit atomically. A losing exchange receives no token material.

## Sessions, refresh, and revocation

A Project browser session is opaque, hardened, and Project/user/browser bound. It may support sign-in reuse among Applications in that Project. Application sessions and refresh families remain Application-bound.

Refresh tokens are high-entropy opaque values stored as digests. Every generation is one-use. At most one concurrent presentation creates a successor; later or concurrent reuse revokes the whole family. SDKs serialize refresh per family and treat an ambiguous lost response as reauthentication.

Project, Application, user, browser session, policy, and signing revisions are revalidated before handoff or refresh commits. Project/user disablement invalidates all affected state; Application disablement affects only that Application. Already issued self-contained access tokens remain valid until short expiry unless a separately designed online check is used.

## Token verification

An Application backend must verify:

- an allowlisted signing algorithm and valid signature;
- `kid` against the exact Project JWKS;
- exact Project `iss` and `aud`;
- Project access-token `typ`;
- `iat`, `nbf`, and `exp` with bounded skew;
- Application/session context required by backend policy.

Never use unverified claims to select a permissive issuer, audience, algorithm, or key endpoint. An OwlAuth Project token is not an upstream OAuth access token and should not be sent to the provider.

## Durable authority and cache safety

PostgreSQL is authoritative for identity, one-use state, sessions, revocation, Project keys, and audit. The operator API key remains only in Control process configuration. Security mutations and required audit records commit in one transaction.

Redis may coordinate limits and cache public derived data. A cache hit cannot turn an authoritative denial into an allow. Redis never proves identity, consumes a ticket, rotates refresh, revokes a credential, activates a key, or establishes Project ownership.

SQLx 0.9 embeds ordered migrations, uses its PostgreSQL history/checksum validation and startup locking, and applies them before readiness in default `auto` mode through a capability absent from normal serving pools. DDL-free `verify` mode checks exact compatibility. OwlAuth adds no second checksum subsystem, and SeaORM schema sync is disabled. Migration or schema incompatibility leaves business listeners unready.

## Keys and secrets

Private signing and data-protection material remains behind Project-aware provider interfaces. PostgreSQL stores public JWKs and opaque key/secret references, not ordinary private keys or provider secret bytes. Redis stores no secret/key authority.

A target key is published in Project JWKS before activation. Runtime publication leases in PostgreSQL prove that ready instances loaded the revision; Redis invalidation is not proof. Rotation keeps old public material through token and cache retention. Emergency revocation stops signing immediately after authoritative observation, while offline verifiers remain bounded by their JWKS cache behavior.

Secrets enter through protected environment/file descriptors, files, or secret managers—not ordinary CLI arguments, public configuration, health responses, panic messages, OpenAPI examples, or agent context.

## Browser and request safety

Runtime serves the Hosted Authentication UI; Control serves the Management Console. They may use distinct origins or trusted disjoint non-root base paths on one origin while retaining separate internal listeners and credentials. In the shared-origin form, Runtime cookies are path-contained so browsers do not send them to Control. Shared origin deliberately shares one browser/XSS trust boundary; distinct origins provide stronger isolation.

- Cookies use `Secure`, `HttpOnly`, host-only/narrow scope where possible, and reviewed `SameSite` behavior.
- Browser state changes use CSRF protection tied to the interaction/session.
- Both surfaces use restrictive CSP, framing, referrer, and cache policy, no third-party executable assets, and no service workers. Their React/Vite output is built and embedded separately per plane; Rust emits only external same-origin scripts/styles from validated manifests, and neither a generic SPA fallback nor one plane's asset tree can serve the other.
- Hosted authentication returns only to the exact stored Application redirect with a short-lived one-use PKCE-bound handoff; interaction handles and tickets are removed from browser history and redacted from referrers/logs before third-party navigation.
- The Management Console keeps the operator key only in active page memory, sends it only as a Bearer header under the configured Control base URL, and clears it on reload, close, lock, or authentication failure.
- CORS is deny-by-default and exact Application-origin based; redirect navigation is not CORS authorization.
- Bodies, headers, URIs, parameter counts, arrays, strings, decompression, concurrency, and deadlines are bounded.
- Duplicate singleton parameters, ambiguous encoding, unsupported media, and conflicting credentials fail consistently.

## Observability and data disclosure

Logs, traces, metrics, errors, audit events, generated examples, and agent context must never contain provider codes/tokens, handoff tickets, access/refresh tokens, PKCE verifiers, cookies, provider secrets, the operator API key, private keys, full callback URLs, or complete profiles.

Redaction happens before serialization/export. Metrics use bounded-cardinality labels; `belongs_to`, provider subjects, arbitrary URLs, and user profiles are not labels. External errors carry stable safe codes and correlation IDs without revealing cross-Project existence or vendor internals.

## Operational posture

Runtime and Control use TLS directly or through declared trusted proxies, separate internal listeners, routers, budgets, PostgreSQL pools/quotas, readiness, and rate policy. Control should bind privately; network placement supplements rather than replaces authentication.

No business listener becomes ready before typed configuration, PostgreSQL/schema compatibility, and plane-critical key/data-protection capabilities are valid. Redis failure follows endpoint-specific bounded fallback or fail-closed behavior and never weakens an invariant.

For the complete target rules, see the [Project Auth flow specification](https://github.com/owlfoundry/owlauth/blob/main/spec/03-project-auth-flows-and-security-invariants.md), [operational security specification](https://github.com/owlfoundry/owlauth/blob/main/spec/06-operations-configuration-and-security.md), and repository [`SECURITY.md`](https://github.com/owlfoundry/owlauth/blob/main/SECURITY.md).
