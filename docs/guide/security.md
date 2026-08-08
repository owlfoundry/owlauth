# Security

OwlAuth handles authentication state, provider credentials, sessions, and signing operations. Its target architecture is fail-closed and Project-scoped.

::: warning Beta security scope
The current implementation includes the Project Auth, email, managed-provider, projection/webhook, persistence, token/session, Control, signer, secret-store, Hosted UI, and SDK safeguards described for its delivered scope, with real PostgreSQL/provider/browser validation. Beta is not security certification or a production support commitment. Operators must independently review deployment TLS/proxy, secret management, database roles, egress, observability, upgrades, and a tested PostgreSQL/external-store/key backup, PITR, and restore program before relying on it.
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

The optional remote Streamable HTTP MCP endpoint belongs to Control and reauthenticates the operator Bearer key on every request. A protected MCP host supplies the header; the key never enters prompts, model-visible context, tools/results, transport session IDs, or a local plugin/CLI process. Protocol tool discovery is not authorization.

### Provider and redirect boundary

Provider callbacks and Application redirects are different URL classes. Both are exact registered values. Wildcards, prefix matching, user-info confusion, redirect chaining, and caller-selected callback identities are forbidden.

External Runtime and callback origins derive from trusted configuration, never arbitrary `Host` or forwarding headers. This release has no trusted-forwarding mode and never uses `Forwarded` or `X-Forwarded-*` as client authority.

## Login and handoff invariants

The target flow binds Project, Application, provider registration, exact callback, exact Application redirect, Hosted Authentication UI interaction, policy revisions, and PKCE challenge in a short-lived PostgreSQL transaction.

- Application handoff requires PKCE `S256`; omitted or `plain` challenges fail.
- Upstream provider state is high entropy, one-use, and bound to the exact Project/provider transaction.
- Provider code exchange is claimed atomically and is not blindly retried after an ambiguous result.
- Provider issuer/signature/claims and stable subject are validated by a provider-specific adapter.
- Local identity lookup uses Project + provider issuer + provider subject—not email or profile fields.
- Matching email never silently links two users.
- Provider access tokens are transient. A renewable credential may be retained only as Project/identity/generation-bound encrypted material for adapter-declared bounded profile synchronization; it is never returned to Applications, accepted for caller-selected scopes, or retained in public profile data/webhooks.
- The final Application redirect carries only a short-lived, one-use, PKCE-bound handoff ticket.
- Reusing a valid same-Project browser session requires explicit CSRF-bound confirmation, current session/user/auth-age/policy checks, and a transaction-revision race against provider/email selection; page input cannot name the user/session.
- Handoff consumption and Application-session creation commit atomically. A losing exchange receives no token material.

## Email identity and Application synchronization

Passwordless email uses the same exact Application redirect and PKCE-bound handoff. After server-validated method selection, email challenge requests are enumeration-safe; canonical lookup uses a keyed digest; OTP and magic-link proofs are newest-generation, short-lived, attempt-bounded, and one-use. Challenge plus encrypted mail outbox pinned to one SMTP configuration generation and eligibility revision commit together. Proof completion revalidates that PostgreSQL status/revision, so a committed disable/compromise denies later proof even after physical delivery; SMTP delivery itself never proves identity. A matching provider email never links accounts without recent explicit proof of both identities.

Each Application receives only its policy-approved revisioned projection after its first successful handoff creates an Application-user binding. Webhook events commit durably with the projection mutation, are HMAC-signed, at-least-once, and may duplicate or arrive out of order. Receivers deduplicate immutable event IDs and compare the Application binding's `projection_revision`; `user_revision` separately identifies the Project-user base revision. Endpoint egress is exact/HTTPS, denies redirects and unsafe/private destinations by default, and webhook payloads never contain provider credentials, source payloads, SMTP data, or unrelated Project users. OwlAuth exposes no v1 Runtime directory, SCIM feed, or bulk export.

## Sessions, refresh, and revocation

A Project browser session is opaque, hardened, and Project/user/browser bound. New Projects allow explicit sign-in reuse among Applications in that Project by default, with a maximum authentication age of 8 hours; operators can disable reuse in Project policy. Application sessions and refresh families remain Application-bound.

Refresh tokens are high-entropy opaque values stored as digests. Every generation is one-use. At most one concurrent presentation creates a successor; later or concurrent reuse revokes the whole family. Core SDKs never blindly replay an ambiguous refresh; the Application or an external stateful integration serializes refresh per family, atomically replaces the credential pair, and treats an ambiguous lost response as reauthentication.

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

OwlAuth Core has no deployment-wide IP, route, tenant, global, bot/risk, traffic-shaping, or commercial quota subsystem. A SaaS or operator-owned ingress owns those generic controls and any `429` contract it adds. Core local connection, in-flight, pool, provider, and worker concurrency bounds protect resources but never establish identity authority; listener in-flight saturation uses deadline-bounded backpressure rather than a Core admission response. Passwordless email separately uses PostgreSQL to suppress a recent actual enqueue to the same canonical recipient within one Project and to cap active Project mail backlog. Suppression advances the real generation as terminal without an outbox and returns the same generic accepted response; it is protocol side-effect safety, not traffic admission or a tenant quota.

SQLx 0.9 embeds ordered migrations, uses its PostgreSQL history/checksum validation and startup locking, and applies them before readiness in default `auto` mode through a capability absent from normal serving pools. DDL-free `verify` mode checks exact compatibility. OwlAuth adds no second checksum subsystem, and SeaORM schema sync is disabled. Migration or schema incompatibility leaves business listeners unready.

## Backup and recovery

Treat PostgreSQL, the separately preserved software custody root or custom-provider authority, deployment identity and URLs, the operator credential, and every current or retained protection ring as one recovery set. Use PostgreSQL physical backup plus WAL archiving, or the equivalent managed-service point-in-time recovery facility, and continuously test restoration against the matched custody authority. A database-only backup is insufficient.

Keep all traffic blocked while restoring. Restore the custody/provider authority first, then PostgreSQL to the selected point, then the exact process configuration. Start the intended Auth replica set in an isolated network with `OWLAUTH_MIGRATION_MODE=verify`, require every started process's local `/ready`, independently verify deployment-level active/retained key convergence, and treat any live envelope that cannot open, signing handle that cannot sign and verify against its committed JWK, or missing long-term key as a recovery failure rather than generating a replacement. Confirm durable Auth worker recovery, then start the intended Control process or processes in `verify` mode and require each `/ready` before reopening traffic. Run any schema upgrade later as a separate reviewed operation. Backup scheduling and restore orchestration remain deployment responsibilities; follow the [deployment recovery checklist](/guide/deployment#backup-restore-and-disaster-recovery).

## Keys and secrets

Private signing and data-protection material remains behind Project-aware provider interfaces. PostgreSQL stores public JWKs plus bounded protected-material envelopes or opaque provider handles, never ordinary plaintext private keys or provider secret bytes.

Environment `*_KEY_VERSION` values select the active entry in one purpose-specific protection or digest ring; changing one is not a request to rotate all OwlAuth keys. New data uses the process-local active version while persisted rows retain their exact version and are read only through the matching active/retained entry. OwlAuth does not coordinate replica rollout, observe fleet convergence, backfill data, switch every process, or retire old versions. Operators must expand the readable set everywhere before activating a writer, preserve rollback material and every live dependency window, rewrap durable email identity and managed-credential material, prove zero references, and only then remove the old version everywhere. Project server-key digests cannot be rehashed because plaintext credentials are never stored. Project signing keys and provider/SMTP/webhook generations instead use their PostgreSQL-backed resource lifecycle APIs. The bundled `OWLAUTH_SOFTWARE_CUSTODY_KEY` is a separate static v1 root: it has no online rotation or retained set and must never be replaced in place. There is no generic “rotate all” endpoint; follow the [external key-ring rollout](/guide/deployment#auth-scaling-and-external-key-ring-rotation) separately for each purpose and preserve it with the recovery set.

A target Project signing key is published in Project JWKS before activation. Runtime reads eligible public material from current PostgreSQL authority; there are no replica publication leases or fleet-activation gate. Deployment rollout and external verifier cache observation remain operational responsibilities. Rotation keeps old public material through token and cache retention. Emergency revocation stops signing immediately after authoritative observation, while offline verifiers remain bounded by their JWKS cache behavior.

Remote signing-key effects use durable operation identities, database-time leases, provider inspection, and explicit cleanup. A non-retryable or unsupported cleanup remains fail-closed as blocked rather than discarding the handle or asserting destruction. After the exact retained provider implementation becomes available again, background signing-key maintenance resumes eligible work from the durable operation state; counters and the last provider-safe diagnostic remain durable. Never force the PostgreSQL row to an erased state or remove historical provider authority without provider-confirmed absence or destruction.

Secrets enter through protected environment/file descriptors, files, or secret managers—not ordinary CLI arguments, public configuration, health responses, panic messages, OpenAPI examples, or agent context.

## Browser and request safety

Auth serves the Runtime Hosted Authentication UI and JSON-only Server API; Control serves the Management Console. The Server API has no HTML, assets, redirects, cookies, or CORS grants. Auth and Control may use distinct origins or trusted disjoint non-root base paths on one origin while retaining separate listeners and credentials; Runtime and Server API remain isolated routers inside Auth. In the shared-origin form, Runtime cookies are path-contained so browsers do not send them to Control. Shared origin deliberately shares one browser/XSS trust boundary; distinct origins provide stronger isolation.

- Cookies use `Secure`, `HttpOnly`, host-only/narrow scope where possible, and reviewed `SameSite` behavior.
- Browser state changes use CSRF protection tied to the interaction/session.
- Both surfaces use restrictive CSP, framing, referrer, and cache policy, no third-party executable assets, and no service workers. Their React/Vite output is built and embedded separately per plane; Rust emits only external same-origin scripts/styles from validated manifests, and neither a generic SPA fallback nor one plane's asset tree can serve the other.
- Hosted authentication returns only to the exact stored Application redirect with a short-lived one-use PKCE-bound handoff; interaction handles and tickets are removed from browser history and redacted from referrers/logs before third-party navigation.
- The Management Console keeps the operator key only in active page memory, sends it only as a Bearer header under the configured Control base URL, and clears it on reload, close, lock, or authentication failure. Project server keys are one-time Control reveals for external secret-manager custody and are sent only by customer backends to the Server API surface.
- CORS is deny-by-default and exact Application-origin based; redirect navigation is not CORS authorization.
- Bodies, parsed headers/URIs, parameter counts, arrays, strings, decompression, in-flight requests, accepted connections, and deadlines are bounded independently for Auth and Control; Runtime and Server API additionally retain independent pools inside Auth. Configure the ingress proxy's parser and connection limits as an earlier complementary boundary.
- Duplicate singleton parameters, ambiguous encoding, unsupported media, and conflicting credentials fail consistently.

## Observability and data disclosure

Logs, traces, metrics, errors, audit events, generated examples, and agent context must never contain provider codes/tokens or renewable credentials, email addresses/OTP/magic tokens, SMTP credentials/message bodies, webhook secrets/bodies, handoff tickets, access/refresh tokens, PKCE verifiers, cookies, provider secrets, the operator API key, Project server-key credentials, private keys, full callback URLs, or complete profiles.

Redaction happens before serialization/export. Metrics use bounded-cardinality labels; `belongs_to`, provider subjects, arbitrary URLs, and user profiles are not labels. External errors carry stable safe codes and correlation IDs without revealing cross-Project existence or vendor internals.

## Operational posture

Auth and Control have separate plain-HTTP listeners, routers, ordinary HTTP budgets, and readiness; production TLS terminates at an operator-owned reverse proxy or load balancer. Runtime, Server API, and Control retain distinct authentication, state, PostgreSQL pools/quotas, and readiness inputs. Auth and Control cannot consume each other's request or connection semaphore; Runtime and Server API share Auth's listener transport budget but have independent PostgreSQL pools. OwlAuth does not trust `Forwarded` or `X-Forwarded-For` for authority; a reverse proxy must enforce its own source, traffic, and protocol policy before forwarding. Server API routes should be called only by intended customer backends, and Control should bind privately; network placement supplements rather than replaces authentication. See [Deployment](/guide/deployment) for the exact ingress and direct-peer consequences.

No business listener becomes ready before typed configuration, PostgreSQL/schema compatibility, and plane-critical key/data-protection capabilities are valid. Local capacity exhaustion fails before additional expensive work and never weakens an invariant.

For the complete target rules, see the [Project Auth flow specification](https://github.com/owlfoundry/owlauth/blob/main/spec/03-project-auth-flows-and-security-invariants.md), [operational security specification](https://github.com/owlfoundry/owlauth/blob/main/spec/06-operations-configuration-and-security.md), [identity connection/email/Application sync specification](https://github.com/owlfoundry/owlauth/blob/main/spec/11-identity-connections-passwordless-email-and-user-sync.md), and repository [`SECURITY.md`](https://github.com/owlfoundry/owlauth/blob/main/SECURITY.md).
