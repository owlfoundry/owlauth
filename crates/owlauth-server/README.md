# owlauth-server

The server library and `owlauth-server` executable for [OwlAuth](https://github.com/owlfoundry/owlauth), a self-hostable Project Auth and identity service.

OwlAuth isolates users, provider/email identities, managed profile connections, SMTP, Application projections/webhooks, sessions, tokens, and signing keys by Project. Applications and end users use the Runtime Project Auth API and Hosted Authentication UI, while operators use the separately exposed Control API and embedded Management Console. OAuth/OIDC is used only for upstream federation; OwlAuth is not a general-purpose downstream OAuth/OIDC authorization server.

> OwlAuth is pre-alpha. The executable provides production-shaped configuration, PostgreSQL migrations and pools, isolated Runtime/Control listeners, embedded browser assets, Control provisioning and user/session lifecycle operations, and federated Runtime Project Auth with strict OIDC, PKCE handoff, refresh rotation, and logout. Interfaces and deployment requirements may still change; evaluate and harden the complete deployment before production use.

## Run locally

From the repository root, copy the public disposable development configuration and start both
planes plus PostgreSQL and Redis:

```bash
cp .env.example .env
make dev
```

Runtime defaults to `http://127.0.0.1:8080/`; its liveness and readiness endpoints are `/health`
and `/ready`, and the Hosted Authentication UI shell is at `/auth/`. Control defaults to
`http://127.0.0.1:8081/`, with the Management Console at `/console/`. The fixed keys in
`.env.example` are public development values and must never be reused outside disposable local
state.

To compose both planes, configure independent listeners and a canonical operator key:

```bash
OWLAUTH_MODE=all \
OWLAUTH_INSTANCE_ID=local-development \
OWLAUTH_POSTGRES_URL=postgresql://owlauth:owlauth_dev@127.0.0.1:5432/owlauth \
OWLAUTH_CONTROL_API_KEY='owl_ctrl_v1_<43-character-base64url-secret>' \
OWLAUTH_RUNTIME_PROCESS_ID=local-runtime \
OWLAUTH_REQUIRED_RUNTIME_PROCESS_IDS=local-runtime \
OWLAUTH_SIGNER_STORE_ROOT=/absolute/path/to/owlauth/signers \
OWLAUTH_SIGNER_STORE_KEY='<43-character-base64url-wrapping-key>' \
OWLAUTH_CONFIGURATION_SECRET_STORE_ROOT=/absolute/path/to/owlauth/configuration-secrets \
OWLAUTH_CONFIGURATION_SECRET_STORE_KEY='<different-43-character-base64url-wrapping-key>' \
OWLAUTH_RUNTIME_KEY_VERSION=1 \
OWLAUTH_RUNTIME_DIGEST_KEY='<43-character-base64url-digest-key>' \
OWLAUTH_RUNTIME_PROTECTION_KEY='<different-43-character-base64url-protection-key>' \
OWLAUTH_EMAIL_IDENTITY_KEY_VERSION=1 \
OWLAUTH_EMAIL_IDENTITY_DIGEST_KEY='<independent-43-character-long-term-digest-key>' \
OWLAUTH_EMAIL_IDENTITY_PROTECTION_KEY='<independent-43-character-long-term-protection-key>' \
OWLAUTH_PROJECTION_EMAIL_KEY_VERSION=1 \
OWLAUTH_PROJECTION_EMAIL_DIGEST_KEY='<independent-43-character-projection-digest-key>' \
OWLAUTH_PROJECTION_EMAIL_PROTECTION_KEY='<independent-43-character-projection-protection-key>' \
OWLAUTH_MANAGED_REAUTHORIZATION_KEY_VERSION=1 \
OWLAUTH_MANAGED_REAUTHORIZATION_DIGEST_KEY='<dedicated-43-character-base64url-target-digest-key>' \
OWLAUTH_MANAGED_REAUTHORIZATION_PROTECTION_KEY='<dedicated-43-character-base64url-target-protection-key>' \
OWLAUTH_IDENTITY_MUTATION_EVIDENCE_KEY_VERSION=1 \
OWLAUTH_IDENTITY_MUTATION_EVIDENCE_DIGEST_KEY='<dedicated-43-character-base64url-evidence-digest-key>' \
OWLAUTH_IDENTITY_MUTATION_EVIDENCE_PROTECTION_KEY='<dedicated-43-character-base64url-evidence-protection-key>' \
OWLAUTH_MANAGED_CREDENTIAL_KEY_VERSION=1 \
OWLAUTH_MANAGED_CREDENTIAL_KEY='<separate-43-character-base64url-managed-credential-key>' \
OWLAUTH_ADMISSION_DIGEST_KEY='<stable-distinct-43-character-base64url-key>' \
OWLAUTH_PROVIDER_ALLOWED_ORIGINS='https://accounts.example/' \
  cargo run --package owlauth-server
```

Every key placeholder above must be replaced with exactly 43 unpadded base64url characters derived from 32 random bytes, and keys with different purposes must be distinct. Control defaults to `http://127.0.0.1:8081/`; its Management Console is at `/console/`. Control API calls require the configured key as an exact Bearer credential.

## Configuration

The process rejects unknown `OWLAUTH_*` variables and validates all selected-plane configuration before binding a listener.

| Variable                                    | Default                                           | Purpose                                                                                                                                                                                    |
| ------------------------------------------- | ------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `OWLAUTH_MODE`                              | `runtime`                                         | `runtime`, `control`, or `all` composition                                                                                                                                                 |
| `OWLAUTH_INSTANCE_ID`                       | required                                          | Stable deployment identity returned by Control discovery and used to derive the default Runtime admission namespace                                                                        |
| `OWLAUTH_RUNTIME_ADDR`                      | `127.0.0.1:8080`                                  | Runtime bind socket                                                                                                                                                                        |
| `OWLAUTH_RUNTIME_BASE_URL`                  | `http://127.0.0.1:8080/`                          | Canonical external Runtime base                                                                                                                                                            |
| `OWLAUTH_CONTROL_ADDR`                      | `127.0.0.1:8081`                                  | Control bind socket                                                                                                                                                                        |
| `OWLAUTH_CONTROL_BASE_URL`                  | `http://127.0.0.1:8081/`                          | Canonical external Control base                                                                                                                                                            |
| `OWLAUTH_CONTROL_API_KEY`                   | required for Control                              | `owl_ctrl_v1_` plus 43 base64url characters                                                                                                                                                |
| `OWLAUTH_CONTROL_MCP_ENABLED`               | `false`                                           | Mounts and advertises Control-base-relative `mcp`; requires HTTPS except exact loopback-IP development                                                                                     |
| `OWLAUTH_CONTROL_MCP_MAX_REQUEST_BYTES`     | `65536`                                           | MCP protocol-message body bound from 1 through `1048576` bytes, nested inside the global Control body bound                                                                                |
| `OWLAUTH_CONTROL_MCP_REQUEST_TIMEOUT_MS`    | `10000`                                           | MCP request deadline from 1 through `60000` milliseconds, nested inside the global Control deadline                                                                                       |
| `OWLAUTH_CONTROL_MCP_MAX_CONCURRENT_REQUESTS` | `16`                                            | MCP-specific fail-fast concurrency budget from 1 through `64`, nested inside the Control listener budget                                                                                  |
| `OWLAUTH_CONTROL_MCP_MAX_REQUESTS_PER_SECOND` | `64`                                            | Process-local authenticated MCP request-rate bound from 1 through `1024`; excess requests fail without entering protocol dispatch                                                         |
| `OWLAUTH_CONTROL_MCP_MAX_RESULT_BYTES`      | `65536`                                           | Maximum serialized structured tool result from 1 through `1048576` bytes                                                                                                                   |
| `OWLAUTH_SIGNER_STORE_ROOT`                 | required for Control and federated Runtime auth   | Absolute root for versioned encrypted software signer material                                                                                                                             |
| `OWLAUTH_SIGNER_STORE_KEY`                  | required for Control and federated Runtime auth   | 32-byte signer wrapping key encoded as 43 unpadded base64url characters                                                                                                                    |
| `OWLAUTH_CONFIGURATION_SECRET_STORE_ROOT`   | required for Control and federated Runtime auth   | Separate absolute root for encrypted provider configuration secrets                                                                                                                        |
| `OWLAUTH_CONFIGURATION_SECRET_STORE_KEY`    | required for Control and federated Runtime auth   | Separate 32-byte wrapping key encoded as 43 unpadded base64url characters                                                                                                                  |
| `OWLAUTH_RUNTIME_KEY_VERSION`               | required when Runtime is selected                 | Positive active version for generic Runtime interaction digest and data-protection material; Control-only does not parse or retain this ring                                              |
| `OWLAUTH_RUNTIME_DIGEST_KEY`                | required when Runtime is selected                 | Generic Runtime 32-byte active keyed-digest key encoded as 43 unpadded base64url characters                                                                                                |
| `OWLAUTH_RUNTIME_PROTECTION_KEY`            | required when Runtime is selected                 | Generic Runtime, distinct 32-byte active data-protection key encoded as 43 unpadded base64url characters                                                                                  |
| `OWLAUTH_RUNTIME_RETAINED_KEYS`             | unset                                             | JSON map of at most 15 retained short-term digest/protection versions needed only by unexpired transactions, challenges, sessions, and outbox rows                                         |
| `OWLAUTH_MANAGED_REAUTHORIZATION_KEY_VERSION` | required for every serving plane                | Positive active version of the purpose-limited managed-reauthorization interaction-target issuer/verifier ring                                                                            |
| `OWLAUTH_MANAGED_REAUTHORIZATION_DIGEST_KEY` | required for every serving plane                 | Dedicated 32-byte target-handle digest key, distinct from every generic Runtime, Runtime admission, and managed-credential root                                                            |
| `OWLAUTH_MANAGED_REAUTHORIZATION_PROTECTION_KEY` | required for every serving plane             | Dedicated 32-byte target-result AEAD key, distinct from the target digest key and every generic Runtime, Runtime admission, and managed-credential root                                    |
| `OWLAUTH_MANAGED_REAUTHORIZATION_RETAINED_KEYS` | unset                                         | JSON map of retained target digest/protection versions used only to replay and verify unexpired managed-reauthorization targets                                                            |
| `OWLAUTH_IDENTITY_MUTATION_EVIDENCE_KEY_VERSION` | required for every serving plane             | Positive active version of the narrow cross-plane identity-candidate evidence ring                                                                                                        |
| `OWLAUTH_IDENTITY_MUTATION_EVIDENCE_DIGEST_KEY` | required for every serving plane              | Dedicated 32-byte candidate-evidence digest key; Runtime can produce while Control can only verify                                                                                        |
| `OWLAUTH_IDENTITY_MUTATION_EVIDENCE_PROTECTION_KEY` | required for every serving plane          | Dedicated 32-byte candidate-evidence AEAD key; distinct from every active and retained root in all other authorities                                                                       |
| `OWLAUTH_IDENTITY_MUTATION_EVIDENCE_RETAINED_KEYS` | unset                                      | JSON map of at most 15 retained evidence digest/protection versions for in-flight mutation confirmation                                                                                   |
| `OWLAUTH_MANAGED_CREDENTIAL_KEY_VERSION`    | required when managed Runtime is selected         | Positive active version of the dedicated long-lived managed-provider credential AEAD ring; never configured as Control-only custody                                                       |
| `OWLAUTH_MANAGED_CREDENTIAL_KEY`            | required when managed Runtime is selected         | Dedicated 32-byte active managed-credential AEAD key, distinct from every active/retained Runtime digest and short-term protection key                                                     |
| `OWLAUTH_MANAGED_CREDENTIAL_RETAINED_KEYS`  | unset                                             | JSON map from retained positive versions to 43-character managed-credential AEAD keys required until inventory and rewrap prove retirement safe                                          |
| `OWLAUTH_ADMISSION_DIGEST_KEY`              | required when Runtime is selected                 | Stable, independent 32-byte admission digest root encoded as 43 unpadded base64url characters; keep unchanged across Runtime protection-key rotations                                     |
| `OWLAUTH_EMAIL_IDENTITY_KEY_VERSION`        | email capability unavailable when omitted         | Positive active version for the independently retained long-term email lookup/PII ring                                                                                                     |
| `OWLAUTH_EMAIL_IDENTITY_DIGEST_KEY`         | required with email identity key version          | Independent 32-byte long-term email identity digest root; must not equal any short-term or retained root                                                                                    |
| `OWLAUTH_EMAIL_IDENTITY_PROTECTION_KEY`     | required with email identity key version          | Independent 32-byte long-term email identity AEAD root; must not equal any other active or retained root                                                                                    |
| `OWLAUTH_EMAIL_IDENTITY_RETAINED_KEYS`      | unset                                             | JSON map of at most 15 independently retained older long-term email identity digest/AEAD versions                                                                                          |
| `OWLAUTH_PROJECTION_EMAIL_KEY_VERSION`      | required for every serving plane                  | Positive active version for the narrow verified-email projection field ring                                                                                                                |
| `OWLAUTH_PROJECTION_EMAIL_DIGEST_KEY`       | required for every serving plane                  | Independent 32-byte verified-email projection digest key encoded as 43 unpadded base64url characters                                                                                      |
| `OWLAUTH_PROJECTION_EMAIL_PROTECTION_KEY`   | required for every serving plane                  | Independent 32-byte verified-email projection AEAD key encoded as 43 unpadded base64url characters                                                                                        |
| `OWLAUTH_PROJECTION_EMAIL_RETAINED_KEYS`    | unset                                             | JSON map of retained projection digest/protection versions required until roster observation and ciphertext inventory prove retirement safe                                                |
| `OWLAUTH_PROJECTION_EMAIL_CUTOVER_VERSION`  | unset                                             | Explicit deployment-wide projection write cutover authorization                                                                                                                            |
| `OWLAUTH_PROJECTION_EMAIL_RETIRE_VERSION`   | unset                                             | Separate retire-only authorization after every required Runtime observation and predecessor reference clears                                                                              |
| `OWLAUTH_EMAIL_IDENTITY_ALIAS_CUTOVER_VERSION` | unset                                          | Explicit email-identity lookup-alias write cutover or pre-retirement rollback; must equal the active email identity version and cannot coexist with retirement                              |
| `OWLAUTH_EMAIL_IDENTITY_ALIAS_RETIRE_VERSION` | unset                                           | Later retire-only rollout after every live Runtime has durably observed post-cutover overlap                                                                                                |
| `OWLAUTH_PROVIDER_ALLOWED_ORIGINS`          | required when Runtime is selected                 | Comma-separated canonical HTTPS origins admitted for OIDC discovery and endpoints                                                                                                          |
| `OWLAUTH_PROVIDER_ALLOW_HTTP_LOOPBACK`      | `false`                                           | Development-only opt-in for exact `127.0.0.1` or `::1` HTTP origins in the provider allowlist; never admits hostnames or non-loopback addresses                                            |
| `OWLAUTH_RUNTIME_PROCESS_ID`                | required when Runtime is selected                 | Stable URL-safe identity used by this Runtime process when publishing observation leases                                                                                                   |
| `OWLAUTH_REQUIRED_RUNTIME_PROCESS_IDS`      | Runtime process ID; required in Control-only mode | Comma-separated deployment roster; every Runtime-capable process must include itself, every required member must lease the revision, and any additional live stale lease blocks activation |
| `OWLAUTH_ADMISSION_REDIS_URL`               | unset                                             | Optional secret-redacted `redis` or `rediss` URL for atomic deployment-wide Runtime admission counters                                                                                    |
| `OWLAUTH_ADMISSION_NAMESPACE`               | digest of `OWLAUTH_INSTANCE_ID`                   | 1-64 character deployment-unique Redis key namespace containing only alphanumeric, underscore, or hyphen characters                                                                       |
| `OWLAUTH_ADMISSION_REDIS_TIMEOUT_MS`        | `100`                                             | Per-operation Redis admission deadline, from `10` through `2000` milliseconds                                                                                                             |
| `OWLAUTH_RUNTIME_MAX_PROCESSES`             | required Runtime roster size                      | Conservative upper bound from the roster size through `64`; divides every local fallback quota without aggregate over-allocation                                                          |
| `OWLAUTH_DEPLOYMENT_SMTP_GENERATION`        | all deployment SMTP fields unset                  | Positive immutable generation number for the deployment-default SMTP registry                                                                                                              |
| `OWLAUTH_DEPLOYMENT_SMTP_STATUS`            | all deployment SMTP fields unset                  | Desired `reconciled`, `active`, `disabled`, or `compromised` status; disabled/compromised reconciliation never requires readable credentials                                               |
| `OWLAUTH_DEPLOYMENT_SMTP_HOST`              | all deployment SMTP fields unset                  | Canonical DNS relay hostname; IP literals are rejected                                                                                                                                      |
| `OWLAUTH_DEPLOYMENT_SMTP_PORT`              | all deployment SMTP fields unset                  | Non-zero relay TCP port                                                                                                                                                                     |
| `OWLAUTH_DEPLOYMENT_SMTP_TLS_MODE`          | all deployment SMTP fields unset                  | `implicit_tls` or mandatory `starttls_required`; no deployment-default plaintext mode                                                                                                      |
| `OWLAUTH_DEPLOYMENT_SMTP_SENDER_ADDRESS`    | all deployment SMTP fields unset                  | Canonical envelope sender address                                                                                                                                                           |
| `OWLAUTH_DEPLOYMENT_SMTP_CREDENTIAL_REF`    | all deployment SMTP fields unset                  | Opaque alias in the external encrypted configuration-secret store; PostgreSQL never stores credential bytes                                                                                |
| `OWLAUTH_DEPLOYMENT_SMTP_SAFE_FINGERPRINT`  | all deployment SMTP fields unset                  | Exactly 64 hexadecimal characters matching the externally stored credential; checked before reconciled/active startup                                                                      |
| `OWLAUTH_DEPLOYMENT_SMTP_ALLOWED_PRIVATE_IPS` | unset                                           | Comma-separated, at most 16 exact private relay addresses; cannot override loopback, mapped, link-local, metadata, multicast, unspecified, or other unconditional destination denies       |
| `OWLAUTH_WEBHOOK_ALLOWED_PRIVATE_IPS`        | unset                                             | Comma-separated, at most 16 exact private webhook addresses; every DNS answer must pass and unconditional destination and listener denies still apply                                      |
| `OWLAUTH_WEBHOOK_EXTRA_ROOT_CERT_DER_FILE`   | unset                                             | Absolute path to one bounded DER trust anchor for private-CA HTTPS webhook destinations; TLS hostname verification and every egress restriction remain enforced                            |
| `OWLAUTH_PUBLICATION_LEASE_TTL_MS`          | `30000`                                           | Runtime key-publication lease lifetime; draining stops renewal and waits for expiry                                                                                                        |
| `OWLAUTH_KEY_PROPAGATION_DELAY_MS`          | `2000`                                            | Minimum all-live-process observation interval and retirement propagation margin; maximum `86400000`                                                                                        |
| `OWLAUTH_SIGNING_VERIFICATION_RETENTION_MS` | `1200000`                                         | Additional clock-skew and advertised JWKS-cache retention added to the 3600-second token maximum; maximum `86400000`                                                                       |
| `OWLAUTH_POSTGRES_URL`                      | required                                          | Serving PostgreSQL URL and authority anchor                                                                                                                                                |
| `OWLAUTH_RUNTIME_POSTGRES_URL`              | serving URL                                       | Runtime pool URL on the same database authority                                                                                                                                            |
| `OWLAUTH_CONTROL_POSTGRES_URL`              | serving URL                                       | Control pool URL on the same database authority                                                                                                                                            |
| `OWLAUTH_MIGRATION_POSTGRES_URL`            | serving URL                                       | Dedicated migration connection URL on the same authority                                                                                                                                   |
| `OWLAUTH_MIGRATION_MODE`                    | `auto`                                            | `auto` applies migrations; `verify` performs a DDL-free checksum-prefix and compatibility-floor check                                                                                                                |
| `OWLAUTH_MIGRATION_OWNER_ROLE`              | unset                                             | Validated PostgreSQL role selected for migration DDL                                                                                                                                       |
| `OWLAUTH_DATABASE_CONNECT_TIMEOUT_MS`       | `5000`                                            | Database connection deadline                                                                                                                                                               |
| `OWLAUTH_MIGRATION_LOCK_TIMEOUT_MS`         | `30000`                                           | Advisory migration-lock deadline                                                                                                                                                           |
| `OWLAUTH_RUNTIME_DATABASE_MAX_CONNECTIONS`  | `20`                                              | Runtime pool bound                                                                                                                                                                         |
| `OWLAUTH_CONTROL_DATABASE_MAX_CONNECTIONS`  | `5`                                               | Control pool bound                                                                                                                                                                         |
| `OWLAUTH_REQUEST_TIMEOUT_MS`                | `10000`                                           | HTTP request deadline                                                                                                                                                                      |
| `OWLAUTH_MAX_REQUEST_BYTES`                 | `1048576`                                         | Request body limit                                                                                                                                                                         |
| `OWLAUTH_SHUTDOWN_TIMEOUT_MS`               | `10000`                                           | Graceful drain deadline                                                                                                                                                                    |

## Upstream provider profiles

Provider creation names one closed adapter kind; dispatch never falls back from a named adapter to generic OIDC semantics:

- `oidc` accepts a canonical issuer other than the reserved Google and GitHub issuers. Discovery and every advertised endpoint must pass `OWLAUTH_PROVIDER_ALLOWED_ORIGINS`. Login uses `openid profile`; optional managed profile synchronization adds the fixed `offline_access` scope and retains only the server-side renewable credential needed for bounded UserInfo refresh.
- `google` requires the exact issuer `https://accounts.google.com` and uses strict OIDC validation with fixed Google discovery, token, UserInfo, and authorization origins. Managed profile synchronization requests exactly `openid profile` plus Google's `access_type=offline` and `prompt=consent` authorization parameters; it does not invent the unsupported `offline_access` scope. Callers cannot request additional Google scopes or use OwlAuth as a token broker.
- `github` requires the exact issuer `https://github.com`, uses fixed GitHub authorization/token/user endpoints, requests exactly `read:user`, and keys identity only by the immutable nonzero numeric REST user ID. It is login-only: identity-mutation proof and managed profile synchronization are unsupported, and no renewable provider credential is retained.

Provider client secrets are write-only Control inputs stored through the encrypted configuration-secret store. Public capability responses expose the selected kind and that adapter's exact managed-profile support/scopes, but never secret or upstream token material. Every adapter applies one Runtime callback policy: HTTPS, plus exact IP-literal loopback HTTP only when the explicit development opt-in is enabled; upstream endpoint-origin policy remains independently adapter-specific.

Runtime business endpoints use fixed-window, endpoint-specific admission before PostgreSQL, provider, or signer work. Redis uses its own clock for window selection, and keys contain only the configured namespace, schema/endpoint labels, fixed-window number, and digests derived from the stable admission-only root; raw client addresses, Project/Application IDs, cookies, tokens, states, provider keys, and handoffs are never key material. Every accepted request also consumes the process's bounded monotonic rolling-window local share divided by `OWLAUTH_RUNTIME_MAX_PROCESSES`. If Redis is absent, unavailable, times out, loses counters, or returns an invalid result, that same local guard remains authoritative and the process stays on fallback through the current local window, so backend transitions cannot add quota. Active local entries are never evicted; capacity saturation fails closed until monotonic expiry. Client/Project/Application/interaction quota or capacity rejection returns `429 rate_limited` with bounded `Retry-After`. Only a sole saturated server-derived Project/Application-scoped keyed-address bucket commits an ordinary random-proof challenge with the same response, Hosted state, resend, expiry, newest/sibling, invalid-proof, and revision behavior while recording a terminal `policy_denied` outbox disposition that workers cannot claim; it neither calls SMTP nor logs/labels the address or bucket. Provider callbacks additionally use a reviewed process-local budget of 16 concurrent outbound exchanges; capacity exhaustion fails before provider dispatch and terminally fails the already-claimed callback rather than creating a waiting queue. Redis is not a concurrency lock or authority. CORS preflight, liveness/readiness, roots, shells, and immutable assets do not consume business buckets.

When Runtime and Control share an external origin, their configured base paths must be disjoint and non-root. Separate origins remain recommended.

Remote MCP is disabled by default. When enabled, the descriptor publishes the canonical Control-base-relative `mcp` URL and the Control listener exposes an MCP Streamable HTTP endpoint backed by `rmcp`. The initial catalog is deliberately stateless, JSON-response, tools-only, and hand-designed: eight read-only tools cover system capabilities, Project/Application inventory, projection policy, and webhook endpoint/delivery inspection; the only mutation is a high-impact projection-policy update exposed exclusively as preview and commit tools. It creates no server session, exposes no prompts or resources, and has no stdio or child-process transport. Every HTTP request must carry the same exact operator Bearer key as Control REST; authentication occurs before protocol parsing, and the adapter removes the Authorization header before MCP dispatch. Configured external Host and optional Origin values are validated. Preview returns one raw high-entropy capability while PostgreSQL stores only its digest, bound to the deployment instance, exact MCP endpoint, Control audience, exact commit tool and command, Project metadata revision, and target revision. PostgreSQL-clock expiry, one-use consumption, the conditional policy mutation, expansion operation, and deployment-operator audit are enforced in one transaction; no direct mutation alias exists.

Deployment SMTP fields are an all-or-none process registry. Startup reconciles immutable metadata into PostgreSQL, pins every email challenge and outbox row to a generation plus eligibility revision, and does not emit another audit event when the desired record is unchanged. Activation retains predecessor metadata for bounded proof compatibility, but generation `n+1`, replacement, disable, or compromise serializes with the fully fenced worker transition and prevents every later claim of stale generation `n` immediately. Operators can inspect and terminally disable/compromise generations through `/v1/system/smtp-default-generations`; process configuration must also be changed before restart or its declared desired state will be reconciled again. In split-plane deployments, every Runtime-capable process and the Control process must receive identical non-secret generation metadata, while the referenced encrypted secret must be distributed only to processes that send or validate active mail. Secret bytes never enter PostgreSQL, logs, audit context, or Control responses.

Runtime retains protected challenge addresses and outbox envelope/body payloads only while they are useful plus a fixed 10-minute terminal investigation window. Bounded Runtime maintenance terminalizes abandoned or exhausted work, irreversibly sets those ciphertext/key-version columns to `NULL`, and deletes expired or terminal magic transfer contexts while retaining safe statuses, timestamps, message IDs, and audit metadata. Each cleanup class runs in an independently timed transaction under a shared 100-row/200 ms tick budget. A cleanup timeout is reported and retried but cannot prevent the same worker tick from claiming due mail.

Runtime uses two independent protection inventories and lifecycles. The short-term `OWLAUTH_RUNTIME_*` ring protects interactions, challenges, and outbox payloads; remove a predecessor from `OWLAUTH_RUNTIME_RETAINED_KEYS` only after the short-term inventory is clear. The durable `OWLAUTH_EMAIL_IDENTITY_*` ring protects encrypted identity addresses and lookup aliases; first rewrap identity PII, backfill and retire aliases under the durable active version, verify the durable inventory is clear, and only then remove that predecessor from `OWLAUTH_EMAIL_IDENTITY_RETAINED_KEYS`. Clearing one inventory never authorizes retirement from the other ring. Missing short-term material is terminalized without cross-purpose fallback; missing durable email-identity material fails readiness closed because silently discarding or substituting identity data would break uniqueness and recovery. Durable active plus retained versions are capped at 16 so every login can atomically backfill the complete accepted alias set. All `OWLAUTH_EMAIL_IDENTITY_*` settings, including long-term secrets and alias rollout flags, are Runtime-only; Control-only configuration explicitly rejects them and must never receive their values.

### Email identity alias cutover runbook

Treat `OWLAUTH_EMAIL_IDENTITY_ALIAS_CUTOVER_VERSION` as a deployment-wide, explicitly staged operation rather than an ordinary rolling environment change:

1. Add the new durable digest and protection keys as the active Runtime version while retaining every old durable version in `OWLAUTH_EMAIL_IDENTITY_RETAINED_KEYS`. Leave the cutover variable unset. Deploy this readable-key set only to the complete split-topology Runtime roster; never send it to Control's validation path. Keep the separate short-term `OWLAUTH_RUNTIME_*` ring unchanged unless it is undergoing its own independently inventoried rotation.
2. Confirm `OWLAUTH_REQUIRED_RUNTIME_PROCESS_IDS` exactly names every Runtime-capable process. Wait until every required process has a live observation lease for the current email-alias authority revision and active key version. An extra live process, a missing roster member, or a stale revision blocks cutover.
3. Drain stale Runtime nodes: stop new traffic and workers, stop lease renewal, wait for the publication lease to expire, and verify the node no longer appears in the live observation set. Do not bypass the roster check.
4. Set `OWLAUTH_EMAIL_IDENTITY_ALIAS_CUTOVER_VERSION` to the active `OWLAUTH_EMAIL_IDENTITY_KEY_VERSION` on the complete Runtime roster. `OWLAUTH_EMAIL_IDENTITY_ALIAS_RETIRE_VERSION` must remain unset; configuration parsing rejects both flags together. Restart or roll only after all members have the readable key set. The authority changes `write_version` only when the exact live roster has observed the predecessor revision; it deliberately keeps both predecessor and new versions in `accepted_versions` and deletes no predecessor rows.
5. Remove the cutover flag, keep all old keys, and leave the retirement flag unset. Run bounded verification/backfill until every durable email identity has the new alias and active-version address protection, no conflict is reported, and every required Runtime process observes the **post-cutover** authority revision. PostgreSQL then records an exact `overlap_verified_revision`. Cutover and this observation phase never collapse `accepted_versions` or delete an alias, so this remains a durable rollback window.
6. If verification fails, roll back before retirement by making the predecessor key version active (while retaining the newer key), setting `OWLAUTH_EMAIL_IDENTITY_ALIAS_CUTOVER_VERSION` to that predecessor version, and waiting for exact-roster/backfill convergence. The authority records a rollback write-version transition while both alias sets remain accepted. Unsetting a variable alone is not a rollback, and rollback is unavailable after retirement authorization.
7. Only after the durable overlap-verification revision exists and every Runtime has observed it, begin a later deployment with **only** `OWLAUTH_EMAIL_IDENTITY_ALIAS_RETIRE_VERSION` set to the active version. Every live/required process must transition from retirement unset to set at or after that exact revision. A flag pre-set before observation remains durably stale and must be rolled off before this rollout. Only the complete later roster authorization records a retirement revision, collapses `accepted_versions`, and begins bounded predecessor deletion.
8. Verify the durable alias and email-identity protection inventories contain no predecessor references, then remove the predecessor durable digest/protection material from `OWLAUTH_EMAIL_IDENTITY_RETAINED_KEYS`. Independently, remove a predecessor from `OWLAUTH_RUNTIME_RETAINED_KEYS` only after the short-term challenge/outbox inventory for that ring is clear; neither inventory substitutes for the other.

This ordering is mandatory in combined and split deployments: Runtime-only readable-key rollout, exact Runtime-roster observation, stale-node drain, cutover-only write transition with overlap, cutover flag removal, durable post-cutover overlap verification, later retire-only complete-roster authorization, bounded alias retirement, then durable protector retirement. Simultaneous/pre-authorized cutover and retirement is invalid. The required Runtime roster, requested cutover/retirement versions, observation revisions, and authority events are non-secret operational metadata, but the `OWLAUTH_EMAIL_IDENTITY_*` environment settings remain confined to Runtime; Control observes only the persisted non-secret lifecycle state exposed by its authorized operational surface.

## Backup, point-in-time recovery, and verify restart

Backup scheduling, WAL archiving, restore orchestration, and retention policy belong to the deployment rather than this executable. A recoverable OwlAuth backup is nevertheless one reviewed set, not a PostgreSQL dump alone:

- a transactionally consistent PostgreSQL base backup or managed snapshot plus the WAL needed for the selected point in time;
- the signer store and configuration-secret store, including every active, overlap, retained, pending, and cleanup-fenced generation still referenced by PostgreSQL;
- the exact instance ID, Runtime and Control external URLs, operator key, wrapping keys, current and retained protection-key rings, provider/SMTP/webhook references, and other process configuration used at that point.

Use PostgreSQL-native physical backup/PITR or the equivalent managed-service facility, continuously test restoration on an isolated deployment, and select a recovery point for which the matching external material is available. Redis is non-authoritative and is not restored as identity state.

A recovery proceeds in this order:

1. Stop admission on every Runtime and Control process and keep external traffic blocked.
2. Restore the signer and configuration-secret stores and make their matched generations available without rotating, reprovisioning, or changing aliases.
3. Restore PostgreSQL to the selected consistent point in time. Do not run manual schema edits or SeaORM schema synchronization.
4. Restore the exact deployment identity, external URLs, operator credential, wrapping keys, and retained protection rings. Start with `OWLAUTH_MIGRATION_MODE=verify`; recovery must not apply DDL.
5. Start one isolated Runtime or Control process, require `/ready`, and inspect logs plus the relevant Control reads. A missing signer, referenced external secret, or long-term protection key is a recovery failure; do not bypass the purpose-scoped fail-closed state by generating replacements.
6. Start the remaining split-plane processes in `verify` mode, confirm the required Runtime roster and durable outbox/lease recovery, then reopen traffic. Redis may start empty or under a fresh namespace.

After the restored deployment is stable, run an ordinary reviewed upgrade separately if a newer schema is desired. Never combine PITR with an unreviewed migration or identity/issuer change.

## OpenAPI and hosted assets

Export complete plane-specific OpenAPI documents without compiling the server:

```bash
make openapi
```

This writes `target/openapi/runtime.json` and `target/openapi/control.json`. Hosted-web contract types and prepared assets are deterministic tracked inputs to Cargo builds:

```bash
make web-contracts
make web-check
make web-build
```

`build.rs` validates every prepared file, representation digest, manifest closure, and plane root. It never invokes Node.js or accesses the network. Production serves only assets embedded in the binary and has no filesystem fallback.

## Package boundary

`owlauth-server` owns the executable and its internal domain, application, persistence, provider, HTTP, and composition modules. Runtime and Control are logical planes over one shared core, not separate server packages. Public HTTP DTOs and OpenAPI definitions belong to `owlauth-types`; SDKs and the endpoint-discovered CLI must not depend on this server crate.

Database migration assets live in [`migrations/`](migrations/README.md) under [`TS-001`](../../spec/technology/ts-001-postgresql-repositories-and-migrations.md). Hosted-web source and preparation tooling live in [`web/`](web/README.md) under [`TS-002`](../../spec/technology/ts-002-hosted-web-and-asset-pipeline.md).

## License

[BSD 3-Clause](LICENSE). The packaged server and container also preserve required third-party redistribution terms under [`third-party/`](third-party/README.md).
