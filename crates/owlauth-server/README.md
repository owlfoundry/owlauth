# owlauth-server

The server library and `owlauth-server` executable for [OwlAuth](https://github.com/owlfoundry/owlauth), a self-hostable Project Auth and identity service.

OwlAuth isolates users, provider/email identities, managed profile connections, SMTP, Application projections/webhooks, sessions, tokens, and signing keys by Project. Applications and end users use the Runtime Project Auth API and Hosted Authentication UI, customer backends use the Project-key Client API, and operators use the separately exposed Control API and embedded Management Console. OAuth/OIDC is used only for upstream federation; OwlAuth is not a general-purpose downstream OAuth/OIDC authorization server.

> OwlAuth is Beta for the delivered self-hosted server scope. The executable provides PostgreSQL authority and embedded migrations, isolated Runtime/Client/Control listeners, Hosted Authentication and Management Console assets, OIDC and passwordless-email Project login, managed provider synchronization, Project session/token lifecycles, signed Application projection webhooks, Control operations, and optional remote MCP. Pre-1.0 interfaces, configuration, and deployment requirements may change. Beta is not deployment certification or a production support commitment; operators own hardening, monitoring, upgrades, and tested PostgreSQL/external-store/key backup, PITR, and restore.

## Run locally

From the repository root, copy the public disposable development configuration and start all three
planes plus PostgreSQL and Redis:

```bash
make install
cp .env.example .env
make dev
```

`make dev-check` runs the same non-mutating `.env`, tool, Docker, and Compose preflight without
starting services. Runtime defaults to `http://127.0.0.1:8080/`; its liveness and readiness endpoints
are `/health` and `/ready`, and the Hosted Authentication UI shell is at `/auth/`. Client defaults to
`http://127.0.0.1:8082/`; its directly openable readiness endpoint is `/ready`. Control defaults to
`http://127.0.0.1:8081/`, with the Management Console at `/console/`. Startup logs print these direct
links. The fixed keys in `.env.example` are public development values and must never be reused outside
disposable local state.

To compose all three planes, configure independent listeners and a canonical operator key:

```bash
OWLAUTH_MODE=all \
OWLAUTH_INSTANCE_ID=local-development \
OWLAUTH_POSTGRES_URL=postgresql://owlauth:owlauth_dev@127.0.0.1:5432/owlauth \
OWLAUTH_CONTROL_API_KEY='owl_ctrl_v1_<43-character-base64url-secret>' \
OWLAUTH_CLIENT_KEY_DIGEST_KEY_VERSION=1 \
OWLAUTH_CLIENT_KEY_DIGEST_KEY='<dedicated-43-character-base64url-client-key-digest-key>' \
OWLAUTH_CLIENT_PROCESS_ID=local-client \
OWLAUTH_RUNTIME_PROCESS_ID=local-runtime \
OWLAUTH_REQUIRED_RUNTIME_PROCESS_IDS=local-runtime \
OWLAUTH_SOFTWARE_CUSTODY_KEY='<43-character-base64url-custody-key>' \
OWLAUTH_RUNTIME_KEY_VERSION=1 \
OWLAUTH_RUNTIME_DIGEST_KEY='<43-character-base64url-digest-key>' \
OWLAUTH_RUNTIME_PROTECTION_KEY='<different-43-character-base64url-protection-key>' \
OWLAUTH_EMAIL_IDENTITY_KEY_VERSION=1 \
OWLAUTH_EMAIL_IDENTITY_DIGEST_KEY='<independent-43-character-long-term-digest-key>' \
OWLAUTH_EMAIL_IDENTITY_PROTECTION_KEY='<independent-43-character-long-term-protection-key>' \
OWLAUTH_PROJECTION_EMAIL_KEY_VERSION=1 \
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
  cargo run --package owlauth-server
```

Every key placeholder above must be replaced with exactly 43 unpadded base64url characters derived from 32 random bytes, and keys with different purposes must be distinct. Client defaults to `http://127.0.0.1:8082/`. Control defaults to `http://127.0.0.1:8081/`; its Management Console is at `/console/`. Control API calls require the configured key as an exact Bearer credential.

## Configuration

The process rejects unknown `OWLAUTH_*` variables and validates all selected-plane configuration before binding a listener. Ordinary serving keeps protected material in PostgreSQL and never opens legacy encrypted-file stores. Upgrades with legacy references must stop serving and run the listenerless `owlauth-server custody-import` command once with Control-only configuration, the four legacy store variables below, and the target `OWLAUTH_SOFTWARE_CUSTODY_KEY`; startup remains fail-closed until the atomic custody cutover succeeds.

| Variable                                            | Default                                           | Purpose                                                                                                                                                                                    |
| --------------------------------------------------- | ------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `OWLAUTH_MODE`                                      | `runtime`                                         | `runtime`, `client`, `control`, or `all` composition                                                                                                                                       |
| `OWLAUTH_INSTANCE_ID`                               | required                                          | Stable deployment identity returned by Control discovery and used to derive the default Runtime admission namespace                                                                        |
| `OWLAUTH_RUNTIME_ADDR`                              | `127.0.0.1:8080`                                  | Runtime bind socket                                                                                                                                                                        |
| `OWLAUTH_RUNTIME_BASE_URL`                          | `http://127.0.0.1:8080/`                          | Canonical external Runtime base                                                                                                                                                            |
| `OWLAUTH_CLIENT_ADDR`                               | `127.0.0.1:8082`                                  | Client bind socket for customer backends only                                                                                                                                              |
| `OWLAUTH_CLIENT_BASE_URL`                           | `http://127.0.0.1:8082/`                          | Canonical external Client base                                                                                                                                                             |
| `OWLAUTH_CONTROL_ADDR`                              | `127.0.0.1:8081`                                  | Control bind socket                                                                                                                                                                        |
| `OWLAUTH_CONTROL_BASE_URL`                          | `http://127.0.0.1:8081/`                          | Canonical external Control base                                                                                                                                                            |
| `OWLAUTH_CONTROL_API_KEY`                           | required for Control                              | `owl_ctrl_v1_` plus 43 base64url characters                                                                                                                                                |
| `OWLAUTH_CLIENT_KEY_DIGEST_KEY_VERSION`             | required for Client or Control                    | Positive active Project client-key digest version                                                                                                                                          |
| `OWLAUTH_CLIENT_KEY_DIGEST_KEY`                     | required for Client or Control                    | Dedicated 32-byte Project client-key digest root encoded as 43 unpadded base64url characters                                                                                               |
| `OWLAUTH_CLIENT_KEY_DIGEST_RETAINED_KEYS`           | unset                                             | JSON map of retained client-key digest versions until active-key inventory and Client roster observation permit retirement                                                                 |
| `OWLAUTH_CLIENT_PROCESS_ID`                         | required when Client is selected                  | Stable URL-safe identity used by this Client process for digest-readiness leases                                                                                                           |
| `OWLAUTH_REQUIRED_CLIENT_PROCESS_IDS`               | Client process ID; required in Control-only mode  | Comma-separated Client roster; every Client-capable process includes itself and every required member must prove readable digest versions                                                  |
| `OWLAUTH_CLIENT_DIGEST_READINESS_LEASE_TTL_MS`      | `30000`                                           | Client digest-readiness lease lifetime from `1000` through `300000` milliseconds                                                                                                           |
| `OWLAUTH_CONTROL_MCP_ENABLED`                       | `false`                                           | Mounts and advertises Control-base-relative `mcp`; requires HTTPS except exact loopback-IP development                                                                                     |
| `OWLAUTH_CONTROL_MCP_MAX_REQUEST_BYTES`             | `65536`                                           | MCP protocol-message body bound from 1 through `1048576` bytes, nested inside the global Control body bound                                                                                |
| `OWLAUTH_CONTROL_MCP_REQUEST_TIMEOUT_MS`            | `10000`                                           | MCP request deadline from 1 through `60000` milliseconds, nested inside the global Control deadline                                                                                        |
| `OWLAUTH_CONTROL_MCP_MAX_CONCURRENT_REQUESTS`       | `16`                                              | MCP-specific fail-fast concurrency budget from 1 through `64`, nested inside the Control listener budget                                                                                   |
| `OWLAUTH_CONTROL_MCP_MAX_REQUESTS_PER_SECOND`       | `64`                                              | Process-local authenticated MCP request-rate bound from 1 through `1024`; excess requests fail without entering protocol dispatch                                                          |
| `OWLAUTH_CONTROL_MCP_MAX_RESULT_BYTES`              | `65536`                                           | Maximum serialized structured tool result from 1 through `1048576` bytes                                                                                                                   |
| `OWLAUTH_SOFTWARE_CUSTODY_KEY`                      | required by the bundled software provider         | 32-byte root encoded as 43 unpadded base64url characters; protects PostgreSQL envelopes and handles and must be backed up separately from PostgreSQL                                       |
| `OWLAUTH_SIGNER_STORE_ROOT`                         | required only by `custody-import`                 | Absolute root of legacy encrypted-file signer material; ordinary serving ignores and does not retain it                                                                                    |
| `OWLAUTH_SIGNER_STORE_KEY`                          | required only by `custody-import`                 | Legacy 32-byte signer wrapping key encoded as 43 unpadded base64url characters                                                                                                             |
| `OWLAUTH_CONFIGURATION_SECRET_STORE_ROOT`           | required only by `custody-import`                 | Separate absolute root of legacy encrypted-file provider configuration secrets                                                                                                             |
| `OWLAUTH_CONFIGURATION_SECRET_STORE_KEY`            | required only by `custody-import`                 | Separate legacy 32-byte wrapping key encoded as 43 unpadded base64url characters                                                                                                           |
| `OWLAUTH_RUNTIME_KEY_VERSION`                       | required when Runtime is selected                 | Positive active version for generic Runtime interaction digest and data-protection material; Control-only does not parse or retain this ring                                               |
| `OWLAUTH_RUNTIME_DIGEST_KEY`                        | required when Runtime is selected                 | Generic Runtime 32-byte active keyed-digest key encoded as 43 unpadded base64url characters                                                                                                |
| `OWLAUTH_RUNTIME_PROTECTION_KEY`                    | required when Runtime is selected                 | Generic Runtime, distinct 32-byte active data-protection key encoded as 43 unpadded base64url characters                                                                                   |
| `OWLAUTH_RUNTIME_RETAINED_KEYS`                     | unset                                             | JSON map of at most 15 retained short-term digest/protection versions needed only by unexpired transactions, challenges, sessions, and outbox rows                                         |
| `OWLAUTH_MANAGED_REAUTHORIZATION_KEY_VERSION`       | required for every serving plane                  | Positive active version of the purpose-limited managed-reauthorization interaction-target issuer/verifier ring                                                                             |
| `OWLAUTH_MANAGED_REAUTHORIZATION_DIGEST_KEY`        | required for every serving plane                  | Dedicated 32-byte target-handle digest key, distinct from every generic Runtime, Runtime admission, and managed-credential root                                                            |
| `OWLAUTH_MANAGED_REAUTHORIZATION_PROTECTION_KEY`    | required for every serving plane                  | Dedicated 32-byte target-result AEAD key, distinct from the target digest key and every generic Runtime, Runtime admission, and managed-credential root                                    |
| `OWLAUTH_MANAGED_REAUTHORIZATION_RETAINED_KEYS`     | unset                                             | JSON map of retained target digest/protection versions used only to replay and verify unexpired managed-reauthorization targets                                                            |
| `OWLAUTH_IDENTITY_MUTATION_EVIDENCE_KEY_VERSION`    | required for every serving plane                  | Positive active version of the narrow cross-plane identity-candidate evidence ring                                                                                                         |
| `OWLAUTH_IDENTITY_MUTATION_EVIDENCE_DIGEST_KEY`     | required for every serving plane                  | Dedicated 32-byte candidate-evidence digest key; Runtime can produce while Control can only verify                                                                                         |
| `OWLAUTH_IDENTITY_MUTATION_EVIDENCE_PROTECTION_KEY` | required for every serving plane                  | Dedicated 32-byte candidate-evidence AEAD key; distinct from every active and retained root in all other authorities                                                                       |
| `OWLAUTH_IDENTITY_MUTATION_EVIDENCE_RETAINED_KEYS`  | unset                                             | JSON map of at most 15 retained evidence digest/protection versions for in-flight mutation confirmation                                                                                    |
| `OWLAUTH_MANAGED_CREDENTIAL_KEY_VERSION`            | required when managed Runtime is selected         | Positive active version of the dedicated long-lived managed-provider credential AEAD ring; never configured as Control-only custody                                                        |
| `OWLAUTH_MANAGED_CREDENTIAL_KEY`                    | required when managed Runtime is selected         | Dedicated 32-byte active managed-credential AEAD key, distinct from every active/retained Runtime digest and short-term protection key                                                     |
| `OWLAUTH_MANAGED_CREDENTIAL_RETAINED_KEYS`          | unset                                             | JSON map from retained positive versions to 43-character managed-credential AEAD keys required until inventory and rewrap prove retirement safe                                            |
| `OWLAUTH_ADMISSION_DIGEST_KEY`                      | required when Runtime or Client is selected       | Stable, independent 32-byte admission digest root encoded as 43 unpadded base64url characters; keep unchanged across Runtime protection-key rotations                                      |
| `OWLAUTH_EMAIL_IDENTITY_KEY_VERSION`                | email capability unavailable when omitted         | Positive active version for the independently retained long-term email lookup/PII ring                                                                                                     |
| `OWLAUTH_EMAIL_IDENTITY_DIGEST_KEY`                 | required with email identity key version          | Independent 32-byte long-term email identity digest root; must not equal any short-term or retained root                                                                                   |
| `OWLAUTH_EMAIL_IDENTITY_PROTECTION_KEY`             | required with email identity key version          | Independent 32-byte long-term email identity AEAD root; must not equal any other active or retained root                                                                                   |
| `OWLAUTH_EMAIL_IDENTITY_RETAINED_KEYS`              | unset                                             | JSON map of at most 15 independently retained older long-term email identity digest/AEAD versions                                                                                          |
| `OWLAUTH_PROJECTION_EMAIL_KEY_VERSION`              | required for every serving plane                  | Positive active version for the narrow verified-email projection AEAD ring                                                                                                                 |
| `OWLAUTH_PROJECTION_EMAIL_PROTECTION_KEY`           | required for every serving plane                  | Independent 32-byte verified-email projection AEAD key encoded as 43 unpadded base64url characters                                                                                         |
| `OWLAUTH_PROJECTION_EMAIL_RETAINED_KEYS`            | unset                                             | JSON map from at most 15 retained positive versions to 43-character projection AEAD keys required until roster observation and ciphertext inventory prove retirement safe                  |
| `OWLAUTH_PROJECTION_EMAIL_CUTOVER_VERSION`          | unset                                             | Explicit deployment-wide projection write cutover authorization                                                                                                                            |
| `OWLAUTH_PROJECTION_EMAIL_RETIRE_VERSION`           | unset                                             | Separate retire-only authorization after every required Runtime observation and predecessor reference clears                                                                               |
| `OWLAUTH_EMAIL_IDENTITY_ALIAS_CUTOVER_VERSION`      | unset                                             | Explicit email-identity lookup-alias write cutover or pre-retirement rollback; must equal the active email identity version and cannot coexist with retirement                             |
| `OWLAUTH_EMAIL_IDENTITY_ALIAS_RETIRE_VERSION`       | unset                                             | Later retire-only rollout after every live Runtime has durably observed post-cutover overlap                                                                                               |
| `OWLAUTH_PROVIDER_ALLOWED_ORIGINS`                  | unset                                             | Upgrade-only legacy input: comma-separated canonical origins copied into missing Project Custom OIDC policies while the durable bridge is pending; ignored after completion                |
| `OWLAUTH_PROVIDER_ALLOW_HTTP_LOOPBACK`              | `false`                                           | Development-only opt-in for exact `127.0.0.1` or `::1` HTTP origins in the provider allowlist; never admits hostnames or non-loopback addresses                                            |
| `OWLAUTH_RUNTIME_PROCESS_ID`                        | required when Runtime is selected                 | Stable URL-safe identity used by this Runtime process when publishing observation leases                                                                                                   |
| `OWLAUTH_REQUIRED_RUNTIME_PROCESS_IDS`              | Runtime process ID; required in Control-only mode | Comma-separated deployment roster; every Runtime-capable process must include itself, every required member must lease the revision, and any additional live stale lease blocks activation |
| `OWLAUTH_ADMISSION_REDIS_URL`                       | unset                                             | Optional secret-redacted `redis` or `rediss` URL for atomic deployment-wide Runtime admission counters                                                                                     |
| `OWLAUTH_ADMISSION_NAMESPACE`                       | digest of `OWLAUTH_INSTANCE_ID`                   | 1-64 character deployment-unique Redis key namespace containing only alphanumeric, underscore, or hyphen characters                                                                        |
| `OWLAUTH_ADMISSION_REDIS_TIMEOUT_MS`                | `100`                                             | Per-operation Redis admission deadline, from `10` through `2000` milliseconds                                                                                                              |
| `OWLAUTH_RUNTIME_MAX_PROCESSES`                     | required Runtime roster size                      | Runtime-only conservative upper bound from its roster size through `64`; divides Runtime local quota without aggregate over-allocation                                                     |
| `OWLAUTH_CLIENT_MAX_PROCESSES`                      | required Client roster size                       | Client-only conservative upper bound from its roster size through `64`; divides Client local quota independently of Runtime replicas                                                       |
| `OWLAUTH_DEPLOYMENT_SMTP_GENERATION`                | all deployment SMTP fields unset                  | Positive immutable generation number for the deployment-default SMTP registry                                                                                                              |
| `OWLAUTH_DEPLOYMENT_SMTP_STATUS`                    | all deployment SMTP fields unset                  | Desired `reconciled`, `active`, `disabled`, or `compromised` status; disabled/compromised reconciliation never requires readable credentials                                               |
| `OWLAUTH_DEPLOYMENT_SMTP_HOST`                      | all deployment SMTP fields unset                  | Canonical DNS relay hostname; IP literals are rejected                                                                                                                                     |
| `OWLAUTH_DEPLOYMENT_SMTP_PORT`                      | all deployment SMTP fields unset                  | Non-zero relay TCP port                                                                                                                                                                    |
| `OWLAUTH_DEPLOYMENT_SMTP_TLS_MODE`                  | all deployment SMTP fields unset                  | `implicit_tls` or mandatory `starttls_required`; no deployment-default plaintext mode                                                                                                      |
| `OWLAUTH_DEPLOYMENT_SMTP_SENDER_ADDRESS`            | all deployment SMTP fields unset                  | Canonical envelope sender address                                                                                                                                                          |
| `OWLAUTH_DEPLOYMENT_SMTP_SAFE_FINGERPRINT`          | all deployment SMTP fields unset                  | Exactly 64 hexadecimal characters matching the externally stored credential; checked before reconciled/active startup                                                                      |
| `OWLAUTH_DEPLOYMENT_SMTP_ALLOWED_PRIVATE_IPS`       | unset                                             | Comma-separated, at most 16 exact private relay addresses; cannot override loopback, mapped, link-local, metadata, multicast, unspecified, or other unconditional destination denies       |
| `OWLAUTH_WEBHOOK_ALLOWED_PRIVATE_IPS`               | unset                                             | Comma-separated, at most 16 exact private webhook addresses; every DNS answer must pass and unconditional destination and listener denies still apply                                      |
| `OWLAUTH_WEBHOOK_EXTRA_ROOT_CERT_DER_FILE`          | unset                                             | Absolute path to one bounded DER trust anchor for private-CA HTTPS webhook destinations; TLS hostname verification and every egress restriction remain enforced                            |
| `OWLAUTH_PUBLICATION_LEASE_TTL_MS`                  | `30000`                                           | Runtime key-publication lease lifetime; draining stops renewal and waits for expiry                                                                                                        |
| `OWLAUTH_KEY_PROPAGATION_DELAY_MS`                  | `2000`                                            | Minimum all-live-process observation interval and retirement propagation margin; maximum `86400000`                                                                                        |
| `OWLAUTH_SIGNING_VERIFICATION_RETENTION_MS`         | `1200000`                                         | Additional clock-skew and advertised JWKS-cache retention added to the 3600-second token maximum; maximum `86400000`                                                                       |
| `OWLAUTH_POSTGRES_URL`                              | required                                          | Serving PostgreSQL URL and authority anchor                                                                                                                                                |
| `OWLAUTH_RUNTIME_POSTGRES_URL`                      | serving URL                                       | Runtime pool URL on the same database authority                                                                                                                                            |
| `OWLAUTH_CLIENT_POSTGRES_URL`                       | serving URL                                       | Client pool URL on the same database authority                                                                                                                                             |
| `OWLAUTH_CONTROL_POSTGRES_URL`                      | serving URL                                       | Control pool URL on the same database authority                                                                                                                                            |
| `OWLAUTH_MIGRATION_POSTGRES_URL`                    | serving URL                                       | Dedicated migration connection URL on the same authority                                                                                                                                   |
| `OWLAUTH_MIGRATION_MODE`                            | `auto`                                            | `auto` applies migrations; `verify` performs a DDL-free checksum-prefix and compatibility-floor check                                                                                      |
| `OWLAUTH_MIGRATION_OWNER_ROLE`                      | unset                                             | Validated PostgreSQL role selected for migration DDL                                                                                                                                       |
| `OWLAUTH_DATABASE_CONNECT_TIMEOUT_MS`               | `5000`                                            | Database connection deadline                                                                                                                                                               |
| `OWLAUTH_DATABASE_LOCK_TIMEOUT_MS`                  | `5000`                                            | PostgreSQL `lock_timeout` for every Runtime, Client, and Control pool session; range `10`-`60000`                                                                                          |
| `OWLAUTH_MIGRATION_LOCK_TIMEOUT_MS`                 | `30000`                                           | PostgreSQL lock wait for the dedicated migration session, including SQLx advisory and DDL locks; range `10`-`300000`                                                                       |
| `OWLAUTH_MIGRATION_STATEMENT_TIMEOUT_MS`            | `300000`                                          | Per-statement PostgreSQL deadline for migration SQL; range `100`-`3600000`                                                                                                                 |
| `OWLAUTH_MIGRATION_DEADLINE_MS`                     | `1800000`                                         | Whole migration-run loss-of-control guard; range `1000`-`86400000` and strictly greater than both migration timeouts                                                                       |
| `OWLAUTH_RUNTIME_DATABASE_MAX_CONNECTIONS`          | `20`                                              | Runtime pool bound                                                                                                                                                                         |
| `OWLAUTH_CLIENT_DATABASE_MAX_CONNECTIONS`           | `10`                                              | Client pool bound                                                                                                                                                                          |
| `OWLAUTH_CONTROL_DATABASE_MAX_CONNECTIONS`          | `5`                                               | Control pool bound                                                                                                                                                                         |
| `OWLAUTH_REQUEST_TIMEOUT_MS`                        | `10000`                                           | HTTP request deadline                                                                                                                                                                      |
| `OWLAUTH_MAX_REQUEST_BYTES`                         | `1048576`                                         | Request body limit                                                                                                                                                                         |
| `OWLAUTH_SHUTDOWN_TIMEOUT_MS`                       | `10000`                                           | Graceful drain deadline                                                                                                                                                                    |

### Key-version and rotation model

A `*_KEY_VERSION` selects the active entry in one purpose-specific data-protection or digest ring;
it is not a command to rotate every OwlAuth secret. New values use the active version and persisted
rows retain the exact version required to read or verify them. Add the predecessor to the matching
`*_RETAINED_KEYS` map before changing an active version, deploy the readable set to every process
that needs that capability, and remove it only after the corresponding PostgreSQL inventory and
roster/readiness checks prove zero live references.

Rotation behavior is purpose-specific:

- short-lived Runtime, managed-reauthorization, and identity-mutation material drains by expiry or
  bounded terminalization rather than full-table re-encryption;
- durable email identity PII/aliases, Application verified-email projection fields, and managed
  provider credentials converge through bounded background rewrap before an old version may retire;
  projection events are immutable and drain only through their retention lifecycle;
- Project client-key digests cannot be rehashed because plaintext client secrets are never stored;
  retain the old digest key, or revoke and reissue affected Project client keys;
- Project JWT signing keys and provider/SMTP/webhook secret generations use their PostgreSQL-backed
  resource lifecycle APIs, not these environment versions;
- `OWLAUTH_SOFTWARE_CUSTODY_KEY` is a separate static v1 root with no online rotation or retained
  set. Never replace it in place; custody-root rotation requires a future explicit envelope/rewrap
  design.

There is intentionally no generic “rotate all” endpoint. The email-identity runbook below documents
the most involved environment-ring transition; every other ring must follow its own inventory and
readiness contract in the normative specifications.

## Upstream provider profiles

Provider creation names one closed adapter kind; dispatch never falls back from a named adapter to generic OIDC semantics:

- `oidc` accepts a canonical issuer other than the reserved Google and GitHub issuers. Discovery and every advertised endpoint must pass the current durable Project egress policy (`allow_all` or exact canonical origins). Login uses `openid profile`; optional managed profile synchronization adds the fixed `offline_access` scope and retains only the server-side renewable credential needed for bounded UserInfo refresh.
- `google` requires the exact issuer `https://accounts.google.com` and uses strict OIDC validation with fixed Google discovery, token, UserInfo, and authorization origins. Managed profile synchronization requests exactly `openid profile` plus Google's `access_type=offline` and `prompt=consent` authorization parameters; it does not invent the unsupported `offline_access` scope. Callers cannot request additional Google scopes or use OwlAuth as a token broker.
- `github` requires the exact issuer `https://github.com`, uses fixed GitHub authorization/token/user endpoints, requests exactly `read:user`, and keys identity only by the immutable nonzero numeric REST user ID. It is login-only: identity-mutation proof and managed profile synchronization are unsupported, and no renewable provider credential is retained.

Provider client secrets are write-only Control inputs sealed by the selected provider into generation-fenced PostgreSQL protected material. Public capability responses expose the selected kind and that adapter's exact managed-profile support/scopes, but never secret or upstream token material. Custom OIDC preflight carries no client secret and reports only reviewed metadata; policy/profile rejection returns `provider_preflight_rejected` (`422`), while bounded discovery or provider failure returns `provider_preflight_unavailable` (`503`). Every adapter applies one Runtime callback policy: HTTPS, plus exact IP-literal loopback HTTP only when the explicit development opt-in is enabled; upstream endpoint-origin policy remains independently adapter-specific.

Runtime and Client business endpoints use fixed-window, endpoint-specific admission before PostgreSQL, provider, or signer work. Redis uses its own clock for window selection, and keys contain only the configured namespace, schema/endpoint labels, fixed-window number, and digests derived from the stable admission-only root; raw client addresses, Project/Application IDs, cookies, tokens, states, provider keys, and handoffs are never key material. Every accepted Runtime request also consumes that process's bounded monotonic rolling-window local share divided by `OWLAUTH_RUNTIME_MAX_PROCESSES`; Client endpoints independently use `OWLAUTH_CLIENT_MAX_PROCESSES`, so one plane's replica count cannot dilute the other's healthy quota. If Redis is absent, unavailable, times out, loses counters, or returns an invalid result, the corresponding local guard remains authoritative and the process stays on fallback through the current local window, so backend transitions cannot add quota. Active local entries are never evicted; capacity saturation fails closed until monotonic expiry. Client/Project/Application/interaction quota or capacity rejection returns `429 rate_limited` with bounded `Retry-After`. Only a sole saturated server-derived Project/Application-scoped keyed-address bucket commits an ordinary random-proof challenge with the same response, Hosted state, resend, expiry, newest/sibling, invalid-proof, and revision behavior while recording a terminal `policy_denied` outbox disposition that workers cannot claim; it neither calls SMTP nor logs/labels the address or bucket. Provider callbacks additionally use a reviewed process-local budget of 16 concurrent outbound exchanges, while Control OIDC preflight has an independent fail-fast budget of 4; capacity exhaustion fails before provider dispatch rather than creating a waiting queue. Redis is not a concurrency lock or authority. CORS preflight, liveness/readiness, roots, shells, and immutable assets do not consume business buckets.

When Runtime and Control share an external origin, their configured base paths must be disjoint and non-root. Separate origins remain recommended.

Remote MCP is disabled by default. When enabled, the descriptor publishes the canonical Control-base-relative `mcp` URL and the Control listener exposes an MCP Streamable HTTP endpoint backed by `rmcp`. The initial catalog is deliberately stateless, JSON-response, tools-only, and hand-designed: eight read-only tools cover system capabilities, Project/Application inventory, projection policy, and webhook endpoint/delivery inspection; the only mutation is a high-impact projection-policy update exposed exclusively as preview and commit tools. It creates no server session, exposes no prompts or resources, and has no stdio or child-process transport. Every HTTP request must carry the same exact operator Bearer key as Control REST; authentication occurs before protocol parsing, and the adapter removes the Authorization header before MCP dispatch. Configured external Host and optional Origin values are validated. Preview returns one raw high-entropy capability while PostgreSQL stores only its digest, bound to the deployment instance, exact MCP endpoint, Control audience, exact commit tool and command, Project metadata revision, and target revision. PostgreSQL-clock expiry, one-use consumption, the conditional policy mutation, expansion operation, and deployment-operator audit are enforced in one transaction; no direct mutation alias exists.

Deployment SMTP fields are an all-or-none process registry. For first-time combined-plane bootstrap, `status=reconciled` may omit the safe fingerprint so Control can bind and seal the credential through its authenticated API; no active database generation may already exist, and Runtime-only startup never accepts this unsealed form. The operator then pins the returned fingerprint in process configuration before activation. Startup reconciles immutable metadata into PostgreSQL, pins every email challenge and outbox row to a generation plus eligibility revision, and does not emit another audit event when the desired record is unchanged. Activation retains predecessor metadata for bounded proof compatibility, but generation `n+1`, replacement, disable, or compromise serializes with the fully fenced worker transition and prevents every later claim of stale generation `n` immediately. Operators can inspect and terminally disable/compromise generations through `/v1/system/smtp-default-generations`; process configuration must also be changed before restart or its declared desired state will be reconciled again. In split-plane deployments, every Runtime-capable process and the Control process must receive identical non-secret generation metadata, while only the selected Control sealing and Runtime opening provider capabilities receive plaintext credentials. PostgreSQL stores only the provider's opaque envelope plus a keyed safe fingerprint; plaintext secret bytes never enter PostgreSQL, logs, audit context, or Control responses.

Runtime retains protected challenge addresses and outbox envelope/body payloads only while they are useful plus a fixed 10-minute terminal investigation window. Bounded Runtime maintenance terminalizes abandoned or exhausted work, irreversibly sets those ciphertext/key-version columns to `NULL`, and deletes expired or terminal magic transfer contexts while retaining safe statuses, timestamps, message IDs, and audit metadata. Each cleanup class runs in an independently timed transaction under a shared 100-row/200 ms tick budget. A cleanup timeout is reported and retried but cannot prevent the same worker tick from claiming due mail.

Runtime uses two independent protection inventories and lifecycles. The short-term `OWLAUTH_RUNTIME_*` ring protects interactions, challenges, and outbox payloads; remove a predecessor from `OWLAUTH_RUNTIME_RETAINED_KEYS` only after the short-term inventory is clear. The durable `OWLAUTH_EMAIL_IDENTITY_*` ring protects encrypted identity addresses and lookup aliases; first rewrap identity PII, backfill and retire aliases under the durable active version, verify the durable inventory is clear, and only then remove that predecessor from `OWLAUTH_EMAIL_IDENTITY_RETAINED_KEYS`. Clearing one inventory never authorizes retirement from the other ring. Missing short-term material is terminalized without cross-purpose fallback; missing durable email-identity material fails readiness closed because silently discarding or substituting identity data would break uniqueness and recovery. Durable active plus retained versions are capped at 16 so every login can atomically backfill the complete accepted alias set. Runtime owns email lookup, writes, alias authority, and rewrap. A Control process that materializes verified-email projections may load the same physical `OWLAUTH_EMAIL_IDENTITY_*` ring only behind the exact `(Project, identity, protected value)` decrypt-only designated-address reader; it receives no lookup digest, alias, encryption, arbitrary-context, or generic Runtime protection capability.

### Verified-email projection key rotation runbook

The projection ring is AEAD-only: its versioned keys protect the verified-email field, while the
public projection document digest remains an unkeyed canonical SHA-256 digest and has no secret
root. Retained-key JSON therefore has the simple shape `{"1":"<43-character-base64url-key>"}`.
Treat `OWLAUTH_PROJECTION_EMAIL_CUTOVER_VERSION` and
`OWLAUTH_PROJECTION_EMAIL_RETIRE_VERSION` as separate deployment-wide phases. Mutable
`application_user_projections` rows are storage-only rewrapped in bounded 100-row transactions with
`FOR UPDATE SKIP LOCKED`; this covers cold rows and rows owned by disabled Projects, Applications,
users, or bindings without changing projection revisions, public documents/digests, source/policy
metadata, or emitting an event. Opportunity-driven materialization also refuses to reuse a
ciphertext whose key version differs from the PostgreSQL-authoritative write version.

1. Keep the predecessor as `OWLAUTH_PROJECTION_EMAIL_KEY_VERSION` and add the future version to
   `OWLAUTH_PROJECTION_EMAIL_RETAINED_KEYS` so both are readable. Deploy the same readable set to
   every serving plane and confirm `OWLAUTH_REQUIRED_RUNTIME_PROCESS_IDS` names the complete Runtime
   roster. Leave both projection rotation flags unset during this verifier-first rollout.
2. Promote the new version into `OWLAUTH_PROJECTION_EMAIL_KEY_VERSION` and its active key, move the
   predecessor into `OWLAUTH_PROJECTION_EMAIL_RETAINED_KEYS`, and set only
   `OWLAUTH_PROJECTION_EMAIL_CUTOVER_VERSION` to the new active version. Runtime stages the version,
   waits for live observations from every
   required Runtime process, and only then advances the PostgreSQL write authority. A missing or
   stale roster observation leaves projection writes and maintenance fail-closed.
3. After cutover, remove the cutover flag and leave retirement unset. Keep all predecessor key
   material deployed while the continuous bounded rewrap lane and ordinary projection access drain
   every mutable projection row. Concurrent Runtime supervisors claim disjoint rows and safely
   resume the remaining inventory after restart.
4. Verify `application_user_projections` has zero rows referencing the predecessor. Do **not** infer
   retirement safety from that inventory alone: `application_user_events` is immutable, so its
   protected verified-email snapshot is never rewrapped or rewritten.
5. Wait for the longest old-version event lifetime and the cleanup backlog to drain. Events have a
   fixed maximum `retain_until` of 30 days from `occurred_at` (the replay window is 29 days), but
   bounded cleanup may take longer when deliveries, attempts, replay descendants, contention, or
   downtime leave a backlog. Continue retaining the predecessor until PostgreSQL reports zero
   `application_user_events.verified_email_key_version` references; an elapsed wall-clock estimate
   is not sufficient.
6. In a later rollout, set only `OWLAUTH_PROJECTION_EMAIL_RETIRE_VERSION` to the predecessor
   version. Keep the complete readable set and exact Runtime roster live. Retirement remains
   blocked while either mutable projections or retained immutable events reference the predecessor;
   once reference-free, authority records retirement and waits the configured propagation delay
   before removing that version from `accepted_versions`.
7. Only after PostgreSQL authority no longer accepts the predecessor, clear the retire flag and
   remove that predecessor entry from `OWLAUTH_PROJECTION_EMAIL_RETAINED_KEYS`. Never combine
   cutover and retirement, bypass the observation/retention gates, delete retained events early, or
   rewrite event ciphertext in place.

### Email identity alias cutover runbook

Treat `OWLAUTH_EMAIL_IDENTITY_ALIAS_CUTOVER_VERSION` as a deployment-wide, explicitly staged operation rather than an ordinary rolling environment change:

1. Add the new durable digest and protection keys as the active version while retaining every old durable version in `OWLAUTH_EMAIL_IDENTITY_RETAINED_KEYS`. Leave the cutover variable unset. Deploy this readable-key set to the complete split-topology Runtime roster and to any Control process that materializes verified-email projections; Control receives it only through the designated-address reader described above and does not participate in alias authority. Keep the separate short-term `OWLAUTH_RUNTIME_*` ring unchanged unless it is undergoing its own independently inventoried rotation.
2. Confirm `OWLAUTH_REQUIRED_RUNTIME_PROCESS_IDS` exactly names every Runtime-capable process. Wait until every required process has a live observation lease for the current email-alias authority revision and active key version. An extra live process, a missing roster member, or a stale revision blocks cutover.
3. Drain stale Runtime nodes: stop new traffic and workers, stop lease renewal, wait for the publication lease to expire, and verify the node no longer appears in the live observation set. Do not bypass the roster check.
4. Set `OWLAUTH_EMAIL_IDENTITY_ALIAS_CUTOVER_VERSION` to the active `OWLAUTH_EMAIL_IDENTITY_KEY_VERSION` on the complete Runtime roster. `OWLAUTH_EMAIL_IDENTITY_ALIAS_RETIRE_VERSION` must remain unset; configuration parsing rejects both flags together. Restart or roll only after all members have the readable key set. The authority changes `write_version` only when the exact live roster has observed the predecessor revision; it deliberately keeps both predecessor and new versions in `accepted_versions` and deletes no predecessor rows.
5. Remove the cutover flag, keep all old keys, and leave the retirement flag unset. Run bounded verification/backfill until every durable email identity has the new alias and active-version address protection, no conflict is reported, and every required Runtime process observes the **post-cutover** authority revision. PostgreSQL then records an exact `overlap_verified_revision`. Cutover and this observation phase never collapse `accepted_versions` or delete an alias, so this remains a durable rollback window.
6. If verification fails, roll back before retirement by making the predecessor key version active (while retaining the newer key), setting `OWLAUTH_EMAIL_IDENTITY_ALIAS_CUTOVER_VERSION` to that predecessor version, and waiting for exact-roster/backfill convergence. The authority records a rollback write-version transition while both alias sets remain accepted. Unsetting a variable alone is not a rollback, and rollback is unavailable after retirement authorization.
7. Only after the durable overlap-verification revision exists and every Runtime has observed it, begin a later deployment with **only** `OWLAUTH_EMAIL_IDENTITY_ALIAS_RETIRE_VERSION` set to the active version. Every live/required process must transition from retirement unset to set at or after that exact revision. A flag pre-set before observation remains durably stale and must be rolled off before this rollout. Only the complete later roster authorization records a retirement revision, collapses `accepted_versions`, and begins bounded predecessor deletion.
8. Verify the durable alias and email-identity protection inventories contain no predecessor references, then remove the predecessor durable digest/protection material from `OWLAUTH_EMAIL_IDENTITY_RETAINED_KEYS`. Independently, remove a predecessor from `OWLAUTH_RUNTIME_RETAINED_KEYS` only after the short-term challenge/outbox inventory for that ring is clear; neither inventory substitutes for the other.

This ordering is mandatory in combined and split deployments: readable-key rollout to the complete Runtime roster and designated Control projection readers, exact Runtime-roster observation, stale-node drain, cutover-only write transition with overlap, cutover flag removal, durable post-cutover overlap verification, later retire-only complete-roster authorization, bounded alias retirement, then durable protector retirement. Simultaneous/pre-authorized cutover and retirement is invalid. The required Runtime roster, requested cutover/retirement versions, observation revisions, and authority events are non-secret operational metadata; Control's only access to the physical ring remains the narrow designated-address reader.

## Database lock and migration recovery

Every Runtime, Client, and Control physical PostgreSQL connection starts with the validated `OWLAUTH_DATABASE_LOCK_TIMEOUT_MS`; startup also queries the effective session setting and fails if PostgreSQL did not apply it. A database-generated lock timeout is a persistence/contention failure. OwlAuth rolls back that statement or transaction and does not automatically replay a mutation, handoff, refresh, proof, or external-effect finalization. Callers may make an explicit retry only under the operation's existing idempotency and revision rules after checking authoritative state.

`auto` migration uses three independent bounds: PostgreSQL lock wait, per-statement execution, and a larger whole-run guard. Timeout or cancellation closes the dedicated backend before serving pools are created, releases SQLx's session advisory lock, leaves the last successful additive migration prefix in `_sqlx_migrations`, and keeps the process unready. Remove the blocker or remediate the statement, preserve the database, and restart explicitly; SQLx resumes from the checksum-matching successful prefix. Never delete history, edit an applied migration, disable constraints, or start serving by switching to `verify` while migrations are pending. `verify` remains DDL-free and is appropriate only when the restored or pre-migrated history is already compatible.

Post-TS-003 migrations isolate expansion, bounded backfill, ordinary index construction, constraint attachment, online validation, and contract steps into ordered transactions. `NOT VALID` FK/CHECK constraints protect new writes before later validation, while ordinary indexes remain transactional and retry-safe rather than using crash-ambiguous concurrent-index scripts. Every earlier build was pre-alpha, so stop every older process before this rewritten series; its first post-initial commit advances `schema_compatibility` and deliberately provides no older-binary restart or concurrent-write bridge. Even with bounded waits, table cardinality, provider-specific PostgreSQL behavior, or a future contract step can require a planned maintenance window. Do not interpret these bounds as universal zero-downtime support.

## Backup, point-in-time recovery, and verify restart

Backup scheduling, WAL archiving, restore orchestration, and retention policy belong to the deployment rather than this executable. A recoverable OwlAuth backup is nevertheless one reviewed set, not a PostgreSQL dump alone:

- a transactionally consistent PostgreSQL base backup or managed snapshot plus the WAL needed for the selected point in time;
- the bundled software custody root or equivalent custom-provider authority needed to sign/open every live PostgreSQL handle/envelope, preserved separately from the database backup;
- the exact instance ID, Runtime, Client, and Control external URLs, operator key, current and retained protection-key rings, provider/SMTP/webhook metadata, and other process configuration used at that point.

Use PostgreSQL-native physical backup/PITR or the equivalent managed-service facility, continuously test restoration on an isolated deployment, and select a recovery point for which the matching custody authority is available. Redis is non-authoritative and is not restored as identity state.

A recovery proceeds in this order:

1. Stop admission on every Runtime, Client, and Control process and keep external traffic blocked.
2. Restore the software custody root or custom-provider authority matching the recovery point without rotating or reprovisioning material.
3. Restore PostgreSQL to the selected consistent point in time. Do not run manual schema edits or SeaORM schema synchronization.
4. Restore the exact deployment identity, external URLs, operator credential, custody/provider configuration, and retained protection rings. Start with `OWLAUTH_MIGRATION_MODE=verify`; recovery must not apply DDL.
5. Start one isolated Runtime process, require `/ready`, and inspect logs plus the relevant Control reads. Startup authenticates every live configuration envelope and signs/verifies through every live signing handle; a missing or mismatched provider authority or long-term protection key is a recovery failure and must not be replaced silently.
6. Start the remaining split-plane processes in `verify` mode, confirm the required Runtime roster and durable outbox/lease recovery, then reopen traffic. Redis may start empty or under a fresh namespace.

After the restored deployment is stable, run an ordinary reviewed upgrade separately if a newer schema is desired. Never combine PITR with an unreviewed migration or identity/issuer change.

## OpenAPI and hosted assets

Export complete plane-specific OpenAPI documents without compiling the server:

```bash
make openapi
```

This writes `target/openapi/runtime.json`, `target/openapi/client.json`, and `target/openapi/control.json`. Hosted-web contract types and prepared assets are deterministic tracked inputs to Cargo builds:

```bash
make web-contracts
make web-check
make web-build
```

`build.rs` validates every prepared file, representation digest, manifest closure, and plane root. It never invokes Node.js or accesses the network. Production serves only assets embedded in the binary and has no filesystem fallback.

## Package boundary

`owlauth-server` owns the executable and its internal domain, application, persistence, provider, HTTP, and composition modules. Runtime, Client, and Control are logical planes over one shared core, not separate server packages. Public HTTP DTOs and OpenAPI definitions belong to `owlauth-types`; SDKs and the endpoint-discovered CLI must not depend on this server crate.

Database migration assets live in [`migrations/`](migrations/README.md) under [`TS-001`](../../spec/technology/ts-001-postgresql-repositories-and-migrations.md). Hosted-web source and preparation tooling live in [`web/`](web/README.md) under [`TS-002`](../../spec/technology/ts-002-hosted-web-and-asset-pipeline.md).

## License

[BSD 3-Clause](LICENSE). The packaged server and container also preserve required third-party redistribution terms under [`third-party/`](third-party/README.md).
