# owlauth-server

The server library and `owlauth-server` executable for [OwlAuth](https://github.com/owlfoundry/owlauth), a self-hostable Project Auth and identity service.

OwlAuth isolates users, provider/email identities, managed profile connections, SMTP, Application projections/webhooks, sessions, tokens, and signing keys by Project. Applications and end users use the Runtime Project Auth API and Hosted Authentication UI, while operators use the separately exposed Control API and embedded Management Console. OAuth/OIDC is used only for upstream federation; OwlAuth is not a general-purpose downstream OAuth/OIDC authorization server.

> OwlAuth is pre-alpha. The executable provides production-shaped configuration, PostgreSQL migrations and pools, isolated Runtime/Control listeners, embedded browser assets, Control provisioning and user/session lifecycle operations, and federated Runtime Project Auth with strict OIDC, PKCE handoff, refresh rotation, and logout. Interfaces and deployment requirements may still change; evaluate and harden the complete deployment before production use.

## Run locally

Start PostgreSQL and Redis from the repository root:

```bash
make dev-up
```

Create separate development-only software-store directories and run the Runtime listener with automatic embedded migrations:

```bash
mkdir -p /tmp/owlauth-dev/signers /tmp/owlauth-dev/configuration-secrets
OWLAUTH_INSTANCE_ID=local-development \
OWLAUTH_POSTGRES_URL=postgresql://owlauth:owlauth_dev@127.0.0.1:5432/owlauth \
OWLAUTH_RUNTIME_PROCESS_ID=local-runtime \
OWLAUTH_SIGNER_STORE_ROOT=/tmp/owlauth-dev/signers \
OWLAUTH_SIGNER_STORE_KEY=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE \
OWLAUTH_CONFIGURATION_SECRET_STORE_ROOT=/tmp/owlauth-dev/configuration-secrets \
OWLAUTH_CONFIGURATION_SECRET_STORE_KEY=AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI \
OWLAUTH_RUNTIME_KEY_VERSION=1 \
OWLAUTH_RUNTIME_DIGEST_KEY=AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM \
OWLAUTH_RUNTIME_PROTECTION_KEY=BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ \
OWLAUTH_ADMISSION_DIGEST_KEY=BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU \
OWLAUTH_PROVIDER_ALLOWED_ORIGINS=https://accounts.example/ \
  cargo run --package owlauth-server
```

The fixed keys above are public development examples and must never be reused outside disposable local state. Runtime defaults to `http://127.0.0.1:8080/`. Its liveness and readiness endpoints are available at `/health` and `/ready`; the Hosted Authentication UI shell is available at `/auth/`.

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
| `OWLAUTH_SIGNER_STORE_ROOT`                 | required for Control and federated Runtime auth   | Absolute root for versioned encrypted software signer material                                                                                                                             |
| `OWLAUTH_SIGNER_STORE_KEY`                  | required for Control and federated Runtime auth   | 32-byte signer wrapping key encoded as 43 unpadded base64url characters                                                                                                                    |
| `OWLAUTH_CONFIGURATION_SECRET_STORE_ROOT`   | required for Control and federated Runtime auth   | Separate absolute root for encrypted provider configuration secrets                                                                                                                        |
| `OWLAUTH_CONFIGURATION_SECRET_STORE_KEY`    | required for Control and federated Runtime auth   | Separate 32-byte wrapping key encoded as 43 unpadded base64url characters                                                                                                                  |
| `OWLAUTH_RUNTIME_KEY_VERSION`               | required when Runtime is selected                 | Positive active version for Runtime digest/data-protection key material                                                                                                                    |
| `OWLAUTH_RUNTIME_DIGEST_KEY`                | required when Runtime is selected                 | 32-byte active keyed-digest key encoded as 43 unpadded base64url characters                                                                                                                |
| `OWLAUTH_RUNTIME_PROTECTION_KEY`            | required when Runtime is selected                 | Distinct 32-byte active data-protection key encoded as 43 unpadded base64url characters                                                                                                    |
| `OWLAUTH_ADMISSION_DIGEST_KEY`              | required when Runtime is selected                 | Stable, independent 32-byte admission digest root encoded as 43 unpadded base64url characters; keep unchanged across Runtime protection-key rotations                                     |
| `OWLAUTH_RUNTIME_RETAINED_KEYS`             | unset                                             | JSON map of retained older digest/protection key versions needed by unexpired protected state                                                                                              |
| `OWLAUTH_PROVIDER_ALLOWED_ORIGINS`          | required when Runtime is selected                 | Comma-separated canonical HTTPS origins admitted for OIDC discovery and endpoints                                                                                                          |
| `OWLAUTH_PROVIDER_ALLOW_HTTP_LOOPBACK`      | `false`                                           | Development-only opt-in for exact `127.0.0.1` or `::1` HTTP origins in the provider allowlist; never admits hostnames or non-loopback addresses                                            |
| `OWLAUTH_RUNTIME_PROCESS_ID`                | required when Runtime is selected                 | Stable URL-safe identity used by this Runtime process when publishing observation leases                                                                                                   |
| `OWLAUTH_REQUIRED_RUNTIME_PROCESS_IDS`      | Runtime process ID; required in Control-only mode | Comma-separated deployment roster; every Runtime-capable process must include itself, every required member must lease the revision, and any additional live stale lease blocks activation |
| `OWLAUTH_ADMISSION_REDIS_URL`               | unset                                             | Optional secret-redacted `redis` or `rediss` URL for atomic deployment-wide Runtime admission counters                                                                                    |
| `OWLAUTH_ADMISSION_NAMESPACE`               | digest of `OWLAUTH_INSTANCE_ID`                   | 1-64 character deployment-unique Redis key namespace containing only alphanumeric, underscore, or hyphen characters                                                                       |
| `OWLAUTH_ADMISSION_REDIS_TIMEOUT_MS`        | `100`                                             | Per-operation Redis admission deadline, from `10` through `2000` milliseconds                                                                                                             |
| `OWLAUTH_RUNTIME_MAX_PROCESSES`             | required Runtime roster size                      | Conservative upper bound from the roster size through `64`; divides every local fallback quota without aggregate over-allocation                                                          |
| `OWLAUTH_PUBLICATION_LEASE_TTL_MS`          | `30000`                                           | Runtime key-publication lease lifetime; draining stops renewal and waits for expiry                                                                                                        |
| `OWLAUTH_KEY_PROPAGATION_DELAY_MS`          | `2000`                                            | Minimum all-live-process observation interval and retirement propagation margin; maximum `86400000`                                                                                        |
| `OWLAUTH_SIGNING_VERIFICATION_RETENTION_MS` | `1200000`                                         | Additional clock-skew and advertised JWKS-cache retention added to the 3600-second token maximum; maximum `86400000`                                                                       |
| `OWLAUTH_POSTGRES_URL`                      | required                                          | Serving PostgreSQL URL and authority anchor                                                                                                                                                |
| `OWLAUTH_RUNTIME_POSTGRES_URL`              | serving URL                                       | Runtime pool URL on the same database authority                                                                                                                                            |
| `OWLAUTH_CONTROL_POSTGRES_URL`              | serving URL                                       | Control pool URL on the same database authority                                                                                                                                            |
| `OWLAUTH_MIGRATION_POSTGRES_URL`            | serving URL                                       | Dedicated migration connection URL on the same authority                                                                                                                                   |
| `OWLAUTH_MIGRATION_MODE`                    | `auto`                                            | `auto` applies migrations; `verify` performs a DDL-free exact history check                                                                                                                |
| `OWLAUTH_MIGRATION_OWNER_ROLE`              | unset                                             | Validated PostgreSQL role selected for migration DDL                                                                                                                                       |
| `OWLAUTH_DATABASE_CONNECT_TIMEOUT_MS`       | `5000`                                            | Database connection deadline                                                                                                                                                               |
| `OWLAUTH_MIGRATION_LOCK_TIMEOUT_MS`         | `30000`                                           | Advisory migration-lock deadline                                                                                                                                                           |
| `OWLAUTH_RUNTIME_DATABASE_MAX_CONNECTIONS`  | `20`                                              | Runtime pool bound                                                                                                                                                                         |
| `OWLAUTH_CONTROL_DATABASE_MAX_CONNECTIONS`  | `5`                                               | Control pool bound                                                                                                                                                                         |
| `OWLAUTH_REQUEST_TIMEOUT_MS`                | `10000`                                           | HTTP request deadline                                                                                                                                                                      |
| `OWLAUTH_MAX_REQUEST_BYTES`                 | `1048576`                                         | Request body limit                                                                                                                                                                         |
| `OWLAUTH_SHUTDOWN_TIMEOUT_MS`               | `10000`                                           | Graceful drain deadline                                                                                                                                                                    |

Runtime business endpoints use fixed-window, endpoint-specific admission before PostgreSQL, provider, or signer work. Redis uses its own clock for window selection, and keys contain only the configured namespace, schema/endpoint labels, fixed-window number, and digests derived from the stable admission-only root; raw client addresses, Project/Application IDs, cookies, tokens, states, provider keys, and handoffs are never key material. Every accepted request also consumes the process's bounded monotonic rolling-window local share divided by `OWLAUTH_RUNTIME_MAX_PROCESSES`. If Redis is absent, unavailable, times out, loses counters, or returns an invalid result, that same local guard remains authoritative and the process stays on fallback through the current local window, so backend transitions cannot add quota. Active local entries are never evicted; capacity saturation fails closed until monotonic expiry. A rejection returns `429 rate_limited` with bounded `Retry-After`. Provider callbacks additionally use a reviewed process-local budget of 16 concurrent outbound exchanges; capacity exhaustion fails before provider dispatch and terminally fails the already-claimed callback rather than creating a waiting queue. Redis is not a concurrency lock or authority. CORS preflight, liveness/readiness, roots, shells, and immutable assets do not consume business buckets.

When Runtime and Control share an external origin, their configured base paths must be disjoint and non-root. Separate origins remain recommended.

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

[BSD 3-Clause](LICENSE).
