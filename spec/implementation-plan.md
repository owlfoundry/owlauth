# OwlAuth server and hosted-web implementation plan

> **Status:** tracked implementation plan; non-normative.
>
> The behavioral authorities are [`spec/01`](01-system-context-and-goals.md) through
> [`spec/11`](11-identity-connections-passwordless-email-and-user-sync.md), with the
> technology selections in [`spec/10`](10-implementation-technology-selections.md),
> [`TS-001`](technology/ts-001-postgresql-repositories-and-migrations.md), and
> [`TS-002`](technology/ts-002-hosted-web-and-asset-pipeline.md). If this plan and an
> owning specification differ, the owning specification wins and this plan is updated.
> Phase numbers below describe dependency order, not releases or compatibility promises.

## 1. Purpose and delivery rules

This document turns the target architecture into an incremental, bottom-up delivery
sequence for the single `owlauth-server` package, the Runtime Hosted Authentication UI,
and the Control Management Console. It includes the server-side well-known descriptor and
remote HTTP MCP adapter, but not delivery planning for the SaaS service or the CLI's SaaS
client. It does not define another product contract or move behavioral authority out of the
concern-specific specifications.

The current repository is a health-only pre-alpha scaffold: there is no domain core,
persistence adapter, migration runner, Runtime/Control composition, Project Auth flow,
or hosted-web package. The plan therefore starts with the narrow technical gates selected
by TS-001 and TS-002, then retains and extends those production-shaped foundations into
complete vertical journeys. It does not create disposable demos whose behavior must later
be replaced.

The following rules apply to every phase:

1. **Dependencies point inward.** Domain and application code know semantic ports, not
   Axum, SeaORM, SQLx, Redis, provider/SMTP payloads, React, or public DTOs.
2. **PostgreSQL proves security facts.** One-use state, Project ownership, revisions,
   sessions, credential generations, outboxes, and audit outcomes are committed there.
   Redis can improve admission and derived-data latency only.
3. **Each increment is usable through its real boundary.** A UI workflow is enabled only
   after its ordinary HTTP contract and application service exist. Browser tests start
   the real Rust server; they do not replace missing backend behavior with a mock server.
4. **A narrow technology spike proves only technology.** The required TS-001 and TS-002
   spikes are retained as production foundations, but do not count as Project Auth,
   Console, or product end-to-end completion.
5. **Schema evolves by expand/migrate/switch/contract.** Released migrations are never
   edited. Each phase remains safe for the declared mixed-version overlap before a later
   contraction.
6. **One vertical journey before breadth.** For example, one real upstream provider is
   completed through handoff before adding other provider adapters; one complete Console
   resource workflow precedes broad CRUD coverage.
7. **No hidden alternate implementations.** CLI, MCP, HTTP, workers, and both web surfaces
   invoke the same application services. Test-only helpers may substitute external ports,
   but never domain authorization, repository transactions, or one-use semantics.
8. **Security and operations ship with the behavior.** Redaction, audit, limits,
   idempotency, deadlines, readiness, recovery, and negative tests are phase exit
   conditions rather than a final cleanup pass.

## 2. Planned implementation shape

Names in this section are organizational guidance, not stable Rust API names. Server-only
modules remain internal to `crates/owlauth-server` unless a real independent boundary is
approved.

```text
crates/owlauth-types/src/
  runtime/                 Runtime DTOs, errors, endpoint metadata, OpenAPI root
  control/                 Control DTOs, problem details, endpoint metadata, OpenAPI root
  health/                  listener-safe probe vocabulary
  export/                  deterministic separate Runtime/Control OpenAPI export

crates/owlauth-server/src/
  domain/                  IDs, aggregates, value objects, state machines, domain errors
    project/ application/ identity/ connection/ login/ email/
    session/ token/ key/ projection/ webhook/ audit/
  application/             commands, queries, orchestration, actor/context types
    ports/                  semantic repositories/UoW and external-effect ports
  adapters/
    postgres/               private SeaORM entities, repositories, UoW, error mapping
    migrations/             SQLx startup migrator and DDL-free verifier
    redis/                  cache, invalidation, and rate coordination only
    providers/              GitHub, Google, and generic OIDC implementations
    secrets/                provider/SMTP/webhook configuration-secret storage
    crypto/                 signer, verification directory, data protection, digests,
                            PostgreSQL managed-credential AEAD protection
    smtp/                   bounded SMTP transport
    http/runtime/           Runtime parsing, middleware, routers, response mapping
    http/control/           Control authentication, routers, response mapping
    web_assets/             separate Runtime/Control manifests, shells, embedding
    workers/                mail, provider-sync, and Application-webhook dispatchers
    telemetry/              redacted logging, metrics, tracing, and audit integration
  composition/              typed config, all/runtime/control roots, lifecycle/readiness

crates/owlauth-server/migrations/
  ordered reviewed SQL      schema authority; no SeaORM schema synchronization

crates/owlauth-server/web/
  src/runtime/              Hosted Authentication UI graph
  src/control/              Management Console graph
  src/shared/               authority-free primitives only
  src/generated/            committed, separate type-only OpenAPI outputs
  scripts/                  generation, manifest validation, deterministic compression
  dist/runtime/             prepared Runtime embed tree (generated)
  dist/control/             prepared Control embed tree (generated)
```

### 2.1 Core application ports

Implement ports when the first consuming vertical slice needs them; do not build a generic
framework in advance.

| Port family | Semantic responsibility | First consumer |
| --- | --- | --- |
| `UnitOfWork` and Project-qualified repositories | transactional commands, conditional state changes, durable audit append, conflict classification | Project/Application bootstrap |
| `Clock`, `EntropySource`, digest service | deterministic time tests and CSPRNG-backed opaque credentials | bootstrap and login |
| `Signer`, `VerificationKeyDirectory` | Project-purpose signing and public key lookup by opaque key reference | key lifecycle/token issuance |
| `DataProtector` | purpose- and context-bound encryption of short-term transaction state and long-term email PII | federated login and email login |
| `ManagedCredentialProtector` | protect/unprotect a renewable credential as versioned AEAD ciphertext bound to exact Project/identity/generation context | managed identity connection |
| `ProviderSecretResolver` | resolve a Project provider client secret from its opaque configuration reference | provider callback |
| `UpstreamProviderClient` | authorization, one code exchange, issuer/subject verification, separately classified credential renewal and bounded read-only profile fetch | federated login |
| `MailTransport` | one bounded SMTP submission from a claimed durable message | passwordless email |
| `UserProjectionPublisher`/webhook transport | sign and deliver one immutable Application event attempt | Application synchronization |
| `Cache`, `RateLimiter`, invalidation publisher | disposable revisioned data and coordinated admission; never an allow authority | first public Runtime endpoint |
| `AuditAppender` | transactional append where required; a sink only for non-transactional telemetry | first mutation |

Ports return bounded semantic results such as `Conflict`, `Unavailable`, `Rejected`,
`AmbiguousExternalOutcome`, or `IntegrityFailure`. Vendor error strings and recoverable
credentials stop at adapters.

### 2.2 Schema increments

Do not land one giant initial schema. Each migration group accompanies the application
behavior that owns it, while preserving direct `project_id` qualification and same-Project
foreign-key constraints.

| Increment | Durable state introduced or expanded |
| --- | --- |
| Foundation | SQLx history; Projects, Applications, redirects, origins, publishable identifiers, policies, Control idempotency, audit |
| Key readiness | key rings, signing keys, key state events, provisioning operations, Runtime publication leases |
| Federated login | provider configurations/assignments, generic method-selection login transactions, linked identities, users, browser sessions, handoff tickets, and minimal Application-user binding/materialized projection with both revisions |
| Application sessions | Application sessions, refresh families/tokens, revision snapshots and revocation state |
| Passwordless email | normalized verification-address evidence as defined by spec 11, email challenges/attempt state, versioned SMTP configuration references, immutable delivery-generation pin, durable mail outbox |
| Managed connections | connection lifecycle, PostgreSQL managed-credential AEAD ciphertext/key version, durable generation-fenced renewal operation, sync metadata, lease/attempt state; never downstream token-broker grants |
| Application sync | projection-policy expansion cursor, immutable events, webhook endpoint/signing-secret references, delivery outbox, attempts, replay/idempotency state; existing bindings/projections are extended rather than introduced here |

Literal table/column names and migration grouping are reviewed against specs 04 and 11
before SQL is merged. Sensitive values use digests, authenticated ciphertext, or opaque
secret-store references as required. V1 provider renewable credentials are purpose-bound
AEAD ciphertext in PostgreSQL so replacement is one authoritative transaction; provider
client secrets, SMTP passwords, webhook signing secrets, and private signing keys remain
external references. None are ordinary plaintext columns.

### 2.3 Contract and generated-client increments

`owlauth-types` exports two complete OpenAPI 3.1 documents without compiling
`owlauth-server`. Runtime and Control DTO modules remain disjoint. A contract increment
lands in this order:

1. define bounded wire vocabulary, stable errors, endpoint metadata, and serialization
   tests in `owlauth-types`;
2. map DTOs explicitly to already-tested application commands/results;
3. export each plane document and prove plane purity;
4. regenerate and review only that plane's committed TypeScript type file;
5. implement its Rust HTTP adapter tests;
6. enable the corresponding web workflow and browser tests.

Representative contract families are those owned by specs 05 and 11:

- Runtime public config, generic login start, hosted transaction method selection,
  provider callback, email challenge/verification, handoff exchange, refresh, current
  user, logout, and Project JWKS;
- Control Project/Application/provider/connection/SMTP/webhook configuration, users and
  identities, sessions, policy, keys, audit, replay, and bounded system capabilities;
- the revisioned bounded user projection on successful handoff/current-user/refresh
  results, plus immutable signed webhook event envelopes for Application backends.

This plan does not freeze route spellings that spec 11 has not assigned. Contract review
must prove exact Project/Application/redirect/PKCE binding, enumeration-safe email
responses, unknown-enum policy, input bounds, idempotency, revision conflicts, and secret
redaction before exposure.

## 3. Cross-phase test model

| Layer | What it proves | What it must not pretend to prove |
| --- | --- | --- |
| Domain unit/state-machine tests | transitions, revisions, expiry, link/merge rules, projection bounds | SQL concurrency or HTTP behavior |
| Application tests with explicit port substitutes | orchestration and classified external outcomes | production adapters or product E2E |
| PostgreSQL integration tests | real migrations, constraints, locks, UoW rollback, one-use races, outbox claiming | browser behavior |
| Adapter contract tests | provider, secret store, SMTP, signer, and webhook protocol mapping with controlled external test servers | a complete user journey |
| In-process HTTP tests | middleware order, route isolation, DTO/error mapping, bounds, auth/CORS | asset/browser security or real socket topology |
| Rust-server browser tests | real routers, embedded assets, configured bases, real implemented API behavior | unsupported flows hidden behind fixture responses |
| Server-backed product E2E | complete implemented journey through PostgreSQL and normal application services | future endpoints or core logic replaced by mocks |
| Release/package tests | offline crate, binary/container assets, migration/readiness and digest parity | semantic correctness already owned below |

A provider test server, SMTP capture server, KMS test adapter, or webhook receiver may stand
in for an external dependency while exercising OwlAuth's real adapter and core. Seeding
normal prerequisite configuration is allowed. Directly inserting impossible terminal
state, mocking the Runtime/Control API under a UI, or replacing application services does
not qualify as E2E.

Concurrency suites include callback double-submit, handoff double exchange, refresh reuse,
email OTP/magic-link races, provider connection sync versus revoke/disconnect, projection
revision races, duplicate outbox claims, webhook replay, and Project disablement between
prepare and commit. Cross-Project variants accompany every Project-owned repository and
public command.

## 4. Delivery phases

### Phase 0 — Retained technical foundations

**Journey enabled:** none is advertised as product functionality. An engineer can build,
package, migrate, and start the correct plane skeleton with trustworthy failure behavior.

**Bottom-up work**

1. Complete the narrow TS-001 validation against disposable PostgreSQL: concurrent SQLx
   migration locking and bounded timeout cleanup; one SeaORM-backed transaction-bound UoW;
   one conditional one-use mutation; separate bounded Runtime/Control pools.
2. Add typed configuration, strict unknown-field rejection, redacted secret wrappers,
   `all`/`runtime`/`control` composition roots, independent listeners, lifecycle, liveness,
   and initially dependency-only readiness. Replace the current single `app()` only when
   plane-specific router tests preserve the scaffold health behavior deliberately.
3. Split `owlauth-types` into Runtime, Control, and health roots and add deterministic
   independent OpenAPI exporters. Do not carry the scaffold's generic OAuth vocabulary
   forward unless an owning public contract needs it.
4. Complete the narrow TS-002 chain with minimal credential-free shells: two plane-pure
   generated clients, two Vite entry graphs/manifests/output roots, normalized manifests,
   deterministic compression, two embed types, configured non-root base support, offline
   Cargo packaging, and plane-local exact asset serving. These shells expose no fake
   Project or login workflows.
5. Add redaction-first telemetry, correlation IDs, request/connection bounds, graceful
   drain, and dependency timeout plumbing used by every later adapter.

**Dependencies:** accepted TS-001/TS-002 and specs 02, 04, 05, 06, 08, 09, and 10.

**Tests and acceptance**

- all TS-001 and TS-002 focused validation gates pass on retained code;
- `runtime` cannot route Control API/assets and does not load the operator key;
- `control`/`all` fail before binding on a malformed/missing canonical key;
- distinct origins and explicitly configured disjoint shared-origin bases resolve only
  their own shell/assets/health routes;
- migration `auto` and DDL-free `verify` fail closed for incompatible histories;
- debug, test, release, unpacked-crate offline, and container paths consume identical
  prepared web assets, with no Node runtime or filesystem fallback.

**Exit condition:** the build/migration/composition/web pipeline is production-shaped and
retained, but README/docs and health/capabilities still state that Project Auth is not
implemented. No browser test is labeled a user login or Console E2E.

### Phase 1 — Operator bootstraps a Project and Application

**Vertical operator journey:** enter the deployment key in the real Console, validate it
through Control, create one Project, register one Application, add exact redirect/origin
entries, inspect revisions, disable/re-enable only transitions supported by the specs, and
lock the Console.

**Bottom-up work**

1. Implement typed IDs/value objects and Project, Application, redirect/origin,
   publishable-identifier, policy, Control-idempotency, and audit domain rules.
2. Add the foundation migration group with same-Project composite constraints, immutable
   public identity, revision columns, append-only audit, and durable resource-lifetime
   idempotency behavior.
3. Implement private SeaORM mappings and a transaction-bound UoW spanning Project,
   Application, configuration, idempotency, and audit repositories.
4. Add `ProjectApplicationService` and `ApplicationConfigurationService`; every mutation
   receives the fixed deployment-operator actor and optional/required expected revisions
   according to the owning spec.
5. Add strict constant-time Control Bearer admission before resource resolution, then the
   bounded `/v1/system`, Project, and Application Control contracts.
6. Regenerate the Control web type file and implement page-memory key capture/disposal,
   Project/Application list-detail-create workflows, exact redirect/origin forms,
   idempotency, conflict recovery, confirmations, and safe problem rendering.

**Dependencies:** Phase 0.

**Tests and acceptance**

- real PostgreSQL tests cover rollback with audit, idempotent replay, digest mismatch,
  revision conflict, duplicate exact entries, and cross-Project child injection;
- authentication grammar parity and constant-time verification are covered without
  exposing key/fingerprint values;
- Console reload, lock, failed authentication, and tab close leave no supported storage,
  DOM, URL/history, log, or cache copy of the key;
- Playwright uses the Rust Control listener and real PostgreSQL for the complete journey;
- Runtime receives neither Control routes nor an Authorization value from the Console.

**Exit condition:** an operator can create authoritative prerequisites without SQL or a
placeholder UI. No provider, login, or token capability is claimed yet.

### Phase 2 — Project signing readiness, public configuration, and provider setup

**Vertical journeys:** the operator provisions and activates a Project signing key only
after Runtime publication evidence, and configures one upstream provider registration for
one Application. The Application can retrieve bounded public configuration and JWKS, but
cannot yet claim successful login.

**Bottom-up work**

1. Implement key-ring/provisioning/lifecycle aggregates, signing-epoch guard semantics,
   provider configuration/assignment aggregates, and active/revision state checks.
2. Add key, publication-lease, provider registration, assignment, and opaque secret
   reference migrations with Project-qualified constraints.
3. Implement key/provider repositories, `Signer`, `VerificationKeyDirectory`,
   `ProviderSecretResolver`, durable provisioning reconciliation, and Runtime publication
   leases. KMS calls occur outside database transactions.
4. Add `KeyLifecycleService`, `ProviderConfigurationService`, public-configuration query,
   and JWKS query. Cache entries are revisioned and dispensable.
5. Add reviewed Control key/provider contracts and Runtime config/JWKS contracts with
   independent generated clients.
6. Add Console key-lifecycle and provider-assignment workflows. Add Runtime UI branding
   bootstrap only for stored public values; do not render a sign-in action until Phase 3.

**Dependencies:** Phase 1 and a real test signer/KMS protocol adapter.

**Tests and acceptance**

- provisioning retry resolves the same durable provider operation; ambiguous outcome is
  reconciled rather than duplicated;
- activation rejects absent/stale publication leases and observes the full propagation
  interval; concurrent signing/lifecycle tests prove the epoch guard;
- provider secrets and signer references never enter public config, OpenAPI examples,
  Console reads, logs, audits, or Redis;
- Runtime public config is exact-Application/CORS bounded and JWKS caching is
  representation-correct;
- provider/key disable and reassignment revisions invalidate prepared stale work in
  integration tests.

**Exit condition:** one Project/Application/provider/key configuration is operationally
ready for login, with no synthetic token or handoff endpoint presented as successful.

### Phase 3 — First complete federated end-user login

**Vertical end-user/Application journey:** an Application starts one generic PKCE S256
login, the Hosted UI renders the admitted method snapshot and explicitly selects the first
supported provider, the real adapter validates one callback, OwlAuth resolves or creates a
Project user, returns a one-use handoff to the exact redirect, and the Application exchanges
it for a signed access token, first refresh token, and authoritative bounded user projection.
A second same-Project Application can then obtain a handoff only after the user explicitly
confirms reuse of the still-eligible Project browser session.

**Bottom-up work**

1. Implement generic login/method-selection and explicit Project browser-session reuse
   confirmation, linked identity, Project user with monotonic `user_revision`, browser
   session, handoff, Application-user binding/materialized
   projection with monotonic `projection_revision`, Application session, and initial
   refresh-family domain state. Provider issuer/subject—not email/profile—is the link key.
2. Add federated-login/session migrations with allowed-method/revision snapshots, CSRF and
   browser binding, keyed digests, encrypted recoverable state, exact redirect/assignment
   snapshots, one-use constraints, unique `(project, application, user)` binding, one
   materialized bounded projection per binding, and transactional audit.
3. Implement repositories and conditional operations for one-way method selection,
   browser-session reuse confirmation, callback claiming/completion, and handoff
   consumption. The handoff transaction creates
   or reuses the binding, materializes the projection/revisions, consumes the ticket, and
   creates session/family/audit together. Add `DataProtector`, digest, first
   `UpstreamProviderClient`, and signer adapters with bounded classified outcomes.
4. Implement `LoginApplicationService`, method selection, browser-session reuse with
   authoritative session/auth-age/security-policy revalidation, identity resolution,
   browser-session creation, handoff exchange, deterministic minimal projection mapping,
   and initial token issuance. Provider exchange is never retried after an ambiguous result
   and never occurs while holding a database transaction.
5. Add generic Runtime start, hosted interaction/method-selection/session-reuse, callback,
   and handoff contracts. The start's optional method hint is presentation-only; callback and
   Application redirect route/value classes remain separate.
6. Regenerate the Runtime client and enable the Hosted UI's admitted-method picker,
   explicit bounded “continue as” confirmation, selected-provider, progress, completion,
   and safe local error/restart states. It receives only an opaque interaction handle and
   bounded public presentation data.

**Dependencies:** Phase 2, one production provider adapter, configured trusted Runtime
base, data protection, and active signer.

**Tests and acceptance**

- generic start snapshots only assigned methods; browser/CSRF/expected-revision races prove
  exactly one current provider/email selection or explicit eligible browser-session reuse
  wins. Safe hints cannot select; caller-named/cross-Project/expired/logged-out/stale-policy
  sessions and switched/replaced Project/Application/provider/callback/redirect/browser/PKCE
  values fail;
- callback claim and ticket exchange races produce one committed winner and no credential
  response for a loser; provider exchange ambiguity makes the transaction terminal;
  binding/projection/session/family/ticket/audit commit atomically;
- unknown verified identity creation and existing issuer/subject resolution are atomic;
  matching email never silently links; cross-Project identity reuse creates independent
  users;
- the first successful handoff creates exactly one Application-user binding/materialized
  projection with both revisions; another Application remains unbound and cannot observe it;
- provider access tokens are transient and absent from database, redirect, projection,
  browser, audit, and telemetry; no downstream provider-token broker route exists;
- browser E2E starts the actual Rust server, real PostgreSQL, the real provider HTTP
  adapter against a controlled standards-compatible provider, and the actual embedded
  Runtime UI; the Application test client performs the real handoff exchange;
- redirect abuse, DOM injection, CSP, no-store, referrer suppression, cookie path, and
  cross-plane asset/route tests pass.

**Exit condition:** one provider has a complete supported journey. Additional providers
may now reuse the port contract and conformance suite; they do not fork login policy.

### Phase 4 — Session lifecycle and security-state propagation

**Vertical Application/end-user journey:** initialize from the handoff user projection,
retrieve current user, serialize refresh, log out one Application or the Project browser
session, and reauthenticate after replay or authoritative disablement.

**Bottom-up work**

1. Complete session/refresh expiry, claims revision, strict generation reuse, Application
   versus browser logout, and Project/Application/user security-revision domain behavior.
2. Expand constraints/indexes only as needed for current-user and refresh critical paths;
   add no Redis authority or unbounded revocation fan-out.
3. Implement refresh rotation and replay-family revocation as one PostgreSQL transaction,
   including referenced browser-session checks and audit.
4. Add `SessionApplicationService`, `TokenApplicationService`, current-user query, logout,
   and Control session/user disable/revoke commands.
5. Add Runtime refresh/current-user/logout and Control user/session contracts, then their
   generated-client changes and Console/Hosted UI session controls.
6. Add Redis revisioned config/JWKS caches and rate coordination only after equivalent
   PostgreSQL-authoritative paths pass with Redis flushed or unavailable.

**Dependencies:** Phase 3.

**Tests and acceptance**

- concurrent refresh of generation `n` and later reuse revoke the complete family with no
  stable winner; a lost response leads the client to reauthenticate;
- browser logout blocks refresh for all derived Application sessions while
  Application-only logout leaves other Applications and the Project browser session valid;
- Project/Application/user/provider/assignment disablement is observed at every owning
  decision/commit point after PostgreSQL commit;
- current-user, handoff, and refresh return the same bounded projection revision shape;
- Redis loss/staleness tests never convert denial, revocation, or cross-Project input into
  allow;
- all three SDK suites become eligible for server-backed E2E only after their consumed
  Runtime paths are real; no earlier fake E2E job is retained.

**Exit condition:** the first federated login is a complete maintainable session product,
not a one-shot authentication demo.

### Phase 5 — First-party verified email OTP and magic-link login

**Vertical end-user/Application journey:** from a generic exact-bound Application login,
choose the admitted email method in Hosted UI, submit an address without learning whether it
exists, receive a Project-branded OTP and magic link through the pinned SMTP generation,
complete either once, return to the exact stored redirect, and exchange the PKCE-bound
handoff.

**Bottom-up work**

1. Extend the Phase 3 transaction with one-way email selection and address-entry/challenge
   states. Implement challenge/attempt/expiry/consumption, verified-email evidence,
   anti-enumeration outcomes, and explicit linking rules. Enforce the non-overridable v1
   OTP/magic expiry, entropy/length, attempt, resend, challenge-count, and transaction
   limits from spec 11; Project policy may only tighten them.
2. Add email identity plus versioned lookup aliases, parent challenge plus separate
   OTP/magic proof rows, versioned per-Project SMTP configurations, deployment-default SMTP
   generation/status/revision registry with safe config fingerprint, and durable mail-outbox
   migrations. Challenge and outbox both pin Project versus explicit deployment default,
   nullable Project SMTP configuration ID, and exact generation/eligibility revision. Bind
   challenge/message to Project, Application, exact redirect, PKCE, browser interaction,
   purpose, and current revisions. Store challenge material as digests or purpose-bound
   ciphertext only where recoverability is required; digest-key rotation uses dual
   lookup/backfill before cutover and cannot create duplicate identities.
3. Implement transactional challenge-plus-outbox enqueue, lease-safe message claiming,
   proof-completion revalidation of pinned current SMTP generation/status/revision,
   authoritative disable/compromise revision transitions, bounded cleanup, attempt history,
   retry/backoff, terminal handling, and retention cleanup.
4. Implement `MailTransport` with per-Project SMTP resolution and explicit deployment
   fallback from spec 11. Startup/readiness matches the default handle generation/fingerprint
   to PostgreSQL; workers resolve only the outbox-pinned still-eligible generation. Production
   requires implicit TLS or mandatory STARTTLS with hostname/certificate validation and no
   downgrade; plaintext is explicit loopback-only development behavior.
5. Add email method-select, challenge begin/resend, verify, and consume commands/contracts.
   Public challenge and verification responses remain enumeration-safe in status, body
   class, and practical timing/rate behavior.
6. Add Control SMTP metadata/write-only-secret workflows and Hosted UI OTP/magic-link,
   resend, expiry, restart, accessibility, and safe error states through the separate
   generated clients.

**Dependencies:** Phase 4, spec 11 contract review, mail worker composition/readiness, and a
safe secret resolver.

**Tests and acceptance**

- known/unknown/disabled/already-linked addresses have indistinguishable public request
  response classes and bounded timing tests; logs, metrics, and Console errors do not
  create a side-channel API;
- OTP and magic link are sibling proofs of one newest challenge generation, each expires
  and becomes unusable when either consumes the parent; OTP attempts and all resend/rate
  bounds are enforced without moving proof across Project, Application, purpose, redirect,
  or PKCE binding;
- the magic-link proof is URL-fragment staged, removed from history, and consumed only by
  explicit same-origin POST, so GET link preview/security scanners cannot consume it;
- concurrent verification yields one authentication completion; resend does not resurrect
  or multiply a consumed challenge;
- transaction rollback cannot leave an intended message without its durable outbox row,
  and worker crash/redelivery cannot authenticate a user or duplicate challenge state;
- Project SMTP, explicit deployment fallback, pinned challenge/outbox generation+revision
  across replacement, disable/compromise versus completion races, bounded cleanup, and an
  already-in-flight delivery whose proof is denied after compromise are tested; missing
  config, TLS/STARTTLS downgrade/certificate failures, transient/permanent outcomes, retry
  exhaustion, restart, backup/restore, and redaction pass with a real capture adapter;
- browser E2E uses the actual Runtime UI/API, PostgreSQL, mail outbox worker, SMTP adapter,
  captured email, and real handoff exchange—never a UI-level mocked verification response.

**Exit condition:** both OTP and magic link satisfy the same Project Auth completion
invariants as federation. Password login remains out of scope.

### Phase 6 — Managed provider connections and profile synchronization

**Vertical end-user/operator journey:** a federated login establishes or updates a managed
connection; the user continues authenticating while its current state permits; login-time
and bounded background synchronization refresh the safe profile; an operator/user-driven
reauthorization, revoke, or disconnect follows explicit transitions.

**Bottom-up work**

1. Implement the connection lifecycle exactly as
   `active`, `reauth_required`, `revoked`, and `disconnected`, including legal transitions,
   revision guards, timestamps, sync cursors/outcome metadata, and deletion/retention rules
   from spec 11.
2. Add connection/sync state, versioned purpose-bound managed-credential AEAD ciphertext
   in PostgreSQL, and durable renewal operations with expected/successor generation,
   adapter attempt ID, `prepared`/`submitted`/terminal status, and lease metadata. The
   `submitted` marker commits before external invocation so post-marker crash is safely
   ambiguous; pre-marker work may be reclaimed. This v1 path deliberately
   avoids external credential-store/database dual writes.
3. Implement atomic connection updates during login and every credential replacement,
   generation-fenced renewal claims, bounded background work, and revision-conditional
   profile writes. Every replacement advances generation; successor ciphertext commits
   before optional profile fetch; late work cannot overwrite revoke/disconnect/user change.
4. Separate provider read-only profile fetch from rotating renewal behind the provider
   port. Read retry requires adapter-declared safety. Rotation persists its durable attempt
   before submission and is not blindly retried after ambiguity/lease loss; absent exact
   idempotent replay, guarded resolution destroys predecessor access and sets
   `reauth_required`.
5. Add application commands/queries and only the Control/Runtime metadata contracts needed
   to present state and reauthentication. Do not expose provider access/refresh tokens or
   add a downstream token-broker operation.
6. Add Console connection status/actions and Hosted UI reauthorization state through their
   own generated clients. Background sync has no browser dependency.

**Dependencies:** Phase 3 for federation, Phase 4 for sessions/revisions, and spec 11's
credential/lifecycle rules. Phase 5 is not required for provider sync itself.

**Tests and acceptance**

- the four-state transition matrix, stale-revision conflicts, revoke/disconnect races, and
  connection behavior after user/Project/provider disablement pass against PostgreSQL;
- login-time sync has a bounded latency budget and defined stale-safe fallback; background
  duplicate read claims/process crashes are idempotent at projection revision level;
- rotation ambiguity, lease loss before/after submission, provider family rotation, exact
  adapter idempotent replay, crash after successor receipt, and commit-before-profile-fetch
  are tested; no path presents an uncertain predecessor again;
- invalid/expired grant or ambiguous non-replayable rotation moves to `reauth_required`;
  explicit revoke/disconnect prevents queued work from restoring `active`;
- connected credentials, references unsuitable for display, and provider payloads are
  absent from Runtime/Control DTOs, user projection, webhook payloads, Redis, audit, logs,
  and browser state;
- source/OpenAPI/router tests prove that no Application-facing provider-token broker exists;
- backup/restore and key rotation inventory prove re-encryption before old managed-
  credential keys retire; missing key material leads to explicit reauthorization/fail-closed
  behavior rather than guessed credential recovery.

**Exit condition:** managed connections improve identity freshness without turning OwlAuth
into a provider-token vault for downstream Applications.

### Phase 7 — Projection evolution and signed Application webhooks

**Vertical Application journey:** an Application already initialized from the Phase 3
binding/projection reconciles current-user/refresh plus duplicate or out-of-order
revision-aware signed webhook deliveries, and an operator can replay an immutable retained
event without creating a different user state.

**Bottom-up work**

1. Extend the Phase 3 binding/projection mapper with full reviewed field ownership,
   Project/Application policy snapshots, bounded fan-out, event-kind vocabulary,
   size/field allowlist, and immutable event envelope from spec 11. Preserve existing
   `user_revision`/`projection_revision`; raw profiles/credentials never enter projection.
2. Add immutable event rows, durable Project/Application policy-expansion operations and
   cursors, Application webhook endpoint metadata, opaque signing-secret references,
   delivery outbox/attempt/lease/replay lineage. Existing bindings are migrated as existing
   visibility state with no synthetic `user.projection.created` event. A new handoff after
   event support emits `created` only when that same transaction first creates its binding;
   later real transitions emit `updated`/`disabled`.
3. Implement projection repositories, lazy stale-policy repair on Runtime reads, bounded
   resumable policy-expansion workers, and lease-safe dispatch. Use stable event/delivery
   identifiers, bounded exponential backoff with jitter, explicit terminal state,
   per-Application fairness, retention, and replay as a new delivery of the same immutable
   event—not mutation re-execution.
4. Implement webhook signing over opaque Application-scoped secret versions. Sign exact
   `timestamp "." event_id "." raw_body`; receivers require the header ID to equal body
   `event_id`. Endpoint URLs are immutable; rotation is prepare/install/activate/dual-sign
   overlap/retire. Every attempt validates the full CNAME/A/AAAA result set, rejects any
   denied/mixed/mapped/metadata target, pins the connected IP while retaining host for
   SNI/cert/Host, rejects redirects/rebinding, and allows only an equivalently enforcing
   proxy.
5. Preserve the Phase 3/4 Runtime handoff/current-user/refresh projection contract and
   extend its generated fixtures only for reviewed policy/schema behavior; add Control
   webhook endpoint, signing-secret rotation metadata, delivery inspection, and replay
   contracts plus the Application receiver event/signature contract.
6. Regenerate both clients. Add Console endpoint configuration, safe attempt inspection,
   explicit replay confirmation, revision conflict handling, and secret write-only display.

**Dependencies:** Phase 4; phases 5 and 6 contribute email/connection-driven projection
changes when present but do not block the core publisher. Spec 11 fixes event semantics.

**Tests and acceptance**

- every user-base or relevant projection-policy mutation either commits each affected
  binding's new `projection_revision` and required outbox event together or commits neither;
  concurrent mutations produce distinct monotonic per-binding revisions while
  `user_revision` advances only for base/security changes;
- Project/Application projection-policy commit creates one resumable expansion operation;
  immediate Runtime reads lazily observe the new policy, and crash/restart of bounded batch
  expansion neither skips nor duplicates a binding revision/event;
- webhook receiver tests verify `timestamp.event_id.raw_body` vectors, header/body ID
  mismatch, timestamp/replay rejection, duplicate idempotency, transient/permanent outcomes,
  timeout/body/response bounds, full DNS chain, mixed public/private, rebinding,
  IPv4-mapped IPv6, metadata/cross-plane targets, proxy equivalence, redirect denial,
  exhaustion, and signing-secret overlap;
- worker crash before/after HTTP outcome yields at-least-once delivery without re-running
  the user mutation; Applications deduplicate by immutable event ID and ignore a
  `projection_revision` older than the stored Application-user projection;
- an Application receives an initial/later event only for a user with its own committed
  Application-user binding; unrelated Applications and unbound Project users receive no
  fan-out or Runtime directory visibility;
- replay preserves original event identity/payload/revision and records a new delivery
  lineage, authorization, confirmation, idempotency, and audit outcome;
- login/current-user/refresh projection fixtures are wire-equivalent at one revision and
  never contain provider tokens, SMTP/webhook secrets, `belongs_to`, or unbounded profile;
- end-to-end Application test uses the real server, PostgreSQL outbox worker, signer, and
  HTTP receiver, including a restart between attempts.

**Exit condition:** an Application can build a reliable bounded local user view without
polling an unbounded directory. SCIM and bulk-directory sync remain absent from schema,
contracts, Console, CLI, and workers in v1.

### Phase 8 — Breadth, operational hardening, and release qualification

**Vertical journeys:** operators manage the complete implemented lifecycle from the
Console; end users use every enabled authentication method through Runtime; Applications
consume sessions and projection synchronization; a deployment can upgrade, split planes,
back up/restore, and diagnose bounded failures without exposing secrets.

**Bottom-up work**

1. Add remaining approved provider adapters through the established conformance suite,
   then remaining Control user/identity/session/policy/audit views. Do not broaden ports to
   fit vendor payloads.
2. Complete Runtime-capable (`runtime`/`all`) worker composition for mail, provider sync,
   and webhooks with PostgreSQL leases, independent budgets, graceful drain,
   readiness/capability reporting, and safe multi-process duplication. `control` can enqueue
   and inspect but does not execute outbound jobs; queue correctness never depends on one
   process, Redis lock, or Control availability.
3. Complete per-plane pools, priority/fairness, Redis degradation, circuit/deadline policy,
   cleanup/retention jobs, audit query bounds, and Project-specific capability health.
4. Finish Console and Hosted UI accessibility, focus/error behavior, malicious-value
   handling, responsive layouts, direct navigation, authentication-failure clearing, and
   every approved high-impact confirmation. Unsupported features are omitted rather than
   shown as nonfunctional controls.
5. Exercise signer and purpose-separated data-protection rotation, operator-key rollout,
   provider/SMTP outage, webhook backlog, migration lock contention, shutdown, and complete
   backup/restore inventory: email canonicalization/digest versions and aliases, long-term
   email PII keys, managed-credential AEAD ciphertext/keys/renewal operations, short-term
   login/challenge/mail keys, pinned Project/default SMTP generation registry/status and
   secret handles, webhook overlap references, projection
   expansion/events/deliveries, signer state, and loss of retained material.
6. Prove expand/migrate/switch/contract compatibility, artifact contents and licenses,
   identical web digest, source-free/no-network runtime image, and server-backed SDK
   conformance against the same instance.
7. After the reviewed Control commands are stable, add the public
   origin-root `/.well-known/owlauth` descriptor and self-hosted Streamable HTTP MCP adapter. Implement
   normal protocol initialization/tool discovery, per-request `owl_ctrl` authentication,
   bounded hand-designed tools, a server-owned impact-class catalog with fail-safe
   high-impact defaults, preview/commit confirmation, Control-only routing, and
   protocol/version conformance. Do not generate tools from OpenAPI and do not add a
   stdio/local process mode. Add the CLI's complete self-hosted descriptor-pin lifecycle
   and typed Control-client path; the SaaS client/MCP remain outside this server plan.

**Dependencies:** completed vertical phases for every feature included in the release.

**Tests and acceptance**

- specs 03, 04, 08, 09, and 11 concurrency/failure matrices pass in combined and split
  topology against one PostgreSQL authority;
- Runtime survives Control outage in split topology, and Control never requires Runtime
  RPC; separate database targets fail configuration even if histories match;
- load tests demonstrate bounded callback/handoff/refresh, mail, provider sync, webhook,
  and Control-list resource use with per-Project fairness and no unbounded queues;
- security tests cover cross-Project references, request ambiguity/bounds, SSRF, open
  redirect, CSRF/origin/fetch metadata, CORS, CSP, DOM injection, cache classes, credential
  redaction, cross-plane route/asset confusion, MCP Host/Origin/DNS-rebinding defenses,
  key/session separation, and no Runtime/local MCP route;
- table-driven CLI discovery tests cover first-use and one-shot confirmation; missing,
  malformed, duplicate-field, and unsupported-schema descriptors; redirect, TLS, and
  cross-origin URL rejection; invalid product/credential pairing; and every product,
  instance, authority, API-base, and credential-class pin change. An observable credential
  provider proves these cases fail before key access, and test servers prove that no
  `Authorization` probe reaches either product. Rebind tests prove old credentials,
  identity-bound target context, and derived caches are cleared before new selection;
- authenticated capability/version negotiation failure, unsupported commands, transport
  failure, and `401`/`403`/`404` prove there is no other-client probe, credential crossover,
  product rediscovery, or post-failure fallback. MCP catalog conformance proves every
  high-impact mutation has only the enforced preview/commit path and no lower-class alias;
- restore resumes workers only from committed generations/cursors/outboxes; short-term
  missing keys terminalize defined work, while long-term email PII/active credentials require
  proven re-encryption before retirement or remain unready. External reference loss fails
  only its purpose closed; Redis is disposable;
- no password authentication, silent email linking, downstream provider-token broker,
  SCIM, bulk directory, server-side Control principal/session, or SaaS/RBAC behavior has
  entered the standalone server accidentally.

**Exit condition:** release evidence covers complete implemented journeys and operational
failure modes. A green build of isolated mocks or static shells is insufficient.

## 5. Journey-to-phase traceability

| Actor journey | First complete phase | Later extension |
| --- | --- | --- |
| Operator enters one deployment key and creates Project/Application | 1 | full lifecycle and hardening in 8 |
| Operator CLI discovers/pins self-hosted endpoint and remote MCP self-describes bounded tools | 8 | SaaS CLI/MCP delivery is owned by a separate SaaS plan |
| Operator provisions signing and assigns a provider | 2 | more adapters/rotation in 8 |
| End user federates and Application exchanges handoff | 3 | managed connection sync in 6 |
| Application receives first binding/projection at handoff | 3 | current-user/refresh in 4; projection evolution/webhooks in 7 |
| Application refreshes/current-user; user logs out | 4 | projection evolution/webhooks in 7 |
| End user signs in by OTP or magic link | 5 | projection events in 7 |
| End user/operator resolves provider reauthorization/revoke/disconnect | 6 | operational backlog/fairness in 8 |
| Application receives signed user changes and requests replay | 7 | release/load/recovery evidence in 8 |
| Split deployment upgrades and restores safely | 8 | ongoing release qualification |

## 6. Global definition of done for an implemented capability

A capability is complete only when all applicable items below are true:

- its behavior is owned by a reviewed normative spec and its public vocabulary by
  `owlauth-types`;
- domain invariants and error meanings have no adapter/vendor types;
- Project ownership is explicit in commands, repository predicates, and PostgreSQL
  constraints;
- the migration is reviewed, embedded, verifiable without DDL, rollback/recovery aware,
  and compatible with the declared rolling window;
- mutations, idempotency, revisions, one-use state, outbox records, and audit commit at the
  owning transaction boundary;
- every external call has an endpoint policy, timeout, bounds, retry/ambiguity rule,
  idempotency/reconciliation story, and redaction tests;
- Runtime and Control DTOs/OpenAPI/clients remain plane-pure and clean regeneration is
  deterministic;
- any web workflow uses the real contract, configured plane base, embedded assets, strict
  security headers, accessible interaction, and no secret-bearing browser persistence;
- combined and relevant split-mode composition, readiness, drain, backup/restore, and
  dependency-loss behavior are tested;
- unit, real-PostgreSQL integration, adapter, HTTP, browser, and server-backed E2E labels
  accurately describe what they exercise;
- unsupported behavior is absent rather than simulated, including silent email linking,
  Application provider-token brokering, SCIM, and bulk-directory synchronization.

## 7. Primary sequencing risks and controls

| Risk | Control in this plan |
| --- | --- |
| Initial schema/domain “big bang” | migration groups and ports land only with their first complete journey |
| UI outruns real server behavior | generated-client order and phase exits forbid mocked-core product E2E |
| TS-001/TS-002 spike becomes throwaway PoC | spike artifacts are production-shaped, retained, and extended |
| Provider/email/webhook external effects cross a DB transaction | durable claim/reconcile/outbox patterns; no network call under transaction |
| Outboxes become a hidden message-broker authority | PostgreSQL remains authoritative; workers use leases and at-least-once idempotency |
| Identity is silently unified by email | issuer/subject and explicit proof rules are tested in federation, email, sync, and projection phases |
| Managed connections become token brokering | purpose-bound `ManagedCredentialProtector`, PostgreSQL generation fencing, metadata-only contracts, and explicit route/source negative tests |
| Projection/webhook payload grows into a directory dump | bounded allowlisted revisioned projection; no SCIM/bulk v1 |
| Console key leaks while adding workflows | page-memory client construction/disposal and storage/DOM/network checks accompany every Console phase |
| Shared web tooling erodes plane separation | independent graph/client/manifest/embed closure and cross-plane byte retrieval tests on every build |
| Background workers starve authentication | independent budgets, Project fairness, bounded claims, and critical-path priority before release |
| A final “hardening phase” hides missing security | each phase has security/operations exit criteria; Phase 8 validates integration rather than inventing them |

The next implementation change should start at Phase 0 and may prepare later schema or
contract design only far enough to preserve compatibility. It should not expose a later
journey until that journey's full phase exit condition can be met.
