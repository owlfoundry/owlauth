# 04 — Storage and automatic embedded migrations

## Ownership and current status

Persistence is a server-internal concern under `crates/owlauth-server`. Versioned migration assets belong under [`crates/owlauth-server/migrations/`](../crates/owlauth-server/migrations/), beside the future code that interprets them. The repository currently has only a migration policy README; no persistence port, database schema, adapter, or runner is implemented.

## Persistence contract

Storage adapters MUST preserve domain invariants under concurrency. They MUST expose explicit transaction boundaries and classify expected conditions such as not found, uniqueness conflict, stale version, unavailable storage, and integrity failure. SQL strings, driver internals, and sensitive row values do not cross the public protocol boundary.

The eventual schema SHOULD enforce invariants that can be expressed safely—unique identities, foreign keys, non-null requirements, valid references, and replay-preventing uniqueness—while domain validation remains authoritative for policy. Timestamps use a documented UTC representation. Token and secret columns receive a specific threat/storage design before creation.

Network calls and unbounded computation MUST NOT run inside transactions. Operations that consume an authorization code, rotate a refresh token, or make another one-use state transition MUST perform validation and mutation atomically with well-defined concurrent outcomes.

## Embedded migration contract

1. Migration source files MUST live in `crates/owlauth-server/migrations/`.
2. The server package MUST embed migration bytes at build time; a deployed server MUST NOT depend on a separately copied migration directory.
3. On every startup, after validating configuration and connecting to storage but before readiness or request admission, the server MUST acquire the migration mechanism's required lock and apply every pending migration in order.
4. Migration identity and checksum MUST be recorded. A changed checksum for an already-applied migration MUST fail startup rather than silently rewrite history.
5. Each migration MUST be transactional where supported. If the engine cannot transact an operation, the migration requires an explicit resumability, rollback, backup, and recovery review.
6. Migration execution MUST be safe to retry after process interruption. Multiple server instances starting concurrently MUST serialize or otherwise coordinate schema changes.
7. A migration or schema-compatibility failure MUST leave readiness false and prevent the HTTP, CLI service, or MCP adapter from serving against an incompatible schema.
8. Automatic means no routine operator command is required. Destructive migrations still require release notes and an explicit recovery plan.

The executable SHOULD expose the applied/expected schema versions in authenticated diagnostics or safe telemetry, never by leaking migration SQL or database credentials.

## Compatibility and rollout

A release declares the oldest schema it can read and the schema it will migrate to. Expand/contract changes needed for rolling deployment are staged across compatible releases. Downgrade is not assumed safe: each irreversible change documents backup and restore expectations. Database backup validation precedes migrations classified as destructive or high risk.

Migration files already released are immutable. Corrections use a new forward migration. Development-only squashing is permitted only before any affected migration has shipped and with explicit maintainer agreement.

## Validation

Tests MUST cover:

- an empty database migrating to current;
- every supported previous released schema migrating to current;
- restart with no pending work;
- checksum/history tampering;
- interruption and retry at documented failure points;
- concurrent startup;
- constraint behavior for security-critical one-use state;
- migration failure keeping the service unready.

Tests use real supported database engines where engine semantics matter; mocks alone are insufficient.

## Acceptance criteria

- The built server can start with migration source files absent from the host filesystem.
- No listener reports ready before migrations complete.
- Failed migrations produce actionable, redacted operator diagnostics and no partially exposed newer process.
- Release validation includes forward migration and documented recovery evidence.
