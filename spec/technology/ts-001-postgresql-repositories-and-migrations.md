# TS-001 — PostgreSQL repository and migration stack

> Registered in [`spec/10`](../10-implementation-technology-selections.md); storage and migration behavior remains owned by [`spec/04`](../04-storage-and-migrations.md).

- **Requirement owner:** spec 04
- **Decision date:** 2026-07-29
- **Implementation validation:** one narrow spike for migration locking and transaction expressibility; remaining evidence comes from ordinary adapter, integration, and release tests

### Selection

`crates/owlauth-server` uses:

- PostgreSQL as the sole authoritative transactional store;
- SeaORM 2 for ordinary PostgreSQL repository and Unit-of-Work implementations;
- SQLx 0.9 only for embedded SQL migrations, DDL-free serving-schema compatibility verification, and migration-focused tests;
- rustls-based Tokio runtime integration for both libraries;
- ordered migration files under `crates/owlauth-server/migrations/`.

SeaORM entities, active models, query expressions, connections, and errors remain private to the PostgreSQL adapter. Application-owned repository and Unit-of-Work ports expose semantic domain inputs/results and explicit conflict classes. A transaction-bound Unit of Work supplies all repositories and the durable audit appender participating in one command.

Direct SQLx queries are not an alternate ordinary repository style. A repository may use SQLx only if this decision is explicitly revised after evidence that SeaORM cannot express a required critical operation safely; incidental convenience is not sufficient.

The production schema is controlled only by reviewed SQL migration files. SeaORM schema synchronization and entity-registry schema management are disabled. OwlAuth does not depend on `sea-orm-migration` and does not introduce a separate persistence or migration workspace crate.

### Dependency profile

The intended minimal feature profile is:

| Dependency    | Required feature categories                                                          | Explicitly excluded                                                |
| ------------- | ------------------------------------------------------------------------------------ | ------------------------------------------------------------------ |
| `sea-orm` 2.x | macros, Tokio rustls runtime, PostgreSQL, UUID/time/JSON mappings used by the schema | default features, `schema-sync`, entity-registry schema management |
| `sqlx` 0.9.x  | macros, migrate, PostgreSQL, Tokio runtime, rustls TLS                               | unrelated database drivers and use as an ordinary repository layer |

Exact patch versions are controlled by `Cargo.lock` and normal dependency review. A major/minor upgrade that changes migration history, locking, feature activation, transaction behavior, or supported Rust toolchain requires revalidation of this selection.

### Why this selection

SeaORM best matches the requirement for a complete async ORM, typed entity relationships, and maintainable repository code while preserving application-owned ports. SQLx's migration subsystem provides compile-time embedding of SQL files and PostgreSQL advisory locking without making handwritten SQL the default repository style.

Keeping the boundary narrow avoids three failure modes:

1. production schema convergence through ORM metadata rather than reviewed migrations;
2. two competing query styles in ordinary repositories;
3. a custom OwlAuth migration-history, checksum, or cross-process locking subsystem.

SQLx's own `_sqlx_migrations` history and checksum behavior is library infrastructure. OwlAuth applies an append-only released-migration policy and does not create a second history table or checksum algorithm.

### Alternatives considered

| Alternative                                      | Decision                                                                                                                                                             |
| ------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SQLx for both repositories and migrations        | Viable fallback if validation exposes an intrinsic SeaORM limitation, but does not satisfy the current full-ORM preference as well                                   |
| Diesel plus `diesel-async`                       | Strong compile-time query model, but higher integration and repository complexity for the current async service                                                      |
| SeaORM plus `sea-orm-migration`                  | Rejected because the evaluated 2.0 dependency path activates unwanted SeaORM schema features and does not supply the selected documented cross-process lock behavior |
| SeaORM schema sync                               | Rejected for production because runtime model convergence is not a reviewed, ordered, rolling-deployment migration contract                                          |
| Mixed SeaORM and direct SQLx repositories        | Rejected because ownership and query conventions become ambiguous                                                                                                    |
| Custom OwlAuth migration/checksum/lock framework | Rejected as unnecessary infrastructure already covered by SQLx and PostgreSQL                                                                                        |

### Required validation evidence

Before broad repository implementation, one disposable-PostgreSQL spike MUST prove concurrent migration locking/timeout behavior and one representative Unit-of-Work plus one-use conditional mutation. The remaining items are ordinary adapter, integration, and release-compatibility tests rather than separate PoCs. Together, validation MUST prove:

1. concurrent startup serializes SQLx migrations and bounded `lock_timeout` failure releases the dedicated connection/session lock;
2. configuration admits only one PostgreSQL server/database authority per deployment; migration configuration may replace only the login credential/owner role and cannot redirect DDL, while every Runtime/Control pool against the same target detects pending, missing, modified, dirty, and database-ahead migration history in `auto` or DDL-free `verify` flow;
3. the migration session activates the configured non-login owner role and resulting schema/table/history ownership and serving grants are correct;
4. Runtime and Control SeaORM pools remain separately bounded under exhaustion;
5. one application-owned Unit of Work atomically spans representative cross-repository mutation and durable audit append, including rollback and error mapping;
6. one-use conditional mutation/row-lock behavior is expressible without leaking ORM types;
7. after the compatibility-aware bridge release, the specifically declared N-1 artifact starts in both `verify` and `auto` modes and operates safely against the expanded N schema during rolling overlap; the bridge's exact-history predecessor is drained before bridge migration instead of being misrepresented as compatible.

Failure of a gate pauses implementation. If failure is intrinsic to SeaORM rather than the adapter design, the fallback decision is SQLx-only repositories plus SQLx migrations; it is not an unbounded mixed stack.

### Revisit triggers

Revisit `TS-001` only when evidence shows one of:

- SeaORM cannot preserve a required transaction, row-lock, constraint, or performance invariant;
- a supported Rust/toolchain or security constraint makes the selected dependency profile untenable;
- SQLx migration locking/history semantics no longer satisfy spec 04;
- deployment architecture changes away from one PostgreSQL authority;
- measured critical-path behavior cannot be corrected within the adapter boundary.
