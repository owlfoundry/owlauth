# OwlAuth database migration

OwlAuth's authoritative PostgreSQL schema is embedded from this directory by SQLx 0.9.

Before the first server release, the complete schema is intentionally maintained as one initial migration: `20260803000000_initial.sql`. It creates the Project/Application ownership graph, Control idempotency and audit authority, one-use MCP confirmation authority, signing and provider lifecycle state, Runtime authentication and session state, passwordless email, managed provider credentials, identity/projection lifecycle, Application synchronization, webhook delivery, durable secret cleanup, and the schema-compatibility floor. There is no supported predecessor database history for this pre-release repository state.

Once the first server release is published, the initial migration becomes immutable. Every later schema change must use an ordered additive migration. Destructive or irreversible changes require an explicit compatibility, rollout, backup, and recovery design; SeaORM schema sync and `sea-orm-migration` never manage the production schema.

Migration execution uses a dedicated connection, a bounded PostgreSQL advisory-lock wait, transactional SQLx history, and bounded failure reporting. `auto` applies compatible pending migrations before either plane reports readiness. `verify` requires the binary's embedded migrations to be a checksum-matching prefix and applies no DDL; `schema_compatibility.minimum_binary_schema_level` separately controls qualified forward expansion history.

Deployment operators own backup scheduling and restore orchestration. A usable recovery point must keep PostgreSQL, software signer/configuration-secret stores, process configuration, opaque references, and every still-referenced retained key version mutually consistent. Stop serving before rollback, restore that complete set, and restart with `OWLAUTH_MIGRATION_MODE=verify`. Missing external references or required retained keys intentionally fail closed for the affected capability.

The target invariants are defined in [`spec/04-storage-and-migrations.md`](../../../spec/04-storage-and-migrations.md), with the selected repository and migration technology in [`spec/technology/ts-001-postgresql-repositories-and-migrations.md`](../../../spec/technology/ts-001-postgresql-repositories-and-migrations.md).
