# OwlAuth database migrations

Versioned PostgreSQL migrations for OwlAuth's authoritative state belong in this directory.

The target schema stores Project-scoped Applications, provider registrations and secret references, users and linked identities, login transactions, handoff tickets, browser and Application sessions, refresh families, public key metadata, deployment-operator idempotency records, and audit events. Project ownership must be enforceable through direct or composite database constraints; Redis is never authoritative for these records.

SQLx 0.9 embeds these migrations into the `owlauth-server` artifact and applies compatible pending migrations before either Runtime or Control reports readiness. Migration execution uses SQLx's PostgreSQL migration history/locking and must be serialized, transactional where PostgreSQL permits it, safe to retry, and fail startup rather than expose a newer binary against an incompatible schema. SeaORM 2 implements ordinary repositories, but SeaORM schema sync and `sea-orm-migration` do not manage the production schema.

Destructive or irreversible migrations require an explicit compatibility, rollout, backup, and recovery design. Expand-and-contract changes must preserve mixed-version operation for the declared rollout window.

> The current pre-alpha server scaffold does not implement persistence or the migration runner, and this directory does not yet contain schema migrations.

The target storage and migration invariants are defined in [`spec/04-storage-and-migrations.md`](../../../spec/04-storage-and-migrations.md).
