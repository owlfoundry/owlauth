# OwlAuth database migrations

Versioned PostgreSQL migrations for OwlAuth's authoritative state belong in this directory.

The target schema stores Project-scoped Applications, provider registrations and secret references, users and linked identities, login transactions, handoff tickets, browser and Application sessions, refresh families, public key metadata, deployment-operator idempotency records, and audit events. Project ownership must be enforceable through direct or composite database constraints; Redis is never authoritative for these records.

SQLx 0.9 embeds these migrations into the `owlauth-server` artifact and applies compatible pending migrations before either Runtime or Control reports readiness. Migration execution uses a dedicated connection, a bounded PostgreSQL advisory-lock wait, transactional migration history, and bounded failure reporting. `verify` mode directly checks the exact embedded SQLx history without creating or changing database objects. SeaORM 2 implements ordinary repositories, but SeaORM schema sync and `sea-orm-migration` do not manage the production schema.

Destructive or irreversible migrations require an explicit compatibility, rollout, backup, and recovery design. Expand-and-contract changes must preserve mixed-version operation for the declared rollout window.

The initial migration establishes Project and Application ownership, deployment-operator idempotency, and audit records. The additive Control provisioning/readiness migration adds exact redirect/origin registration, publishable Application identifiers, signing rings and lifecycle operations, Runtime publication leases, provider secret operations, and same-Project provider assignments. New migrations must use final domain names and preserve the invariants above.

The target storage and migration invariants are defined in [`spec/04-storage-and-migrations.md`](../../../spec/04-storage-and-migrations.md).
