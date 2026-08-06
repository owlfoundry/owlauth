# PostgreSQL migrations

This directory is OwlAuth's clean pre-deployment schema baseline.

- `20260806000000_foundation.sql` creates functions and tables.
- `20260806001000_authorities.sql` seeds the required singleton authorities.
- `20260806002000_invariants.sql` installs keys, constraints, indexes, and triggers.

The history was rebuilt before the first deployed schema and contains only the final model. Once
any production database has applied this baseline, these files and checksums are immutable. Future
changes must be new ordered migrations.

OwlAuth verifies the applied SQLx history exactly: migration count, version, success state, and
checksum must match the running binary.
