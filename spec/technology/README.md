# Implementation technology decisions

This directory contains detailed, canonical technology decision records registered by [`spec/10`](../10-implementation-technology-selections.md).

| ID | Decision | Requirement owner |
| --- | --- | --- |
| [`TS-001`](ts-001-postgresql-repositories-and-migrations.md) | PostgreSQL repositories and migrations | [`spec/04`](../04-storage-and-migrations.md) |
| [`TS-002`](ts-002-hosted-web-and-asset-pipeline.md) | Hosted web surfaces and asset pipeline | [`spec/09`](../09-hosted-web-surfaces-and-control-auth.md) |

The register is the sole authority for decision status and answers which technologies are approved. Each detail record owns the dependency profile, rationale, rejected alternatives, focused validation, and revisit triggers. Concern-specific specs continue to own behavior and security invariants.

Create another decision record only when a concrete choice is costly to reverse, constrains multiple adapters, or materially affects an architecture or security boundary. Mature, reversible implementation dependencies do not require a record merely because they are dependencies. A focused spike is required only for a material uncertainty whose failure would change the architecture or cause expensive rework; all other evidence belongs in ordinary implementation tests.
