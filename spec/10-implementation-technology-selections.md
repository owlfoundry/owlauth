# 10 — Implementation technology selections

## Purpose and decision states

This document records concrete implementation technologies after the architecture requirements that constrain them are stable. It prevents adapters from drifting into incompatible stacks while keeping domain and application policy independent of vendors.

Decision states are:

- **Accepted:** approved for implementation; acceptance does not waive the stated validation gate;
- **Proposed:** preferred but awaiting explicit approval or evidence;
- **Research needed:** requirements exist, but candidates have not been compared;
- **Superseded:** retained with a pointer to the replacement decision.

Architecture behavior remains owned by the concern-specific specs. This register owns decision identity, approval status, selected stack, and the pointer to its detailed record. Detailed records own rationale, dependency boundaries, focused validation, and revisit triggers. A technology not listed here is not implicitly approved merely because it can satisfy an interface.

## Selection register

| ID                                                                      | Concern                                                     | Status   | Selection                                                                                                          | Requirement owner                                                                                                                                                                                                   |
| ----------------------------------------------------------------------- | ----------------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`TS-001`](technology/ts-001-postgresql-repositories-and-migrations.md) | PostgreSQL repository and migration stack                   | Accepted | SeaORM 2 repositories plus SQLx 0.9 embedded SQL migrations                                                        | [`spec/04`](04-storage-and-migrations.md)                                                                                                                                                                           |
| [`TS-002`](technology/ts-002-hosted-web-and-asset-pipeline.md)          | Hosted Authentication UI and Management Console toolchain   | Accepted | React 19 + TypeScript + Vite 8, plane-specific OpenAPI clients/manifests, and `rust-embed` 8                       | [`spec/09`](09-hosted-web-surfaces-and-control-auth.md)                                                                                                                                                             |
| [`TS-003`](technology/ts-003-key-provider-and-postgresql-custody.md)    | Signing/configuration-secret custody and provider extension | Accepted | Public statically linked Rust SPI plus bundled PostgreSQL-envelope software custody; no bundled KMS implementation | [`spec/02`](02-domain-and-crate-boundaries.md), [`spec/04`](04-storage-and-migrations.md), [`spec/06`](06-operations-configuration-and-security.md), [`spec/08`](08-consistency-resilience-and-plane-separation.md) |

Detailed records are indexed in [`spec/technology/`](technology/README.md). This register remains the single list of approved implementation technologies.
