# OwlAuth architecture specifications

This directory defines the normative high-level architecture of OwlAuth: system boundaries, project isolation, authentication flows, data structures, consistency rules, security invariants, and deployment topology.

OwlAuth is a project-scoped authentication and identity service. It uses OAuth/OIDC only when federating to upstream identity providers such as GitHub or Google. Downstream applications consume OwlAuth's project authentication, session, user, and token APIs; OwlAuth does not act as a general-purpose OAuth authorization server for them.

User guidance belongs in [`docs/`](../docs/). Language-neutral SDK behavior belongs in [`sdks/spec/`](../sdks/spec/). Generated OpenAPI documents are derived from Rust definitions in `crates/owlauth-types`.

## Specification map

| Spec | Owning concern |
| --- | --- |
| [`01-system-context-and-goals.md`](01-system-context-and-goals.md) | product model, Project/Application boundaries, logical planes, and standalone/integrated topology |
| [`02-domain-and-crate-boundaries.md`](02-domain-and-crate-boundaries.md) | shared application/domain core, package ownership, use cases, and dependency direction |
| [`03-project-auth-flows-and-security-invariants.md`](03-project-auth-flows-and-security-invariants.md) | upstream provider authentication, handoff, project sessions/tokens, refresh, and logout |
| [`04-storage-and-migrations.md`](04-storage-and-migrations.md) | PostgreSQL authority, Redis roles, project-scoped data model, transactions, migrations, and recovery |
| [`05-http-contract-and-surface-boundaries.md`](05-http-contract-and-surface-boundaries.md) | Runtime and Control HTTP surfaces, listener isolation, DTO ownership, and error contracts |
| [`06-operations-configuration-and-security.md`](06-operations-configuration-and-security.md) | process composition, configuration, project keys, health, observability, and network posture |
| [`07-cli-and-mcp-boundaries.md`](07-cli-and-mcp-boundaries.md) | Control scopes, CLI/MCP adapters, `belongs_to`, and external RBAC gateway boundaries |
| [`08-consistency-resilience-and-plane-separation.md`](08-consistency-resilience-and-plane-separation.md) | cross-plane consistency, failure semantics, resource isolation, and physical split conditions |

Each requirement has one owning document. Other documents reference that requirement instead of redefining it.

## Authority map

| Concern | Authority |
| --- | --- |
| Project, application, identity, provider, login, session, refresh, token, key, and policy rules | Internal application and domain modules of `crates/owlauth-server` |
| Public Runtime and Control HTTP DTOs and OpenAPI definitions | Rust definitions in `crates/owlauth-types` |
| PostgreSQL schema and migration assets | `crates/owlauth-server/migrations/` |
| Runtime and Control composition, listeners, persistence adapters, and operational ports | `crates/owlauth-server` |
| Public remote administration client | `crates/owlauth-cli` through a deliberately isolated Control client surface |
| Language-neutral SDK behavior | [`sdks/spec/`](../sdks/spec/) and generated public contracts |
| User-facing operational guidance | [`docs/`](../docs/) |

## Cross-cutting invariants

1. One OwlAuth deployment is one administrative trust domain with one operator policy. It may contain many isolated Projects but is not itself a multi-tenant organization or RBAC system.
2. A Project is the identity and authentication isolation boundary. Applications within one Project share its user directory; users, linked identities, sessions, refresh families, provider credentials, and token namespace never cross Projects.
3. `belongs_to` is optional opaque Project metadata for an external control system. It is indexed but is not a tenant, principal, scope, or OwlAuth authorization boundary.
4. OwlAuth has one shared application/domain core. Runtime HTTP, Control HTTP, CLI-facing APIs, and MCP adapters do not own alternate business rules.
5. PostgreSQL is the authoritative transactional store. Redis is non-authoritative and cannot prove identity, handoff consumption, session validity, refresh rotation, revocation, Project status, or key state.
6. Runtime / Protocol Plane and Control Plane use distinct listeners and authentication policies even when composed into one process.
7. Control adapters cannot mutate tables directly. Every mutation passes through an application service and Project-bound domain invariants.
8. Provider callbacks and application redirects are distinct URL classes and both use exact registered values. Login state, handoff tickets, refresh tokens, sessions, and management credentials have explicit binding and replay semantics.
9. Browser applications receive only public Project/Application configuration. Provider secrets, management credentials, refresh-token digests, and private keys never enter public configuration or logs.
10. Private signing and data-protection keys exist only behind key-provider interfaces. PostgreSQL contains public material and opaque references, never ordinary private-key bytes.
11. The server is one Rust server package and one binary/container artifact. `all`, `runtime`, and `control` are composition modes, not independent domain implementations.
12. Network and storage side effects are bounded and have explicit timeout, retry, idempotency, and failure semantics.

## Normative language

`MUST`, `MUST NOT`, `SHOULD`, and `MAY` are normative design terms. “Runtime” is shorthand for “Runtime / Protocol Plane.” “Control” means the administrative control plane. “Shared core” means the application services, domain model, and ports used by both planes.
