# OwlAuth architecture specifications

This directory defines the normative high-level architecture of the self-hosted OwlAuth server: system boundaries, project isolation, authentication flows, data structures, consistency rules, security invariants, and deployment topology.

OwlAuth is a project-scoped authentication and identity service. It uses OAuth/OIDC only when federating to upstream identity providers such as GitHub or Google. Downstream applications consume OwlAuth's project authentication, session, user, and token APIs; OwlAuth does not act as a general-purpose OAuth authorization server for them.

The server deliberately has a single deployment-level operator trust model rather than organizations, memberships, tenant RBAC, customer API keys, or billing. OwlAuth is a self-hosted product and does not define a separate multi-tenant service.

User guidance belongs in [`docs/`](../docs/). Language-neutral SDK behavior belongs in [`sdks/spec/`](../sdks/spec/). Generated OpenAPI documents are derived from Rust definitions in `crates/owlauth-types`.

## Specification map

| Spec                                                                                                                         | Owning concern                                                                                                                      |
| ---------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| [`01-system-context-and-goals.md`](01-system-context-and-goals.md)                                                           | product model, Project/Application boundaries, logical planes, and standalone/integrated topology                                   |
| [`02-domain-and-crate-boundaries.md`](02-domain-and-crate-boundaries.md)                                                     | shared application/domain core, package ownership, use cases, and dependency direction                                              |
| [`03-project-auth-flows-and-security-invariants.md`](03-project-auth-flows-and-security-invariants.md)                       | upstream provider authentication, handoff, project sessions/tokens, refresh, and logout                                             |
| [`04-storage-and-migrations.md`](04-storage-and-migrations.md)                                                               | PostgreSQL authority, Redis roles, project-scoped data model, transactions, migrations, and recovery                                |
| [`05-http-contract-and-surface-boundaries.md`](05-http-contract-and-surface-boundaries.md)                                   | Runtime and Control HTTP surfaces, listener isolation, DTO ownership, and error contracts                                           |
| [`06-operations-configuration-and-security.md`](06-operations-configuration-and-security.md)                                 | process composition, configuration, project keys, health, observability, and network posture                                        |
| [`07-cli-and-mcp-boundaries.md`](07-cli-and-mcp-boundaries.md)                                                               | deployment-operator Control trust, shared CLI profile boundary, self-hosted HTTP MCP, `belongs_to`, and external gateway boundaries |
| [`08-consistency-resilience-and-plane-separation.md`](08-consistency-resilience-and-plane-separation.md)                     | cross-plane consistency, failure semantics, resource isolation, and physical split conditions                                       |
| [`09-hosted-web-surfaces-and-control-auth.md`](09-hosted-web-surfaces-and-control-auth.md)                                   | Runtime Hosted Authentication UI, Control Management Console, external URL separation, and browser credential/security boundaries   |
| [`10-implementation-technology-selections.md`](10-implementation-technology-selections.md)                                   | implementation technology selection register and decision status                                                                    |
| [`11-identity-connections-passwordless-email-and-user-sync.md`](11-identity-connections-passwordless-email-and-user-sync.md) | managed provider connection/profile sync, passwordless email/SMTP, revisioned user projections, and signed Application webhooks     |
| [`technology/`](technology/README.md)                                                                                        | detailed accepted selections, dependency boundaries, focused validation, alternatives, and revisit triggers                         |

[`implementation-plan.md`](implementation-plan.md) is the tracked bottom-up execution sequence for the server and hosted web surfaces. It is not behavioral authority: when it conflicts with a numbered specification or accepted technology record, the canonical specification/record wins and the plan must be corrected.

Each requirement has one owning document. Other documents reference that requirement instead of redefining it.

## Authority map

| Concern                                                                                                               | Authority                                                                                                                        |
| --------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Project, application, identity, provider, login, session, refresh, token, key, and policy rules                       | Internal application and domain modules of `crates/owlauth-server`                                                               |
| Public Runtime and Control HTTP DTOs and OpenAPI definitions                                                          | Rust definitions in `crates/owlauth-types`                                                                                       |
| PostgreSQL schema and migration assets                                                                                | `crates/owlauth-server/migrations/`                                                                                              |
| Runtime and Control composition, listeners, persistence adapters, embedded hosted web surfaces, and operational ports | `crates/owlauth-server`                                                                                                          |
| Public remote administration client                                                                                   | one `crates/owlauth-cli` executable whose profiles discover and pin a self-hosted `owlauth-server` endpoint                      |
| Self-hosted MCP protocol/tool adapter                                                                                 | the optional remote Streamable HTTP MCP surface in `crates/owlauth-server` Control; it is not part of OpenAPI or the CLI process |
| Language-neutral SDK behavior                                                                                         | [`sdks/spec/`](../sdks/spec/) and generated public contracts                                                                     |
| User-facing operational guidance                                                                                      | [`docs/`](../docs/)                                                                                                              |

## Cross-cutting invariants

01. One OwlAuth deployment is one administrative trust domain. Its Control API accepts only the deployment's `OWLAUTH_CONTROL_API_KEY`; a valid key has full Control authority. It may contain many isolated Projects but is not itself a multi-tenant organization or RBAC system.
02. A Project is the identity and authentication isolation boundary. Applications within one Project share its user directory; users, linked identities, sessions, refresh families, provider credentials, and token namespace never cross Projects.
03. `belongs_to` is optional opaque Project metadata for an external control system. It is indexed but is not a tenant, principal, scope, or OwlAuth authorization boundary.
04. OwlAuth has one shared application/domain core. Runtime HTTP, Control HTTP, the CLI's Control adapter, and remote HTTP MCP do not own alternate server business rules.
05. PostgreSQL is the authoritative transactional store. Redis is non-authoritative and cannot prove identity, handoff consumption, session validity, refresh rotation, revocation, Project status, or key state.
06. Runtime / Protocol Plane and Control Plane use distinct listeners and authentication policies even when composed into one process.
07. Control adapters cannot mutate tables directly. Every mutation passes through an application service and Project-bound domain invariants.
08. Provider callbacks and application redirects are distinct URL classes and both use exact registered values. Login state, handoff tickets, refresh tokens, and sessions have explicit binding and replay semantics.
09. Browser applications receive only public Project/Application configuration. Provider secrets, the operator API key, refresh-token digests, and private keys never enter public configuration or logs. Runtime never accepts the operator API key.
10. Private signing and data-protection keys exist only behind key-provider interfaces. PostgreSQL contains public material and opaque references, never ordinary private-key bytes.
11. The server is one Rust server package and one binary/container artifact. `all`, `runtime`, and `control` are composition modes, not independent domain implementations.
12. Network and storage side effects are bounded and have explicit timeout, retry, idempotency, and failure semantics.
13. Runtime owns the Hosted Authentication UI and Control owns the Management Console. They may use distinct origins or trusted non-overlapping base paths, but never share routers or credentials; the Console keeps the operator key only in active page memory.
14. Managed provider credentials are retained only for OwlAuth's bounded identity-profile synchronization and never brokered downstream. Email proof is one-use and never silently links a provider identity. Application user synchronization is revisioned, bounded to an existing Application-user binding, signed, asynchronous, and durable-outbox-backed.
15. One `owlauth` executable uses endpoint-discovered profiles pinned to the OwlAuth server product, instance, authority, API base, and operator credential class without authenticated identity probing. The optional MCP adapter is a remote Control HTTP surface that self-describes through the protocol; no CLI/plugin bundles a local MCP process.

## Normative language

`MUST`, `MUST NOT`, `SHOULD`, and `MAY` are normative design terms. “Runtime” is shorthand for “Runtime / Protocol Plane.” “Control” means the administrative control plane. “Shared core” means the application services, domain model, and ports used by both planes.
