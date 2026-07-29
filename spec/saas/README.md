# OwlAuth SaaS architecture specifications

This directory defines the normative architecture for operating OwlAuth as a multi-tenant SaaS product. It is a separate product layer over one or more ordinary `owlauth-server` deployments.

The SaaS layer owns tenant identity, administration, authorization, commercial policy, and fleet orchestration. `owlauth-server` remains a single-operator Project Auth service. Its Control API accepts one deployment-level operator API key configured through `OWLAUTH_CONTROL_API_KEY`; it does not implement organizations, memberships, tenant roles, customer API keys, subscriptions, or billing.

These documents describe product and service boundaries. They do not require the SaaS implementation to live in `crates/owlauth-server`, use the server's internal modules, or share its database. The SaaS layer consumes only published OwlAuth Runtime and Control contracts.

## Specification map

| Spec | Owning concern |
| --- | --- |
| [`01-system-context-and-boundaries.md`](01-system-context-and-boundaries.md) | product topology, Platform Identity, Managed Auth cells, trust boundaries, and exclusions |
| [`02-domain-and-data-ownership.md`](02-domain-and-data-ownership.md) | Account, Organization, membership, service account, managed Project, subscription, and authority boundaries |
| [`03-authentication-authorization-and-api-keys.md`](03-authentication-authorization-and-api-keys.md) | platform authentication, tenant RBAC, SaaS API keys, request authorization, and operator separation |
| [`04-managed-cells-and-control-workflows.md`](04-managed-cells-and-control-workflows.md) | cell registry, Project provisioning, `belongs_to`, Control gateway behavior, reconciliation, and Runtime routing |
| [`05-billing-entitlements-and-metering.md`](05-billing-entitlements-and-metering.md) | plans, subscriptions, entitlements, quotas, usage measurement, and billing failure semantics |
| [`06-operations-security-and-resilience.md`](06-operations-security-and-resilience.md) | deployment isolation, secret handling, recovery, audit, support access, and availability |

The root [`spec/`](../README.md) remains authoritative for each `owlauth-server` deployment. This directory is authoritative only for the SaaS layer and its orchestration of those deployments. Where an OwlAuth server invariant is referenced here, the root specification owns its detailed semantics.

## Authority map

| Concern | Authority |
| --- | --- |
| SaaS accounts, organizations, memberships, roles, invitations, service accounts, and customer API keys | SaaS transactional database and SaaS authorization services |
| Plans, subscriptions, entitlements, commercial limits, invoices, and billing state | SaaS transactional database plus the configured payment provider where explicitly reconciled |
| Cell assignment and Organization-to-Project ownership registry | SaaS transactional database |
| Project authentication, Project users, linked identities, applications, providers, sessions, tokens, and signing keys | The assigned `owlauth-server` deployment and its PostgreSQL authority |
| Project `belongs_to` | OwlAuth Project metadata used as a checked copy of the SaaS Organization identifier; never the SaaS ownership authority by itself |
| Platform administrator authentication | A separate Platform Identity OwlAuth deployment; Organization authorization remains in the SaaS layer |
| Deployment-level OwlAuth Control authorization | The configured `OWLAUTH_CONTROL_API_KEY` for that managed deployment |
| Detailed tenant actor attribution | SaaS audit records; a managed OwlAuth server sees only its deployment operator |

## Cross-cutting invariants

1. OwlAuth SaaS is an external multi-tenant control system, not a mode or hidden tenant subsystem inside `owlauth-server`.
2. Platform Identity and customer Managed Auth use separate OwlAuth deployments, databases, operator keys, and cryptographic namespaces in production.
3. A SaaS Organization may own multiple OwlAuth Projects. An OwlAuth Project belongs to exactly one SaaS Organization in the SaaS registry while managed by the service.
4. SaaS Account, Organization Member, and managed Project User are distinct identities. A Project User never gains Organization administration by authenticating to a customer application.
5. Tenant callers authenticate only to the SaaS surface. They never receive or directly use a managed deployment's `OWLAUTH_CONTROL_API_KEY`.
6. Every SaaS management request authorizes the external principal, Organization, action, and target resource before issuing an allowlisted OwlAuth Control command.
7. The SaaS registry is the ownership authority. OwlAuth `belongs_to` and `metadata_revision` are checked as defense-in-depth against stale or confused-deputy mutations.
8. Customer Runtime authentication does not synchronously depend on the SaaS API, Platform Identity, payment provider, or OwlAuth Control listener.
9. Billing and commercial policy are not inferred from lossy logs, metrics, or security audit events. Billable usage requires an explicit durable measurement contract.
10. A managed Project has a stable cell assignment and Runtime issuer. Moving it between deployments is not assumed to be transparent.
11. The SaaS layer never imports `owlauth-server` implementation modules or reads/writes an OwlAuth database directly.
12. The managed deployment operator key is a fleet secret with full Control authority for that deployment. Network isolation, per-cell credentials, secret rotation, and strict gateway allowlists contain its blast radius.

## Normative language

`MUST`, `MUST NOT`, `SHOULD`, and `MAY` are normative design terms. “Platform Identity” means the isolated OwlAuth deployment used to authenticate SaaS accounts. “Managed Auth” means OwlAuth deployments serving customer Projects. A “cell” is one independently operated Managed Auth deployment and its data/cryptographic dependencies. “SaaS API key” means a customer credential for the SaaS API; “operator API key” means the deployment secret accepted by an OwlAuth Control listener. They are never interchangeable.
