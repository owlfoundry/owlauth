---
layout: home

title: OwlAuth
titleTemplate: Self-hostable project authentication

hero:
  name: OwlAuth
  text: Project-scoped authentication infrastructure
  tagline: Self-host users, upstream identity federation, sessions, and tokens for related applications—without turning your product model into OAuth client plumbing.
  actions:
    - theme: brand
      text: Understand OwlAuth
      link: /guide/architecture
    - theme: alt
      text: Develop OwlAuth
      link: /guide/getting-started
    - theme: alt
      text: View on GitHub
      link: https://github.com/owlfoundry/owlauth

features:
  - title: Project isolation
    details: Each Project owns its users, linked identities, provider configuration, sessions, refresh families, token namespace, and signing keys.
  - title: Application sharing
    details: Web, mobile, native, and server Applications inside one Project share its user directory and Project token trust boundary.
  - title: Upstream federation and managed profiles
    details: OwlAuth uses OAuth or OIDC only with upstream identity providers and may retain a server-only least-scope renewable credential for bounded profile synchronization.
  - title: Passwordless email
    details: Projects can host OTP and magic-link authentication through Project-selected SMTP, with one-use proofs and no silent email linking.
  - title: Application user synchronization
    details: Applications receive bounded revisioned user projections and optional signed durable webhooks only for users already bound to them.
  - title: Auth and Control separation
    details: Auth hosts isolated Runtime and Server API routers, while privileged administration uses an independent Control listener over the same application and domain core.
  - title: Hosted web surfaces
    details: Runtime provides hosted end-user authentication pages, while Control provides an API-key-driven Management Console in the same server artifact.
  - title: First-party SDK design
    details: TypeScript, Python, and Rust clients target the Runtime Project Auth contract, including PKCE handoff and coordinated refresh behavior.
  - title: Self-hosted authority
    details: PostgreSQL is the durable authority, and private signing or data-protection keys stay behind provider interfaces.
---

::: warning Beta
OwlAuth is pre-1.0. APIs and deployment requirements may change; review the deployment and security guides before operating it.
:::

## The product model

A single OwlAuth **Deployment** is one administrative trust domain. It can contain many isolated **Projects**. A Project represents one product or related application family, and contains one or more **Applications**.

```mermaid
flowchart TB
    D[OwlAuth Deployment]
    D --> P1[Project A]
    D --> P2[Project B]
    P1 --> A1[Web Application]
    P1 --> A2[Mobile Application]
    P1 --> U1[Shared Project A users and sessions]
    P2 --> A3[Server Application]
    P2 --> U2[Independent Project B users and sessions]
```

Applications in one Project share users and Project token trust. Applications that require isolated users or token audiences belong in separate Projects. A person using the same GitHub identity in two Projects maps to two independent Project users.

OwlAuth owns authentication, identity linking, Project sessions, and Project token claims. Your application backend still owns business authorization—organizations, memberships, billing roles, document access, and other product policy.

## OAuth/OIDC is upstream only

OwlAuth can broker sign-in to a Project's configured upstream provider or verify a first-party email OTP/magic link, then returns an OwlAuth Project user projection and session credentials through the same one-use, PKCE-bound handoff. Downstream Applications consume the **Project Auth API**; they do not register general OAuth grants or receive OAuth/OIDC provider tokens from OwlAuth.

A Project access token is an OwlAuth application-session JWT. It is not an upstream provider token and it does not make OwlAuth a general-purpose OAuth authorization server.

## Read next

- [Deployment](/guide/deployment) — released artifacts, production configuration, TLS ingress, PostgreSQL, scaling, probes, upgrades, and tested recovery.
- [Architecture](/guide/architecture) — Projects, Applications, authentication flow, logical planes, storage, and deployment modes.
- [Getting started](/guide/getting-started) — build, validate, and inspect the current Beta implementation.
- [SDKs](/guide/sdks) — implemented protocol operations and the explicit Application-owned state boundary.
- [Building a SaaS](/guide/building-saas) — compose external tenant authorization, managed cells, reconciliation, and billing around self-hosted OwlAuth.
- [CLI and agent integrations](/guide/agent-integrations) — endpoint-discovered CLI boundaries, documentation plugin, and remote HTTP MCP capabilities.
- [Security](/guide/security) — target invariants, operational trust boundaries, and vulnerability reporting.
