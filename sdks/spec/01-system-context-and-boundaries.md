# 01 — SDK system context and boundaries

## Purpose and current baseline

The official SDKs make OwlAuth Runtime Project Auth safer and idiomatic in TypeScript, Python, and Rust. They help an Application use its public Project/Application configuration, initiate login through an upstream provider, complete a PKCE-bound handoff, call explicit Project credential operations, read the current Project user, and log out. The core packages expose protocol APIs and enforce protocol safety; they do not own platform navigation, credential persistence, or framework session state.

They are not OAuth authorization servers, identity providers, policy engines, administrative clients, Project Client API wrappers, user-directory SDKs, or substitutes for backend business authorization. OAuth/OIDC details belong between OwlAuth and the configured upstream provider. Downstream Applications use the Project Auth API rather than registering OAuth grants or receiving provider tokens from OwlAuth.

The current TypeScript, Python, and Rust packages are Beta Runtime Project Auth clients. They implement contract-aligned transport, public configuration and JWKS retrieval, caller-held PKCE pending state, callback validation and one-use handoff exchange, credential refresh, current-user queries, and logout, with real-server coverage. The requirements below describe their current safety contract and acceptance gates unless explicitly marked as future work.

## Public Project Auth concepts

| Concept                     | SDK treatment                                                               | Authority                                                            |
| --------------------------- | --------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| Runtime base URL            | explicit trusted configuration; HTTPS in production                         | Application/deployment configuration                                 |
| `project_id`                | public identifier selecting one isolated Project                            | OwlAuth Runtime validates current Project state                      |
| `application_id`            | public identifier selecting one Application in that Project                 | OwlAuth Runtime validates ownership/status                           |
| Publishable Application key | optional public SDK/config identifier                                       | attribution/quota only; never user or Control authority              |
| Public auth configuration   | bounded providers, display/configuration fields, and safe Runtime URLs      | OwlAuth Runtime response                                             |
| Login transaction           | explicit caller-held local correlation plus server transaction result       | Runtime and PostgreSQL are authoritative                             |
| PKCE verifier/challenge     | fresh SDK-generated S256 material returned in one bound pending transaction | Application retains the pending value; Runtime validates at exchange |
| Handoff ticket              | short-lived opaque one-use result delivered at the Application redirect     | Runtime creates and atomically consumes it                           |
| Project access token        | short-lived signed JWT for one Project user/Application session             | Project issuer/audience and signing keys                             |
| Refresh token               | opaque one-use rotating credential for one Application session family       | PostgreSQL-authoritative strict rotation                             |
| Current Project user        | bounded Project-local user/session view                                     | Runtime evaluates token and current state                            |

Public Project/Application identifiers are not secrets and never authenticate Client or Control operations. Project client keys, provider client secrets, provider tokens, management credentials, storage rows, and private signing keys never enter an SDK configuration or response.

## Actors and responsibilities

| Actor                               | Responsibility at the SDK boundary                                                                 | Not provided or decided by the core SDK                                     |
| ----------------------------------- | -------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| Application developer               | typed protocol inputs/results, cancellation, stable errors, and explicit custody of returned state | deciding Project state, identity links, or backend authorization            |
| End user and user agent             | explicit browser/native handoff boundary                                                           | exposing upstream credentials to the SDK                                    |
| OwlAuth Runtime                     | interoperable Project Auth requests                                                                | importing server implementation or trusting SDK assertions                  |
| Upstream provider                   | reached through a Runtime-provided login URL                                                       | direct provider token exchange by the SDK                                   |
| Application backend                 | receives and verifies Project access tokens                                                        | treating the SDK as authorization policy                                    |
| Application integration/state store | navigation, callback placement, persistence, atomic replacement, and refresh serialization         | expecting the core SDK to select platform storage or manage framework state |
| Operator/test runner                | public configuration and safe diagnostics                                                          | receiving credentials in logs/errors                                        |

The Application process, browser/native user agent, network, application-owned state store, backend, and Runtime are separate trust boundaries. Local structure checks improve ergonomics but do not establish Project membership, user identity, or authorization.

## Target layering

A production SDK has four explicit layers:

1. generated or contract-aligned Runtime wire models and low-level operation declarations;
2. handwritten transport and origin/retry policy;
3. handwritten protocol-safety helpers for PKCE generation, callback validation, one-use handoff, strict refresh request semantics, current user, and logout;
4. an idiomatic explicit public API and stable semantic errors.

The core SDKs return navigation targets, pending-login state, credential pairs, and cleanup requirements as explicit values. They do not navigate a user agent, mutate browser history, choose persistent storage, install request interceptors, or maintain framework session state. Browser, native, server-session, and framework convenience layers may be supplied by an Application or another library without changing the Runtime protocol.

Generated Client and Control operations are not part of an SDK. Customer backends consume the independent Client OpenAPI through user-owned generated code, while administrative access belongs to the `owlauth` CLI/Console/MCP Control surfaces. A Runtime SDK cannot gain Client or Control authority merely because DTO definitions share a Rust package.

Applications may use documented low-level Runtime operations, but the default path must preserve safe ordering, redaction, Project/Application binding, and one-use semantics.

## Client construction and Project binding

The intended client configuration includes:

- a trusted Runtime base URL;
- public `project_id` and `application_id`;
- an optional publishable Application key when the Runtime contract requires it;
- explicit transport deadlines and cancellation configuration.

A client instance is bound to one Project/Application pair. Changing either requires a distinct client. Pending-login state and credentials are explicit caller-held values bound to the same Runtime/Project/Application context; a token, refresh family, handoff ticket, provider selection, or public configuration loaded for one pair cannot be reused for another.

Base URLs are parsed and normalized consistently without silently dropping configured path prefixes. Production defaults require HTTPS; loopback development allowances require explicit opt-in. SDKs do not discover another Runtime origin from arbitrary headers or follow credential-bearing redirects across origins.

## Project isolation and backend boundary

Every Runtime path is Project-qualified. The SDK includes the configured Project/Application identifiers where required, but Runtime revalidates them against authoritative state. A caller cannot combine Project A configuration with an Application, ticket, refresh token, or user from Project B.

Project access tokens are JWT credentials for the Project backend, not upstream-provider or generic OAuth access tokens. SDKs may expose token metadata safely, but backend verification is a separate responsibility: signature, algorithm, `kid`, exact Project issuer/audience, token type, time claims, and any allowed `app_id` must be checked.

OwlAuth authenticates a Project user. The Application backend still owns organization membership, document access, billing roles, and other business authorization.

## Language independence

Observable semantics are shared while syntax remains idiomatic:

- TypeScript uses promises, `AbortSignal`, discriminated results/errors, and Web-standard runtime primitives shared by supported browsers and Node.js. The core is published once as `@owlauth/client`; the initial protocol API defines neither a separate browser package nor an `@owlauth/client/browser` entry point.
- Python uses typed exceptions and an explicitly chosen sync/async policy.
- Rust uses `Result`, non-exhaustive errors, and explicitly selected async runtime/HTTP boundaries.

The TypeScript implementation does not import Node-only runtime modules into its portable core or hide browser behavior behind environment detection. Browser compatibility is a tested runtime claim for the same API, not an implicit navigation/storage wrapper. A platform limitation is documented and tested rather than hidden behind weaker PKCE, retry, or redaction behavior.

## Acceptance criteria

- Public API review distinguishes stable handwritten symbols from generated/internal code.
- Client state cannot cross a configured Project/Application boundary.
- Public IDs and publishable keys are never presented as secrets or Client/Control credentials.
- Project client keys and Client OpenAPI operations are absent from every package API and artifact.
- Equivalent conformance cases produce equivalent semantic outcomes in all languages.
- Rust dependency checks prove no edge to `owlauth-server`.
- The published TypeScript core has one `@owlauth/client` artifact and passes its declared Node.js and browser runtime matrices before browser support is claimed.
- Documentation contains no examples of unavailable Project Auth operations until implemented and real-server tested.
