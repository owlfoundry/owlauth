# TS-002 — Hosted web surfaces and asset pipeline

> Registered in [`spec/10`](../10-implementation-technology-selections.md); hosted-web behavior and browser authority remains owned by [`spec/09`](../09-hosted-web-surfaces-and-control-auth.md).

- **Decision date:** 2026-07-29
- **Requirement owner:** spec 09
- **Implementation validation:** one narrow two-plane build/package spike; remaining evidence comes from ordinary build, browser, integration, and release tests

### Selection

`crates/owlauth-server/web` is one private package in the repository pnpm workspace and owns both browser surfaces with these version baselines:

| Concern | Selection |
| --- | --- |
| UI language and library | strict TypeScript and React 19 |
| Routing | no general Runtime router initially; React Router 8 Declarative mode for the Console with explicit `basename` |
| Forms and state | semantic native forms, application-owned hooks and bounded state machines; no default form, server-cache, or global-state library |
| Styling | external CSS Modules plus CSS custom properties |
| Build | Vite 8 with two explicit configs, entry graphs, output roots, and manifests |
| Browser client | separate OpenAPI 3.1 documents; `openapi-typescript` 7 type generation plus `openapi-fetch` 0.17 |
| Binary embedding | two `rust-embed` 8 derive types with embedding enabled in debug/test/release and an OwlAuth-owned Axum adapter |
| Tests | Vitest 4, React Testing Library 16, Playwright 1, and `@axe-core/playwright` 4 |
| Static quality | TypeScript strict options, ESLint flat config with typed typescript-eslint/React Hooks/jsx-a11y, and Prettier 3 |

Exact compatible patch versions are controlled by `pnpm-lock.yaml` and `Cargo.lock`. A selected major upgrade remains subject to the output, CSP, contract, package, and browser gates below. The current root-wide Vite 6 override must be removed, narrowed to the documentation dependency that needs it, or otherwise reconciled during implementation; it cannot silently downgrade this workspace.

This is one authoring toolchain but two deployable applications. Runtime and Control MAY share authority-free source components and design tokens. They MUST NOT share an emitted chunk, output root, Vite manifest, normalized server manifest, generated plane client, client singleton, route table, bootstrap, or Rust embed type. TypeScript project references, restricted-import lint rules, independent Vite builds, postbuild inspection, and Rust router ownership enforce the direction:

```text
runtime -> shared + Runtime generated contract
control -> shared + Control generated contract
shared  -> neither plane
```

React is used only as a browser UI library. OwlAuth does not select React Server Components, React/Router framework mode, SSR, Server Actions as a server protocol, or a Node.js production runtime. The Runtime Hosted UI starts without a general router. The Console uses only React Router Declarative mode below its configured `console/` base.

CSS-in-JS, inline style attributes, Tailwind as the base system, raw HTML sinks, runtime template compilation, remote imports, third-party executable/style/font assets, workers, service workers, and runtime plugins are outside the selected profile. React Hook Form, TanStack Query, Redux, MSW, or another form/cache/global-state/mock dependency requires evidence from implemented workflow complexity and an explicit dependency review; none is selected speculatively.

### Plane-specific contracts and clients

`owlauth-types` owns a deterministic export utility that produces complete, separate Runtime and Control OpenAPI 3.1 documents without compiling `owlauth-server`. This avoids a cycle in which compiling the server needs web assets while building the web assets needs server-generated OpenAPI. The documents remain derived ephemeral artifacts as required by the repository contract policy.

`openapi-typescript` consumes each document independently and emits two committed internal type-only files so review and clean source type-checks do not depend on an already built server. A clean regeneration plus diff is the drift gate; the generated files never become contract authority. CI validates that each OpenAPI document and generated import graph contains only its plane.

Each application constructs its own `openapi-fetch` client from the immutable configured same-origin plane base. The Control client is created only after key verification. Its request middleware closes over the page-memory operator key, permits only URLs below the configured Control base, adds exactly the Bearer header, and supports explicit disposal on lock or authentication failure. It does not put the key in React props/state, a module singleton, DOM, storage, URL, telemetry, or errors. Runtime source has no Control contract import or operator-key client constructor.

Generated types do not make untrusted URLs or rendered values safe and do not perform runtime response validation. Application-owned adapters still validate navigation destinations, bounded discriminants, and dangerous sinks. Both clients call only the ordinary plane HTTP contracts and implement no alternate business policy.

### Vite manifest and public-base contract

Each Vite build has exactly one custom JavaScript entry and writes to a plane-owned output root with its own `.vite/manifest.json`; this is not one multi-page build that may extract shared chunks. Vite-authored development HTML is not shipped. Rust follows the entry's transitive manifest `imports` and `css` closure and generates the production shell with only external module, preload, and stylesheet references.

Build output uses relocatable relative asset references. Rust prepends only the validated immutable configured plane base to normalized manifest paths. It does not infer an authority or prefix from `Host`, forwarding headers, browser location heuristics, or build-time deployment environment. It emits no `<base>` and no inline runtime-configuration script. A fixed safe meta field or same-origin bootstrap response may communicate the non-secret configured base path to client code.

A repository-owned deterministic postbuild step consumes each Vite manifest and emits a versioned normalized server manifest. It MUST:

- prove exactly one plane entry and a closed set of relative canonical files below that plane's output root;
- reject absolute URLs, authority, traversal, encoded separators, backslashes, queries/fragments, missing or duplicate files, MIME disagreement, cross-plane names/imports, source maps, unlisted output, and runtime-remote code;
- reject inline handlers/styles, string-to-code APIs, worker/service-worker registration, and other output forbidden by spec 09;
- record MIME, byte length, digest, and representation metadata;
- deterministically create and verify Brotli and gzip variants for eligible fingerprinted text assets by a repository-owned script rather than another Vite plugin.

Dynamic imports are absent by default. If admitted later, every chunk remains manifest-reachable and relative-base behavior is revalidated in both external URL topologies. The module-preload polyfill is disabled only after the documented supported-browser baseline proves native support; otherwise it is an external bundled import, never inline code.

### Rust shell, embedding, and serving

Runtime and Control define separate `rust-embed` roots and enable embedded behavior in debug/test as well as release so tests cannot pass through an accidental runtime filesystem. The shipped server never reads web assets from disk.

An OwlAuth-owned Axum adapter, not `ServeDir`, `axum-embed`, or a generic SPA service, serves only exact normalized-manifest allowlisted paths selected by the owning router. It admits GET/HEAD, sets explicit MIME and `nosniff`, performs bounded `Accept-Encoding` selection, and returns representation-correct ETags and `Vary: Accept-Encoding`. Fingerprinted credential-free assets use `Cache-Control: public, max-age=31536000, immutable`; the HTML shell, bootstrap, errors, and APIs use `no-store`. A miss remains a plane-local 404 and cannot fall through to the other embed or a shell across excluded API, health, callback, hosted-interaction, or asset routes.

Rust renders a fixed HTML shell from validated manifest and base-path values only. It contains no interaction, branding, operator, error, redirect, or credential data; those values arrive through bounded APIs and are rendered as untrusted text. Production shell output has no inline script, style, handler, JSON blob, third-party URL, or `<base>`. CSP uses same-origin external script/style/connect resources, denies default/object/base/frame/worker/manifest capabilities, constrains form action, and is accompanied by the cache, referrer, permissions, MIME, and opener policies in spec 09.

### Build, package, and release graph

The one valid server-web build order is:

```text
export Runtime and Control OpenAPI
-> regenerate/check the two internal TS type files
-> lint, type-check, and component-test
-> build the two Vite graphs
-> normalize, inspect, and precompress both asset trees
-> browser/security tests
-> Cargo build/test/package
```

Every CI, server-release, crate-publication, and Docker path that compiles or packages `owlauth-server` invokes this graph or consumes the same checksummed platform-independent web-assets artifact. `build.rs` MAY validate asset presence/version/digest and emit rebuild tracking, but MUST NOT invoke pnpm, mutate source, download dependencies, or access the network.

The published `owlauth-server` crate includes both production asset roots and normalized manifests, so a crates.io consumer builds with Cargo only. A missing or stale prepared tree in a source checkout fails with an actionable error rather than an empty UI or filesystem fallback.

Docker uses cacheable Rust contract-export, Node/pnpm frozen web-build, and final Rust build stages. The runtime image contains only the server binary and required OS runtime files: no Node.js, pnpm store, source map, raw web source, writable asset tree, sidecar, CDN dependency, or network-loaded code. Linux, macOS, Windows, crate publication, and container builds verify the same web-assets digest before embedding it.

### Test and security baseline

Component tests use Vitest and Testing Library with accessible role/name queries and injected Fetch implementations. MSW is not selected initially. Real-browser Playwright tests start the Rust server and trusted test proxy and cover Chromium, Firefox, and WebKit; axe automation supplements, but does not replace, keyboard, focus, semantic, zoom, and human-informed accessibility review.

Required static/browser integration coverage includes:

- clean OpenAPI regeneration, contract purity, import direction, and separate manifest closures;
- distinct origins and shared-origin disjoint non-root bases, direct navigation, and every excluded fallback route;
- strict CSP enforcement, no remote/inline/evaluated code, no worker/service worker, and no `Service-Worker-Allowed`;
- exact redirect behavior, malicious text/URL/problem values, oversized data, and DOM/navigation sink protection;
- operator-key verification, same-base Bearer requests, lock/reload/authentication failure, disposal, and absence from browser storage/cache/history/DOM/log/error surfaces;
- Runtime cookie path containment, no cross-plane asset retrieval, and no operator key received by Runtime;
- Brotli/gzip/identity negotiation, ETags, `Vary`, HEAD, immutable/no-store cache classes, MIME, missing/corrupt files, and route confusion;
- keyboard-only workflows, focus/error association, semantic names/roles, and automated accessibility findings;
- released binary/container operation with source assets removed and outbound network unavailable.

### Why this selection

React has the strongest proportional forms, accessibility, router, testing, and maintenance ecosystem among the evaluated candidates. Solid is technically viable but adds ecosystem and active major-transition risk without a required rendering benefit. Lit is optimized for reusable Web Components rather than these cohesive applications. Leptos adds Wasm/Trunk loader and browser-toolchain complexity, and its lead maintainer has announced light maintenance rather than the active expansion this security-sensitive UI would prefer. Different frameworks would not create browser-origin isolation.

`openapi-typescript` plus `openapi-fetch` provides the smallest generated/runtime boundary that supports OpenAPI 3.1, typed paths, custom same-origin bases, and a narrow credential middleware. Orval and Hey API generate broader SDK/query/mock/configuration surfaces than these same-version internal clients require. OpenAPI Generator adds a large templating/Java-oriented toolchain. Kiota requires abstractions, serializer, and request-adapter runtime packages disproportionate to same-version embedded clients.

`rust-embed` supplies active compile-time embedding and file metadata while allowing separate roots. `include_dir` is a viable fallback but a weaker metadata/maintenance fit. General Axum filesystem/embed services expose fallback and serving behavior broader than the manifest allowlist required here.

### Required validation evidence

Before broad UI implementation, one narrow end-to-end spike MUST prove the acyclic OpenAPI-to-two-build-to-two-embed chain, offline Cargo packaging, and correct asset loading under both configured external URL topologies. The remaining items are ordinary build, browser, integration, and release tests rather than separate PoCs. Together, validation MUST prove:

1. deterministic plane-pure OpenAPI 3.1 export from `owlauth-types` without compiling the server, byte-stable TS regeneration, drift failure, and rejected cross-plane imports;
2. two Vite manifest closures with no shared emitted file and no inline/eval/remote/worker/service-worker/source-map output;
3. correct shell, asset, API, callback, and client-navigation behavior on distinct origins and on one origin with disjoint non-root bases, using only configured base values;
4. absent or correct manifest-reachable dynamic imports and module preloads in both topologies;
5. normalized-manifest rejection of traversal, encoding, URL, duplicate/missing file, MIME, unlisted-output, corruption, and cross-plane cases;
6. byte-reproducible Brotli/gzip output and correct bounded negotiation, ETags, `Vary`, HEAD, cache, and MIME behavior;
7. debug/test/release embedding, asset-change rebuild tracking, plane-local 404/fallback behavior, and inability of either router to retrieve the other plane's bytes;
8. strict CSP and output checks plus malicious rendering, exact redirect, route partition, cookie containment, no-service-worker, keyboard, focus, and accessibility browser tests;
9. Console key verification and one authenticated call followed by lock/reload/authentication failure, proving the key is page-memory only, disposable, Control-base confined, and absent from Runtime and observable browser/server surfaces;
10. Cargo packaging of both generated trees, offline build of the unpacked crate without Node, final binary/container serving with source asset directories removed, and the same asset digest across Linux/macOS/Windows/container consumers.

Failure pauses broad implementation. First adjust the adapter or build design. Revisit React, the OpenAPI client pair, or `rust-embed` only when evidence shows an intrinsic limitation rather than an OwlAuth integration defect.

### Revisit triggers

Revisit `TS-002` when evidence shows one of:

- a selected major cannot preserve external-only strict-CSP output or supported-browser behavior;
- independent graphs/manifests cannot prevent cross-plane emitted dependencies;
- the OpenAPI pair cannot express a required operation/error or maintain deterministic plane purity;
- `rust-embed` cannot preserve rebuild, offline crate, or reproducible release requirements;
- measured Runtime payload/startup or Console workflow complexity cannot be corrected within the selected boundaries;
- accessibility requirements cannot be met by the selected primitives/tooling;
- deployment introduces an independently versioned UI runtime, CDN, or frontend server, which is an architecture change rather than a routine dependency replacement.
