# TS-002 — Hosted web surfaces and asset pipeline

> Registered in [`spec/10`](../10-implementation-technology-selections.md); hosted-web behavior and browser authority remain owned by [`spec/09`](../09-hosted-web-surfaces-and-control-auth.md), while product information architecture and visual interaction design are owned by [`spec/12`](../12-product-ui-and-interaction-design.md).

- **Decision date:** 2026-07-29
- **Requirement owner:** spec 09
- **Implementation validation:** one narrow two-browser-surface build/package spike; remaining evidence comes from ordinary build, browser, integration, and release tests

### Selection

`crates/owlauth-server/web` is one private package in the repository pnpm workspace and owns both browser surfaces with these version baselines:

| Concern                 | Selection                                                                                                                         |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| UI language and library | strict TypeScript and React 19                                                                                                    |
| Routing                 | no general Runtime router initially; React Router 8 Declarative mode for the Console with explicit `basename`                     |
| Forms and state         | semantic native forms, application-owned hooks and bounded state machines; no default form, server-cache, or global-state library |
| Styling                 | external CSS Modules plus CSS custom properties                                                                                   |
| Build                   | Vite 8 with two explicit configs, entry graphs, output roots, and manifests                                                       |
| Browser client          | separate OpenAPI 3.1 documents; `openapi-typescript` 7 type generation plus `openapi-fetch` 0.17                                  |
| Binary embedding        | two `rust-embed` 8 derive types with embedding enabled in debug/test/release and an OwlAuth-owned Axum adapter                    |
| Asset compression       | `tower-http` response compression scoped to immutable asset routes; no OwlAuth-owned compression or negotiation implementation    |
| Tests                   | Vitest 4, React Testing Library 16, Playwright 1, and `@axe-core/playwright` 4                                                    |
| Static quality          | TypeScript strict options, ESLint flat config with typed typescript-eslint/React Hooks/jsx-a11y, and Prettier 3                   |

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

`owlauth-types` owns a deterministic export utility that produces complete, separate Runtime, Client, and Control OpenAPI 3.1 documents without compiling `owlauth-server`. This avoids a cycle in which compiling the server needs web assets while building the web assets needs server-generated OpenAPI. The documents remain derived build artifacts; exact Runtime/Client/Control JSON files are attached to each server release.

`openapi-typescript` consumes only the Runtime and Control documents for Hosted Web and emits two committed internal type-only files so review and clean source type-checks do not depend on an already built server. Client types are never generated into or imported by Hosted Web. A clean regeneration plus diff is the drift gate; the generated files never become contract authority. CI validates that each OpenAPI document and generated import graph contains only its plane.

Each application constructs its own `openapi-fetch` client from the immutable configured same-origin plane base. The Control client is created only after key verification. Its request middleware closes over the page-memory operator key, permits only URLs below the configured Control base, adds exactly the Bearer header, and supports explicit disposal on lock or authentication failure. It does not put the key in React props/state, a module singleton, DOM, storage, URL, telemetry, or errors. Runtime source has no Control contract import or operator-key client constructor.

Generated types do not make untrusted URLs or rendered values safe and do not perform runtime response validation. Application-owned adapters still validate navigation destinations, bounded discriminants, and dangerous sinks. Both clients call only the ordinary plane HTTP contracts and implement no alternate business policy.

Hosted Web MUST NOT import or bundle the independently versioned `@owlauth/client`. That SDK owns downstream Application Project Auth operations, not Control authority, Hosted method selection, browser navigation, or the complete server-version-matched Runtime ceremony surface. Reusing it here would create a release/version boundary in the server build without eliminating either internal plane client. Its correct integration role is external evidence: real-server browser and Node end-to-end tests install the packaged SDK candidate and exercise OwlAuth as an Application consumer would.

### Vite manifest and public-base contract

Each Vite build has exactly one custom JavaScript entry and writes to a plane-owned output root with its own `.vite/manifest.json`; this is not one multi-page build that may extract shared chunks. Vite-authored development HTML is not shipped. Rust follows the entry's transitive manifest `imports` and `css` closure and generates the production shell with only external module, preload, and stylesheet references.

Build output uses relocatable relative asset references. Rust prepends only the validated immutable configured plane base to normalized manifest paths. It does not infer an authority or prefix from `Host`, forwarding headers, browser location heuristics, or build-time deployment environment. It emits no `<base>` and no inline runtime-configuration script. A fixed safe meta field may communicate the non-secret configured base path to client code. In addition, an eligible no-store Runtime top-level document MAY attach the exact bounded server-authored Hosted bootstrap through allowlisted, attribute-escaped, non-executable meta fields; this contextual document is not part of the executable asset closure.

A repository-owned deterministic postbuild step consumes each Vite manifest and emits a versioned normalized server manifest. It MUST:

- prove exactly one plane entry and a closed set of relative canonical files below that plane's output root;
- reject absolute URLs, authority, traversal, encoded separators, backslashes, queries/fragments, missing or duplicate files, MIME disagreement, cross-plane names/imports, source maps, unlisted output, and runtime-remote code;
- reject inline handlers/styles, string-to-code APIs, worker/service-worker registration, and other output forbidden by spec 09; and
- record the canonical asset MIME, byte length, and digest needed for embedding and validation.

Content-hashed output names are the cache-version authority. Changed bytes MUST produce a different path; reproducible unchanged bytes MUST retain the same path. The `no-store` HTML shell is therefore refreshed on navigation/reload and references the current immutable asset closure, while previously cached hashed files may remain harmlessly until browser eviction. A fixed mutable `app.js` name, query-string cache busting, or service-worker update layer is not an alternative in V1.

Vite's ordinary production report records raw and gzip-estimated output sizes for review. V1 adds no bespoke bundle-budget or compression artifact pipeline; measured payload or startup regression is handled through the revisit trigger below. Dynamic imports remain absent by default and are admitted only when measured startup evidence justifies plane-local splitting. If admitted, every chunk remains manifest-reachable and relative-base behavior is revalidated in both external URL topologies. The module-preload polyfill is disabled only after the documented supported-browser baseline proves native support; otherwise it is an external bundled import, never inline code.

### Rust shell, embedding, and serving

Runtime and Control define separate `rust-embed` roots and enable embedded behavior in debug/test as well as release so tests cannot pass through an accidental runtime filesystem. The shipped server never reads web assets from disk.

An OwlAuth-owned Axum adapter, not `ServeDir`, `axum-embed`, or a generic SPA service, serves only exact normalized-manifest allowlisted paths selected by the owning router. It admits GET/HEAD and sets explicit MIME, `nosniff`, and cache class. Fingerprinted credential-free assets use `Cache-Control: public, max-age=31536000, immutable`; the HTML shell, bootstrap, errors, and APIs use `no-store`. A miss remains a plane-local 404 and cannot fall through to the other embed or a shell across excluded API, health, callback, hosted-interaction, or asset routes.

Eligible text assets receive Brotli/gzip response compression from `tower-http::compression::CompressionLayer`, enabled with only the required codecs and scoped to the asset router rather than authenticated APIs or Hosted HTML. The framework owns `Accept-Encoding` negotiation, `Content-Encoding`, `Vary`, and identity fallback. OwlAuth does not precompress files, store compressed representations in the manifest or binary, parse encoding quality values, or implement representation-specific ETags. Content-hashed immutable paths are the asset cache validator; V1 omits asset ETags rather than maintaining validators across framework-generated representations.

Each binary embeds exactly one asset generation. During an in-place mixed-version rollout, a shell returned by one generation can briefly request a hashed asset from another instance that does not contain it. V1 accepts that transient unavailability and a normal reload/retry after rollout; it does not retain multiple generations or add a CDN, service worker, mutable filename, or cross-version fallback. Deployments requiring uninterrupted mixed-version serving may use document/subresource affinity or drain-and-switch orchestration outside OwlAuth, and a future product guarantee would require a separate architecture decision.

Rust renders one fixed executable shell and asset closure from validated manifest and base-path values only. Those executable/static artifacts contain no interaction, branding, operator, error, redirect, or credential data. For an eligible Runtime top-level navigation, Rust MAY produce a contextual copy of that shell with an allowlisted, typed, bounded Hosted bootstrap in escaped non-executable meta attributes after the exact persisted interaction has been bound or read under specs 05 and 09. The response MUST remain `no-store`, use strict attribute escaping and the restrictive CSP, and the browser MUST runtime-validate and remove the context nodes immediately after reading them. Context fields MUST NOT contain arbitrary HTML, remote resources, vendor errors, provider secrets, operator credentials, or Application credentials; an exact bound CSRF value and bounded untrusted presentation text are permitted. Production output has no inline executable script, style, handler, executable JSON/script block, third-party URL, raw-HTML sink, or `<base>`. CSP uses same-origin external script/style/connect resources, denies default/object/base/frame/worker/manifest capabilities, constrains form action, and is accompanied by the cache, referrer, permissions, MIME, and opener policies in spec 09.

### Build, package, and release graph

The one valid server-web build order is:

```text
export Runtime, Client, and Control OpenAPI
-> regenerate/check only the Runtime and Control internal TS type files; reject Client imports
-> lint, type-check, and component-test
-> build the two Vite graphs
-> normalize and inspect both asset trees
-> browser/security tests
-> Cargo build/test/package
```

Every CI, server-release, crate-publication, and Docker path that compiles or packages `owlauth-server` invokes this graph or consumes the same checksummed platform-independent web-assets artifact. `build.rs` MAY validate asset presence/version/digest and emit rebuild tracking, but MUST NOT invoke pnpm, mutate source, download dependencies, or access the network.

The published `owlauth-server` crate includes both production asset roots and normalized manifests, so a crates.io consumer builds with Cargo only. A missing or stale prepared tree in a source checkout fails with an actionable error rather than an empty UI or filesystem fallback.

Docker uses cacheable Rust contract-export, Node/pnpm frozen web-build, and final Rust build stages. The runtime image contains only the server binary and required OS runtime files: no Node.js, pnpm store, source map, raw web source, writable asset tree, sidecar, CDN dependency, or network-loaded code. Linux, macOS, Windows, crate publication, and container builds verify the same web-assets digest before embedding it.

### Test and security baseline

Component tests use Vitest and Testing Library with accessible role/name queries and injected Fetch implementations. MSW is not selected initially. The current declared real-browser Playwright baseline starts the Rust server and trusted test proxy and covers Chromium and Firefox; WebKit and Safari support remains deferred until the same secure end-to-end gate is available for that engine family. Axe automation supplements, but does not replace, keyboard, focus, semantic, zoom, and human-informed accessibility review.

A UI source rewrite preserves behavior and security evidence, not obsolete markup. Pure configured-base/client/validator tests and Rust HTTP/asset tests remain at their owning boundaries. Component and browser tests retain exact protocol payloads, revision/CSRF/idempotency behavior, credential disposal, navigation safety, plane isolation, accessibility, and real-server outcomes, while selectors tied to old IDs, tag nesting, sibling order, or all-in-one screen navigation are replaced. Repeated workflows use small semantic screen/page drivers; visible controls continue to be located by accessible role/name, with test hooks reserved for machine values that have no meaningful visible locator. Exact prose is frozen only when the wording itself is a security, enumeration, honesty, or recovery contract.

Required static/browser integration coverage includes:

- clean OpenAPI regeneration, contract purity, import direction, and separate manifest closures;
- repeat clean builds with identical inputs producing identical content-hashed asset paths, bytes, and normalized manifests;
- distinct origins and shared-origin disjoint non-root bases, direct navigation, and every excluded fallback route;
- strict CSP enforcement, no remote/inline/evaluated code, no worker/service worker, and no `Service-Worker-Allowed`;
- exact redirect behavior, malicious text/URL/problem values, oversized data, contextual-meta attribute escaping, immediate bootstrap-node removal, and DOM/navigation sink protection;
- operator-key verification, same-base Bearer requests, lock/reload/authentication failure, disposal, and absence from browser storage/cache/history/DOM/log/error surfaces;
- Runtime cookie path containment, no cross-plane asset retrieval, and no operator key received by Runtime;
- one framework-compression integration path proving that an eligible asset is compressed when the client advertises a supported codec, identity fallback remains usable, `Vary: Accept-Encoding` is present, and GET/HEAD, immutable/no-store cache classes, MIME, missing/corrupt files, and route confusion remain correct;
- keyboard-only workflows, focus/error association, semantic names/roles, and automated accessibility findings;
- released binary/container operation with source assets removed and outbound network unavailable.

### Why this selection

React has the strongest proportional forms, accessibility, router, testing, and maintenance ecosystem among the evaluated candidates. Solid is technically viable but adds ecosystem and active major-transition risk without a required rendering benefit. Lit is optimized for reusable Web Components rather than these cohesive applications. Leptos adds Wasm/Trunk loader and browser-toolchain complexity, and its lead maintainer has announced light maintenance rather than the active expansion this security-sensitive UI would prefer. Different frameworks would not create browser-origin isolation.

`openapi-typescript` plus `openapi-fetch` provides the smallest generated/runtime boundary that supports OpenAPI 3.1, typed paths, custom same-origin bases, and a narrow credential middleware. Orval and Hey API generate broader SDK/query/mock/configuration surfaces than these same-version internal clients require. OpenAPI Generator adds a large templating/Java-oriented toolchain. Kiota requires abstractions, serializer, and request-adapter runtime packages disproportionate to same-version embedded clients.

`rust-embed` supplies active compile-time embedding and file metadata while allowing separate roots. `include_dir` is a viable fallback but a weaker metadata/maintenance fit. General Axum filesystem/embed services expose fallback and serving behavior broader than the manifest allowlist required here.

### Required validation evidence

Before broad UI implementation, one narrow end-to-end spike MUST prove the acyclic OpenAPI-to-two-build-to-two-embed chain, offline Cargo packaging, and correct asset loading under both configured external URL topologies. The remaining items are ordinary build, browser, integration, and release tests rather than separate PoCs. Together, validation MUST prove:

01. deterministic plane-pure OpenAPI 3.1 export from `owlauth-types` without compiling the server, byte-stable TS regeneration, drift failure, and rejected cross-plane imports;
02. two deterministic Vite content-hashed manifest closures with no shared emitted file and no inline/eval/remote/worker/service-worker/source-map output;
03. correct shell, asset, API, callback, and client-navigation behavior on distinct origins and on one origin with disjoint non-root bases, using only configured base values;
04. absent or correct manifest-reachable dynamic imports and module preloads in both topologies;
05. normalized-manifest rejection of traversal, encoding, URL, duplicate/missing file, MIME, unlisted-output, corruption, and cross-plane cases;
06. framework-owned asset compression and identity fallback, `Vary`, GET/HEAD, cache, and MIME behavior without precompressed artifacts or OwlAuth-owned negotiation logic;
07. debug/test/release embedding, asset-change rebuild tracking, plane-local 404/fallback behavior, and inability of either router to retrieve the other plane's bytes;
08. strict CSP and output checks plus malicious rendering, exact redirect, route partition, cookie containment, no-service-worker, keyboard, focus, and accessibility browser tests;
09. Console key verification and one authenticated call followed by lock/reload/authentication failure, proving the key is page-memory only, disposable, Control-base confined, and absent from Runtime and observable browser/server surfaces;
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
