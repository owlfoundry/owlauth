# OwlAuth hosted web

This private workspace package owns the two browser surfaces embedded by `owlauth-server`:

- the Runtime Hosted Authentication UI;
- the Control Management Console.

The accepted stack and validation boundary are defined by
[`TS-002`](../../../spec/technology/ts-002-hosted-web-and-asset-pipeline.md). Browser authority,
route separation, credential handling, and external URL behavior remain owned by
[`spec/09`](../../../spec/09-hosted-web-surfaces-and-control-auth.md).

## Plane boundaries

Each application has an independent entry graph, TypeScript project, Vite configuration, output
root, manifest, generated client, and Rust embed root. Shared code is authority-free and cannot
import either plane.

| Path                               | Ownership                                                                 |
| ---------------------------------- | ------------------------------------------------------------------------- |
| `src/runtime/`                     | Runtime Hosted Authentication UI only                                     |
| `src/control/`                     | Control Management Console only                                           |
| `src/shared/`                      | Authority-free components and safe helpers                                |
| `src/generated/runtime-openapi.ts` | Committed type-only Runtime contract                                      |
| `src/generated/control-openapi.ts` | Committed type-only Control contract                                      |
| `scripts/`                         | Contract drift, boundary, manifest, and deterministic compression tooling |
| `dist/runtime/`                    | Tracked prepared Runtime assets and normalized server manifest            |
| `dist/control/`                    | Tracked prepared Control assets and normalized server manifest            |

Vite is configured to emit no shared cross-plane chunks. The source scanner rejects plane-crossing
imports, and asset preparation validates each emitted manifest closure, path, MIME type, plane
prefix, and forbidden worker/evaluated-code pattern.

## Commands

From the repository root:

```bash
pnpm --filter @owlauth/server-web contracts:generate
pnpm --filter @owlauth/server-web check
pnpm --filter @owlauth/server-web build
pnpm --filter @owlauth/server-web test:e2e
```

`contracts:generate` exports complete OpenAPI documents from `owlauth-types` and updates only the
two committed generated type files. `check` runs boundary validation, ESLint, Prettier, TypeScript
project references, Vitest, and build-script tests. `build` rejects contract drift, rebuilds both
planes independently, then creates deterministic gzip/Brotli representations and server manifests.
`test:e2e` starts an isolated PostgreSQL 17 container and the real Rust Auth and Control listeners,
then runs the fresh-database provisioning-readiness journey with Playwright and axe. The current
real-browser qualification baseline is Chromium and Firefox. WebKit and Safari are not declared
supported until an equivalent real Rust-server security gate exists. Install the selected Playwright
browsers first with `pnpm --filter @owlauth/server-web exec playwright install`.

Prepared `dist/` trees are tracked so an ordinary Cargo source build and a crates.io package build
remain deterministic and offline. `owlauth-server/build.rs` rejects missing, stale, extra,
symlinked, or digest-mismatched files before Rust compilation. The production binary embeds the two
roots separately and never serves this directory from the filesystem.

## Browser authority

The Runtime shell contains no Control client or operator credential path. The Console verifies the
deployment operator key through the ordinary Control API and keeps it only in active page memory. It
does not expose the key from the disposable client's closure or place it in React state, browser
storage, URLs, logs, or emitted assets, and disposes the authenticated client on lock, verification
failure, stale completion, and unmount.

The Runtime can render exact bounded Project/Application public readiness when explicitly addressed,
but remains a truthful no-login-interaction screen. The Console implements Project, Application,
signing-key, provider-secret, and assignment provisioning through the ordinary generated Control
client; it does not synthesize login, user, session, or token behavior.
