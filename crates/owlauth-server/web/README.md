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
```

`contracts:generate` exports complete OpenAPI documents from `owlauth-types` and updates only the
two committed generated type files. `check` runs boundary validation, ESLint, Prettier, TypeScript
project references, Vitest, and build-script tests. `build` rejects contract drift, rebuilds both
planes independently, then creates deterministic gzip/Brotli representations and server manifests.

Prepared `dist/` trees are tracked so an ordinary Cargo source build and a crates.io package build
remain deterministic and offline. `owlauth-server/build.rs` rejects missing, stale, extra,
symlinked, or digest-mismatched files before Rust compilation. The production binary embeds the two
roots separately and never serves this directory from the filesystem.

## Browser authority

The Runtime shell contains no Control client or operator credential path. The Console verifies the
deployment operator key through the ordinary Control API and keeps it only in active page memory. It
does not place the key in React state, browser storage, URLs, logs, or emitted assets, and disposes
the authenticated client on lock, verification failure, and unmount.

The current Runtime screen is intentionally limited to a truthful availability shell until login
interactions are implemented. The Console currently exposes only system verification and lock
behavior; it does not imply that the full management resource API exists.
