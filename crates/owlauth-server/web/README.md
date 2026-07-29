# OwlAuth hosted web package boundary

This directory owns the source and build tooling for the two browser surfaces embedded by `owlauth-server`:

- the Runtime Hosted Authentication UI;
- the Control Management Console.

The accepted stack and validation boundary are defined by [`TS-002`](../../../spec/technology/ts-002-hosted-web-and-asset-pipeline.md). Browser authority, route separation, credential handling, and external URL behavior remain owned by [`spec/09`](../../../spec/09-hosted-web-surfaces-and-control-auth.md).

## Ownership boundaries

One private package in the repository pnpm workspace will author both applications, but each application has an independent entry graph, TypeScript project, Vite configuration, output root, manifest, generated plane client, and Rust embed root. Shared code is authority-free and cannot import either plane.

| Path | Ownership |
| --- | --- |
| `src/runtime/` | Runtime Hosted Authentication UI only |
| `src/control/` | Control Management Console only |
| `src/shared/` | authority-free components, design tokens, and safe helpers |
| `src/generated/runtime-openapi.ts` | committed type-only output derived from Runtime OpenAPI |
| `src/generated/control-openapi.ts` | committed type-only output derived from Control OpenAPI |
| `scripts/` | deterministic generation, manifest validation, and precompression tooling |
| `dist/runtime/` | ignored generated Runtime assets and normalized server manifest |
| `dist/control/` | ignored generated Control assets and normalized server manifest |

Generated `dist/` trees are build artifacts. Release preparation includes them in the published server crate and embeds them into the binary, but they are not ordinary source files. Production never serves this directory from the filesystem.

## Creation policy

The current server is still a health-only scaffold, so this directory intentionally contains no placeholder package, empty source modules, or speculative dependencies. The narrow TS-002 implementation spike creates `package.json`, configs, source directories, and the pnpm workspace entry together when they first form a buildable vertical slice. Until then, this README is the tracked ownership boundary.
