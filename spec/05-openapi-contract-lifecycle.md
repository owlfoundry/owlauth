# 05 — Generated OpenAPI contract lifecycle

## Authority and current baseline

Reviewed Rust definitions in `crates/protocol` are the source for the public HTTP contract. `utoipa` currently generates a document containing only `/health`, `HealthResponse`, and a small OAuth error-code schema. `crates/server` can emit it with:

```bash
cargo run --package owlauth -- --openapi
```

This does not mean an HTTP listener or OAuth endpoints exist. The generated document MUST NOT be committed to this repository; generate it into a temporary/build location when validation or SDK tooling needs it.

## Lifecycle

1. **Design:** update the owning server and SDK specifications, including security and compatibility impact.
2. **Implement:** change protocol DTOs/routes and domain mapping together. Every documented operation must map to a composed server route before it is advertised as implemented.
3. **Generate:** emit OpenAPI deterministically from the exact source revision under test.
4. **Validate:** lint the document, reject unresolved or secret-bearing examples, and compare it with the release baseline using an OpenAPI-aware compatibility checker.
5. **Test:** drive server contract tests and SDK generation/conformance using that ephemeral artifact.
6. **Publish:** package or attach the contract only where a release process explicitly requires it, preserving source revision and server version provenance. Publication does not make a repository copy authoritative.

## Contract requirements

Every public operation MUST define stable operation identity, authentication, request content type, parameter constraints, response schema, relevant status codes, and OAuth-standard error behavior. Schemas distinguish omitted from null and document formats and bounds. Examples use unmistakably synthetic values and no valid credentials.

Generated OpenAPI describes wire shape, not all semantic and security behavior. OAuth invariants in spec 03 and SDK handwritten behavior in `sdks/spec` remain normative where OpenAPI cannot express them. Health, readiness, admin, and MCP surfaces MUST NOT accidentally enter a public SDK contract merely because they share a router.

## Compatibility policy

A contract diff is reviewed semantically, not merely textually. Removing/renaming operations or fields, adding required input, narrowing accepted values, changing authentication, changing error meaning, or making a previously optional response field required is normally breaking. Additive endpoints or optional response fields still require SDK review because generated languages may model enums or unknown fields differently.

Pre-1.0 status permits faster iteration under SemVer but does not permit silent incompatibility. Every intentional break is called out and coordinated with affected SDK release lines. Server and SDK versions remain independent; compatibility is recorded as tested ranges rather than synchronized numbers.

## Determinism and provenance

Generation MUST be reproducible for the same source and toolchain. Output ordering or timestamps SHOULD NOT cause meaningless diffs. CI records the source commit, server package version, generator/tool versions, and document digest. A digest mismatch after regeneration fails validation until explained.

## Acceptance criteria

- CI generates into a temporary path and leaves the working tree clean.
- The document passes syntax, lint, and security checks.
- Contract tests prove every advertised route is composed and every composed public route is represented.
- Compatibility review blocks unexplained breaking changes.
- SDK jobs consume one identified artifact rather than independently drifting documents.
