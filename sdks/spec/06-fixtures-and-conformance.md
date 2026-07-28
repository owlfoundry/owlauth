# 06 — Fixtures, conformance, and end-to-end validation

## Machine-readable attachments

[`fixtures/`](fixtures/) stores shared wire examples; [`conformance/`](conformance/) stores language-neutral behavior cases. They are reviewed attachments to these specifications and use relative paths plus an explicit `schemaVersion`.

The current attachments are intentionally minimal:

- [`fixtures/health-response.json`](fixtures/health-response.json) contains `{ "status": "ok" }`;
- [`conformance/cases.json`](conformance/cases.json) asserts that health fixture only.

This corpus does not validate a transport or OAuth behavior. It MUST NOT be described as an OAuth conformance suite.

## Fixture rules

Fixtures MUST be valid JSON (or another explicitly adopted machine format), deterministic, minimal, and synthetic. They MUST NOT contain usable secrets, real domains/accounts, live tokens, production identifiers, or generated OpenAPI copies. Secret-like tests use obvious non-production sentinels and assert that those sentinels never appear in rendered output.

Each case has a unique stable name, input or fixture reference, expected semantic output/error, and optional capability/version requirement. Corpus schema changes increment `schemaVersion` and keep runners able to explain unsupported versions rather than silently skipping them.

## Conformance runner responsibilities

Every official SDK loads the same corpus and translates only the language binding. A runner MUST:

- fail on unknown required fields, missing fixtures, duplicate case names, or unsupported schema versions;
- report skipped optional capabilities explicitly;
- compare semantic output rather than incidental formatting;
- exercise generated models plus handwritten transport/lifecycle/error layers as applicable;
- keep language-specific unit tests for idioms not representable in shared data.

A case passing in one language is not cross-language conformance. Required cases pass in all SDKs that claim the capability.

## Validation stages

### Current checks

While SDKs are base-URL-only package scaffolds, CI can run package builds, static checks, unit tests, OpenAPI generation checks, and the small health fixture/case validation if a runner exists. Mock transport tests, once added, are unit/contract tests.

### Future real-server E2E

After OwlAuth implements HTTP OAuth behavior, CI MUST start a real OwlAuth server with isolated configuration, keys, database, port, and deterministic test clients/users. It MUST then run TypeScript, Python, and Rust SDKs against that process for every claimed cross-language flow, including negative and refresh/concurrency cases where supported. Server logs are scanned for seeded secrets and the database/environment are discarded after the job.

Do **not** add fake or placeholder E2E tests now. A mocked response, static fixture, generated client compile, or health-model round trip is not server-backed E2E and must not be labeled as such.

## Acceptance criteria

- Attachment references resolve and schema versions are validated.
- All required cases execute in every claiming SDK with equivalent outcomes.
- CI labels package/unit/contract/conformance/E2E stages accurately.
- OAuth release claims wait for a real-server cross-language E2E job, not a mock.
