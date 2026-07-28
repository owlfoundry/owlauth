# 02 — Generated contract and models

## Contract input

SDK generation consumes one OpenAPI document emitted from the exact OwlAuth server source revision under validation:

```bash
cargo run --package owlauth-server -- --openapi > <temporary-build-path>/owlauth-openapi.json
```

The OpenAPI file is ephemeral and MUST NOT be committed. Its source revision, server version, generator version/configuration, and digest MUST be recorded in CI or release provenance. The current document describes only health metadata and a small OAuth error enum; it is not a usable OAuth client contract.

## Generation boundary

Generation MAY produce:

- wire request/response models;
- serialization/deserialization code;
- endpoint path/method declarations;
- low-level operation clients.

Generation MUST NOT invent lifecycle policy for browser opening, PKCE verifier custody, token persistence, refresh rotation/replay, retry safety, or language-level error taxonomy. Those layers remain handwritten and tested.

Generated output location and commit policy are chosen per SDK package. Regardless of whether language source is shipped, regeneration MUST be deterministic and reviewed. This repository still does not commit the generated OpenAPI input.

## Model conventions

All SDKs MUST preserve wire distinctions relevant to compatibility:

- absent versus explicit `null`;
- required versus optional fields;
- unknown enum values according to a documented forward-compatibility policy;
- integer/string/time formats without lossy conversion;
- OAuth error code plus safe optional metadata;
- unknown response fields where tolerant reading is intended.

Wire models MUST not expose secret-bearing default `repr`, `Debug`, inspection, equality snapshots, or serialization accidentally. Secret wrappers SHOULD redact by default and require an explicit operation to access raw material.

Names may be idiomatic but mappings remain deterministic. Reserved-word escaping and acronym casing rules are pinned in generator configuration. Generated code MUST not overwrite handwritten files.

## Drift and compatibility

CI regenerates from the single ephemeral contract and either compares generated source to the package baseline or builds/tests directly from the output. Unexplained drift fails. An OpenAPI-aware diff flags removal, required-input additions, type narrowing, authentication changes, response/error changes, and enum compatibility hazards before SDK updates proceed.

The server contract may evolve independently of an SDK. Each SDK records supported server contract/version ranges and tests tolerant behavior. A new OpenAPI operation is not part of the SDK's stable public API until its generated layer, handwritten semantics where needed, tests, and docs are released.

## Acceptance criteria

- Generation is reproducible with pinned tools/configuration.
- A clean generation job does not modify the checked-out OpenAPI tree or leave an OpenAPI file to commit.
- Model round-trip tests cover omission/null, unknown fields/enums, bounds, and redaction.
- Handwritten code imports generated layers through a narrow adapter so generator replacement is possible.
- Release provenance identifies the exact contract digest used.
