# TS-003 — Key-provider SPI and PostgreSQL software custody

> Registered in [`spec/10`](../10-implementation-technology-selections.md); custody, storage, lifecycle, and failure behavior remain owned by [`spec/02`](../02-domain-and-crate-boundaries.md), [`spec/04`](../04-storage-and-migrations.md), [`spec/06`](../06-operations-configuration-and-security.md), and [`spec/08`](../08-consistency-resilience-and-plane-separation.md).

- **Decision date:** 2026-08-04
- **Requirement owners:** specs 02, 04, 06, and 08
- **Implementation validation:** public-API compile fixtures plus software-provider, PostgreSQL, composition, recovery, and split-plane integration tests

### Selection

OwlAuth uses a small published Rust SPI crate, `crates/owlauth-key-provider`, and ordinary static linking for replaceable signing-key and configuration-secret custody. `owlauth-server` depends on that crate and exposes a public high-level composition builder that accepts role-specific provider capabilities. The official binary composes only the bundled local software-custody provider; it is not a KMS implementation. The OwlAuth repository and official distribution include no AWS KMS, Google Cloud KMS, Azure Key Vault, Vault/OpenBao Transit, PKCS#11, or other remote/HSM provider implementation. A community crate or deployment that needs one implements the SPI in a separate crate and builds a custom server binary.

V1 does not load native plugins at runtime. It does not scan a plugin directory, load Rust `dylib`/`cdylib` libraries, supervise provider subprocesses, or define a sidecar protocol. A custom provider is trusted code in the OwlAuth process and is not sandboxed by the SPI.

The provider crate follows the server release version, is published before `owlauth-server`, and remains independent of server/domain, PostgreSQL, HTTP, configuration, and vendor SDK types. It owns only bounded provider-neutral values, classified redacted errors, and object-safe async capability traits. It MUST NOT expose one vendor-shaped or omnipotent `Kms` trait.

The capability split is:

| Capability                  | Plane/role     | Contract                                                                                                                                                                                                       |
| --------------------------- | -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| signing-key provisioner     | Control        | declare `StableOperation` or `StatelessHandle` semantics; provision one exact algorithm and return a bounded opaque handle plus normalized public key; inspect or destroy according to that declared lifecycle |
| Runtime signer              | Runtime        | sign one complete JWS signing input with an exact algorithm and opaque handle; never create, enumerate, export, or destroy keys                                                                                |
| configuration-secret sealer | Control        | seal bounded plaintext under exact server-derived context and return a bounded opaque envelope plus a safe request fingerprint; never read existing material                                                   |
| configuration-secret opener | Runtime/worker | open only the supplied envelope under the same exact context; never enumerate, provision, or mutate material                                                                                                   |

The traits are `Send + Sync` and dyn-compatible. Their async methods use the crate's single selected object-safe future convention (for example `async_trait` expansion or an explicit boxed-future alias); public signatures do not use non-object-safe generic methods or provider-defined associated types. Server composition holds role objects behind `Arc<dyn …>` or an equivalent opaque wrapper rather than requiring one concrete provider type across the server.

The SPI owns confidential bounded byte wrappers that zeroize on drop where supported, redact `Debug`/`Display`, are not `Clone` or serializable by default, and require an explicit consuming/access closure for provider use. Handles, envelopes, fingerprints, signatures, operation IDs, provider IDs, and public keys are distinct newtypes with independent maximum sizes; they are never interchangeable `Vec<u8>`, `String`, `serde_json::Value`, or arbitrary maps. Provider errors contain only a closed class, safe retry classification, and optional bounded provider-neutral metadata—never an arbitrary vendor message, cause chain, handle, envelope, context, or plaintext.

The SPI defines one deterministic versioned canonical encoding for protection/signing context and publishes cross-implementation fixtures. The server constructs that typed context from authoritative IDs/generations; adapters receive and authenticate the exact canonical bytes rather than rebuilding AAD from vendor or server structs. A composition registration assigns one immutable bounded provider ID to each capability set. Duplicate IDs are invalid; stored `provider_id + format_version + material_kind` dispatches to exactly one compatible role, and absence/mismatch never tries another registration or the bundled provider.

The server retains Project qualification, owning-resource/generation context construction, key-ring lifecycle, public-key/JWK validation, publish-before-sign evidence, algorithm policy, idempotency, PostgreSQL transactions, audit, readiness, retries, and signature verification. Provider adapters normalize raw-message versus digest signing, provider public-key formats, and signature encodings such as ECDSA DER into the exact JWS-ready result required by OwlAuth. Runtime verifies every returned signature against the committed normalized public key before issuing the credential; failure is an integrity error and cannot trigger another provider/key attempt.

Algorithms are explicit provider capabilities. Ed25519/EdDSA is the bundled v1 default. An adapter MUST reject an unsupported algorithm and MUST NOT downgrade or substitute it. Supporting a provider without Ed25519, including Azure Key Vault's currently documented generally available EC set, requires an explicit OwlAuth algorithm-agility change such as ES256 and does not alter an existing key ring implicitly.

### Bundled software provider

The bundled provider requires one deployment-supplied 32-byte software custody master key. The key is delivered through the deployment's secret-injection mechanism and never enters PostgreSQL, Redis, DTOs, logs, telemetry, panic output, CLI output, or public configuration.

HKDF-SHA-256 with a fixed versioned OwlAuth extract salt and distinct length-delimited `info` labels derives non-overlapping 32-byte subkeys for at least:

- signing-material XChaCha20-Poly1305 envelopes;
- provider/SMTP/webhook configuration-secret XChaCha20-Poly1305 envelopes;
- HMAC-SHA-256 stable request fingerprints.

Purpose derivation limits accidental cross-use; it does not claim independent compromise domains after the root is disclosed. Every XChaCha20-Poly1305 envelope uses a fresh CSPRNG 24-byte nonce and authenticates a canonical length-delimited bounded context containing the deployment instance, scope and Project where applicable, material ID, resource kind, owning resource ID, generation, field purpose, provider-format identifier, and context version. The HMAC fingerprint covers an independently labeled canonical encoding of the exact same context plus plaintext; raw concatenation without length framing is forbidden.

The software signing provisioner generates the exact allowed Ed25519 seed locally, encrypts it with randomized AEAD, and returns a bounded opaque software envelope plus normalized public key. The server commits that envelope in PostgreSQL with the signing-key row and verifies the public key before publication. The Runtime signer decrypts only the selected envelope under its exact context and zeroizes transient plaintext key material.

The server first durably reserves one stable material ID and owner/generation under the Control idempotency operation after comparing its normalized non-secret request digest. The software secret sealer encrypts provider, SMTP, and webhook secret bytes under that exact context with randomized AEAD and returns the envelope plus a separately derived safe request fingerprint. PostgreSQL then commits the envelope record, owning configuration/generation, completed operation/idempotency result, and audit atomically. Runtime and workers open only the exact selected generation. Ciphertext is not used as an identity, uniqueness key, reservation key, or fingerprint.

V1 has one static software custody root and no online root rotation or active/retained root set for this boundary. Operators MUST NOT replace the root in place. Every replica requiring one of these capabilities receives the same root. Backup recovery requires the matching root; a database backup alone is intentionally insufficient to recover protected material. Online rewrap and root rotation require a later explicit schema, rollout, inventory, and failure-semantics design.

### Durable representation

PostgreSQL owns a stable protected-material record for each signing handle or configuration-secret envelope. The record has a server-generated immutable ID; scope/Project; typed owner kind, UUID, and generation; material kind; provider identifier and format version; bounded context digest and opaque envelope/handle bytes; bounded safe fingerprint where applicable; lifecycle state; and timestamps. The owner tuple is unique, and owner rows prove the exact tuple through a composite FK or commit-final deferred constraint. Operation/snapshot/cleanup rows reference the stable material ID rather than copying randomized ciphertext.

For bundled configuration-secret writes, a small prepare transaction compares the normalized non-secret request digest and creates/locks the pending idempotency operation plus stable material/owner IDs without plaintext or envelope. Sealing occurs outside a transaction; a final conditional fingerprint comparison plus record creation and owner-generation activation then finalize atomically. Retried sealing reuses the same context and fingerprint while randomized envelope bytes may differ. Disablement, retirement, compromise, or cleanup uses guarded lifecycle mutation and live-authority crypto-erasure of the envelope while retaining the necessary tombstone. Historical PostgreSQL backups/WAL may still contain ciphertext and remain recoverable with the root; backup retention and root handling are outside any claim of physical erasure. There is no external file write, shared-volume requirement, external-store reservation, matched filesystem backup, or post-commit file cleanup. The stable row identity and lifecycle fence prevent stale writers from resurrecting erased material.

Signing provisioners declare one of two closed lifecycle semantics. `StableOperation`, the safe default for existing and remote providers, creates or addresses an external object under the durable operation ID: retries and inspection return the byte-identical handle and public key, and abandoned objects follow explicit safe destruction. `StatelessHandle` creates no provider-side object or durable effect: each retry may return a fresh random self-contained handle, inspection returns `NotFound + ExactInputSafe`, and PostgreSQL is the sole live authority. A lost pre-commit stateless handle is therefore not an orphan; cleanup erases the committed opaque bytes and retains only the fenced tombstone without requiring provider destruction. The bundled randomized software signing provider uses `StatelessHandle`. Provider/SMTP/webhook sealing likewise returns a self-contained opaque envelope and is not modeled as creation of an externally named generic secret object.

### Public composition

`owlauth-server` exposes a narrow builder or equivalent `run_with_providers` entry point. It accepts capability registrations and server configuration without making private repositories, Axum routers, application errors, or database rows public. The existing `run` entry point remains the official composition and delegates to the same path with the bundled software provider. Core configuration has no vendor-shaped `kms` map, dynamic type name, or arbitrary provider payload: a custom binary parses its own bounded vendor configuration, constructs the independent provider objects, assigns reviewed provider IDs, and hands only capabilities to the server builder.

Custom binaries must explicitly provide every capability required by their selected `all`, `runtime`, or `control` mode. Missing, duplicated, provider-ID-mismatched, or algorithm-incompatible capabilities fail during composition/readiness rather than falling back to the bundled provider or another key generation.

### SemVer and compatibility rules

Because downstream crates implement these traits, adding a required trait method, changing a signature, weakening object safety, or changing a value's meaning is breaking. New optional behavior should use a new capability trait, a new explicitly versioned value, or a defaulted method only when old implementations retain safe semantics. Opaque handle/envelope and error sizes are bounded, provider identifiers and format versions are explicit, and unknown versions fail closed.

A provider implementation may follow its own release cadence, but compatibility is with an exact supported `owlauth-key-provider` API range. OwlAuth does not certify arbitrary custom implementations or custom binaries.

### Why this selection

PostgreSQL ciphertext removes the operational need for writable local secret directories, shared filesystems, and coordinated database/filesystem snapshots while retaining a separate recovery factor outside the database. A narrow SPI keeps KMS/HSM support possible without imposing a KMS service on default self-hosted deployments.

Static Rust composition preserves ordinary type checking and avoids pretending that Rust's native library formats are a stable third-party plugin ABI. A role-specific capability split also preserves least authority: Control can provision without opening secrets, while Runtime can sign/open without creating, enumerating, exporting, or destroying unrelated material.

### Alternatives considered

| Alternative                                   | Decision                                                                                                                                                                        |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| encrypted signer and secret files             | Superseded for v1 default custody: creates HA/shared-volume and matched-backup complexity without a meaningful trust-boundary gain when the same process holds the wrapping key |
| require a managed KMS                         | Rejected as the default because v1 self-hosting must not require an external key service; remains implementable through the SPI                                                 |
| one generic `Kms` trait                       | Rejected because vendor primitives, algorithm/input/signature formats, and secret-encryption models differ, and one trait would overgrant every caller                          |
| Rust `dylib`/`cdylib` runtime plugins         | Rejected for v1 because ordinary Rust traits do not define a stable FFI ABI, allocator, layout, panic, or version-negotiation contract                                          |
| subprocess or sidecar plugin protocol         | Deferred because it introduces another distributed protocol, authentication, supervision, deployment, and recovery boundary not required by v1                                  |
| internal-only provider module                 | Rejected because it does not let contributors or deployments implement providers without forking private server internals                                                       |
| copy ciphertext into every owner/snapshot row | Rejected because randomized ciphertext is not stable identity and copies make context binding, cleanup, and future rewrap unsafe                                                |

### Required validation evidence

Before declaring this decision implemented, tests MUST prove:

01. the SPI crate has no server, database, HTTP, configuration, or vendor SDK dependency and all capability traits are object-safe;
02. compile fixtures can implement a third-party provider and compose a custom server without importing private server modules;
03. `all`, `runtime`, `client`, and `control` composition receive only their required capabilities and fail closed for missing, mismatched, oversized, unknown-version, or unsupported-algorithm values; Client receives no signer, sealer, opener, or generic custody capability;
04. the software provider has fixed HKDF-SHA-256/HMAC-SHA-256/XChaCha20-Poly1305 vectors, uses fresh 24-byte nonces and canonical length-delimited exact context, produces stable safe fingerprints independently of ciphertext randomness, and rejects context/provider/version substitution;
05. signing provisioning commits the protected-material row, normalized public key, key metadata, and operation outcome consistently, and Runtime verifies that signatures match the committed public key;
06. provider/SMTP/webhook secret creation, rotation, activation, overlap, disablement, compromise, cleanup, idempotent replay, crash, and stale-writer races preserve one authoritative PostgreSQL lifecycle without filesystem state;
07. opaque values and plaintext never enter DTOs, logs, telemetry, audit safe context, Redis, or error text, and transient plaintext/key material is bounded and zeroized where supported;
08. split Runtime processes using the same root can open/sign exact committed generations, while a wrong root or restored database without the root makes only the affected capabilities fail closed;
09. stable-operation remote signer test providers prove create/reconcile ambiguity, byte-identical inspection, public-key consistency, exact algorithm handling, JWS-ready signature normalization, and safe destruction classification;
10. the stateless software signer proves fresh same-operation handles, `NotFound + ExactInputSafe` inspection, crash recovery through fresh provisioning, and cleanup by PostgreSQL opaque-value erasure without `cleanup_blocked`;
11. Cargo publication verifies `owlauth-key-provider` is available before `owlauth-server`, downstream SemVer checks run, and the official binary still uses the same public composition path.

### Revisit triggers

Revisit `TS-003` when:

- online software-root rotation or multiple active/retained custody roots become a requirement;
- a provider requires a secret-sealing external-object lifecycle that cannot return a self-contained opaque envelope safely;
- a stable cross-language or runtime-loaded plugin ABI becomes a product requirement;
- out-of-process isolation is required rather than trusted in-process custom code;
- a new signing algorithm changes JWS, JWKS, lifecycle, or verifier behavior;
- measured envelope/handle size or remote-sign latency cannot fit the bounded provider contract.
