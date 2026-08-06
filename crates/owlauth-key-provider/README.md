# owlauth-key-provider

Provider-neutral Rust SPI for statically composed OwlAuth signing-key and configuration-secret
custody implementations.

> OwlAuth and this SPI are Beta and pre-1.0. Downstream providers must select an exact supported API
> range and treat required trait or value-semantic changes as breaking.

The crate exposes bounded values, redacted errors, deterministic protection context, explicit stable-operation versus stateless self-contained-handle provisioning semantics, and separate object-safe capabilities for:

- Control signing-key provisioning, inspection, and destruction;
- Runtime signing with an exact algorithm and opaque handle;
- Control configuration-secret sealing; and
- Runtime/worker exact-context configuration-secret opening.

Provider implementations use the crate's re-exported `owlauth_key_provider::async_trait` attribute;
this is the selected object-safe future convention. Signing capability objects also declare immutable
algorithm and material-format sets so server composition can reject incompatible role registrations
before serving.

It contains no server, database, HTTP, configuration, OpenAPI, or vendor SDK integration. Provider
implementations are trusted code statically linked into a custom OwlAuth server binary. OwlAuth does
not define a runtime dynamic-library, directory-scanned, subprocess, or sidecar plugin mechanism.

The official server bundles its local PostgreSQL-envelope software provider inside
`owlauth-server`; vendor KMS/HSM providers belong in independent crates.

See [TS-003](../../spec/technology/ts-003-key-provider-and-postgresql-custody.md) for the accepted
boundary.

## License

[BSD 3-Clause](LICENSE).
