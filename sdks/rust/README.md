# owlauth-client

The official Rust SDK for [OwlAuth Project Auth](https://github.com/owlfoundry/owlauth).

```bash
cargo add owlauth-client
```

```rust
use owlauth_client::Client;

let client = Client::new("https://auth.example.com");
assert_eq!(client.base_url(), "https://auth.example.com");
```

## Current status

This crate is a pre-alpha scaffold and crate-name reservation. The current `Client` only stores the supplied base URL. It does not send HTTP requests or implement production authentication.

In particular, this release does not yet fetch public Project/Application configuration, initiate login with an upstream provider, manage PKCE, exchange a handoff ticket, refresh Project credentials, return the current user, or perform logout. Do not use it as a production authentication client.

## Intended Project Auth surface

Future releases will provide idiomatic Rust APIs for:

- initialization with a Runtime base URL and public Project/Application identifiers;
- safe retrieval of publishable authentication configuration;
- upstream-provider login initiation;
- Application-generated PKCE and one-use handoff exchange;
- short-lived Project JWT access tokens and opaque rotating refresh tokens;
- current Project user/session lookup and logout;
- non-exhaustive typed errors, explicit async cancellation/deadlines, and strict retry behavior.

OwlAuth uses OAuth/OIDC only with configured upstream identity providers. This crate will not expose OwlAuth as a downstream general-purpose OAuth authorization server. It consumes public Runtime contracts and must never depend on `owlauth-server` or receive server-internal authority.

## Compatibility and security

The SDK is independently versioned from `owlauth-server`, the CLI, and the TypeScript/Python SDKs. Supported server contract ranges will be documented when HTTP behavior ships.

See the language-neutral [SDK specifications](https://github.com/owlfoundry/owlauth/tree/main/sdks/spec) and the repository [security policy](https://github.com/owlfoundry/owlauth/blob/main/SECURITY.md).

## License

BSD 3-Clause. See [LICENSE](LICENSE).
