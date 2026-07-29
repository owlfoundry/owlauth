# owlauth-client

The official Python SDK for [OwlAuth Project Auth](https://github.com/owlfoundry/owlauth).

The distribution is named `owlauth-client`; import it as `owlauth`:

```bash
pip install owlauth-client
```

```python
from owlauth import Client

client = Client("https://auth.example.com")
print(client.base_url)
```

## Current status

This package is a pre-alpha scaffold and package-name reservation. The current `Client` only stores the supplied base URL. It does not send HTTP requests or implement production authentication.

In particular, this release does not yet fetch public Project/Application configuration, initiate login with an upstream provider, manage PKCE, exchange a handoff ticket, refresh Project credentials, return the current user, or perform logout. Do not use it as a production authentication client.

## Intended Project Auth surface

Future releases will provide typed Python APIs for:

- initialization with a Runtime base URL and public Project/Application identifiers;
- safe retrieval of publishable authentication configuration;
- upstream-provider login initiation;
- Application-generated PKCE and one-use handoff exchange;
- short-lived Project JWT access tokens and opaque rotating refresh tokens;
- current Project user/session lookup and logout;
- stable exceptions, explicit deadlines/cancellation, and strict retry behavior.

OwlAuth uses OAuth/OIDC only with configured upstream identity providers. This package will not expose OwlAuth as a downstream general-purpose OAuth authorization server, and public Application identifiers will never grant Control access.

## Compatibility and security

The SDK supports Python 3.11 through 3.14 and is independently versioned from `owlauth-server`, the CLI, and the TypeScript/Rust SDKs. Supported server contract ranges will be documented when HTTP behavior ships.

See the language-neutral [SDK specifications](https://github.com/owlfoundry/owlauth/tree/main/sdks/spec) and the repository [security policy](https://github.com/owlfoundry/owlauth/blob/main/SECURITY.md).

## License

BSD 3-Clause. See [LICENSE](LICENSE).
