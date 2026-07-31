# owlauth-client

The official async Rust protocol SDK for [OwlAuth Project Auth](https://github.com/owlfoundry/owlauth).

```bash
cargo add owlauth-client
```

## Project-bound client

```rust,no_run
use owlauth_client::{Client, ClientConfig};

# async fn example() -> Result<(), owlauth_client::Error> {
let client = Client::new(ClientConfig::new(
    "https://identity.example/runtime/",
    "prj_public",
    "app_public",
    "owl_app_publishable",
))?;

let public = client.public_configuration().await?;
assert!(public.login_available);
# Ok(())
# }
```

A `Client` is immutable and bound to one Runtime origin, Project, and Application. HTTPS is required by default. Plain HTTP is accepted only for `localhost`, `127.0.0.1`, or `::1` when `allow_insecure_loopback` is explicitly enabled.

## Login and credential lifecycle

`begin_login` generates fresh OS-CSPRNG PKCE S256 and Application state, calls generic login start, and returns a Hosted URL plus explicit `PendingLogin`. It does not navigate, choose a provider, persist state, mutate history, or manage an Application session.

After the Application receives Runtime's exact callback, pass the complete callback and caller-held pending value to `complete_login`. Local redirect/state/context/expiry validation happens before network dispatch. The pending value is consumed, and handoff exchange is never automatically retried.

```rust,no_run
# use owlauth_client::{Client, ClientConfig};
# async fn example(client: Client, callback: &str) -> Result<(), owlauth_client::Error> {
let login = client
    .begin_login("https://app.example/auth/callback", None, None)
    .await?;
// The Application explicitly navigates to login.hosted_url and retains login.pending.
let credentials = client.complete_login(callback, login.pending).await?;
let user = client.current_user(credentials.access_token()).await?;
let successor = client.refresh(&credentials).await?;
client.logout_application(successor.access_token()).await?;
# let _ = user;
# Ok(())
# }
```

`CredentialPair` contains one atomic access/refresh generation. Tokens are redacted from `Debug`; raw values are exposed only through deliberate `expose()` calls. The core does not serialize refresh, persist credentials, or atomically replace caller storage. Applications must single-flight each family and replace or quarantine the complete pair.

`prepare_browser_logout` returns a Hosted confirmation target as data and never navigates.

## Errors and one-use ambiguity

`Error` exposes stable `ErrorCategory`, machine code, retry policy, local-state action, operation, optional request ID, and status. Messages and `Debug` output never contain request bodies, callbacks, PKCE, handoff tickets, or tokens.

A timeout, cancellation, or disconnect after handoff, refresh, or logout dispatch is `ErrorCategory::Indeterminate`. The SDK never blind-replays one-use material. The caller must follow `local_action()` and reauthenticate or reconcile rather than retrying the same generation.

The public `Transport`, `EntropySource`, and `Clock` boundaries support deterministic contract testing without creating a fake end-to-end claim. The production transport verifies TLS, refuses redirects, enforces an overall deadline, and bounds responses.

## Real-server conformance

The ignored integration test drives the SDK, real Hosted UI endpoints, manually preserved hardened cookies, and a controlled auto-authorizing OIDC provider without depending on `owlauth-server`:

```bash
OWLAUTH_E2E_RUNTIME_URL=https://runtime.example/ \
OWLAUTH_E2E_PROJECT_ID=prj_public \
OWLAUTH_E2E_APPLICATION_ID=app_public \
OWLAUTH_E2E_PUBLISHABLE_KEY=owl_app_publishable \
OWLAUTH_E2E_REDIRECT_URI=https://app.example/callback \
OWLAUTH_E2E_PROVIDER_KEY=oidc-main \
cargo test -p owlauth-client --test server_e2e -- --ignored --exact real_runtime_project_auth_lifecycle
```

For a loopback HTTP Runtime, additionally set `OWLAUTH_E2E_ALLOW_INSECURE_LOOPBACK=1`. The provider must use Runtime's production OIDC adapter and immediately redirect its authorization request after validating PKCE/nonce/client/redirect inputs.

## Security boundary

The SDK never receives upstream provider tokens or secrets and is not a general OAuth authorization-server client. Application backends independently verify OwlAuth access-token signatures and trust namespace against the exact Project JWKS; merely possessing or decoding a token is not authorization verification.

The crate has no dependency on `owlauth-server` and owns no browser, filesystem, keychain, framework, or session state.

## License

BSD 3-Clause. See [LICENSE](LICENSE).
