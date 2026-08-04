# owlauth-client

The official async Rust protocol SDK for [OwlAuth Project Auth](https://github.com/owlfoundry/owlauth).

> This SDK is Beta and pre-1.0. Its API may change through reviewed releases. Exact-artifact qualification proves one source commit, Runtime contract, corpus, archive, and runtime coordinate; it is not a broad compatibility range, deployment certification, or production support commitment.

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

After the Application receives Runtime's exact callback, pass the complete callback and caller-held pending value to `complete_login`. Local redirect/state/context/expiry validation happens before network dispatch. Malformed inspection does not consume pending state; handoff exchange consumes it atomically and is never automatically retried.

Callers that inspect callbacks separately may use `validate_callback(&pending)` and then `exchange_handoff(validated)`. Validation borrows `PendingLogin`, and the validated callback shares its one-attempt guard; the guard is consumed only when exchange starts. The owned `complete_login(callback, pending)` convenience remains available. A malformed or context-invalid success response received after a sensitive dispatch is `ErrorCategory::Indeterminate` with code `invalid_response_after_dispatch`, because the remote commit cannot be disproved.

```rust,no_run
# use owlauth_client::{Client, ClientConfig};
# async fn example(client: Client, callback: &str) -> Result<(), owlauth_client::Error> {
let login = client
    .begin_login("https://app.example/auth/callback", None, None)
    .await?;
// The Application explicitly navigates to login.hosted_url and retains login.pending.
let credentials = client.complete_login(callback, login.pending).await?;
let user = client.current_user(credentials.access_token()).await?;
// Exact `owlauth.user.v1`; None means the Application projection has no admitted value.
let (_locale, _verified_email) = (&user.projection.locale, &user.projection.verified_email);
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

## Real-server and exact-crate qualification

Workspace `cargo test -p owlauth-client` exercises source-level unit and shared conformance behavior. The ignored `server_e2e` source test can help harness development, but running it against the workspace is not exact-crate evidence.

From a clean repository root, run:

```bash
make web-e2e
```

The repository gate generates current Runtime contract provenance, packages one `.crate`, binds its crates.io upload metadata and canonical candidate descriptor, verifies all digests, extracts the archive, and creates a separate Cargo consumer with a path dependency on the extracted crate. The internal integration test is copied into that consumer. It receives bounded expected-version, wrong-Project/Application, publishable-key, controlled-provider, and loopback fault-proxy values from the product harness.

Against its own Project/Application on the shared Chromium topology, the exact crate covers all eight claimed operations, one-use handoff replay, concurrent refresh/family invalidation, Application and browser logout, and dropped committed responses for handoff, refresh, and logout. A narrow raw helper drives Hosted/provider navigation; it does not depend on `owlauth-server` and is not a public SDK API.

CI separately compiles, tests, and lints the same external consumer on stable Rust, then binds that fragment and the Chromium journey into the component final evidence manifest. `owlauth_client::VERSION` must equal the extracted crate metadata. A final manifest proves one exact source/Runtime/archive coordinate; it is not a broad compatibility or production-support claim.

## Security boundary

The SDK never receives upstream provider tokens or secrets and is not a general OAuth authorization-server client. Application backends independently verify OwlAuth access-token signatures and trust namespace against the exact Project JWKS; merely possessing or decoding a token is not authorization verification.

The crate has no dependency on `owlauth-server` and owns no browser, filesystem, keychain, framework, or session state.

`owlauth_client::VERSION` is compiled from Cargo package metadata; exact-artifact qualification requires it to equal the installed crate version.

## License

BSD 3-Clause. See [LICENSE](LICENSE).
