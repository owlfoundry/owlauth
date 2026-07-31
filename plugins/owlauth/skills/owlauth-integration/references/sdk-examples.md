# Current SDK examples

These examples show the implemented pre-alpha protocol boundary. Each client is immutable and bound to one Runtime, Project, Application, and publishable key. The Application owns navigation, pending-state and credential persistence, callback history cleanup, refresh single-flight/atomic replacement, and framework or backend sessions.

## TypeScript

```typescript
import { Client } from "@owlauth/client";

const owlauth = new Client({
  baseUrl: "https://identity.example.com/runtime/",
  projectId: "project_public_id",
  applicationId: "application_public_id",
  publishableKey: "publishable_key",
});

const started = await owlauth.beginLogin({
  redirectUri: "https://app.example.com/auth/callback",
});

// The Application retains started.pending and explicitly navigates to started.hostedUrl.
const credentials = await owlauth.completeLogin(callbackUrl, started.pending);
const user = await owlauth.currentUser(credentials.accessToken);
const successor = await owlauth.refresh(credentials);
```

The same `@owlauth/client` artifact uses Web-standard APIs in supported browsers and Node.js. It does not navigate, use browser storage, or provide a separate browser entry point.

## Python

```python
from owlauth import Client

client = Client(
    "https://identity.example.com/runtime/",
    "project_public_id",
    "application_public_id",
    "publishable_key",
)

started = client.begin_login("https://app.example.com/auth/callback")
# The Application retains started.pending and explicitly navigates to started.hosted_url.
credentials = client.complete_login(callback_url, started.pending)
user = client.current_user(credentials)
successor = client.refresh(credentials)
```

The Python client is synchronous and uses a redirect-refusing, TLS-verifying standard-library transport by default.

## Rust

```rust,no_run
use owlauth_client::{Client, ClientConfig};

# async fn example(callback_url: &str) -> Result<(), owlauth_client::Error> {
let client = Client::new(ClientConfig::new(
    "https://identity.example.com/runtime/",
    "project_public_id",
    "application_public_id",
    "publishable_key",
))?;

let started = client
    .begin_login("https://app.example.com/auth/callback", None, None)
    .await?;
// The Application retains started.pending and explicitly navigates to started.hosted_url.
let credentials = client.complete_login(callback_url, started.pending).await?;
let user = client.current_user(credentials.access_token()).await?;
let successor = client.refresh(&credentials).await?;
# let _ = (user, successor);
# Ok(())
# }
```

## Security notes

- Project/Application IDs and publishable keys are public integration identifiers, not Control credentials.
- Remove callback handoff/state values from browser history before loading third-party resources.
- Never log or serialize pending state, PKCE verifiers, handoff tickets, access tokens, or refresh tokens. SDK wrappers redact them by default; raw values require deliberate exposure.
- Never blindly replay handoff or refresh after an ambiguous dispatched outcome. Follow the typed error action and reauthenticate or reconcile.
- Application backends verify the exact Project issuer, audience, EdDSA signature and `kid`, token type, time claims, `app_id`, and session context against Project JWKS. SDK possession or decoding is not authorization.
- Read each package README and `sdks/spec/` for complete cancellation, logout, persistence, and compatibility requirements.
