# @owlauth/client

The official Web-standard TypeScript SDK for [OwlAuth Project Auth](https://github.com/owlfoundry/owlauth). The same package runs in supported browsers and Node.js 20, 22, and 24; there is no separate browser entry point. The current browser support matrix is Playwright Chromium and Firefox. WebKit and Safari are not yet declared supported.

```bash
pnpm add @owlauth/client
```

## Configure one Project and Application

```typescript
import { Client } from "@owlauth/client";

const owlauth = new Client({
  baseUrl: "https://identity.example.com/runtime/",
  projectId: "project_public_id",
  applicationId: "application_public_id",
  publishableKey: "publishable_key",
});
```

HTTPS is required by default. An explicit `allowInsecureLoopback: true` option exists only for loopback development. A configured path prefix is preserved for every request.

## Start and complete login

```typescript
const { hostedUrl, pending } = await owlauth.beginLogin({
  redirectUri: "https://app.example.com/auth/callback",
});

// The Application owns navigation and custody of `pending`.
window.location.assign(hostedUrl);

// After Runtime returns to the exact registered callback:
const credentials = await owlauth.completeLogin(window.location.href, pending);
```

`beginLogin` creates PKCE S256 and Application state with Web Crypto. It does not select a provider, navigate, persist state, mutate history, or create a framework session. The Application must remove callback values from browser history before loading third-party resources.

`PendingLogin`, `ValidatedCallback`, `CredentialPair`, and token wrappers redact protocol secrets from `toString()` and JSON output. Raw tokens are available only through the deliberate `expose()` method.

## Credential lifecycle

```typescript
const current = await owlauth.currentUser(credentials.accessToken);

// The Application must serialize refresh per family and atomically replace the pair.
const successor = await owlauth.refresh(credentials);

// Revokes only this Application session.
await owlauth.logoutApplication(successor.accessToken);

// Returns a Hosted target as data; the SDK never navigates.
const browserLogout = await owlauth.prepareBrowserLogout(successor.accessToken);
```

Refresh, handoff exchange, and logout are never retried automatically. If transport fails after dispatch, the SDK raises `OwlAuthError` with category `Indeterminate`; callers must quarantine the pending login or credential family and must not replay one-use material.

## Public data

```typescript
const configuration = await owlauth.getPublicConfiguration();
const jwks = await owlauth.getProjectJwks();
```

Configuration and every authenticated response are checked against the immutable Project/Application context. Fetching JWKS does not itself verify a JWT or establish authorization.

## Cancellation, deadlines, and errors

Every network method accepts `{ signal, timeoutMs }`. Client construction also accepts a default `timeoutMs` and an injectable Web-standard `fetch`, Web Crypto provider, and clock for deterministic integrations and tests.

`OwlAuthError` exposes stable, secret-free fields:

- `category` and machine `code`;
- `operation`;
- `retry`: `never`, `safe_after_delay`, or `application_decision`;
- caller `action`, such as `discard_pending` or `quarantine_credentials`;
- an allowlisted request ID and HTTP status when available.

Unknown Runtime codes remain conservative and non-retryable. Raw response bodies, callback URLs, tokens, handoff tickets, and PKCE verifiers are never copied into public errors.

## Explicit real-server E2E entry

`pnpm test:e2e` is a separate executable suite and never silently skips. It requires one already provisioned real Runtime, Application, signing key, and controlled standards-compatible provider:

- `OWLAUTH_E2E_RUNTIME_BASE_URL`
- `OWLAUTH_E2E_PROJECT_ID`
- `OWLAUTH_E2E_APPLICATION_ID`
- `OWLAUTH_E2E_PUBLISHABLE_KEY`
- `OWLAUTH_E2E_REDIRECT_URI`
- `OWLAUTH_E2E_BROWSER_DRIVER_URL`
- optional `OWLAUTH_E2E_PROVIDER_KEY`
- optional `OWLAUTH_E2E_BROWSER_DRIVER_TOKEN`
- `OWLAUTH_E2E_ALLOW_INSECURE_LOOPBACK=1` only for explicit loopback development HTTP

The browser-driver endpoint accepts `{ hostedUrl, redirectUri, providerKey }`, performs a real top-level browser journey through the embedded Hosted UI and controlled provider without intercepting Runtime, and returns bounded JSON `{ callbackUrl }`. The SDK suite then performs callback validation, handoff exchange, current-user, refresh rotation, replay-family rejection, Application logout, and post-logout rejection through the public SDK.

## Application responsibilities

The core SDK intentionally does not own:

- navigation or browser-history cleanup;
- browser/native/backend persistence;
- refresh single-flight or atomic compare-and-swap;
- automatic request interception;
- framework session state;
- JWT trust verification for an Application backend.

See the language-neutral [SDK specifications](https://github.com/owlfoundry/owlauth/tree/main/sdks/spec) and [security policy](https://github.com/owlfoundry/owlauth/blob/main/SECURITY.md).

## License

BSD 3-Clause. See [LICENSE](LICENSE).
