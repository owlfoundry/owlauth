# @owlauth/client

The official Web-standard TypeScript SDK for [OwlAuth Project Auth](https://github.com/owlfoundry/owlauth). The same package runs in supported browsers and Node.js 20, 22, and 24; there is no separate browser entry point. The current browser support matrix is Playwright Chromium and Firefox. WebKit and Safari are not yet declared supported.

> This SDK is Beta and pre-1.0. Its API may change through reviewed releases. Exact-artifact qualification proves one source commit, Runtime contract, corpus, archive, and runtime coordinate; it is not a broad compatibility range, deployment certification, or production support commitment.

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

// Explicitly export secret-bearing state into Application-owned protected custody.
await applicationSession.storePendingLogin(pending.exportRecord());
window.location.assign(hostedUrl);

// After Runtime returns to the exact registered callback, atomically take the record.
const pendingRecord = await applicationSession.takePendingLogin();
const restoredPending = owlauth.restorePendingLogin(pendingRecord);
const credentials = await owlauth.completeLogin(window.location.href, restoredPending);
```

`beginLogin` creates PKCE S256 and Application state with Web Crypto. It does not select a provider, navigate, persist state, mutate history, or create a framework session. The Application must remove callback values from browser history before loading third-party resources.

`PendingLogin`, `ValidatedCallback`, `CredentialPair`, and token wrappers redact protocol secrets from `toString()` and JSON output. `exportRecord()` is a deliberately named secret-bearing boundary for Application-owned protected storage; `restorePendingLogin()` and `restoreCredentialPair()` reject unknown fields, stale values, and another Runtime origin/base path, Project, or Application. Raw tokens are otherwise available only through the deliberate `expose()` method. The example's `applicationSession` is Application code, not SDK storage.

### Migration notes

`AccessToken`, `PendingLogin`, `CredentialPair`, and `ValidatedCallback` are Client-produced or Client-restored values and cannot be constructed as unbound transport credentials. `PkceVerifier` is not exported from the package root. Applications retain opaque values in memory or use the explicit versioned record boundary rather than reconstructing lifecycle state. Malformed callback inspection and a positively prevented dispatch preserve pending state, while exchange consumes it immediately before dispatch. A malformed, uncontracted-status, or context-invalid response received after a sensitive operation was dispatched is `Indeterminate` with code `invalid_response_after_dispatch`, because the remote commit cannot be disproved.

## Credential lifecycle

```typescript
const current = await owlauth.currentUser(credentials.accessToken);
// Exact `owlauth.user.v1`; null means the Application projection has no admitted value.
const { locale, verifiedEmail } = current.projection;

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

An optional `ClientOptions.debugHook` receives one immutable, secret-free completion event per real network attempt. It is disabled by default, and hook failures are ignored. Events contain only the fixed operation, method, closed outcome, elapsed milliseconds, dispatch flag, and optional safe status/error metadata; they never contain URLs, headers, bodies, identifiers, callbacks, PKCE, or credentials.

`OwlAuthError` exposes stable, secret-free fields:

- `category` and machine `code`;
- `operation`;
- `retry`: `never`, `safe_after_delay`, or `application_decision`;
- caller `action`, such as `discard_pending` or `quarantine_credentials`;
- an allowlisted request ID and HTTP status when available;
- bounded `retryAfterSeconds` when an optional SaaS/ingress layer returns a contract-valid `429 rate_limited` response.

A valid Core `408 request_timeout` is `Timeout` with caller-decision retry and no local action for non-sensitive operations. For a dispatched handoff, refresh, or logout operation it is `Indeterminate` with the existing quarantine action because the server deadline may expire after authority work starts. Malformed `408` responses fail conservatively as invalid responses. Unknown Runtime codes remain conservative and non-retryable. Raw response bodies, callback URLs, tokens, handoff tickets, and PKCE verifiers are never copied into public errors.

## Real-server and exact-artifact qualification

`pnpm test` and `pnpm check` exercise workspace source, mock transports, and the shared conformance corpus. They are not registry-artifact or end-to-end evidence.

From a clean repository root, run:

```bash
make web-e2e
```

The repository gate generates current Runtime contract provenance, builds one npm tarball and canonical candidate descriptor, verifies both digests, installs the tarball in an external consumer, serves that candidate's `dist` modules from the controlled Application origin, and executes the public SDK API in Chromium and Firefox page realms against one real OwlAuth topology. It provisions a distinct Project/Application for TypeScript, validates browser Fetch/CORS/Web Crypto/callback behavior, checks wrong-context rejection, and covers all eight claimed operations, one-use replay/concurrent-refresh behavior, Application and browser logout, and dropped committed responses for handoff, refresh, and logout.

The internal `test/e2e-real-server.mjs` runner intentionally rejects a package resolved inside the repository. It is copied into the clean consumer by the product harness and receives bounded isolation, browser-driver, evidence-run, expected-version, and loopback fault-proxy values from that harness. The browser driver accepts `{ hostedUrl, redirectUri, providerKey, browserName, evidenceRunId }`, performs a real top-level journey without intercepting Runtime, and returns bounded `{ callbackUrl }` data. Do not invoke the workspace runner or a manually installed package as exact-artifact evidence.

CI separately qualifies the same candidate under Node.js 20, 22, and 24 plus a Vite 8.1.5 production bundle, then binds those fragments and the Chromium/Firefox journeys into the component final evidence manifest. A final manifest proves one exact source/Runtime/archive coordinate; it is not a broad compatibility or production-support claim.

## Application responsibilities

The core SDK intentionally does not own:

- navigation or browser-history cleanup;
- browser/native/backend persistence;
- refresh single-flight or atomic compare-and-swap;
- automatic request interception;
- framework session state;
- JWT trust verification for an Application backend.

See the language-neutral [SDK specifications](https://github.com/owlfoundry/owlauth/tree/main/sdks/spec) and [security policy](https://github.com/owlfoundry/owlauth/blob/main/SECURITY.md).

The root package exports `VERSION`; exact-artifact qualification requires it to equal the installed npm package version.

## License

BSD 3-Clause. See [LICENSE](LICENSE).
