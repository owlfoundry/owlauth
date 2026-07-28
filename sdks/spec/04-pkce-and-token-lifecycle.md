# 04 — PKCE and token lifecycle

## Status

PKCE, authorization-result handling, token exchange, token storage, and refresh are not implemented. The current SDKs MUST NOT be presented as performing OAuth. This contract becomes applicable with the first supported Authorization Code flow.

## Authorization initiation

The lifecycle helper MUST:

1. generate a fresh PKCE verifier with a CSPRNG and derive an `S256` challenge;
2. generate fresh correlation state with a CSPRNG;
3. bind verifier, state, client, redirect URI, scopes, issuer/base URL, and creation/expiry in a short-lived pending transaction;
4. return an authorization URL and opaque transaction handle without logging secrets;
5. never accept a caller-supplied `plain` challenge downgrade.

Opening a browser is an explicit application action, not a hidden side effect of model construction. The SDK does not collect the resource owner's password.

## Redirect/result handling

The application supplies redirect parameters through a documented callback boundary. The SDK validates exact state using constant-time comparison where applicable, expiry, one-use status, issuer/origin expectations, and presence/exclusivity of code versus OAuth error before exchange. It consumes pending state so replay fails even if a later exchange errors.

The verifier is sent only to the configured token endpoint over an accepted secure transport. Code, verifier, state, and full callback URL are redacted from errors and telemetry.

## Token representation and persistence

Token responses distinguish access token, optional refresh token, token type, granted scopes, and server expiry. Expiry calculations retain the receipt instant and account for wall-clock uncertainty. Raw token values use redacted wrappers where each language permits.

SDKs MUST NOT silently persist tokens. Applications provide an explicit token-store interface or keep tokens in memory. Any official persistence adapter requires a separate platform security design. Serialization, backups, crash reports, browser storage, and debug tools are treated as disclosure channels.

## Refresh lifecycle

Before sending a request, the lifecycle layer MAY refresh within a documented skew window. Refresh for the same session/token family is single-flight within a process: concurrent callers share one result rather than rotating the same token repeatedly.

On success, the new token set MUST be committed atomically to the application-provided store before old material is discarded according to server rotation semantics. On definitive `invalid_grant`, local refresh state is invalidated and reauthorization is required. On timeout/disconnect or another ambiguous outcome, the SDK MUST NOT blindly replay; it returns a typed indeterminate result and avoids overwriting possibly rotated state.

Cross-process refresh coordination is not magically provided by an in-process SDK. Token-store implementations supporting multiple processes must expose compare-and-swap/version semantics or applications must serialize externally.

## Client authentication

Public-client helpers do not accept or manufacture a client secret. If confidential clients are later supported, secret injection, supported methods, rotation, and non-disclosure require a distinct configuration path. Browser-distributed SDK code MUST never embed a confidential credential.

## Acceptance criteria

- Deterministic tests inject entropy/clock boundaries and verify S256 vectors without weakening production RNG.
- Cases cover state mismatch/replay/expiry, error callbacks, verifier custody, scope changes, expiry skew, refresh single-flight, `invalid_grant`, and ambiguous refresh outcomes.
- Captured logs/errors/debug strings contain none of the seeded secret values.
- Real-server E2E is required before the flow is advertised as interoperable.
