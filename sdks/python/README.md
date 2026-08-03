# owlauth-client

The official synchronous Python SDK for [OwlAuth Project Auth](https://github.com/owlfoundry/owlauth).
The distribution is `owlauth-client`; import it as `owlauth`.

```bash
pip install owlauth-client
```

## Project-bound client

A client is immutable and bound to one Runtime, Project, Application, and publishable key:

```python
from owlauth import Client

client = Client(
    "https://identity.example/runtime/",
    "project_public_id",
    "application_public_id",
    "publishable_key",
)

configuration = client.get_public_configuration()
jwks = client.get_project_jwks()
```

HTTPS is required. Local development may explicitly opt into an HTTP loopback URL with
`allow_insecure_loopback=True`; TLS verification cannot be disabled through the SDK.
Configured Runtime path prefixes are preserved for every request.

## Login and caller-owned state

```python
started = client.begin_login(
    "https://app.example/callback",
    presentation_hint="Use your organization account",
)

# The Application explicitly navigates to started.hosted_url and retains started.pending.
# After the exact Application callback:
credentials = client.complete_login(callback_url, started.pending)
```

`begin_login` creates a fresh OS-CSPRNG PKCE S256 verifier and Application state. It does not
select an upstream provider, navigate, write browser history, or persist pending state. The
Application owns navigation and pending-state custody.

The callback is validated locally before a handoff request is sent. Project, Application,
Runtime, redirect, state, expiry, and one-attempt binding are checked. Handoff tickets and PKCE
verifiers are redacted by default and are never automatically replayed.

## Credential lifecycle

```python
current = client.current_user(credentials)
# Exact `owlauth.user.v1`; None means the Application projection has no admitted value.
locale, verified_email = current.projection.locale, current.projection.verified_email
successor = client.refresh(credentials)
completion = client.logout_application(successor)
logout_target = client.prepare_browser_logout(successor)
```

A `CredentialPair` contains one atomic access/refresh generation. Raw credentials are available
only through the explicit `SecretValue.reveal()` method and are redacted from `str` and `repr`.
The SDK does not persist credentials, serialize refresh, or atomically replace Application state.
Applications must single-flight refresh per family and atomically replace or quarantine the full
pair.

Application logout revokes the exact Application session. Project browser logout preparation
returns a Hosted confirmation target as data; the SDK never navigates to it.

## Errors and ambiguous outcomes

All public failures derive from `OwlAuthError` and expose stable `category`, `code`, `retry`,
`action`, `operation`, and optional validated `request_id` fields. Messages are SDK-owned and do
not include raw Runtime bodies, callback URLs, tokens, tickets, or PKCE values.

Handoff, refresh, Application logout, and Project browser-logout preparation are never retried.
If a timeout, cancellation, disconnect, or server failure occurs after dispatch and the commit
outcome cannot be known, the SDK raises `IndeterminateError`. The caller must follow its
`LocalAction`: quarantine pending state or the complete credential family and reauthenticate.

Every operation accepts an optional bounded `timeout`. The default standard-library transport is
synchronous, verifies TLS, disables redirects, and bounds headers and JSON bodies. Tests and
specialized integrations may inject the exported narrow `Transport` protocol; a custom transport
uses `TransportFailure(kind, dispatched=...)` to preserve ambiguity semantics.

## Conformance and real-Runtime verification

`load_conformance_corpus()` loads the shared versioned fixtures with schema, required-field,
duplicate-name, size, reference, and path-containment validation.

The real-server journey is a separate explicit command and is never silently skipped by unit tests:

```bash
OWLAUTH_E2E_RUNTIME_URL=https://runtime.example/ \
OWLAUTH_E2E_PROJECT_ID=project_public_id \
OWLAUTH_E2E_APPLICATION_ID=application_public_id \
OWLAUTH_E2E_PUBLISHABLE_KEY=publishable_key \
OWLAUTH_E2E_REDIRECT_URI=https://application.example/callback \
uv run --project sdks/python python sdks/python/tests/runtime_e2e.py
```

The already provisioned Runtime must use a controlled provider that completes authorization by
bounded redirects. The script uses the real SDK for config, start, callback exchange, current-user,
refresh, replay rejection, Application logout, and Project browser logout. A narrow HTTP helper
only drives Hosted/provider navigation with Fetch Metadata and manually preserves hardened Secure
cookies on loopback. For an explicitly configured HTTP loopback Runtime, also set
`OWLAUTH_E2E_ALLOW_INSECURE_LOOPBACK=1`.

Python 3.11, 3.12, 3.13, and 3.14 are supported. The SDK is independently versioned from the
server, CLI, and other language SDKs.

This package is a Project Auth protocol client, not a downstream OAuth authorization server or a
provider-token broker. Provider credentials and provider access/refresh tokens never enter its
public API.

## License

BSD 3-Clause. See [LICENSE](LICENSE).
