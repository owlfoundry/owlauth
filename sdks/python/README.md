# owlauth-client

The official synchronous Python SDK for [OwlAuth Project Auth](https://github.com/owlfoundry/owlauth).
The distribution is `owlauth-client`; import it as `owlauth`.

> This SDK is Beta and pre-1.0. Its API may change through reviewed releases. Exact-artifact qualification proves one source commit, Runtime contract, corpus, archive, and runtime coordinate; it is not a broad compatibility range, deployment certification, or production support commitment.

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

A page transition, process restart, or other deliberate custody boundary may use the explicit
secret-bearing record API:

```python
pending_record = started.pending.export_record()
# Encrypt and store the entire record under Application-owned access control.
restored_pending = client.restore_pending_login(decrypted_pending_record)
credentials = client.complete_login(callback_url, restored_pending)
```

`restore_pending_login()` accepts only the current closed record schema, exact normalized Runtime
base URL (including path prefix), Project, and Application. It validates redirect, state, PKCE, and
expiry bounds without I/O. The Application must delete or atomically mark its durable pending copy
consumed immediately before exchange and must not restore it after a definitive or ambiguous
outcome.

## Credential lifecycle

```python
current = client.current_user(credentials)
# Exact `owlauth.user.v1`; None means the Application projection has no admitted value.
locale, verified_email = current.projection.locale, current.projection.verified_email
successor = client.refresh(credentials)
completion = client.logout_application(successor)
logout_target = client.prepare_browser_logout(successor)
```

A `CredentialPair` contains one atomic access/refresh generation bound to the exact normalized
Runtime base URL, Project, and Application. Credential-bearing operations accept that bound pair,
not an unbound raw token, and reject a context mismatch before dispatch. Raw credentials are
available only through the explicit `SecretValue.reveal()` method and are redacted from `str` and
`repr`; ordinary pickle serialization is rejected.

For deliberate durable custody, `credentials.export_record()` returns the complete secret-bearing
atomic generation and `client.restore_credentials(record)` validates and restores it without I/O.
The record must be encrypted and replaced as one unit. The SDK does not choose storage, serialize
refresh, or atomically replace Application state. Applications must single-flight refresh per
family and atomically replace or quarantine the full pair.

### Migration notes

`SecretValue` is intentionally not a dataclass. Generic dataclass serialization such as
`dataclasses.asdict()` can no longer expose its backing value, and copy/deepcopy retain redacted
representations. Use `reveal()` only at an explicit credential-release boundary. Canonical
operation values now identify `exchange_handoff` and `refresh_session`; a malformed or
context-invalid success response received after either sensitive dispatch raises
`IndeterminateError` with code `invalid_response_after_dispatch` rather than `ProtocolError`.

Application logout revokes the exact Application session. Project browser logout preparation
returns a Hosted confirmation target as data; the SDK never navigates to it.

## Errors and ambiguous outcomes

All public failures derive from `OwlAuthError` and expose stable `category`, `code`, `retry`,
`action`, `operation`, optional validated `request_id`, and optional `retry_after_seconds` fields.
A valid `429` requires one decimal-seconds `Retry-After` value between 0 and 86400; malformed or
missing guidance is an invalid response rather than an invented delay. Messages are SDK-owned and
do not include raw Runtime bodies, callback URLs, tokens, tickets, or PKCE values.

Handoff, refresh, Application logout, and Project browser-logout preparation are never retried.
If a timeout, cancellation, disconnect, or server failure occurs after dispatch and the commit
outcome cannot be known, the SDK raises `IndeterminateError`. The caller must follow its
`LocalAction`: quarantine pending state or the complete credential family and reauthenticate.

Every operation accepts an optional bounded `timeout`. The default standard-library transport is
synchronous, verifies TLS, disables redirects, and bounds headers and JSON bodies. Tests and
specialized integrations may inject the exported narrow `Transport` protocol; a custom transport
uses `TransportFailure(kind, dispatched=...)` to preserve ambiguity semantics. Pending handoff
material is released for another explicit attempt only when the transport positively reports
`dispatched=False`.

## Conformance and real-Runtime qualification

`load_conformance_corpus()` loads the shared versioned fixtures with schema, required-field,
duplicate-name, size, reference, and path-containment validation. `uv run --locked pytest` exercises
workspace source and those cases; it is not wheel or end-to-end evidence.

From a clean repository root, run:

```bash
make web-e2e
```

The repository gate generates current Runtime contract provenance, builds one wheel and canonical
candidate descriptor, verifies both digests, installs the wheel without dependencies in a fresh
external virtual environment, and copies the internal real-Runtime runner outside the repository.
The runner intentionally rejects an `owlauth` import resolved from the workspace. It receives
bounded expected-version, wrong-Project/Application, publishable-key, Hosted-navigation, and
loopback fault-proxy values from the product harness; do not invoke the workspace runner as
exact-artifact evidence.

Against its own Project/Application on the shared Chromium topology, the exact wheel covers all
eight claimed operations, one-use handoff replay, concurrent refresh/family invalidation,
Application and browser logout, and dropped committed responses for handoff, refresh, and logout.
A narrow raw HTTP helper only drives Hosted/provider navigation with Fetch Metadata and hardened
cookie handling; it is not an SDK transport or public API.

CI separately qualifies the same wheel under Python 3.11, 3.12, 3.13, and 3.14, then binds those
fragments and the Chromium journey into the component final evidence manifest. The SDK is
independently versioned from the server, CLI, and other language SDKs. Exact-artifact qualification
requires `owlauth.__version__` to equal installed wheel metadata. A final manifest proves one exact
source/Runtime/archive coordinate, not a broad compatibility or production-support claim.

This package is a Project Auth protocol client, not a downstream OAuth authorization server or a
provider-token broker. Provider credentials and provider access/refresh tokens never enter its
public API.

## License

BSD 3-Clause. See [LICENSE](LICENSE).
