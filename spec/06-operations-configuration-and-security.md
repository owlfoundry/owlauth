# 06 — Operations, configuration, and security

## Current baseline

There is no production runtime configuration, HTTP listener, database connection, key provider, deployment guide, or readiness implementation. The current binary's version/OpenAPI output is development scaffolding. This document is the target operational contract.

## Startup and shutdown order

Target startup order is:

1. parse and validate configuration without printing secret values;
2. initialize redacted diagnostics and correlation IDs;
3. load key/secret-provider handles and validate required capabilities;
4. connect to storage and run embedded automatic migrations;
5. compose domain services and adapters;
6. bind listeners;
7. report ready only after required dependencies and migration state are valid.

On shutdown, the server stops admission, marks unready, drains bounded in-flight requests, flushes safe telemetry, and closes resources. Startup or shutdown failure returns a non-zero exit status.

## Configuration

Configuration has typed fields, one documented precedence order, strict parsing, and startup validation. Unknown fields SHOULD fail rather than be ignored. Security-relevant defaults MUST be safe: externally visible issuer, allowed origins, forwarding-header trust, listen address, TLS expectations, cookie policy, request limits, timeouts, and database/key locations are explicit.

Issuer and redirect decisions MUST NOT derive from attacker-controlled headers. Proxy headers are accepted only from configured trusted proxies. Development shortcuts are opt-in, conspicuously labeled, and cannot be enabled accidentally in a production profile.

## Secret and key handling

Secrets enter through environment/file/secret-manager or key-provider adapters with documented precedence and permission requirements. Secret values MUST NOT be accepted as ordinary command-line arguments, committed config, OpenAPI examples, health output, panic text, or telemetry attributes. Configuration display uses structural redaction. Files containing secrets require restrictive ownership/permissions where supported.

Signing/encryption keys have identifiers, purpose, algorithm, activation, retirement, and overlap policy. Rotation is observable and rehearsed. Missing, malformed, or unsafe keys prevent readiness.

## Network and HTTP posture

Production-facing traffic requires TLS at the service or a documented trusted proxy. The server applies header/body limits, request deadlines, bounded concurrency, safe content types, response security headers, and rate controls before costly work. CORS is deny-by-default and endpoint-specific. Administrative surfaces, if designed later, require separate authentication and exposure policy.

`/health` currently exists only as protocol metadata. Target liveness answers whether the process is alive without querying every dependency. Readiness answers whether the process can safely serve and remains false during migration or required dependency failure. Neither endpoint exposes versions, topology, credentials, SQL, key material, or user/client existence beyond explicitly reviewed metadata.

## Observability and audit

Structured events carry timestamp, severity, stable event name, request/correlation ID, latency, and safe actor references. Metrics use bounded-cardinality labels. Traces and errors redact authorization headers, cookies, URL query values carrying protocol data, request bodies, codes, tokens, verifiers, passwords, and client secrets. Panics and backtraces are internal only.

Security audit events are distinguished from debug logs, access-controlled, and assigned retention/integrity policy. Operators can diagnose migration version, dependency class, and configuration field name without receiving the corresponding secret value.

## Operational readiness

Before production guidance exists, the project needs a threat model, supported topology, backup/restore procedure, key rotation runbook, migration recovery, resource sizing, rate-limit strategy, incident response, vulnerability reporting, and tested upgrade path. `SECURITY.md` remains the disclosure entrypoint.

## Acceptance criteria

- Configuration tests cover precedence, unknown fields, invalid combinations, and redaction.
- Integration tests prove migration gating, readiness transitions, limits, deadlines, and graceful shutdown.
- Automated secret scanning and log-capture tests find no sensitive values.
- Deployment documentation states trust assumptions and avoids production claims until security/reliability gates pass.
