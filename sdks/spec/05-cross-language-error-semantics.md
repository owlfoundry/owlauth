# 05 — Cross-language error semantics

## Goal

Applications need the same decision-relevant meaning in every official SDK without depending on raw HTTP-library exceptions or unsafe server diagnostics. Errors are typed, chain their redacted cause where idiomatic, and preserve stable machine-readable fields.

## Semantic taxonomy

| Class | Meaning | Typical application action |
| --- | --- | --- |
| `Configuration` | invalid local base URL, timeout, client config, or unsupported option | fix configuration; no request |
| `Protocol` | malformed/unexpected HTTP response or contract violation | stop; diagnose compatibility/server |
| `OAuth` | standards-defined OAuth error with safe code/metadata | branch by code and flow context |
| `Authentication` | client/user/session authentication cannot proceed | reauthenticate or fix credentials |
| `Authorization` | authenticated actor lacks permission/scope | request appropriate access; do not retry blindly |
| `RateLimited` | request rejected by rate policy | honor bounded retry guidance |
| `Transport` | DNS/TLS/connectivity/I/O failure before a definite protocol result | retry only if operation policy permits |
| `Timeout` | deadline elapsed; server effect may be unknown | treat one-use mutation as ambiguous |
| `Cancelled` | caller stopped waiting; server effect may be unknown | application decides recovery |
| `Indeterminate` | outcome of a security-sensitive one-use/state change cannot be known safely | reconcile or reauthorize; never blind replay |

Not-found/conflict/validation classes MAY be added when real public operations require them. Taxonomy changes require cross-language review.

## Required fields

Every public error exposes a stable category/code, safe message, optional request/correlation ID, and a retry classification (`never`, `safe_after_delay`, or `application_decision`). OAuth errors preserve the standardized `error` code and only reviewed optional fields. Server response bodies, headers, URLs, and causes are not exposed wholesale.

An unknown OAuth code remains inspectable without deserialization failure, while known codes may have typed conveniences. HTTP status assists diagnostics but is not the sole semantic classifier.

## Language mapping

- TypeScript uses exported error classes or a documented discriminant and preserves `cause` safely.
- Python uses an exported exception hierarchy with stable attributes and no secret-bearing `repr`/`str`.
- Rust uses a non-exhaustive exported error enum/struct strategy so additions do not force unsafe matching; `Display` is redacted and sources are bounded.

Names may differ idiomatically, but fixtures map each to the same semantic class and retry policy.

## Disclosure control

Messages MUST NOT contain authorization headers, cookies, client secrets, passwords, codes, tokens, PKCE verifiers, raw response bodies, or callback URLs. Truncation alone is not sufficient redaction. Diagnostic opt-in may expose safe status, headers allowlisted by name, timing, and correlation metadata—never raw secrets.

## Acceptance criteria

- Shared conformance cases verify category, stable fields, retry classification, unknown-code behavior, and redaction across languages.
- HTTP library implementation details are available only as safe chained causes and are not required for application branching.
- Ambiguous token/code operations never become a generic automatically retryable transport error.
- Public error taxonomy changes receive SemVer review per SDK.
