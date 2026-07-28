# 01 — SDK system context and boundaries

## Purpose and current baseline

Official SDKs make OwlAuth's public HTTP protocol safer and more idiomatic in TypeScript, Python, and Rust. They are not embedded authorization servers, policy engines, administrative backdoors, or substitutes for OAuth-aware application design.

At present, each SDK only constructs a client configuration containing a base URL. There is no transport, generated model layer, OAuth flow, or server-backed behavior. Examples using that object are placeholders.

## Actors and boundaries

| Actor | SDK responsibility | SDK non-responsibility |
| --- | --- | --- |
| Application developer | typed inputs/results, lifecycle helpers, useful errors | deciding server authorization policy |
| End user/user agent | safe handoff data for browser authorization | collecting credentials inside the SDK |
| OwlAuth server | interoperable public requests | importing internal server code or state |
| Token store supplied by application | narrow read/write/delete integration | silently choosing insecure persistence |
| Operator/test runner | configuration and diagnostics | receiving secrets in logs/errors |

The application process, browser/user agent, network, token store, and server are separate trust boundaries. An SDK MUST validate local structure but cannot treat local values as proof of authorization.

## Layering

A target SDK has four explicit layers:

1. generated or contract-aligned wire models and low-level operation declarations;
2. handwritten transport policy;
3. handwritten OAuth lifecycle coordination (PKCE, authorization result handling, refresh serialization);
4. an idiomatic public API and stable semantic errors.

Applications MAY use low-level operations when documented, but unsafe ordering or secret display MUST not become the default. Generated identifiers SHOULD remain internal where exposing them would lock users to generator churn.

## Public boundary

SDK public APIs include constructor/configuration, documented request/result models, lifecycle abstractions, errors, cancellation behavior, and extension points. Internal generator runtime, HTTP library exceptions, server crate types, and fixture formats are not automatically public.

Base URLs MUST be parsed and normalized consistently without silently rewriting path prefixes. Production defaults require HTTPS; explicit loopback development exceptions require clear opt-in. SDKs MUST not discover an issuer from arbitrary response headers or switch origins because of an untrusted redirect.

## Language independence

Observable behavior is shared; syntax is idiomatic:

- TypeScript follows promises, `AbortSignal`, discriminated unions/errors, and package export conventions.
- Python follows typed exceptions, sync/async policy chosen explicitly, context management where needed, and import compatibility.
- Rust follows `Result`, typed errors, async runtime/HTTP boundaries chosen explicitly, and feature discipline.

A language limitation is documented and tested rather than hidden behind divergent security behavior.

## Acceptance criteria

- Public API review identifies which symbols are stable and which are generated/internal.
- Equivalent conformance cases produce equivalent semantic outcomes in all languages.
- Rust SDK dependency checks prove no path/dependency edge to server workspace crates.
- Documentation contains no examples of unavailable OAuth calls until implemented.
