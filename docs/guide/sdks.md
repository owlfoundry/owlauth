# SDKs

OwlAuth reserves these client package names:

| Language | Registry package | Import |
| --- | --- | --- |
| TypeScript | `@owlauth/client` | `@owlauth/client` |
| Python | `owlauth-client` | `owlauth` |
| Rust | `owlauth-client` | `owlauth_client` |

Each SDK uses independent SemVer and an independent release tag. A Python-only change does not require TypeScript or Rust version changes.

The initial `0.0.1` packages expose only a minimal client configuration object. PKCE, token refresh, transport behavior, and error mapping will be handwritten for each language after the protocol stabilizes. The shared target behavior, machine-readable fixtures, and conformance policy are indexed in [`sdks/spec/`](https://github.com/owlfoundry/owlauth/tree/main/sdks/spec).

Current checks are package, unit, and small fixture/conformance checks—not end-to-end OAuth tests. Once OAuth behavior exists, CI is expected to start a real OwlAuth server and run all three SDKs against it; placeholder or mocked tests must not be labeled E2E.

## TypeScript

```typescript
import { Client } from "@owlauth/client";

const client = new Client("https://auth.example.com");
console.log(client.baseUrl);
```

## Python

```python
from owlauth import Client

client = Client("https://auth.example.com")
print(client.base_url)
```

## Rust

```rust
use owlauth_client::Client;

let client = Client::new("https://auth.example.com");
println!("{}", client.base_url());
```

These are placeholder examples, not production OAuth flows.
