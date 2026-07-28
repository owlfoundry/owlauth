# SDK examples

These examples reflect the current `0.0.1` placeholder API. Do not extend them with OAuth operations until those operations exist in the published clients.

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
