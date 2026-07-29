# Current SDK examples

These examples reflect the current placeholder API. Each client stores only a base URL. Project/Application configuration, provider login, handoff exchange, tokens, refresh, current-user operations, and logout are not implemented in these packages yet.

Do not extend the examples with target Project Auth methods until those methods exist in the published client.

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
