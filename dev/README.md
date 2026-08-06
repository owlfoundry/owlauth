# Local development infrastructure

`dev/compose.yml` runs the disposable infrastructure used by local OwlAuth development:

- PostgreSQL 17 on `127.0.0.1:5432`;
- Redis 8 on `127.0.0.1:6379`.

The services bind to loopback by default and use named Docker volumes. The default credentials are intentionally development-only.

To run the complete OwlAuth application from the repository root:

```bash
cp .env.example .env
make dev
```

`make dev` rebuilds the embedded web assets, starts this infrastructure, and runs the combined
Runtime, Client, and Control process in the foreground using PostgreSQL-resident protected material.
Application configuration lives in the ignored root `.env`; the committed root `.env.example`
contains public disposable development values only.

Infrastructure can also be managed independently:

```bash
make dev-up
make dev-status
make dev-logs
make dev-down
```

`make dev-reset` removes the containers and both data volumes before starting healthy empty services again. It is intentionally destructive to local development data.

Optional Compose-only overrides can be placed in `dev/.env`:

```bash
cp dev/.env.example dev/.env
```

The default application URLs are:

```text
postgres://owlauth:owlauth_dev@127.0.0.1:5432/owlauth
redis://127.0.0.1:6379/
```

Container-backed Rust integration tests do not reuse these long-lived services. They start isolated PostgreSQL and Redis containers through Testcontainers and remove them after each test process. When Docker is unavailable locally those tests report a skip; CI sets `OWLAUTH_REQUIRE_DOCKER=1` so container startup failures are fatal.
