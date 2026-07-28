# owlauth-server

The server library and `owlauth-server` executable for [OwlAuth](https://github.com/owlfoundry/owlauth), a self-hostable OAuth 2.1 authorization server and user management platform.

OwlAuth is pre-alpha. The current server exposes a health endpoint and generated OpenAPI scaffold; functional OAuth and persistence flows are not implemented yet.

## Run

```bash
cargo run --package owlauth-server
```

Generate the current OpenAPI document:

```bash
cargo run --package owlauth-server -- --openapi
```

## License

BSD 3-Clause.
