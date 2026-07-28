# owlauth-cli

The `owlauth` command-line interface for [OwlAuth](https://github.com/owlfoundry/owlauth).

OwlAuth is pre-alpha. The current CLI provides release-backed self-update support; management commands will be added only with documented server contracts.

```bash
owlauth --version
owlauth update --dry-run --version 0.0.2
owlauth update
```

The CLI is independent from the `owlauth-server` implementation and does not provide local database or authorization bypasses.

## License

BSD 3-Clause.
