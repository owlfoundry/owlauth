# owlauth-cli

The `owlauth` command-line interface for administering [OwlAuth](https://github.com/owlfoundry/owlauth).

The target CLI is a remote client of OwlAuth's authenticated Control API. It does not link the server implementation, open the server database, load Project private keys, or bypass server-side scope and Project checks.

> OwlAuth is pre-alpha. The current CLI provides help/version output and checksum-verified self-update only. Project, Application, provider, user, session, policy, key, audit, and MCP management commands are not implemented.

## Current commands

```bash
owlauth --help
owlauth --version
owlauth update --dry-run
owlauth update
```

A specific released version can be selected with `--version`; `--force` permits reinstalling the selected version. Run `owlauth update --help` for the exact current options.

The updater downloads native archives from GitHub Releases and verifies them against the release's mandatory `SHA256SUMS` before installation. The public shell and PowerShell installers use the same verified release path.

## Target boundary

Future management commands will call only documented Control operations and will preserve:

- distinct Control credentials and endpoints;
- deny-by-default management scopes;
- explicit Project targeting and revision checks;
- safe secret input that avoids command history and process arguments;
- confirmation for destructive or security-sensitive transitions;
- stable machine-readable output and exit codes.

The normative boundary is defined in [`spec/07-cli-and-mcp-boundaries.md`](../../spec/07-cli-and-mcp-boundaries.md).

## License

[BSD 3-Clause](LICENSE).
