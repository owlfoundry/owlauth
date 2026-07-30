# owlauth-cli

The `owlauth` command-line interface for administering [OwlAuth](https://github.com/owlfoundry/owlauth).

One binary is the remote client for both self-hosted OwlAuth Control and OwlAuth SaaS. A profile stores a trusted administrative service origin but no user-configured product type. Origin-root discovery pins the product, stable instance, authority, API base, and credential class before the CLI selects an isolated self-hosted or SaaS client.

> OwlAuth is pre-alpha. Endpoint profiles, strict discovery, self-hosted system inspection, and checksum-verified self-update are implemented. Project/Application/provider/user/session/policy/key/audit management and SaaS tenant commands are not yet implemented.

## Endpoint profiles

Add an endpoint only after reviewing the displayed public descriptor:

```bash
owlauth profile add local \
  --endpoint http://127.0.0.1:8081 \
  --yes
owlauth profile inspect local
owlauth profile check local
owlauth profile use local
```

There is no `--type`. HTTPS is required except for explicit loopback development. Discovery uses exact origin-root `GET /.well-known/owlauth`, rejects redirects and cross-origin API/MCP URLs, and accepts only supported `owlauth-server`/`operator-api-key` or `owlauth-saas`/`saas-api-key` pairs.

Profiles store only an environment-variable reference, never a raw key. The inferred references are `OWLAUTH_CONTROL_API_KEY` for self-hosted endpoints and `OWLAUTH_SAAS_API_KEY` for SaaS; select a different variable name with `--credential-env`. Profile data is written atomically under the platform configuration directory. `OWLAUTH_CONFIG_DIR` provides an explicit configuration directory for isolated automation.

An endpoint identity change never updates a pin implicitly. Review and confirm a deliberate replacement:

```bash
owlauth profile rebind local \
  --endpoint https://new-admin.example.com \
  --credential-env OWLAUTH_NEW_CONTROL_API_KEY \
  --yes
```

Rebind replaces the complete identity pin and credential reference. No credential or product context is carried across automatically.

## Typed dispatch

Every authenticated command repeats discovery validation before reading the referenced credential. A missing/malformed descriptor or changed product, instance, authority, API base, or credential class fails without credential release. The CLI never probes both products, infers identity from an authenticated error, retries against the other adapter, or stores a key.

The currently implemented authenticated command is self-hosted system inspection:

```bash
export OWLAUTH_CONTROL_API_KEY='owl_ctrl_v1_<43-character-base64url-secret>'
owlauth --profile local system
```

Replace the placeholder with a real canonical key. If discovery selected SaaS, `system` is rejected as unsupported before reading `OWLAUTH_SAAS_API_KEY`; future SaaS commands will use the isolated SaaS typed client and SaaS-owned DTOs/authorization.

## Self-update

```bash
owlauth --version
owlauth update --dry-run
owlauth update
```

A specific released version can be selected with `--version`; `--force` permits reinstalling it. The updater downloads native archives from GitHub Releases and verifies them against the release's mandatory `SHA256SUMS` before installation. The public shell and PowerShell installers use the same verified release path.

The CLI does not link either service implementation, access databases, load Project private keys, launch a local MCP process, or bypass server Project checks or SaaS tenant authorization. The normative boundaries are defined in [`spec/07-cli-and-mcp-boundaries.md`](../../spec/07-cli-and-mcp-boundaries.md) and [`spec/saas/07-cli-and-http-mcp-surfaces.md`](../../spec/saas/07-cli-and-http-mcp-surfaces.md).

## License

[BSD 3-Clause](LICENSE).
