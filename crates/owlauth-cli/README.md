# owlauth-cli

The `owlauth` command-line interface for administering [OwlAuth](https://github.com/owlfoundry/owlauth).

One binary is the remote client for both self-hosted OwlAuth Control and OwlAuth SaaS. A profile stores a trusted administrative service origin but no user-configured product type. Origin-root discovery pins the product, stable instance, authority, API base, and credential class before the CLI selects an isolated self-hosted or SaaS client.

> OwlAuth is pre-alpha. Endpoint profiles, strict discovery, typed self-hosted Project/Application/user/session/provider/key/projection/webhook operations, cursor-bounded event and delivery inspection, system inspection, and checksum-verified self-update are implemented. Audit export and SaaS tenant commands are not yet implemented.

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

Rebind requires `--credential-env`, rejects the existing reference, and shows the proposed new reference with both identities before confirmation. It never reads either credential. The confirmed operation replaces the complete identity pin and credential reference; no credential, typed client, or product context is carried across automatically.

## Typed dispatch

Every authenticated command repeats discovery validation before reading the referenced credential, then completes a bounded self-hosted `GET system` authentication handshake before exposing the typed client. A missing/malformed descriptor, changed product/instance/authority/API base/credential class, or rejected operator key fails before any provider or webhook resource secret is read. The CLI never probes both products, infers identity from an authenticated error, retries against the other adapter, or stores a key.

The self-hosted client supports typed commands for:

- Project list/get/create/disable, token/session policy get/set, and Project-user list/get/identity/session inspection, disable, and exact session revoke;
- Application list/get/create/disable and cursor-bounded immutable user-event history;
- provider list/create/disable/assign/unassign for the closed `oidc`, `google`, and `github` kinds;
- signing-key list/create/activate/retire/revoke;
- Project- or Application-scoped projection-policy get/set;
- webhook endpoint list/get/create/subscription update/test/activate/disable, write-only secret rotation prepare/activate, cursor-bounded delivery inspection, and explicit replay.

Examples:

```bash
export OWLAUTH_CONTROL_API_KEY='owl_ctrl_v1_<43-character-base64url-secret>'
owlauth --profile local system
owlauth --profile local project list
owlauth --profile local project create \
  --display-name 'Example' \
  --idempotency-key project_create_20260803
owlauth --profile local application list \
  11111111-1111-4111-8111-111111111111
owlauth --profile local signing-key list \
  11111111-1111-4111-8111-111111111111
```

All Control path identifiers must be canonical lowercase hyphenated UUIDs. Create commands require an explicit 8–128 character `--idempotency-key`; retain and reuse that key when reconciling an ambiguous transport outcome instead of submitting the same normalized create under a new key. Revision-fenced trust, visibility, activation, disable, retirement, revoke, assignment, unassignment, endpoint-test, and policy changes require explicit `--yes` where exposed. The CLI rejects the operation before authentication when confirmation is absent; when present, it prints a redacted preview containing the selected profile, pinned endpoint/instance, exact target, operation, and bounded effect before authenticating. Full-replacement booleans such as `--browser-session-reuse` and `--verified-email-enabled` require an explicit `true` or `false` value.

Provider client secrets and webhook signing secrets, including candidate rotation generations, are accepted only through named environment-variable references:

```bash
export PROVIDER_CLIENT_SECRET='write-only-provider-secret'
owlauth --profile local provider create \
  11111111-1111-4111-8111-111111111111 \
  --kind github \
  --provider-key github \
  --display-name GitHub \
  --issuer https://github.com \
  --client-id example-client \
  --client-secret-env PROVIDER_CLIENT_SECRET \
  --expected-project-revision 1 \
  --idempotency-key provider_create_20260803
```

Raw secrets are never accepted as ordinary command arguments. Owned operator and resource-secret buffers are explicitly zeroized after use; the synchronous HTTP serializer may still create bounded transient transport-body copies that are dropped normally. A write-only resource secret must use a different environment reference and value from the active operator credential, preventing accidental operator-key submission to provider or webhook storage. Replace placeholders with real canonical values. If discovery selects SaaS, every self-hosted command is rejected before credential access; a future SaaS surface will use an isolated SaaS typed client and SaaS-owned DTOs/authorization.

The CLI intentionally omits generic HTTP/OpenAPI forwarding, Runtime and worker routes, raw database or key-store access, provider/key reconcile recovery, identity-mutation proof workflows, and operations absent from the reviewed public Control contract. Webhook replay is an explicit high-impact command: after an ambiguous transport outcome, inspect the paginated delivery history before deciding whether another replay is warranted.

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
