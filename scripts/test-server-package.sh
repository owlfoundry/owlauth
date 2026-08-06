#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repository_root"

package_version() {
  local manifest="$1"
  sed -n 's/^version = "\([^"]*\)"$/\1/p' "$manifest" | head -n 1
}

key_provider_version="$(package_version crates/owlauth-key-provider/Cargo.toml)"
types_version="$(package_version crates/owlauth-types/Cargo.toml)"
server_version="$(package_version crates/owlauth-server/Cargo.toml)"
key_provider_archive="target/package/owlauth-key-provider-${key_provider_version}.crate"
types_archive="target/package/owlauth-types-${types_version}.crate"
server_archive="target/package/owlauth-server-${server_version}.crate"
work_directory="$(mktemp -d "${TMPDIR:-/tmp}/owlauth-package.XXXXXX")"
cleanup() {
  rm -rf "$work_directory"
}
trap cleanup EXIT

rm -f "$key_provider_archive" "$types_archive" "$server_archive"
cargo package \
  --manifest-path crates/owlauth-key-provider/Cargo.toml \
  --locked --allow-dirty --no-verify
cargo package \
  --manifest-path crates/owlauth-types/Cargo.toml \
  --locked --allow-dirty --no-verify
cargo package \
  --manifest-path crates/owlauth-server/Cargo.toml \
  --locked --allow-dirty --no-verify \
  --config 'patch.crates-io.owlauth-key-provider.path="crates/owlauth-key-provider"' \
  --config 'patch.crates-io.owlauth-types.path="crates/owlauth-types"'

server_files="$(tar -tzf "$server_archive" | sed 's#^[^/]*/##')"
grep -qx LICENSE <<< "$server_files"
grep -qx build.rs <<< "$server_files"
migration_files="$(grep '^migrations/.*\.sql$' <<< "$server_files")"
expected_migration_files="$(
  for migration in crates/owlauth-server/migrations/*.sql; do
    printf 'migrations/%s\n' "$(basename "$migration")"
  done
)"
[[ "$migration_files" == "$expected_migration_files" ]]
grep -qx third-party/README.md <<< "$server_files"
grep -qx third-party/rmcp/LICENSE <<< "$server_files"
grep -q 'Apache License' <(tar -xOzf "$server_archive" "owlauth-server-${server_version}/third-party/rmcp/LICENSE")
grep -qx web/dist/runtime/server-manifest.json <<< "$server_files"
grep -qx web/dist/control/server-manifest.json <<< "$server_files"

tar -xzf "$key_provider_archive" -C "$work_directory"
tar -xzf "$types_archive" -C "$work_directory"
tar -xzf "$server_archive" -C "$work_directory"
cat > "$work_directory/Cargo.toml" <<EOF
[workspace]
members = ["owlauth-server-${server_version}"]
resolver = "3"

[patch.crates-io]
owlauth-key-provider = { path = "owlauth-key-provider-${key_provider_version}" }
owlauth-types = { path = "owlauth-types-${types_version}" }
EOF

CARGO_NET_OFFLINE=true cargo generate-lockfile \
  --manifest-path "$work_directory/Cargo.toml"
CARGO_NET_OFFLINE=true cargo build \
  --manifest-path "$work_directory/Cargo.toml" \
  --package owlauth-server \
  --locked

printf 'verified offline build of packaged owlauth-server %s\n' "$server_version"
