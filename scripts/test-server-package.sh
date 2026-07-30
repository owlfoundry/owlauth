#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repository_root"

package_version() {
  local manifest="$1"
  sed -n 's/^version = "\([^"]*\)"$/\1/p' "$manifest" | head -n 1
}

types_version="$(package_version crates/owlauth-types/Cargo.toml)"
server_version="$(package_version crates/owlauth-server/Cargo.toml)"
types_archive="target/package/owlauth-types-${types_version}.crate"
server_archive="target/package/owlauth-server-${server_version}.crate"
work_directory="$(mktemp -d "${TMPDIR:-/tmp}/owlauth-package.XXXXXX")"
cleanup() {
  rm -rf "$work_directory"
}
trap cleanup EXIT

rm -f "$types_archive" "$server_archive"
cargo package \
  --manifest-path crates/owlauth-types/Cargo.toml \
  --locked --allow-dirty --no-verify
cargo package \
  --manifest-path crates/owlauth-server/Cargo.toml \
  --locked --allow-dirty --no-verify

server_files="$(tar -tzf "$server_archive" | sed 's#^[^/]*/##')"
grep -qx LICENSE <<< "$server_files"
grep -qx build.rs <<< "$server_files"
grep -qx migrations/20260729000000_project_application_core.sql <<< "$server_files"
grep -qx web/dist/runtime/server-manifest.json <<< "$server_files"
grep -qx web/dist/control/server-manifest.json <<< "$server_files"

tar -xzf "$types_archive" -C "$work_directory"
tar -xzf "$server_archive" -C "$work_directory"
cat > "$work_directory/Cargo.toml" <<EOF
[workspace]
members = ["owlauth-server-${server_version}"]
resolver = "3"

[patch.crates-io]
owlauth-types = { path = "owlauth-types-${types_version}" }
EOF

CARGO_NET_OFFLINE=true cargo generate-lockfile \
  --manifest-path "$work_directory/Cargo.toml"
CARGO_NET_OFFLINE=true cargo build \
  --manifest-path "$work_directory/Cargo.toml" \
  --package owlauth-server \
  --locked

printf 'verified offline build of packaged owlauth-server %s\n' "$server_version"
