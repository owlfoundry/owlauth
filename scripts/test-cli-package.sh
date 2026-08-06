#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repository_root"

package_version() {
  local manifest="$1"
  sed -n 's/^version = "\([^"]*\)"$/\1/p' "$manifest" | head -n 1
}

types_version="$(package_version crates/owlauth-types/Cargo.toml)"
cli_version="$(package_version crates/owlauth-cli/Cargo.toml)"
types_archive="target/package/owlauth-types-${types_version}.crate"
cli_archive="target/package/owlauth-cli-${cli_version}.crate"
work_directory="$(mktemp -d "${TMPDIR:-/tmp}/owlauth-cli-package.XXXXXX")"
cleanup() {
  rm -rf "$work_directory"
}
trap cleanup EXIT

rm -f "$types_archive" "$cli_archive"
cargo package \
  --manifest-path crates/owlauth-types/Cargo.toml \
  --locked --allow-dirty --no-verify
cargo package \
  --manifest-path crates/owlauth-cli/Cargo.toml \
  --locked --allow-dirty --no-verify \
  --config 'patch.crates-io.owlauth-types.path="crates/owlauth-types"'

cli_files="$(tar -tzf "$cli_archive" | sed 's#^[^/]*/##')"
grep -qx LICENSE <<< "$cli_files"
grep -qx src/main.rs <<< "$cli_files"

tar -xzf "$types_archive" -C "$work_directory"
tar -xzf "$cli_archive" -C "$work_directory"
cat > "$work_directory/Cargo.toml" <<EOF
[workspace]
members = ["owlauth-cli-${cli_version}"]
resolver = "3"

[patch.crates-io]
owlauth-types = { path = "owlauth-types-${types_version}" }
EOF

CARGO_NET_OFFLINE=true cargo generate-lockfile \
  --manifest-path "$work_directory/Cargo.toml"
CARGO_NET_OFFLINE=true cargo build \
  --manifest-path "$work_directory/Cargo.toml" \
  --package owlauth-cli \
  --locked

printf 'verified offline build of packaged owlauth-cli %s\n' "$cli_version"
