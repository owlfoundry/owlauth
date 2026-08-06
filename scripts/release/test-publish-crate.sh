#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
publisher="$repository_root/scripts/release/publish-crate.sh"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT
manifest="$temporary_directory/Cargo.toml"

expect_failure() {
  if "$@" >/dev/null 2>&1; then
    printf 'expected command to fail:' >&2
    printf ' %q' "$@" >&2
    printf '\n' >&2
    exit 1
  fi
}

cat > "$manifest" <<'EOF'
[package]
name = "owlauth-release-guard-test"
version = "0.0.0-dev"
EOF
expect_failure "$publisher" "$manifest" "0.0.0-dev"
expect_failure "$publisher" "$manifest"

sed -i.bak 's/0\.0\.0-dev/1.2.3/' "$manifest"
rm -f "$manifest.bak"
expect_failure "$publisher" "$manifest" "1.2.4"

printf 'crate publication guard tests passed\n'
