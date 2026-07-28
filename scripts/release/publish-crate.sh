#!/usr/bin/env bash
set -euo pipefail

manifest="${1:-}"
if [[ -z "$manifest" || ! -f "$manifest" ]]; then
  printf 'usage: %s <Cargo.toml>\n' "$0" >&2
  exit 2
fi

read -r package version < <(
  awk '
    /^\[package\]$/ { in_package = 1; next }
    /^\[/ { in_package = 0 }
    in_package && /^name = / {
      name = $0
      sub(/^[^"]*"/, "", name)
      sub(/".*$/, "", name)
    }
    in_package && /^version = / {
      version = $0
      sub(/^[^"]*"/, "", version)
      sub(/".*$/, "", version)
    }
    END { print name, version }
  ' "$manifest"
)
[[ -n "$package" && -n "$version" ]] || {
  printf 'failed to read package name and version from %s\n' "$manifest" >&2
  exit 1
}

cargo package --locked --manifest-path "$manifest"
archive="target/package/${package}-${version}.crate"
[[ -f "$archive" ]] || {
  printf 'cargo package did not create %s\n' "$archive" >&2
  exit 1
}

metadata_file="$(mktemp)"
trap 'rm -f "$metadata_file"' EXIT
status="$(curl --silent --show-error \
  --user-agent 'owlauth-release (https://github.com/owlfoundry/owlauth; jizhongsheng957@gmail.com)' \
  --output "$metadata_file" --write-out '%{http_code}' \
  "https://crates.io/api/v1/crates/$package/$version")"
case "$status" in
  200)
    local_checksum="$(sha256sum "$archive" | awk '{print $1}')"
    published_checksum="$(python3 -c \
      'import json, sys; print(json.load(sys.stdin)["version"]["checksum"])' \
      < "$metadata_file")"
    if [[ "$local_checksum" != "$published_checksum" ]]; then
      printf 'published %s %s checksum does not match this source package\n' \
        "$package" "$version" >&2
      exit 1
    fi
    printf '%s %s is already published with the expected checksum\n' "$package" "$version"
    ;;
  404)
    : "${CARGO_REGISTRY_TOKEN:?CARGO_REGISTRY_TOKEN is required}"
    cargo publish --locked --manifest-path "$manifest"
    ;;
  *)
    printf 'crates.io returned HTTP %s while checking %s %s\n' \
      "$status" "$package" "$version" >&2
    exit 1
    ;;
esac
