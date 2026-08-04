#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_python="${ARTIFACT_PYTHON:-python3}"
archive="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
descriptor="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
upload_metadata="$(cd "$(dirname "$3")" && pwd)/$(basename "$3")"

"$artifact_python" "$repository_root/scripts/sdk_artifact.py" verify \
  --component rust --archive "$archive" --descriptor "$descriptor" \
  --upload-metadata "$upload_metadata" >/dev/null
version="$("$artifact_python" -c 'import json,sys; print(json.load(open(sys.argv[1]))["coordinate"]["version"])' "$descriptor")"
work_directory="$(mktemp -d "${TMPDIR:-/tmp}/owlauth-rust-package.XXXXXX")"
cleanup() {
  rm -rf "$work_directory"
}
trap cleanup EXIT

tar -xzf "$archive" -C "$work_directory"
candidate="$work_directory/owlauth-client-$version"
consumer="$work_directory/consumer"
mkdir -p "$consumer/tests" "$work_directory/spec"
cp "$repository_root/sdks/rust/tests/conformance.rs" "$consumer/tests/"
cp "$repository_root/sdks/rust/tests/protocol.rs" "$consumer/tests/"
cp "$repository_root/sdks/rust/tests/public_api.rs" "$consumer/tests/"
cp -R "$repository_root/sdks/spec/conformance" "$work_directory/spec/"
cp -R "$repository_root/sdks/spec/fixtures" "$work_directory/spec/"
cat > "$consumer/Cargo.toml" <<EOF
[package]
name = "owlauth-artifact-consumer"
version = "0.0.0"
edition = "2024"
publish = false

[dependencies]
owlauth-client = { path = "$candidate" }
async-trait = "0.1.91"
base64 = "0.22.1"
serde = { version = "1.0.229", features = ["derive"] }
serde_json = "1.0.151"
sha2 = "0.10.9"
tokio = { version = "1.53.1", features = ["macros", "rt"] }
EOF
cat > "$consumer/tests/artifact_origin.rs" <<EOF
#[test]
fn reports_the_packaged_version() {
    assert_eq!(owlauth_client::VERSION, "$version");
}
EOF

cargo test --manifest-path "$consumer/Cargo.toml" --locked 2>/dev/null || {
  cargo generate-lockfile --manifest-path "$consumer/Cargo.toml"
  cargo test --manifest-path "$consumer/Cargo.toml" --locked
}
manifest_path="$(cargo metadata --manifest-path "$consumer/Cargo.toml" --format-version 1 \
  | "$artifact_python" -c 'import json,sys; p=json.load(sys.stdin)["packages"]; print(next(x["manifest_path"] for x in p if x["name"]=="owlauth-client"))')"
[[ "$manifest_path" == "$candidate/Cargo.toml" ]]
tree="$(cargo tree --manifest-path "$consumer/Cargo.toml" --edges normal --prefix none)"
if grep -Eq '^owlauth-(server|types) ' <<< "$tree"; then
  echo "Rust SDK artifact must not depend on server implementation packages" >&2
  exit 1
fi

printf 'verified clean crate consumer for owlauth-client %s\n' "$version"
