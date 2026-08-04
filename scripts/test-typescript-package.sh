#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_python="${ARTIFACT_PYTHON:-python3}"
archive="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
descriptor="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"

"$artifact_python" "$repository_root/scripts/sdk_artifact.py" verify \
  --component typescript --archive "$archive" --descriptor "$descriptor" >/dev/null
version="$("$artifact_python" -c 'import json,sys; print(json.load(open(sys.argv[1]))["coordinate"]["version"])' "$descriptor")"
work_directory="$(mktemp -d "${TMPDIR:-/tmp}/owlauth-typescript-package.XXXXXX")"
cleanup() {
  rm -rf "$work_directory"
}
trap cleanup EXIT

consumer="$work_directory/typescript"
mkdir -p "$consumer/test" "$work_directory/spec"
cp "$repository_root/sdks/typescript/test/client.test.mjs" "$consumer/test/"
cp "$repository_root/sdks/typescript/test/conformance.test.mjs" "$consumer/test/"
cp "$repository_root/sdks/typescript/test/portable-artifact.test.mjs" "$consumer/test/"
cp -R "$repository_root/sdks/spec/conformance" "$work_directory/spec/"
cp -R "$repository_root/sdks/spec/fixtures" "$work_directory/spec/"

cat > "$consumer/package.json" <<'EOF'
{
  "name": "owlauth-typescript-artifact-consumer",
  "private": true,
  "type": "module"
}
EOF
(
  cd "$consumer"
  npm install --ignore-scripts --no-save "$archive"
)
cat > "$consumer/version-smoke.mjs" <<'EOF'
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { VERSION } from "@owlauth/client";

assert.equal(VERSION, process.env.EXPECTED_VERSION);
const resolved = fileURLToPath(import.meta.resolve("@owlauth/client"));
assert.ok(resolved.includes("node_modules/@owlauth/client/dist/index.js"), resolved);
assert.equal(resolved.startsWith(process.env.REPOSITORY_ROOT), false, resolved);
EOF
(
  cd "$consumer"
  EXPECTED_VERSION="$version" REPOSITORY_ROOT="$repository_root" node version-smoke.mjs
  OWLAUTH_TYPESCRIPT_PACKAGE="@owlauth/client" \
    OWLAUTH_TYPESCRIPT_INTERNAL_TYPES="$consumer/node_modules/@owlauth/client/dist/types.js" \
    node --test test/client.test.mjs test/conformance.test.mjs
  OWLAUTH_TYPESCRIPT_PACKAGE_ROOT="$consumer/node_modules/@owlauth/client" \
    node --test test/portable-artifact.test.mjs
)

printf 'verified clean npm consumer for @owlauth/client %s\n' "$version"
