#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_python="${ARTIFACT_PYTHON:-python3}"
archive="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
descriptor="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
"$artifact_python" "$repository_root/scripts/sdk_artifact.py" verify \
  --component typescript --archive "$archive" --descriptor "$descriptor" >/dev/null

work_directory="$(mktemp -d "${TMPDIR:-/tmp}/owlauth-typescript-browser.XXXXXX")"
cleanup() {
  rm -rf "$work_directory"
}
trap cleanup EXIT
cat > "$work_directory/package.json" <<'EOF'
{
  "name": "owlauth-browser-artifact-consumer",
  "private": true,
  "type": "module"
}
EOF
cat > "$work_directory/index.html" <<'EOF'
<div id="version"></div><script type="module" src="/src.js"></script>
EOF
cat > "$work_directory/src.js" <<'EOF'
import { Client, VERSION } from "@owlauth/client";
window.owlauthArtifact = { Client, VERSION };
document.querySelector("#version").textContent = VERSION;
EOF
(
  cd "$work_directory"
  npm install --ignore-scripts --no-save "$archive" vite@8.1.5
  npx vite build
)
combined="$(find "$work_directory/dist/assets" -type f -name '*.js' -exec cat {} +)"
for forbidden in 'from "node:' 'require(' 'process.' 'Buffer.'; do
  if grep -Fq "$forbidden" <<< "$combined"; then
    echo "browser bundle contains forbidden runtime dependency: $forbidden" >&2
    exit 1
  fi
done

printf 'verified browser bundle from exact @owlauth/client tarball\n'
