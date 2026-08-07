#!/usr/bin/env bash
set -euo pipefail

repository="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repository"

if [[ -n "$(git status --porcelain --untracked-files=all)" ]]; then
  echo "scripts/run-web-e2e.sh requires a clean worktree so candidate bytes match HEAD" >&2
  exit 1
fi

python="${OWLAUTH_E2E_ARTIFACT_PYTHON:-$repository/.venv/bin/python}"
if [[ ! -x "$python" ]]; then
  python="$(command -v python3)"
fi
source_commit="$(git rev-parse HEAD)"
work="$(mktemp -d "${TMPDIR:-/tmp}/owlauth-web-e2e.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/typescript" "$work/python" "$work/rust" "$work/cli"

"$python" scripts/sdk-contract.py check --provenance "$work/sdk-contract-provenance.json"

pnpm --filter @owlauth/client check
pnpm --filter @owlauth/client build
typescript_version="$(node -p "require('./sdks/typescript/package.json').version")"
typescript_archive="$work/typescript/owlauth-client-$typescript_version.tgz"
(
  cd sdks/typescript
  npm pack --pack-destination "$work/typescript" >/dev/null
)
"$python" scripts/sdk_artifact.py describe \
  --component typescript \
  --archive "$typescript_archive" \
  --contract-provenance "$work/sdk-contract-provenance.json" \
  --source-commit "$source_commit" \
  --output "$work/typescript/candidate.json"

(
  cd sdks/python
  uv run --locked hatchling build -t wheel -d "$work/python"
)
python_version="$("$python" -c 'import tomllib; print(tomllib.load(open("sdks/python/pyproject.toml", "rb"))["project"]["version"])')"
python_archive="$work/python/owlauth_client-${python_version}-py3-none-any.whl"
"$python" scripts/sdk_artifact.py describe \
  --component python \
  --archive "$python_archive" \
  --contract-provenance "$work/sdk-contract-provenance.json" \
  --source-commit "$source_commit" \
  --output "$work/python/candidate.json"

rust_version="$(sed -n 's/^version = "\([^"]*\)"$/\1/p' sdks/rust/Cargo.toml | head -n 1)"
rust_archive="$work/rust/owlauth-client-${rust_version}.crate"
rust_upload_metadata="$work/rust/owlauth-client-${rust_version}.upload.json"
rm -f "target/package/owlauth-client-${rust_version}.crate"
cargo package --manifest-path sdks/rust/Cargo.toml --locked --allow-dirty --no-verify
cp "target/package/owlauth-client-${rust_version}.crate" "$rust_archive"
"$python" scripts/sdk_artifact.py rust-upload-metadata \
  --archive "$rust_archive" \
  --output "$rust_upload_metadata"
"$python" scripts/sdk_artifact.py describe \
  --component rust \
  --archive "$rust_archive" \
  --upload-metadata "$rust_upload_metadata" \
  --contract-provenance "$work/sdk-contract-provenance.json" \
  --source-commit "$source_commit" \
  --output "$work/rust/candidate.json"

sha256() {
  "$python" -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$1"
}

export OWLAUTH_E2E_ARTIFACT_PYTHON="$python"
export OWLAUTH_E2E_PYTHON="$python"
export OWLAUTH_E2E_TYPESCRIPT_ARCHIVE="$typescript_archive"
export OWLAUTH_E2E_TYPESCRIPT_DESCRIPTOR="$work/typescript/candidate.json"
export OWLAUTH_E2E_TYPESCRIPT_ARCHIVE_SHA256="$(sha256 "$typescript_archive")"
export OWLAUTH_E2E_TYPESCRIPT_DESCRIPTOR_SHA256="$(sha256 "$work/typescript/candidate.json")"
export OWLAUTH_E2E_PYTHON_ARCHIVE="$python_archive"
export OWLAUTH_E2E_PYTHON_DESCRIPTOR="$work/python/candidate.json"
export OWLAUTH_E2E_PYTHON_ARCHIVE_SHA256="$(sha256 "$python_archive")"
export OWLAUTH_E2E_PYTHON_DESCRIPTOR_SHA256="$(sha256 "$work/python/candidate.json")"
export OWLAUTH_E2E_RUST_ARCHIVE="$rust_archive"
export OWLAUTH_E2E_RUST_DESCRIPTOR="$work/rust/candidate.json"
export OWLAUTH_E2E_RUST_UPLOAD_METADATA="$rust_upload_metadata"
export OWLAUTH_E2E_RUST_ARCHIVE_SHA256="$(sha256 "$rust_archive")"
export OWLAUTH_E2E_RUST_DESCRIPTOR_SHA256="$(sha256 "$work/rust/candidate.json")"

scripts/test-cli-package.sh "$work/cli/owlauth"
export OWLAUTH_E2E_CLI_BINARY="$work/cli/owlauth"

pnpm --filter @owlauth/server-web exec playwright test "$@"
