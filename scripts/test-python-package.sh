#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_python="${ARTIFACT_PYTHON:-python3}"
archive="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
descriptor="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"

"$artifact_python" "$repository_root/scripts/sdk_artifact.py" verify \
  --component python --archive "$archive" --descriptor "$descriptor" \
  --distribution-directory "$(dirname "$archive")" >/dev/null
version="$("$artifact_python" -c 'import json,sys; print(json.load(open(sys.argv[1]))["coordinate"]["version"])' "$descriptor")"
work_directory="$(mktemp -d "${TMPDIR:-/tmp}/owlauth-python-package.XXXXXX")"
cleanup() {
  rm -rf "$work_directory"
}
trap cleanup EXIT

python -m venv "$work_directory/venv"
python_bin="$work_directory/venv/bin/python"
"$python_bin" -m pip install --disable-pip-version-check --no-deps "$archive"
"$python_bin" -m pip install --disable-pip-version-check pytest==9.0.3

mkdir -p "$work_directory/sdks/python/tests" "$work_directory/sdks/spec"
cp "$repository_root/sdks/python/tests/test_client.py" "$work_directory/sdks/python/tests/"
cp "$repository_root/sdks/python/tests/test_conformance.py" "$work_directory/sdks/python/tests/"
cp "$repository_root/sdks/python/tests/test_transport.py" "$work_directory/sdks/python/tests/"
cp -R "$repository_root/sdks/spec/conformance" "$work_directory/sdks/spec/"
cp -R "$repository_root/sdks/spec/fixtures" "$work_directory/sdks/spec/"

EXPECTED_VERSION="$version" REPOSITORY_ROOT="$repository_root" VENV_ROOT="$work_directory/venv" \
  "$python_bin" - <<'PY'
import importlib.metadata
import os
from pathlib import Path

import owlauth

origin = Path(owlauth.__file__).resolve()
assert origin.is_relative_to(Path(os.environ["VENV_ROOT"]).resolve()), origin
assert not origin.is_relative_to(Path(os.environ["REPOSITORY_ROOT"]).resolve()), origin
assert owlauth.__version__ == os.environ["EXPECTED_VERSION"]
assert importlib.metadata.version("owlauth-client") == os.environ["EXPECTED_VERSION"]
PY
(
  cd "$work_directory"
  "$python_bin" -m pytest -q sdks/python/tests
)

printf 'verified clean wheel consumer for owlauth-client %s\n' "$version"
