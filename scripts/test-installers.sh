#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT
fixtures="$temporary_directory/fixtures"
fake_bin="$temporary_directory/bin"
install_dir="$temporary_directory/installed"
mkdir -p "$fixtures/archive" "$fake_bin" "$install_dir"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch=x86_64 ;;
  arm64|aarch64) arch=aarch64 ;;
  *) printf 'unsupported test architecture: %s\n' "$arch" >&2; exit 1 ;;
esac
case "$os" in
  linux) target="$arch-unknown-linux-gnu" ;;
  darwin) target="$arch-apple-darwin" ;;
  *) printf 'unsupported installer test OS: %s\n' "$os" >&2; exit 1 ;;
esac
archive_name="owlauth-cli-0.0.3-$target.tar.gz"
printf '#!/usr/bin/env sh\nprintf "fixture owlauth 0.0.3\\n"\n' > "$fixtures/archive/owlauth"
chmod +x "$fixtures/archive/owlauth"
tar -czf "$fixtures/$archive_name" -C "$fixtures/archive" owlauth
if command -v sha256sum >/dev/null 2>&1; then
  checksum="$(sha256sum "$fixtures/$archive_name" | awk '{print $1}')"
else
  checksum="$(shasum -a 256 "$fixtures/$archive_name" | awk '{print $1}')"
fi
printf '%s  %s\n' "$checksum" "$archive_name" > "$fixtures/SHA256SUMS"
cat > "$fixtures/releases.json" <<'JSON'
[
  {
    "url": "https://api.github.com/repos/owlfoundry/owlauth/releases/4",
    "tag_name": "server-v9.0.0",
    "author": {"login": "release-test"},
    "draft": false,
    "prerelease": false
  },
  {
    "url": "https://api.github.com/repos/owlfoundry/owlauth/releases/3",
    "tag_name": "cli-v0.0.4-rc.1",
    "author": {"login": "release-test"},
    "draft": false,
    "prerelease": true
  },
  {
    "url": "https://api.github.com/repos/owlfoundry/owlauth/releases/2",
    "tag_name": "cli-v0.0.3",
    "author": {"login": "release-test"},
    "draft": false,
    "prerelease": false
  }
]
JSON
cat > "$fake_bin/curl" <<'SH'
#!/usr/bin/env sh
set -eu
url=""
output=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) output="$2"; shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
case "$url" in
  *api.github.com*) source="$TEST_INSTALLER_FIXTURES/releases.json" ;;
  */SHA256SUMS) source="$TEST_INSTALLER_FIXTURES/SHA256SUMS" ;;
  */owlauth-cli-*) source="$TEST_INSTALLER_FIXTURES/${url##*/}" ;;
  *) printf 'unexpected fixture URL: %s\n' "$url" >&2; exit 1 ;;
esac
if [ -n "$output" ]; then cp "$source" "$output"; else cat "$source"; fi
SH
chmod +x "$fake_bin/curl"

PATH="$fake_bin:$PATH" \
TEST_INSTALLER_FIXTURES="$fixtures" \
OWLAUTH_INSTALL_DIR="$install_dir" \
OWLAUTH_NO_MODIFY_PATH=1 \
  sh "$repository_root/scripts/install.sh" >/dev/null
"$install_dir/owlauth" | grep -qx 'fixture owlauth 0.0.3'

if PATH="$fake_bin:$PATH" \
  TEST_INSTALLER_FIXTURES="$fixtures" \
  OWLAUTH_VERSION='../invalid' \
  OWLAUTH_INSTALL_DIR="$install_dir" \
  OWLAUTH_NO_MODIFY_PATH=1 \
  sh "$repository_root/scripts/install.sh" >/dev/null 2>&1; then
  printf 'installer accepted an invalid version\n' >&2
  exit 1
fi

printf 'installer tests passed\n'
