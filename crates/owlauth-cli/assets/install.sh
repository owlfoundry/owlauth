#!/usr/bin/env sh
set -eu

REPO="${OWLAUTH_GITHUB_REPO:-owlfoundry/owlauth}"
VERSION="${OWLAUTH_VERSION:-latest}"
INSTALL_DIR="${OWLAUTH_INSTALL_DIR:-$HOME/.local/bin}"
NO_MODIFY_PATH="${OWLAUTH_NO_MODIFY_PATH:-0}"
TMP_DIR="${TMPDIR:-/tmp}/owlauth-install-$$"

fail() {
  printf 'owlauth install error: %s\n' "$*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

is_semver() {
  printf '%s\n' "$1" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'
}

fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then
    wget -q "$1" -O "$2"
  else
    fail "install curl or wget"
  fi
}

fetch_stdout() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget -q "$1" -O -
  else
    fail "install curl or wget"
  fi
}

resolve_version() {
  if [ "$VERSION" != "latest" ]; then
    value="${VERSION#cli-v}"
    value="${value#v}"
    is_semver "$value" || fail "version is not valid SemVer: $VERSION"
    printf '%s\n' "$value"
    return
  fi
  value="$(fetch_stdout "https://api.github.com/repos/$REPO/releases?per_page=100" | awk '
    /"url": "https:\/\/api.github.com\/repos\// && /\/releases\/[0-9]+",/ {
      if (seen && tag ~ /^cli-v/ && draft == "false" && prerelease == "false") {
        sub(/^cli-v/, "", tag)
        print tag
        emitted = 1
        exit
      }
      seen = 1
      tag = draft = prerelease = ""
      next
    }
    /^[[:space:]]*"tag_name":/ {
      split($0, fields, "\"")
      tag = fields[4]
    }
    /^[[:space:]]*"draft":/ {
      draft = $0
      sub(/^[^:]*:[[:space:]]*/, "", draft)
      sub(/,.*/, "", draft)
    }
    /^[[:space:]]*"prerelease":/ {
      prerelease = $0
      sub(/^[^:]*:[[:space:]]*/, "", prerelease)
      sub(/,.*/, "", prerelease)
    }
    END {
      if (!emitted && seen && tag ~ /^cli-v/ && draft == "false" && prerelease == "false") {
        sub(/^cli-v/, "", tag)
        print tag
      }
    }
  ')"
  [ -n "$value" ] || fail "could not resolve the latest stable CLI release"
  is_semver "$value" || fail "latest CLI release tag is not valid SemVer: $value"
  printf '%s\n' "$value"
}

detect_target() {
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) arch=x86_64 ;;
    arm64|aarch64) arch=aarch64 ;;
    *) fail "unsupported architecture: $arch" ;;
  esac
  case "$os" in
    linux) printf '%s-unknown-linux-gnu\n' "$arch" ;;
    darwin) printf '%s-apple-darwin\n' "$arch" ;;
    *) fail "unsupported operating system: $os" ;;
  esac
}

verify_checksum() {
  archive="$1"
  checksums="$2"
  name="$(basename "$archive")"
  expected="$(awk -v name="$name" '$2 == name || $2 == "*" name {print $1; exit}' "$checksums")"
  [ -n "$expected" ] || fail "SHA256SUMS has no entry for $name"
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$archive" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "$archive" | awk '{print $1}')"
  else
    fail "missing sha256sum or shasum"
  fi
  [ "$actual" = "$expected" ] || fail "checksum mismatch for $name"
}

ensure_path() {
  case ":$PATH:" in *":$INSTALL_DIR:"*) return ;; esac
  if [ "$NO_MODIFY_PATH" = 1 ]; then
    printf 'add %s to PATH\n' "$INSTALL_DIR"
    return
  fi
  profile="$HOME/.profile"
  case "${SHELL:-}" in
    */zsh) profile="$HOME/.zshrc" ;;
    */bash) profile="$HOME/.bashrc" ;;
  esac
  if [ ! -f "$profile" ] || ! grep -Fq "$INSTALL_DIR" "$profile"; then
    printf '\nexport PATH="%s:$PATH"\n' "$INSTALL_DIR" >> "$profile"
    printf 'updated PATH in %s\n' "$profile"
  fi
}

main() {
  need uname
  need tar
  version="$(resolve_version)"
  target="$(detect_target)"
  tag="cli-v$version"
  archive_name="owlauth-cli-$version-$target.tar.gz"
  base_url="https://github.com/$REPO/releases/download/$tag"
  mkdir -p "$TMP_DIR" "$INSTALL_DIR"
  trap 'rm -rf "$TMP_DIR"' EXIT INT TERM
  fetch "$base_url/$archive_name" "$TMP_DIR/$archive_name"
  fetch "$base_url/SHA256SUMS" "$TMP_DIR/SHA256SUMS"
  verify_checksum "$TMP_DIR/$archive_name" "$TMP_DIR/SHA256SUMS"
  mkdir "$TMP_DIR/extracted"
  tar -xzf "$TMP_DIR/$archive_name" -C "$TMP_DIR/extracted"
  [ -f "$TMP_DIR/extracted/owlauth" ] || fail "archive is missing owlauth"
  staged="$INSTALL_DIR/.owlauth.tmp.$$"
  cp "$TMP_DIR/extracted/owlauth" "$staged"
  chmod 0755 "$staged"
  mv -f "$staged" "$INSTALL_DIR/owlauth"
  printf 'installed %s from %s\n' "$INSTALL_DIR/owlauth" "$tag"
  ensure_path
}

main "$@"
