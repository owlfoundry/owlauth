#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
verifier="$repository_root/scripts/release/verify-release.sh"

# shellcheck source=verify-release.sh
source "$verifier"

valid_versions=(
  "0.0.0"
  "1.2.3"
  "1.0.0-alpha"
  "1.0.0-alpha.1"
  "1.0.0-0.3.7"
  "1.0.0-x.7.z.92+build.5"
)
invalid_versions=(
  "01.2.3"
  "1.02.3"
  "1.2.03"
  "1.2.3-01"
  "1.2.3-."
  "1.2.3-a..b"
  "1.2.3+"
)

for version in "${valid_versions[@]}"; do
  if ! is_semver "$version"; then
    printf 'expected valid SemVer: %s\n' "$version" >&2
    exit 1
  fi
done

for version in "${invalid_versions[@]}"; do
  if is_semver "$version"; then
    printf 'expected invalid SemVer: %s\n' "$version" >&2
    exit 1
  fi
done

expect_failure() {
  if "$@" >/dev/null 2>&1; then
    printf 'expected command to fail:' >&2
    printf ' %q' "$@" >&2
    printf '\n' >&2
    exit 1
  fi
}

temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT
remote="$temporary_directory/remote.git"
work="$temporary_directory/work"
updater="$temporary_directory/updater"

git init --quiet --bare "$remote"
git init --quiet --initial-branch=main "$work"
cp "$repository_root/Cargo.toml" "$work/Cargo.toml"
mkdir -p \
  "$work/crates/owlauth-cli" \
  "$work/crates/owlauth-server" \
  "$work/crates/owlauth-types" \
  "$work/scripts/release"
cp "$repository_root/crates/owlauth-cli/Cargo.toml" "$work/crates/owlauth-cli/Cargo.toml"
cp "$repository_root/crates/owlauth-server/Cargo.toml" "$work/crates/owlauth-server/Cargo.toml"
cp "$repository_root/crates/owlauth-types/Cargo.toml" "$work/crates/owlauth-types/Cargo.toml"
cp "$verifier" "$work/scripts/release/verify-release.sh"
server_version="$(manifest_version "$repository_root/crates/owlauth-server/Cargo.toml")"
cli_version="$(manifest_version "$repository_root/crates/owlauth-cli/Cargo.toml")"

git -C "$work" config user.name "Release Test"
git -C "$work" config user.email "release-test@example.com"
git -C "$work" add Cargo.toml crates scripts/release/verify-release.sh
git -C "$work" commit --quiet -m "initial"
git -C "$work" remote add origin "$remote"
git -C "$work" push --quiet --set-upstream origin main
git --git-dir="$remote" symbolic-ref HEAD refs/heads/main

run_verifier() {
  local component="$1"
  shift
  (
    cd "$work"
    env "$@" "$verifier" "$component"
  )
}

run_verifier cli GITHUB_REF_NAME="release/cli/$cli_version" >/dev/null
git -C "$work" tag "cli-v$cli_version"
git -C "$work" push --quiet origin "cli-v$cli_version"
expect_failure run_verifier cli GITHUB_REF_NAME="release/cli/$cli_version"
git -C "$work" push --quiet --delete origin "cli-v$cli_version"
git -C "$work" tag --delete "cli-v$cli_version" >/dev/null

run_verifier server GITHUB_REF_NAME="release/server/$server_version" >/dev/null

git -C "$work" tag "server-v$server_version"
git -C "$work" push --quiet origin "server-v$server_version"
expect_failure run_verifier server GITHUB_REF_NAME="release/server/$server_version"

git -C "$work" push --quiet --delete origin "server-v$server_version"
git -C "$work" tag --delete "server-v$server_version" >/dev/null
expect_failure run_verifier server GITHUB_REF_NAME="release/server/$server_version" \
  RELEASE_REMOTE=missing

git clone --quiet "$remote" "$updater"
git -C "$updater" config user.name "Release Test"
git -C "$updater" config user.email "release-test@example.com"
printf 'advanced\n' > "$updater/ADVANCED"
git -C "$updater" add ADVANCED
git -C "$updater" commit --quiet -m "advance main"
git -C "$updater" push --quiet origin main
expect_failure run_verifier server GITHUB_REF_NAME="release/server/$server_version"

printf 'release verifier tests passed\n'
