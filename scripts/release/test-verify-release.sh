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
mkdir -p "$work/scripts/release"
cp "$verifier" "$work/scripts/release/verify-release.sh"

git -C "$work" config user.name "Release Test"
git -C "$work" config user.email "release-test@example.com"
git -C "$work" add Cargo.toml scripts/release/verify-release.sh
git -C "$work" commit --quiet -m "initial"
git -C "$work" remote add origin "$remote"
git -C "$work" push --quiet --set-upstream origin main

run_verifier() {
  (
    cd "$work"
    env "$@" "$verifier" server
  )
}

run_verifier GITHUB_REF_NAME=release/server/0.0.1 >/dev/null

git -C "$work" tag server-v0.0.1
git -C "$work" push --quiet origin server-v0.0.1
expect_failure run_verifier GITHUB_REF_NAME=release/server/0.0.1

git -C "$work" push --quiet --delete origin server-v0.0.1
git -C "$work" tag --delete server-v0.0.1 >/dev/null
expect_failure run_verifier GITHUB_REF_NAME=release/server/0.0.1 \
  RELEASE_REMOTE=missing

git clone --quiet "$remote" "$updater"
git -C "$updater" config user.name "Release Test"
git -C "$updater" config user.email "release-test@example.com"
printf 'advanced\n' > "$updater/ADVANCED"
git -C "$updater" add ADVANCED
git -C "$updater" commit --quiet -m "advance main"
git -C "$updater" push --quiet origin main
expect_failure run_verifier GITHUB_REF_NAME=release/server/0.0.1

printf 'release verifier tests passed\n'
