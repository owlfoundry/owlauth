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
mkdir -p "$work/scripts/release"
cp "$verifier" "$work/scripts/release/verify-release.sh"

git -C "$work" config user.name "Release Test"
git -C "$work" config user.email "release-test@example.com"
git -C "$work" add scripts/release/verify-release.sh
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

cli_tag=cli-v1.2.3
git -C "$work" tag "$cli_tag"
git -C "$work" push --quiet origin "$cli_tag"
run_verifier cli GITHUB_REF_TYPE=tag GITHUB_REF_NAME="$cli_tag" >/dev/null
expect_failure run_verifier cli GITHUB_REF_TYPE=branch GITHUB_REF_NAME="$cli_tag"
expect_failure run_verifier server GITHUB_REF_TYPE=tag GITHUB_REF_NAME="$cli_tag"
expect_failure run_verifier cli GITHUB_REF_TYPE=tag GITHUB_REF_NAME=cli-v9.9.9
expect_failure run_verifier cli GITHUB_REF_TYPE=tag GITHUB_REF_NAME="$cli_tag" \
  RELEASE_REMOTE=missing

invalid_tag=cli-v01.2.3
git -C "$work" tag "$invalid_tag"
git -C "$work" push --quiet origin "$invalid_tag"
expect_failure run_verifier cli GITHUB_REF_TYPE=tag GITHUB_REF_NAME="$invalid_tag"

server_tag=server-v2.0.0
git -C "$work" tag -a "$server_tag" -m "$server_tag"
git -C "$work" push --quiet origin "$server_tag"
run_verifier server GITHUB_REF_TYPE=tag GITHUB_REF_NAME="$server_tag" >/dev/null

git clone --quiet "$remote" "$updater"
git -C "$updater" config user.name "Release Test"
git -C "$updater" config user.email "release-test@example.com"
printf 'advanced\n' > "$updater/ADVANCED"
git -C "$updater" add ADVANCED
git -C "$updater" commit --quiet -m "advance main"
git -C "$updater" push --quiet origin main
expect_failure run_verifier cli GITHUB_REF_TYPE=tag GITHUB_REF_NAME="$cli_tag"

printf 'release verifier tests passed\n'
