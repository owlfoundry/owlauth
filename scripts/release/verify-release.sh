#!/usr/bin/env bash
set -euo pipefail

is_semver() {
  local version="$1"
  local numeric='(0|[1-9][0-9]*)'
  local prerelease_identifier='(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
  local prerelease="${prerelease_identifier}(\.${prerelease_identifier})*"
  local build='[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*'
  local pattern="^${numeric}\.${numeric}\.${numeric}(-${prerelease})?(\+${build})?$"

  [[ "$version" =~ $pattern ]]
}

read_release_metadata() {
  local component="$1"

  case "$component" in
    server)
      prefix="release/server/"
      tag_prefix="server-v"
      manifest_version="$(
        awk '
          /^\[workspace\.package\]$/ { in_workspace_package = 1; next }
          /^\[/ { in_workspace_package = 0 }
          in_workspace_package && /^version = / {
            sub(/^[^"]*"/, "")
            sub(/".*$/, "")
            print
            exit
          }
        ' Cargo.toml
      )"
      ;;
    typescript)
      prefix="release/sdk/typescript/"
      tag_prefix="typescript-v"
      manifest_version="$(sed -n 's/^  "version": "\([^"]*\)",$/\1/p' sdks/typescript/package.json | head -n 1)"
      ;;
    python)
      prefix="release/sdk/python/"
      tag_prefix="python-v"
      manifest_version="$(sed -n 's/^version = "\([^"]*\)"$/\1/p' sdks/python/pyproject.toml | head -n 1)"
      ;;
    rust)
      prefix="release/sdk/rust/"
      tag_prefix="rust-v"
      manifest_version="$(sed -n 's/^version = "\([^"]*\)"$/\1/p' sdks/rust/Cargo.toml | head -n 1)"
      ;;
    *)
      printf 'usage: %s {server|typescript|python|rust}\n' "$0" >&2
      return 2
      ;;
  esac
}

main() {
  local component="${1:-}"
  local branch version remote release_commit main_commit tag tag_matches
  local prefix tag_prefix manifest_version

  read_release_metadata "$component"

  branch="${GITHUB_REF_NAME:-$(git branch --show-current)}"
  if [[ "$branch" != "$prefix"* ]]; then
    printf 'expected branch prefix %s, got %s\n' "$prefix" "$branch" >&2
    return 1
  fi

  version="${branch#"$prefix"}"
  if [[ "$version" == */* ]] || ! is_semver "$version"; then
    printf 'branch does not end in a valid SemVer version: %s\n' "$version" >&2
    return 1
  fi

  if [[ -z "$manifest_version" || "$version" != "$manifest_version" ]]; then
    printf 'branch version %s does not match %s manifest version %s\n' \
      "$version" "$component" "${manifest_version:-<missing>}" >&2
    return 1
  fi

  remote="${RELEASE_REMOTE:-origin}"
  if ! git fetch --quiet --no-tags "$remote" \
    +refs/heads/main:refs/remotes/release-verification/main; then
    printf 'failed to fetch main from release remote %s\n' "$remote" >&2
    return 1
  fi

  release_commit="$(git rev-parse HEAD)"
  main_commit="$(git rev-parse refs/remotes/release-verification/main)"
  if [[ "$release_commit" != "$main_commit" ]]; then
    printf 'release commit %s must equal current main commit %s\n' \
      "$release_commit" "$main_commit" >&2
    return 1
  fi

  tag="${tag_prefix}${version}"
  if ! tag_matches="$(git ls-remote --tags "$remote" "refs/tags/$tag")"; then
    printf 'failed to query release tag %s from remote %s\n' "$tag" "$remote" >&2
    return 1
  fi
  if [[ -n "$tag_matches" ]]; then
    printf 'release tag already exists: %s\n' "$tag" >&2
    return 1
  fi

  printf 'verified %s release %s at %s\n' "$component" "$version" "$release_commit" >&2
  printf '%s\n' "$version"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
