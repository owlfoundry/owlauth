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

release_tag_prefix() {
  case "$1" in
    server) printf 'server-v\n' ;;
    cli) printf 'cli-v\n' ;;
    typescript) printf 'typescript-v\n' ;;
    python) printf 'python-v\n' ;;
    rust) printf 'rust-v\n' ;;
    *)
      printf 'usage: %s {server|cli|typescript|python|rust}\n' "$0" >&2
      return 2
      ;;
  esac
}

main() {
  local component="${1:-}"
  local tag_prefix tag version remote release_commit main_commit tag_commit remote_tag_commit
  local conflicting_tag conflicting_remote_ref shared_remote_refs

  tag_prefix="$(release_tag_prefix "$component")"
  if [[ -n "${GITHUB_REF_TYPE:-}" && "$GITHUB_REF_TYPE" != "tag" ]]; then
    printf 'release workflow requires a tag ref, got %s\n' "$GITHUB_REF_TYPE" >&2
    return 1
  fi

  tag="${GITHUB_REF_NAME:-$(git describe --tags --exact-match HEAD 2>/dev/null || true)}"
  if [[ "$tag" != "$tag_prefix"* ]]; then
    printf 'expected tag prefix %s, got %s\n' "$tag_prefix" "${tag:-<none>}" >&2
    return 1
  fi

  version="${tag#"$tag_prefix"}"
  if ! is_semver "$version"; then
    printf 'tag does not end in a valid SemVer version: %s\n' "$version" >&2
    return 1
  fi
  if [[ "$version" == "0.0.0-dev" ]]; then
    printf 'release tag uses the reserved development sentinel: %s\n' "$version" >&2
    return 1
  fi

  remote="${RELEASE_REMOTE:-origin}"
  if ! git fetch --quiet --no-tags "$remote" \
    +refs/heads/main:refs/remotes/release-verification/main; then
    printf 'failed to fetch main from release remote %s\n' "$remote" >&2
    return 1
  fi

  release_commit="$(git rev-parse HEAD^{commit})"
  main_commit="$(git rev-parse refs/remotes/release-verification/main^{commit})"
  if [[ "$release_commit" != "$main_commit" ]]; then
    printf 'release commit %s must equal current main commit %s\n' \
      "$release_commit" "$main_commit" >&2
    return 1
  fi

  if ! tag_commit="$(git rev-parse "refs/tags/$tag^{commit}" 2>/dev/null)"; then
    printf 'release tag is not available in the checkout: %s\n' "$tag" >&2
    return 1
  fi
  if [[ "$tag_commit" != "$release_commit" ]]; then
    printf 'release tag %s points at %s instead of checked-out commit %s\n' \
      "$tag" "$tag_commit" "$release_commit" >&2
    return 1
  fi

  if ! remote_tag_commit="$(
    git ls-remote --tags "$remote" "refs/tags/$tag" "refs/tags/$tag^{}" |
      awk '
        $2 ~ /\^\{\}$/ { peeled = $1 }
        $2 !~ /\^\{\}$/ { direct = $1 }
        END { print (peeled != "" ? peeled : direct) }
      '
  )"; then
    printf 'failed to query release tag %s from remote %s\n' "$tag" "$remote" >&2
    return 1
  fi
  if [[ -z "$remote_tag_commit" || "$remote_tag_commit" != "$release_commit" ]]; then
    printf 'remote release tag %s must resolve to %s, got %s\n' \
      "$tag" "$release_commit" "${remote_tag_commit:-<missing>}" >&2
    return 1
  fi

  # Server and CLI releases both materialize the public owlauth-types crate, so
  # their otherwise-independent tags form one strictly increasing sequence.
  conflicting_tag=""
  case "$component" in
    server) conflicting_tag="cli-v$version" ;;
    cli) conflicting_tag="server-v$version" ;;
  esac
  if [[ -n "$conflicting_tag" ]]; then
    if ! conflicting_remote_ref="$(
      git ls-remote --tags "$remote" \
        "refs/tags/$conflicting_tag" "refs/tags/$conflicting_tag^{}"
    )"; then
      printf 'failed to query shared owlauth-types version tag %s from remote %s\n' \
        "$conflicting_tag" "$remote" >&2
      return 1
    fi
    if [[ -n "$conflicting_remote_ref" ]]; then
      printf 'release version %s is already reserved by %s for shared owlauth-types publication\n' \
        "$version" "$conflicting_tag" >&2
      return 1
    fi
    if ! shared_remote_refs="$(
      git ls-remote --tags "$remote" 'refs/tags/server-v*' 'refs/tags/cli-v*'
    )"; then
      printf 'failed to query shared owlauth-types release sequence from remote %s\n' \
        "$remote" >&2
      return 1
    fi
    if ! printf '%s\n' "$shared_remote_refs" | \
      python3 scripts/release/verify-shared-crate-version.py \
        --version "$version" --current-tag "$tag"; then
      return 1
    fi
  fi

  printf 'verified %s release tag %s at %s\n' "$component" "$tag" "$release_commit" >&2
  printf '%s\n' "$version"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
