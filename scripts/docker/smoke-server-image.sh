#!/usr/bin/env bash
set -euo pipefail

image="${1:?usage: $0 IMAGE}"
container="owlauth-smoke-${RANDOM}-$$"

cleanup() {
  docker rm --force "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker run --detach --name "$container" "$image" >/dev/null

if [[ "$(docker exec "$container" sh -c 'cat /proc/1/comm')" != "tini" ]]; then
  printf 'server image must run under tini as PID 1: %s\n' "$image" >&2
  docker logs "$container" >&2
  exit 1
fi

license_path=/usr/share/licenses/owlauth/LICENSE
if ! docker exec "$container" grep -q "BSD 3-Clause License" "$license_path"; then
  printf 'server image must include the OwlAuth BSD license: %s\n' "$image" >&2
  exit 1
fi

for _ in {1..30}; do
  if docker exec "$container" \
    curl --fail --silent --show-error http://127.0.0.1:8080/health >/dev/null 2>&1; then
    printf 'server image health check passed: %s\n' "$image"
    exit 0
  fi
  sleep 1
done

printf 'server image did not become healthy: %s\n' "$image" >&2
docker logs "$container" >&2
exit 1
