#!/usr/bin/env bash
set -euo pipefail

image="${1:?usage: $0 IMAGE}"
suffix="${RANDOM}-$$"
network="owlauth-smoke-${suffix}"
database_container="owlauth-smoke-postgres-${suffix}"
server_container="owlauth-smoke-server-${suffix}"
postgres_image="${OWLAUTH_SMOKE_POSTGRES_IMAGE:-postgres:17-bookworm}"

# shellcheck disable=SC2317
cleanup() {
  docker rm --force "$server_container" "$database_container" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
}
trap cleanup EXIT

for attempt in 1 2 3; do
  if docker pull "$postgres_image" >/dev/null; then
    break
  fi
  if [[ "$attempt" == 3 ]]; then
    printf 'failed to pull smoke-test PostgreSQL image after %s attempts: %s\n' "$attempt" "$postgres_image" >&2
    exit 1
  fi
  sleep "$((attempt * 2))"
done

docker network create "$network" >/dev/null
docker run --detach \
  --name "$database_container" \
  --network "$network" \
  --network-alias postgres \
  --env POSTGRES_DB=owlauth \
  --env POSTGRES_USER=owlauth \
  --env POSTGRES_PASSWORD=owlauth_smoke \
  "$postgres_image" >/dev/null

for _ in {1..60}; do
  if docker exec "$database_container" pg_isready --username owlauth --dbname owlauth >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
if ! docker exec "$database_container" pg_isready --username owlauth --dbname owlauth >/dev/null 2>&1; then
  printf 'smoke-test PostgreSQL did not become ready\n' >&2
  docker logs "$database_container" >&2
  exit 1
fi

docker run --detach \
  --name "$server_container" \
  --network "$network" \
  --env OWLAUTH_INSTANCE_ID=smoke-deployment \
  --env OWLAUTH_POSTGRES_URL=postgresql://owlauth:owlauth_smoke@postgres:5432/owlauth \
  --env OWLAUTH_RUNTIME_PROCESS_ID=smoke-runtime \
  "$image" >/dev/null

pid_one=""
for _ in {1..30}; do
  if pid_one="$(docker exec "$server_container" sh -c 'cat /proc/1/comm' 2>/dev/null)"; then
    break
  fi
  sleep 1
done
if [[ "$pid_one" != "tini" ]]; then
  printf 'server image must run under tini as PID 1: %s\n' "$image" >&2
  docker inspect "$server_container" >&2 || true
  docker logs "$server_container" >&2
  exit 1
fi

license_path=/usr/share/licenses/owlauth/LICENSE
if ! docker exec "$server_container" grep -q "BSD 3-Clause License" "$license_path"; then
  printf 'server image must include the OwlAuth BSD license: %s\n' "$image" >&2
  exit 1
fi

for command in node npm pnpm; do
  if docker exec "$server_container" sh -c "command -v $command" >/dev/null 2>&1; then
    printf 'runtime image must not contain build tool %s: %s\n' "$command" "$image" >&2
    exit 1
  fi
done
if docker exec "$server_container" test -e /workspace; then
  printf 'runtime image must not contain the build workspace: %s\n' "$image" >&2
  exit 1
fi

for _ in {1..60}; do
  if [[ "$(docker inspect --format '{{.State.Running}}' "$server_container")" != "true" ]]; then
    break
  fi
  if docker exec "$server_container" \
    curl --fail --silent --show-error http://127.0.0.1:8080/health >/dev/null 2>&1 \
    && docker exec "$server_container" \
      curl --fail --silent --show-error http://127.0.0.1:8080/ready >/dev/null 2>&1; then
    printf 'server image health and readiness checks passed: %s\n' "$image"
    exit 0
  fi
  sleep 1
done

printf 'server image did not become ready: %s\n' "$image" >&2
docker logs "$server_container" >&2
exit 1
