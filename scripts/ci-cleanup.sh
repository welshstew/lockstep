#!/usr/bin/env bash
# CI only (GNU date): removes what cancelled runs left behind. A cancelled job can skip its
# `if: always()` tear-down, leaving a whole compose project running (containers, volumes,
# networks). This removes every lockstep-* compose project whose newest object is more than
# MAX_AGE_HOURS old (default 2), never the current run's ($COMPOSE_PROJECT_NAME), and then
# lockstep images nothing uses any more: the per-run images from before compose.ci.yaml named
# them, and the untagged ones each rebuild leaves behind.
#   MAX_AGE_HOURS=2 DRY_RUN=1 scripts/ci-cleanup.sh
set -uo pipefail
max=${MAX_AGE_HOURS:-2}
cutoff=$(( $(date +%s) - max * 3600 ))
PROJECTS='^lockstep-(ci|tests|openbao|vault-release)-'
run() { if [[ -n ${DRY_RUN:-} ]]; then echo "would run: $*"; else "$@" >/dev/null 2>&1 || true; fi; }
label() { echo "label=com.docker.compose.project=$1"; }
epoch() { date -d "$1" +%s 2>/dev/null || echo 0; }

projects=$( {
  docker ps -a --filter label=com.docker.compose.project --format '{{.Label "com.docker.compose.project"}}'
  docker volume ls --filter label=com.docker.compose.project --format '{{.Label "com.docker.compose.project"}}'
  docker network ls --filter label=com.docker.compose.project --format '{{.Label "com.docker.compose.project"}}'
} | grep -E "$PROJECTS" | sort -u)

for p in $projects; do
  [[ $p == "${COMPOSE_PROJECT_NAME:-}" ]] && continue
  newest=0
  for id in $(docker ps -aq --filter "$(label "$p")"); do
    t=$(epoch "$(docker inspect -f '{{.Created}}' "$id")"); (( t > newest )) && newest=$t
  done
  for id in $(docker volume ls -q --filter "$(label "$p")"); do
    t=$(epoch "$(docker volume inspect -f '{{.CreatedAt}}' "$id")"); (( t > newest )) && newest=$t
  done
  for id in $(docker network ls -q --filter "$(label "$p")"); do
    t=$(epoch "$(docker network inspect -f '{{.Created}}' "$id")"); (( t > newest )) && newest=$t
  done
  (( newest > cutoff )) && { echo "keeping $p (in use within ${max}h)"; continue; }
  echo "removing $p (left behind)"
  ids=$(docker ps -aq --filter "$(label "$p")"); [[ -n $ids ]] && run docker rm -f $ids
  ids=$(docker volume ls -q --filter "$(label "$p")"); [[ -n $ids ]] && run docker volume rm -f $ids
  ids=$(docker network ls -q --filter "$(label "$p")"); [[ -n $ids ]] && run docker network rm $ids
done

# Images: `docker rmi` without -f refuses one a container still uses, so a running job is safe.
old=$(docker images --format '{{.Repository}}:{{.Tag}}' | grep -E "${PROJECTS}[0-9]" || true)
dangling=$(docker images --filter dangling=true --filter label=com.docker.compose.project \
  --format '{{.ID}} {{.Label "com.docker.compose.project"}}' | awk '$2 ~ /^lockstep-/ {print $1}')
n=$(printf '%s\n' $old $dangling | grep -c . || true)
echo "removing $n unused lockstep image(s)"
for i in $old $dangling; do run docker rmi "$i"; done
exit 0
