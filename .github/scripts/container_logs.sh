#!/usr/bin/env bash
# Keep and collect the logs of the production containers for the daily error report
# (see .github/workflows/daily-error-report.yml).
#
#   container_logs.sh archive
#       Save the full log of every container to $CONTAINER_LOG_ARCHIVE_DIR before a deploy.
#       A deploy recreates the containers and docker drops their logs with them, so without
#       this the next report could not see errors that happened before the deploy.
#       Archives older than 14 days are deleted.
#
#   container_logs.sh collect <output dir> <since, RFC3339>
#       Write every log line after <since> (live containers plus the archives of containers
#       that were replaced) to <output dir>/logs/<service>__<first 12 chars of the id>.log
#       (each line starts with docker's UTC timestamp) and the `docker inspect` output to
#       <output dir>/containers.json.
#
# Containers are found through the compose project name (default: the current directory
# name in lower case, the same rule docker compose uses). Override with COMPOSE_PROJECT_NAME.
set -euo pipefail

PROJECT="${COMPOSE_PROJECT_NAME:-$(basename "$PWD" | tr '[:upper:]' '[:lower:]')}"
ARCHIVE="${CONTAINER_LOG_ARCHIVE_DIR:-$HOME/container-logs/$PROJECT}"

containers() {
  docker ps -a --filter "label=com.docker.compose.project=$PROJECT" --format '{{.ID}}'
}

# <service>__<id12>.log
log_name() {
  local svc
  svc=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.service"}}' "$1")
  echo "${svc:-unknown}__${1:0:12}.log"
}

case "${1:-}" in
  archive)
    mkdir -p "$ARCHIVE"
    for id in $(containers); do
      docker logs --timestamps "$id" > "$ARCHIVE/$(log_name "$id")" 2>&1 || true
    done
    find "$ARCHIVE" -name '*.log' -mtime +14 -delete
    echo "archived the logs of $(containers | wc -l) container(s) to $ARCHIVE"
    ;;
  collect)
    out="$2"
    since="$3"
    mkdir -p "$out/logs"
    ids=$(containers)
    for id in $ids; do
      docker logs --timestamps --since "$since" "$id" > "$out/logs/$(log_name "$id")" 2>&1 || true
    done
    # Replaced containers only exist in the archive; for live ones the fresh log above wins.
    if [ -d "$ARCHIVE" ]; then
      for f in "$ARCHIVE"/*.log; do
        [ -e "$f" ] || continue
        [ -e "$out/logs/$(basename "$f")" ] || cp "$f" "$out/logs/"
      done
    fi
    if [ -n "$ids" ]; then
      # shellcheck disable=SC2086
      docker inspect $ids > "$out/containers.json"
    else
      echo '[]' > "$out/containers.json"
    fi
    echo "compose project=$PROJECT: collected $(find "$out/logs" -name '*.log' | wc -l) log file(s)"
    ;;
  *)
    echo "usage: $0 archive | collect <output dir> <since>" >&2
    exit 2
    ;;
esac
