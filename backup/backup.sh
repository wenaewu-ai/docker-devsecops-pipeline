#!/bin/sh
# Daily PostgreSQL backup with verification and retention.
#
#   backup.sh            take one backup now
#   backup.sh --daemon   run forever, one backup per day at BACKUP_TIME (container time zone, TZ)
#
# pg_dump takes a consistent snapshot without blocking readers or writers, so it is safe to
# run against a live database. Every dump is written to a temporary name, read back in full
# with pg_restore (which decodes every table's data without restoring anything), and only
# then renamed. A file named *.dump is therefore always a complete, readable backup.
#
# Connection settings come from the standard PG* variables (PGHOST, PGUSER, PGPASSWORD,
# PGDATABASE). Log lines are parsed by the daily error report: keep the
# "backup completed" / "backup failed" prefixes.
set -u
umask 077 # dumps contain the whole database: readable by the owner only

BACKUP_TIME="${BACKUP_TIME:-22:00}"
BACKUP_DIR="${BACKUP_DIR:-/backups}"
BACKUP_RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"

log() {
  echo "[backup $(date '+%Y-%m-%d %H:%M:%S')] $*"
}

one_line() {
  printf '%s' "$1" | tr '\n' ' '
}

run_backup() {
  mkdir -p "$BACKUP_DIR"
  file="$BACKUP_DIR/${PGDATABASE}_$(date +%Y%m%d_%H%M%S).dump"
  tmp="$file.partial"
  log "starting backup of ${PGDATABASE} -> ${file}"

  if ! err=$(pg_dump --format=custom --file="$tmp" 2>&1); then
    rm -f "$tmp"
    log "backup failed: $(one_line "$err")"
    return 1
  fi
  if ! err=$(pg_restore --file=/dev/null "$tmp" 2>&1); then
    rm -f "$tmp"
    log "backup failed: verification could not read the dump: $(one_line "$err")"
    return 1
  fi
  mv "$tmp" "$file"
  log "backup completed and verified: ${file} ($(du -h "$file" | cut -f1))"

  if [ "$BACKUP_RETENTION_DAYS" -gt 0 ]; then
    old=$(find "$BACKUP_DIR" -name "${PGDATABASE}_*.dump" -mtime "+${BACKUP_RETENTION_DAYS}" | wc -l)
    if [ "$old" -gt 0 ]; then
      find "$BACKUP_DIR" -name "${PGDATABASE}_*.dump" -mtime "+${BACKUP_RETENTION_DAYS}" -delete
      log "removed ${old} backup(s) older than ${BACKUP_RETENTION_DAYS} days"
    fi
  fi
  # A dump interrupted by a restart leaves a .partial file behind; clear day-old leftovers.
  find "$BACKUP_DIR" -name '*.partial' -mtime +1 -delete
}

case "${1:-}" in
  --daemon)
    log "scheduler started: daily at ${BACKUP_TIME} (${TZ:-UTC}) for ${PGDATABASE}, keeping ${BACKUP_RETENTION_DAYS} days"
    last_run=""
    while true; do
      today=$(date +%F)
      if [ "$(date +%H:%M)" = "$BACKUP_TIME" ] && [ "$last_run" != "$today" ]; then
        last_run="$today"
        run_backup || true # keep the scheduler alive; the daily report flags the failure
      fi
      sleep 20
    done
    ;;
  *)
    run_backup
    ;;
esac
