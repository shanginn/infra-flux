#!/bin/sh
set -eu

fail() {
  now="$(date +%s)"
  printf 'mail_backup_success 0\nmail_backup_last_attempt_timestamp_seconds %s\n' "$now" > /tmp/backup.prom
  wget -qO- --post-file=/tmp/backup.prom \
    http://mail-backup-pushgateway:9091/metrics/job/mail-hub/instance/rubase >/dev/null || true
}
trap fail EXIT

export RESTIC_PASSWORD_FILE=/backup-secrets/restic-password
export RESTIC_CACHE_DIR=/home/nonroot/.cache/restic
export AWS_ACCESS_KEY_ID
AWS_ACCESS_KEY_ID="$(cat /backup-secrets/access-key)"
export AWS_SECRET_ACCESS_KEY
AWS_SECRET_ACCESS_KEY="$(cat /backup-secrets/secret-key)"
export RESTIC_REPOSITORY
RESTIC_REPOSITORY="s3:$(cat /backup-secrets/endpoint)/$(cat /backup-secrets/bucket)"

if ! restic snapshots >/dev/null 2>&1; then
  restic init
fi

while IFS="$(printf '\t')" read -r account credential archive; do
  [ -n "$account" ] || continue
  export VANDELAY_PASSWORD
  VANDELAY_PASSWORD="$(cat "/credentials/$credential")"
  /tools/vandelay import jmap \
    --url https://mx1.shanginn.io:8443 \
    --auth-basic "$account" \
    --account-name "$account" \
    "/snapshots/$archive"
done </work/backup-targets.tsv

restic backup /snapshots --tag stalwart-vandelay --host rubase-mail-hub
restic forget --keep-daily 14 --keep-weekly 8 --keep-monthly 12 --prune
restic check --read-data-subset=5%

now="$(date +%s)"
printf 'mail_backup_success 1\nmail_backup_last_attempt_timestamp_seconds %s\nmail_backup_last_success_timestamp_seconds %s\n' "$now" "$now" > /tmp/backup.prom
wget -qO- --post-file=/tmp/backup.prom \
  http://mail-backup-pushgateway:9091/metrics/job/mail-hub/instance/rubase >/dev/null
trap - EXIT
