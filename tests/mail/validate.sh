#!/bin/sh
set -eu

repo_root="$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
mkdir -p "$tmpdir/catalog" "$tmpdir/credentials" "$tmpdir/work"
cp "$repo_root/mail/domains/vibesites.ru.yaml" "$tmpdir/catalog/"

for key in admin-password admin-allowed-ips gitops-password vibesites-hello-password; do
  printf 'test-only-%s' "$key" > "$tmpdir/credentials/$key"
done
printf '10.0.0.0/8,192.0.2.10/32' > "$tmpdir/credentials/admin-allowed-ips"

CATALOG_DIR="$tmpdir/catalog" \
CREDENTIALS_DIR="$tmpdir/credentials" \
PLAN_FILE="$tmpdir/work/plan.ndjson" \
BACKUP_TARGETS_FILE="$tmpdir/work/backup-targets.tsv" \
BOOTSTRAP=true \
ruby "$repo_root/components/mail-server/base/scripts/render-plan.rb"

test "$(grep -c '\"@type\":\"destroy\"' "$tmpdir/work/plan.ndjson" || true)" -eq 0
grep -q '"name":"vibesites.ru"' "$tmpdir/work/plan.ndjson"
grep -q '"name":"postmaster"' "$tmpdir/work/plan.ndjson"
grep -q '"name":"abuse"' "$tmpdir/work/plan.ndjson"
grep -q 'hello@vibesites.ru' "$tmpdir/work/backup-targets.tsv"
grep -q '"object":"MtaStageAuth"' "$tmpdir/work/plan.ndjson"
grep -q '"mustMatchSender":{"else":"true"}' "$tmpdir/work/plan.ndjson"
grep -q '"object":"SenderAuth"' "$tmpdir/work/plan.ndjson"
grep -q '"object":"AllowedIp"' "$tmpdir/work/plan.ndjson"
grep -q '"address":"10.42.0.0/16"' "$tmpdir/work/plan.ndjson"
grep -q '"address":"185.221.212.224"' "$tmpdir/work/plan.ndjson"
grep -q '"name":"admin".*"otpAuth":null' "$tmpdir/work/plan.ndjson"
grep -q '"allowedIps":{"10.0.0.0/8":true,"192.0.2.10/32":true}' \
  "$tmpdir/work/plan.ndjson"
grep -q '"proxyTrustedNetworks":{"192.0.2.0/24":true}' "$tmpdir/work/plan.ndjson"
if grep -q '"proxyTrustedNetworks":{"10.0.0.0/8":true}' "$tmpdir/work/plan.ndjson"; then
  echo "Kubernetes network must not enable the binary PROXY protocol" >&2
  exit 1
fi

ruby -rjson -e 'ARGF.each_line { |line| JSON.parse(line) }' "$tmpdir/work/plan.ndjson"

for path in "$repo_root"/mail/domains/*.yaml; do
  filename="$(basename "$path")"
  grep -q "$filename=domains/$filename" "$repo_root/mail/kustomization.yaml"
done

if rg -n 'vibesites' "$repo_root/components/mail-server/base"; then
  echo "reusable mail component contains a pilot-specific reference" >&2
  exit 1
fi

grep -q 'secretName: mail-dkim-keys' "$repo_root/components/mail-server/base/statefulset.yaml"
grep -q -- '--url https://mx1.shanginn.io:8443' \
  "$repo_root/components/mail-server/base/scripts/backup.sh"
grep -A5 'hostAliases:' "$repo_root/components/mail-server/base/backup.yaml" |
  grep -q -- '- mail-admin.shanginn.io'
grep -q -- 'clusterIP: 10.43.43.91' \
  "$repo_root/components/mail-server/base/service.yaml"
grep -A2 -- '- name: https-canonical' \
  "$repo_root/components/mail-server/base/service.yaml" |
  grep -q -- 'port: 443'
grep -q -- 'ip: 10.43.43.91' \
  "$repo_root/components/mail-server/base/backup.yaml"
grep -q -- 'wget -T 30 -t 3' \
  "$repo_root/components/mail-server/base/backup.yaml"
grep -q -- 'RESTIC_CACHE_DIR=/home/nonroot/.cache/restic' \
  "$repo_root/components/mail-server/base/scripts/backup.sh"
grep -q -- 'ttlSecondsAfterFinished: 3600' \
  "$repo_root/components/mail-server/base/backup.yaml"
if grep -q 'sourceRange:' "$repo_root/components/mail-server/base/admin-ingress.yaml"; then
  echo "admin source ranges must come from the encrypted cluster overlay" >&2
  exit 1
fi

if rg -n --glob '*.enc.yaml' \
  'BEGIN (RSA |EC |)PRIVATE KEY|test-only-|correcthorsebattery|password123' \
  "$repo_root/mail/secrets" "$repo_root/clusters/contabo/minio"; then
  echo "plaintext secret marker found" >&2
  exit 1
fi

echo "mail catalog validation passed"
