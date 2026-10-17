#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 1 ]]; then
  echo 'Usage: test-image.sh LOCAL_IMAGE_REF' >&2
  exit 2
fi
source_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
docker run --rm --platform linux/amd64 --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges --user 19999:19999 \
  --cpus 2 --memory 3g --shm-size 256m \
  --tmpfs /tmp:rw,nosuid,nodev,size=768m,uid=19999,gid=19999 \
  --tmpfs /var/lib/postgresql:rw,nosuid,nodev,size=16m,uid=19999,gid=19999 \
  --mount "type=bind,source=${source_dir}/patroni.example.yaml,target=/tests/patroni.yaml,readonly" \
  --entrypoint /opt/patroni/bin/python "$1" /opt/infra/image-smoke.py /tests/patroni.yaml
