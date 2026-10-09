#!/usr/bin/env bash
# Build the tool image, create the internal network, start the beacon listener.
# Idempotent: safe to re-run.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"

docker build -t bbx-tools:1 -f "$HERE/Dockerfile.tools" "$HERE"

# --internal: no route out of the network; members can only reach each other.
docker network inspect bbx-net >/dev/null 2>&1 || docker network create --internal bbx-net

mkdir -p "$ROOT/listener"
docker rm -f bbx-listener >/dev/null 2>&1 || true
docker run -d --name bbx-listener --network bbx-net \
  --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges \
  -v "$HERE/bbx_listener.py:/srv/bbx_listener.py:ro" \
  -v "$ROOT/listener:/srv/log" \
  -e BBX_LISTENER_LOG=/srv/log/listener_requests.jsonl \
  bbx-tools:1 python3 /srv/bbx_listener.py
docker ps --filter name=bbx-listener --format '{{.Names}} {{.Status}}'
