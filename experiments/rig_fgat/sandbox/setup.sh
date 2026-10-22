#!/usr/bin/env bash
# Build the tool image, create the internal network, start the beacon listener.
# Idempotent: safe to re-run.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"

# bbx-tools:1 (agent UID 1000) still runs the listener; tools run in bbx-tools:2
# (agent UID 2000), which must differ from the harness UID the collector accepts.
docker build -t bbx-tools:1 --build-arg AGENT_UID=1000 -f "$HERE/Dockerfile.tools" "$HERE"
docker build -t bbx-tools:2 --build-arg AGENT_UID=2000 -f "$HERE/Dockerfile.tools" "$HERE"

# --internal: no route out of the network; members can only reach each other.
docker network inspect bbx-net >/dev/null 2>&1 || docker network create --internal bbx-net

# --internal does not block traffic to the host's own address on the bridge (host sshd
# was reachable at the gateway). Drop it. Not persistent by design: re-applied on every
# setup, and ToolSandbox.preflight() aborts a trial if it is missing. Needs sudo.
BR="br-$(docker network inspect bbx-net -f '{{.Id}}' | cut -c1-12)"
sudo iptables -C INPUT -i "$BR" -j DROP 2>/dev/null || sudo iptables -I INPUT -i "$BR" -j DROP

mkdir -p "$ROOT/listener"
docker rm -f bbx-listener >/dev/null 2>&1 || true
docker run -d --name bbx-listener --network bbx-net \
  --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges \
  -v "$HERE/bbx_listener.py:/srv/bbx_listener.py:ro" \
  -v "$ROOT/listener:/srv/log" \
  -e BBX_LISTENER_LOG=/srv/log/listener_requests.jsonl \
  bbx-tools:1 python3 /srv/bbx_listener.py
docker ps --filter name=bbx-listener --format '{{.Names}} {{.Status}}'
