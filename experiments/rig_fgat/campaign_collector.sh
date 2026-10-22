#!/bin/bash
# One FGAT collector for a whole trial campaign (The Agentic Black Box, Vol 2).
#
#   campaign_collector.sh start    start the collector (UDP mirror on 127.0.0.1:9999)
#   campaign_collector.sh status   is it running; record count; sealed or not
#   campaign_collector.sh verify   verify the journal against the anchor and the store
#   campaign_collector.sh stop
#
# Layout under $CAMPAIGN (default ./campaign beside this script):
#   run/       events.sock (legacy), records.sock, blobs.sock; collector.pid, collector.log
#   evidence/  audit_journal.jsonl, operational.jsonl, rejected.jsonl, store/, store.incoming/
#
# After the first start, seal the evidence as root (store.incoming stays unsealed:
# finished blobs are renamed out of it):
#   sudo chattr +a evidence/audit_journal.jsonl evidence/operational.jsonl \
#                  evidence/rejected.jsonl evidence/store
# The operational file is the local anchor. It counts as an anchor only once a
# copy is kept off this host (e.g. a capture of the UDP mirror stored elsewhere).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CAMPAIGN="${CAMPAIGN:-$HERE/campaign}"
COLLECTOR="${COLLECTOR:-$HERE/collector/collector_daemon.py}"
[ -f "$COLLECTOR" ] || COLLECTOR="$HERE/../../collector/collector_daemon.py"
RUN="$CAMPAIGN/run"; EV="$CAMPAIGN/evidence"
PIDF="$RUN/collector.pid"

running() { [ -f "$PIDF" ] && kill -0 "$(cat "$PIDF")" 2>/dev/null; }

case "${1:-}" in
  start)
    if running; then echo "already running (pid $(cat "$PIDF"))"; exit 0; fi
    mkdir -p "$RUN" "$EV"
    nohup python3 -u "$COLLECTOR" --socket "$RUN/events.sock" \
      --worm "$EV/audit_journal.jsonl" --operational "$EV/operational.jsonl" \
      --rejects "$EV/rejected.jsonl" --store "$EV/store" \
      --udp-mirror 127.0.0.1:9999 >> "$RUN/collector.log" 2>&1 &
    echo $! > "$PIDF"
    for _ in $(seq 50); do [ -S "$RUN/records.sock" ] && break; sleep 0.1; done
    touch "$EV/rejected.jsonl"
    echo "collector pid $(cat "$PIDF"); sockets in $RUN; evidence in $EV"
    ;;
  status)
    if running; then echo "running (pid $(cat "$PIDF"))"; else echo "not running"; fi
    [ -f "$EV/audit_journal.jsonl" ] && echo "journal records: $(wc -l < "$EV/audit_journal.jsonl")"
    lsattr -d "$EV/audit_journal.jsonl" "$EV/operational.jsonl" "$EV/rejected.jsonl" "$EV/store" 2>/dev/null || true
    ;;
  verify)
    python3 "$COLLECTOR" --verify --worm "$EV/audit_journal.jsonl" \
      --anchor "$EV/operational.jsonl" --store "$EV/store"
    ;;
  stop)
    if running; then kill "$(cat "$PIDF")"; rm -f "$PIDF"; echo stopped; else echo "not running"; fi
    ;;
  *) echo "usage: $0 start|status|verify|stop"; exit 2 ;;
esac
