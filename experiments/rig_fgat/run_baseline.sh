#!/bin/bash
# Lab checklist step 6: uninstrumented V2-A baseline sessions (Part 1 evidence).
# Preflight before every session; stops at the first preflight failure.
#   ./run_baseline.sh [N=5] [OUT=baseline]
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
N="${1:-5}"; OUT="${2:-$HERE/baseline}"
RIG="${RIG:-$HOME/code/rig-harness-eval/rig.py}"
export RIG_BASE_URL="${RIG_BASE_URL:-http://localhost:11434/v1}" RIG_MODEL="${RIG_MODEL:-qwen3.8:27b}"
mkdir -p "$OUT/runs" "$OUT/preflight"
for i in $(seq "$N"); do
  echo "=== baseline session $i/$N $(date -u +%FT%TZ)"
  python3 "$HERE/preflight.py" --rig "$RIG" --out "$OUT/preflight" > "$OUT/preflight/last.txt" && tail -1 "$OUT/preflight/last.txt" || { tail -12 "$OUT/preflight/last.txt"; echo "preflight failed; stopping"; exit 1; }
  python3 "$HERE/fgat_rig_trial.py" --variant V2 --gate A --rig "$RIG" --uninstrumented --out "$OUT/runs" \
    > "$OUT/runs/session-$i.log" 2>&1
  tail -8 "$OUT/runs/session-$i.log"
done
