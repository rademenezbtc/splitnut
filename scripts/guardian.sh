#!/usr/bin/env bash
# Stop or start one guardian of a running demo (scripts/demo.sh).
#   ./scripts/guardian.sh stop 3
#   ./scripts/guardian.sh start 3
#   ./scripts/guardian.sh status
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
W="${DEMO_DIR:-$ROOT/.demo}"
cmd="${1:-status}"; i="${2:-}"

alive() { [ -f "$W/pids/guardian-$1.pid" ] && kill -0 "$(cat "$W/pids/guardian-$1.pid")" 2>/dev/null; }

case "$cmd" in
  stop)
    [ -n "$i" ] || { echo "usage: $0 stop N"; exit 1; }
    if alive "$i"; then kill "$(cat "$W/pids/guardian-$i.pid")"; rm -f "$W/pids/guardian-$i.pid"; echo "guardian $i stopped"
    else echo "guardian $i is not running"; fi ;;
  start)
    [ -n "$i" ] || { echo "usage: $0 start N"; exit 1; }
    [ -f "$W/guardian-$i.cmd" ] || { echo "no demo state for guardian $i (run scripts/demo.sh first)"; exit 1; }
    if alive "$i"; then echo "guardian $i is already running"; exit 0; fi
    nohup bash -c "exec $(cat "$W/guardian-$i.cmd")" >> "$W/logs/guardian-$i.log" 2>&1 &
    echo $! > "$W/pids/guardian-$i.pid"
    echo "guardian $i started (it resumes the group from its encrypted state)" ;;
  status)
    for f in "$W"/guardian-*.cmd; do
      [ -f "$f" ] || continue
      n=$(basename "$f" .cmd); n=${n#guardian-}
      if alive "$n"; then echo "guardian $n: running"; else echo "guardian $n: stopped"; fi
    done ;;
  *) echo "usage: $0 stop N | start N | status"; exit 1 ;;
esac
