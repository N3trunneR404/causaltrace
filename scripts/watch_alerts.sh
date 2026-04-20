#!/usr/bin/env bash
# scripts/watch_alerts.sh — live tail of results/marathon/verdicts.jsonl with colour.
# Run in a second terminal while attacking.
set -euo pipefail

FILE="${1:-$HOME/causaltrace/results/marathon/verdicts.jsonl}"

if [[ ! -e "$FILE" ]]; then
  echo "waiting for $FILE ..." >&2
  while [[ ! -e "$FILE" ]]; do sleep 1; done
fi

echo "══════════════════════════════════════════════"
echo "  CausalTrace Live Alert Monitor — $FILE"
echo "══════════════════════════════════════════════"

tail -n 0 -F "$FILE" | python3 -u -c '
import sys, json, time
RED = "\033[91m"; YEL = "\033[93m"; GRN = "\033[92m"; DIM = "\033[2m"; RST = "\033[0m"
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try: v = json.loads(line)
    except Exception:
        print(DIM + line + RST); continue
    ts     = v.get("timestamp", v.get("ts", time.time()))
    action = v.get("action", "?")
    label  = v.get("label", v.get("kind", "?"))
    cgs    = v.get("affected_cgroups", [v.get("cgroup","?")])
    reason = v.get("reason", "")
    rq     = v.get("rayleigh", None)
    gt     = v.get("global_threshold", None)
    color  = RED if action in ("KILL","BLOCK") else (YEL if action=="MONITOR" else GRN)
    extra  = f" rq={rq:.3f}/{gt:.3f}" if isinstance(rq,(int,float)) and isinstance(gt,(int,float)) else ""
    print(f"{color}[{ts}] {action:7s} {label:28s} cg={cgs}{extra}{RST}  {DIM}{reason}{RST}")
    sys.stdout.flush()
'
