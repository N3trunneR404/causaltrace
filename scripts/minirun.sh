#!/bin/bash
# scripts/minirun.sh — bounded smoke test, beefed up for verifiable CI numbers.
#
# Goal: in ≤ 10 min produce a detection-rate estimate per scenario with
# a Wilson 95% CI narrow enough to fail a regression that drops any
# scenario's detection rate below 80%. With n=10 injections per
# scenario and 5 scenarios = 50 injections total, the CI half-width at
# p=1.0 is ~0.31 — wide for paper use, but narrow enough to catch a
# regression that goes 10/10 → 5/10.
#
# Budget (total ≤ 600 s):
#   00–15 s   preflight + compose
#   15–40 s   launch loader (monitor mode — do not mutate trust)
#   40–80 s   warmup (≥6 pristine cycles for guarded EMA)
#   80–550s   5 scenarios × 10 injections (~50 total)
#  550–585 s  cooldown
#  585–600 s  aggregate + emit summary.json
#
# Scenarios: {2, 4, 7, 10, 11}. One per detection path:
#   2  dup2 invariant (Tier 1)
#   4  fork acceleration (Tier 1)
#   7  cross-container lateral (Tier 2 novel edge + Tier 3 sheaf)
#   10 rare-syscall invariants (Tier 1)
#   11 memfd fileless OOD (Tier 1 + Tier 3)
#
# Exit codes:
#   0  all 5 scenarios have detection rate ≥ 0.8 with lower CI > 0.5
#   1  preflight failed
#   2  loader died
#   3  one or more scenarios below the threshold

set -u

START_TS=$(date +%s)
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

RESULTS_DIR="${REPO_ROOT}/results/minirun"
mkdir -p "$RESULTS_DIR"
MINIRUN_LOG="${RESULTS_DIR}/minirun.log"
LOADER_LOG="${RESULTS_DIR}/loader.log"
SUMMARY_JSON="${RESULTS_DIR}/summary.json"
VERDICTS_SRC="${REPO_ROOT}/results/causaltrace/verdicts.jsonl"
VERDICTS_COPY="${RESULTS_DIR}/verdicts.jsonl"
INJECTIONS_LOG="${RESULTS_DIR}/injections.ndjson"
SCENARIO_TAG=/tmp/causaltrace_current_scenario

SCENARIOS=(2 4 7 10 11)
N_INJECTIONS=10
DETECT_WINDOW_S=8
MIN_PASS_RATE=0.8
MIN_PASS_CI_LOW=0.5

exec > >(tee -a "$MINIRUN_LOG") 2>&1
say() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }

[ "$(id -u)" -eq 0 ] || { say "FAIL: minirun must run as root"; exit 1; }

LOADER_PID=""
cleanup() {
    if [ -n "$LOADER_PID" ] && kill -0 "$LOADER_PID" 2>/dev/null; then
        kill -TERM "$LOADER_PID" 2>/dev/null
        for _ in 1 2 3 4 5 6 7 8; do
            kill -0 "$LOADER_PID" 2>/dev/null || break
            sleep 0.5
        done
        kill -0 "$LOADER_PID" 2>/dev/null && kill -KILL "$LOADER_PID" 2>/dev/null
    fi
    echo "0" > "$SCENARIO_TAG" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

say "minirun starting (budget 10 min; 5×${N_INJECTIONS} = 50 injections)"

# Stage 1: preflight.
say "STAGE 1/6: preflight + docker compose"
if ! bash "${REPO_ROOT}/scripts/preflight.sh"; then
    say "preflight FAILED"; exit 1
fi
docker compose up -d >/dev/null 2>&1 || true
bash "${REPO_ROOT}/scripts/test_connectivity.sh" >/dev/null 2>&1 || true

# Reset verdict log so only this run's data is measured.
mkdir -p "$(dirname "$VERDICTS_SRC")"
: > "$VERDICTS_SRC"

# Stage 2: launch loader in monitor mode. Monitor intentionally — we
# don't want SIGKILLs or trust mutations leaking out of CI.
say "STAGE 2/6: launching loader (monitor mode)"
(cd "$REPO_ROOT"; exec python3 loader.py --mode monitor) \
    >"$LOADER_LOG" 2>&1 &
LOADER_PID=$!

ATTACHED=0
for _ in $(seq 1 50); do
    sleep 0.5
    if ! kill -0 "$LOADER_PID" 2>/dev/null; then
        say "loader died during startup — see $LOADER_LOG"; exit 2
    fi
    if grep -qi "attached\|detection interval\|Tier 3 running" "$LOADER_LOG" 2>/dev/null; then
        ATTACHED=1; break
    fi
done
[ "$ATTACHED" -eq 1 ] && say "loader attached" || say "loader attach sentinel not seen — continuing"

# Stage 3: warmup — 30 s of traffic so the guarded EMA clears its 30 s
# pristine-streak threshold before attacks start.
say "STAGE 3/6: warmup (40 s; guarded EMA needs ≥6 pristine cycles)"
WARMUP_END=$(( $(date +%s) + 40 ))
while [ "$(date +%s)" -lt "$WARMUP_END" ]; do
    for c in ct-web ct-api ct-db; do
        docker exec "$c" sh -c 'uptime >/dev/null; echo >/dev/null' 2>/dev/null || true
    done
    sleep 1
done

# Stage 4: attack sweep with per-injection logging.
say "STAGE 4/6: attack sweep (5 scenarios × ${N_INJECTIONS} injections)"
: > "$INJECTIONS_LOG"
for sid in "${SCENARIOS[@]}"; do
    script=$(ls "${REPO_ROOT}/attacks/scenario_${sid}_"*.sh 2>/dev/null | head -1)
    [ -z "$script" ] && { say "  s${sid} missing — skipping"; continue; }
    for n in $(seq 1 "$N_INJECTIONS"); do
        t_inject=$(python3 -c 'import time; print(time.time())')
        echo "$sid" > "$SCENARIO_TAG"
        bash "$script" >/dev/null 2>&1 || true
        python3 - "$sid" "$n" "$t_inject" <<'PY' >> "$INJECTIONS_LOG"
import json, sys
print(json.dumps({"scenario": int(sys.argv[1]), "injection_n": int(sys.argv[2]),
                  "t_inject": float(sys.argv[3])}))
PY
        sleep "$DETECT_WINDOW_S"
        echo "0" > "$SCENARIO_TAG"
    done
    say "  s${sid}: ${N_INJECTIONS} injections done"
done

# Stage 5: cooldown + snapshot.
say "STAGE 5/6: cooldown (30 s)"
sleep 30
cp -f "$VERDICTS_SRC" "$VERDICTS_COPY" 2>/dev/null || : > "$VERDICTS_COPY"

# Stage 6: aggregate. Use the marathon analyzer's Wilson CI logic.
say "STAGE 6/6: aggregating with Wilson 95% CIs"
python3 - "$VERDICTS_COPY" "$INJECTIONS_LOG" "$SUMMARY_JSON" \
          "${SCENARIOS[*]}" "$N_INJECTIONS" \
          "$MIN_PASS_RATE" "$MIN_PASS_CI_LOW" <<'PY'
import json, math, os, statistics, sys
verdicts_p, inj_p, out_p, sids_s, n_inj, min_rate, min_ci = sys.argv[1:]
sids     = [int(x) for x in sids_s.split()]
n_inj    = int(n_inj)
min_rate = float(min_rate)
min_ci   = float(min_ci)

NEEDLES = {2:"fd_redirect", 4:"fork_bomb", 7:"two_hop",
           10:"escape", 11:"fileless"}
DETECT_WINDOW = 10.0

def wilson(k, n, z=1.959963984540054):
    if n <= 0: return (0.0, 0.0)
    p = k/n
    denom  = 1 + z*z/n
    centre = (p + z*z/(2*n)) / denom
    half   = (z*math.sqrt(p*(1-p)/n + z*z/(4*n*n))) / denom
    return (max(0.0, centre-half), min(1.0, centre+half))

def load(p):
    if not os.path.exists(p): return []
    out = []
    with open(p) as f:
        for ln in f:
            ln = ln.strip()
            if not ln: continue
            try: out.append(json.loads(ln))
            except: pass
    return out

def ts(v):
    for k in ("timestamp","ts","time"):
        if isinstance(v.get(k),(int,float)): return float(v[k])
    return None

def matches(v, sid):
    ndl = NEEDLES.get(sid);
    if ndl is None: return False
    if v.get("action") == "ALLOW": return False
    hay = ((v.get("label") or "") + " " + (v.get("reason") or "")).lower()
    return ndl in hay

verdicts   = load(verdicts_p)
injections = load(inj_p)
ts_vs = [(v, ts(v)) for v in verdicts]
ts_vs = [(v,t) for v,t in ts_vs if t is not None]

per = {}
for inj in injections:
    sid = int(inj["scenario"]); t0 = float(inj["t_inject"])
    d = per.setdefault(sid, {"injections": 0, "hits": 0, "ttks": []})
    d["injections"] += 1
    for v,t in ts_vs:
        if t < t0 or t > t0 + DETECT_WINDOW: continue
        if matches(v, sid):
            d["hits"] += 1; d["ttks"].append(t - t0); break

rows = []; pass_count = 0
for sid in sids:
    d = per.get(sid, {"injections": 0, "hits": 0, "ttks": []})
    n, h = d["injections"], d["hits"]
    rate = h/n if n else 0.0
    lo, hi = wilson(h, n)
    p = (rate >= min_rate) and (lo >= min_ci)
    if p: pass_count += 1
    rows.append({"scenario": sid, "injections": n, "hits": h,
                 "rate": rate, "ci_low": lo, "ci_high": hi, "pass": p,
                 "ttk_p50": statistics.median(d["ttks"]) if d["ttks"] else None,
                 "ttk_p95": sorted(d["ttks"])[int(0.95*(len(d["ttks"])-1))] if d["ttks"] else None})

summary = {"total_scenarios": len(sids), "passed": pass_count,
           "failed": len(sids) - pass_count,
           "min_pass_rate": min_rate, "min_pass_ci_low": min_ci,
           "by_scenario": rows,
           "total_verdicts_logged": len(verdicts),
           "total_injections": len(injections)}
open(out_p, "w").write(json.dumps(summary, indent=2))
# print a compact footer
for r in rows:
    mark = "✓" if r["pass"] else "✗"
    print(f"  {mark} s{r['scenario']:>2}: {r['hits']}/{r['injections']} "
          f"= {r['rate']:.2f} [CI {r['ci_low']:.2f}, {r['ci_high']:.2f}] "
          f"ttk_p50={r['ttk_p50']}")
print(f"result: {pass_count}/{len(sids)} scenarios passed "
      f"(threshold rate ≥ {min_rate}, CI_low ≥ {min_ci})")
PY

ELAPSED=$(( $(date +%s) - START_TS ))
say "minirun elapsed: ${ELAPSED}s"

FAIL_COUNT=$(python3 -c "import json; print(json.load(open('$SUMMARY_JSON'))['failed'])")
exit $([ "$FAIL_COUNT" -eq 0 ] && echo 0 || echo 3)
