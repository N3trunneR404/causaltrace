#!/bin/bash
# scripts/marathon.sh — A*-grade evaluation orchestrator (fresh, no reuse).
#
# Design goals:
#   * Every artifact under results/marathon/ is produced in THIS run.
#     No cached Falco/Tetragon logs are reused; every baseline is
#     exercised against the same attack sequence in the same host.
#   * 10 attack scenarios (S2..S11) × 15 injections = 150 fresh
#     injections total. S1 (normal) is kept separate and feeds the FPR
#     baseline.
#   * Calibration is long enough to be defensible (≥30 min → ≥360
#     bigram windows per container, 6× the validator floor of 60).
#   * FPR baseline is long enough for tight confidence intervals
#     (2 h → 120 detection cycles, CI half-width ≪ 1 FP/h at 0 hits).
#   * Overhead is measured with enough repetitions (5 runs × 5 min each
#     per condition) for a t-test to have meaningful power.
#   * Stress test: the Tier 3 daemon runs with a concurrent benign load
#     generator during attack injection so we measure detection under
#     realistic contention, not a silent host.
#
# Stage budget (wall-clock):
#   00  preflight + testbed                                 ~1 min
#   C   fresh calibration                                  30 min
#   E1  FPR baseline                                      120 min
#   E2  detection rate + TTK (150 injections + cooldown)   90 min
#   E4  overhead (5 runs * 5 min * 2 conditions)           50 min
#   E5  OOD held-out                                       20 min
#   E6a Falco baseline (same attack sequence)              30 min
#   E6b Tetragon baseline (same attack sequence)           30 min
#   analyzer                                                 1 min
#   TOTAL                                                 ~6.3 hours
#
# Run inside tmux / nohup:
#   sudo nohup bash scripts/marathon.sh > marathon.nohup.log 2>&1 &
#
# Resumable. --resume skips stages marked done in state.json. --only
# lets you run just a subset (comma-separated, e.g. --only=E2,E4).

set -u

START_TS=$(date +%s)
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

RESULTS_DIR="${REPO_ROOT}/results/marathon"
STATE_FILE="${RESULTS_DIR}/state.json"
LOG_FILE="${RESULTS_DIR}/marathon.log"
VERDICTS_SRC="${REPO_ROOT}/results/causaltrace/verdicts.jsonl"
SCENARIO_TAG=/tmp/causaltrace_current_scenario

# ── Evaluation parameters (tune here, not inside stages) ────────────
ATTACK_SCENARIOS=(2 3 4 5 6 7 8 9 10 11)   # S1 is normal; 10 attacks
N_INJECTIONS=15                             # 10 * 15 = 150 total
DETECT_WINDOW_S=18                          # cushion for 2 Tier-3 cycles
CALIBRATION_S=1800                          # 30 min
FPR_DURATION_S=7200                         # 2 h
OVERHEAD_DURATION_S=300                     # 5 min per run
OVERHEAD_RUNS=5                             # 5 runs per condition
OOD_SCENARIOS=(11)                          # held-out / zero-day techniques
OOD_INJECTIONS=30                           # 30 S11 injections for E5

# ── CLI parsing ─────────────────────────────────────────────────────
ONLY=""
RESUME=0
for arg in "$@"; do
    case "$arg" in
        --only=*) ONLY="${arg#--only=}" ;;
        --resume) RESUME=1 ;;
        --no-calibrate) SKIP_CAL=1 ;;
    esac
done

mkdir -p "$RESULTS_DIR"
exec > >(tee -a "$LOG_FILE") 2>&1
say() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }

if [ "$(id -u)" -ne 0 ]; then
    say "FAIL: marathon must run as root"
    exit 1
fi

# ── Stage gate ──────────────────────────────────────────────────────
state_done() {
    [ "$RESUME" -eq 1 ] || return 1
    [ -f "$STATE_FILE" ] || return 1
    python3 -c "
import json, sys
s = json.load(open('$STATE_FILE'))
sys.exit(0 if s.get('$1', {}).get('done') else 1)
" 2>/dev/null
}
state_mark() {
    python3 - "$1" "$2" <<'PY'
import json, os, sys, time
path = os.environ['STATE_FILE']
key, status = sys.argv[1], sys.argv[2]
try: s = json.load(open(path))
except Exception: s = {}
s.setdefault(key, {})
s[key]['done']        = (status == 'done')
s[key]['finished_ts'] = time.time()
json.dump(s, open(path, 'w'), indent=2)
PY
}
export STATE_FILE
skip_if_only() {
    [ -z "$ONLY" ] && return 1
    case ",$ONLY," in (*",$1,"*) return 1 ;; (*) return 0 ;; esac
}

# ── Loader lifecycle ────────────────────────────────────────────────
LOADER_PID=""
start_loader() {
    local mode="$1"
    say "loader → $mode"
    (cd "$REPO_ROOT" && exec python3 loader.py --mode "$mode") \
        >>"$RESULTS_DIR/loader.log" 2>&1 &
    LOADER_PID=$!
    for _ in $(seq 1 60); do
        sleep 1
        kill -0 "$LOADER_PID" 2>/dev/null || {
            say "loader died during startup"; return 1; }
        grep -qi "attached\|detection interval" "$RESULTS_DIR/loader.log" && return 0
    done
    say "loader attach sentinel not seen within 60s — continuing"
    return 0
}
stop_loader() {
    [ -n "$LOADER_PID" ] || return 0
    kill -0 "$LOADER_PID" 2>/dev/null || { LOADER_PID=""; return 0; }
    kill -TERM "$LOADER_PID" 2>/dev/null || true
    for _ in $(seq 1 10); do
        kill -0 "$LOADER_PID" 2>/dev/null || break
        sleep 1
    done
    kill -0 "$LOADER_PID" 2>/dev/null && kill -KILL "$LOADER_PID" 2>/dev/null
    LOADER_PID=""
}

# ── Stress generator: concurrent benign load during attacks ─────────
STRESS_PID=""
start_stress() {
    # A gentle mixed workload across the three testbed containers. Keeps
    # the Tier 3 bigram windows populated so we measure detection under
    # realistic signal density, not a silent host.
    say "starting concurrent stress load"
    (while true; do
        for c in ct-web ct-api ct-db; do
            docker exec "$c" sh -c 'for i in 1 2 3 4 5; do uptime; done' \
                >/dev/null 2>&1 || true
        done
        sleep 1
    done) >/dev/null 2>&1 &
    STRESS_PID=$!
}
stop_stress() {
    [ -n "$STRESS_PID" ] || return 0
    kill "$STRESS_PID" 2>/dev/null || true
    STRESS_PID=""
}

cleanup() {
    stop_loader
    stop_stress
    echo "0" > "$SCENARIO_TAG" 2>/dev/null || true
    ELAPSED=$(( $(date +%s) - START_TS ))
    say "marathon ended. elapsed=${ELAPSED}s"
}
trap cleanup EXIT INT TERM

snap_verdicts() { cp -f "$VERDICTS_SRC" "$1" 2>/dev/null || : > "$1"; }
reset_verdicts() { : > "$VERDICTS_SRC" 2>/dev/null || true; }

# Detect auxiliary tools. These are optional; stages that need them
# are skipped gracefully when absent (and flagged in state.json).
HAS_FALCO=0
HAS_TETRAGON=0
command -v falco >/dev/null     && HAS_FALCO=1
command -v tetragon >/dev/null  && HAS_TETRAGON=1

# ════════════════════════════════════════════════════════════════════
#  Preflight + testbed
# ════════════════════════════════════════════════════════════════════
say "marathon starting (resume=$RESUME only=${ONLY:-all}) 150-injection plan"
if ! bash "${REPO_ROOT}/scripts/preflight.sh"; then
    say "preflight FAILED"
    exit 1
fi
docker compose up -d >/dev/null 2>&1 || true
bash "${REPO_ROOT}/scripts/test_connectivity.sh" >/dev/null 2>&1 || true
mkdir -p "$(dirname "$VERDICTS_SRC")"

# ════════════════════════════════════════════════════════════════════
#  C — Fresh calibration (30 min)
# ════════════════════════════════════════════════════════════════════
if state_done C; then
    say "C calibration already done — skipping"
elif skip_if_only C; then
    say "C skipped by --only"
elif [ "${SKIP_CAL:-0}" -eq 1 ]; then
    say "C skipped by --no-calibrate"
else
    say "C: fresh calibration (${CALIBRATION_S}s)"
    # Clear previous calibration so we really ARE starting from scratch.
    if [ -d calibration ]; then
        mv calibration "calibration.pre-$(date +%s)" || true
    fi
    # Traffic generator in the background.
    (bash "${REPO_ROOT}/scripts/generate_normal_traffic.sh" >/dev/null 2>&1) &
    GEN_PID=$!
    # Override the duration so calibrate_runner sleeps this long.
    CAUSALTRACE_CALIBRATION_S=$CALIBRATION_S \
        python3 loader.py --calibrate \
            >"${RESULTS_DIR}/loader_calibrate.log" 2>&1
    kill $GEN_PID 2>/dev/null || true
    say "validating calibration"
    python3 -m tier3.calibration_driver ./calibration \
        >"${RESULTS_DIR}/calibration_validation.txt" 2>&1 || {
        say "calibration validator FAILED — aborting"
        exit 2
    }
    state_mark C done
fi

# ════════════════════════════════════════════════════════════════════
#  E1 — FPR baseline (2h)
# ════════════════════════════════════════════════════════════════════
if state_done E1; then
    say "E1 already done — skipping"
elif skip_if_only E1; then
    say "E1 skipped by --only"
else
    say "E1: FPR baseline (${FPR_DURATION_S}s = $((FPR_DURATION_S/60))m normal traffic)"
    reset_verdicts
    start_loader enforce
    (bash "${REPO_ROOT}/scripts/generate_normal_traffic.sh" >/dev/null 2>&1) &
    GEN_PID=$!
    sleep "$FPR_DURATION_S"
    kill $GEN_PID 2>/dev/null || true
    snap_verdicts "${RESULTS_DIR}/e1_fpr.jsonl"
    stop_loader
    state_mark E1 done
fi

# ════════════════════════════════════════════════════════════════════
#  E2 + E3 — Detection rate + TTK (150 injections under stress)
# ════════════════════════════════════════════════════════════════════
run_attack_sweep() {
    # $1 = output jsonl path, $2 = output ndjson inject-log path
    local out_jsonl="$1"
    local out_ndjson="$2"
    local label_tag="$3"           # e.g. "causaltrace" / "falco" / "tetragon"

    reset_verdicts
    : > "$out_ndjson"
    start_stress
    for sid in "${ATTACK_SCENARIOS[@]}"; do
        local script
        script=$(ls "${REPO_ROOT}/attacks/scenario_${sid}_"*.sh 2>/dev/null | head -1)
        [ -z "$script" ] && { say "  s${sid} missing"; continue; }
        for n in $(seq 1 "$N_INJECTIONS"); do
            local tag="${label_tag}.s${sid}.i${n}"
            local t_inject
            t_inject=$(python3 -c 'import time; print(time.time())')
            echo "$sid" > "$SCENARIO_TAG"
            bash "$script" >/dev/null 2>&1 || true
            python3 - "$tag" "$t_inject" "$sid" "$n" <<'PY' >> "$out_ndjson"
import json, sys
print(json.dumps({"tag": sys.argv[1], "t_inject": float(sys.argv[2]),
                  "scenario": int(sys.argv[3]), "injection_n": int(sys.argv[4])}))
PY
            sleep "$DETECT_WINDOW_S"
            echo "0" > "$SCENARIO_TAG"
        done
        say "  s${sid}: ${N_INJECTIONS} injections done"
    done
    stop_stress
    snap_verdicts "$out_jsonl"
}

if state_done E2 && state_done E3; then
    say "E2/E3 already done — skipping"
elif skip_if_only E2 && skip_if_only E3; then
    say "E2/E3 skipped by --only"
else
    say "E2/E3: 10 scenarios × ${N_INJECTIONS} = $(( ${#ATTACK_SCENARIOS[@]} * N_INJECTIONS )) injections under stress"
    start_loader enforce
    run_attack_sweep \
        "${RESULTS_DIR}/e2_verdicts.jsonl" \
        "${RESULTS_DIR}/e2_injections.ndjson" \
        "causaltrace"
    stop_loader
    state_mark E2 done
    state_mark E3 done
fi

# ════════════════════════════════════════════════════════════════════
#  E4 — Overhead (5 runs × 5 min × 2 modes)
# ════════════════════════════════════════════════════════════════════
if state_done E4; then
    say "E4 already done — skipping"
elif skip_if_only E4; then
    say "E4 skipped by --only"
else
    say "E4: overhead (${OVERHEAD_RUNS} runs × ${OVERHEAD_DURATION_S}s × 2 modes)"
    : > "${RESULTS_DIR}/e4_overhead.ndjson"
    for mode in off on; do
        if [ "$mode" = "off" ]; then stop_loader
        else                         start_loader enforce
        fi
        for run in $(seq 1 "$OVERHEAD_RUNS"); do
            say "  overhead mode=$mode run=$run/${OVERHEAD_RUNS}"
            python3 - "$mode" "$run" "$OVERHEAD_DURATION_S" <<'PY' >> "${RESULTS_DIR}/e4_overhead.ndjson"
import ctypes, json, sys, time
libc = ctypes.CDLL("libc.so.6")
mode, run, dur = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
t0 = time.monotonic(); deadline = t0 + dur; n = 0
while time.monotonic() < deadline:
    for _ in range(10000): libc.getpid()
    n += 10000
el = time.monotonic() - t0
print(json.dumps({"mode": mode, "run": run, "elapsed_s": el,
                  "syscalls": n, "rate_per_s": n/el}))
PY
        done
    done
    stop_loader
    state_mark E4 done
fi

# ════════════════════════════════════════════════════════════════════
#  E5 — OOD robustness (30 × S11 under stress)
# ════════════════════════════════════════════════════════════════════
if state_done E5; then
    say "E5 already done — skipping"
elif skip_if_only E5; then
    say "E5 skipped by --only"
else
    say "E5: OOD (${OOD_INJECTIONS} × S11 under stress)"
    reset_verdicts
    start_loader enforce
    start_stress
    : > "${RESULTS_DIR}/e5_injections.ndjson"
    for sid in "${OOD_SCENARIOS[@]}"; do
        script=$(ls "${REPO_ROOT}/attacks/scenario_${sid}_"*.sh 2>/dev/null | head -1)
        [ -z "$script" ] && continue
        for n in $(seq 1 "$OOD_INJECTIONS"); do
            t_inject=$(python3 -c 'import time; print(time.time())')
            echo "$sid" > "$SCENARIO_TAG"
            bash "$script" >/dev/null 2>&1 || true
            python3 - "ood.s${sid}.i${n}" "$t_inject" "$sid" "$n" <<'PY' >> "${RESULTS_DIR}/e5_injections.ndjson"
import json, sys
print(json.dumps({"tag": sys.argv[1], "t_inject": float(sys.argv[2]),
                  "scenario": int(sys.argv[3]), "injection_n": int(sys.argv[4])}))
PY
            sleep "$DETECT_WINDOW_S"
            echo "0" > "$SCENARIO_TAG"
        done
    done
    stop_stress
    snap_verdicts "${RESULTS_DIR}/e5_ood.jsonl"
    stop_loader
    state_mark E5 done
fi

# ════════════════════════════════════════════════════════════════════
#  E6a — Falco baseline (fresh; same 150 attacks)
# ════════════════════════════════════════════════════════════════════
if state_done E6a; then
    say "E6a already done — skipping"
elif skip_if_only E6a; then
    say "E6a skipped by --only"
elif [ "$HAS_FALCO" -eq 0 ]; then
    say "E6a: falco not installed — marking N/A"
    python3 - <<PY
import json
path = "${STATE_FILE}"
try: s = json.load(open(path))
except Exception: s = {}
s["E6a"] = {"done": True, "na": True, "reason": "falco not installed"}
json.dump(s, open(path, "w"), indent=2)
PY
else
    say "E6a: Falco baseline (same ${#ATTACK_SCENARIOS[@]}×${N_INJECTIONS} attacks)"
    FALCO_LOG="${RESULTS_DIR}/falco_stock.jsonl"
    : > "$FALCO_LOG"
    (falco -o json_output=true -o "log_level=info" >"$FALCO_LOG" 2>/dev/null) &
    FALCO_PID=$!
    # Give falco 15s to attach its drivers.
    sleep 15
    run_attack_sweep \
        "${RESULTS_DIR}/e6a_verdicts.jsonl" \
        "${RESULTS_DIR}/e6a_injections.ndjson" \
        "falco"
    kill -TERM "$FALCO_PID" 2>/dev/null
    for _ in 1 2 3 4 5; do kill -0 "$FALCO_PID" 2>/dev/null || break; sleep 1; done
    kill -KILL "$FALCO_PID" 2>/dev/null || true
    state_mark E6a done
fi

# ════════════════════════════════════════════════════════════════════
#  E6b — Tetragon baseline (fresh; same 150 attacks)
# ════════════════════════════════════════════════════════════════════
if state_done E6b; then
    say "E6b already done — skipping"
elif skip_if_only E6b; then
    say "E6b skipped by --only"
elif [ "$HAS_TETRAGON" -eq 0 ]; then
    say "E6b: tetragon not installed — marking N/A"
    python3 - <<PY
import json
path = "${STATE_FILE}"
try: s = json.load(open(path))
except Exception: s = {}
s["E6b"] = {"done": True, "na": True, "reason": "tetragon not installed"}
json.dump(s, open(path, "w"), indent=2)
PY
else
    say "E6b: Tetragon baseline (same ${#ATTACK_SCENARIOS[@]}×${N_INJECTIONS} attacks)"
    TETRA_LOG="${RESULTS_DIR}/tetragon_stock.jsonl"
    : > "$TETRA_LOG"
    (tetragon --export-filename "$TETRA_LOG" 2>/dev/null) &
    TPID=$!
    sleep 15
    run_attack_sweep \
        "${RESULTS_DIR}/e6b_verdicts.jsonl" \
        "${RESULTS_DIR}/e6b_injections.ndjson" \
        "tetragon"
    kill -TERM "$TPID" 2>/dev/null
    for _ in 1 2 3 4 5; do kill -0 "$TPID" 2>/dev/null || break; sleep 1; done
    kill -KILL "$TPID" 2>/dev/null || true
    state_mark E6b done
fi

# ════════════════════════════════════════════════════════════════════
#  Analyze
# ════════════════════════════════════════════════════════════════════
say "running analyzer"
python3 "${REPO_ROOT}/scripts/marathon_analyze.py" \
        --dir "$RESULTS_DIR" \
        --n-injections "$N_INJECTIONS" \
        --attack-scenarios "$(IFS=,; echo "${ATTACK_SCENARIOS[*]}")" \
    || say "analyzer non-zero"

say "marathon complete. artifacts under $RESULTS_DIR"
exit 0
