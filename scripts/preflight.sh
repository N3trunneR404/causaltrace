#!/bin/bash
# Phase 7A — preflight checks before starting the CausalTrace daemon.
#
# Verifies the environment is sane: kernel features, BPF filesystem,
# toolchain, Docker testbed, clock source, absence of stale pins.
# Exits 0 on PASS, 1 on any FAIL. Output is a one-line-per-check report
# so it's easy to eyeball in CI and in ops runbooks.
#
# Usage: bash scripts/preflight.sh   (no sudo required for most checks;
#                                     privileged checks are marked and
#                                     auto-skipped when not root).

set -u

PASS=0
FAIL=0
WARN=0

ok()   { printf '  [ok]    %s\n'   "$*"; PASS=$((PASS+1)); }
fail() { printf '  [FAIL]  %s\n'   "$*"; FAIL=$((FAIL+1)); }
warn() { printf '  [warn]  %s\n'   "$*"; WARN=$((WARN+1)); }

echo "CausalTrace preflight"
echo "------------------------------------------------------------"

# 1. Kernel version: BPF ring buffer needs ≥ 5.8, BTF needs ≥ 5.2.
# We target ≥ 5.8 as the minimum supported.
KREL=$(uname -r)
KMAJ=$(echo "$KREL" | cut -d. -f1)
KMIN=$(echo "$KREL" | cut -d. -f2)
if [ "$KMAJ" -gt 5 ] || { [ "$KMAJ" -eq 5 ] && [ "$KMIN" -ge 8 ]; }; then
    ok "kernel $KREL (>= 5.8 required for BPF ring buffer)"
else
    fail "kernel $KREL too old (need >= 5.8)"
fi

# 2. BPF filesystem — needed for map/prog pinning (phase 2 TC drop).
if mount | grep -q 'type bpf'; then
    ok "BPF filesystem mounted"
else
    fail "BPF fs not mounted at /sys/fs/bpf (run: mount -t bpf bpf /sys/fs/bpf)"
fi

# 3. cgroup v2 — required for bpf_get_current_cgroup_id semantics.
if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
    ok "cgroup v2 unified hierarchy present"
else
    warn "cgroup v2 not detected — daemon may fall back to v1 heuristics"
fi

# 4. Toolchain: bcc, clang, llvm for runtime compile.
if python3 -c 'import bcc' 2>/dev/null; then
    BV=$(python3 -c 'import bcc; print(bcc.__version__)')
    ok "python bcc ${BV}"
else
    fail "python3 -c 'import bcc' failed — install bpfcc-tools or python3-bcc"
fi
command -v clang >/dev/null && ok "clang present: $(clang --version | head -1)" || fail "clang not found"
command -v bpftool >/dev/null && ok "bpftool present" || warn "bpftool missing (pinning fallback path unavailable)"
command -v tc >/dev/null && ok "tc (iproute2) present" || fail "tc not found — TC drop cannot attach"

# 5. Docker testbed. run_all.sh assumes ct-web, ct-api, ct-db.
if command -v docker >/dev/null; then
    for c in ct-web ct-api ct-db; do
        if docker inspect "$c" >/dev/null 2>&1; then
            RUNNING=$(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null)
            if [ "$RUNNING" = "true" ]; then
                ok "container $c running"
            else
                warn "container $c exists but not running (docker compose up -d)"
            fi
        else
            warn "container $c not found (testbed not initialized)"
        fi
    done
else
    warn "docker CLI not in PATH — testbed checks skipped"
fi

# 6. Stale BPF pins from a prior run. Phase 2 pins under /sys/fs/bpf/causaltrace/.
# If the supervisor was SIGKILLed, these linger and block re-pinning.
if [ "$(id -u)" -eq 0 ]; then
    PIN_DIR=/sys/fs/bpf/causaltrace
    if [ -d "$PIN_DIR" ]; then
        COUNT=$(find "$PIN_DIR" -mindepth 1 2>/dev/null | wc -l)
        if [ "$COUNT" -gt 0 ]; then
            warn "stale pins under $PIN_DIR ($COUNT entries) — supervisor cleanup will remove them"
        else
            ok "pin dir $PIN_DIR empty"
        fi
    else
        ok "no prior pin dir (fresh state)"
    fi
else
    warn "not root — skipping pin-directory inspection"
fi

# 7. Calibration artifacts (if the operator is about to run enforce mode).
if [ -d calibration ]; then
    if [ -f calibration/restriction_maps.npz ] && [ -f calibration/edge_thresholds.json ]; then
        ok "calibration/ contains artifacts (run validator for deep check: python3 -m tier3.calibration_driver ./calibration)"
    else
        warn "calibration/ exists but incomplete — run loader.py --calibrate"
    fi
else
    warn "no calibration/ directory (daemon can only run in monitor mode)"
fi

# 8. Clock: bpf_ktime_get_ns() is CLOCK_MONOTONIC; daemon uses
# time.monotonic_ns(). If they drift we get spurious staleness drops.
if [ -r /proc/timer_list ]; then
    ok "monotonic clock accessible"
fi

# 9. /proc/sys/kernel/perf_event_paranoid — affects kprobe/uprobe.
PARANOID=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo "?")
if [ "$PARANOID" = "?" ]; then
    warn "cannot read perf_event_paranoid"
elif [ "$PARANOID" -le 2 ]; then
    ok "perf_event_paranoid=${PARANOID} (kprobes allowed for root)"
else
    warn "perf_event_paranoid=${PARANOID} is high; some kprobes may be rejected"
fi

echo "------------------------------------------------------------"
echo "preflight: pass=$PASS warn=$WARN fail=$FAIL"
if [ "$FAIL" -gt 0 ]; then
    echo "RESULT: FAIL — address the errors above before running the daemon."
    exit 1
fi
echo "RESULT: PASS"
exit 0
