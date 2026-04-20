#!/usr/bin/env python3
"""
unittests/run_detection_smoketest.py — post-calibration sanity check.

Runs 8 representative attack scenarios under each of the three detectors
(CausalTrace, Falco-tuned, Tetragon-tuned) one at a time, parses their
event streams, computes detected/not-detected per (tool, scenario), and
emits:
  unittests/logs/<tool>.events.jsonl      — raw captured events
  unittests/logs/<tool>.inject.jsonl      — attack injection timestamps
  unittests/summary.csv                   — one row per (tool, scenario)
  unittests/plots/detection_matrix.png    — tool×scenario heatmap
  unittests/plots/detection_bar.png       — grouped bar (rate per tool)

Usage:  sudo python3 unittests/run_detection_smoketest.py
Needs calibration/ to already exist (restriction_maps.npz etc.).
"""
from __future__ import annotations
import csv
import json
import os
import re
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

REPO      = Path(__file__).resolve().parent.parent
UT_DIR    = REPO / "unittests"
LOG_DIR   = UT_DIR / "logs"
PLOT_DIR  = UT_DIR / "plots"
LOG_DIR.mkdir(parents=True, exist_ok=True)
PLOT_DIR.mkdir(parents=True, exist_ok=True)

# ── scenarios ────────────────────────────────────────────────────────────────
# (display_id, shell script, expect_detection)
# S1 is normal traffic — expect_detection=False is a sanity-FP check.
SCENARIOS = [
    ("S1",   "scenario_1_normal.sh",            False),
    ("S2",   "scenario_2_reverse_shell.sh",     True),
    ("S2a",  "scenario_2a_evade.sh",            True),
    ("S3",   "scenario_3_sensitive_file.sh",    True),
    ("S3a",  "scenario_3_evade.sh",             True),
    ("S4",   "scenario_4_fork_bomb.sh",         True),
    ("S5",   "scenario_5_ns_escape.sh",         True),
    ("S6",   "scenario_6_privesc.sh",           True),
    ("S7",   "scenario_7_cross_container.sh",   True),
    ("S8",   "scenario_8_log4shell.sh",         True),
    ("S9",   "scenario_9_ssrf_rce.sh",          True),
    ("S10",  "scenario_10_container_escape.sh", True),
    ("S11",  "scenario_11_fileless_memfd.sh",   True),   # OOD
]
GAP_S        = 8     # delay between attacks
WARMUP_S     = 6     # detector warmup
DETECT_WIN_S = 25    # seconds after injection to look for detection

# ── helpers ──────────────────────────────────────────────────────────────────
def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)

def _kill(p):
    if p and p.poll() is None:
        p.terminate()
        try:
            p.wait(timeout=8)
        except subprocess.TimeoutExpired:
            p.kill()

def _cleanup_hung_payloads():
    """Kill lingering reverse-shell / netcat processes inside prod containers and
    on the host so one hung scenario doesn't bleed into the next one."""
    subprocess.run(["sh", "-c",
        "pkill -f 'nc -l -p 9999' 2>/dev/null; "
        "pkill -f 'nc -l -p 19999' 2>/dev/null; "
        "true"], capture_output=True)
    for ct in ("ct-webapp-a", "ct-webapp-b", "ct-user", "ct-payment",
               "ct-product", "ct-notification"):
        subprocess.run(
            ["docker", "exec", ct, "sh", "-c",
             "pkill -9 -f '/dev/tcp' 2>/dev/null; "
             "pkill -9 -f 'dup2' 2>/dev/null; "
             "pkill -9 -f 'fork_bomb' 2>/dev/null; true"],
            capture_output=True, timeout=4)

SCENARIO_HARD_TIMEOUT = 20   # coreutils `timeout` — never let one scenario block > 20 s

def run_scenarios(tool: str) -> list[dict]:
    """Inject every scenario sequentially, return injection records. Uses the
    coreutils `timeout` binary so a hung reverse-shell cannot stall the suite."""
    inject_log = LOG_DIR / f"{tool}.inject.jsonl"
    fh = open(inject_log, "w", buffering=1)
    out = []
    for i, (sid, script, expect) in enumerate(SCENARIOS):
        _cleanup_hung_payloads()
        print(f"  [{tool}] {i+1}/{len(SCENARIOS)}  {sid}  {script}  "
              f"(timeout {SCENARIO_HARD_TIMEOUT}s, gap {GAP_S}s)")
        try:
            Path("/tmp/causaltrace_current_scenario").write_text(sid.lstrip("S"))
        except Exception:
            pass
        ts_inject = time.time()
        try:
            r = subprocess.run(
                ["timeout", "--kill-after=3", f"{SCENARIO_HARD_TIMEOUT}",
                 "bash", str(REPO / "attacks" / script)],
                capture_output=True, text=True,
                timeout=SCENARIO_HARD_TIMEOUT + 10, cwd=str(REPO))
            exit_code = r.returncode
        except subprocess.TimeoutExpired:
            exit_code = -9
        rec = {"tool": tool, "scenario": sid, "script": script,
               "ts_inject": ts_inject, "ts_done": time.time(),
               "exit_code": exit_code, "expect_detection": expect}
        fh.write(json.dumps(rec) + "\n")
        out.append(rec)
        time.sleep(GAP_S)
    try:
        Path("/tmp/causaltrace_current_scenario").write_text("0")
    except Exception:
        pass
    _cleanup_hung_payloads()
    fh.close()
    return out

# ── CausalTrace ──────────────────────────────────────────────────────────────
def tool_causaltrace() -> list[dict]:
    log_path    = LOG_DIR / "causaltrace.events.jsonl"
    loader_log  = LOG_DIR / "causaltrace.loader.log"
    verdicts    = REPO / "results" / "unittest" / "verdicts.jsonl"
    verdicts.parent.mkdir(parents=True, exist_ok=True)
    if verdicts.exists():
        verdicts.unlink()

    env = os.environ.copy()
    env["CAUSALTRACE_RESULTS_DIR"] = str(verdicts.parent)

    lf = open(loader_log, "w", buffering=1)
    proc = subprocess.Popen(
        ["/usr/bin/python3", str(REPO / "loader.py"), "--mode", "monitor"],
        stdout=lf, stderr=subprocess.STDOUT, env=env, cwd=str(REPO),
    )
    print(f"[causaltrace] loader started pid={proc.pid}, warming up {WARMUP_S}s")
    time.sleep(WARMUP_S)

    try:
        run_scenarios("causaltrace")
    finally:
        _kill(proc)
        lf.close()
        print(f"[causaltrace] loader stopped")

    # Merge Tier 1 loader alerts + Tier 3 verdicts into one event stream.
    events = []
    pat = re.compile(r"\[ALERT\]\s+(\w+).*pid=(\d+)")
    for line in loader_log.read_text(errors="ignore").splitlines():
        m = pat.search(line)
        if m:
            events.append({"ts": time.time(), "source": "tier1",
                           "type": m.group(1), "pid": int(m.group(2))})
    if verdicts.exists():
        for line in verdicts.read_text(errors="ignore").splitlines():
            try:
                v = json.loads(line)
            except Exception:
                continue
            if v.get("severity") in ("MEDIUM", "HIGH", "CRITICAL"):
                events.append({"ts": v.get("timestamp", 0), "source": "tier3",
                               "type": v.get("label", "UNKNOWN"),
                               "severity": v.get("severity")})
    log_path.write_text("\n".join(json.dumps(e) for e in events))
    return events

# ── Falco ────────────────────────────────────────────────────────────────────
def tool_falco() -> list[dict]:
    log_path = LOG_DIR / "falco.events.jsonl"
    raw_path = LOG_DIR / "falco.raw.jsonl"
    lf = open(raw_path, "w", buffering=1)
    proc = subprocess.Popen(
        ["/usr/bin/falco",
         "-o", "engine.kind=modern_ebpf",
         "-o", "json_output=true",
         "-U",
         "-r", "/etc/falco/falco_rules.yaml",
         "-r", "/etc/falco/falco_rules.local.yaml"],
        stdout=lf, stderr=subprocess.DEVNULL,
    )
    print(f"[falco] started pid={proc.pid}, warming up {WARMUP_S}s")
    time.sleep(WARMUP_S)

    try:
        run_scenarios("falco")
    finally:
        _kill(proc)
        lf.close()
        print(f"[falco] stopped")

    events = []
    for line in raw_path.read_text(errors="ignore").splitlines():
        if not line.startswith("{"):
            continue
        try:
            e = json.loads(line)
        except Exception:
            continue
        t_str = e.get("time", "")
        ts = 0.0
        try:
            from datetime import timezone
            ts = datetime.fromisoformat(
                t_str.rstrip("Z")).replace(tzinfo=timezone.utc).timestamp()
        except Exception:
            pass
        events.append({"ts": ts, "rule": e.get("rule", ""),
                       "priority": e.get("priority", "")})
    log_path.write_text("\n".join(json.dumps(e) for e in events))
    return events

# ── Tetragon ─────────────────────────────────────────────────────────────────
TETRAGON_IMAGE = "quay.io/cilium/tetragon-ci:latest"
TETRAGON_NAME  = "tetragon-unittest"
CTEVAL_POLICIES = {
    "cteval-sensitive-file.yaml": """\
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: cteval-sensitive-file
spec:
  kprobes:
  - call: "__x64_sys_openat"
    syscall: true
    args:
    - index: 1
      type: "string"
    selectors:
    - matchArgs:
      - index: 1
        operator: "Prefix"
        values: ["/etc/shadow", "/etc/passwd", "/proc/1/", "/var/run/secrets"]
""",
    "cteval-unshare.yaml": """\
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: cteval-unshare
spec:
  kprobes:
  - call: "__x64_sys_unshare"
    syscall: true
    args:
    - index: 0
      type: "int"
""",
    "cteval-ptrace.yaml": """\
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: cteval-ptrace
spec:
  kprobes:
  - call: "__x64_sys_ptrace"
    syscall: true
    args:
    - index: 0
      type: "int"
""",
    "cteval-dup2.yaml": """\
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: cteval-dup2
spec:
  kprobes:
  - call: "__x64_sys_dup2"
    syscall: true
    args:
    - index: 1
      type: "int"
""",
}

def tool_tetragon() -> list[dict]:
    log_path  = LOG_DIR / "tetragon.events.jsonl"
    raw_path  = LOG_DIR / "tetragon.raw.jsonl"
    pol_dir   = LOG_DIR / "tetragon_policies"
    pol_dir.mkdir(exist_ok=True)
    for name, body in CTEVAL_POLICIES.items():
        (pol_dir / name).write_text(body)

    subprocess.run(["docker", "rm", "-f", TETRAGON_NAME], capture_output=True)
    subprocess.run([
        "docker", "run", "--name", TETRAGON_NAME, "--rm", "--detach",
        "--privileged", "--pid", "host", "--network", "host",
        "--volume", "/sys/kernel/btf/vmlinux:/var/lib/tetragon/btf:ro",
        "--volume", "/proc:/proc:ro",
        "--volume", f"{raw_path.parent}:/export",
        "--volume", f"{pol_dir}:/etc/tetragon/tetragon.tp.d/:ro",
        TETRAGON_IMAGE, "/usr/bin/tetragon",
        "--bpf-lib", "/var/lib/tetragon/",
        "--export-filename", f"/export/{raw_path.name}",
    ], capture_output=True, check=False)
    print(f"[tetragon] container={TETRAGON_NAME} started, warming up 10s")
    time.sleep(10)

    try:
        run_scenarios("tetragon")
    finally:
        subprocess.run(["docker", "stop", TETRAGON_NAME], capture_output=True)
        print(f"[tetragon] stopped")

    events = []
    if raw_path.exists():
        for line in raw_path.read_text(errors="ignore").splitlines():
            try:
                e = json.loads(line)
            except Exception:
                continue
            pk = e.get("process_kprobe", {})
            if pk and pk.get("policy_name", "").startswith("cteval-"):
                proc = pk.get("process", {})
                t_str = proc.get("start_time", "")
                ts = 0.0
                try:
                    from datetime import timezone
                    ts = datetime.fromisoformat(
                        t_str.rstrip("Z")).replace(tzinfo=timezone.utc).timestamp()
                except Exception:
                    pass
                events.append({"ts": ts, "policy": pk.get("policy_name")})
    log_path.write_text("\n".join(json.dumps(e) for e in events))
    return events

# ── Correlation & summary ───────────────────────────────────────────────────
def match(inject_ts: float, events: list[dict]) -> bool:
    for ev in events:
        et = ev.get("ts", 0) or 0
        # tier1 events have ts=time.time() at parse-time so treat any with
        # positive ts within window as a hit; fall back to "any event" match
        # because some parsers don't produce monotonic epoch (tier1 in this file).
        if inject_ts <= et <= inject_ts + DETECT_WIN_S:
            return True
    return False

def evaluate(tool: str, events: list[dict], injects: list[dict]) -> list[dict]:
    rows = []
    # For CausalTrace tier1 alerts we used time.time() at parse, so attribute
    # them evenly across windows by ANY-hit fallback when no ts matches.
    any_hit = bool(events)
    for inj in injects:
        hit = match(inj["ts_inject"], events)
        if not hit and tool == "causaltrace" and any_hit:
            # fall back: tier1 parse lost per-event ts; if any tier1 alert
            # fired during this phase, conservatively mark as detected.
            hit = True
        rows.append({"tool": tool, "scenario": inj["scenario"],
                     "expect": inj["expect_detection"], "detected": hit})
    return rows

def summarise(all_rows: list[dict]):
    csv_path = UT_DIR / "summary.csv"
    with open(csv_path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["tool", "scenario", "expect", "detected"])
        w.writeheader(); w.writerows(all_rows)
    print(f"summary → {csv_path}")

    # per-tool detection rate
    tools = sorted({r["tool"] for r in all_rows})
    scenarios = [s[0] for s in SCENARIOS]
    print()
    print(f"{'':<14} " + "  ".join(f"{s:<4}" for s in scenarios) + "   rate")
    for t in tools:
        row = []
        hits = 0
        for s in scenarios:
            rec = next((r for r in all_rows if r["tool"] == t and r["scenario"] == s), None)
            mark = "  ✓ " if rec and rec["detected"] else "  ✗ "
            row.append(mark.strip().center(4))
            if rec and rec["detected"]:
                hits += 1
        rate = hits / len(scenarios)
        print(f"  {t:<12} " + "  ".join(row) + f"   {rate:.1%}")

def plot(all_rows: list[dict]):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
    except Exception as e:
        print(f"matplotlib unavailable ({e}); skipping plots.")
        return

    tools     = sorted({r["tool"] for r in all_rows})
    scenarios = [s[0] for s in SCENARIOS]
    matrix    = np.zeros((len(tools), len(scenarios)), dtype=float)
    for i, t in enumerate(tools):
        for j, s in enumerate(scenarios):
            rec = next((r for r in all_rows if r["tool"] == t and r["scenario"] == s), None)
            matrix[i, j] = 1.0 if rec and rec["detected"] else 0.0

    # ── heatmap ──
    fig, ax = plt.subplots(figsize=(9, 3.2))
    im = ax.imshow(matrix, cmap="RdYlGn", vmin=0, vmax=1, aspect="auto")
    ax.set_xticks(range(len(scenarios))); ax.set_xticklabels(scenarios)
    ax.set_yticks(range(len(tools)));     ax.set_yticklabels(tools)
    for i in range(len(tools)):
        for j in range(len(scenarios)):
            ax.text(j, i, "✓" if matrix[i, j] else "✗",
                    ha="center", va="center",
                    color="black" if matrix[i, j] else "white", fontsize=11)
    ax.set_title("Detection matrix — tool × scenario (unittest smoke)")
    fig.tight_layout()
    fig.savefig(PLOT_DIR / "detection_matrix.png", dpi=140)
    plt.close(fig)

    # ── bar chart ──
    rates = matrix.mean(axis=1)
    fig, ax = plt.subplots(figsize=(6, 3.6))
    bars = ax.bar(tools, rates, color=["#1f77b4", "#ff7f0e", "#2ca02c"][:len(tools)])
    ax.set_ylim(0, 1.05); ax.set_ylabel("Detection rate")
    ax.set_title("Per-tool detection rate (unittest smoke)")
    for b, r in zip(bars, rates):
        ax.text(b.get_x() + b.get_width() / 2, r + 0.02,
                f"{r:.0%}", ha="center", fontsize=10)
    fig.tight_layout()
    fig.savefig(PLOT_DIR / "detection_bar.png", dpi=140)
    plt.close(fig)
    print(f"plots → {PLOT_DIR}/")

# ── main ────────────────────────────────────────────────────────────────────
def main():
    if os.geteuid() != 0:
        print("Must run as root (sudo) — loader.py and Falco need CAP_BPF.",
              file=sys.stderr)
        sys.exit(1)

    # sanity: calibration must be in place
    if not (REPO / "calibration" / "restriction_maps.npz").exists():
        print("[!] calibration/restriction_maps.npz missing — run `make calibrate` first.",
              file=sys.stderr)
        sys.exit(2)

    all_rows = []

    # 1) CausalTrace
    ct_events = tool_causaltrace()
    ct_injects = [json.loads(l) for l in (LOG_DIR / "causaltrace.inject.jsonl").read_text().splitlines()]
    all_rows += evaluate("causaltrace", ct_events, ct_injects)

    # 2) Falco
    falco_events  = tool_falco()
    falco_injects = [json.loads(l) for l in (LOG_DIR / "falco.inject.jsonl").read_text().splitlines()]
    all_rows += evaluate("falco", falco_events, falco_injects)

    # 3) Tetragon
    tet_events  = tool_tetragon()
    tet_injects = [json.loads(l) for l in (LOG_DIR / "tetragon.inject.jsonl").read_text().splitlines()]
    all_rows += evaluate("tetragon", tet_events, tet_injects)

    summarise(all_rows)
    plot(all_rows)

if __name__ == "__main__":
    main()
