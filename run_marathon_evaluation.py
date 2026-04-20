#!/usr/bin/env python3
"""
run_marathon_evaluation.py — CausalTrace A* Paper Marathon Orchestrator

12-hour sequential evaluation pipeline:
  Phase 1: CausalTrace calibration    (4 h, dense multi-pattern traffic)
  Phase 2: CausalTrace attack eval    (3 h, 100 attacks, Poisson-spaced)
  Phase 3: Falco evaluation           (2.5 h, 50 stock + 50 tuned)
  Phase 4: Tetragon evaluation        (2.5 h, 50 stock + 50 tuned)
  ─────────────────────────────────────────────────────────────────────
  Total:                              12 h

Phase 1 runs dense wrk load + docker-exec inter-service patterns across ALL
calibrated edges (nginx→webapp, api-gw→services, services→db/kafka/redis).
This replaces the prior 30-minute light calibration.

Attack timing: Poisson process, mean=90s, clamped [45s, 200s].
100 attacks × 90s ≈ 2.5h — fits comfortably inside the 3h Phase 2 window.
Phases 3 and 4 replay the same 100-attack sequence (half per config).

Outputs (all in results/marathon/):
  attacks.jsonl          — timestamped injection log
  loader.log             — Tier-1 kernel alerts (stdout of loader.py)
  verdicts.jsonl         — Tier-3 sheaf verdicts
  signals.jsonl          — per-cycle d=74 signal vectors
  falco_stock.jsonl      — Falco stock-rules alerts
  falco_tuned.jsonl      — Falco tuned-rules alerts
  tetragon_stock.jsonl   — Tetragon events (no policy)
  tetragon_tuned.jsonl   — Tetragon events (CTEval policies)
  detection_timeline.json— per-attack injection vs first-detection latency
  metrics.jsonl          — 15-second system resource samples
  calibration_traffic.log— verbose log of calibration traffic patterns
  state.json             — resume checkpoint

Usage:
  sudo python3 run_marathon_evaluation.py           # full 12-hour run
  sudo python3 run_marathon_evaluation.py --resume  # skip completed phases
  sudo python3 run_marathon_evaluation.py --phase 2 # run only Phase 2
  python3 run_marathon_evaluation.py --dry-run      # show attack sequence
"""

import argparse
import json
import logging
import os
import random
import re
import shutil
import signal
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# Schedule  (must sum to 12 h)
# ─────────────────────────────────────────────────────────────────────────────

PHASE1_DURATION_S  = 4 * 3600        #  4 h — calibration (full-mode)
PHASE2_DURATION_S  = 3 * 3600        #  3 h — CausalTrace attack eval (full-mode)
PHASE3_DURATION_S  = int(2.5 * 3600) # 2.5 h — Falco (full-mode)
PHASE4_DURATION_S  = int(2.5 * 3600) # 2.5 h — Tetragon (full-mode)
# Full-mode total: 12 h.

# FAST-mode (default) compressed durations for deadline runs.
FAST_PHASE1_DURATION_S = 60 * 60     # 60 min calibration — enough for 20-edge mesh
# Phase 2/3/4 durations in fast mode are derived from sequence length ×
# (FAST_INTERVAL_S + ~3s scenario runtime). No need for hard caps.

# ─────────────────────────────────────────────────────────────────────────────
# Attack sequence — ONE fixed random permutation of 150 attacks, replayed per tool.
# Covers every non-OOD attack type with randomly-drawn but seed-fixed counts.
# S11 (fileless memfd) is OOD and injected at fixed offsets inside every tool's replay.
# ─────────────────────────────────────────────────────────────────────────────

NUM_ATTACKS    = 150     # total non-OOD attacks per tool replay
S11_INJECTIONS = 5       # S11 fileless OOD instances per tool replay
ATTACK_MEAN_S  = 90.0    # Poisson mean inter-attack gap (non-fast mode)
ATTACK_MIN_S   = 45.0
ATTACK_MAX_S   = 200.0

# Fast mode (--fast): compressed fixed-gap schedule — default for deadline runs.
# 150 attacks × 20s + 5 S11 × ~5s each ≈ 52 min per tool; 4 tools ≈ 3.5 h + calibration.
FAST_INTERVAL_S   = 20.0
FAST_NUM_ATTACKS  = 150
FAST_MODE         = True   # default True; --no-fast flips it off for the full-length run

# ─────────────────────────────────────────────────────────────────────────────
# Traffic constants
# ─────────────────────────────────────────────────────────────────────────────

# Dense calibration wrk: high concurrency to saturate all edges
WRK_CAL_THREADS     = 8
WRK_CAL_CONNECTIONS = 50
# Background attack-phase wrk: lighter — just keep edges warm
WRK_ATK_THREADS     = 4
WRK_ATK_CONNECTIONS = 20

WRK_TARGETS = [
    "http://localhost:8080/",   # nginx-lb on host
]

# ─────────────────────────────────────────────────────────────────────────────
# Production container names and IPs
# ─────────────────────────────────────────────────────────────────────────────

C_NGINX    = "ct-nginx"
C_WEBAPP_A = "ct-webapp-a"
C_WEBAPP_B = "ct-webapp-b"
C_API_GW   = "ct-api-gw"
C_PRODUCT  = "ct-product"
C_INVENTORY= "ct-inventory"
C_ORDER    = "ct-order"
C_PAYMENT  = "ct-payment"
C_USER     = "ct-user"
C_NOTIF    = "ct-notification"
C_POSTGRES = "ct-postgres"
C_REDIS    = "ct-redis"
C_CART     = "ct-cart"
C_AUTH     = "ct-auth"
C_SEARCH   = "ct-search"
C_ANALYTICS= "ct-analytics"
C_LOGGER   = "ct-logger"
C_METRICS  = "ct-metrics"
C_PROM     = "ct-prometheus"
C_GRAFANA  = "ct-grafana"
C_ATTACKER = "ct_attacker"

# IPs — ct_prod_net is 10.88.0.0/24, ct_attack_net is 10.88.1.0/24.
IP_NGINX    = "10.88.0.10"
IP_WEBAPP_A = "10.88.0.11"
IP_WEBAPP_B = "10.88.0.12"
IP_API_GW   = "10.88.0.13"
IP_PRODUCT  = "10.88.0.14"
IP_INVENTORY= "10.88.0.15"
IP_ORDER    = "10.88.0.16"
IP_PAYMENT  = "10.88.0.17"
IP_USER     = "10.88.0.18"
IP_NOTIF    = "10.88.0.19"
IP_REDIS    = "10.88.0.20"
IP_POSTGRES = "10.88.0.21"
IP_CART     = "10.88.0.22"
IP_AUTH     = "10.88.0.23"
IP_SEARCH   = "10.88.0.24"
IP_ANALYTICS= "10.88.0.25"
IP_LOGGER   = "10.88.0.26"
IP_METRICS  = "10.88.0.27"
IP_PROM     = "10.88.0.28"
IP_GRAFANA  = "10.88.0.29"
IP_ATTACKER = "10.88.1.100"
HOST_IP     = "10.88.0.1"

# ─────────────────────────────────────────────────────────────────────────────
# Tool paths
# ─────────────────────────────────────────────────────────────────────────────

FALCO_BIN         = "/usr/bin/falco"
FALCO_RULES_STOCK = "/etc/falco/falco_rules.yaml"
FALCO_RULES_TUNED = "/etc/falco/falco_rules.local.yaml"
TETRAGON_IMAGE    = "quay.io/cilium/tetragon-ci:latest"

# ─────────────────────────────────────────────────────────────────────────────
# Output paths
# ─────────────────────────────────────────────────────────────────────────────

# Always resolve relative to this script's location, regardless of CWD
_REPO = Path(__file__).resolve().parent
MARATHON_DIR       = _REPO / "results" / "marathon"
STATE_FILE         = MARATHON_DIR / "state.json"
ATTACKS_LOG        = MARATHON_DIR / "attacks.jsonl"
METRICS_LOG        = MARATHON_DIR / "metrics.jsonl"
DETECTION_TIMELINE = MARATHON_DIR / "detection_timeline.json"
CAL_TRAFFIC_LOG    = MARATHON_DIR / "calibration_traffic.log"

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────

def setup_logging():
    MARATHON_DIR.mkdir(parents=True, exist_ok=True)
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    fh = RotatingFileHandler(
        MARATHON_DIR / "marathon.log",
        maxBytes=20 * 1024 * 1024, backupCount=5,
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))

    root.addHandler(fh)
    root.addHandler(ch)

log = logging.getLogger("marathon")

# ─────────────────────────────────────────────────────────────────────────────
# State management
# ─────────────────────────────────────────────────────────────────────────────

def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            pass
    return {"completed_phases": [], "attack_sequence": []}

def save_state(state: dict):
    STATE_FILE.write_text(json.dumps(state, indent=2))

# ─────────────────────────────────────────────────────────────────────────────
# Subprocess helpers
# ─────────────────────────────────────────────────────────────────────────────

def _kill_proc(p):
    if p and p.poll() is None:
        try:
            p.terminate()
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait(timeout=5)
        except Exception:
            pass

def _docker_exec(container: str, cmd: str, timeout: int = 10) -> subprocess.CompletedProcess:
    full = ["docker", "exec", container, "sh", "-c", cmd]
    try:
        return subprocess.run(full, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(full, -1, "", "TIMEOUT")
    except Exception as e:
        return subprocess.CompletedProcess(full, -1, "", str(e))

def _docker_exec_bg(container: str, cmd: str):
    full = ["docker", "exec", "-d", container, "sh", "-c", cmd]
    try:
        return subprocess.Popen(full, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        return None

# ─────────────────────────────────────────────────────────────────────────────
# Dense calibration traffic
# ─────────────────────────────────────────────────────────────────────────────

# Inline Lua script for wrk — randomises path + User-Agent to mimic browser traffic
_WRK_LUA = """
local user_agents = {
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
  "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
  "python-requests/2.31.0",
  "Go-http-client/1.1",
}
local paths = {"/", "/health", "/api/status", "/metrics", "/favicon.ico"}
math.randomseed(os.time())
request = function()
  local ua = user_agents[math.random(#user_agents)]
  local path = paths[math.random(#paths)]
  wrk.headers["User-Agent"] = ua
  return wrk.format("GET", path)
end
"""

def _write_wrk_lua(path: Path):
    path.write_text(_WRK_LUA)

def _start_wrk(target: str, threads: int, conns: int, duration_s: int,
               lua_script: Path = None) -> subprocess.Popen:
    cmd = ["wrk", f"-t{threads}", f"-c{conns}", f"-d{duration_s}s",
           "--timeout", "5s"]
    if lua_script and lua_script.exists():
        cmd += ["-s", str(lua_script)]
    cmd.append(target)
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# Edge-exercise patterns: each tuple is (container, shell-command)
# Covers ALL calibrated edges so restriction maps are learned for each.
_EDGE_PATTERNS = [
    # nginx front-door (host-exposed) — warms the browser-edge
    (None,          f"curl -s -A 'Mozilla/5.0' http://localhost:8080/ > /dev/null"),
    # nginx → webapp-a/b via container net
    (C_NGINX,       f"curl -s http://{IP_WEBAPP_A}:8080/ > /dev/null || true"),
    (C_NGINX,       f"curl -s http://{IP_WEBAPP_B}:8080/ > /dev/null || true"),
    # webapp → api-gw
    (C_WEBAPP_A,    f"curl -s http://{IP_API_GW}:8080/ > /dev/null || true"),
    (C_WEBAPP_B,    f"curl -s http://{IP_API_GW}:8080/ > /dev/null || true"),
    # api-gw → fanout
    (C_API_GW,      f"curl -s http://{IP_PRODUCT}:8080/ > /dev/null || true"),
    (C_API_GW,      f"curl -s http://{IP_ORDER}:8080/   > /dev/null || true"),
    (C_API_GW,      f"curl -s http://{IP_USER}:8080/    > /dev/null || true"),
    (C_API_GW,      f"curl -s http://{IP_CART}:8080/    > /dev/null || true"),
    (C_API_GW,      f"curl -s http://{IP_SEARCH}:8080/  > /dev/null || true"),
    (C_API_GW,      f"curl -s http://{IP_AUTH}:8080/    > /dev/null || true"),
    # order → payment, inventory, notification
    (C_ORDER,       f"curl -s http://{IP_PAYMENT}:8080/   > /dev/null || true"),
    (C_ORDER,       f"curl -s http://{IP_INVENTORY}:8080/ > /dev/null || true"),
    (C_ORDER,       f"curl -s http://{IP_NOTIF}:8080/     > /dev/null || true"),
    # data-layer: redis / postgres probes
    (C_PRODUCT,     f"nc -z -w1 {IP_REDIS} 6379    2>/dev/null || true"),
    (C_PRODUCT,     f"nc -z -w1 {IP_POSTGRES} 5432 2>/dev/null || true"),
    (C_CART,        f"nc -z -w1 {IP_REDIS} 6379    2>/dev/null || true"),
    (C_USER,        f"nc -z -w1 {IP_POSTGRES} 5432 2>/dev/null || true"),
    # observability fanout
    (C_LOGGER,      f"curl -s http://{IP_METRICS}:8080/   > /dev/null || true"),
    (C_METRICS,     f"curl -s http://{IP_PROM}:9090/      > /dev/null || true"),
    (C_PROM,        f"curl -s http://{IP_GRAFANA}:3000/   > /dev/null || true"),
    (C_ANALYTICS,   f"curl -s http://{IP_LOGGER}:8080/    > /dev/null || true"),
]

def _run_edge_patterns(log_fh, cycle: int):
    """Execute one round of edge patterns. Called every 2 seconds during calibration."""
    for container, cmd in _EDGE_PATTERNS:
        if container:
            r = _docker_exec(container, cmd, timeout=4)
        else:
            try:
                r = subprocess.run(["sh", "-c", cmd],
                                   capture_output=True, text=True, timeout=4)
            except Exception:
                r = None
        # Brief log every 100 cycles to avoid overwhelming the file
        if cycle % 100 == 0 and r is not None and log_fh:
            log_fh.write(f"[cycle {cycle}] {cmd[:60]} → rc={r.returncode}\n")

def _calibration_traffic_worker(duration_s: int, stop_event):
    """
    Background thread: run edge patterns on a tight 2-second loop for
    the full calibration window. This is the inner loop that exercises
    every inter-container edge so the sheaf CCA can learn restriction maps.
    """
    import threading
    t_end = time.monotonic() + duration_s
    cycle = 0
    log_fh = open(CAL_TRAFFIC_LOG, "w", buffering=1)
    log_fh.write(f"Calibration traffic started at {datetime.now().isoformat()}\n")
    log_fh.write(f"Duration: {duration_s}s ({duration_s//3600}h)\n")
    log_fh.write(f"Patterns per cycle: {len(_EDGE_PATTERNS)}\n\n")

    while not stop_event.is_set() and time.monotonic() < t_end:
        cycle += 1
        _run_edge_patterns(log_fh, cycle)

        # Every 30 cycles (~1 min): burst of 10 concurrent curl requests
        # to train CCA that bursts are normal (not anomalous)
        if cycle % 30 == 0:
            burst = [
                subprocess.Popen(["sh", "-c",
                    f"curl -s http://localhost:8080/ > /dev/null"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                for _ in range(10)
            ]
            for p in burst:
                try:
                    p.wait(timeout=5)
                except Exception:
                    p.kill()

        # Every 300 cycles (~10 min): log calibration heartbeat
        if cycle % 300 == 0:
            elapsed = duration_s - int(t_end - time.monotonic())
            log_fh.write(f"[{elapsed}s elapsed] cycle={cycle}\n")
            log_fh.flush()
            log.info(f"  Calibration traffic: cycle {cycle} | "
                     f"{int(t_end - time.monotonic())//60}m remaining")

        stop_event.wait(timeout=2.0)  # 2-second cycle

    log_fh.write(f"\nCalibration traffic ended. Total cycles: {cycle}\n")
    log_fh.close()

# ─────────────────────────────────────────────────────────────────────────────
# Background HTTP traffic (used during attack phases to keep edges warm)
# ─────────────────────────────────────────────────────────────────────────────

def start_background_traffic(duration_s: int, threads: int, conns: int) -> list:
    procs = []
    lua = MARATHON_DIR / "wrk_random.lua"
    _write_wrk_lua(lua)

    if shutil.which("wrk"):
        for target in WRK_TARGETS:
            p = _start_wrk(target, threads, conns, duration_s, lua)
            procs.append(p)
            log.info(f"wrk → {target}  t={threads} c={conns} d={duration_s}s  pid={p.pid}")
    else:
        log.warning("wrk not found — falling back to generate_prod_traffic.sh")

    # Always run the inter-service curl script too — keeps internal edges warm
    p = subprocess.Popen(
        ["bash", "testbed-production/generate_prod_traffic.sh", str(duration_s)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    procs.append(p)
    return procs

def stop_background_traffic(procs: list):
    for p in procs:
        _kill_proc(p)

# ─────────────────────────────────────────────────────────────────────────────
# Metrics sampling
# ─────────────────────────────────────────────────────────────────────────────

_last_cpu_idle  = None
_last_cpu_total = None

def sample_metrics(phase: str) -> dict:
    global _last_cpu_idle, _last_cpu_total
    m = {"ts": time.time(), "phase": phase}
    try:
        parts = Path("/proc/stat").read_text().splitlines()[0].split()
        vals  = [int(x) for x in parts[1:]]
        total = sum(vals)
        idle  = vals[3] + vals[4]
        if _last_cpu_total is not None:
            dt = total - _last_cpu_total
            di = idle  - _last_cpu_idle
            m["cpu_util"] = round(1.0 - di / max(dt, 1), 4)
        _last_cpu_total = total
        _last_cpu_idle  = idle
    except Exception:
        pass
    try:
        info = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            p = line.split()
            if len(p) >= 2:
                info[p[0].rstrip(":")] = int(p[1])
        total_kb = info.get("MemTotal", 1)
        avail_kb = info.get("MemAvailable", total_kb)
        m["mem_util"]     = round(1.0 - avail_kb / total_kb, 4)
        m["mem_avail_mb"] = avail_kb // 1024
    except Exception:
        pass
    return m

def metrics_loop(phase: str, interval: int, stop_event):
    fh = open(METRICS_LOG, "a", buffering=1)
    while not stop_event.is_set():
        fh.write(json.dumps(sample_metrics(phase)) + "\n")
        stop_event.wait(timeout=interval)
    fh.close()

# ─────────────────────────────────────────────────────────────────────────────
# Tool process managers
# ─────────────────────────────────────────────────────────────────────────────

class LoaderProcess:
    def __init__(self, mode: str, log_path: Path, results_dir: Path):
        self.mode = mode
        self.log_path = log_path
        self.results_dir = results_dir
        self.proc = None
        self._log_fh = None

    def start(self):
        env = os.environ.copy()
        signals_log = str(self.results_dir / "signals.jsonl")
        env["CAUSALTRACE_SIGNAL_LOG"]  = signals_log
        env["CAUSALTRACE_RESULTS_DIR"] = str(self.results_dir)

        loader = str(_REPO / "loader.py")
        # loader.py --mode only accepts monitor/enforce; --calibrate is a separate flag
        if self.mode == "calibrate":
            cmd = [sys.executable, loader, "--mode", "monitor", "--calibrate"]
        else:
            cmd = [sys.executable, loader, "--mode", self.mode]

        self._log_fh = open(self.log_path, "w", buffering=1)
        self.proc = subprocess.Popen(
            cmd,
            stdout=self._log_fh, stderr=subprocess.STDOUT,
            env=env, cwd=str(_REPO),   # always run from project root
        )
        log.info(f"Loader started  mode={self.mode}  pid={self.proc.pid}")

    def stop(self):
        _kill_proc(self.proc)
        if self._log_fh:
            self._log_fh.close()
        log.info("Loader stopped")

    def is_alive(self):
        return self.proc and self.proc.poll() is None


class FalcoProcess:
    def __init__(self, mode: str, output_path: Path):
        self.mode = mode
        self.output_path = output_path
        self.proc = None
        self._fh = None

    def start(self):
        rules = ["-r", FALCO_RULES_STOCK]
        if self.mode == "tuned":
            rules += ["-r", FALCO_RULES_TUNED]
        cmd = [FALCO_BIN,
               "-o", "engine.kind=modern_ebpf",
               "-o", "json_output=true",
               "-U"] + rules
        self._fh = open(self.output_path, "w", buffering=1)
        self.proc = subprocess.Popen(cmd, stdout=self._fh, stderr=subprocess.DEVNULL)
        log.info(f"Falco started  mode={self.mode}  pid={self.proc.pid}")
        time.sleep(4)   # allow eBPF programs to attach

    def stop(self):
        _kill_proc(self.proc)
        if self._fh:
            self._fh.close()
        log.info(f"Falco stopped  mode={self.mode}")

    def is_alive(self):
        return self.proc and self.proc.poll() is None


class TetragonProcess:
    def __init__(self, mode: str, output_path: Path, policy_dir: Path = None):
        self.mode = mode
        self.output_path = output_path
        self.policy_dir = policy_dir
        self.name = f"tetragon-marathon-{mode}"
        self._tail = None

    def start(self):
        subprocess.run(["docker", "rm", "-f", self.name], capture_output=True)
        # Use a host-mounted export dir so Tetragon writes events to a host file
        export_dir = self.output_path.parent
        export_dir.mkdir(parents=True, exist_ok=True)
        export_file_host = str(self.output_path)
        export_file_ctr = f"/export/{self.output_path.name}"
        mounts = [
            "--volume", "/sys/kernel/btf/vmlinux:/var/lib/tetragon/btf:ro",
            "--volume", "/proc:/proc:ro",
            "--volume", f"{export_dir}:/export",
        ]
        if self.mode == "tuned" and self.policy_dir and self.policy_dir.exists():
            mounts += ["--volume",
                       f"{self.policy_dir}:/etc/tetragon/tetragon.tp.d/:ro"]
        cmd = [
            "docker", "run", "--name", self.name, "--rm", "--detach",
            "--privileged", "--pid", "host", "--network", "host",
            *mounts,
            TETRAGON_IMAGE,
            "/usr/bin/tetragon",
            "--bpf-lib", "/var/lib/tetragon/",
            "--export-filename", export_file_ctr,
        ]
        subprocess.run(cmd, capture_output=True, check=False)
        time.sleep(8)   # allow eBPF programs to attach
        log.info(f"Tetragon started  mode={self.mode}  container={self.name}  export={export_file_host}")

    def stop(self):
        _kill_proc(self._tail)
        subprocess.run(["docker", "stop", self.name], capture_output=True)
        log.info(f"Tetragon stopped  mode={self.mode}")

    def is_alive(self):
        r = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", self.name],
            capture_output=True, text=True,
        )
        return r.stdout.strip() == "true"

# ─────────────────────────────────────────────────────────────────────────────
# CTEval Tetragon TracingPolicies
# ─────────────────────────────────────────────────────────────────────────────

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
        values:
        - "/etc/shadow"
        - "/etc/passwd"
        - "/proc/1/"
        - "/var/run/secrets"
""",
    "cteval-dup2-fd-redirect.yaml": """\
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: cteval-dup2-fd-redirect
spec:
  kprobes:
  - call: "__x64_sys_dup2"
    syscall: true
    args:
    - index: 1
      type: "int"
    selectors:
    - matchArgs:
      - index: 1
        operator: "InMap"
        values:
        - "0"
        - "1"
        - "2"
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
    "cteval-tcp-connect.yaml": """\
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: cteval-tcp-connect
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
""",
}

def write_tetragon_policies(policy_dir: Path):
    policy_dir.mkdir(parents=True, exist_ok=True)
    for fname, content in CTEVAL_POLICIES.items():
        (policy_dir / fname).write_text(content)
    log.info(f"Wrote {len(CTEVAL_POLICIES)} CTEval TracingPolicies → {policy_dir}")

# ─────────────────────────────────────────────────────────────────────────────
# Attack catalogue
# ─────────────────────────────────────────────────────────────────────────────

# Every non-OOD attack resolves to one of the scenario_*.sh scripts under attacks/.
# The scenario script handles its own target-container selection and payload.
# The "weight" column biases how many times this type appears in the 150-permutation.
ATTACK_CATALOGUE = [
    # (id,   weight, scenario script,                        display_name)
    ("S2",   3, "scenario_2_reverse_shell.sh",     "reverse_shell"),
    ("S2a",  2, "scenario_2a_evade.sh",            "revshell_evasion"),
    ("S3",   3, "scenario_3_sensitive_file.sh",    "sensitive_file"),
    ("S3a",  2, "scenario_3_evade.sh",             "sensfile_evasion"),
    ("S4",   2, "scenario_4_fork_bomb.sh",         "fork_bomb"),
    ("S5",   2, "scenario_5_ns_escape.sh",         "ns_escape"),
    ("S6",   2, "scenario_6_privesc.sh",           "privesc"),
    ("S7",   2, "scenario_7_cross_container.sh",   "cross_container"),
    ("S8",   2, "scenario_8_log4shell.sh",         "log4shell"),
    ("S9",   2, "scenario_9_ssrf_rce.sh",          "ssrf_rce"),
    ("S10",  1, "scenario_10_container_escape.sh", "container_escape"),
]

# S11 fileless OOD — injected at fixed offsets inside every tool's replay.
S11_SCRIPT = "scenario_11_fileless_memfd.sh"
S11_ID     = "S11"

_ATTACKS_DIR = _REPO / "attacks"

def _run_scenario_script(script_name: str, timeout: int = 60) -> subprocess.CompletedProcess:
    """Invoke one of the attacks/scenario_*.sh files. The scripts are self-contained:
    they pick their own target container and drive the payload end-to-end."""
    script_path = _ATTACKS_DIR / script_name
    cmd = ["bash", str(script_path)]
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, cwd=str(_REPO))
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, -1, "", "TIMEOUT")
    except Exception as e:
        return subprocess.CompletedProcess(cmd, -1, "", str(e))

def _inject_attack(attack_id: str, script: str) -> dict:
    ts = time.time()
    # S4 fork_bomb and S10 container_escape are potentially heavy; give them more slack.
    timeout = 90 if attack_id in ("S4", "S10", "S11") else 45
    r = _run_scenario_script(script, timeout=timeout)
    return {
        "ts_inject": ts,
        "attack_id": attack_id,
        "script":    script,
        "exit_code": r.returncode,
        "stderr_tail": (r.stderr or "")[-200:] if r.stderr else "",
    }

def generate_attack_sequence(n: int, seed: int = 42, fixed_delay: float = None,
                              s11_count: int = None) -> list:
    """
    Build ONE fixed random permutation of n non-OOD attacks covering every type
    in ATTACK_CATALOGUE with weight-biased random counts (every type gets ≥1).
    Then splice s11_count S11 OOD injections at evenly-spaced offsets.

    Returns a list of dicts: {attack_id, script, delay_s, is_ood}.
    Same seed → identical sequence across every tool replay (reproducibility).
    """
    rng = random.Random(seed)
    if s11_count is None:
        s11_count = S11_INJECTIONS

    ids     = [a[0] for a in ATTACK_CATALOGUE]
    weights = [a[1] for a in ATTACK_CATALOGUE]
    scripts = {a[0]: a[2] for a in ATTACK_CATALOGUE}

    # Weighted random counts per type, guaranteeing each type gets ≥1 slot.
    counts = {aid: 1 for aid in ids}
    remaining = n - len(ids)
    for _ in range(remaining):
        pick = rng.choices(ids, weights=weights, k=1)[0]
        counts[pick] += 1

    pool = []
    for aid, c in counts.items():
        pool.extend([aid] * c)
    rng.shuffle(pool)

    base = []
    for aid in pool:
        if fixed_delay is not None:
            delay = fixed_delay
        else:
            raw   = rng.expovariate(1.0 / ATTACK_MEAN_S)
            delay = max(ATTACK_MIN_S, min(ATTACK_MAX_S, raw))
        base.append({"attack_id": aid, "script": scripts[aid],
                     "delay_s": round(delay, 1), "is_ood": False})

    # Splice S11 at evenly-spaced offsets (avoid the first and last few slots).
    if s11_count > 0:
        span    = len(base)
        offsets = [int((i + 1) * span / (s11_count + 1)) for i in range(s11_count)]
        # Reverse order so earlier inserts don't shift later indices.
        for off in sorted(offsets, reverse=True):
            base.insert(off, {
                "attack_id": S11_ID,
                "script":    S11_SCRIPT,
                "delay_s":   round(fixed_delay if fixed_delay else 15.0, 1),
                "is_ood":    True,
            })
    return base

def run_attack_sequence(sequence: list, phase: str) -> list:
    injections = []
    fh = open(ATTACKS_LOG, "a", buffering=1)
    total = len(sequence)
    for i, atk in enumerate(sequence):
        tag = "OOD" if atk.get("is_ood") else "   "
        log.info(f"[{phase}] {i+1}/{total} {tag} {atk['attack_id']:4s} "
                 f"{atk['script']}  (wait {atk['delay_s']:.0f}s)")
        # Tag the verdicts daemon so it can label this injection window.
        try:
            Path("/tmp/causaltrace_current_scenario").write_text(
                atk["attack_id"].lstrip("S"))
        except Exception:
            pass
        time.sleep(atk["delay_s"])
        rec = _inject_attack(atk["attack_id"], atk["script"])
        rec["phase"]    = phase
        rec["seq_idx"]  = i
        rec["is_ood"]   = bool(atk.get("is_ood"))
        injections.append(rec)
        fh.write(json.dumps(rec) + "\n")
        try:
            Path("/tmp/causaltrace_current_scenario").write_text("0")
        except Exception:
            pass
    fh.close()
    return injections

# ─────────────────────────────────────────────────────────────────────────────
# Detection timeline
# ─────────────────────────────────────────────────────────────────────────────

def _parse_loader_alerts(path: Path) -> list:
    pat = re.compile(
        r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[.,]\d+).*\[ALERT\]\s+(\w+)")
    out = []
    try:
        for line in path.read_text(errors="ignore").splitlines():
            m = pat.search(line)
            if m:
                try:
                    ts = datetime.strptime(m.group(1)[:23],
                                           "%Y-%m-%d %H:%M:%S,%f").timestamp()
                except ValueError:
                    ts = 0.0
                out.append({"ts": ts, "type": m.group(2)})
    except Exception:
        pass
    return out

def _parse_verdicts(path: Path) -> list:
    out = []
    try:
        for line in path.read_text(errors="ignore").splitlines():
            try:
                v = json.loads(line)
            except Exception:
                continue
            if v.get("severity") in ("MEDIUM", "HIGH", "CRITICAL"):
                out.append({"ts": v.get("timestamp", 0),
                             "severity": v.get("severity"),
                             "label": v.get("label")})
    except Exception:
        pass
    return out

def _parse_falco(path: Path) -> list:
    out = []
    try:
        for line in path.read_text(errors="ignore").splitlines():
            if not line.startswith("{"):
                continue
            try:
                e = json.loads(line)
                # Falco timestamps are ISO strings; convert to epoch float
                t_str = e.get("time", "")
                ts = 0.0
                try:
                    from datetime import timezone
                    ts = datetime.fromisoformat(
                        t_str.rstrip("Z")).replace(tzinfo=timezone.utc).timestamp()
                except Exception:
                    pass
                out.append({"ts": ts, "rule": e.get("rule", "")})
            except Exception:
                pass
    except Exception:
        pass
    return out

def _parse_tetragon(path: Path) -> list:
    out = []
    try:
        for line in path.read_text(errors="ignore").splitlines():
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
                out.append({"ts": ts, "policy": pk.get("policy_name")})
    except Exception:
        pass
    return out

def build_detection_timeline(state: dict):
    WINDOW = 60.0   # look for detections up to 60s after injection

    injections = []
    try:
        for line in ATTACKS_LOG.read_text(errors="ignore").splitlines():
            try:
                injections.append(json.loads(line))
            except Exception:
                pass
    except Exception:
        pass

    ct_t1     = _parse_loader_alerts(MARATHON_DIR / "loader.log")
    ct_t3     = _parse_verdicts(MARATHON_DIR / "verdicts.jsonl")
    f_stock   = _parse_falco(MARATHON_DIR / "falco_stock.jsonl")
    f_tuned   = _parse_falco(MARATHON_DIR / "falco_tuned.jsonl")
    tet_tuned = _parse_tetragon(MARATHON_DIR / "tetragon_tuned.jsonl")

    def first_after(events, t0):
        for ev in sorted(events, key=lambda x: x.get("ts", 0)):
            et = ev.get("ts", 0)
            if t0 <= et <= t0 + WINDOW:
                return round(et - t0, 4)
        return None

    rows = []
    for inj in injections:
        t0    = inj.get("ts_inject", 0)
        phase = inj.get("phase", "")
        rows.append({
            "attack_id": inj.get("attack_id"),
            "phase":     phase,
            "ts_inject": t0,
            "is_ood":    inj.get("is_ood", False),
            "script":    inj.get("script"),
            "ct_tier1_latency_s":       first_after(ct_t1, t0),
            "ct_tier3_latency_s":       first_after(ct_t3, t0),
            "falco_stock_latency_s":    first_after(f_stock,  t0) if "falco_stock"  in phase else None,
            "falco_tuned_latency_s":    first_after(f_tuned,  t0) if "falco_tuned"  in phase else None,
            "tetragon_tuned_latency_s": first_after(tet_tuned, t0) if "tetragon_tuned" in phase else None,
        })

    out = {"generated_at": time.time(), "attacks": rows}
    DETECTION_TIMELINE.write_text(json.dumps(out, indent=2))
    log.info(f"Detection timeline → {DETECTION_TIMELINE}  ({len(rows)} rows)")

# ─────────────────────────────────────────────────────────────────────────────
# Phases
# ─────────────────────────────────────────────────────────────────────────────

def phase1_calibrate(state: dict):
    """
    Phase 1 — dense calibration. 60 min in fast mode, 4 h in full mode.

    Runs two parallel traffic workloads against the 20-container mesh:
      A) wrk HTTP flood to nginx:9080 and webapp-a:9081  (high-rate, random paths)
      B) Edge-pattern worker: docker-exec inter-service calls on a 2-second loop,
         covering every container→container edge that CCA needs to learn.
    """
    import threading
    duration_s = FAST_PHASE1_DURATION_S if FAST_MODE else PHASE1_DURATION_S
    log.info("=" * 70)
    log.info(f"PHASE 1: Dense Calibration — {duration_s//60} min")
    log.info(f"  wrk: {WRK_CAL_THREADS}t/{WRK_CAL_CONNECTIONS}c per target")
    log.info(f"  Edge patterns: {len(_EDGE_PATTERNS)} patterns × 2s cycle")
    log.info("=" * 70)

    stop_metrics = threading.Event()
    stop_traffic = threading.Event()
    threading.Thread(
        target=metrics_loop, args=("calibration", 15, stop_metrics), daemon=True
    ).start()

    # wrk flood
    lua = MARATHON_DIR / "wrk_random.lua"
    _write_wrk_lua(lua)
    wrk_procs = []
    if shutil.which("wrk"):
        for target in WRK_TARGETS:
            p = _start_wrk(target, WRK_CAL_THREADS, WRK_CAL_CONNECTIONS,
                           duration_s, lua)
            wrk_procs.append(p)
            log.info(f"  wrk → {target}  pid={p.pid}")
    else:
        log.warning("  wrk not found — using curl-only calibration traffic")

    # Edge-pattern worker thread
    threading.Thread(
        target=_calibration_traffic_worker,
        args=(duration_s, stop_traffic),
        daemon=True,
    ).start()

    # Start loader in calibrate mode
    loader = LoaderProcess(
        mode="calibrate",
        log_path=MARATHON_DIR / "loader_calibrate.log",
        results_dir=MARATHON_DIR / "calibration_out",
    )
    loader.start()

    # Progress ticker (every 15 min, or 5 min in fast mode)
    tick = 300 if FAST_MODE else 900
    t_end = time.time() + duration_s
    while time.time() < t_end:
        remaining = int(t_end - time.time())
        log.info(f"  Phase 1: {remaining // 60}m remaining …")
        time.sleep(min(tick, remaining + 1))

    loader.stop()
    stop_traffic.set()
    stop_metrics.set()
    for p in wrk_procs:
        _kill_proc(p)

    # Copy calibration artifacts to canonical location if they landed elsewhere
    cal_src = MARATHON_DIR / "calibration_out"
    cal_dst = Path("calibration")
    if cal_src.exists():
        for f in cal_src.iterdir():
            if f.is_file():
                shutil.copy2(f, cal_dst / f.name)
        log.info(f"  Calibration artifacts copied to {cal_dst}/")

    state["completed_phases"].append("phase1")
    state["phase1_end_ts"] = time.time()
    save_state(state)
    log.info("Phase 1 complete.")


def phase2_causaltrace_attack(state: dict):
    """Phase 2 — CausalTrace attack evaluation."""
    import threading
    n_atk = FAST_NUM_ATTACKS if FAST_MODE else NUM_ATTACKS
    delay  = FAST_INTERVAL_S if FAST_MODE else None
    dur_s  = int(n_atk * (FAST_INTERVAL_S + 3)) if FAST_MODE else PHASE2_DURATION_S
    label  = f"~{dur_s//60}m / {n_atk} attacks @{FAST_INTERVAL_S:.0f}s" if FAST_MODE else f"3h / {n_atk} attacks"
    log.info("=" * 70)
    log.info(f"PHASE 2: CausalTrace Attack Evaluation  ({label})")
    log.info("=" * 70)

    seq_key = "attack_sequence_fast" if FAST_MODE else "attack_sequence"
    if not state.get(seq_key):
        state[seq_key] = generate_attack_sequence(n_atk, seed=99 if FAST_MODE else 42,
                                                  fixed_delay=delay)
        save_state(state)
    seq = state[seq_key]

    stop_metrics = threading.Event()
    threading.Thread(
        target=metrics_loop, args=("causaltrace_attack", 15, stop_metrics), daemon=True
    ).start()

    traffic_procs = start_background_traffic(
        dur_s, WRK_ATK_THREADS, WRK_ATK_CONNECTIONS
    )

    loader = LoaderProcess(
        mode="monitor",
        log_path=MARATHON_DIR / "loader.log",
        results_dir=MARATHON_DIR / ("results_fast" if FAST_MODE else "results"),
    )
    loader.start()
    time.sleep(8)   # BPF warmup

    state["phase2_start_ts"] = time.time()
    save_state(state)

    run_attack_sequence(seq, phase="causaltrace")

    loader.stop()
    stop_background_traffic(traffic_procs)
    stop_metrics.set()

    state["completed_phases"].append("phase2")
    state["phase2_end_ts"] = time.time()
    save_state(state)
    log.info("Phase 2 complete.")


def phase3_falco(state: dict):
    """Phase 3 — Falco evaluation. Stock AND tuned each replay the FULL sequence."""
    import threading
    delay = FAST_INTERVAL_S if FAST_MODE else None
    slot_s = int((NUM_ATTACKS + S11_INJECTIONS) * (FAST_INTERVAL_S + 3)) \
             if FAST_MODE else PHASE3_DURATION_S // 2
    log.info("=" * 70)
    log.info(f"PHASE 3: Falco Evaluation  (stock + tuned, full replay each)")
    log.info("=" * 70)

    seq_key  = "attack_sequence_fast" if FAST_MODE else "attack_sequence"
    base_seq = state.get(seq_key) or generate_attack_sequence(
        NUM_ATTACKS, seed=99 if FAST_MODE else 42, fixed_delay=delay)
    seq = [{**a, "delay_s": FAST_INTERVAL_S} for a in base_seq] if FAST_MODE else base_seq

    for mode, out_path in [
        ("stock", MARATHON_DIR / "falco_stock.jsonl"),
        ("tuned", MARATHON_DIR / "falco_tuned.jsonl"),
    ]:
        sub_seq = seq
        log.info(f"  Falco {mode}: {len(sub_seq)} attacks over {slot_s//60}m")
        stop_metrics = threading.Event()
        threading.Thread(
            target=metrics_loop, args=(f"falco_{mode}", 30, stop_metrics), daemon=True
        ).start()

        traffic_procs = start_background_traffic(
            slot_s, WRK_ATK_THREADS, WRK_ATK_CONNECTIONS
        )
        falco = FalcoProcess(mode=mode, output_path=out_path)
        falco.start()

        run_attack_sequence(sub_seq, phase=f"falco_{mode}")

        falco.stop()
        stop_background_traffic(traffic_procs)
        stop_metrics.set()

    state["completed_phases"].append("phase3")
    state["phase3_end_ts"] = time.time()
    save_state(state)
    log.info("Phase 3 complete.")


def phase4_tetragon(state: dict):
    """Phase 4 — Tetragon evaluation. Stock AND tuned each replay the FULL sequence."""
    import threading
    delay = FAST_INTERVAL_S if FAST_MODE else None
    slot_s = int((NUM_ATTACKS + S11_INJECTIONS) * (FAST_INTERVAL_S + 3)) \
             if FAST_MODE else PHASE4_DURATION_S // 2
    log.info("=" * 70)
    log.info(f"PHASE 4: Tetragon Evaluation  (stock + tuned, full replay each)")
    log.info("=" * 70)

    seq_key  = "attack_sequence_fast" if FAST_MODE else "attack_sequence"
    base_seq = state.get(seq_key) or generate_attack_sequence(
        NUM_ATTACKS, seed=99 if FAST_MODE else 42, fixed_delay=delay)
    seq = [{**a, "delay_s": FAST_INTERVAL_S} for a in base_seq] if FAST_MODE else base_seq

    policy_dir = MARATHON_DIR / "tetragon_policies"
    write_tetragon_policies(policy_dir)

    for mode, out_path, use_pol in [
        ("stock", MARATHON_DIR / "tetragon_stock.jsonl", False),
        ("tuned", MARATHON_DIR / "tetragon_tuned.jsonl", True),
    ]:
        sub_seq = seq
        log.info(f"  Tetragon {mode}: {len(sub_seq)} attacks over {slot_s//60}m")
        stop_metrics = threading.Event()
        threading.Thread(
            target=metrics_loop, args=(f"tetragon_{mode}", 30, stop_metrics), daemon=True
        ).start()

        traffic_procs = start_background_traffic(
            slot_s, WRK_ATK_THREADS, WRK_ATK_CONNECTIONS
        )
        tetragon = TetragonProcess(
            mode=mode,
            output_path=out_path,
            policy_dir=policy_dir if use_pol else None,
        )
        tetragon.start()

        run_attack_sequence(sub_seq, phase=f"tetragon_{mode}")

        tetragon.stop()
        stop_background_traffic(traffic_procs)
        stop_metrics.set()

    state["completed_phases"].append("phase4")
    state["phase4_end_ts"] = time.time()
    save_state(state)
    log.info("Phase 4 complete.")

# ─────────────────────────────────────────────────────────────────────────────
# Preflight
# ─────────────────────────────────────────────────────────────────────────────

def preflight() -> bool:
    ok = True
    if os.geteuid() != 0:
        log.error("Must run as root:  sudo python3 run_marathon_evaluation.py")
        ok = False

    r = subprocess.run(
        ["docker", "ps", "--filter", f"name={C_WEBAPP_A}", "--format", "{{.Names}}"],
        capture_output=True, text=True,
    )
    if C_WEBAPP_A not in r.stdout:
        log.error(f"Testbed not running. cd testbed-production && docker compose up -d")
        ok = False
    else:
        log.info(f"  Testbed: {C_WEBAPP_A} running ✓")

    if not Path(FALCO_BIN).exists():
        log.error(f"Falco not found at {FALCO_BIN}")
        ok = False
    else:
        log.info(f"  Falco: {FALCO_BIN} ✓")

    r = subprocess.run(["docker", "images", "-q", TETRAGON_IMAGE],
                       capture_output=True, text=True)
    if not r.stdout.strip():
        log.error(f"Tetragon image missing: docker pull {TETRAGON_IMAGE}")
        ok = False
    else:
        log.info(f"  Tetragon image: present ✓")

    if shutil.which("wrk"):
        log.info(f"  wrk: found ✓")
    else:
        log.warning("  wrk: NOT found — calibration will use curl fallback (slower)")

    return ok

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    setup_logging()
    MARATHON_DIR.mkdir(parents=True, exist_ok=True)

    parser = argparse.ArgumentParser(description="CausalTrace 12-hour Marathon")
    parser.add_argument("--phase", type=int, default=0,
                        help="Run only this phase (1–4). Default: all.")
    parser.add_argument("--start-phase", type=int, default=1,
                        help="Start from this phase (skip earlier phases). Default: 1.")
    parser.add_argument("--resume", action="store_true",
                        help="Skip phases listed in state.json as completed.")
    parser.add_argument("--no-preflight", action="store_true")
    parser.add_argument("--fast", action="store_true",
                        help=f"Fast mode (default): {FAST_INTERVAL_S:.0f}s fixed gaps, "
                             f"{FAST_NUM_ATTACKS} attacks + {S11_INJECTIONS} S11 OOD per tool.")
    parser.add_argument("--no-fast", action="store_true",
                        help="Disable fast mode — use full-length Poisson schedule.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print schedule and attack sequence, then exit.")
    args = parser.parse_args()

    global FAST_MODE
    if args.fast:
        FAST_MODE = True
    if getattr(args, "no_fast", False):
        FAST_MODE = False
    log.info(f"MODE: {'FAST' if FAST_MODE else 'FULL'}  "
             f"{FAST_INTERVAL_S:.0f}s gaps, {FAST_NUM_ATTACKS} attacks/tool + "
             f"{S11_INJECTIONS} S11 OOD")

    # ── Dry run ────────────────────────────────────────────────────────────
    if args.dry_run:
        if FAST_MODE:
            per_tool_min = (NUM_ATTACKS + S11_INJECTIONS) * (FAST_INTERVAL_S + 3) / 60
            cal_min      = FAST_PHASE1_DURATION_S / 60
            total_h      = (cal_min + per_tool_min * 5) / 60  # CT + Falco×2 + Tetragon×2
            print(f"FAST mode schedule  (~{total_h:.1f} h total):")
            print(f"  Phase 1  {cal_min:.0f} min calibration")
            print(f"  Phase 2  {per_tool_min:.0f} min  CausalTrace   ({NUM_ATTACKS}+{S11_INJECTIONS} OOD)")
            print(f"  Phase 3  {per_tool_min*2:.0f} min  Falco         (stock+tuned, full replay each)")
            print(f"  Phase 4  {per_tool_min*2:.0f} min  Tetragon      (stock+tuned, full replay each)")
        else:
            total_h = (PHASE1_DURATION_S + PHASE2_DURATION_S +
                       PHASE3_DURATION_S + PHASE4_DURATION_S) / 3600
            print(f"FULL mode schedule  ({total_h:.1f} h total):")
            print(f"  Phase 1  {PHASE1_DURATION_S//3600}h   calibration (dense traffic)")
            print(f"  Phase 2  {PHASE2_DURATION_S//3600}h   CausalTrace ({NUM_ATTACKS}+{S11_INJECTIONS} OOD)")
            print(f"  Phase 3  {PHASE3_DURATION_S/3600:.1f}h  Falco (stock+tuned replay)")
            print(f"  Phase 4  {PHASE4_DURATION_S/3600:.1f}h  Tetragon (stock+tuned replay)")
        print()
        seq = generate_attack_sequence(NUM_ATTACKS, seed=42,
                                       fixed_delay=FAST_INTERVAL_S if FAST_MODE else None)
        from collections import Counter
        counts = Counter(a["attack_id"] for a in seq)
        print(f"Attack sequence ({len(seq)} total, seed=42):")
        print(f"  Per-type counts: {dict(counts)}")
        for i, a in enumerate(seq[:20]):
            tag = "OOD" if a.get("is_ood") else "   "
            print(f"  {i+1:3d}. {tag} [{a['attack_id']:4s}] {a['script']:<36} wait={a['delay_s']:.0f}s")
        print(f"  ... ({len(seq)} total)")
        est_duration = sum(a["delay_s"] for a in seq) / 60
        print(f"\nEstimated attack phase duration: {est_duration:.1f} min / tool")
        sys.exit(0)

    # ── Header ─────────────────────────────────────────────────────────────
    log.info("=" * 70)
    log.info("CausalTrace 12-hour Marathon Evaluation")
    log.info(f"  Output : {MARATHON_DIR.absolute()}")
    log.info(f"  Start  : {datetime.now().isoformat()}")
    log.info(f"  Total  : {(PHASE1_DURATION_S+PHASE2_DURATION_S+PHASE3_DURATION_S+PHASE4_DURATION_S)/3600:.0f}h")
    log.info("=" * 70)

    if not args.no_preflight and not preflight():
        sys.exit(1)

    state = load_state()

    def should_run(n: int) -> bool:
        if args.phase and args.phase != n:
            return False
        if n < args.start_phase:
            log.info(f"Skipping phase {n} (--start-phase={args.start_phase})")
            return False
        name = f"phase{n}"
        if args.resume and name in state.get("completed_phases", []):
            log.info(f"Skipping phase {n} (already in state.json)")
            return False
        return True

    # Graceful shutdown
    def _shutdown(sig, frame):
        log.info("Interrupt — saving state and exiting")
        save_state(state)
        sys.exit(0)
    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    try:
        if should_run(1):
            phase1_calibrate(state)
        if should_run(2):
            phase2_causaltrace_attack(state)
        if should_run(3):
            phase3_falco(state)
        if should_run(4):
            phase4_tetragon(state)

        log.info("Building detection timeline …")
        build_detection_timeline(state)

        log.info("Running paper analysis …")
        subprocess.run(
            [sys.executable, str(_REPO / "scripts" / "paper_analysis.py")],
            check=False, cwd=str(_REPO),
        )

    except KeyboardInterrupt:
        save_state(state)

    log.info("Marathon complete.")
    log.info(f"All results in: {MARATHON_DIR.absolute()}")


if __name__ == "__main__":
    main()
