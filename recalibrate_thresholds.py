#!/usr/bin/env python3
"""
recalibrate_thresholds.py
─────────────────────────
Re-measures edge energy thresholds using L2 distance (not Mahalanobis).

WHY THIS IS NEEDED:
  calibrate.py saves restriction maps (F_u, F_v) but never saves edge_cov_inv.
  At runtime sheaf_detector.py falls back to L2 distance, but edge_thresholds.json
  and global_threshold.json were set using Mahalanobis units → wrong scale → FPR=100%.

WHAT THIS DOES (10 minutes, no re-training):
  1. Loads existing CCA matrices from calibration/restriction_maps.npz
  2. Runs background traffic (wrk) for COLLECT_S seconds with NO attacks
  3. Reads live signal vectors from the sheaf daemon via signals.jsonl
  4. Computes residuals F_u @ x_u - F_v @ x_v in L2 space
  5. Sets per-edge threshold = μ + 4σ of ||residual||²
  6. Sets global Rayleigh threshold = μ + 4σ of Rayleigh quotients
  7. Writes updated edge_thresholds.json and global_threshold.json

Run as: sudo python3 recalibrate_thresholds.py
"""
import subprocess, time, json, sys, os, signal, pickle
import numpy as np
from pathlib import Path

_REPO        = Path(__file__).resolve().parent
CAL_DIR      = _REPO / "calibration"
COLLECT_S    = 600        # 10 minutes of normal traffic
SIGMA_MULT   = 4.0        # μ + 4σ  (same as original calibration)
SIGNAL_LOG   = _REPO / "results" / "marathon" / "rethreshold_signals.jsonl"
LOADER_LOG   = _REPO / "results" / "marathon" / "rethreshold_loader.log"

WRK_BIN      = "wrk"
WRK_LUA      = str(_REPO / "results" / "marathon" / "wrk_random.lua")

def load_restriction_maps():
    """Load CCA matrices from calibration/restriction_maps.npz."""
    import json as _json
    with open(CAL_DIR / "calibrated_edges.json") as f:
        edges = _json.load(f)
    src_to_dst = {}
    for e in edges:
        s, d = int(e[0]), int(e[1])
        if s not in src_to_dst:
            src_to_dst[s] = d

    data = np.load(str(CAL_DIR / "restriction_maps.npz"))
    maps = {}
    groups = {}
    for k in data.files:
        parts = k.rsplit("_", 2)
        if len(parts) != 3:
            continue
        prefix, lag_str, side = parts
        if side not in ("u", "v"):
            continue
        try:
            lag = int(lag_str)
        except ValueError:
            continue
        pfx = prefix.split("_", 2)
        if len(pfx) < 2:
            continue
        try:
            src = int(pfx[1])
        except ValueError:
            continue
        groups.setdefault((src, lag), {})[side] = k

    for (src, lag), sides in groups.items():
        if "u" not in sides or "v" not in sides:
            continue
        dst = src_to_dst.get(src)
        if dst is None:
            continue
        maps[(src, dst, lag)] = (data[sides["u"]], data[sides["v"]])

    print(f"  Loaded {len(maps)} restriction maps: "
          f"{sorted(set((u,v) for u,v,_ in maps))}")
    return maps


def start_loader():
    env = os.environ.copy()
    env["CAUSALTRACE_SIGNAL_LOG"]  = str(SIGNAL_LOG)
    env["CAUSALTRACE_RESULTS_DIR"] = str(_REPO / "results" / "marathon" / "rethreshold_results")
    Path(env["CAUSALTRACE_RESULTS_DIR"]).mkdir(parents=True, exist_ok=True)
    log_fh = open(LOADER_LOG, "w", buffering=1)
    proc = subprocess.Popen(
        [sys.executable, str(_REPO / "loader.py"), "--mode", "monitor"],
        stdout=log_fh, stderr=subprocess.STDOUT,
        env=env, cwd=str(_REPO),
    )
    print(f"  Loader started pid={proc.pid}")
    return proc, log_fh


def start_wrk(duration_s):
    procs = []
    for port in [9080, 9081]:
        p = subprocess.Popen(
            [WRK_BIN, "-t4", "-c20", f"-d{duration_s}s",
             "--timeout", "5s", "-s", WRK_LUA,
             f"http://localhost:{port}/"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        procs.append(p)
    print(f"  wrk started (ports 9080+9081, {duration_s}s)")
    return procs


def collect_signals(duration_s):
    """Tail SIGNAL_LOG for duration_s, return list of records."""
    print(f"  Collecting {duration_s}s of signals …", flush=True)
    SIGNAL_LOG.unlink(missing_ok=True)
    deadline = time.monotonic() + duration_s
    records = []
    seen_bytes = 0
    last_print = time.monotonic()

    while time.monotonic() < deadline:
        if SIGNAL_LOG.exists():
            with open(SIGNAL_LOG) as fh:
                fh.seek(seen_bytes)
                for line in fh:
                    try:
                        records.append(json.loads(line))
                    except Exception:
                        pass
                seen_bytes = fh.tell()

        if time.monotonic() - last_print >= 60:
            elapsed = int(duration_s - (deadline - time.monotonic()))
            print(f"    {elapsed}s/{duration_s}s — {len(records)} records so far")
            last_print = time.monotonic()
        time.sleep(2)

    print(f"  Collected {len(records)} signal records")
    return records


def compute_thresholds(records, maps):
    """
    Compute L2-based per-edge thresholds and global Rayleigh threshold.
    Returns: edge_thresholds dict, global_threshold float, edge_cov_inv dict
    """
    edge_energies  = {}   # (u,v,lag) → list of L2 ||F_u x_u - F_v x_v||²
    rayleigh_vals  = []

    for rec in records:
        pc = rec.get("per_container", {})
        if not pc:
            continue
        signals = {int(k): np.array(v) for k, v in pc.items()}

        total_raw = 0.0
        x_global_parts = []

        calibrated_pairs = set((u, v) for (u, v, _) in maps)
        for (u, v) in calibrated_pairs:
            if u not in signals or v not in signals:
                continue
            x_u = signals[u]
            x_v = signals[v]
            max_e = 0.0
            for lag in [0, 1, 2]:
                if (u, v, lag) not in maps:
                    continue
                Fu, Fv = maps[(u, v, lag)]
                diff = Fu @ x_u - Fv @ x_v
                e = float(np.dot(diff, diff))   # L2
                edge_energies.setdefault((u, v, lag), []).append(e)
                if e > max_e:
                    max_e = e
            total_raw += max_e

        # Global Rayleigh
        for cg, x in signals.items():
            x_global_parts.append(x)
        if x_global_parts:
            x_global = np.concatenate(x_global_parts)
            x_norm_sq = float(np.dot(x_global, x_global))
            ray = total_raw / max(x_norm_sq, 1e-10)
            rayleigh_vals.append(ray)

    edge_thresholds = {}
    for (u, v, lag), energies in edge_energies.items():
        arr = np.array(energies)
        tau = float(arr.mean() + SIGMA_MULT * arr.std())
        edge_thresholds[(u, v, lag)] = tau
        print(f"    edge ({u},{v}) lag={lag}: n={len(arr)} "
              f"μ={arr.mean():.2f} σ={arr.std():.2f} τ={tau:.2f}")

    if rayleigh_vals:
        arr = np.array(rayleigh_vals)
        global_tau = float(arr.mean() + SIGMA_MULT * arr.std())
        print(f"    global Rayleigh: n={len(arr)} "
              f"μ={arr.mean():.4f} σ={arr.std():.4f} τ={global_tau:.4f}")
    else:
        global_tau = 1.0
        print("  WARNING: no Rayleigh values — defaulting to 1.0")

    # edge_cov_inv: identity matrix in L2 space (no Mahalanobis)
    edge_cov_inv = {}
    for key in maps:
        u, v, lag = key
        Fu, _ = maps[key]
        d = Fu.shape[0]
        edge_cov_inv[key] = np.eye(d)   # identity = pure L2

    return edge_thresholds, global_tau, edge_cov_inv


def save_thresholds(edge_thresholds, global_tau, edge_cov_inv):
    """Update calibration files with L2-based thresholds."""
    # edge_thresholds.json
    with open(CAL_DIR / "edge_thresholds.json", "w") as f:
        json.dump({str(k): v for k, v in edge_thresholds.items()}, f)
    print(f"  Wrote edge_thresholds.json ({len(edge_thresholds)} entries)")

    # global_threshold.json
    with open(CAL_DIR / "global_threshold.json", "w") as f:
        json.dump({"global": global_tau}, f)
    print(f"  Wrote global_threshold.json  τ={global_tau:.6f}")

    # edge_cov_inv.npz  (save identity matrices so daemon can load them)
    inv_data = {}
    for (u, v, lag), mat in edge_cov_inv.items():
        inv_data[f"COV_{u}_{v}_{lag}"] = mat
    np.savez(str(CAL_DIR / "edge_cov_inv.npz"), **inv_data)
    print(f"  Wrote edge_cov_inv.npz ({len(inv_data)} entries)")


def main():
    print("=" * 60)
    print("CausalTrace — Re-threshold (L2 space, 10-min baseline)")
    print("=" * 60)

    # Step 1: Load existing CCA matrices
    print("\n[1/4] Loading existing restriction maps …")
    maps = load_restriction_maps()
    if not maps:
        print("ERROR: no restriction maps found — run calibration first")
        sys.exit(1)

    # Step 2: Start loader + wrk
    print("\n[2/4] Starting loader and background traffic …")
    loader_proc, loader_fh = start_loader()
    time.sleep(10)   # BPF warmup
    wrk_procs = start_wrk(COLLECT_S + 30)

    # Step 3: Collect signals
    print(f"\n[3/4] Collecting {COLLECT_S}s of normal-traffic signals …")
    try:
        records = collect_signals(COLLECT_S)
    finally:
        loader_proc.terminate()
        try:
            loader_proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            loader_proc.kill()
        loader_fh.close()
        for p in wrk_procs:
            p.terminate()

    if len(records) < 20:
        print(f"ERROR: only {len(records)} records — need more signal data")
        sys.exit(1)

    # Step 4: Compute thresholds
    print("\n[4/4] Computing L2-based thresholds …")
    edge_thresholds, global_tau, edge_cov_inv = compute_thresholds(records, maps)

    if not edge_thresholds:
        print("ERROR: no edge thresholds computed — check cgroup ID alignment")
        sys.exit(1)

    save_thresholds(edge_thresholds, global_tau, edge_cov_inv)

    print("\n✓ Re-threshold complete. Calibration files updated.")
    print(f"  global_threshold = {global_tau:.6f}  (was 0.171234)")
    print("  Now restart marathon: sudo python3 run_marathon_evaluation.py --fast --start-phase 2")


if __name__ == "__main__":
    main()
