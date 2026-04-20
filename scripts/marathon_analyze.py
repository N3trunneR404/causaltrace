#!/usr/bin/env python3
# scripts/marathon_analyze.py
"""
A*-grade analyzer for the fresh-run marathon.

Consumes the artifacts that `scripts/marathon.sh` writes:
  marathon.log               (not parsed)
  state.json                 stage progress
  calibration_validation.txt (opaque; recorded in summary)
  e1_fpr.jsonl               E1 — 2h normal-traffic baseline
  e2_verdicts.jsonl          E2 — CausalTrace verdicts during attacks
  e2_injections.ndjson       E2 — per-injection tag + t_inject + scenario
  e4_overhead.ndjson         E4 — 5×5min syscall throughput, 2 modes
  e5_ood.jsonl, e5_injections.ndjson                 E5
  falco_stock.jsonl / e6a_injections.ndjson          E6a
  tetragon_stock.jsonl / e6b_injections.ndjson       E6b

Emits (under --dir):
  marathon_summary.json         canonical, used by plot scripts
  detection_rate.csv            per-scenario rate + Wilson 95% CI
  ttk_percentiles.csv           per-scenario p50/p95/p99 + mean
  fpr.csv                       FPR headline + Wilson CI
  overhead.csv                  per-mode rate + stdev
  overhead_ttest.json           Welch's t-test on (off vs on) with Cohen's d
  baseline_comparison.csv       per-tool detection rate + Wilson CI on SAME attacks
  per_scenario_baseline.csv     long-format: (scenario, tool, rate, ci_low, ci_high)

Confidence intervals:
  - Wilson 95% CI for binomial proportions (detection rates, FPR).
    Exact binomial would be more conservative but unnecessary at n=150.
  - Welch's t-test for overhead because the two samples are
    independent (daemon off vs on) and variances may differ.

Everything is defensive: any missing file yields `present=false` in
the summary instead of a crash — so partial marathons (--only=E2)
still produce useful output.
"""

import argparse
import csv
import json
import math
import statistics
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# ── Scenario metadata ────────────────────────────────────────────────
SCENARIO_LABELS = {
    1: "Normal",           2: "ReverseShell",
    3: "SensitiveFile",    4: "ForkBomb",
    5: "NamespaceEscape",  6: "PrivEsc",
    7: "CrossContainer",   8: "Log4Shell",
    9: "SSRFtoRCE",       10: "ContainerEscape",
    11: "FilelessMemfd",
}

# Substring needles used to match verdicts to scenarios. These mirror
# the ones in minirun.sh; update both if you rename semantic labels.
SCENARIO_NEEDLES = {
    1:  None,
    2:  "fd_redirect",
    3:  "sensitive",
    4:  "fork_bomb",
    5:  "unshare",
    6:  "privesc",
    7:  "two_hop",
    8:  "log4shell",
    9:  "ssrf",
    10: "escape",
    11: "fileless",
}

# Secondary substrings — some scenarios trip multiple invariants and
# any of these substrings in label/reason is a valid match.
SCENARIO_ALT = {
    8:  {"fd_redirect"},            # Log4Shell stage-2 is a reverse shell
    9:  {"novel_edge", "fd_redirect"},
    10: {"unshare", "mount", "bpf", "memfd"},
    11: {"memfd"},
}

DETECT_WINDOW_S = 20.0     # cushion beyond marathon.sh's 18s sleep


# ── Statistical helpers ──────────────────────────────────────────────
def wilson_ci(k: int, n: int, z: float = 1.959963984540054) -> Tuple[float, float]:
    """
    Wilson score 95% CI for a binomial proportion.
    Collapses to (0, 0) when n = 0 so callers don't special-case it.
    """
    if n <= 0:
        return (0.0, 0.0)
    p = k / n
    denom  = 1.0 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half   = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def welch_t(x: List[float], y: List[float]) -> Dict[str, Any]:
    """Welch's two-sample t-test. Returns t, dof, p (two-sided) and Cohen's d."""
    nx, ny = len(x), len(y)
    if nx < 2 or ny < 2:
        return {"t": None, "dof": None, "p_two_sided": None, "cohen_d": None}
    mx, my = statistics.fmean(x), statistics.fmean(y)
    vx = statistics.variance(x) if nx > 1 else 0.0
    vy = statistics.variance(y) if ny > 1 else 0.0
    se = math.sqrt(vx / nx + vy / ny) if (vx or vy) else 0.0
    if se == 0.0:
        return {"t": None, "dof": None, "p_two_sided": None, "cohen_d": None}
    t = (mx - my) / se
    # Welch–Satterthwaite
    num = (vx / nx + vy / ny) ** 2
    den = ((vx / nx) ** 2) / max(nx - 1, 1) + ((vy / ny) ** 2) / max(ny - 1, 1)
    dof = num / den if den else nx + ny - 2
    # Two-sided p from Student-t CDF via regularized incomplete beta.
    # math.erfc is good enough for large dof; for dof < 30 we use the
    # approximation p ≈ erfc(|t|/sqrt(2)) which is exact in the normal
    # limit. The paper reports exact p via scipy if available.
    try:
        from scipy import stats  # type: ignore
        p = 2.0 * (1.0 - stats.t.cdf(abs(t), dof))
    except Exception:
        p = math.erfc(abs(t) / math.sqrt(2.0))
    pooled_sd = math.sqrt((vx * (nx - 1) + vy * (ny - 1)) / max(nx + ny - 2, 1))
    cohen_d = (mx - my) / pooled_sd if pooled_sd else None
    return {"t": t, "dof": dof, "p_two_sided": p, "cohen_d": cohen_d}


# ── Loaders ──────────────────────────────────────────────────────────
def _load_jsonl(path: Path) -> List[dict]:
    if not path.exists():
        return []
    out: List[dict] = []
    with path.open() as f:
        for ln in f:
            ln = ln.strip()
            if not ln:
                continue
            try:
                out.append(json.loads(ln))
            except Exception:
                pass
    return out


def _ts_of(v: dict) -> Optional[float]:
    for k in ("timestamp", "ts", "time", "output_fields"):
        val = v.get(k)
        if isinstance(val, (int, float)):
            return float(val)
    return None


def _matches(v: dict, sid: int) -> bool:
    needle = SCENARIO_NEEDLES.get(sid)
    alts   = SCENARIO_ALT.get(sid, set())
    if needle is None:
        return False
    # CausalTrace verdict format.
    action = v.get("action")
    if action is not None and action == "ALLOW":
        return False
    hay = ((v.get("label") or "") + " " + (v.get("reason") or "")
           + " " + (v.get("rule") or "")          # falco
           + " " + (v.get("process_exec") or "")  # tetragon coarse
          ).lower()
    if needle in hay:
        return True
    return any(alt in hay for alt in alts)


# ── Match injections to verdicts ─────────────────────────────────────
def match_injections(injections: List[dict], verdicts: List[dict]) -> Dict[int, Dict[str, Any]]:
    """
    For each injection, find the earliest matching verdict in its time
    window. Returns per-scenario {injections, hits, ttks}.
    """
    ts_vs = [(v, _ts_of(v)) for v in verdicts]
    ts_vs = [(v, t) for v, t in ts_vs if t is not None]
    per: Dict[int, Dict[str, Any]] = {}
    for inj in injections:
        sid = int(inj["scenario"])
        t0  = float(inj["t_inject"])
        d = per.setdefault(sid, {"injections": 0, "hits": 0, "ttks": []})
        d["injections"] += 1
        if SCENARIO_NEEDLES.get(sid) is None:
            continue
        for v, t in ts_vs:
            if t < t0 or t > t0 + DETECT_WINDOW_S:
                continue
            if _matches(v, sid):
                d["hits"] += 1
                d["ttks"].append(t - t0)
                break
    return per


# ── Stage analyzers ──────────────────────────────────────────────────
def analyze_e1(root: Path, duration_s: float = 7200.0) -> Dict[str, Any]:
    path = root / "e1_fpr.jsonl"
    entries = _load_jsonl(path)
    non_allow = [e for e in entries if e.get("action") != "ALLOW"]
    # "Cycles" = detection windows of ~5s; at 2h that's 1440. We express
    # FPR as alerts per hour and report CI on the per-cycle rate.
    cycles = int(duration_s / 5.0)
    fp = len(non_allow)
    ci_low, ci_high = wilson_ci(fp, cycles)
    return {
        "present":        path.exists(),
        "duration_s":     duration_s,
        "duration_hours": duration_s / 3600.0,
        "total_entries":  len(entries),
        "false_positives": fp,
        "fp_per_hour":    fp / max(duration_s / 3600.0, 1e-9),
        "wilson_ci_per_cycle": [ci_low, ci_high],
        "labels_seen":    sorted({e.get("label") for e in non_allow if e.get("label")}),
    }


def analyze_e2_e3(root: Path, attack_scenarios: List[int], n_injections: int) -> Dict[str, Any]:
    inj = _load_jsonl(root / "e2_injections.ndjson")
    vd  = _load_jsonl(root / "e2_verdicts.jsonl")
    if not inj:
        return {"present": False}
    per = match_injections(inj, vd)
    rows: List[Dict[str, Any]] = []
    total_inj = 0
    total_hit = 0
    for sid in attack_scenarios:
        d = per.get(sid, {"injections": 0, "hits": 0, "ttks": []})
        n = d["injections"]
        h = d["hits"]
        ci_low, ci_high = wilson_ci(h, n)
        ttks = sorted(d["ttks"])
        rows.append({
            "scenario_id":    sid,
            "scenario":       SCENARIO_LABELS.get(sid, str(sid)),
            "injections":     n,
            "hits":           h,
            "detection_rate": h / n if n else None,
            "ci_low":         ci_low,
            "ci_high":        ci_high,
            "ttk_p50":        statistics.median(ttks) if ttks else None,
            "ttk_p95":        ttks[int(0.95 * (len(ttks) - 1))] if ttks else None,
            "ttk_p99":        ttks[int(0.99 * (len(ttks) - 1))] if ttks else None,
            "ttk_mean":       statistics.fmean(ttks) if ttks else None,
        })
        total_inj += n
        total_hit += h
    overall_low, overall_high = wilson_ci(total_hit, total_inj)
    return {
        "present":        True,
        "rows":           rows,
        "total_injections": total_inj,
        "total_hits":       total_hit,
        "overall_rate":     total_hit / total_inj if total_inj else None,
        "overall_ci":       [overall_low, overall_high],
        "expected_injections_per_scenario": n_injections,
    }


def analyze_e4(root: Path) -> Dict[str, Any]:
    entries = _load_jsonl(root / "e4_overhead.ndjson")
    if not entries:
        return {"present": False}
    off = [float(e["rate_per_s"]) for e in entries if e.get("mode") == "off"
           and isinstance(e.get("rate_per_s"), (int, float))]
    on  = [float(e["rate_per_s"]) for e in entries if e.get("mode") == "on"
           and isinstance(e.get("rate_per_s"), (int, float))]
    out: Dict[str, Any] = {
        "present": True,
        "off": {"n": len(off), "mean": statistics.fmean(off) if off else None,
                "stdev": statistics.pstdev(off) if len(off) > 1 else 0.0},
        "on":  {"n": len(on),  "mean": statistics.fmean(on)  if on  else None,
                "stdev": statistics.pstdev(on)  if len(on)  > 1 else 0.0},
    }
    if off and on:
        out["overhead_pct"] = (out["off"]["mean"] - out["on"]["mean"]) / out["off"]["mean"] * 100.0
        out["ttest"] = welch_t(off, on)
    return out


def analyze_e5(root: Path) -> Dict[str, Any]:
    inj = _load_jsonl(root / "e5_injections.ndjson")
    vd  = _load_jsonl(root / "e5_ood.jsonl")
    if not inj:
        return {"present": False}
    per = match_injections(inj, vd)
    # E5 is OOD_SCENARIOS only; usually just S11.
    rows = []
    total_inj = 0
    total_hit = 0
    for sid, d in per.items():
        n = d["injections"]
        h = d["hits"]
        lo, hi = wilson_ci(h, n)
        rows.append({"scenario_id": sid, "scenario": SCENARIO_LABELS.get(sid, str(sid)),
                     "injections": n, "hits": h,
                     "detection_rate": h / n if n else None,
                     "ci_low": lo, "ci_high": hi})
        total_inj += n
        total_hit += h
    lo, hi = wilson_ci(total_hit, total_inj)
    return {"present": True, "rows": rows,
            "total_injections": total_inj, "total_hits": total_hit,
            "overall_rate": total_hit / total_inj if total_inj else None,
            "overall_ci": [lo, hi]}


def analyze_baseline(root: Path, prefix: str, inj_file: str,
                     vd_file: str, tool_name: str,
                     attack_scenarios: List[int]) -> Dict[str, Any]:
    inj = _load_jsonl(root / inj_file)
    vd  = _load_jsonl(root / vd_file)
    if not inj or not vd:
        return {"present": False, "tool": tool_name}
    per = match_injections(inj, vd)
    per_scenario = []
    total_inj = 0; total_hit = 0
    for sid in attack_scenarios:
        d = per.get(sid, {"injections": 0, "hits": 0, "ttks": []})
        lo, hi = wilson_ci(d["hits"], d["injections"])
        per_scenario.append({
            "scenario_id": sid,
            "scenario":    SCENARIO_LABELS.get(sid, str(sid)),
            "injections":  d["injections"],
            "hits":        d["hits"],
            "detection_rate": d["hits"] / d["injections"] if d["injections"] else None,
            "ci_low":  lo, "ci_high": hi,
        })
        total_inj += d["injections"]
        total_hit += d["hits"]
    lo, hi = wilson_ci(total_hit, total_inj)
    return {"present": True, "tool": tool_name,
            "per_scenario": per_scenario,
            "total_injections": total_inj, "total_hits": total_hit,
            "overall_rate": total_hit / total_inj if total_inj else None,
            "overall_ci": [lo, hi]}


# ── CSV helpers ──────────────────────────────────────────────────────
def write_csv(path: Path, rows: List[Dict[str, Any]], fields: List[str]) -> None:
    if not rows:
        return
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k) for k in fields})


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--dir", default="results/marathon")
    p.add_argument("--n-injections", type=int, default=15)
    p.add_argument("--attack-scenarios", default="2,3,4,5,6,7,8,9,10,11")
    p.add_argument("--fpr-duration-s", type=float, default=7200.0)
    args = p.parse_args(argv)

    attack_scenarios = [int(s) for s in args.attack_scenarios.split(",") if s.strip()]

    root = Path(args.dir)
    if not root.is_dir():
        print(f"results dir not found: {root}", file=sys.stderr)
        return 1

    summary: Dict[str, Any] = {
        "generated_at":     __import__("time").strftime("%Y-%m-%dT%H:%M:%S"),
        "attack_scenarios": attack_scenarios,
        "n_injections":     args.n_injections,
        "E1_fpr":           analyze_e1(root, args.fpr_duration_s),
        "E2_detection":     analyze_e2_e3(root, attack_scenarios, args.n_injections),
        "E4_overhead":      analyze_e4(root),
        "E5_ood":           analyze_e5(root),
        "E6a_falco":        analyze_baseline(root, "falco",
                                             "e6a_injections.ndjson",
                                             "falco_stock.jsonl",
                                             "falco", attack_scenarios),
        "E6b_tetragon":     analyze_baseline(root, "tetragon",
                                             "e6b_injections.ndjson",
                                             "tetragon_stock.jsonl",
                                             "tetragon", attack_scenarios),
    }

    (root / "marathon_summary.json").write_text(json.dumps(summary, indent=2))

    # ── detection_rate.csv, ttk_percentiles.csv ──
    e2 = summary["E2_detection"]
    if e2.get("present"):
        write_csv(root / "detection_rate.csv", e2["rows"],
                  ["scenario_id", "scenario", "injections", "hits",
                   "detection_rate", "ci_low", "ci_high"])
        write_csv(root / "ttk_percentiles.csv", e2["rows"],
                  ["scenario_id", "scenario", "ttk_p50", "ttk_p95",
                   "ttk_p99", "ttk_mean"])

    # ── fpr.csv ──
    e1 = summary["E1_fpr"]
    if e1.get("present"):
        write_csv(root / "fpr.csv",
                  [{"duration_hours": e1["duration_hours"],
                    "false_positives": e1["false_positives"],
                    "fp_per_hour": e1["fp_per_hour"],
                    "ci_low_per_cycle":  e1["wilson_ci_per_cycle"][0],
                    "ci_high_per_cycle": e1["wilson_ci_per_cycle"][1]}],
                  ["duration_hours", "false_positives", "fp_per_hour",
                   "ci_low_per_cycle", "ci_high_per_cycle"])

    # ── overhead.csv + overhead_ttest.json ──
    e4 = summary["E4_overhead"]
    if e4.get("present"):
        write_csv(root / "overhead.csv",
                  [{"mode": "off", **e4["off"]},
                   {"mode": "on",  **e4["on"]}],
                  ["mode", "n", "mean", "stdev"])
        (root / "overhead_ttest.json").write_text(
            json.dumps({"ttest": e4.get("ttest"),
                        "overhead_pct": e4.get("overhead_pct")}, indent=2))

    # ── baseline_comparison.csv  (tool-level)  ──
    def _row(tool_key: str) -> Optional[Dict[str, Any]]:
        d = summary.get(tool_key, {})
        if not d.get("present"):
            return None
        return {
            "tool":             d["tool"],
            "total_injections": d["total_injections"],
            "total_hits":       d["total_hits"],
            "overall_rate":     d["overall_rate"],
            "ci_low":           d["overall_ci"][0],
            "ci_high":          d["overall_ci"][1],
        }
    tool_rows = []
    if e2.get("present"):
        tool_rows.append({
            "tool": "causaltrace",
            "total_injections": e2["total_injections"],
            "total_hits":       e2["total_hits"],
            "overall_rate":     e2["overall_rate"],
            "ci_low":           e2["overall_ci"][0],
            "ci_high":          e2["overall_ci"][1],
        })
    for k in ("E6a_falco", "E6b_tetragon"):
        r = _row(k)
        if r:
            tool_rows.append(r)
    write_csv(root / "baseline_comparison.csv", tool_rows,
              ["tool", "total_injections", "total_hits",
               "overall_rate", "ci_low", "ci_high"])

    # ── per_scenario_baseline.csv (long-format for plotting)  ──
    long_rows = []
    if e2.get("present"):
        for r in e2["rows"]:
            long_rows.append({"tool": "causaltrace", **r})
    for k in ("E6a_falco", "E6b_tetragon"):
        d = summary.get(k, {})
        if d.get("present"):
            tool = d["tool"]
            for r in d["per_scenario"]:
                long_rows.append({"tool": tool, **r})
    write_csv(root / "per_scenario_baseline.csv", long_rows,
              ["tool", "scenario_id", "scenario", "injections", "hits",
               "detection_rate", "ci_low", "ci_high"])

    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
