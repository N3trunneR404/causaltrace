#!/usr/bin/env python3
"""Build the per-scenario detection-rate table with Wilson 95 % CIs across all
five detector configurations (CausalTrace, Falco stock/tuned, Tetragon
stock/tuned). Emits both a CSV and a LaTeX table ready for Chapter 6."""
from __future__ import annotations
import csv
import json
import math
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MAR  = REPO / "results" / "marathon"
FAST = MAR / "results_fast"
OUT  = Path(__file__).resolve().parent

DETECT_WIN = 25.0   # seconds after injection

# ── parsers ────────────────────────────────────────────────────────────────

def _load_jsonl(p: Path):
    if not p.exists():
        return []
    out = []
    for line in p.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            pass
    return out

def _parse_iso(t: str) -> float:
    if not t:
        return 0.0
    try:
        t = t.rstrip("Z")
        return datetime.fromisoformat(t).replace(tzinfo=timezone.utc).timestamp()
    except Exception:
        return 0.0

def load_ct_tier1_ts() -> list[float]:
    """Tier-1 ALERT lines from loader.log."""
    log = MAR / "loader.log"
    out = []
    if not log.exists():
        return out
    pat = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[,.]\d+).*\[ALERT\]")
    for line in log.read_text(errors="ignore").splitlines():
        m = pat.match(line)
        if not m:
            continue
        try:
            ts = datetime.strptime(m.group(1)[:23], "%Y-%m-%d %H:%M:%S,%f").timestamp()
            out.append(ts)
        except Exception:
            pass
    return sorted(out)

def load_ct_tier3_ts() -> list[float]:
    """Tier-3 verdict timestamps (any severity >= MEDIUM)."""
    out = []
    for v in _load_jsonl(FAST / "verdicts.jsonl"):
        if v.get("severity") in ("MEDIUM", "HIGH", "CRITICAL"):
            ts = v.get("timestamp", 0)
            if ts:
                out.append(float(ts))
    return sorted(out)

def load_falco_ts(path: Path) -> list[float]:
    out = [_parse_iso(e.get("time", "")) for e in _load_jsonl(path)]
    return sorted(t for t in out if t > 0)

def load_tetragon_ts(path: Path) -> list[float]:
    out = []
    for e in _load_jsonl(path):
        pk = e.get("process_kprobe", {})
        if pk and pk.get("policy_name", "").startswith("cteval-"):
            proc = pk.get("process", {}) or {}
            t = _parse_iso(proc.get("start_time", ""))
            if t > 0:
                out.append(t)
    return sorted(out)

# ── correlation ────────────────────────────────────────────────────────────

def first_hit_after(events: list[float], t0: float, window: float = DETECT_WIN) -> bool:
    # binary search would be cleaner; list is <= ~few thousand entries so linear is fine
    for t in events:
        if t < t0:
            continue
        if t <= t0 + window:
            return True
        break
    return False

# ── Wilson CI ──────────────────────────────────────────────────────────────

def wilson_ci(hits: int, n: int, z: float = 1.96) -> tuple[float, float, float]:
    """Return (p_hat, lower, upper) for a binomial proportion."""
    if n == 0:
        return 0.0, 0.0, 0.0
    p = hits / n
    denom = 1.0 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return p, max(0.0, centre - half), min(1.0, centre + half)

# ── main ───────────────────────────────────────────────────────────────────

def main():
    attacks = _load_jsonl(MAR / "attacks.jsonl")
    phases = {
        "causaltrace":      "CausalTrace",
        "falco_stock":      "Falco (stock)",
        "falco_tuned":      "Falco (tuned)",
        "tetragon_stock":   "Tetragon (stock)",
        "tetragon_tuned":   "Tetragon (tuned)",
    }

    ct_t1  = load_ct_tier1_ts()
    ct_t3  = load_ct_tier3_ts()
    ct_union = sorted(set(ct_t1) | set(ct_t3))
    fs     = load_falco_ts(MAR / "falco_stock.jsonl")
    ft     = load_falco_ts(MAR / "falco_tuned.jsonl")
    ts_stk = load_tetragon_ts(MAR / "tetragon_stock.jsonl")
    ts_tun = load_tetragon_ts(MAR / "tetragon_tuned.jsonl")

    events = {
        "causaltrace":    ct_union,
        "falco_stock":    fs,
        "falco_tuned":    ft,
        "tetragon_stock": ts_stk,
        "tetragon_tuned": ts_tun,
    }

    # Per-scenario tally per phase
    tally: dict[tuple[str, str], list[int]] = defaultdict(lambda: [0, 0])  # [hits, total]
    for a in attacks:
        phase = a.get("phase")
        if phase not in events:
            continue
        sid = a.get("attack_id")
        t0  = float(a.get("ts_inject", 0))
        if t0 <= 0:
            continue
        hit = first_hit_after(events[phase], t0)
        k = (phase, sid)
        tally[k][1] += 1
        if hit:
            tally[k][0] += 1

    scenarios = sorted({sid for _, sid in tally.keys()},
                       key=lambda s: int(re.sub(r"[^0-9]", "", s) or 0))

    # CSV
    csv_path = OUT / "detection_rates.csv"
    with open(csv_path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["tool", "scenario", "hits", "total", "rate", "ci_low", "ci_high"])
        for phase, name in phases.items():
            for sid in scenarios:
                h, n = tally.get((phase, sid), [0, 0])
                p, lo, hi = wilson_ci(h, n)
                w.writerow([name, sid, h, n, f"{p:.3f}", f"{lo:.3f}", f"{hi:.3f}"])
        # totals
        for phase, name in phases.items():
            h = sum(v[0] for (p, s), v in tally.items() if p == phase)
            n = sum(v[1] for (p, s), v in tally.items() if p == phase)
            p, lo, hi = wilson_ci(h, n)
            w.writerow([name, "TOTAL", h, n, f"{p:.3f}", f"{lo:.3f}", f"{hi:.3f}"])
    print(f"CSV  → {csv_path}")

    # LaTeX — compact column headers, footnotesize, CI values without brackets
    # to shrink the column width.
    short_headers = {
        "causaltrace":    "CausalTrace",
        "falco_stock":    "Falco-s",
        "falco_tuned":    "Falco-t",
        "tetragon_stock": "Tetra-s",
        "tetragon_tuned": "Tetra-t",
    }
    tex_path = OUT / "table_detection_rates.tex"
    with open(tex_path, "w") as fh:
        fh.write(r"\setlength\tabcolsep{3.2pt}" + "\n")
        fh.write(r"\begin{tabular}{@{}l" + "c" * (len(phases)) + r"@{}}" + "\n")
        fh.write(r"\toprule" + "\n")
        fh.write("Scen. & " + " & ".join(short_headers[p] for p in phases.keys()) +
                r" \\" + "\n")
        fh.write(r"\midrule" + "\n")
        for sid in scenarios:
            row = [sid]
            for phase in phases.keys():
                h, n = tally.get((phase, sid), [0, 0])
                if n == 0:
                    row.append("--")
                    continue
                p, lo, hi = wilson_ci(h, n)
                row.append(f"{p*100:.1f}")
            fh.write(" & ".join(row) + r" \\" + "\n")
        fh.write(r"\midrule" + "\n")
        row = [r"\textbf{All}"]
        for phase in phases.keys():
            h = sum(v[0] for (p, s), v in tally.items() if p == phase)
            n = sum(v[1] for (p, s), v in tally.items() if p == phase)
            if n == 0:
                row.append("--")
                continue
            p, lo, hi = wilson_ci(h, n)
            row.append(f"\\textbf{{{p*100:.1f}}}")
        fh.write(" & ".join(row) + r" \\" + "\n")
        # Add CI row
        fh.write(r"CI$_{95}$ & " +
                 " & ".join(
                    (lambda h, n:
                        (("--" if n == 0 else
                          (lambda t: f"[{t[1]*100:.0f},{t[2]*100:.0f}]")(wilson_ci(h, n))))
                    )(sum(v[0] for (p, s), v in tally.items() if p == phase),
                      sum(v[1] for (p, s), v in tally.items() if p == phase))
                    for phase in phases.keys()
                 ) + r" \\" + "\n")
        fh.write(r"\bottomrule" + "\n")
        fh.write(r"\end{tabular}" + "\n")
    print(f"TeX  → {tex_path}")

    # Pretty ASCII summary for stdout
    print()
    print(f"{'scenario':<6}" + "".join(f"  {phases[p][:18]:>18}" for p in phases))
    for sid in scenarios:
        row = f"{sid:<6}"
        for phase in phases:
            h, n = tally.get((phase, sid), [0, 0])
            if n == 0:
                row += "  " + "--".rjust(18)
                continue
            p, lo, hi = wilson_ci(h, n)
            row += f"  {p*100:>5.1f}% [{lo*100:>4.0f}-{hi*100:>4.0f}]".rjust(20)
        print(row)
    row = f"{'TOTAL':<6}"
    for phase in phases:
        h = sum(v[0] for (p, s), v in tally.items() if p == phase)
        n = sum(v[1] for (p, s), v in tally.items() if p == phase)
        p, lo, hi = wilson_ci(h, n)
        row += f"  {p*100:>5.1f}% [{lo*100:>4.0f}-{hi*100:>4.0f}]".rjust(20)
    print(row)

if __name__ == "__main__":
    main()
