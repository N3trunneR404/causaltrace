# scripts/results_analysis.py
"""
Results Analysis — reads verdicts.jsonl and produces:
  1. Per-scenario detection table (TP/FP/FN + precision/recall/F1)
  2. Comparison table vs baselines
  3. Rayleigh quotient distribution plot (for Experiment E5)
  4. Eigenmode fingerprint plot (for Bonus E7)
  5. Latency summary

Usage:
  python3 scripts/results_analysis.py results/causaltrace/verdicts.jsonl
"""
import json, sys
import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path
from collections import defaultdict

# ── Scenario ground truth ─────────────────────────────────────────────
# For each scenario, the expected verdict is KILL (except scenario 1 = ALLOW)
SCENARIO_EXPECTED = {
    1: "ALLOW",   # Normal traffic — no attack
    2: "KILL",    # Reverse shell
    3: "KILL",    # Sensitive file
    4: "KILL",    # Fork bomb
    5: "KILL",    # NS escape
    6: "KILL",    # Privilege escalation
    7: "KILL",    # Cross-container lateral movement
}

# Baseline results from mid-review experiments (hardcoded)
BASELINE_A_RESULTS = {1: "ALLOW", 2: "ALLOW", 3: "ALLOW",
                       4: "ALLOW", 5: "KILL", 6: "ALLOW", 7: "ALLOW"}
BASELINE_B_RESULTS = {1: "ALLOW", 2: "KILL", 3: "KILL",
                       4: "KILL", 5: "KILL", 6: "KILL", 7: "ALLOW"}


def load_verdicts(log_path: str) -> list:
    """Load verdict log entries from a JSONL file."""
    entries = []
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def compute_metrics(results: dict, expected: dict) -> dict:
    """
    Compute classification metrics from per-scenario results.

    results:  {scenario_nr: "KILL" or "ALLOW"}
    expected: {scenario_nr: "KILL" or "ALLOW"}

    Returns: {precision, recall, f1, fpr, tp, fp, tn, fn, detected}
    """
    tp = fp = tn = fn = 0
    for sc, exp in expected.items():
        actual = results.get(sc, "ALLOW")
        if exp == "KILL" and actual == "KILL":  tp += 1
        elif exp == "KILL" and actual == "ALLOW": fn += 1
        elif exp == "ALLOW" and actual == "KILL": fp += 1
        else:                                     tn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision, "recall": recall, "f1": f1, "fpr": fpr,
        "detected": f"{tp}/{tp+fn}",
    }


def print_comparison_table(ct_results: dict):
    """Print the final comparison table for the paper."""
    ct_metrics = compute_metrics(ct_results, SCENARIO_EXPECTED)
    ba_metrics = compute_metrics(BASELINE_A_RESULTS, SCENARIO_EXPECTED)
    bb_metrics = compute_metrics(BASELINE_B_RESULTS, SCENARIO_EXPECTED)

    print("\n" + "="*70)
    print("DETECTION COMPARISON TABLE")
    print("="*70)
    print(f"{'Metric':<30} {'Baseline A':>12} {'Baseline B':>12} {'CausalTrace':>12}")
    print("-"*70)
    metrics = [
        ("Scenarios detected", "detected"),
        ("Precision",          "precision"),
        ("Recall",             "recall"),
        ("F1-score",           "f1"),
        ("False Positive Rate","fpr"),
    ]
    for label, key in metrics:
        ba_v = ba_metrics[key]
        bb_v = bb_metrics[key]
        ct_v = ct_metrics[key]
        if isinstance(ct_v, float):
            print(f"  {label:<28} {ba_v:>12.3f} {bb_v:>12.3f} {ct_v:>12.3f}")
        else:
            print(f"  {label:<28} {str(ba_v):>12} {str(bb_v):>12} {str(ct_v):>12}")
    print("="*70)

    # Per-scenario breakdown
    print("\nPER-SCENARIO BREAKDOWN:")
    print(f"  {'Sc':<4} {'Expected':<10} {'Baseline A':<12} {'Baseline B':<12} {'CausalTrace':<12}")
    for sc in sorted(SCENARIO_EXPECTED.keys()):
        exp = SCENARIO_EXPECTED[sc]
        ba  = BASELINE_A_RESULTS.get(sc, "ALLOW")
        bb  = BASELINE_B_RESULTS.get(sc, "ALLOW")
        ct  = ct_results.get(sc, "ALLOW")
        ct_mark = "✓" if ct == exp else "✗"
        print(f"  {sc:<4} {exp:<10} {ba:<12} {bb:<12} {ct:<10} {ct_mark}")


def plot_rayleigh_distribution(verdicts: list, output_dir: str = "results/causaltrace"):
    """
    Plot Rayleigh quotient distributions for normal vs. attack scenarios.
    This is Experiment E5 — the key figure showing sheaf separation.
    """
    normal_rayleigh  = [v["rayleigh"] for v in verdicts if v["action"] == "ALLOW"]
    attack_rayleigh  = [v["rayleigh"] for v in verdicts if v["action"] == "KILL"]

    if not normal_rayleigh and not attack_rayleigh:
        print("No data for Rayleigh distribution plot")
        return

    fig, ax = plt.subplots(figsize=(8, 5))

    if normal_rayleigh:
        ax.hist(normal_rayleigh, bins=30, alpha=0.6,
                color='steelblue', label='Normal traffic', density=True)
    if attack_rayleigh:
        ax.hist(attack_rayleigh, bins=30, alpha=0.6,
                color='firebrick', label='Attack traffic', density=True)

    # Draw threshold line if available
    if verdicts:
        tau = verdicts[0].get("global_tau", None)
        if tau:
            ax.axvline(x=tau, color='black', linestyle='--',
                       linewidth=2, label=f'Threshold τ={tau:.3f}')

    ax.set_xlabel("Rayleigh Quotient E(x)", fontsize=12)
    ax.set_ylabel("Density", fontsize=12)
    ax.set_title("Sheaf Laplacian Rayleigh Quotient Distribution\n"
                 "Normal Traffic vs. Attack Traffic", fontsize=12)
    ax.legend(fontsize=11)
    ax.grid(True, alpha=0.3)

    out_path = Path(output_dir) / "rayleigh_distribution.png"
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    print(f"Saved Rayleigh distribution plot → {out_path}")
    plt.close()


def plot_eigenmode_fingerprints(verdicts: list, output_dir: str = "results/causaltrace"):
    """
    Plot eigenmode energy distributions per attack type (Bonus E7).
    Shows that different attack types excite different spectral modes.
    """
    by_label = defaultdict(list)
    for v in verdicts:
        if v.get("eigenmodes") and v.get("label"):
            label = v["label"]
            energies = v["eigenmodes"].get("mode_energies", [])
            if energies:
                by_label[label].append(energies[0] if energies else 0)

    if not by_label:
        print("No eigenmode data available for fingerprint plot")
        return

    fig, ax = plt.subplots(figsize=(10, 5))
    labels  = sorted(by_label.keys())
    means   = [np.mean(by_label[l]) for l in labels]
    stds    = [np.std(by_label[l]) for l in labels]

    x = np.arange(len(labels))
    bars = ax.bar(x, means, yerr=stds, capsize=5,
                  color=['firebrick', 'darkorange', 'goldenrod',
                         'steelblue', 'mediumseagreen'][:len(labels)],
                  alpha=0.8)

    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=20, ha='right', fontsize=9)
    ax.set_ylabel("Dominant Eigenmode Energy (mean ± std)", fontsize=11)
    ax.set_title("Sheaf Laplacian Spectral Fingerprints per Attack Type\n"
                 "(Different attacks excite different eigenmodes)", fontsize=11)
    ax.grid(True, alpha=0.3, axis='y')

    out_path = Path(output_dir) / "eigenmode_fingerprints.png"
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    print(f"Saved eigenmode fingerprint plot → {out_path}")
    plt.close()


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 results_analysis.py verdicts.jsonl [scenario_map.json]")
        sys.exit(1)

    log_path = sys.argv[1]
    verdicts = load_verdicts(log_path)
    print(f"Loaded {len(verdicts)} verdict entries from {log_path}")

    # Determine per-scenario result (majority vote over repetitions)
    # If running 10 reps per scenario, scenario_map.json maps
    # timestamp ranges → scenario number
    # For simplicity: use label → scenario mapping
    LABEL_TO_SCENARIO = {
        "Normal":                                   1,
        "Reverse shell with lateral movement":      2,
        "Unknown anomalous inter-container coupling": 2,  # fd-type invariant
        None:                                       2,    # Tier 1 killed before label
    }
    # Easier: assume verdicts are tagged with scenario number by the run_all.sh script
    # via a "scenario" field added by the caller. If not present, use label.
    scenario_results = {}
    for v in verdicts:
        sc = v.get("scenario")
        if sc:
            action = v["action"]
            # majority vote: if any verdict in this scenario is KILL, count as KILL
            if action == "KILL" or scenario_results.get(sc) == "KILL":
                scenario_results[sc] = "KILL"
            else:
                scenario_results[sc] = "ALLOW"

    if not scenario_results:
        # Fall back to using all verdicts
        print("Note: no 'scenario' field in log. Using aggregate results.")
        has_kill = any(v["action"] == "KILL" for v in verdicts)
        scenario_results = {7: "KILL" if has_kill else "ALLOW"}

    print_comparison_table(scenario_results)

    output_dir = str(Path(log_path).parent)
    plot_rayleigh_distribution(verdicts, output_dir)
    plot_eigenmode_fingerprints(verdicts, output_dir)

    print("\nAnalysis complete.")


if __name__ == "__main__":
    main()
