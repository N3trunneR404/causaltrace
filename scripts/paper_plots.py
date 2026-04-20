#!/usr/bin/env python3
"""Publication-quality plots for the CausalTrace paper.

Reads results/paper/detection_matrix.json and produces:
  - fig_detection_heatmap.pdf/png  : per-attack × tool matrix
  - fig_detection_bars.pdf/png     : total detections per tool
  - fig_recall_by_class.pdf/png    : stateless vs compound recall
  - fig_signal_dimensions.pdf/png  : d=74 signal allocation (from design)
  - fig_eigenmode_fingerprints.pdf/png : topological signatures (if data)
  - fig_latency.pdf/png            : detection latency distributions (if data)
"""
import json
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

ROOT = Path("results/paper")
FIG = ROOT / "figures"
FIG.mkdir(parents=True, exist_ok=True)

plt.rcParams.update({
    "font.family": "serif",
    "font.size": 10,
    "axes.titlesize": 11,
    "axes.labelsize": 10,
    "legend.fontsize": 9,
    "figure.dpi": 140,
    "savefig.dpi": 300,
    "savefig.bbox": "tight",
})

matrix = json.loads((ROOT / "detection_matrix.json").read_text())
ATTACKS = matrix["attacks"]
TOOLS = ["Falco (stock)", "Falco (tuned)", "Tetragon (stock)",
         "Tetragon (tuned)", "CausalTrace"]

# Pretty labels
ATTACK_LABELS = {
    "bash_revshell":          "S2a  Bash rev-shell",
    "python_dup2_revshell":   "S2b  Python dup2",
    "sensitive_file":         "S3   /etc/shadow",
    "fork_bomb":              "S4   Fork bomb",
    "unshare_userns":         "S5   unshare userns",
    "ptrace_traceme":         "S6   ptrace",
    "cross_container":        "S7   Cross-container",
    "staged_ssrf":            "S8   Staged SSRF",
}
ATTACK_CLASS = {
    "bash_revshell":"stateless", "python_dup2_revshell":"stateless",
    "sensitive_file":"stateless", "fork_bomb":"stateless",
    "unshare_userns":"stateless", "ptrace_traceme":"stateless",
    "cross_container":"compound", "staged_ssrf":"compound",
}

# ---------- Figure 1: detection heatmap ----------
M = np.array([[1 if matrix["tools"][t][a] else 0 for t in TOOLS] for a in ATTACKS])
fig, ax = plt.subplots(figsize=(6.8, 4.2))
cmap = plt.cm.get_cmap("RdYlGn")
im = ax.imshow(M, cmap=cmap, vmin=0, vmax=1, aspect="auto")
ax.set_xticks(range(len(TOOLS)))
ax.set_xticklabels(TOOLS, rotation=20, ha="right")
ax.set_yticks(range(len(ATTACKS)))
ax.set_yticklabels([ATTACK_LABELS[a] for a in ATTACKS])
for i in range(len(ATTACKS)):
    for j in range(len(TOOLS)):
        sym = "DETECT" if M[i, j] else "miss"
        ax.text(j, i, sym, ha="center", va="center",
                color="white" if M[i, j] else "black", fontsize=9, fontweight="bold")
ax.set_title("Detection Matrix: Real Tool Output on Production Testbed")
# per-tool totals under labels
for j, t in enumerate(TOOLS):
    n = int(M[:, j].sum())
    ax.text(j, len(ATTACKS) - 0.3, f"{n}/{len(ATTACKS)}",
            ha="center", va="top", fontsize=9, transform=ax.transData,
            color="navy", fontweight="bold")
plt.tight_layout()
for ext in ("pdf", "png"):
    fig.savefig(FIG / f"fig_detection_heatmap.{ext}")
plt.close(fig)

# ---------- Figure 2: bar chart of detections ----------
totals = [int(sum(matrix["tools"][t].values())) for t in TOOLS]
colors = ["#8c8c8c", "#5c7fb1", "#bfa35c", "#a86a3d", "#2e7d32"]
fig, ax = plt.subplots(figsize=(6.2, 3.4))
bars = ax.bar(TOOLS, totals, color=colors, edgecolor="black", linewidth=0.6)
ax.axhline(len(ATTACKS), color="gray", linestyle="--", linewidth=0.8, label="Max (8)")
for b, v in zip(bars, totals):
    ax.text(b.get_x() + b.get_width()/2, v + 0.1, str(v),
            ha="center", va="bottom", fontsize=10, fontweight="bold")
ax.set_ylabel("Attacks detected (out of 8)")
ax.set_ylim(0, 9)
ax.set_title("Per-tool Detection Totals")
plt.setp(ax.get_xticklabels(), rotation=15, ha="right")
plt.tight_layout()
for ext in ("pdf", "png"):
    fig.savefig(FIG / f"fig_detection_bars.{ext}")
plt.close(fig)

# ---------- Figure 3: recall by attack class ----------
stateless_ids = [a for a in ATTACKS if ATTACK_CLASS[a] == "stateless"]
compound_ids = [a for a in ATTACKS if ATTACK_CLASS[a] == "compound"]
def recall(tool, ids):
    return sum(1 for a in ids if matrix["tools"][tool][a]) / len(ids)
sl = [recall(t, stateless_ids) for t in TOOLS]
cp = [recall(t, compound_ids) for t in TOOLS]
x = np.arange(len(TOOLS))
w = 0.38
fig, ax = plt.subplots(figsize=(6.5, 3.6))
ax.bar(x - w/2, sl, w, label=f"Stateless ({len(stateless_ids)} attacks)",
       color="#4a6fa5", edgecolor="black", linewidth=0.5)
ax.bar(x + w/2, cp, w, label=f"Compound ({len(compound_ids)} attacks)",
       color="#c0392b", edgecolor="black", linewidth=0.5)
ax.set_xticks(x); ax.set_xticklabels(TOOLS, rotation=15, ha="right")
ax.set_ylabel("Recall"); ax.set_ylim(0, 1.1)
ax.set_title("Recall by Attack Class")
ax.legend(loc="upper left")
ax.grid(axis="y", alpha=0.3)
plt.tight_layout()
for ext in ("pdf", "png"):
    fig.savefig(FIG / f"fig_recall_by_class.{ext}")
plt.close(fig)

# ---------- Figure 4: d=74 signal dimension allocation ----------
groups = [
    ("Syscall bigram CMS", 32, "#1f77b4"),
    ("Top-24 syscall freq", 24, "#ff7f0e"),
    ("File/Net/IPC mix",    9,  "#2ca02c"),
    ("Behavior invariants", 5,  "#d62728"),
    ("Connection graph",    2,  "#9467bd"),
    ("Ancestry/lineage",    2,  "#8c564b"),
]
labels = [g[0] for g in groups]
sizes = [g[1] for g in groups]
colors_p = [g[2] for g in groups]
fig, ax = plt.subplots(figsize=(5.4, 3.8))
wedges, _, autot = ax.pie(
    sizes, labels=None, autopct=lambda p: f"{int(round(p*sum(sizes)/100))}",
    startangle=90, colors=colors_p, wedgeprops=dict(edgecolor="white", linewidth=1.2))
for t in autot:
    t.set_color("white"); t.set_fontweight("bold")
ax.legend(wedges, [f"{l} ({s})" for l, s in zip(labels, sizes)],
          loc="center left", bbox_to_anchor=(1.0, 0.5), frameon=False)
ax.set_title(f"CausalTrace signal vector composition (d = {sum(sizes)})")
plt.tight_layout()
for ext in ("pdf", "png"):
    fig.savefig(FIG / f"fig_signal_dimensions.{ext}")
plt.close(fig)

# ---------- Figure 5: capability coverage matrix ----------
capabilities = [
    "Stateless syscall rules",
    "Container-scoped filtering",
    "Per-event network alert",
    "Kernel-path enforcement (kill)",
    "Temporal correlation",
    "Cross-container lineage",
    "Multi-stage compound detection",
    "Topological/structural novelty",
    "No operator-authored rules needed",
]
# rough capability matrix (tool x capability)
cap_matrix = np.array([
    # Falco stock, Falco tuned, Tet stock, Tet tuned, CausalTrace
    [1, 1, 0, 1, 1],  # stateless
    [1, 1, 1, 1, 1],
    [1, 1, 0, 1, 1],
    [0, 0, 0, 0, 1],  # kernel-path kill — only CT via bpf_send_signal
    [0, 0, 0, 0, 1],
    [0, 0, 0, 0, 1],
    [0, 1, 0, 0, 1],  # tuned Falco catches some via novel-port rule
    [0, 0, 0, 0, 1],
    [1, 0, 1, 0, 1],  # stock tools need no custom authoring
])
fig, ax = plt.subplots(figsize=(6.8, 4.6))
im = ax.imshow(cap_matrix, cmap="Greens", vmin=0, vmax=1, aspect="auto")
ax.set_xticks(range(len(TOOLS))); ax.set_xticklabels(TOOLS, rotation=20, ha="right")
ax.set_yticks(range(len(capabilities))); ax.set_yticklabels(capabilities)
for i in range(cap_matrix.shape[0]):
    for j in range(cap_matrix.shape[1]):
        sym = "Y" if cap_matrix[i, j] else "-"
        ax.text(j, i, sym, ha="center", va="center",
                color="white" if cap_matrix[i, j] else "gray", fontsize=13)
ax.set_title("Detection Capabilities vs Deployment Effort")
plt.tight_layout()
for ext in ("pdf", "png"):
    fig.savefig(FIG / f"fig_capabilities.{ext}")
plt.close(fig)

# ---------- Figure 6: compound-attack timeline (SSRF window accumulation) ----------
# Reconstructed from verdict reasons that include (window=N) annotations.
verdicts_path = ROOT / "raw_causaltrace/verdicts.jsonl"
window_events = []
if verdicts_path.exists():
    import re
    for line in verdicts_path.read_text().splitlines():
        try:
            v = json.loads(line)
        except Exception:
            continue
        m = re.search(r"window=(\d+)", v.get("reason", "") or "")
        if m:
            window_events.append({
                "ts": v.get("wall_ts_iso", ""),
                "window": int(m.group(1)),
                "severity": v.get("severity", "NONE"),
                "novel": v.get("novel_edges", 0),
            })
if window_events:
    fig, ax = plt.subplots(figsize=(6.8, 3.2))
    idx = np.arange(len(window_events))
    windows = [e["window"] for e in window_events]
    novels = [e["novel"] for e in window_events]
    sev_colors = {"LOW": "#bbbbbb", "MEDIUM": "#f0b030",
                  "HIGH": "#d0503d", "CRITICAL": "#8b0000"}
    bar_colors = [sev_colors.get(e["severity"], "#888") for e in window_events]
    ax.bar(idx - 0.2, novels, 0.4, label="Novel edges (this cycle)",
           color="#4a6fa5", edgecolor="black", linewidth=0.4)
    ax.bar(idx + 0.2, windows, 0.4, label="Window accumulation (30s)",
           color=bar_colors, edgecolor="black", linewidth=0.4)
    ax.set_xlabel("Detection cycle (sequential)")
    ax.set_ylabel("Unique edges")
    ax.set_title("Compound Confirmation: per-cycle novelty vs 30s sliding window")
    legend_handles = [
        mpatches.Patch(color="#4a6fa5", label="Novel edges (this cycle)"),
        mpatches.Patch(color="#f0b030", label="MEDIUM verdict"),
        mpatches.Patch(color="#d0503d", label="HIGH verdict"),
    ]
    ax.legend(handles=legend_handles, loc="upper left")
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    for ext in ("pdf", "png"):
        fig.savefig(FIG / f"fig_window_accumulation.{ext}")
    plt.close(fig)

print("Figures written to", FIG)
for p in sorted(FIG.glob("*.pdf")):
    print(" -", p.name)
