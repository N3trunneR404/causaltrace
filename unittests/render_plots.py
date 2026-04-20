#!/usr/bin/env python3
"""Regenerate the detection heatmap + per-tool bar chart from summary.csv."""
import csv
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

UT_DIR   = Path(__file__).resolve().parent
PLOT_DIR = UT_DIR / "plots"
PLOT_DIR.mkdir(exist_ok=True)

rows = list(csv.DictReader(open(UT_DIR / "summary.csv")))
tools     = sorted({r["tool"] for r in rows})
scenarios = []
for r in rows:
    if r["scenario"] not in scenarios:
        scenarios.append(r["scenario"])

matrix = np.zeros((len(tools), len(scenarios)))
for i, t in enumerate(tools):
    for j, s in enumerate(scenarios):
        rec = next((r for r in rows if r["tool"] == t and r["scenario"] == s), None)
        matrix[i, j] = 1.0 if rec and rec["detected"] == "True" else 0.0

# Heatmap
fig, ax = plt.subplots(figsize=(9, 3.4))
im = ax.imshow(matrix, cmap="RdYlGn", vmin=0, vmax=1, aspect="auto")
ax.set_xticks(range(len(scenarios))); ax.set_xticklabels(scenarios)
ax.set_yticks(range(len(tools)));     ax.set_yticklabels(tools)
for i in range(len(tools)):
    for j in range(len(scenarios)):
        mark = "\u2713" if matrix[i, j] else "\u2717"
        ax.text(j, i, mark, ha="center", va="center",
                color="black" if matrix[i, j] else "white", fontsize=12)
ax.set_title("Detection matrix — tool \u00d7 scenario (unittest smoke)")
fig.tight_layout()
fig.savefig(PLOT_DIR / "detection_matrix.png", dpi=140)
plt.close(fig)

# Bars
rates = matrix.mean(axis=1)
fig, ax = plt.subplots(figsize=(6, 3.6))
bars = ax.bar(tools, rates, color=["#1f77b4", "#ff7f0e", "#2ca02c"][:len(tools)])
ax.set_ylim(0, 1.05); ax.set_ylabel("Detection rate")
ax.set_title("Per-tool detection rate (unittest smoke)")
for b, r in zip(bars, rates):
    ax.text(b.get_x() + b.get_width() / 2, r + 0.02, f"{r:.0%}",
            ha="center", fontsize=11)
fig.tight_layout()
fig.savefig(PLOT_DIR / "detection_bar.png", dpi=140)
plt.close(fig)

print(f"plots → {PLOT_DIR}/")
for p in sorted(PLOT_DIR.iterdir()):
    print(f"  {p.name}  {p.stat().st_size // 1024} KB")
