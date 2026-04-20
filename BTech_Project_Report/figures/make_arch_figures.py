#!/usr/bin/env python3
"""Architectural diagrams for the thesis — v3.

Rewrite goals:
  * matplotlib is NOT in text.usetex mode, so LaTeX commands like
    \\texttt / \\textsc / \\textit render as LITERAL text in v2.  All text
    is now plain; monospaced identifiers go inside $\\mathtt{...}$ (which
    matplotlib's mathtext understands).
  * The three-tier architecture is split into FIVE clean panels instead of
    one crowded overview so labels never overlap:
        fig_arch_overview          — three-tier block diagram
        fig_arch_tier1_detail      — dispatcher + handlers + compound gate
        fig_dataflow_normal        — numbered flow on benign traffic
        fig_dataflow_attack        — numbered flow on detected attack
        fig_sliding_window         — Tier-3 5-second cycle timeline
  * Every canvas is sized to leave headroom for text; fonts never smaller
    than 7 pt inside boxes.
"""
from __future__ import annotations
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Circle, Rectangle

OUT = Path(__file__).resolve().parent

PAPER_STYLE = {
    "font.family":     "serif",
    "font.size":       8,
    "axes.titlesize":  10,
    "savefig.bbox":    "tight",
    "savefig.dpi":     300,
    "pdf.fonttype":    42,
    "ps.fonttype":     42,
}

W = {
    "black": "#000000", "orange": "#E69F00", "sky": "#56B4E9",
    "green": "#009E73", "yellow": "#F0E442", "blue": "#0072B2",
    "vermillion": "#D55E00", "pink": "#CC79A7",
    "lightgrey": "#E6E6E6", "midgrey": "#BFBFBF", "darkgrey": "#666666",
}


def box(ax, x, y, w, h, text, color=W["lightgrey"], ec=W["darkgrey"],
        fontsize=8, weight="normal", lw=1.0, textcolor="black"):
    ax.add_patch(FancyBboxPatch((x, y), w, h,
                                boxstyle="round,pad=0.03,rounding_size=0.04",
                                facecolor=color, edgecolor=ec, linewidth=lw))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center",
            fontsize=fontsize, weight=weight, color=textcolor,
            linespacing=1.25)


def arrow(ax, x1, y1, x2, y2, color=W["black"], lw=1.0, style="->",
          ls="-", mutation=12):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2),
        arrowstyle=style, mutation_scale=mutation, lw=lw,
        color=color, linestyle=ls, shrinkA=3, shrinkB=3))


def _save(fig, name):
    fig.savefig(OUT / f"{name}.pdf")
    fig.savefig(OUT / f"{name}.png", dpi=200)
    print(f"  saved  {name}")
    plt.close(fig)


# ── Fig 4.1: Three-tier overview (no crowded details) ──────────────────────
def fig_arch_overview():
    plt.rcParams.update(PAPER_STYLE)
    fig, ax = plt.subplots(figsize=(10.5, 6.2))
    ax.set_xlim(0, 14.5)
    ax.set_ylim(0, 8.4)
    ax.axis("off")

    # Title
    ax.text(7.25, 8.1, "CausalTrace — three-tier overview",
            ha="center", fontsize=11, weight="bold")

    # User-space row: 22 containers represented by 6 reps + ellipsis
    ax.text(0.3, 7.35, "USER SPACE", fontsize=7.5, weight="bold",
            color=W["darkgrey"])
    reps = ["ct-nginx", "ct-api-gw", "ct-webapp-a", "ct-product",
            "ct-redis", "ct-postgres"]
    for i, n in enumerate(reps):
        box(ax, 0.6 + i * 1.55, 6.55, 1.45, 0.60, n,
            color=W["sky"], ec=W["blue"], fontsize=7)
    ax.text(0.6 + 6 * 1.55 + 0.1, 6.85,
            "… 22 containers total …", fontsize=7, style="italic",
            color=W["darkgrey"])

    # Tier-3 daemon box (right side, userspace)
    box(ax, 11.4, 6.35, 2.9, 1.00,
        "Tier-3 daemon\n(Python, 5 s cycle)\nCCA · Mahalanobis · Rayleigh",
        color=W["green"], ec=W["black"], fontsize=7.5, weight="bold",
        textcolor="white")

    # Kernel/userspace separator
    ax.plot([0.3, 14.3], [5.90, 5.90], color=W["darkgrey"], lw=0.8, ls="--")
    ax.text(0.35, 6.00, "user space", fontsize=7, color=W["darkgrey"])
    ax.text(0.35, 5.75, "kernel",     fontsize=7, color=W["darkgrey"])

    # Syscall arrows down into Tier-1
    for i in range(6):
        arrow(ax, 0.6 + i * 1.55 + 0.72, 6.55,
              0.6 + i * 1.55 + 0.72, 5.12,
              color=W["darkgrey"], lw=0.7, mutation=10)
    ax.text(5.5, 6.05, "syscalls", fontsize=7, color=W["darkgrey"],
            style="italic")

    # Tier-1 banner
    ax.text(0.3, 5.30, "KERNEL", fontsize=7.5, weight="bold",
            color=W["darkgrey"])
    box(ax, 0.6, 4.25, 10.4, 0.85,
        "Tier-1  —  stateless invariant enforcement\n"
        "raw_tracepoint/sys_enter · bigram CMS · 6 handlers · compound gate",
        color=W["orange"], ec=W["vermillion"], fontsize=8.5, weight="bold")

    # Tier-2 banner
    box(ax, 0.6, 3.20, 10.4, 0.85,
        "Tier-2  —  attribution and session severance\n"
        "tcp_v4_connect · inet_csk_accept · byte accumulator · TC direct-action drop",
        color=W["pink"], ec=W["black"], fontsize=8.5, weight="bold")

    # Shared-BPF-map bridge
    box(ax, 0.6, 1.95, 10.4, 0.85,
        "Shared BPF maps  (ringbufs · behaviour bits · client trust · drop-IP list · verdict map)",
        color=W["lightgrey"], ec=W["darkgrey"], fontsize=8.5)

    # Tier-3 <-> shared maps dashed arrows
    arrow(ax, 11.4, 2.40, 11.0, 2.40,
          color=W["green"], lw=1.0, ls="--", mutation=10)
    arrow(ax, 11.0, 2.55, 11.4, 2.55,
          color=W["green"], lw=1.0, ls="--", mutation=10)
    ax.text(12.9, 4.40, "reads\nCMS + bits\n(one-way)",
            fontsize=7, color=W["green"], ha="center", style="italic")
    arrow(ax, 12.9, 6.30, 12.9, 2.85,
          color=W["green"], lw=1.0, ls="--", mutation=10)
    arrow(ax, 13.4, 2.85, 13.4, 6.30,
          color=W["green"], lw=1.0, ls="--", mutation=10)
    ax.text(13.95, 4.40, "writes\nverdict_map\n(one-way)",
            fontsize=7, color=W["green"], ha="center", style="italic")

    # Legend strip at bottom
    box(ax, 0.6, 0.75, 3.3, 0.65,
        "stateless in-kernel enforcement\n(Tier-1: < 5 µs)",
        color=W["orange"], ec=W["vermillion"], fontsize=7)
    box(ax, 4.1, 0.75, 3.3, 0.65,
        "attribution / session drop\n(Tier-2: < 1 µs per packet)",
        color=W["pink"], ec=W["black"], fontsize=7)
    box(ax, 7.6, 0.75, 3.3, 0.65,
        "sheaf analytics\n(Tier-3: 5 s cycle, ~2 % CPU)",
        color=W["green"], ec=W["black"], fontsize=7, textcolor="white")
    box(ax, 11.1, 0.75, 3.2, 0.65,
        "shared state only —\nno tier blocks another",
        color=W["lightgrey"], ec=W["darkgrey"], fontsize=7)

    _save(fig, "fig_arch_overview")


# ── Fig 4.2: Tier-1 detail (dispatcher + handlers + compound gate) ────────
def fig_arch_tier1_detail():
    plt.rcParams.update(PAPER_STYLE)
    fig, ax = plt.subplots(figsize=(11.0, 7.8))
    ax.set_xlim(0, 14.0)
    ax.set_ylim(0, 10.6)
    ax.axis("off")

    ax.text(7.0, 10.3, "Tier-1 internals — dispatcher, six handlers, compound gate",
            ha="center", fontsize=11, weight="bold")

    # Dispatcher header
    box(ax, 0.4, 8.55, 13.2, 1.10,
        "raw_tracepoint/sys_enter  dispatcher\n"
        "host-ns filter → CMS bigram update → tail-call prog_array[nr]",
        color=W["yellow"], ec=W["orange"], fontsize=9, weight="bold")

    # Six handler boxes
    handlers = [
        ("handle_fork",    "clone/clone3\n$d^{2}>0$ acceleration", W["orange"]),
        ("handle_execve",  "shell basename\nfd 0/1/2 is socket?", W["orange"]),
        ("handle_file",    "openat path-class\n/etc/sha, /proc/1/",  W["orange"]),
        ("handle_privesc", "setuid(0), ptrace\nunshare, setns",      W["orange"]),
        ("handle_dup2",    "dup2(oldfd,newfd)\nfd-type invariant",   W["orange"]),
        ("handle_unshare", "CLONE_NEWNS /\nCLONE_NEWUSER",           W["orange"]),
    ]
    hx0, hy0 = 0.4, 6.55
    hw, hh = 2.15, 1.65
    for i, (name, body, col) in enumerate(handlers):
        x = hx0 + i * (hw + 0.09)
        box(ax, x, hy0, hw, hh,
            f"{name}\n\n{body}",
            color=col, ec=W["vermillion"], fontsize=7.5, weight="bold")
        # connector from dispatcher
        arrow(ax, x + hw / 2, 8.55, x + hw / 2, hy0 + hh,
              color=W["vermillion"], lw=0.9, mutation=9)
        # connector down to gate
        arrow(ax, x + hw / 2, hy0, x + hw / 2, 5.15,
              color=W["vermillion"], lw=0.9, mutation=9)

    # Compound gate
    box(ax, 0.4, 4.30, 13.2, 0.85,
        "compound gate  $\\mathtt{maybe\\_kill(cg,\\ case)}$  —  "
        "Case A (strict)  ·  Case D (self-inflicted)  ·  Case X (trust-gated)",
        color=W["vermillion"], ec=W["black"], fontsize=9, weight="bold",
        textcolor="white")

    # Three action outcomes
    box(ax, 0.4, 2.75, 4.0, 1.20,
        "Case A — strict invariant\n"
        "• burn client_trust = BURNED\n"
        "• drop_ip_list[ip] = now + 5 min\n"
        "• (fallback) bpf_send_signal(SIGKILL)",
        color="#FFDDDD", ec=W["vermillion"], fontsize=7.8)
    box(ax, 4.7, 2.75, 4.0, 1.20,
        "Case D — self-inflicted\n"
        "• no external attacker\n"
        "• bpf_send_signal(SIGKILL)\n"
        "• clears fork-rate state",
        color="#F9E5D5", ec=W["orange"], fontsize=7.8)
    box(ax, 9.0, 2.75, 4.6, 1.20,
        "Case X — soft bit, trust-gated\n"
        "• trust = CALIBRATED → allow + Tier-3\n"
        "• trust = UNKNOWN/OBSERVED → drop session\n"
        "• no permanent trust burn",
        color="#DDEEFF", ec=W["sky"], fontsize=7.8)

    for x in (2.4, 6.7, 11.3):
        arrow(ax, x, 4.30, x, 3.98, color=W["darkgrey"], lw=0.8, mutation=9)

    # Downstream maps touched
    box(ax, 0.4, 1.25, 4.0, 1.10,
        "writes:\nclient_trust · drop_ip_list\nalerts_rb",
        color=W["lightgrey"], ec=W["darkgrey"], fontsize=7.5)
    box(ax, 4.7, 1.25, 4.0, 1.10,
        "kills:\nvictim PID only\nno network-layer action",
        color=W["lightgrey"], ec=W["darkgrey"], fontsize=7.5)
    box(ax, 9.0, 1.25, 4.6, 1.10,
        "waits:\ndefers decision to Tier-3\nnext 5-s cycle compounds evidence",
        color=W["lightgrey"], ec=W["darkgrey"], fontsize=7.5)

    for x in (2.4, 6.7, 11.3):
        arrow(ax, x, 2.75, x, 2.40, color=W["darkgrey"], lw=0.7, mutation=8)

    ax.text(7.0, 0.55,
            "All six handlers route enforcement through one point; "
            "only three outcomes are possible.",
            ha="center", fontsize=7.5, style="italic", color=W["darkgrey"])

    _save(fig, "fig_arch_tier1_detail")


# ── Fig 4.3: Normal-traffic data flow ──────────────────────────────────────
def fig_dataflow_normal():
    plt.rcParams.update(PAPER_STYLE)
    fig, ax = plt.subplots(figsize=(11.0, 5.6))
    ax.set_xlim(0, 14.0)
    ax.set_ylim(0, 7.2)
    ax.axis("off")

    ax.text(7.0, 6.95, "Information flow — benign traffic (no alert fires)",
            ha="center", fontsize=10.5, weight="bold")

    # Actors
    box(ax, 0.2, 4.55, 2.4, 1.10,
        "legitimate client\n10.88.0.100",
        color=W["green"], ec=W["black"], fontsize=8, weight="bold",
        textcolor="white")
    box(ax, 5.4, 4.55, 3.2, 1.10,
        "ct-webapp-a\n(inside container)",
        color=W["sky"], ec=W["blue"], fontsize=8, weight="bold")
    box(ax, 10.6, 4.55, 3.2, 1.10,
        "Tier-1 dispatcher\n+ handlers (in kernel)",
        color=W["orange"], ec=W["vermillion"], fontsize=8, weight="bold")

    box(ax, 5.4, 2.40, 3.2, 1.00,
        "BPF maps\nCMS bigrams · behaviour bits",
        color=W["lightgrey"], ec=W["darkgrey"], fontsize=8)
    box(ax, 10.6, 2.40, 3.2, 1.00,
        "Tier-3 daemon\n(5 s cycle, userspace)",
        color=W["green"], ec=W["black"], fontsize=8, textcolor="white")

    box(ax, 0.2, 2.40, 2.4, 1.00,
        "trust promoter\n(userspace worker)",
        color=W["pink"], ec=W["black"], fontsize=7.5)

    # Numbered steps
    def lbl(ax, x, y, n, text, col=W["black"]):
        ax.text(x, y, f"({n})", fontsize=8.5, weight="bold", color=col)
        ax.text(x + 0.45, y, text, fontsize=7.8, color=col)

    # (1) client → webapp
    arrow(ax, 2.6, 5.10, 5.4, 5.10, color=W["green"], lw=1.3)
    lbl(ax, 3.0, 5.40, 1, "HTTP request", W["green"])

    # (2) webapp → syscalls → Tier-1
    arrow(ax, 8.6, 5.10, 10.6, 5.10, color=W["darkgrey"], lw=1.0)
    lbl(ax, 8.7, 5.40, 2, "syscalls (openat, read, sendmsg...)", W["darkgrey"])

    # (3) Tier-1 → maps
    arrow(ax, 12.2, 4.55, 8.0, 3.40, color=W["orange"], lw=1.0)
    lbl(ax, 9.0, 4.10, 3, "CMS update + no invariant match", W["orange"])

    # (4) Tier-3 reads maps
    arrow(ax, 10.6, 2.90, 8.6, 2.90, color=W["green"], lw=1.0, ls="--")
    lbl(ax, 8.8, 3.15, 4, "daemon reads CMS + bits", W["green"])

    # (5) Tier-3 writes verdict=ALLOW (no box drawn, but text)
    box(ax, 10.6, 0.9, 3.2, 1.00,
        "verdict_map\nALLOW (severity = NONE)",
        color="#DDFFDD", ec=W["green"], fontsize=7.5)
    arrow(ax, 12.2, 2.40, 12.2, 1.90, color=W["green"], lw=1.0, ls="--")
    lbl(ax, 12.7, 2.10, 5, "no action", W["green"])

    # (6) Trust promoter reads context, upgrades OBSERVED -> CALIBRATED
    arrow(ax, 1.4, 4.55, 1.4, 3.40, color=W["pink"], lw=1.0)
    lbl(ax, 0.25, 3.90, 6, "bytes ≥ 5120 AND time ≥ 1 s", W["pink"])
    arrow(ax, 2.6, 2.90, 5.4, 2.90, color=W["pink"], lw=1.0)
    lbl(ax, 2.7, 3.15, 7, "trust[client] := CALIBRATED", W["pink"])

    # Takeaway
    ax.text(7.0, 0.35,
            "Benign request completes; CMS accumulates normal bigrams; "
            "Tier-3 verdict = NONE; client earns trust.",
            ha="center", fontsize=7.8, style="italic", color=W["darkgrey"])

    _save(fig, "fig_dataflow_normal")


# ── Fig 4.4: Attack-detection data flow ────────────────────────────────────
def fig_dataflow_attack():
    plt.rcParams.update(PAPER_STYLE)
    fig, ax = plt.subplots(figsize=(12.0, 8.0))
    ax.set_xlim(0, 15.0)
    ax.set_ylim(0, 10.0)
    ax.axis("off")

    ax.text(7.5, 9.70, "Information flow — detected attack (S2 reverse shell → S7 pivot)",
            ha="center", fontsize=10.5, weight="bold")

    # Row 1 actors (user/kernel boundary top)
    box(ax, 0.2, 7.85, 2.4, 1.10,
        "ct_attacker\n10.88.1.100",
        color="#FFDDDD", ec=W["vermillion"], fontsize=8, weight="bold")
    box(ax, 6.0, 7.85, 3.0, 1.10,
        "ct-webapp-a\n(exploit lands here)",
        color=W["sky"], ec=W["blue"], fontsize=8, weight="bold")
    box(ax, 11.5, 7.85, 3.3, 1.10,
        "Tier-1 handle_dup2\n(kernel, stateless)",
        color=W["orange"], ec=W["vermillion"], fontsize=8, weight="bold")

    # Row 2 kernel maps
    box(ax, 6.0, 5.50, 3.0, 1.00,
        "behaviour bits\nBIT_FD_REDIRECT = 1",
        color=W["lightgrey"], ec=W["darkgrey"], fontsize=7.5)
    box(ax, 11.5, 5.50, 3.3, 1.00,
        "maybe_kill(cg, 'A')\ncompound gate",
        color=W["vermillion"], ec=W["black"], fontsize=8, weight="bold",
        textcolor="white")

    # Row 3 action maps
    box(ax, 6.0, 3.60, 3.0, 1.00,
        "client_trust\nattacker_ip := BURNED",
        color="#FFDDDD", ec=W["vermillion"], fontsize=7.5)
    box(ax, 11.5, 3.60, 3.3, 1.00,
        "drop_ip_list\n[attacker_ip] = now + 5 m",
        color="#FFDDDD", ec=W["vermillion"], fontsize=7.5)

    # Left side: TC classifier and next packet
    box(ax, 0.2, 5.50, 2.4, 1.00,
        "Tier-2 TC\nclassifier (veth)",
        color=W["pink"], ec=W["black"], fontsize=7.5, weight="bold")
    box(ax, 0.2, 1.30, 2.4, 1.00,
        "next packet:\nTC_ACT_SHOT",
        color=W["pink"], ec=W["black"], fontsize=7.5, weight="bold")

    # Bottom row: Tier-3 confirmation
    box(ax, 11.5, 1.30, 3.3, 1.00,
        "Tier-3 daemon\nnovel edge → HIGH",
        color=W["green"], ec=W["black"], fontsize=7.5, weight="bold",
        textcolor="white")
    box(ax, 6.0, 1.30, 3.0, 1.00,
        "verdict_map\nSIGKILL · confirmed",
        color="#FFDDDD", ec=W["vermillion"], fontsize=7.5, weight="bold")

    # Numbered labels — always placed in clear whitespace midway between boxes
    def lbl(ax, x, y, n, text, col=W["black"], ha="center"):
        ax.text(x, y, f"({n}) {text}", fontsize=7.8, color=col,
                weight="bold", ha=ha,
                bbox=dict(boxstyle="round,pad=0.2", facecolor="white",
                          edgecolor="none", alpha=0.85))

    # (1) attacker → webapp
    arrow(ax, 2.6, 8.40, 6.0, 8.40, color=W["vermillion"], lw=1.4)
    lbl(ax, 4.3, 8.70, 1, "RCE payload", W["vermillion"])

    # (2) webapp → Tier-1 (dup2 fires)
    arrow(ax, 9.0, 8.40, 11.5, 8.40, color=W["vermillion"], lw=1.2)
    lbl(ax, 10.25, 8.70, 2, "dup2(sockfd, 0/1/2)", W["vermillion"])

    # (3) Tier-1 → behaviour bits (dashed)
    arrow(ax, 11.5, 8.25, 9.0, 6.20, color=W["orange"], lw=1.0, ls="--")
    lbl(ax, 10.30, 7.25, 3, "set BIT", W["orange"])

    # (4) Tier-1 → gate
    arrow(ax, 13.15, 7.85, 13.15, 6.50, color=W["vermillion"], lw=1.2)
    lbl(ax, 14.0, 7.20, 4, "Case A", W["vermillion"], ha="center")

    # (5) gate → BURNED
    arrow(ax, 11.5, 5.85, 9.0, 4.35, color=W["vermillion"], lw=1.0)
    lbl(ax, 10.30, 5.05, 5, "BURN", W["vermillion"])

    # (6) gate → drop_ip_list
    arrow(ax, 13.15, 5.50, 13.15, 4.60, color=W["vermillion"], lw=1.0)
    lbl(ax, 14.05, 5.00, 6, "TC drop", W["vermillion"])

    # (7) TC classifier consults drop_ip_list (dotted long arrow)
    arrow(ax, 11.5, 4.10, 2.6, 6.00, color=W["pink"], lw=0.9, ls=":")
    lbl(ax, 6.5, 5.15, 7, "packet lookup", W["pink"])

    # (8) next attacker packet → DROP
    arrow(ax, 1.4, 5.50, 1.4, 2.30, color=W["pink"], lw=1.2)
    lbl(ax, 1.4, 3.90, 8, "DROP", W["pink"])

    # (9) gate side → Tier-3 (next cycle)
    arrow(ax, 13.15, 3.60, 13.15, 2.30, color=W["green"], lw=1.0, ls="--")
    lbl(ax, 14.05, 2.95, 9, "T3 cycle", W["green"])

    # (10) Tier-3 → verdict_map
    arrow(ax, 11.5, 1.80, 9.0, 1.80, color=W["green"], lw=1.0, ls="--")
    lbl(ax, 10.25, 2.05, 10, "SIGKILL", W["green"])

    # Takeaway
    ax.text(7.5, 0.35,
            "Tier-1 fires at step 2 (< 5 µs) · Tier-2 drops subsequent packets at step 8 · "
            "Tier-3 adds cross-container confirmation at steps 9–10",
            ha="center", fontsize=7.8, style="italic", color=W["darkgrey"])

    _save(fig, "fig_dataflow_attack")


# ── Fig 4.5: Tier-3 sliding-window cycle ──────────────────────────────────
def fig_sliding_window():
    plt.rcParams.update(PAPER_STYLE)
    fig, ax = plt.subplots(figsize=(11.0, 4.8))
    ax.set_xlim(0, 14.0)
    ax.set_ylim(0, 6.2)
    ax.axis("off")

    ax.text(7.0, 5.90, "Tier-3 — 5-second sliding-window cycle",
            ha="center", fontsize=11, weight="bold")

    # Timeline axis
    ax.plot([0.6, 13.4], [3.3, 3.3], color=W["black"], lw=1.2)
    for i in range(6):
        x = 0.6 + i * (12.8 / 5)
        ax.plot([x, x], [3.20, 3.40], color=W["black"], lw=1.2)
        ax.text(x, 2.95, f"{i*5} s", ha="center", fontsize=8)

    # Shaded cycle windows (4 windows of 5s each)
    cyc_colors = [W["green"], W["sky"], W["orange"], W["pink"]]
    for i in range(4):
        x0 = 0.6 + i * (12.8 / 5)
        x1 = 0.6 + (i + 1) * (12.8 / 5)
        ax.add_patch(Rectangle((x0, 3.50), x1 - x0, 1.10,
                               facecolor=cyc_colors[i], edgecolor=W["black"],
                               alpha=0.28, linewidth=0.8))
        ax.text((x0 + x1) / 2, 4.05, f"cycle N+{i}",
                ha="center", fontsize=8.5, weight="bold")
        ax.text((x0 + x1) / 2, 3.72,
                "ingest · project · Rayleigh · verdict",
                ha="center", fontsize=6.5, style="italic")

    # Below axis: step boxes for what happens inside one cycle
    ax.text(7.0, 2.50, "Inside one cycle N (≈ 50 – 200 ms of CPU time):",
            ha="center", fontsize=8.5, weight="bold", color=W["darkgrey"])

    steps = [
        "1. read CMS per cg",
        "2. read behaviour\n    bits",
        "3. drain telemetry\n    ring buffer",
        "4. extract d = 74\n    signal",
        "5. per-edge energy\n    $r_e^\\top \\Sigma_e^{-1} r_e$",
        "6. global Rayleigh $R$\n    vs $\\tau^{(t)}$",
        "7. compound\n    confirm",
        "8. write verdict\n    + update EMA",
    ]
    sx0 = 0.6
    sw = (13.4 - 0.6) / len(steps) - 0.08
    for i, s in enumerate(steps):
        x = sx0 + i * (sw + 0.08)
        box(ax, x, 0.80, sw, 1.50, s,
            color=W["lightgrey"], ec=W["darkgrey"], fontsize=7)
        if i < len(steps) - 1:
            arrow(ax, x + sw, 1.55, x + sw + 0.08, 1.55,
                  color=W["darkgrey"], lw=0.6, mutation=7)

    # Side note on EMA gate
    ax.text(7.0, 0.35,
            "Guarded EMA: $\\tau^{(t+1)} = (1-\\alpha)\\,\\tau^{(t)} + \\alpha R$ "
            "only if the last six cycles were pristine ($\\alpha = 0.02$).",
            ha="center", fontsize=7.8, style="italic", color=W["darkgrey"])

    _save(fig, "fig_sliding_window")


# ── Threat model (re-done with plain text) ─────────────────────────────────
def fig_threat_model():
    plt.rcParams.update(PAPER_STYLE)
    fig, ax = plt.subplots(figsize=(9.0, 5.0))
    ax.set_xlim(0, 13.0)
    ax.set_ylim(0, 7.0)
    ax.axis("off")

    box(ax, 0.3, 4.20, 3.4, 2.20,
        "ATTACKER\n• remote TCP RCE\n• no host root\n"
        "• scripted payloads\n• may pivot between\n  containers",
        color=W["pink"], ec=W["black"], fontsize=8, weight="bold")
    box(ax, 4.4, 4.20, 4.0, 2.20,
        "ASSETS\n• 22-container mesh\n• database tier data\n"
        "• cross-container flows\n• shared host kernel",
        color=W["sky"], ec=W["blue"], fontsize=8, weight="bold")
    box(ax, 9.1, 4.20, 3.6, 2.20,
        "DEFENDER\n• in-kernel observer\n"
        "• in-kernel enforcer\n• sheaf analyst\n• host-root loader",
        color=W["green"], ec=W["black"], fontsize=8, weight="bold",
        textcolor="white")

    arrow(ax, 3.75, 5.30, 4.35, 5.30, color=W["vermillion"], lw=1.6)
    arrow(ax, 9.05, 5.30, 8.45, 5.30, color=W["green"], lw=1.6)
    ax.text(4.05, 5.55, "attack", fontsize=7.5, ha="center",
            color=W["vermillion"], style="italic")
    ax.text(8.75, 5.55, "control", fontsize=7.5, ha="center",
            color=W["green"], style="italic")

    ax.add_patch(Rectangle((0.3, 1.90), 12.4, 1.80, linewidth=0.8,
                           edgecolor=W["darkgrey"], facecolor=W["lightgrey"],
                           alpha=0.35))
    ax.text(0.5, 3.30, "IN SCOPE", fontsize=8, weight="bold")
    ax.text(0.5, 2.95,
            "S2 / S2a reverse shell  ·  S3 / S3a sensitive file  ·  S4 fork bomb",
            fontsize=7.5)
    ax.text(0.5, 2.65,
            "S5 ns escape  ·  S6 privesc  ·  S7 cross-container pivot",
            fontsize=7.5)
    ax.text(0.5, 2.35,
            "S8 Log4Shell  ·  S9 SSRF→RCE  ·  S10 container escape  ·  S11 fileless memfd",
            fontsize=7.5)

    ax.add_patch(Rectangle((0.3, 0.30), 12.4, 1.25, linewidth=0.8,
                           edgecolor=W["darkgrey"], facecolor=W["lightgrey"],
                           alpha=0.18))
    ax.text(0.5, 1.15, "OUT OF SCOPE", fontsize=8, weight="bold",
            color=W["darkgrey"])
    ax.text(0.5, 0.80,
            "host-root takeover  ·  calibration poisoning  ·  IPv6  ·  kernel-exploit bypass of eBPF",
            fontsize=7.5, color=W["darkgrey"])
    ax.text(0.5, 0.50,
            "hardware side-channels  ·  compromise of the BPF verifier itself",
            fontsize=7.5, color=W["darkgrey"])

    ax.set_title("Threat model — scope boundary", pad=6, fontsize=10)
    _save(fig, "fig_threat_model")


# ── Compound gate (v3, plain text) ─────────────────────────────────────────
def fig_compound_gate():
    plt.rcParams.update(PAPER_STYLE)
    fig, ax = plt.subplots(figsize=(10.0, 6.0))
    ax.set_xlim(0, 13.0)
    ax.set_ylim(0, 7.5)
    ax.axis("off")

    ax.text(6.5, 7.25, "Compound enforcement gate — three routing cases",
            ha="center", fontsize=10.5, weight="bold")

    # Root
    box(ax, 4.7, 6.10, 3.6, 0.75, "maybe_kill(cg, case)",
        color=W["yellow"], ec=W["black"], fontsize=9, weight="bold")

    # Three case boxes
    box(ax, 0.3, 4.10, 4.0, 1.30,
        "Case A — strict invariant\n"
        "dup2→stdio, shell+socket,\nsetuid(0), unshare, log4shell",
        color=W["vermillion"], ec=W["black"], fontsize=8, weight="bold",
        textcolor="white")
    box(ax, 4.5, 4.10, 4.0, 1.30,
        "Case D — self-inflicted\nfork bomb ($d^{2} > 0$)\nrunaway workload",
        color=W["orange"], ec=W["black"], fontsize=8, weight="bold")
    box(ax, 8.7, 4.10, 4.0, 1.30,
        "Case X — soft bit\ntrust-gated by client IP\n"
        "(plain shell, lone openat)",
        color=W["sky"], ec=W["black"], fontsize=8, weight="bold")

    arrow(ax, 5.7, 6.10, 2.3, 5.40, color=W["black"], lw=1.0)
    arrow(ax, 6.5, 6.10, 6.5, 5.40, color=W["black"], lw=1.0)
    arrow(ax, 7.3, 6.10, 10.7, 5.40, color=W["black"], lw=1.0)

    # Downstream actions
    box(ax, 0.3, 2.00, 4.0, 1.40,
        "client IP attributable?\n"
        "yes → BURN  +  TC drop 5 min\n"
        "no  → SIGKILL task",
        color=W["pink"], ec=W["black"], fontsize=7.8)
    box(ax, 4.5, 2.00, 4.0, 1.40,
        "SIGKILL task\n(no external party)",
        color=W["lightgrey"], ec=W["darkgrey"], fontsize=8)
    box(ax, 8.7, 2.00, 4.0, 1.40,
        "trust = CALIBRATED?\n"
        "yes → ALLOW (Case B)\n"
        "no  → drop session (Case C)",
        color=W["pink"], ec=W["black"], fontsize=7.8)

    arrow(ax, 2.3, 4.10, 2.3, 3.40, color=W["vermillion"], lw=1.0)
    arrow(ax, 6.5, 4.10, 6.5, 3.40, color=W["orange"], lw=1.0)
    arrow(ax, 10.7, 4.10, 10.7, 3.40, color=W["sky"], lw=1.0)

    # Final outcome row
    box(ax, 0.3, 0.40, 4.0, 1.00, "attacker IP burned +\n"
        "5-min packet drop",
        color="#FFDDDD", ec=W["vermillion"], fontsize=8, weight="bold")
    box(ax, 4.5, 0.40, 4.0, 1.00, "offending task killed\n(in-kernel)",
        color="#F9E5D5", ec=W["orange"], fontsize=8, weight="bold")
    box(ax, 8.7, 0.40, 4.0, 1.00, "graceful path or\nsession drop",
        color="#DDEEFF", ec=W["sky"], fontsize=8, weight="bold")
    for x in (2.3, 6.5, 10.7):
        arrow(ax, x, 2.00, x, 1.40, color=W["darkgrey"], lw=0.7, mutation=9)

    _save(fig, "fig_compound_gate")


# ── Trust FSM ──────────────────────────────────────────────────────────────
def fig_trust_state_machine():
    plt.rcParams.update(PAPER_STYLE)
    fig, ax = plt.subplots(figsize=(10.0, 4.4))
    ax.set_xlim(0, 12.5)
    ax.set_ylim(0, 5.0)
    ax.axis("off")

    ax.text(6.25, 4.75, "Per-client trust automaton",
            ha="center", fontsize=10.5, weight="bold")

    states = [
        ("UNKNOWN\n(0)",    1.4, 2.6, W["lightgrey"], "black"),
        ("OBSERVED\n(1)",   4.4, 2.6, W["sky"],       "black"),
        ("CALIBRATED\n(2)", 7.9, 2.6, W["green"],     "white"),
        ("BURNED\n(255)",  11.0, 2.6, W["vermillion"], "white"),
    ]
    for label, x, y, c, textcol in states:
        ax.add_patch(Circle((x, y), 0.85, facecolor=c,
                            edgecolor=W["black"], linewidth=1.2))
        ax.text(x, y, label, ha="center", va="center", fontsize=8.5,
                weight="bold", color=textcol)

    trans = [
        (2.25, 2.6, 3.55, 2.6,  "first SYN\nfrom IP"),
        (5.25, 2.6, 7.05, 2.6,  "bytes ≥ 5120 AND\ntime ≥ 1 s"),
        (7.90, 1.75, 10.75, 1.75, "Case A breach\n(strict invariant)"),
        (4.40, 3.45, 10.75, 3.45, "Case X breach\nwhile untrusted"),
    ]
    for x1, y1, x2, y2, lbl in trans:
        arrow(ax, x1, y1, x2, y2, color=W["black"], lw=1.1, mutation=11)
        ax.text((x1 + x2) / 2, y2 + 0.33, lbl, ha="center",
                fontsize=7.5, style="italic")

    actions = [("action: ALLOW", 1.4),
               ("action: ALLOW", 4.4),
               ("action: soft-gate (Case X)", 7.9),
               ("action: drop 5 min", 11.0)]
    for t, x in actions:
        ax.text(x, 0.70, t, ha="center", fontsize=7.5,
                color=W["vermillion"] if "drop" in t else W["darkgrey"],
                weight="bold" if "drop" in t else "normal")

    _save(fig, "fig_trust_state_machine")


# ── Testbed topology ───────────────────────────────────────────────────────
def fig_testbed_topology():
    plt.rcParams.update(PAPER_STYLE)
    fig, ax = plt.subplots(figsize=(10.0, 6.0))
    ax.set_xlim(0, 14.0)
    ax.set_ylim(0, 8.0)
    ax.axis("off")

    # Prod bridge
    ax.add_patch(Rectangle((1.1, 1.3), 10.3, 4.7, linewidth=1.3,
        edgecolor=W["blue"], facecolor="#E8F1FB", alpha=0.55))
    ax.text(6.25, 5.75, "ct_prod_net    10.88.0.0/24",
            ha="center", fontsize=9, weight="bold", color=W["blue"])

    names = [
        "ct-nginx",     "ct-webapp-a", "ct-webapp-b", "ct-api-gw",  "ct-product",
        "ct-inventory", "ct-order",    "ct-payment",  "ct-user",    "ct-notification",
        "ct-redis",     "ct-postgres", "ct-cart",     "ct-auth",    "ct-search",
        "ct-analytics", "ct-logger",   "ct-metrics",  "ct-prom",    "ct-grafana",
    ]
    cols = 5
    for i, n in enumerate(names):
        r, c = divmod(i, cols)
        x = 1.35 + c * 1.98
        y = 4.80 - r * 0.80
        box(ax, x, y, 1.85, 0.55, n,
            color=W["sky"], ec=W["blue"], fontsize=7)

    ax.text(6.25, 1.45,
            "20 workload services running Python HTTPServer",
            ha="center", fontsize=7.5, color=W["darkgrey"], style="italic")

    # Attack bridge (right)
    ax.add_patch(Rectangle((11.7, 1.3), 2.1, 4.7, linewidth=1.3,
        edgecolor=W["vermillion"], facecolor="#FEECE3", alpha=0.55))
    ax.text(12.75, 5.75,
            "ct_attack_net\n10.88.1.0/24",
            ha="center", fontsize=8.5, weight="bold", color=W["vermillion"])
    box(ax, 11.85, 3.1, 1.8, 0.75,
        "ct_attacker\n10.88.1.100",
        color=W["pink"], ec=W["vermillion"], fontsize=7.5, weight="bold")

    # Legit client (left)
    box(ax, 0.1, 3.1, 1.0, 0.75,
        "ct_legit\n.100",
        color=W["green"], ec=W["black"], fontsize=7.5, weight="bold",
        textcolor="white")
    arrow(ax, 1.10, 3.48, 1.30, 3.48, color=W["green"], lw=1.0)
    arrow(ax, 11.85, 3.48, 11.55, 3.48, color=W["vermillion"], lw=1.0)
    ax.text(11.40, 3.70, "cross-bridge\nforwarding",
            fontsize=6.5, color=W["vermillion"], ha="right", style="italic")

    # Host kernel banner
    ax.add_patch(Rectangle((0.2, 6.80), 13.6, 0.80, linewidth=1.0,
        edgecolor=W["black"], facecolor=W["yellow"], alpha=0.7))
    ax.text(7.0, 7.20,
            "Host kernel (Linux 6.17)  ·  CausalTrace eBPF  ·  Tier-3 sheaf daemon",
            ha="center", fontsize=9, weight="bold")

    ax.set_title("Testbed topology — 20 workload services + isolated attacker bridge",
                 pad=6, fontsize=10)
    _save(fig, "fig_testbed_topology")


def main():
    fig_arch_overview()
    fig_arch_tier1_detail()
    fig_dataflow_normal()
    fig_dataflow_attack()
    fig_sliding_window()
    fig_threat_model()
    fig_compound_gate()
    fig_trust_state_machine()
    fig_testbed_topology()
    # Back-compat alias so chap_4.tex's old \includegraphics still resolves.
    import shutil
    for src, dst in [
        ("fig_arch_overview.pdf",        "fig_system_architecture.pdf"),
        ("fig_arch_overview.png",        "fig_system_architecture.png"),
    ]:
        if (OUT / src).exists():
            shutil.copy(OUT / src, OUT / dst)
            print(f"  alias  {dst}  →  {src}")


if __name__ == "__main__":
    main()
