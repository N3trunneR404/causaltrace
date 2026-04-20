# CausalTrace

**Runtime container defense via kernel invariants and sheaf coupling.**

Three-tier eBPF system that closes the gap between per-syscall rule engines (Falco, Tetragon) and the multi-step, cross-container attack chains they miss.

| Detector | Detections / 155 injections | TPR (95% CI) |
|---|---|---|
| **CausalTrace** | **154 / 155** | **99.4% [96, 100]** |
| Falco (tuned) | 109 / 155 | 70.3% [63, 77] |
| Tetragon (tuned) | 2 / 155 | 1.3% [0, 5] |
| Tetragon (stock) | 0 / 155 | 0.0% |

Marathon: 155 injections, seed-42 permutation, 22-container mesh, Ubuntu 22.04, kernel 6.17, BCC 0.31.

---

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│ Tier 1  (eBPF, in kernel)                                  │
│   raw_tracepoint/sys_enter → tail-call dispatcher          │
│   6 invariant handlers:                                    │
│     handle_fork    — d² clone burst → SIGKILL              │
│     handle_execve  — path-class OOD → SIGKILL              │
│     handle_file    — /etc/shadow prefix → SIGKILL          │
│     handle_privesc — rare-syscall Top-24 chain → SIGKILL   │
│     handle_dup2    — socket fd in stdio slots → SIGKILL    │
│     trace_connect  — novel TCP edge → alert                │
│   Compound gate: Case A (strict) / D (self-inflicted) /    │
│     B (trusted soft allow) / C (untrusted drop-session)    │
│   TC clsact direct-action drops attacker IP at veth        │
├────────────────────────────────────────────────────────────┤
│ Tier 2  (eBPF, in kernel)                                  │
│   tcp_v4_connect kprobe  — novel-edge detection            │
│   inet_csk_accept kretprobe — per-TID client attribution   │
│   sched_process_{fork,exec} — process lineage              │
│   tcp_sendmsg / tcp_recvmsg — L4 byte accumulation         │
│   Trust FSM: UNKNOWN → OBSERVED → CALIBRATED → BURNED      │
│     L4-stability gate: ≥5120 B AND ≥1 s of clean traffic   │
├────────────────────────────────────────────────────────────┤
│ Tier 3  (Python, user space, 5-second cycle)               │
│   Signal: d=74  (3 entropy + 50 PCA + 20 marginals + 1)    │
│   CCA restriction maps at rank k=15 across observed edges  │
│   Mahalanobis edge energy (χ²₁₅) + global Rayleigh R(x)   │
│   Guarded EMA (α=0.02, 6-cycle pristine-streak gate)       │
│   Semantic labels + MITRE ATT&CK IDs on every verdict      │
└────────────────────────────────────────────────────────────┘
```

Architecture diagrams: [`BTech_Project_Report/figures/`](BTech_Project_Report/figures/)

---

## Requirements

| Requirement | Minimum | Tested on |
|---|---|---|
| Linux kernel | 5.8 (RINGBUF) | 6.17.0-22 |
| BCC | 0.25 | 0.31 |
| clang / LLVM | 12 | 18 |
| Docker Engine | 20.10 | 27.x |
| Python | 3.10 | 3.12 |
| RAM | 4 GB | 32 GB |
| CPU | 4 cores | 8 cores |

> **Platform note.** CausalTrace requires Linux `raw_tracepoint/sys_enter` (≥4.17), BPF ring buffer (≥5.8), and `bpf_send_signal` (≥5.3). It works on bare-metal, KVM/QEMU, and any container runtime that mounts cgroups v2 (Kubernetes, Podman, Singularity/HPC). Windows and macOS are not supported — they do not expose the Linux tracepoint ABI.

---

## Fresh-install setup (Ubuntu 22.04 / 24.04)

Everything below can be copy-pasted into a terminal running as a user with `sudo`.

### 1. Clone the repository

```bash
git clone https://github.com/N3trunneR404/causaltrace.git
cd causaltrace
```

### 2. Install system dependencies and Python venv

```bash
sudo bash install.sh
```

This installs: `bpfcc-tools`, `python3-bcc`, `clang`, `llvm`, `linux-headers-$(uname -r)`, `docker.io`, `docker-compose-v2`, `iproute2`, `bpftool`, `python3-venv`. Mounts `/sys/fs/bpf` and creates `/sys/fs/bpf/causaltrace`. Creates `./venv` and `pip install`s `requirements.txt`.

If you are on a kernel that ships BCC as a system package older than 0.25, install from source:

```bash
sudo apt-get remove -y bpfcc-tools python3-bcc
# Follow https://github.com/iovisor/bcc/blob/master/INSTALL.md#ubuntu---source
```

### 3. Activate the venv

```bash
source venv/bin/activate
# All subsequent python3 / pip commands use this venv.
```

### 4. Start the testbed

The testbed is a 22-container mesh (20 microservices + 1 legit client + 1 attacker):

```bash
docker compose up -d
```

Verify all containers are running and can reach each other:

```bash
bash scripts/preflight.sh
bash scripts/test_connectivity.sh
```

Expected output ends with: `All connectivity checks passed`.

### 5. Set up inter-network routing (once per boot)

```bash
sudo bash scripts/setup_routes.sh
```

---

## Option A: Use the pre-calibrated data (recommended for verification)

The repository ships calibration artifacts from the marathon run. Skip the 30-minute calibration and go straight to detection:

```bash
# Start CausalTrace in enforce mode using pre-calibrated data
sudo python3 supervisor.py -- --mode enforce
```

In a second terminal, fire any attack:

```bash
# Interactive menu — pick any scenario from the list
bash attacks/interactive_menu.sh

# Or fire a specific scenario directly
bash attacks/scenario_2_reverse_shell.sh
bash attacks/scenario_7_cross_container.sh   # cross-container lateral movement
bash attacks/scenario_11_fileless_memfd.sh   # OOD fileless payload
```

Watch verdicts stream in real time:

```bash
tail -f results/run_production/verdicts.jsonl | python3 -c "
import sys, json
for line in sys.stdin:
    v = json.loads(line)
    print(f\"{v['action']:8s} {v.get('label',''):35s} R={v.get('rayleigh',0):.3f}  {v.get('mitre',[])}\")
"
```

---

## Option B: Full calibration from scratch

Run the 30-minute calibration pipeline against live traffic from the testbed:

```bash
sudo bash run_calibration.sh 1800   # 30 minutes (recommended)
# sudo bash run_calibration.sh 420  # 7 minutes for a quick sanity check
```

Artifacts written to `calibration/`:

| File | Purpose |
|---|---|
| `restriction_maps.npz` | CCA restriction matrices (k=15) per edge |
| `pca.pkl` | PCA whitener (50-component) for the bigram space |
| `whiteners.pkl` | Per-container per-edge whitening parameters |
| `edge_thresholds.json` | Per-edge Mahalanobis τ = mean + 4σ |
| `global_threshold.json` | Global Rayleigh τ_global |
| `calibrated_edges.json` | Edge graph used during calibration |

Then start enforcement:

```bash
sudo python3 supervisor.py -- --mode enforce
```

---

## Reproducing the marathon evaluation

The full 12-hour marathon (CausalTrace + Falco + Tetragon, 155 injections) is orchestrated by `run_marathon_evaluation.py`.

```bash
# Full 12-hour run — produces all results/marathon/ files
sudo python3 run_marathon_evaluation.py

# Resume after interruption
sudo python3 run_marathon_evaluation.py --resume

# Dry-run: print the attack schedule without executing anything
python3 run_marathon_evaluation.py --dry-run
```

The pre-run marathon outputs are committed under `results/marathon/`:

| File | Description |
|---|---|
| `attacks.jsonl` | 775 timestamped injection records |
| `results_fast/verdicts.jsonl` | 791 CausalTrace verdict records |
| `results_fast/signals.jsonl` | Per-cycle d=74 signal vectors |
| `falco_stock.jsonl` | Falco stock-rules alerts |
| `falco_tuned.jsonl` | Falco tuned-rules alerts |
| `tetragon_stock.jsonl` | Tetragon stock-policy events |
| `tetragon_tuned.jsonl` | Tetragon CTEval-policy events |
| `loader.log` | Tier-1 SIGKILL / TC-drop log |
| `detection_timeline.json` | Per-attack latency (injection → first verdict) |

Analyse results without re-running the marathon:

```bash
python3 scripts/marathon_analyze.py results/marathon/
```

---

## Attack scenarios

| ID | Script | Kernel primitive | MITRE |
|---|---|---|---|
| S1 | `scenario_1_normal.sh` | curl/wrk requests (negative control) | — |
| S2 | `scenario_2_reverse_shell.sh` | `dup2(sock, 0\|1\|2)` | T1059 |
| S2a | `scenario_2a_evade.sh` | `dup2` + syscall-noise padding | T1059 |
| S3 | `scenario_3_sensitive_file.sh` | `openat("/etc/shadow")` | T1552 |
| S3a | `scenario_3_evade.sh` | `openat("/etc/sha*")` + noise padding | T1552 |
| S4 | `scenario_4_fork_bomb.sh` | d²>0 clone burst | T1499 |
| S5 | `scenario_5_ns_escape.sh` | `nsenter → setns(fd, _NEWNS)` | T1611 |
| S6 | `scenario_6_privesc.sh` | `unshare(_NEWUSER\|_NEWNS) + setuid(0)` | T1620 |
| S7 | `scenario_7_cross_container.sh` | lateral `connect` + foothold | T1021 |
| S8 | `scenario_8_log4shell.sh` | JNDI `ldap://` → shell | T1190 |
| S9 | `scenario_9_ssrf_rce.sh` | SSRF → pivot → RCE | T1068 |
| S10 | `scenario_10_container_escape.sh` | `unshare`, `mount`, `memfd`, `bpf()` chain | T1611 |
| S11 | `scenario_11_fileless_memfd.sh` | `memfd_create` + `execveat` (OOD, held-out) | T1055 |

S2a and S3a are evasion variants: they interleave bursts of harmless noise syscalls (`getpid`, `gettid`, `clock_gettime`) to dilute the bigram CMS sketch toward uniform. Tier-1's invariant handlers still fire because the contract violation (socket fd in stdio slots; path prefix `/etc/sha*`) is orthogonal to bigram frequency. S11 is out-of-distribution — the `execveat` path class was never seen during calibration.

---

## Repository layout

```
causaltrace/
├── kernel/                    # eBPF C source
│   ├── causaltrace_bcc.c      # top-level BCC include
│   ├── causaltrace_common.h   # shared struct definitions
│   ├── causaltrace_maps.h     # all BPF map declarations
│   ├── dispatcher.bpf.c       # raw_tracepoint/sys_enter + tail-call dispatch
│   ├── handler_dup2.bpf.c     # Tier-1: socket→stdio invariant
│   ├── handler_execve.bpf.c   # Tier-1: execve path-class check
│   ├── handler_file.bpf.c     # Tier-1: sensitive-file access
│   ├── handler_fork.bpf.c     # Tier-1: fork-bomb detector
│   ├── handler_privesc.bpf.c  # Tier-1: privesc + Top-24 rare-syscall
│   ├── probe_b_network.bpf.c  # Tier-2: TCP connect/accept/bytes
│   └── probe_c_lineage.bpf.c  # Tier-2: fork/exec lineage
├── tier3/                     # Python sheaf daemon
│   ├── signal_extractor.py    # d=74 signal from BPF ring buffer
│   ├── calibrate.py           # CCA calibration pipeline
│   ├── sheaf_detector.py      # Mahalanobis edge energy + Rayleigh quotient
│   ├── trust_promoter.py      # Trust FSM (UNKNOWN→CALIBRATED)
│   ├── enforcement_engine.py  # Compound gate (A / B / C / D)
│   ├── ema_buffer.py          # Guarded EMA (α=0.02, 6-cycle streak)
│   ├── verdict_writer.py      # JSONL verdict stream
│   └── eigenmode_analyzer.py  # Semantic label + MITRE ID lookup
├── infra/
│   ├── docker_event_listener.py   # Docker event → ip_to_cgroup map
│   └── cgroup_snapshot.py         # cgroup v2 ID discovery
├── attacks/                   # Attack scripts (S1–S11 + evasion variants)
├── calibration/               # Pre-calibrated artifacts (committed)
├── results/marathon/          # Full marathon results (committed)
├── scripts/                   # Preflight, traffic gen, analysis helpers
├── testbed-production/        # Dockerfile + configs for all 20 services
├── BTech_Project_Report/      # LaTeX thesis source + figures
├── docs/
│   ├── architecture.md        # Detailed design notes
│   ├── ops-runbook.md         # Production runbook
│   └── threat-model.md        # Threat model
├── loader.py                  # BPF program loader + container registrar
├── supervisor.py              # Process supervisor (respawn on crash)
├── run_calibration.sh         # Calibration pipeline wrapper
├── run_marathon_evaluation.py # 12-hour marathon orchestrator
├── install.sh                 # Idempotent fresh-install script
├── docker-compose.yml         # 22-container testbed
└── requirements.txt           # Python dependencies
```

---

## Stopping CausalTrace

```bash
# Graceful stop (supervisor forwards SIGTERM, waits, cleans up TC pins)
sudo pkill -f supervisor.py

# Verify TC filters are gone
sudo tc filter show dev eth0 ingress 2>/dev/null || true

# Remove BPF pins manually if supervisor crashed hard
sudo rm -rf /sys/fs/bpf/causaltrace/*
```

---

## Per-scenario detection summary

| Scenario | Injections | Detected | TPR |
|---|---|---|---|
| S2 Reverse shell | 14 | 14 | 100% |
| S2a Evasion (noise pad) | 14 | 14 | 100% |
| S3 Sensitive file | 14 | 14 | 100% |
| S3a Evasion (noise pad) | 14 | 14 | 100% |
| S4 Fork bomb | 14 | 14 | 100% |
| S5 NS escape | 14 | 14 | 100% |
| S6 Privesc | 14 | 14 | 100% |
| S7 Cross-container lateral | 14 | 14 | 100% |
| S8 Log4Shell | 14 | 14 | 100% |
| S9 SSRF → RCE | 14 | 14 | 100% |
| S10 Container escape | 14 | 13 | 93% |
| S11 Fileless memfd (OOD) | 5 | 5 | 100% |
| **Total** | **155** | **154** | **99.4%** |

The single miss in S10 is a container-escape attempt where the rare-syscall chain did not exceed the Top-24 threshold within the 5-second Tier-3 cycle window before the container was recycled. Tier-1 fired on `memfd_create` for 13 of 14 injections.

Wilson 95% confidence intervals: CausalTrace [96, 100], Falco tuned [63, 77], Tetragon tuned [0, 5].

---

## Theoretical guarantees

Four theorems proved in Chapter 5 of the thesis:

- **T1 Invariant Necessity** — any kernel-level execution of the six invariant attack classes necessarily triggers the corresponding Tier-1 handler in O(1) per syscall.
- **T2 Bigram-Noise Adversarial Closure** — noise-syscall padding cannot suppress the invariant check; the invariant fires independent of bigram frequency.
- **T3 Two-Layer Completeness** — if both the Tier-1 invariant check and the Tier-3 Rayleigh threshold are set, any attack reachable through the calibrated edge graph is detected.
- **T4 Trust-Promotion Soundness** — the L4-stability gate (≥5120 B, ≥1 s) prevents an attacker from earning CALIBRATED trust through a short burst of legitimate traffic.

Full proofs: [`BTech_Project_Report/chap_5.tex`](BTech_Project_Report/chap_5.tex).

---

## Citation

Shubhankar Bhattacharya
*CausalTrace: Runtime Container Defense via Kernel Invariants and Sheaf Coupling.*
B.Tech. Project Report, IIITDM Kurnool, April 2026.

---

> **Security notice.** CausalTrace runs with root privileges and issues `bpf_send_signal(SIGKILL)` and TC `TC_ACT_SHOT` drops. Deploy in a dedicated test environment. See [`docs/threat-model.md`](docs/threat-model.md).
