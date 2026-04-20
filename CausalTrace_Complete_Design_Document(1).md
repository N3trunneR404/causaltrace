# CausalTrace — Complete Design and Implementation Document

**Version:** Final (April 2026) — Authoritative implementation reference  
**Authors:** Shubhankar Bhattacharya (122CS0047), Anmol Kashyap (122CS0039)  
**Guide:** Dr. Anil Kumar R, Department of CSE, IIITDM Kurnool  
**Document purpose:** Complete specification for implementing CausalTrace from scratch.
Every design decision is recorded alongside the problem that motivated it.
A developer reading only this document should be able to implement the entire system.

---

## TABLE OF CONTENTS

1. Project Background and Motivation
2. Baseline Evaluation Results (Mid-Review Findings)
3. Research Gaps — Formal Statement
4. Final Architecture — v5 Overview
5. Design Decision Log (Problem → Solution pairs from all critique rounds)
6. Kernel-Space Implementation — Tier 1 (Stateless Enforcement)
7. Kernel-Space Implementation — Tier 2 (Data Collection + In-Kernel Patterns)
8. User-Space Implementation — Tier 3 (Sheaf Daemon)
9. Infrastructure: BCC Loader, Docker Event Listener
10. Testbed and Attack Scenarios
11. Evaluation Plan
12. File Manifest and Implementation Order
13. Mathematical Reference

---

## 1. PROJECT BACKGROUND AND MOTIVATION

### 1.1 The Container Security Problem

Container technologies (Docker, Kubernetes) provide lightweight process isolation through Linux namespaces and cgroups. However, isolation is enforced at the kernel level through the **shared syscall interface**, creating a fundamental vulnerability: a containerised process that knows the right sequence of individually-legitimate syscalls can escape its container entirely.

Example escape sequence:
```
openat("/proc/1/ns/mnt", O_RDONLY)   # legitimate: reading a file
setns(fd, CLONE_NEWNS)                # legitimate: switching namespaces
→ CONTAINER ESCAPED                   # only the sequence is malicious
```

Each syscall is individually permitted. Only the causal sequence reveals the attack. This is the **core problem** CausalTrace addresses.

### 1.2 Why Existing Tools Fail

Existing eBPF security tools (Falco, Tetragon, Tracee) operate on **individual syscall events** or **statically defined rules**. They share three fundamental limitations:

**Semantic blindness:** The same syscall means different things depending on calling context:
- `openat("/etc/passwd")` → benign when called by `apt-get` (UID lookup), malicious when called by an attacker (credential theft)
- `clone()` burst → benign during `make -j16` (parallel build), malicious during a fork bomb
- `setuid(0)` → benign when called by `runc` during container init, malicious when called by an attacker

Rule-based systems cannot resolve this semantic gap. Our mid-review experiments confirmed this experimentally: Baseline B required a 12-entry process whitelist to avoid blocking legitimate container operations, and each whitelisted name is an evasion vector (rename your attack binary to "apt-get").

**Single-container scope:** All reviewed systems operate per-container. Multi-stage attacks that traverse container boundaries (Web → API → DB lateral movement) are completely invisible to single-container monitors.

**No temporal reasoning:** Bag-of-system-calls (BoSC) approaches aggregate syscall frequencies without ordering. The sequence `openat → setns` is not distinguished from `setns → openat`, even though only the former is a namespace escape.

### 1.3 CausalTrace's Approach

CausalTrace addresses all three limitations through a three-tier architecture:

- **Tier 1 (kernel, ~μs):** Deterministic invariant detectors for known attack classes. An invariant is a physical operation the attacker *must* perform regardless of language, evasion technique, or obfuscation. Example: any reverse shell must call `dup2(sockfd, 0)` to redirect stdin to a socket. This is a physical requirement — there is no reverse shell without it.

- **Tier 2 (kernel, ~μs):** Data collection and in-kernel multi-step pattern detection. Tracks network connections between containers, maintains per-container behavioral bitfields, detects two-hop attack patterns (shell spawn + lateral connect) entirely in-kernel.

- **Tier 3 (user-space, ~1s):** Sheaf Laplacian spectral detector for *unknown* attacks — attacks for which no invariant has been written. Uses algebraic topology to detect inter-container behavioral inconsistency. A container whose syscall distribution has shifted from its calibrated baseline creates measurable inconsistency with its neighbors in the container communication graph.

---

## 2. BASELINE EVALUATION RESULTS (MID-REVIEW FINDINGS)

These results are from the February 2026 mid-review. They are the experimental foundation for CausalTrace's design choices.

### 2.1 Baseline A: Bertinatto BoSC Replication

**What it does:** Attaches a raw tracepoint to `sys_enter`, builds per-process Bag-of-System-Calls (BoSC) frequency vectors, detects anomalies by comparing against normal profiles.

**Implementation platform:** GCP e2-standard-2, Ubuntu 22.04, kernel 6.8.0

**Six kernel 6.8 compatibility bugs fixed during implementation:**
1. `struct mnt_namespace` incomplete definition → fixed by reading full `struct ns_common` (layout on 6.8: stash at +0, ops at +8, inum at +16)
2. Self-tracing feedback loop → fixed by filtering tracer PID via `BPF_ARRAY(ignore_pid)`
3. Ring buffer overflow → fixed by early filtering of high-volume syscalls (`futex`, `epoll_wait`)
4. Home directory expansion under sudo → fixed with `os.path.expanduser()`
5. PID truncation → fixed with proper u64 pid_tgid handling
6. Incorrect `ns_common.inum` offset → was reading `atomic_long_t stash` at offset 0 instead of `inum` at offset 16

**Results:**
- Captured 35,096 syscall events
- Fired 1 alert (container escape: `openat(/proc/1/ns/mnt)` + `setns(CLONE_NEWNS)`)
- **Missed 4 of 5 attacks:** fork bomb, reverse shell, sensitive file access, privilege escalation
- Root cause: BoSC is unordered — the same syscalls in any order produce the same frequency vector. Cannot distinguish `clone()` burst from `make -j` vs. fork bomb.
- No enforcement capability (detection only)
- No cross-container correlation

**Detection score: 1/7 attack scenarios**

### 2.2 Baseline B: Modified PATROL (Kernel-Native Enforcement)

**What it does:** Moves PATROL's Go userspace enforcement into kernel-space eBPF using tail-call chaining. Four detection rules implemented as eBPF handlers: fork bomb (rate counting), reverse shell (binary name matching), sensitive file (path prefix matching), privilege escalation (syscall argument checking).

**Key innovation over original PATROL:** Eliminated the userspace round-trip (eBPF → ring buffer → Go → kill()) by using `bpf_send_signal(SIGKILL)` directly within the eBPF execution context. Measured latency: 0.3–2.5 μs vs. PATROL's ~23 μs.

**Results:**
| Rule | Measured Latency |
|------|-----------------|
| Fork bomb | 1.4–2.5 μs |
| Reverse shell | 0.7–0.9 μs |
| Sensitive file | 0.3–0.9 μs |
| Privilege escalation | 0.8 μs |
| PATROL (reference) | ~23 μs |

**Critical problem discovered — False Positives:**
When activated during normal container operations, Baseline B immediately blocked:
- `apt-get` (pid 4464) → flagged as `SENSITIVE_FILE` for reading `/etc/passwd` (benign UID resolution)
- `gpgv` (pid 4475) → flagged as `FORK_BOMB` during GPG signature verification
- `runc:[2:INIT]` → blocked for `setuid(0)` during container creation (prevents container from starting)

**Resolution required:** A 12-entry process whitelist (`runc`, `containerd`, `dockerd`, `apt-get`, `dpkg`, `gpgv`, `useradd`, `groupadd`, `sleep`, and 3 others). Each whitelisted name is an evasion vector — an attacker can rename their malicious binary to "apt-get".

**Detection score: 5/7 attack scenarios** (misses both cross-container scenarios)

**The key finding:** Neither baseline can detect cross-container lateral movement (Scenario 7). This is the primary novelty claim of CausalTrace.

---

## 3. RESEARCH GAPS — FORMAL STATEMENT

Seven research gaps were identified through literature review and confirmed by baseline experiments:

| ID | Gap | Confirmed By |
|----|-----|-------------|
| G1 | Semantic blindness: identical syscalls have context-dependent meaning that rules cannot resolve | Baseline B false positives (12 whitelist entries) |
| G2 | Loss of temporal ordering: BoSC loses sequence information | Baseline A missing fork bomb (clone burst vs. fork bomb indistinguishable) |
| G3 | Single-container scope: no cross-container event correlation | Both baselines silent on Scenario 7 |
| G4 | No semantic intent: statistical detection without attack classification | Neither baseline produces MITRE ATT&CK labels |
| G5 | Userspace enforcement latency: PATROL's 23 μs round-trip allows syscall to complete | Baseline B measurement vs. PATROL reference |
| G6 | No ML-to-kernel feedback: verdicts computed in userspace cannot affect kernel-level decisions on subsequent syscalls | Architecture of all reviewed systems |
| G7 | Training data dependency: existing ML approaches require external labelled datasets | BoSC requires normal profiles, GCN would need labelled attack chains |

---

## 4. FINAL ARCHITECTURE — V5 OVERVIEW

### 4.1 The Two-Surface Detection Principle

Attacks have two detectability surfaces:

**Surface 1 — Physical Invariants (deterministic, unevadable):**
Every attack class has operations the attacker *must* perform regardless of evasion technique.
- A reverse shell **must** redirect `fd 0/1/2` to a network socket via `dup2(sockfd, 0/1/2)`
- A fork bomb **must** fork exponentially (the rate itself must be accelerating)
- A namespace escape **must** call `setns()` or `unshare()` with namespace flags

These are **class invariants** — one handler covers every implementation of the attack (bash, python, perl, go, any language) because the physical requirement is the same regardless of implementation.

**Surface 2 — Behavioral Consistency (statistical, covers unknowns):**
Unknown attacks or novel variants may not trigger any known invariant, but they will change the container's syscall transition distribution. The Sheaf Laplacian detects this as inter-container behavioral inconsistency — when a compromised container's behavior diverges from the coupling patterns learned during normal calibration.

**The detection coverage chain:**
```
1. Does the attack match a known class with an invariant?
   YES → Tier 1 kills in ~μs. Done.
   NO  ↓

2. Does the attack produce a detectable two-step pattern (shell + lateral connect)?
   YES → Tier 2 kills in ~μs. Done.
   NO  ↓

3. Does the attack change the container's syscall transition distribution at all?
   YES → Tier 3 sheaf Laplacian detects in ~1s. Done.
   NO  ↓

4. Does the attack produce exactly the same syscall distribution as normal?
   → Theoretically undetectable by any syscall-based monitor.
     (This limits what the attacker can actually accomplish.)
```

### 4.2 Architecture Diagram (Text)

```
┌──────────────────────────────────────────────────────────────────────┐
│  NODE (single host — one CausalTrace instance)                       │
│                                                                      │
│  [ct-web: 172.20.0.10] ◄──TCP──► [ct-api: 172.20.0.20] ◄──TCP──►   │
│  [ct-db:  172.20.0.30]     Docker bridge, IPv6 disabled              │
│                                                                      │
│ ════════════════════════ KERNEL SPACE ══════════════════════════════ │
│                                                                      │
│  TIER 1: STATELESS ENFORCEMENT (raw_tracepoint/sys_enter, ~μs)      │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ On every container syscall:                                    │  │
│  │  1. NS filter: skip host processes (compare mnt_ns inode)      │  │
│  │  2. verdict_map check: if KILL → bpf_send_signal(9)           │  │
│  │  3. cgroup inherit check: handle post-unshare transitions      │  │
│  │  4. Noise filter: skip noise syscalls for bigram prev_idx      │  │
│  │  5. Bigram CMS update (verifier-safe, cold-path continues)     │  │
│  │  6. tail-call dispatch to handler by syscall_nr:               │  │
│  │     ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐      │  │
│  │     │  fork    │ │  execve  │ │   file   │ │ privesc  │      │  │
│  │     │ accel.   │ │ sh/nc/py │ │ /etc/shd │ │setuid(0) │      │  │
│  │     │ d²/dt²>0 │ │          │ │          │ │+ unshare │      │  │
│  │     └──────────┘ └──────────┘ └──────────┘ └──────────┘      │  │
│  │     ┌──────────┐                                              │  │
│  │     │  dup2/3  │  ← fd-type invariant: S_IFSOCK → stdin      │  │
│  │     │ S_IFSOCK │    (catches ALL reverse shells, any lang)    │  │
│  │     └──────────┘                                              │  │
│  │  All handlers: bpf_send_signal(9) + set behavior bit          │  │
│  └────────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  TIER 2: DATA COLLECTION + IN-KERNEL PATTERNS (~μs)                 │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ Probe B: kretprobe/tcp_v4_connect                              │  │
│  │   → Records (src_cgroup, dst_ip→dst_cgroup, dst_port)         │  │
│  │   → Two-hop check: if (bit0|bit6) set within 5s → SIGKILL     │  │
│  │   → Emits CONNECTION_EVENT to telemetry_rb                    │  │
│  │                                                                │  │
│  │ Probe C: sched_process_fork + sys_enter_execve                │  │
│  │   → Maintains process lineage (parent→child)                  │  │
│  │   → Sets shell-spawn bit in container_behavior                │  │
│  │                                                                │  │
│  │ container_behavior map: 8-bit flags + 8 per-bit timestamps    │  │
│  │   bit0=shell(ts0)  bit1=lateral(ts1)  bit2=sensitive(ts2)    │  │
│  │   bit3=ns_probe(ts3) bit4=privesc(ts4) bit5=large_xfer(ts5)  │  │
│  │   bit6=fd_redirect/INVARIANT(ts6) bit7=fork_accel/INVARIANT(ts7)│
│  └────────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  BPF Maps (shared state — kernel↔kernel and kernel↔userspace):      │
│  alerts_rb(64KB) ← Tier 1 high-priority alerts only                 │
│  telemetry_rb(256KB) ← Probe B connection events                    │
│  verdict_map ← Tier 3 writes, Tier 1 reads every syscall            │
│  bigram_sketch_map ← Tier 1 writes, Tier 3 reads every cycle        │
│  container_behavior ← All tiers read/write                          │
│  ip_to_cgroup ← Docker event listener writes, Probe B reads         │
│                                                                      │
│ ════════════════════════ USER SPACE ════════════════════════════════ │
│                                                                      │
│  TIER 3: SHEAF DAEMON (~1s cycle)                                   │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ Stage 1: Novel-Edge Detector                                   │  │
│  │   → Any connection on uncalibrated (src,dst,port) → HIGH alert│  │
│  │                                                                │  │
│  │ Stage 2: Signal Extraction (d=74 per container)               │  │
│  │   → Read bigram_sketch_map → reconstruct CMS estimates        │  │
│  │   → PCA project 625 bigrams → 50 dims                        │  │
│  │   → Rényi entropy (α=0.5,1.0,2.0) → 3 dims                  │  │
│  │   → Transition marginals → 20 dims                            │  │
│  │   → Syscall rate → 1 dim                                      │  │
│  │   → Total: 74 dims (NO invariant bits — decoupled from math)  │  │
│  │   → Whiten: (x - μ_cal) / σ_cal                              │  │
│  │                                                                │  │
│  │ Stage 3: Sheaf Laplacian Spectral Test (dual path + multi-lag)│  │
│  │   → EMA path (α=0.2): catches slow-drip exfiltration          │  │
│  │   → Raw path: catches sudden attacks                          │  │
│  │   → Multi-lag (0s,5s,10s): catches async attack chains        │  │
│  │   → Mahalanobis distance (4-sigma threshold)                  │  │
│  │                                                                │  │
│  │ Stage 4: Sheaf Eigenmode Analysis                             │  │
│  │   → L_F eigenvectors → spectral fingerprint per scenario      │  │
│  │   → Different attack types excite different modes             │  │
│  │                                                                │  │
│  │ Stage 5: Semantic Label Engine                                │  │
│  │   → Read container_behavior bitfields (invariant bits)        │  │
│  │   → Map bit patterns → MITRE ATT&CK labels                   │  │
│  │   → COMPLETELY SEPARATE from sheaf math (no bit fusion)       │  │
│  │                                                                │  │
│  │ Stage 6: Verdict → verdict_map → kernel enforcement           │  │
│  │   → Staleness TTL: drop windows >10s old (GIL protection)    │  │
│  └────────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  SUPPORTING DAEMONS:                                                 │
│  Docker Event Listener → ip_to_cgroup + bigram map pre-population   │
└──────────────────────────────────────────────────────────────────────┘
```

### 4.3 Signal Flow Summary

```
Container syscall
    → raw_tracepoint/sys_enter (Tier 1 dispatcher)
        → NS filter (skip host)
        → verdict_map check (instant kill if VERDICT_KILL)
        → cgroup inherit check (unshare fix)
        → noise filter (don't advance bigram for getpid/getuid/etc)
        → bigram CMS update (count (prev_syscall, current_syscall) pairs)
        → tail-call to handler (fork/execve/file/privesc/dup2)
            → handler: check invariant
            → if match: set behavior bit + bpf_send_signal(9)

    → kretprobe/tcp_v4_connect (Probe B)
        → resolve dst_ip → dst_cgroup via ip_to_cgroup
        → set BIT_LATERAL_CONNECT + bit_ts[1]
        → check: (bit0|bit6) set within 5s? → SIGKILL + alert
        → emit CONNECTION_EVENT to telemetry_rb

Every ~5s: Tier 3 reads bigram_sketch_map + container_behavior
    → extract d=74 signal per container
    → whiten against calibration stats
    → update EMA buffer
    → check sheaf Laplacian energy (both raw and EMA paths)
    → check eigenmode fingerprints
    → read behavior bits → semantic label
    → if anomaly: write verdict_map → kernel kills on next syscall
```

---

## 5. DESIGN DECISION LOG (Problem → Solution Pairs)

This section documents every significant design decision, the problem that motivated it, and why the chosen solution is correct. A developer implementing this system should understand all of these.

### Decision 1: Why the fd-type invariant (not just binary name matching)

**Problem:** Baseline B's execve handler matches shell binary names (`sh`, `bash`, `nc`, `python`). This catches `bash -c "bash -i >& /dev/tcp/..."` but misses `python3 -c "import socket,os; os.dup2(s.fileno(),0)"`. An attacker using any language other than bash evades detection entirely. Additionally, obfuscating the binary name (renaming python3 to "chromeupdate") defeats binary-name matching.

**Solution:** Hook `dup2` (syscall 33) and `dup3` (syscall 292). Traverse `task→files→fdt→fd[oldfd]→f_inode→i_mode`. If `(i_mode & 0xF000) == 0xC000` (S_IFSOCK), a socket is being redirected to stdin/stdout/stderr. This is the **physical invariant** of a reverse shell — there is no interactive reverse shell without this operation regardless of language, binary name, or obfuscation.

**Why unevadable:** The attacker cannot establish interactive shell access over a network connection without redirecting their socket fd to the process's stdin/stdout/stderr. This is not a rule about what the attacker does — it is a rule about what the physics of Unix I/O requires.

**False positive rate:** Near-zero. The only legitimate use of `dup2(socket, 0/1/2)` is tools like socat or netcat — detectable by context (they're not preceded by shell spawns in production containers).

### Decision 2: Why fork acceleration instead of fixed threshold

**Problem:** A fixed fork threshold (e.g., 100 forks/second) generates false positives on `make -j16` (parallel builds) and container startup scripts. Both create short bursts of many forks. The difference between `make -j16` and a fork bomb is not the absolute rate — it is the **dynamics** of the rate.

**Solution:** Track three consecutive 1-second windows: `prev_prev_count`, `prev_count`, `count`. Compute the second discrete derivative: `d2 = count - 2*prev_count + prev_prev_count`. A fork bomb has positive `d2` (the rate itself is increasing — exponential growth). `make -j16` ramps up briefly then **stabilizes** (`d2 → 0` after the ramp). Container startup forks a fixed number of processes then stops (`d2 → 0`).

**Condition for alarm:** `rate > 50 AND d2 > 0 AND rate > prev > prev_prev`
**Hard ceiling:** `rate > 500` always triggers (defense in depth)

### Decision 3: Why invariant bits are NOT in the sheaf signal vector

**Problem (v4 design):** An earlier design put all 8 invariant bits as dimensions 74-81 of the sheaf signal vector, with the idea that bits set to 0 during calibration (σ=ε=1e-6) would produce enormous whitened values (1/1e-6 = 1,000,000) during attacks, guaranteeing separation.

**Why this is wrong:**
1. **Numerical degeneracy:** The covariance matrix has σ²=1e-12 on those diagonal entries. When computing Mahalanobis distance with `np.linalg.inv(cov)`, the condition number is ~10¹². NumPy will either raise `LinAlgError` or return garbage.
2. **Conceptual redundancy:** If an invariant bit is set, Tier 1 already called `bpf_send_signal(9)` within ~1μs. The process is dead. Using expensive sheaf math to "confirm" something that was already enforced adds zero detection value.
3. **Wrong architecture:** The sheaf Laplacian's value is detecting **unknown** attacks where no invariant fires. For unknown attacks, there are no bits to fuse. The "structural separation guarantee" was solving a problem that doesn't exist in the correct detection flow.

**Solution:** Invariant bits are **completely decoupled** from the sheaf signal vector. `d=74` continuous features only. Invariant bits feed **only** the Semantic Label Engine (Stage 5). The detection flow is:

```
Known attack → invariant fires → Tier 1 SIGKILL (~μs) → done
                                   ↓ (async, non-blocking)
                            Bits read by Semantic Engine → MITRE label

Unknown attack → no invariant fires → bigram shift only
                                   → sheaf Laplacian detects
                                   → verdict_map → kill on next syscall
```

### Decision 4: Per-bit timestamps (not single timestamp) in behavior_state

**Problem:** Original design stored a single `ts` field updated whenever any bit was set. Scenario: shell bit (bit0) set on Monday (ts=Monday). On Friday, a legitimate file read updates ts to Friday. One second later, a legitimate database connect fires. The two-hop check reads: `(now - ts < 5s)` = TRUE, `flags & BIT_SHELL_SPAWN` = TRUE (bit never cleared) → false positive SIGKILL on legitimate traffic.

**Solution:** `bit_ts[8]` — a separate 64-bit timestamp for each of the 8 behavior bits. The two-hop check uses `bit_ts[0]` (shell) and `bit_ts[6]` (fd_redirect) independently. Additionally: **lazy expiry** — on every flag read, clear any bit whose timestamp is older than `TWOHOP_WINDOW_NS` (5 seconds). Stale bits are automatically cleaned without any background task.

### Decision 5: Cold path continues to tail-call (not return 0)

**Problem:** The bigram sketch is pre-populated by the Docker event listener on container start. But there is a race window (~10-50ms) between container start and map population. If a malicious entrypoint runs syscalls before the map is populated, the dispatcher hits `if (!sketch) return 0` and silently skips **all invariant dispatch** — including the fork, execve, file, and dup2 handlers that don't depend on the bigram sketch at all.

**Solution:** On cold path (sketch NULL), skip bigram tracking but **still** execute `bpf_tail_call(ctx, &prog_array, syscall_nr)`. All Tier 1 invariant handlers are active from the very first syscall.

### Decision 6: Noise syscall filtering before bigram update

**Problem:** Bigram obfuscation attack — an attacker injects side-effect-free syscalls between each malicious one to destroy the bigram signature. Example: `openat → getpid → read → getuid → connect → getpid → sendto`. The malicious bigrams `(openat→read)` and `(read→connect)` are replaced by benign bigrams `(openat→getpid)`, `(getpid→read)`, etc.

**Solution:** Before updating `prev_idx`, check if the current syscall is in the noise set: `{getpid(39), getuid(102), gettid(186), getppid(110), time(201), clock_gettime(228)}`. If yes, execute the tail-call (so handlers still fire) but **don't advance `prev_idx`**. The noise syscall is transparent to bigram computation — the attacker's injected getpid doesn't appear in the CMS.

**Why this creates an adversarial trap (Proposition 3):**
- If attacker uses noise syscalls to break bigrams: filtered, prev_idx unchanged, malicious bigrams still recorded
- If attacker uses non-noise syscalls (side effects): those syscalls ARE tracked, their counts inflate dramatically, producing bigram distribution shift detectable by sheaf Laplacian
- The attacker cannot win: trivial obfuscation is filtered; non-trivial obfuscation triggers statistical detection

### Decision 7: LRU hash for connect_sk_stash

**Problem:** The `kprobe/tcp_v4_connect` + `kretprobe/tcp_v4_connect` pair uses a stash map keyed by `pid_tgid` to pass the `struct sock *` pointer from entry to return. With `BPF_MAP_TYPE_HASH` and `max_entries=1024`, an attacker can flood outbound `nc` connections to random IPs. The map fills up. When the legitimate malicious connection fires, `bpf_map_update_elem` returns an error and the entry is never stashed. The kretprobe finds no entry and silently drops the event. Probe B is blind.

**Solution:** `BPF_MAP_TYPE_LRU_HASH` with `max_entries=4096`. Under LRU eviction, the oldest entries are dropped automatically. Since the round-trip time between `kprobe` and `kretprobe` for a single connection is microseconds, the legitimate entry will survive LRU eviction unless the flood is faster than the legitimate connection — which would itself trigger Tier 1 rate limits (500+ connects per second → fork acceleration invariant fires, or the flood generates obvious bigram anomalies).

### Decision 8: Split ring buffers (alerts vs. telemetry)

**Problem:** A single 256KB ring buffer is shared between Tier 1 alert events (`ALERT_FD_REDIRECT`, `ALERT_FORK_ACCEL`, `ALERT_TWO_HOP`) and Tier 2 telemetry events (`CONNECTION_EVENT`). An attacker floods outbound connections to non-container IPs (which don't match `ip_to_cgroup` but still trigger the hook). This fills the ring buffer faster than the Python daemon can consume it. When the real attack fires, `bpf_ringbuf_reserve(&alerts, ...)` returns NULL. The eBPF handler still calls `bpf_send_signal(9)` (enforcement works), but the alert is lost — Tier 3 has no semantic context, the eigenmode analysis and semantic labeling fail.

**Solution:** Two separate ring buffers:
- `alerts_rb` (64KB): Tier 1 handlers ONLY. Low volume (one alert per attack event), high priority.
- `telemetry_rb` (256KB): Probe B connection events ONLY. High volume but non-critical.

The Python daemon polls both with separate callbacks. Critical alerts can never be starved by telemetry floods.

### Decision 9: Updated top-24 syscall tracking list

**Problem:** The original top-20 list included `poll(7)`, `lseek(8)`, `rt_sigaction(13)`, `rt_sigprocmask(14)`. These are high-frequency but low-security-value syscalls. More importantly, dangerous syscalls like `io_uring_enter(426)`, `ptrace(101)`, `memfd_create(319)`, and `bpf(321)` were lumped into the "other" bucket (index 24). An attacker using `io_uring` for fileless I/O produces bigrams `(24→24)` — indistinguishable from any other "other→other" transition, hiding in statistical noise.

**Solution:** Replace the 4 low-value syscalls with security-critical ones. Expand to top-24 (25 indices including "other"):
- **Removed:** poll(7), lseek(8), rt_sigaction(13), rt_sigprocmask(14)
- **Added:** ptrace(101), mount(165), unshare(272), setns(308), memfd_create(319), bpf(321), io_uring_enter(426)

Each dangerous syscall now has its own bigram dimensions. `io_uring_enter → io_uring_enter` at high frequency is a clearly anomalous bigram.

### Decision 10: Cgroup inheritance on unshare(CLONE_NEWCGROUP)

**Problem:** An attacker calls `unshare(CLONE_NEWCGROUP)` to create a new cgroup for their process. All subsequent `bpf_get_current_cgroup_id()` calls return the new cgroup ID. The `container_behavior` map entry for the new cgroup is empty — no bits set, no history. The two-hop check sees a clean state: shell spawn on Monday is completely forgotten. Historical suspicion is erased.

**Solution:** Hook `unshare` in the privesc handler. When `CLONE_NEWCGROUP` flag is detected, store the current (old) cgroup_id in `pending_cgroup_inherit` keyed by `pid_tgid`. On the very next syscall from this PID (caught in the dispatcher), compare the new cgroup_id to the old one. If different, copy the behavior_state from the old cgroup to the new one using `bpf_map_update_elem(&container_behavior, &new_cg, old_state, BPF_NOEXIST)`. The attacker's behavioral history follows them across cgroup transitions.

### Decision 11: Multi-lag CCA alignment (lags 0, 5, 10 seconds)

**Problem:** In a multi-stage attack, the cause (Web compromise) and the effect (DB exfiltration) may not be synchronous. If the attacker spends 7 seconds on the Web container before connecting to the API, the CCA restriction maps learned at lag=0 (simultaneous windows) will not capture the causal coupling. The sheaf Laplacian computes zero edge energy (the containers appear uncorrelated because their signals are offset in time) and misses the attack.

**Solution:** During calibration, learn restriction maps at three temporal offsets: lag=0 (same window), lag=1 (one 5-second window apart), lag=2 (two windows apart). At runtime, compute Mahalanobis edge energy for all three lags and take the **maximum**. This catches attack chains with up to 10 seconds of asynchronous delay between stages.

**Memory cost:** 3 windows × 74 floats × 8 bytes × 3 containers = ~5KB. Negligible.
**Compute cost:** 3 × 50×74 = 11,100 multiply-adds per edge. <0.01ms.

### Decision 12: EMA dual-path detection (α=0.2)

**Problem:** Low-and-slow exfiltration — an attacker reads 10 bytes every 6 seconds. The bigram CMS resets every 5 seconds (WINDOW_NS). In any individual 5-second window, the attacker's activity produces only 1-2 abnormal bigrams — insufficient to shift the whitened signal past the 4-sigma threshold. The sheaf Laplacian never fires.

**Solution:** Maintain an Exponential Moving Average of whitened signals: `x_ema(t) = α·x_raw(t) + (1-α)·x_ema(t-1)` with α=0.2. The EMA creates a mathematical "memory" across windows. A persistent 0.5σ anomaly per window reaches `0.5/(1-0.8) = 2.5σ` in steady state — detectable in ~15 windows (~75 seconds).

Run the sheaf detector on **both** `x_raw` (catches sudden attacks) and `x_ema` (catches slow-drip attacks). Calibrate separate thresholds for each path. Fire if either exceeds its threshold.

### Decision 13: Sheaf eigenmode analysis for spectral fingerprinting

**Problem:** The basic sheaf Laplacian produces a single binary output: anomalous or not. For the paper's contribution, we want to show that different attack types produce distinguishable spectral signatures — not just binary detection but spectral characterization.

**Solution:** After calibration, compute eigendecomposition of `L_F` (the sheaf Laplacian matrix). At runtime, project the anomalous signal onto eigenvectors. Different attack types excite different eigenmodes:
- Web-only reverse shell → mode where Web deviates, API/DB agree
- Full lateral chain (Web→API→DB) → modes where multiple containers are involved
- Fork bomb → isolated container mode (single container anomaly)

This is ~30 lines of Python, ~0.1ms overhead, and provides a bonus experimental result: spectral fingerprinting of attack types without any classifier.

### Decision 14: IPv6 disabled on Docker bridge

**Problem:** `probe_b_connect.bpf.c` hooks `tcp_v4_connect` (IPv4 only). If IPv6 is enabled on the Docker bridge, an attacker can use the IPv6 link-local or global address of the target container. The `ip_to_cgroup` map resolution returns NULL (IPv6 address not in the IPv4 map), the connection event is never written to the ring buffer, and Probe B is completely blind to the lateral movement.

**Solution:** Disable IPv6 on the Docker bridge: `enable_ipv6: false` in `docker-compose.yml`. Document as a known limitation: "IPv6 support requires hooking `tcp_v6_connect` and extending `ip_to_cgroup` to 128-bit keys. Left as future work."

---

## 6. KERNEL-SPACE IMPLEMENTATION — TIER 1

### 6.1 Common Header (causaltrace_common.h)

This file is included by ALL BPF programs. It defines all shared constants, structs, and helper functions.

```c
// causaltrace_common.h
// ─── REQUIRED INCLUDES ────────────────────────────────────────────────
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ─── CONSTANTS ────────────────────────────────────────────────────────
#define MAX_CONTAINERS     256
#define CMS_ROWS           4           // Count-Min Sketch hash rows
#define CMS_COLS           128         // Must be power of 2 for fast masking
#define CMS_COL_MASK       (CMS_COLS - 1)   // = 0x7F — verifier bound
#define TOP_SYSCALLS       25          // 24 tracked + 1 "other" bucket
#define MAX_BIGRAMS        (TOP_SYSCALLS * TOP_SYSCALLS)  // = 625
#define WINDOW_NS          (5ULL * 1000000000ULL)   // 5-second CMS window
#define MAX_FD             1024        // fd bound for verifier
#define TWOHOP_WINDOW_NS   (5ULL * 1000000000ULL)   // 5s for two-hop detection

// ─── ALERT TYPE CODES ─────────────────────────────────────────────────
#define ALERT_FORK_BOMB       1
#define ALERT_REVERSE_SHELL   2
#define ALERT_SENSITIVE_FILE  3
#define ALERT_PRIVESC         4
#define ALERT_FD_REDIRECT     5
#define ALERT_FORK_ACCEL      6
#define ALERT_TWO_HOP         7
#define ALERT_NS_ESCAPE       8
#define EVENT_CONNECTION    100   // telemetry only (not a security alert)

// ─── VERDICT CODES ────────────────────────────────────────────────────
#define VERDICT_ALLOW  0
#define VERDICT_KILL   1

// ─── BEHAVIOR BITFIELD DEFINITIONS ────────────────────────────────────
#define BIT_SHELL_SPAWN     (1ULL << 0)
#define BIT_LATERAL_CONNECT (1ULL << 1)
#define BIT_SENSITIVE_FILE  (1ULL << 2)
#define BIT_NS_PROBE        (1ULL << 3)
#define BIT_PRIVESC         (1ULL << 4)
#define BIT_LARGE_TRANSFER  (1ULL << 5)
#define BIT_FD_REDIRECT     (1ULL << 6)   // INVARIANT: socket→stdin/stdout/stderr
#define BIT_FORK_ACCEL      (1ULL << 7)   // INVARIANT: exponential fork acceleration

// ─── STRUCTS ──────────────────────────────────────────────────────────

// Per-container behavioral state — 8 flag bits + 8 per-bit timestamps
// IMPORTANT: bit_ts[i] stores the timestamp when bit i was last set.
// This prevents stale-bit false positives (the single-ts design bug).
struct behavior_state {
    __u64 flags;         // 64-bit behavior bitfield (only bits 0-7 used)
    __u64 bit_ts[8];     // per-bit timestamps (ns from bpf_ktime_get_ns())
    __u64 conn_dst_cg;   // last lateral connect() destination cgroup_id
    __u16 conn_port;     // last lateral connect() destination port
    __u16 _pad[3];       // alignment padding
    // sizeof = 8 + 64 + 8 + 2 + 6 = 88 bytes
};

// Fork rate tracking — three-window history for acceleration detection
struct rate_state {
    __u64 window_start;    // ns timestamp of current window start
    __u64 count;           // fork count in current 1s window
    __u64 prev_count;      // fork count in previous 1s window
    __u64 prev_prev_count; // fork count two windows ago
    // sizeof = 32 bytes
};

// Bigram Count-Min Sketch — one per container
// Tracks (syscall_i → syscall_{i+1}) transition counts
struct bigram_sketch {
    __u32 counters[CMS_ROWS][CMS_COLS];  // 4 × 128 = 512 entries × 4B = 2048B
    __u32 prev_idx;    // index of last tracked syscall (0-24); NOT updated for noise syscalls
    __u32 _pad;        // alignment
    __u64 total_count; // total bigrams observed in current window
    __u64 window_start; // ns timestamp of current window start
    // sizeof = 2048 + 4 + 4 + 8 + 8 = 2072 bytes
};

// Alert/event record — written to ring buffers
struct alert_t {
    __u32 type;        // ALERT_* or EVENT_CONNECTION constant
    __u32 pid;         // pid (upper 32 bits of pid_tgid)
    __u64 cgroup_id;   // source container
    __u64 timestamp;   // bpf_ktime_get_ns()
    __u64 flags;       // behavior bitfield snapshot at alert time
    __u64 extra;       // type-specific context:
                       //   FD_REDIRECT: (oldfd << 32) | newfd
                       //   FORK_ACCEL: current fork rate
                       //   TWO_HOP: dst_cgroup_id
                       //   CONNECTION: (dst_ip << 32) | dst_port
    // sizeof = 40 bytes
};

// ─── CMS HASH CONSTANTS ───────────────────────────────────────────────
// Different primes for each row to minimize hash collisions
// These are compile-time constants — the verifier sees them as proven bounds
static const __u32 CMS_PRIMES[CMS_ROWS] = {
    2654435761U, 2246822519U, 3266489917U, 668265263U
};
static const __u32 CMS_SEEDS[CMS_ROWS] = {1, 7, 13, 31};

// ─── SYSCALL INDEX MAPPING ────────────────────────────────────────────
// Maps syscall numbers to [0..24] indices for bigram CMS.
// 24 tracked syscalls + index 24 for "everything else".
// SECURITY NOTE: Dangerous syscalls are explicitly tracked (not in "other"):
//   ptrace, mount, unshare, setns, memfd_create, bpf, io_uring_enter
static __always_inline __u32 syscall_to_idx(__u32 nr) {
    switch (nr) {
        case 0:   return 0;   // read
        case 1:   return 1;   // write
        case 2:   return 2;   // open
        case 3:   return 3;   // close
        case 4:   return 4;   // stat
        case 5:   return 5;   // fstat
        case 9:   return 6;   // mmap
        case 10:  return 7;   // mprotect
        case 12:  return 8;   // brk
        case 16:  return 9;   // ioctl
        case 21:  return 10;  // access
        case 22:  return 11;  // pipe
        case 41:  return 12;  // socket
        case 42:  return 13;  // connect
        case 43:  return 14;  // accept
        case 44:  return 15;  // sendto
        case 101: return 16;  // ptrace      ← security-critical: explicitly tracked
        case 165: return 17;  // mount       ← container escape vector
        case 272: return 18;  // unshare     ← namespace manipulation
        case 308: return 19;  // setns       ← namespace transition
        case 319: return 20;  // memfd_create ← fileless malware
        case 321: return 21;  // bpf         ← attacker eBPF abuse
        case 426: return 22;  // io_uring_enter ← io_uring bypass
        case 59:  return 23;  // execve      ← always track
        default:  return 24;  // other
    }
}

// ─── NOISE SYSCALL FILTER ─────────────────────────────────────────────
// Returns 1 if the syscall should be skipped for bigram purposes.
// These syscalls have no side effects and are used for obfuscation.
// IMPORTANT: tail-call dispatch still fires for these (Tier 1 invariants
//   are NOT skipped). Only the bigram prev_idx update is skipped.
// SECURITY: If attacker uses non-noise syscalls to break bigrams,
//   those syscalls inflate their bigram counts → sheaf detects distribution shift.
static __always_inline int is_noise_syscall(__u32 nr) {
    switch (nr) {
        case 39:   // getpid
        case 102:  // getuid
        case 186:  // gettid
        case 110:  // getppid
        case 201:  // time
        case 228:  // clock_gettime
            return 1;
        default:
            return 0;
    }
}
```

### 6.2 BPF Map Declarations (causaltrace_maps.h)

```c
// causaltrace_maps.h
// All maps are declared here and pinned to the BPF filesystem.
// Maps are shared across all eBPF programs via BCC pinning.

// ─── CORE CONTROL MAPS ────────────────────────────────────────────────

// Host mount namespace inode — used to identify host processes vs. container processes
// Written once by loader at startup. Read by every syscall handler.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);   // host ns inum from /proc/self/ns/mnt
} host_ns SEC(".maps");

// Tail-call dispatch table — maps syscall_nr → eBPF program fd
// Written by loader (attaches handler programs). Read by dispatcher.
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 512);
    __type(key, __u32);     // syscall number
    __type(value, __u32);   // program fd
} prog_array SEC(".maps");

// ─── TIER 3 → TIER 1 FEEDBACK ─────────────────────────────────────────
// Written by Tier 3 Python daemon with verdict for known-bad containers.
// Read by dispatcher on EVERY syscall — instant kill without userspace round-trip.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONTAINERS);
    __type(key, __u64);     // cgroup_id
    __type(value, __u32);   // VERDICT_ALLOW or VERDICT_KILL
} verdict_map SEC(".maps");

// ─── TIER 1 STATE MAPS ────────────────────────────────────────────────

// Fork rate tracking — three consecutive 1-second windows per container
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONTAINERS);
    __type(key, __u64);                  // cgroup_id
    __type(value, struct rate_state);
} rate_map SEC(".maps");

// Per-container behavioral bitfield + per-bit timestamps
// CRITICAL: bit_ts[i] is the timestamp when bit i was last set.
// Lazy expiry: bits older than TWOHOP_WINDOW_NS are cleared on read.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONTAINERS);
    __type(key, __u64);                     // cgroup_id
    __type(value, struct behavior_state);   // 88 bytes
} container_behavior SEC(".maps");

// ─── TIER 2 STATE MAPS ────────────────────────────────────────────────

// IP → cgroup_id: populated by Docker event listener (user-space)
// Read by Probe B to resolve dst_ip → dst_cgroup_id
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONTAINERS);
    __type(key, __u32);     // IPv4 address (network byte order)
    __type(value, __u64);   // cgroup_id of container with this IP
} ip_to_cgroup SEC(".maps");

// Bigram Count-Min Sketch — one entry per container
// PRE-POPULATED by Docker event listener with zeroed entries to avoid cold-path stack overflow.
// Updated by dispatcher on every container syscall.
// Read by Tier 3 daemon every detection cycle.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONTAINERS);
    __type(key, __u64);                     // cgroup_id
    __type(value, struct bigram_sketch);    // 2072 bytes
} bigram_sketch_map SEC(".maps");

// tcp_v4_connect sk-stash: entry → return probe communication
// LRU to prevent map exhaustion under SYN flood attacks.
// Increased to 4096 entries for headroom.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);   // LRU not HASH (prevents exhaustion)
    __uint(max_entries, 4096);
    __type(key, __u64);    // pid_tgid
    __type(value, __u64);  // struct sock * (stored as u64)
} connect_sk_stash SEC(".maps");

// Cgroup inheritance: tracks PIDs that called unshare(CLONE_NEWCGROUP)
// Written by privesc handler, read and cleared by dispatcher
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);    // pid_tgid
    __type(value, __u64);  // old cgroup_id (before unshare)
} pending_cgroup_inherit SEC(".maps");

// ─── RING BUFFERS — SPLIT BY PRIORITY ────────────────────────────────
// CRITICAL: Split prevents telemetry floods from starving security alerts.

// High-priority alerts from Tier 1 handlers ONLY (ALERT_* events)
// Low volume (one entry per attack event), high priority
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);     // 64KB
} alerts_rb SEC(".maps");

// Tier 2 connection tracking events (EVENT_CONNECTION)
// Higher volume (one entry per inter-container connection)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);    // 256KB
} telemetry_rb SEC(".maps");

// ─── STATISTICS ───────────────────────────────────────────────────────
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");
// Index definitions: [0]=total_syscalls, [1]=container_syscalls,
// [2]=alerts_fired, [3]=kills_issued, [4]=novel_edges
```

### 6.3 Dispatcher (dispatcher.bpf.c)

The dispatcher is the entry point — it runs on **every** container syscall. It is the highest-throughput eBPF program and must be fast and verifier-compliant.

**Verifier constraints satisfied:**
- `prev_idx > 24` defensive bound before use (verifier needs proven range)
- `hash = (...) & CMS_COL_MASK` bounds array index to [0,127]
- `#pragma unroll` on all fixed-count loops
- All kernel struct access via `BPF_CORE_READ_INTO` (CO-RE portability)
- NULL checks after every `bpf_map_lookup_elem`
- Stack usage: ~180 bytes (within 256B tail-call budget)

```c
// dispatcher.bpf.c
#include "causaltrace_common.h"
#include "causaltrace_maps.h"

SEC("raw_tracepoint/sys_enter")
int dispatcher(struct bpf_raw_tracepoint_args *ctx) {

    // ── Step 1: Read syscall number ──────────────────────────────────
    // For raw_tracepoint/sys_enter: ctx->args[1] is the syscall number
    unsigned long syscall_nr = ctx->args[1];

    // ── Step 2: Container filter — skip host processes ──────────────
    // Read current task's mount namespace inode via CO-RE
    // This is portable across kernel versions with different struct layouts
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct nsproxy *nsproxy = NULL;
    BPF_CORE_READ_INTO(&nsproxy, task, nsproxy);
    if (!nsproxy) return 0;

    struct mnt_namespace *mnt_ns = NULL;
    BPF_CORE_READ_INTO(&mnt_ns, nsproxy, mnt_ns);
    if (!mnt_ns) return 0;

    unsigned int mnt_ns_inum = 0;
    BPF_CORE_READ_INTO(&mnt_ns_inum, mnt_ns, ns.inum);

    // Compare against stored host namespace inode
    __u32 key_zero = 0;
    __u32 *host_ns_inum = bpf_map_lookup_elem(&host_ns, &key_zero);
    if (!host_ns_inum) return 0;
    if (mnt_ns_inum == *host_ns_inum) return 0;  // host process — skip

    // All subsequent code runs only for container processes
    __u64 cg = bpf_get_current_cgroup_id();

    // ── Step 3: Verdict map check (Tier 3 → Tier 1 feedback) ────────
    // This is how Tier 3's sheaf verdict becomes kernel enforcement.
    // If Tier 3 has written VERDICT_KILL for this cgroup, kill immediately.
    __u32 *verdict = bpf_map_lookup_elem(&verdict_map, &cg);
    if (verdict && *verdict == VERDICT_KILL) {
        bpf_send_signal(9);  // SIGKILL — instant
        return 0;
    }

    // ── Step 4: Cgroup inheritance check (unshare fix) ──────────────
    // If this PID recently called unshare(CLONE_NEWCGROUP), it may have
    // moved to a new cgroup. We need to copy behavioral history.
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *old_cg_ptr = bpf_map_lookup_elem(&pending_cgroup_inherit, &pid_tgid);
    if (old_cg_ptr) {
        __u64 old_cg = *old_cg_ptr;
        if (cg != old_cg) {
            // Cgroup transition detected — copy behavioral history
            struct behavior_state *old_state = bpf_map_lookup_elem(&container_behavior, &old_cg);
            if (old_state) {
                // BPF_NOEXIST: don't overwrite if new cgroup already has state
                bpf_map_update_elem(&container_behavior, &cg, old_state, BPF_NOEXIST);
            }
        }
        bpf_map_delete_elem(&pending_cgroup_inherit, &pid_tgid);
    }

    // ── Step 5: Bigram CMS update (verifier-safe) ────────────────────
    // Cold path (sketch NULL): skip bigram tracking but CONTINUE to tail-call.
    // This ensures Tier 1 handlers are active even during the startup race window.
    // Hot path: update the CMS with the (prev_syscall, current_syscall) bigram.
    struct bigram_sketch *sketch = bpf_map_lookup_elem(&bigram_sketch_map, &cg);

    if (sketch) {
        __u64 now = bpf_ktime_get_ns();

        // Window reset: zero all counters when current window expires
        if (now - sketch->window_start > WINDOW_NS) {
            // Cannot memset the full 2KB struct inline — unroll loops instead
            #pragma unroll
            for (int row = 0; row < CMS_ROWS; row++) {
                #pragma unroll
                for (int col = 0; col < CMS_COLS; col++) {
                    sketch->counters[row][col] = 0;
                }
            }
            sketch->total_count = 0;
            sketch->window_start = now;
        }

        // Map current syscall to [0..24] index
        __u32 curr_idx = syscall_to_idx((__u32)syscall_nr);

        // NOISE FILTER: Skip prev_idx update for side-effect-free syscalls.
        // These are used by attackers to break bigram signatures. By not advancing
        // prev_idx, noise syscalls are invisible to the CMS.
        // IMPORTANT: tail-call still fires — invariant handlers still run.
        if (!is_noise_syscall((__u32)syscall_nr)) {
            __u32 prev_idx = sketch->prev_idx;
            // Defensive bound: verifier requires proof that prev_idx <= 24
            if (prev_idx > 24) prev_idx = 24;

            // Compute bigram key: prev * TOP_SYSCALLS + curr
            // Max value: 24*25+24 = 624 < MAX_BIGRAMS=625 — safe
            __u32 bigram_key = prev_idx * TOP_SYSCALLS + curr_idx;

            // CMS update: 4 hash functions, each bounded by CMS_COL_MASK
            // The & operator provides the verifier-required array bound proof
            #pragma unroll
            for (int i = 0; i < CMS_ROWS; i++) {
                __u32 hash = (bigram_key * CMS_PRIMES[i] + CMS_SEEDS[i]) & CMS_COL_MASK;
                // hash is provably in [0, 127] — verifier accepts this array access
                sketch->counters[i][hash] += 1;
            }

            sketch->total_count += 1;
            sketch->prev_idx = curr_idx;  // advance only for non-noise syscalls
        }
        // For noise syscalls: CMS not updated, prev_idx unchanged, they're transparent
    }
    // Cold path (sketch == NULL): fall through to tail-call without bigram update

    // ── Step 6: Tail-call dispatch to handler by syscall number ──────
    // If no handler is registered for this syscall number, the tail call
    // silently fails and we return 0 — this is the normal case for most syscalls.
    bpf_tail_call(ctx, &prog_array, (__u32)syscall_nr);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

### 6.4 fd-Type Invariant Handler (handler_dup2.bpf.c)

This handler detects **all** reverse shells regardless of language or technique. It is the most important new invariant in CausalTrace v5.

**Physical invariant:** Any reverse shell that provides interactive shell access must redirect at least one of stdin(0), stdout(1), stderr(2) to a network socket. This is a fundamental Unix I/O requirement. The attacker cannot bypass it.

**Verifier compliance:**
- `oldfd` bounds-checked: `if (oldfd < 0 || oldfd >= MAX_FD) return 0`
- `newfd` bounds-checked: `if (newfd < 0 || newfd > 2) return 0`  
- `fd_array[oldfd]` safe because oldfd is proven [0,1023] at this point
- All struct traversal via `BPF_CORE_READ_INTO` and `bpf_probe_read_kernel`
- Stack: ~80 bytes

```c
// handler_dup2.bpf.c
// Tail-called for: dup2 (syscall 33) and dup3 (syscall 292)
#include "causaltrace_common.h"
#include "causaltrace_maps.h"

SEC("raw_tracepoint/sys_enter")
int handle_dup2(struct bpf_raw_tracepoint_args *ctx) {
    // For raw_tracepoint/sys_enter, ctx->args[0] is struct pt_regs *
    // On x86_64: rdi = first argument, rsi = second argument
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];

    long oldfd_long = 0, newfd_long = 0;
    BPF_CORE_READ_INTO(&oldfd_long, regs, di);  // x86_64: rdi = first arg
    BPF_CORE_READ_INTO(&newfd_long, regs, si);  // x86_64: rsi = second arg

    int oldfd = (int)oldfd_long;
    int newfd = (int)newfd_long;

    // ── BOUND CHECK 1: target must be stdin, stdout, or stderr ────────
    // We only care about socket → stdin/stdout/stderr redirections.
    // dup2 to any other fd is not a reverse shell invariant.
    if (newfd < 0 || newfd > 2) return 0;

    // ── BOUND CHECK 2: source fd must be in valid range ───────────────
    // REQUIRED for verifier to accept fd_array[oldfd] below.
    // Without this explicit bound, the verifier rejects the program.
    if (oldfd < 0 || oldfd >= MAX_FD) return 0;

    // ── Traverse kernel data structures to determine fd type ──────────
    // We need to check if oldfd refers to a socket (S_IFSOCK in i_mode).
    // Path: current_task → files_struct → fdtable → file[oldfd] → inode → i_mode
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    struct files_struct *files = NULL;
    BPF_CORE_READ_INTO(&files, task, files);
    if (!files) return 0;

    struct fdtable *fdt = NULL;
    BPF_CORE_READ_INTO(&fdt, files, fdt);
    if (!fdt) return 0;

    struct file **fd_array = NULL;
    BPF_CORE_READ_INTO(&fd_array, fdt, fd);
    if (!fd_array) return 0;

    // Read fd_array[oldfd] — safe: oldfd proven [0, MAX_FD-1] above
    struct file *f = NULL;
    bpf_probe_read_kernel(&f, sizeof(f), &fd_array[oldfd]);
    if (!f) return 0;

    struct inode *inode = NULL;
    BPF_CORE_READ_INTO(&inode, f, f_inode);
    if (!inode) return 0;

    unsigned short i_mode = 0;
    BPF_CORE_READ_INTO(&i_mode, inode, i_mode);

    // ── THE INVARIANT CHECK ───────────────────────────────────────────
    // S_IFSOCK = 0xC000, S_IFMT = 0xF000 (extracts file type bits)
    // If source fd is a socket being redirected to stdin/stdout/stderr,
    // this is the physical requirement of a reverse shell.
    if ((i_mode & 0xF000) == 0xC000) {
        __u64 cg = bpf_get_current_cgroup_id();
        __u64 now = bpf_ktime_get_ns();

        // Set BIT_FD_REDIRECT in the container's behavioral bitfield
        // with per-bit timestamp (v5 fix for stale-bit false positives)
        struct behavior_state *state = bpf_map_lookup_elem(&container_behavior, &cg);
        if (state) {
            state->flags |= BIT_FD_REDIRECT;
            state->bit_ts[6] = now;  // bit 6 = BIT_FD_REDIRECT
        }

        // Emit alert to high-priority ring buffer
        struct alert_t *alert = bpf_ringbuf_reserve(&alerts_rb, sizeof(struct alert_t), 0);
        if (alert) {
            alert->type = ALERT_FD_REDIRECT;
            alert->pid = bpf_get_current_pid_tgid() >> 32;
            alert->cgroup_id = cg;
            alert->timestamp = now;
            alert->flags = state ? state->flags : BIT_FD_REDIRECT;
            // extra: encodes oldfd and newfd for logging
            alert->extra = ((__u64)oldfd << 32) | (__u64)(unsigned int)newfd;
            bpf_ringbuf_submit(alert, 0);
        }

        // ENFORCE: Kill the process immediately
        bpf_send_signal(9);  // SIGKILL
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

### 6.5 Fork Acceleration Handler (handler_fork.bpf.c)

Detects fork bombs using the **second discrete derivative** of fork rate rather than a fixed threshold. This eliminates false positives on `make -j16` and container startup.

**Mathematical basis:**
- `d2 = rate[t] - 2*rate[t-1] + rate[t-2]` (second discrete derivative)
- Fork bomb: d2 > 0 always (exponential growth)
- `make -j16`: rate ramps up briefly, then stabilizes → d2 → 0
- Container startup: forks ~10-20 processes then stops → d2 → 0

```c
// handler_fork.bpf.c
// Tail-called for: clone (syscall 56) and clone3 (syscall 435)
#include "causaltrace_common.h"
#include "causaltrace_maps.h"

SEC("raw_tracepoint/sys_enter")
int handle_fork(struct bpf_raw_tracepoint_args *ctx) {
    __u64 cg = bpf_get_current_cgroup_id();
    __u64 now = bpf_ktime_get_ns();

    struct rate_state *rs = bpf_map_lookup_elem(&rate_map, &cg);
    if (!rs) {
        // First fork from this container — initialize state
        struct rate_state new_rs = {};
        new_rs.window_start = now;
        new_rs.count = 1;
        bpf_map_update_elem(&rate_map, &cg, &new_rs, BPF_NOEXIST);
        return 0;
    }

    // ── Window rotation (1-second windows) ───────────────────────────
    __u64 window_ns = 1000000000ULL;  // 1 second in nanoseconds
    if (now - rs->window_start > window_ns) {
        // Rotate: current → prev → prev_prev
        rs->prev_prev_count = rs->prev_count;
        rs->prev_count = rs->count;
        rs->count = 1;  // start new window with current fork
        rs->window_start = now;
    } else {
        rs->count += 1;
    }

    // ── ACCELERATION INVARIANT ────────────────────────────────────────
    // Only check when we have 3 full windows of data AND rate exceeds floor.
    // The floor (50 forks/s) prevents false positives on startup bursts.
    __u64 rate = rs->count;
    __u64 prev = rs->prev_count;
    __u64 prev_prev = rs->prev_prev_count;

    if (rate > 50 && prev > 0 && prev_prev > 0) {
        // Second discrete derivative (d2)
        // d2 > 0 means rate is accelerating (exponential growth signature)
        // Using signed arithmetic for the subtraction
        __s64 d2 = (__s64)rate - 2*(__s64)prev + (__s64)prev_prev;

        // Three conditions for fork bomb:
        // 1. d2 > 0: rate is accelerating
        // 2. rate > prev: current window is higher than previous
        // 3. prev > prev_prev: previous window was higher than the one before
        // Together: monotonically increasing with positive acceleration = exponential
        if (d2 > 0 && rate > prev && prev > prev_prev) {
            struct behavior_state *state = bpf_map_lookup_elem(&container_behavior, &cg);
            if (state) {
                state->flags |= BIT_FORK_ACCEL;
                state->bit_ts[7] = now;  // bit 7 = BIT_FORK_ACCEL
            }

            struct alert_t *alert = bpf_ringbuf_reserve(&alerts_rb, sizeof(struct alert_t), 0);
            if (alert) {
                alert->type = ALERT_FORK_ACCEL;
                alert->pid = bpf_get_current_pid_tgid() >> 32;
                alert->cgroup_id = cg;
                alert->timestamp = now;
                alert->flags = state ? state->flags : BIT_FORK_ACCEL;
                alert->extra = rate;  // current fork rate for logging
                bpf_ringbuf_submit(alert, 0);
            }

            bpf_send_signal(9);  // SIGKILL
        }
    }

    // Hard ceiling: 500 forks/second is never legitimate in a container
    // Defense in depth — catches edge cases where acceleration check might miss
    if (rate > 500) {
        bpf_send_signal(9);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

### 6.6 Execve Handler (handler_execve.bpf.c)

Detects reverse shells by matching against known shell binary names.

**Note:** This is a SECONDARY detection mechanism. The `dup2` fd-type invariant (handler_dup2.bpf.c) is the PRIMARY one. The execve handler catches shells earlier in the process, before the dup2 call. The dup2 handler catches any shell in any language that the execve handler misses.

```c
// handler_execve.bpf.c
// Tail-called for: execve (syscall 59)
#include "causaltrace_common.h"
#include "causaltrace_maps.h"

// Shell binary basenames to detect (byte-level comparison, no strcmp in eBPF)
// Covers common shell binaries and network tools used in reverse shells
#define SHELL_MATCH(buf, s) (buf[0]==s[0] && buf[1]==s[1] && buf[2]==s[2])

SEC("raw_tracepoint/sys_enter")
int handle_execve(struct bpf_raw_tracepoint_args *ctx) {
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];

    // Read filename from userspace (first argument to execve)
    char filename[128] = {};
    long fname_ptr = 0;
    BPF_CORE_READ_INTO(&fname_ptr, regs, di);  // rdi = filename pointer
    bpf_probe_read_user_str(filename, sizeof(filename), (void *)fname_ptr);

    // Extract basename: find last '/' and compare from there
    // Manual loop required — eBPF prohibits library calls
    char basename[16] = {};
    int last_slash = -1;
    #pragma unroll
    for (int i = 0; i < 127; i++) {
        if (filename[i] == '\0') break;
        if (filename[i] == '/') last_slash = i;
    }

    int start = last_slash + 1;
    #pragma unroll
    for (int i = 0; i < 15; i++) {
        if (filename[start + i] == '\0') break;
        basename[i] = filename[start + i];
    }

    // Check against known shell/network binaries
    // Two-char prefixes for speed; covers: sh, bash, dash, ash, zsh,
    // nc, ncat, netcat, python, python3, perl, ruby, php
    int is_shell = 0;
    if (basename[0] == 's' && basename[1] == 'h' && (basename[2] == '\0'))
        is_shell = 1;
    else if (basename[0] == 'b' && basename[1] == 'a' && basename[2] == 's')
        is_shell = 1;  // bash
    else if (basename[0] == 'd' && basename[1] == 'a' && basename[2] == 's')
        is_shell = 1;  // dash
    else if (basename[0] == 'n' && basename[1] == 'c' && basename[2] == '\0')
        is_shell = 1;  // nc
    else if (basename[0] == 'n' && basename[1] == 'c' && basename[2] == 'a')
        is_shell = 1;  // ncat, netcat
    else if (basename[0] == 'z' && basename[1] == 's' && basename[2] == 'h')
        is_shell = 1;  // zsh

    if (is_shell) {
        __u64 cg = bpf_get_current_cgroup_id();
        __u64 now = bpf_ktime_get_ns();

        struct behavior_state *state = bpf_map_lookup_elem(&container_behavior, &cg);
        if (state) {
            state->flags |= BIT_SHELL_SPAWN;
            state->bit_ts[0] = now;  // bit 0 = BIT_SHELL_SPAWN
        }

        struct alert_t *alert = bpf_ringbuf_reserve(&alerts_rb, sizeof(struct alert_t), 0);
        if (alert) {
            alert->type = ALERT_REVERSE_SHELL;
            alert->pid = bpf_get_current_pid_tgid() >> 32;
            alert->cgroup_id = cg;
            alert->timestamp = now;
            alert->flags = state ? state->flags : BIT_SHELL_SPAWN;
            bpf_ringbuf_submit(alert, 0);
        }

        bpf_send_signal(9);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

### 6.7 File Handler (handler_file.bpf.c)

Detects access to sensitive files via path prefix matching.

```c
// handler_file.bpf.c
// Tail-called for: openat (syscall 257)
#include "causaltrace_common.h"
#include "causaltrace_maps.h"

SEC("raw_tracepoint/sys_enter")
int handle_file(struct bpf_raw_tracepoint_args *ctx) {
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];

    // openat(dirfd, pathname, flags, mode)
    // rsi = pathname (second argument)
    long path_ptr = 0;
    BPF_CORE_READ_INTO(&path_ptr, regs, si);  // x86_64: rsi = second arg

    char path[128] = {};
    bpf_probe_read_user_str(path, sizeof(path), (void *)path_ptr);

    // Byte-level prefix matching against sensitive paths
    // eBPF prohibits strcmp() — manual comparison required
    // Patterns: /etc/shadow, /etc/passwd, /proc/1/ns, /var/run/secrets
    int is_sensitive = 0;

    // /etc/shadow
    if (path[0]=='/' && path[1]=='e' && path[2]=='t' && path[3]=='c' &&
        path[4]=='/' && path[5]=='s' && path[6]=='h' && path[7]=='a')
        is_sensitive = 1;

    // /etc/passwd
    if (path[0]=='/' && path[1]=='e' && path[2]=='t' && path[3]=='c' &&
        path[4]=='/' && path[5]=='p' && path[6]=='a' && path[7]=='s')
        is_sensitive = 1;

    // /proc/1/ns (namespace probe — host PID 1's namespaces)
    if (path[0]=='/' && path[1]=='p' && path[2]=='r' && path[3]=='o' &&
        path[4]=='c' && path[5]=='/' && path[6]=='1' && path[7]=='/')
        is_sensitive = 1;

    // /var/run/secrets (Kubernetes service account tokens)
    if (path[0]=='/' && path[1]=='v' && path[2]=='a' && path[3]=='r' &&
        path[4]=='/' && path[5]=='r' && path[6]=='u' && path[7]=='n' &&
        path[8]=='/' && path[9]=='s' && path[10]=='e' && path[11]=='c')
        is_sensitive = 1;

    if (is_sensitive) {
        __u64 cg = bpf_get_current_cgroup_id();
        __u64 now = bpf_ktime_get_ns();

        struct behavior_state *state = bpf_map_lookup_elem(&container_behavior, &cg);
        if (state) {
            // Set appropriate bit based on path type
            if (path[5] == '1' && path[6] == '/')
                state->flags |= BIT_NS_PROBE;  // /proc/1/ access = namespace probe
            else
                state->flags |= BIT_SENSITIVE_FILE;
            state->bit_ts[2] = now;
            state->bit_ts[3] = now;
        }

        struct alert_t *alert = bpf_ringbuf_reserve(&alerts_rb, sizeof(struct alert_t), 0);
        if (alert) {
            alert->type = ALERT_SENSITIVE_FILE;
            alert->pid = bpf_get_current_pid_tgid() >> 32;
            alert->cgroup_id = cg;
            alert->timestamp = now;
            alert->flags = state ? state->flags : BIT_SENSITIVE_FILE;
            bpf_ringbuf_submit(alert, 0);
        }

        bpf_send_signal(9);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

### 6.8 PrivEsc Handler (handler_privesc.bpf.c)

Detects `setuid(0)`, `unshare` with namespace flags, and registers cgroup inheritance.

```c
// handler_privesc.bpf.c
// Tail-called for: setuid (105), setns (308), unshare (272), ptrace (101)
#include "causaltrace_common.h"
#include "causaltrace_maps.h"

SEC("raw_tracepoint/sys_enter")
int handle_privesc(struct bpf_raw_tracepoint_args *ctx) {
    unsigned long syscall_nr = ctx->args[1];
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];

    __u64 cg = bpf_get_current_cgroup_id();
    __u64 now = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    int should_kill = 0;

    if (syscall_nr == 272) {  // unshare
        long flags_long = 0;
        BPF_CORE_READ_INTO(&flags_long, regs, di);  // rdi = flags
        long flags = flags_long;

        // CLONE_NEWCGROUP: register for behavior inheritance on next syscall
        if (flags & 0x02000000) {
            bpf_map_update_elem(&pending_cgroup_inherit, &pid_tgid, &cg, BPF_ANY);
        }

        // CLONE_NEWNS (mount) or CLONE_NEWUSER: namespace escape attempt
        if (flags & 0x00020000 || flags & 0x10000000) {
            should_kill = 1;
        }
    }

    else if (syscall_nr == 105) {  // setuid
        long uid_long = 0;
        BPF_CORE_READ_INTO(&uid_long, regs, di);
        if (uid_long == 0) {
            should_kill = 1;
        }
    }

    // setns and ptrace: always suspicious in container context
    else if (syscall_nr == 308 || syscall_nr == 101) {
        should_kill = 1;
    }

    if (should_kill) {
        struct behavior_state *state = bpf_map_lookup_elem(&container_behavior, &cg);
        if (state) {
            state->flags |= BIT_PRIVESC;
            state->bit_ts[4] = now;
        }

        struct alert_t *alert = bpf_ringbuf_reserve(&alerts_rb, sizeof(struct alert_t), 0);
        if (alert) {
            alert->type = ALERT_PRIVESC;
            alert->pid = pid_tgid >> 32;
            alert->cgroup_id = cg;
            alert->timestamp = now;
            alert->flags = state ? state->flags : BIT_PRIVESC;
            alert->extra = (__u64)syscall_nr;
            bpf_ringbuf_submit(alert, 0);
        }

        bpf_send_signal(9);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

---

## 7. KERNEL-SPACE IMPLEMENTATION — TIER 2

### 7.1 Network Link Tracker (probe_b_network.bpf.c)

Tracks inter-container TCP connections. This is the most critical Tier 2 component — it creates the edges in the container communication graph that the sheaf Laplacian operates on.

**Design notes:**
- `kprobe/tcp_v4_connect`: fires at entry, stashes `struct sock *` in `connect_sk_stash`
- `kretprobe/tcp_v4_connect`: fires on return (when connection is established), reads stashed sk pointer
- Uses LRU map for sk stash to prevent exhaustion attacks
- Resolves dst_ip → dst_cgroup via `ip_to_cgroup` map
- Two-hop invariant check with per-bit timestamps (v5 fix)
- Emits to `telemetry_rb` (not `alerts_rb`) to prevent telemetry from starving alerts

```c
// probe_b_network.bpf.c
#include "causaltrace_common.h"
#include "causaltrace_maps.h"

// Entry: stash sock pointer for the return probe
// The socket fields (dst_addr, dst_port) aren't populated at entry time
SEC("kprobe/tcp_v4_connect")
int trace_connect_entry(struct pt_regs *ctx) {
    // tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
    // sk is the first argument — PT_REGS_PARM1 gets rdi
    __u64 sk_ptr = PT_REGS_PARM1(ctx);
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    // Stash sk pointer keyed by pid_tgid for the return probe
    // LRU_HASH ensures this doesn't exhaust under flood attacks
    bpf_map_update_elem(&connect_sk_stash, &pid_tgid, &sk_ptr, BPF_ANY);
    return 0;
}

// Return: connection is established, read socket fields
SEC("kretprobe/tcp_v4_connect")
int trace_connect_return(struct pt_regs *ctx) {
    // Only process successful connects (return value = 0)
    int ret = PT_REGS_RC(ctx);
    if (ret != 0) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *sk_ptr = bpf_map_lookup_elem(&connect_sk_stash, &pid_tgid);
    if (!sk_ptr) return 0;

    struct sock *sk = (struct sock *)(*sk_ptr);
    bpf_map_delete_elem(&connect_sk_stash, &pid_tgid);

    // Read 4-tuple from socket structure via CO-RE
    __u32 dst_addr = 0;
    __u16 dst_port = 0;
    BPF_CORE_READ_INTO(&dst_addr, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&dst_port, sk, __sk_common.skc_dport);
    dst_port = __bpf_ntohs(dst_port);  // convert from network to host byte order

    // Resolve destination IP to container cgroup
    __u64 *dst_cg_ptr = bpf_map_lookup_elem(&ip_to_cgroup, &dst_addr);
    if (!dst_cg_ptr) return 0;  // not a known container — skip
    __u64 dst_cg = *dst_cg_ptr;

    __u64 src_cg = bpf_get_current_cgroup_id();
    __u64 now = bpf_ktime_get_ns();

    // ── TWO-HOP INVARIANT CHECK ───────────────────────────────────────
    struct behavior_state *src_state = bpf_map_lookup_elem(&container_behavior, &src_cg);
    if (src_state) {
        // Set lateral connect bit with per-bit timestamp
        src_state->flags |= BIT_LATERAL_CONNECT;
        src_state->bit_ts[1] = now;
        src_state->conn_dst_cg = dst_cg;
        src_state->conn_port = dst_port;

        // Lazy expiry: clear bits whose per-bit timestamps have expired
        // This prevents stale-bit false positives (v5 fix for the Monday-Friday problem)
        #pragma unroll
        for (int i = 0; i < 8; i++) {
            if ((now - src_state->bit_ts[i]) > TWOHOP_WINDOW_NS) {
                src_state->flags &= ~(1ULL << i);
            }
        }

        // Check: was there a shell spawn (bit0) or fd-redirect (bit6) recently?
        // Using per-bit timestamps — ONLY check the relevant bits' own timestamps
        __u64 shell_ts    = src_state->bit_ts[0];  // BIT_SHELL_SPAWN timestamp
        __u64 fd_redir_ts = src_state->bit_ts[6];  // BIT_FD_REDIRECT timestamp
        __u64 latest_dangerous = shell_ts > fd_redir_ts ? shell_ts : fd_redir_ts;

        if ((now - latest_dangerous) < TWOHOP_WINDOW_NS) {
            if (src_state->flags & (BIT_SHELL_SPAWN | BIT_FD_REDIRECT)) {
                // TWO-HOP ATTACK PATTERN DETECTED IN KERNEL
                // (shell OR reverse shell) + lateral connect within 5 seconds
                struct alert_t *alert = bpf_ringbuf_reserve(&alerts_rb, sizeof(struct alert_t), 0);
                if (alert) {
                    alert->type = ALERT_TWO_HOP;
                    alert->pid = pid_tgid >> 32;
                    alert->cgroup_id = src_cg;
                    alert->timestamp = now;
                    alert->flags = src_state->flags;
                    alert->extra = dst_cg;  // which container was targeted
                    bpf_ringbuf_submit(alert, 0);
                }
                bpf_send_signal(9);
            }
        }
    }

    // Emit connection event to TELEMETRY ring buffer (not alerts)
    // This is used by Tier 3 for novel-edge detection and sheaf calibration
    struct alert_t *evt = bpf_ringbuf_reserve(&telemetry_rb, sizeof(struct alert_t), 0);
    if (evt) {
        evt->type = EVENT_CONNECTION;
        evt->cgroup_id = src_cg;
        evt->timestamp = now;
        evt->extra = ((__u64)dst_addr << 32) | (__u64)dst_port;
        evt->flags = dst_cg;   // reusing flags field for dst_cgroup_id
        bpf_ringbuf_submit(evt, 0);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

### 7.2 Process Lineage Tracker (probe_c_lineage.bpf.c)

Tracks process fork/exec events to build the process lineage tree within each container. Sets `BIT_SHELL_SPAWN` when a shell binary is exec'd.

```c
// probe_c_lineage.bpf.c
#include "causaltrace_common.h"
#include "causaltrace_maps.h"

// Track shell spawns via exec events
SEC("tracepoint/sched/sched_process_exec")
int trace_exec(struct trace_event_raw_sched_process_exec *ctx) {
    // Get filename from tracepoint args
    unsigned fname_off = ctx->__data_loc_filename & 0xFFFF;
    char *fname = (char *)ctx + fname_off;

    // Check if this is a shell binary
    // Same matching logic as handler_execve but via tracepoint (not kprobe)
    char ch0 = 0, ch1 = 0, ch2 = 0;
    bpf_probe_read_kernel(&ch0, 1, fname);
    bpf_probe_read_kernel(&ch1, 1, fname + 1);
    bpf_probe_read_kernel(&ch2, 1, fname + 2);

    int is_shell = 0;
    if (ch0=='s' && ch1=='h' && ch2=='\0') is_shell = 1;
    if (ch0=='b' && ch1=='a' && ch2=='s') is_shell = 1;  // bash
    if (ch0=='d' && ch1=='a' && ch2=='s') is_shell = 1;  // dash
    if (ch0=='n' && ch1=='c' && ch2=='\0') is_shell = 1; // nc

    if (is_shell) {
        __u64 cg = bpf_get_current_cgroup_id();
        __u64 now = bpf_ktime_get_ns();

        struct behavior_state *state = bpf_map_lookup_elem(&container_behavior, &cg);
        if (state) {
            state->flags |= BIT_SHELL_SPAWN;
            state->bit_ts[0] = now;
        }
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

---

## 8. USER-SPACE IMPLEMENTATION — TIER 3

Tier 3 is a Python daemon (~500 lines total) that runs every ~5 seconds. All components are described below with complete pseudocode.

### 8.1 Signal Extractor (signal_extractor.py)

Converts a container's raw bigram CMS into a d=74 dimensional signal vector.

**Why d=74 and not more:**
- 400+ bigram frequencies → PCA → 50 dims (retains >95% variance, stable CCA)
- 3 Rényi entropy values (different sensitivity to rare vs. common events)
- 20 transition probability marginals (Markov structure)
- 1 syscall rate
- **NO invariant bits** — those go only to the Semantic Label Engine

**Why bigrams instead of unigrams:**
Bigrams capture transition structure: `[read→write→read]` produces different bigrams than `[read→read→write]` even with identical syscall multisets. This resolves G2 (loss of temporal ordering) without a sequential model.

```python
# signal_extractor.py
import numpy as np
from dataclasses import dataclass
from typing import Optional

# CMS constants — must match causaltrace_common.h exactly
CMS_ROWS = 4
CMS_COLS = 128
CMS_COL_MASK = 127
TOP_SYSCALLS = 25
MAX_BIGRAMS = TOP_SYSCALLS * TOP_SYSCALLS  # = 625
WINDOW_SECONDS = 5.0

# Must match CMS_PRIMES and CMS_SEEDS in common.h
CMS_PRIMES = [2654435761, 2246822519, 3266489917, 668265263]
CMS_SEEDS = [1, 7, 13, 31]


@dataclass
class BigramSketch:
    """Python representation of struct bigram_sketch from BPF."""
    counters: np.ndarray   # shape: (CMS_ROWS, CMS_COLS), dtype=uint32
    prev_idx: int
    total_count: int
    window_start: int      # nanoseconds


@dataclass
class CalibrationStats:
    """Calibration data needed for signal extraction."""
    pca_components: np.ndarray  # shape: (50, MAX_BIGRAMS) — PCA projection matrix
    pca_mean: np.ndarray        # shape: (MAX_BIGRAMS,) — mean of training bigrams


def reconstruct_bigrams(sketch: BigramSketch) -> np.ndarray:
    """
    Reconstruct bigram frequency estimates from the Count-Min Sketch.
    CMS estimate for each bigram: minimum of estimates across all hash rows.
    This gives an over-estimate, but the minimum is the least biased.
    """
    estimates = np.zeros((MAX_BIGRAMS, CMS_ROWS), dtype=np.float64)
    for bg_idx in range(MAX_BIGRAMS):
        for row in range(CMS_ROWS):
            col = (bg_idx * CMS_PRIMES[row] + CMS_SEEDS[row]) & CMS_COL_MASK
            estimates[bg_idx, row] = sketch.counters[row, col]
    return estimates.min(axis=1)  # CMS minimum estimate


def renyi_entropy(p: np.ndarray, alpha: float) -> float:
    """
    Rényi entropy of order alpha.
    H_alpha(p) = (1/(1-alpha)) * log2(sum(p_i^alpha))
    For alpha → 1: equals Shannon entropy.
    
    alpha < 1: emphasizes rare events (catches anomalous syscalls)
    alpha > 1: emphasizes common events (good for profiling baselines)
    Using three alpha values gives sensitivity at different scales.
    """
    p_nz = p[p > 1e-12]  # exclude zeros (log undefined)
    if len(p_nz) == 0:
        return 0.0
    if alpha == 1.0:
        return float(-np.sum(p_nz * np.log2(p_nz)))
    return float((1.0 / (1.0 - alpha)) * np.log2(np.sum(p_nz ** alpha)))


def extract_signal_74(sketch: BigramSketch,
                      cal_stats: CalibrationStats) -> np.ndarray:
    """
    Extract d=74 dimensional signal vector from a bigram CMS.
    
    IMPORTANT: Invariant bits (container_behavior.flags) are NOT included here.
    They go ONLY to the Semantic Label Engine. Including them here would cause
    covariance matrix degeneracy (condition number ~10^12) in the Mahalanobis
    distance computation.
    
    Signal components:
      [0:3]    Rényi entropy H_α for α ∈ {0.5, 1.0, 2.0}         = 3 dims
      [3:53]   PCA projection of bigram frequencies (625→50)        = 50 dims
      [53:73]  Transition probability marginals (top-24 rows max)   = 20 dims
      [73]     Total syscall rate (count / window_seconds)           = 1 dim
    
    Returns: np.ndarray, shape (74,), dtype float64
    """
    # Reconstruct bigram frequencies from CMS
    raw_bigrams = reconstruct_bigrams(sketch)  # shape: (MAX_BIGRAMS,) = (625,)

    total = raw_bigrams.sum()
    if total < 1.0:
        return np.zeros(74, dtype=np.float64)

    p = raw_bigrams / total  # normalize to probability distribution

    # ── Rényi entropy at three scales ────────────────────────────────
    p_nz = p[p > 1e-12]
    H_05 = renyi_entropy(p_nz, 0.5)   # emphasizes rare events (anomaly-sensitive)
    H_10 = renyi_entropy(p_nz, 1.0)   # Shannon entropy (baseline)
    H_20 = renyi_entropy(p_nz, 2.0)   # emphasizes common events (profile)

    # ── PCA projection of bigram frequencies ─────────────────────────
    # cal_stats.pca_components: (50, 625) learned during calibration
    # Projects 625-dim bigram space to 50-dim subspace retaining >95% variance
    bigram_centered = raw_bigrams - cal_stats.pca_mean   # center first
    bigram_pca = cal_stats.pca_components @ bigram_centered  # (50,)

    # ── Transition probability marginals ──────────────────────────────
    # Reshape bigrams to (24, 24) matrix (excluding the "other" row/col)
    # Then take max transition probability from each source syscall
    # Captures Markov structure: "how deterministic is syscall i's next step?"
    top_bigrams = p[:576].reshape(24, 24)  # 24*24 = 576 (exclude "other" index 24)
    row_sums = top_bigrams.sum(axis=1)
    row_sums[row_sums == 0] = 1.0  # avoid division by zero
    trans_probs = top_bigrams / row_sums[:, np.newaxis]
    marginals = trans_probs.max(axis=1)  # shape: (24,) but we want 20

    # Take top 20 marginals (by index, keeping consistent dimension)
    marginals_20 = marginals[:20]

    # ── Syscall rate ──────────────────────────────────────────────────
    rate = total / WINDOW_SECONDS

    # ── Assemble final signal vector ──────────────────────────────────
    x = np.concatenate([
        [H_05, H_10, H_20],   # 3
        bigram_pca,             # 50
        marginals_20,           # 20
        [rate]                  # 1
    ])                          # total: 74 dimensions

    return x.astype(np.float64)
```

### 8.2 Feature Whitener (whitener.py)

Standardizes signals to zero mean, unit variance per dimension. This is essential for the Mahalanobis distance to work correctly — dimensions with different natural scales would otherwise dominate the distance measure.

```python
# whitener.py
import numpy as np

class FeatureWhitener:
    """
    Zero-mean, unit-variance whitening per feature dimension.
    
    epsilon=1e-6 regularizes zero-variance dimensions.
    
    NOTE: Do NOT use this with a signal vector that includes invariant bits.
    If invariant bits (always 0 during calibration) were included:
      - std[invariant_dims] = 0 → regularized to epsilon=1e-6
      - Whitened value during attack = 1/1e-6 = 10^6
      - Covariance matrix has 10^-12 on those diagonals
      - np.linalg.inv(cov) has condition number 10^12 → numerical garbage
    
    The solution is to NOT include invariant bits in the signal vector.
    See Design Decision 3 for full explanation.
    """
    
    def __init__(self, epsilon: float = 1e-6):
        self.epsilon = epsilon
        self.mean: np.ndarray = None
        self.std: np.ndarray = None
        self._fitted = False
    
    def fit(self, X_calibration: np.ndarray):
        """
        Learn mean and std from calibration data.
        X_calibration: shape (T, d) where T = number of time windows, d = 74
        Requires T >> d for stable estimates (T >= 300 recommended, 60 minimum)
        """
        self.mean = X_calibration.mean(axis=0)    # (d,)
        self.std = np.maximum(
            X_calibration.std(axis=0),
            self.epsilon                            # floor at epsilon
        )
        self._fitted = True
    
    def transform(self, x: np.ndarray) -> np.ndarray:
        """Whiten a single signal vector. x: shape (d,)"""
        if not self._fitted:
            raise RuntimeError("Must call fit() before transform()")
        return (x - self.mean) / self.std
    
    def transform_batch(self, X: np.ndarray) -> np.ndarray:
        """Whiten a batch. X: shape (T, d)"""
        if not self._fitted:
            raise RuntimeError("Must call fit() before transform_batch()")
        return (X - self.mean) / self.std
```

### 8.3 EMA Signal Buffer (ema_buffer.py)

Accumulates small, persistent anomalies that individual windows miss.

```python
# ema_buffer.py
import numpy as np
from typing import Dict

class EMASignalBuffer:
    """
    Exponential Moving Average for slow-drip attack detection.
    
    Motivation: Low-and-slow exfiltration (10 bytes every 6 seconds) resets
    the bigram CMS each 5-second window. No individual window shows enough
    anomaly to fire. The EMA accumulates drift over time.
    
    With alpha=0.2:
      - A persistent 0.5σ anomaly reaches 0.5/(1-0.8) = 2.5σ steady-state
      - Time to reach 80% of steady-state: ~7 windows (35 seconds)
      - Time to breach 4-sigma threshold: ~15 windows (~75 seconds)
    
    The sheaf detector runs on BOTH x_raw (sudden attacks) and x_ema
    (slow-drip attacks) with separate calibrated thresholds.
    """
    
    def __init__(self, alpha: float = 0.2, d: int = 74):
        self.alpha = alpha
        self.d = d
        self._ema: Dict[int, np.ndarray] = {}   # cgroup_id → EMA signal
    
    def update(self, cg_id: int, x_raw: np.ndarray) -> np.ndarray:
        """
        Update EMA for a container and return the current EMA signal.
        x_raw: whitened signal vector, shape (d,)
        Returns: EMA signal vector, shape (d,)
        """
        if cg_id not in self._ema:
            self._ema[cg_id] = x_raw.copy()
        else:
            self._ema[cg_id] = self.alpha * x_raw + (1 - self.alpha) * self._ema[cg_id]
        return self._ema[cg_id].copy()
    
    def get(self, cg_id: int) -> np.ndarray:
        return self._ema.get(cg_id, None)
    
    def reset(self, cg_id: int):
        """Reset EMA when container is restarted."""
        self._ema.pop(cg_id, None)
```

### 8.4 Calibration (calibrate.py)

Learns the restriction maps from normal traffic. Run this before enforcement mode.

**What to run during calibration (30-60 minutes):**
- Normal HTTP traffic through NGINX proxy (generates Web→API TCP connections)
- API→DB queries (generates API→DB TCP connections)  
- Traffic bursts every ~30 seconds (simulates realistic load)
- Container restart/recovery cycles
- Package manager operations (apt-get update)

**Why these patterns:** The CCA must learn restriction maps for all communication patterns that occur during normal operation. Missing a pattern during calibration means it will appear as a novel edge during enforcement and trigger a false alert.

```python
# calibrate.py
import numpy as np
from sklearn.decomposition import PCA
from sklearn.cross_decomposition import CCA
import json, pickle
from pathlib import Path
from typing import Dict, List, Tuple
from collections import defaultdict

from signal_extractor import BigramSketch, CalibrationStats, extract_signal_74
from whitener import FeatureWhitener

class SheafCalibrator:
    """
    Learns the sheaf Laplacian restriction maps from normal container traffic.
    
    Calibration pipeline:
    1. PCA: pool all bigram vectors, learn 625→50 projection
    2. Whitening: per-container zero-mean unit-variance normalization
    3. CCA: for each observed edge, learn restriction maps at 3 temporal lags
    4. Mahalanobis thresholds: 4-sigma on calibration residuals
    5. Global Rayleigh quotient threshold: 4-sigma global
    
    CRITICAL: 4-sigma (not 3-sigma) because Mahalanobis distances follow
    chi-squared distribution. At k=50 dimensions, 3-sigma would give too
    many false positives. 4-sigma → ≤0.003% FPR.
    """
    
    def __init__(self, d: int = 74, k: int = 50):
        self.d = d   # signal dimension (74: 3 entropy + 50 PCA + 20 marginals + 1 rate)
        self.k = k   # shared coupling space dimension (CCA components)
        
        # Learned during calibration:
        self.pca = None                   # sklearn PCA object
        self.whitener: Dict[int, FeatureWhitener] = {}    # per container
        self.restriction_maps = {}        # (u, v, lag) → (F_u, F_v)
        self.edge_cov_inv = {}            # (u, v, lag) → Σ^{-1} (Mahalanobis)
        self.edge_thresholds = {}         # (u, v, lag) → τ_e (4-sigma)
        self.ema_edge_thresholds = {}     # (u, v) → τ_ema_e
        self.global_threshold = None      # τ_global (Rayleigh quotient)
        self.ema_global_threshold = None
        self.calibrated_edges = set()     # set of (src_cg, dst_cg, dst_port) tuples
        self.cal_stats = None             # CalibrationStats for signal extraction
    
    def calibrate(self,
                  bigram_traces: Dict[int, List[BigramSketch]],
                  connection_events: List[dict],
                  duration_minutes: float) -> None:
        """
        Main calibration entry point.
        
        bigram_traces: {cgroup_id: [BigramSketch, ...]} — one sketch per 5s window
        connection_events: list of {src_cg, dst_cg, dst_port, timestamp} dicts
        duration_minutes: how long calibration ran (for validation)
        
        Minimum requirements:
          - T >= 60 time windows per container (5 minutes at 5s windows)
          - All containers must have data (non-empty bigram_traces for each)
          - At least one connection event per calibrated edge
        """
        print(f"Calibrating on {duration_minutes:.1f} min of traffic...")
        print(f"Containers: {list(bigram_traces.keys())}")
        
        # ── Step 1: PCA on pooled bigram vectors ──────────────────────
        print("Step 1: Learning PCA projection (625 → 50 dims)...")
        all_bigrams = []
        for cg_id, sketches in bigram_traces.items():
            for sketch in sketches:
                from signal_extractor import reconstruct_bigrams
                bg = reconstruct_bigrams(sketch)
                all_bigrams.append(bg)
        
        all_bigrams_arr = np.array(all_bigrams)  # (N, 625)
        self.pca = PCA(n_components=50)
        self.pca.fit(all_bigrams_arr)
        
        explained = self.pca.explained_variance_ratio_.sum()
        print(f"  PCA explained variance: {explained:.3f}")
        if explained < 0.90:
            print("  WARNING: Explained variance < 90%. Need more calibration data.")
        
        self.cal_stats = CalibrationStats(
            pca_components=self.pca.components_,
            pca_mean=self.pca.mean_
        )
        
        # ── Step 2: Extract signals and learn per-container whitening ──
        print("Step 2: Learning per-container whitening...")
        container_signals = {}  # cg_id → (T, 74) whitened signals
        
        for cg_id, sketches in bigram_traces.items():
            signals = []
            for sketch in sketches:
                x = extract_signal_74(sketch, self.cal_stats)
                signals.append(x)
            X = np.array(signals)  # (T, 74)
            
            whitener = FeatureWhitener(epsilon=1e-6)
            whitener.fit(X)
            self.whitener[cg_id] = whitener
            container_signals[cg_id] = whitener.transform_batch(X)
            
            print(f"  Container {cg_id}: {len(signals)} windows, "
                  f"mean_std={X.std(axis=0).mean():.3f}")
        
        # ── Step 3: Learn CCA restriction maps per observed edge × lag ─
        print("Step 3: Learning CCA restriction maps (3 lags per edge)...")
        observed_edges = self._extract_edges(connection_events)
        
        for (u, v, port) in observed_edges:
            self.calibrated_edges.add((u, v, port))
            
            if u not in container_signals or v not in container_signals:
                print(f"  Skipping edge ({u},{v}): missing container data")
                continue
            
            X_u = container_signals[u]  # (T, 74), whitened
            X_v = container_signals[v]  # (T, 74), whitened
            
            for lag in [0, 1, 2]:  # 0s, 5s, 10s temporal offset
                # Align: X_u[i] paired with X_v[i+lag]
                if lag > 0:
                    X_u_l = X_u[:-lag]   # (T-lag, 74)
                    X_v_l = X_v[lag:]    # (T-lag, 74)
                else:
                    X_u_l = X_u
                    X_v_l = X_v
                
                T = len(X_u_l)
                if T < self.k + 10:
                    print(f"  Skipping edge ({u},{v}) lag={lag}: only {T} samples")
                    continue
                
                # CCA: find projections F_u, F_v that maximize correlation
                # between F_u @ X_u and F_v @ X_v
                cca = CCA(n_components=self.k)
                cca.fit(X_u_l, X_v_l)
                
                F_u = cca.x_rotations_.T  # (k, d) = (50, 74)
                F_v = cca.y_rotations_.T  # (k, d) = (50, 74)
                self.restriction_maps[(u, v, lag)] = (F_u, F_v)
                
                # Compute normal residuals for Mahalanobis threshold
                diffs = np.array([
                    F_u @ X_u_l[t] - F_v @ X_v_l[t]
                    for t in range(T)
                ])  # (T, k)
                
                # Covariance of normal residuals in shared space
                cov = np.cov(diffs.T) + 1e-6 * np.eye(self.k)
                cov_inv = np.linalg.inv(cov)
                self.edge_cov_inv[(u, v, lag)] = cov_inv
                
                # 4-sigma Mahalanobis threshold
                mahal_dists = np.array([
                    diffs[t] @ cov_inv @ diffs[t]
                    for t in range(T)
                ])
                mu_e = mahal_dists.mean()
                sigma_e = mahal_dists.std()
                self.edge_thresholds[(u, v, lag)] = mu_e + 4 * sigma_e
                
                print(f"  Edge ({u},{v}) lag={lag}: "
                      f"T={T}, μ={mu_e:.2f}, σ={sigma_e:.2f}, "
                      f"τ={self.edge_thresholds[(u,v,lag)]:.2f}")
        
        # ── Step 4: Global Rayleigh quotient threshold ─────────────────
        print("Step 4: Computing global Rayleigh quotient threshold...")
        global_energies = self._compute_global_energies(container_signals)
        
        if len(global_energies) > 0:
            mu_g = global_energies.mean()
            sigma_g = global_energies.std()
            self.global_threshold = mu_g + 4 * sigma_g
            print(f"  Global: μ={mu_g:.4f}, σ={sigma_g:.4f}, τ={self.global_threshold:.4f}")
        
        print(f"Calibration complete. {len(self.calibrated_edges)} edges calibrated.")
    
    def _extract_edges(self, connection_events: List[dict]) -> set:
        """Extract unique (src_cg, dst_cg, dst_port) from connection events."""
        edges = set()
        for evt in connection_events:
            edges.add((evt['src_cg'], evt['dst_cg'], evt['dst_port']))
        return edges
    
    def _compute_global_energies(self, container_signals: dict) -> np.ndarray:
        """Compute Rayleigh quotient E(x) = x^T L_F x / ||x||^2 for each time window."""
        energies = []
        all_cgs = sorted(container_signals.keys())
        T = min(len(container_signals[cg]) for cg in all_cgs)
        
        for t in range(T):
            signals_t = {cg: container_signals[cg][t] for cg in all_cgs}
            total_energy = 0.0
            
            for (u, v, lag) in self.restriction_maps:
                if lag != 0: continue  # use lag=0 for global threshold
                if u not in signals_t or v not in signals_t: continue
                
                F_u, F_v = self.restriction_maps[(u, v, lag)]
                diff = F_u @ signals_t[u] - F_v @ signals_t[v]
                cov_inv = self.edge_cov_inv.get((u, v, lag))
                if cov_inv is not None:
                    energy = diff @ cov_inv @ diff
                else:
                    energy = np.dot(diff, diff)
                total_energy += energy
            
            x_global = np.concatenate([signals_t[cg] for cg in all_cgs])
            x_norm_sq = np.dot(x_global, x_global)
            if x_norm_sq > 0:
                energies.append(total_energy / x_norm_sq)
        
        return np.array(energies) if energies else np.array([0.0])
    
    def save(self, calibration_dir: str):
        """Save all calibration data to disk."""
        Path(calibration_dir).mkdir(parents=True, exist_ok=True)
        
        # Restriction maps and covariances
        np.savez(f"{calibration_dir}/restriction_maps.npz",
                 **{f"F_{u}_{v}_{lag}_{k}": v
                    for (u, v, lag), (Fu, Fv) in self.restriction_maps.items()
                    for k, v in [('u', Fu), ('v', Fv)]})
        
        # Thresholds
        with open(f"{calibration_dir}/edge_thresholds.json", 'w') as f:
            json.dump({str(k): float(v) for k, v in self.edge_thresholds.items()}, f)
        
        with open(f"{calibration_dir}/global_threshold.json", 'w') as f:
            json.dump({'global': float(self.global_threshold or 0)}, f)
        
        # Calibrated edges
        with open(f"{calibration_dir}/calibrated_edges.json", 'w') as f:
            json.dump(list(self.calibrated_edges), f)
        
        # Whiteners and PCA
        with open(f"{calibration_dir}/whiteners.pkl", 'wb') as f:
            pickle.dump(self.whitener, f)
        
        with open(f"{calibration_dir}/pca.pkl", 'wb') as f:
            pickle.dump(self.pca, f)
        
        print(f"Calibration saved to {calibration_dir}/")
```

### 8.5 Sheaf Detector (sheaf_detector.py)

The runtime detection engine. Runs every ~5 seconds.

```python
# sheaf_detector.py
import numpy as np
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from signal_extractor import extract_signal_74, BigramSketch
from whitener import FeatureWhitener
from ema_buffer import EMASignalBuffer
from calibrate import SheafCalibrator

VERDICT_ALLOW = 0
VERDICT_KILL = 1

@dataclass
class EdgeAnomaly:
    src: int    # src cgroup_id
    dst: int    # dst cgroup_id
    lag: int    # temporal lag that produced max energy
    energy: float
    threshold: float
    ratio: float = 0.0  # energy / threshold

@dataclass
class NovelEdgeAlert:
    src: int
    dst: int
    port: int
    severity: str = "HIGH"

@dataclass
class AttackLabel:
    name: str
    mitre_ids: List[str]
    severity: str    # CRITICAL, HIGH, MEDIUM, LOW, NONE
    
@dataclass
class EigenmodeResult:
    total_energy: float
    dominant_modes: List[int]
    mode_energies: List[float]
    
@dataclass
class Verdict:
    action: int                              # VERDICT_ALLOW or VERDICT_KILL
    affected_cgroups: List[int] = field(default_factory=list)
    rayleigh: float = 0.0
    global_threshold: float = 0.0
    edge_anomalies: List[EdgeAnomaly] = field(default_factory=list)
    novel_edges: List[NovelEdgeAlert] = field(default_factory=list)
    label: Optional[AttackLabel] = None
    eigenmodes: Optional[EigenmodeResult] = None
    reason: str = ""


class SheafDetector:
    """
    Runtime sheaf Laplacian detector.
    
    Called every ~5 second detection cycle with:
    - Current bigram sketches from BPF maps
    - Current container behavior bitfields from BPF maps
    - Recent connection events from telemetry ring buffer
    - Internal state: EMA buffers and signal history deques
    """
    
    def __init__(self, cal: SheafCalibrator):
        self.cal = cal
        self.ema_buffer = EMASignalBuffer(alpha=0.2, d=74)
        # Signal history for multi-lag detection: 3 windows per container
        self.signal_history: Dict[int, deque] = defaultdict(lambda: deque(maxlen=3))
        self.eigenmode_analyzer = None  # initialized after calibration
        
    def setup_eigenmode_analyzer(self):
        """
        Build sheaf Laplacian matrix and compute eigendecomposition.
        Called once after calibration data is loaded.
        
        The sheaf Laplacian L_F is a block matrix with blocks:
          (L_F)_{vv} = sum_{e: v◁e} F_{v◁e}^T @ F_{v◁e}
          (L_F)_{uv} = -F_{u◁e}^T @ F_{v◁e}  if e=(u,v) in E
        
        For n containers with d-dimensional signals:
          L_F is (n*d) × (n*d) = (3*74) × (3*74) = 222 × 222
        """
        try:
            from eigenmode_analyzer import SheafEigenmodeAnalyzer
            # Build L_F from restriction maps (lag=0 only for eigendecomposition)
            L_F = self._build_laplacian()
            if L_F is not None:
                self.eigenmode_analyzer = SheafEigenmodeAnalyzer(L_F)
                print("Eigenmode analyzer initialized")
        except Exception as e:
            print(f"Warning: Could not initialize eigenmode analyzer: {e}")
    
    def _build_laplacian(self) -> Optional[np.ndarray]:
        """Build the sheaf Laplacian matrix from lag=0 restriction maps."""
        containers = sorted(set(
            cg for (u, v, lag) in self.cal.restriction_maps if lag == 0
            for cg in [u, v]
        ))
        n = len(containers)
        if n < 2:
            return None
        
        cg_to_idx = {cg: i for i, cg in enumerate(containers)}
        d = self.cal.d
        L_F = np.zeros((n * d, n * d), dtype=np.float64)
        
        for (u, v, lag), (F_u, F_v) in self.cal.restriction_maps.items():
            if lag != 0:
                continue
            i_u = cg_to_idx.get(u)
            i_v = cg_to_idx.get(v)
            if i_u is None or i_v is None:
                continue
            
            # Diagonal blocks: F_{v◁e}^T @ F_{v◁e}
            L_F[i_u*d:(i_u+1)*d, i_u*d:(i_u+1)*d] += F_u.T @ F_u
            L_F[i_v*d:(i_v+1)*d, i_v*d:(i_v+1)*d] += F_v.T @ F_v
            # Off-diagonal blocks: -F_{u◁e}^T @ F_{v◁e}
            L_F[i_u*d:(i_u+1)*d, i_v*d:(i_v+1)*d] -= F_u.T @ F_v
            L_F[i_v*d:(i_v+1)*d, i_u*d:(i_u+1)*d] -= F_v.T @ F_u
        
        return L_F
    
    def _compute_edge_energy(self, F_u: np.ndarray, x_u: np.ndarray,
                              F_v: np.ndarray, x_v: np.ndarray,
                              cov_inv: Optional[np.ndarray]) -> float:
        """Compute Mahalanobis edge energy: (F_u @ x_u - F_v @ x_v)^T Σ^-1 (...)"""
        diff = F_u @ x_u - F_v @ x_v   # (k,)
        if cov_inv is not None:
            return float(diff @ cov_inv @ diff)
        return float(np.dot(diff, diff))   # fallback to L2
    
    def detect_cycle(self,
                     current_sketches: Dict[int, BigramSketch],
                     current_behaviors: Dict[int, dict],
                     current_connections: List[dict]) -> Verdict:
        """
        Main detection cycle. Called every ~5 seconds.
        
        Parameters:
          current_sketches: {cg_id: BigramSketch} — read from bigram_sketch_map
          current_behaviors: {cg_id: dict} — read from container_behavior map
          current_connections: [{'src_cg', 'dst_cg', 'dst_port'}, ...] from telemetry_rb
        """
        
        # ── Stage 1: Novel-edge detection ─────────────────────────────
        # Check for connections on uncalibrated (src, dst, port) tuples.
        # These are flagged immediately — calibration defines what is "normal".
        novel_alerts = []
        for conn in current_connections:
            key = (conn['src_cg'], conn['dst_cg'], conn['dst_port'])
            if key not in self.cal.calibrated_edges:
                novel_alerts.append(NovelEdgeAlert(
                    src=conn['src_cg'],
                    dst=conn['dst_cg'],
                    port=conn['dst_port']
                ))
        
        # ── Stage 2: Signal extraction and whitening ───────────────────
        raw_signals: Dict[int, np.ndarray] = {}
        ema_signals: Dict[int, np.ndarray] = {}
        
        for cg_id, sketch in current_sketches.items():
            x_raw = extract_signal_74(sketch, self.cal.cal_stats)
            
            whitener = self.cal.whitener.get(cg_id)
            if whitener:
                x_white = whitener.transform(x_raw)
            else:
                x_white = x_raw  # uncalibrated container — use raw
            
            raw_signals[cg_id] = x_white
            ema_signals[cg_id] = self.ema_buffer.update(cg_id, x_white)
            self.signal_history[cg_id].append(x_white)
        
        # ── Stage 3: Sheaf Laplacian spectral test (dual path + multi-lag) ──
        edge_alerts = []
        total_raw_energy = 0.0
        total_ema_energy = 0.0
        
        calibrated_pairs = set((u, v) for (u, v, lag) in self.cal.restriction_maps)
        
        for (u, v) in calibrated_pairs:
            if u not in raw_signals or v not in raw_signals:
                continue
            
            x_u_raw = raw_signals[u]
            x_v_raw = raw_signals[v]
            x_u_ema = ema_signals[u]
            x_v_ema = ema_signals[v]
            
            # Multi-lag: try lags 0, 1, 2; take maximum energy
            max_raw_energy = 0.0
            max_ema_energy = 0.0
            best_lag = 0
            
            for lag in [0, 1, 2]:
                if (u, v, lag) not in self.cal.restriction_maps:
                    continue
                F_u, F_v = self.cal.restriction_maps[(u, v, lag)]
                cov_inv = self.cal.edge_cov_inv.get((u, v, lag))
                
                # Raw path: use current signals
                raw_e = self._compute_edge_energy(F_u, x_u_raw, F_v, x_v_raw, cov_inv)
                if raw_e > max_raw_energy:
                    max_raw_energy = raw_e
                    best_lag = lag
                
                # EMA path: for lag, use history if available
                if lag == 0:
                    ema_e = self._compute_edge_energy(F_u, x_u_ema, F_v, x_v_ema, cov_inv)
                    max_ema_energy = max(max_ema_energy, ema_e)
            
            total_raw_energy += max_raw_energy
            total_ema_energy += max_ema_energy
            
            # Per-edge threshold check (4-sigma on calibration residuals)
            tau_raw = max(
                self.cal.edge_thresholds.get((u, v, lag), float('inf'))
                for lag in [0, 1, 2]
            )
            tau_ema = self.cal.ema_edge_thresholds.get((u, v), tau_raw * 0.7)
            
            if max_raw_energy > tau_raw or max_ema_energy > tau_ema:
                edge_alerts.append(EdgeAnomaly(
                    src=u, dst=v, lag=best_lag,
                    energy=max_raw_energy, threshold=tau_raw,
                    ratio=max_raw_energy / max(tau_raw, 1e-10)
                ))
        
        # Global Rayleigh quotient (raw path)
        x_global = np.concatenate([
            raw_signals[cg] for cg in sorted(raw_signals.keys())
            if cg in raw_signals
        ]) if raw_signals else np.array([])
        
        x_norm_sq = float(np.dot(x_global, x_global)) if len(x_global) > 0 else 0.0
        rayleigh = total_raw_energy / max(x_norm_sq, 1e-10)
        
        # ── Stage 4: Eigenmode analysis ───────────────────────────────
        eigenmode_result = None
        if self.eigenmode_analyzer is not None and len(x_global) > 0:
            try:
                eigenmode_result = self.eigenmode_analyzer.analyze(x_global)
            except Exception:
                pass
        
        # ── Stage 5: Semantic label from behavior bits ─────────────────
        # COMPLETELY SEPARATE from sheaf math — reads behavior bitfields
        label = self._compute_semantic_label(current_behaviors, edge_alerts, rayleigh)
        
        # ── Stage 6: Verdict ───────────────────────────────────────────
        global_threshold = self.cal.global_threshold or float('inf')
        
        if novel_alerts or edge_alerts or rayleigh > global_threshold:
            affected = set()
            for a in novel_alerts:
                affected.update([a.src, a.dst])
            for a in edge_alerts:
                affected.update([a.src, a.dst])
            
            reason_parts = []
            if novel_alerts:
                reason_parts.append(f"{len(novel_alerts)} novel edge(s)")
            if edge_alerts:
                reason_parts.append(f"{len(edge_alerts)} anomalous edge(s)")
            if rayleigh > global_threshold:
                reason_parts.append(f"Rayleigh={rayleigh:.3f}>τ={global_threshold:.3f}")
            
            return Verdict(
                action=VERDICT_KILL,
                affected_cgroups=list(affected),
                rayleigh=rayleigh,
                global_threshold=global_threshold,
                edge_anomalies=edge_alerts,
                novel_edges=novel_alerts,
                label=label,
                eigenmodes=eigenmode_result,
                reason="; ".join(reason_parts)
            )
        
        return Verdict(action=VERDICT_ALLOW)
    
    def _compute_semantic_label(self, behaviors: Dict[int, dict],
                                 edge_alerts: List[EdgeAnomaly],
                                 rayleigh: float) -> AttackLabel:
        """
        Map invariant bit patterns to MITRE ATT&CK labels.
        
        READS FROM: container_behavior.flags (invariant bits from kernel)
        NOT FROM: sheaf signal vector (those are continuous, not discrete)
        
        Priority order: first matching rule wins.
        """
        # Collect all set bits across all containers in the potential attack chain
        chain_bits = set()
        for cg_id, beh in behaviors.items():
            flags = beh.get('flags', 0)
            for i in range(8):
                if flags & (1 << i):
                    chain_bits.add(i)
        
        # bit 6 = BIT_FD_REDIRECT, bit 1 = BIT_LATERAL_CONNECT
        if 6 in chain_bits and 1 in chain_bits:
            return AttackLabel("Reverse shell with lateral movement",
                               ["T1059.004", "T1021.004"], "CRITICAL")
        
        # bit 2 = BIT_SENSITIVE_FILE, bit 5 = BIT_LARGE_TRANSFER
        if 2 in chain_bits and 5 in chain_bits:
            return AttackLabel("Credential theft → data exfiltration",
                               ["T1003", "T1048"], "CRITICAL")
        
        # bit 3 = BIT_NS_PROBE, bit 4 = BIT_PRIVESC
        if 3 in chain_bits and 4 in chain_bits:
            return AttackLabel("Container escape attempt",
                               ["T1611"], "HIGH")
        
        # bit 7 = BIT_FORK_ACCEL
        if 7 in chain_bits:
            return AttackLabel("Fork bomb / resource exhaustion",
                               ["T1499.001"], "HIGH")
        
        # bit 0 = BIT_SHELL_SPAWN, bit 1 = BIT_LATERAL_CONNECT
        if 0 in chain_bits and 1 in chain_bits:
            return AttackLabel("Shell spawn with lateral connection",
                               ["T1059", "T1021"], "HIGH")
        
        # Sheaf anomaly without any invariant bits: unknown attack
        if edge_alerts or rayleigh > 0:
            return AttackLabel("Unknown anomalous inter-container coupling",
                               [], "MEDIUM")
        
        return AttackLabel("Normal", [], "NONE")
```

### 8.6 Sheaf Eigenmode Analyzer (eigenmode_analyzer.py)

Provides spectral fingerprinting — different attack types excite different eigenmodes of L_F. This is a bonus result for the paper showing the sheaf Laplacian classifies attacks, not just detects them.

```python
# eigenmode_analyzer.py
import numpy as np
from dataclasses import dataclass
from typing import List

@dataclass
class EigenmodeResult:
    total_energy: float
    dominant_modes: List[int]       # indices of top-5 modes by energy
    mode_energies: List[float]      # energy in each dominant mode
    energy_distribution: List[float] # fraction of total energy per mode

class SheafEigenmodeAnalyzer:
    """
    Computes spectral fingerprints from the sheaf Laplacian.
    
    One-time eigendecomposition after calibration.
    Runtime: one matrix-vector multiply per detection cycle (~0.1ms).
    
    Key insight: Different attack types excite different eigenmodes:
    - Reverse shell (Web only): energy in mode corresponding to Web deviation
    - Lateral movement (Web→API): energy spread across Web+API modes
    - Fork bomb: energy in mode corresponding to isolated container anomaly
    - Normal traffic: energy near-zero across all non-trivial modes
    
    This enables post-hoc attack type identification from spectral structure
    alone, without any trained classifier.
    """
    
    def __init__(self, L_F: np.ndarray):
        """
        L_F: the sheaf Laplacian matrix, shape (n*d, n*d)
        For 3 containers, d=74: L_F is 222×222
        
        eigh (not eig): L_F is real symmetric, so eigenvalues are real.
        More numerically stable than eig for symmetric matrices.
        """
        eigenvalues, eigenvectors = np.linalg.eigh(L_F)
        
        # Keep only non-trivial modes (eigenvalue > epsilon)
        # λ=0 modes correspond to global constant signals (trivial/uninformative)
        mask = eigenvalues > 1e-8
        self.eigenvalues = eigenvalues[mask]
        self.eigenvectors = eigenvectors[:, mask]   # columns are eigenvectors
        
        print(f"Eigenmode analyzer: {len(self.eigenvalues)} non-trivial modes "
              f"(of {len(eigenvalues)} total, "
              f"λ_max={self.eigenvalues[-1]:.3f})")
    
    def analyze(self, x_global: np.ndarray) -> EigenmodeResult:
        """
        Project anomalous global signal onto eigenmodes.
        
        x_global: concatenated whitened signal [x_Web; x_API; x_DB], shape (n*d,)
        
        The coefficient c_i = v_i^T @ x_global measures how much the signal
        is in the direction of eigenvector v_i. The energy in mode i is
        c_i^2 * λ_i (eigenvalue weights the contribution by mode importance).
        """
        # Project signal onto all eigenvectors simultaneously
        coeffs = self.eigenvectors.T @ x_global   # (num_modes,)
        mode_energies = coeffs**2 * self.eigenvalues   # energy per mode
        
        total = float(mode_energies.sum())
        top_k = min(5, len(mode_energies))
        top_idx = np.argsort(mode_energies)[::-1][:top_k].tolist()
        
        return EigenmodeResult(
            total_energy=total,
            dominant_modes=top_idx,
            mode_energies=[float(mode_energies[i]) for i in top_idx],
            energy_distribution=[float(mode_energies[i] / max(total, 1e-10))
                                  for i in top_idx]
        )
```

### 8.7 Main Daemon Loop (daemon_main.py)

The orchestrator that ties everything together.

```python
# daemon_main.py
"""
CausalTrace Tier 3 Sheaf Daemon — Main Loop

Runs every DETECTION_INTERVAL seconds.
Reads BPF maps, runs detection pipeline, writes verdicts.

Usage:
  sudo python3 daemon_main.py --mode monitor    # log only, no enforcement
  sudo python3 daemon_main.py --mode enforce    # write verdict_map
  sudo python3 daemon_main.py --calibrate       # run calibration phase
"""
import time, argparse, logging, json, ctypes
from collections import defaultdict, deque
from pathlib import Path

# BCC import — requires sudo and BCC installation
from bcc import BPF

# CausalTrace modules
from signal_extractor import BigramSketch, CalibrationStats
from calibrate import SheafCalibrator
from sheaf_detector import SheafDetector, VERDICT_KILL, VERDICT_ALLOW
from ema_buffer import EMASignalBuffer

DETECTION_INTERVAL = 5.0    # seconds between detection cycles
CALIBRATION_DIR = "/home/causaltrace/calibration"
STALENESS_TTL = 10.0        # seconds: drop data older than this (GIL death spiral prevention)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger("causaltrace")


class CausalTraceDaemon:
    def __init__(self, bpf_obj: BPF, mode: str = "monitor"):
        self.bpf = bpf_obj
        self.mode = mode   # "monitor" or "enforce"
        
        # BPF maps (accessed via BCC Python API)
        self.bigram_sketch_map = bpf_obj.get_table("bigram_sketch_map")
        self.container_behavior = bpf_obj.get_table("container_behavior")
        self.verdict_map = bpf_obj.get_table("verdict_map")
        
        # Calibration and detection
        self.cal = self._load_calibration()
        self.detector = SheafDetector(self.cal) if self.cal else None
        
        if self.detector:
            self.detector.setup_eigenmode_analyzer()
        
        # Connection event buffer (collected from telemetry ring buffer)
        self.recent_connections: deque = deque(maxlen=1000)
        
        # Results logging
        Path("results/causaltrace").mkdir(parents=True, exist_ok=True)
        self.results_log = open("results/causaltrace/verdicts.jsonl", 'a')
    
    def _load_calibration(self) -> SheafCalibrator:
        """Load calibration data from disk. Returns None if not calibrated."""
        cal_path = Path(CALIBRATION_DIR)
        if not (cal_path / "edge_thresholds.json").exists():
            log.warning("No calibration found. Run with --calibrate first.")
            return None
        
        import pickle
        cal = SheafCalibrator()
        
        with open(cal_path / "pca.pkl", 'rb') as f:
            cal.pca = pickle.load(f)
        with open(cal_path / "whiteners.pkl", 'rb') as f:
            cal.whitener = pickle.load(f)
        with open(cal_path / "edge_thresholds.json") as f:
            raw = json.load(f)
            cal.edge_thresholds = {eval(k): v for k, v in raw.items()}
        with open(cal_path / "global_threshold.json") as f:
            cal.global_threshold = json.load(f)['global']
        with open(cal_path / "calibrated_edges.json") as f:
            cal.calibrated_edges = set(tuple(e) for e in json.load(f))
        
        from signal_extractor import CalibrationStats
        cal.cal_stats = CalibrationStats(
            pca_components=cal.pca.components_,
            pca_mean=cal.pca.mean_
        )
        
        log.info(f"Calibration loaded: {len(cal.calibrated_edges)} edges, "
                 f"global_threshold={cal.global_threshold:.4f}")
        return cal
    
    def _read_bigram_sketches(self) -> dict:
        """Read all bigram sketches from BPF map."""
        sketches = {}
        for key, value in self.bigram_sketch_map.items():
            cg_id = key.value
            # Convert BPF struct to Python BigramSketch
            import numpy as np
            counters = np.array([[value.counters[r][c]
                                   for c in range(128)]
                                  for r in range(4)], dtype=np.uint32)
            sketches[cg_id] = BigramSketch(
                counters=counters,
                prev_idx=value.prev_idx,
                total_count=value.total_count,
                window_start=value.window_start
            )
        return sketches
    
    def _read_container_behaviors(self) -> dict:
        """Read all behavior bitfields from BPF map."""
        behaviors = {}
        for key, value in self.container_behavior.items():
            cg_id = key.value
            behaviors[cg_id] = {
                'flags': value.flags,
                'bit_ts': [value.bit_ts[i] for i in range(8)],
                'conn_dst_cg': value.conn_dst_cg,
                'conn_port': value.conn_port
            }
        return behaviors
    
    def _write_verdict(self, cgroup_id: int, verdict: int):
        """Write verdict to BPF verdict_map (kernel reads this on next syscall)."""
        key = ctypes.c_uint64(cgroup_id)
        val = ctypes.c_uint32(verdict)
        self.verdict_map[key] = val
    
    def _setup_telemetry_callback(self):
        """Register callback for telemetry ring buffer (connection events)."""
        def handle_connection(ctx, data, size):
            import ctypes
            class AlertT(ctypes.Structure):
                _fields_ = [
                    ('type', ctypes.c_uint32),
                    ('pid', ctypes.c_uint32),
                    ('cgroup_id', ctypes.c_uint64),
                    ('timestamp', ctypes.c_uint64),
                    ('flags', ctypes.c_uint64),
                    ('extra', ctypes.c_uint64),
                ]
            event = ctypes.cast(data, ctypes.POINTER(AlertT)).contents
            if event.type == 100:  # EVENT_CONNECTION
                self.recent_connections.append({
                    'src_cg': event.cgroup_id,
                    'dst_cg': event.flags,           # flags field reused for dst_cg
                    'dst_port': event.extra & 0xFFFF, # lower 32 bits of extra
                    'timestamp': event.timestamp
                })
        
        self.bpf["telemetry_rb"].open_ring_buffer(handle_connection)
    
    def run_detection_cycle(self):
        """Single detection cycle."""
        cycle_start = time.monotonic()
        
        # Poll ring buffer for new connection events
        self.bpf.ring_buffer_poll(timeout=100)
        
        # Staleness check: if we're behind, drop stale data and resync
        now_ns = time.time_ns()
        fresh_connections = [
            c for c in self.recent_connections
            if (now_ns - c['timestamp']) / 1e9 < STALENESS_TTL
        ]
        
        if len(fresh_connections) < len(self.recent_connections):
            dropped = len(self.recent_connections) - len(fresh_connections)
            if dropped > 10:
                log.warning(f"Dropped {dropped} stale connection events (daemon behind)")
        
        # Read current BPF state
        sketches = self._read_bigram_sketches()
        behaviors = self._read_container_behaviors()
        
        if not sketches:
            return  # No container data yet
        
        if self.detector is None:
            log.debug("No calibration loaded — running in observation mode only")
            return
        
        # Run sheaf detection pipeline
        verdict = self.detector.detect_cycle(
            current_sketches=sketches,
            current_behaviors=behaviors,
            current_connections=list(fresh_connections)
        )
        
        # Clear processed connections
        self.recent_connections.clear()
        
        # Log result
        log_entry = {
            'timestamp': time.time(),
            'action': 'KILL' if verdict.action == VERDICT_KILL else 'ALLOW',
            'rayleigh': verdict.rayleigh,
            'global_threshold': verdict.global_threshold,
            'edge_anomalies': len(verdict.edge_anomalies),
            'novel_edges': len(verdict.novel_edges),
            'label': verdict.label.name if verdict.label else None,
            'mitre': verdict.label.mitre_ids if verdict.label else [],
            'severity': verdict.label.severity if verdict.label else 'NONE',
            'reason': verdict.reason
        }
        
        if verdict.action == VERDICT_KILL:
            log.warning(f"ATTACK DETECTED: {verdict.label.name if verdict.label else 'Unknown'} | "
                       f"Containers: {verdict.affected_cgroups} | "
                       f"Rayleigh: {verdict.rayleigh:.3f} | "
                       f"Reason: {verdict.reason}")
            
            if self.mode == "enforce":
                for cg_id in verdict.affected_cgroups:
                    self._write_verdict(cg_id, VERDICT_KILL)
                    log.info(f"  verdict_map[{cg_id}] = KILL")
        
        self.results_log.write(json.dumps(log_entry) + '\n')
        self.results_log.flush()
        
        # Timing check
        elapsed = time.monotonic() - cycle_start
        if elapsed > DETECTION_INTERVAL:
            log.warning(f"Detection cycle took {elapsed:.2f}s (>{DETECTION_INTERVAL}s) — "
                       f"consider reducing container count or using multiprocessing")
    
    def run(self):
        """Main loop."""
        log.info(f"CausalTrace Tier 3 running in {self.mode} mode")
        log.info(f"Detection interval: {DETECTION_INTERVAL}s")
        
        self._setup_telemetry_callback()
        
        while True:
            cycle_start = time.monotonic()
            try:
                self.run_detection_cycle()
            except KeyboardInterrupt:
                log.info("Shutting down...")
                break
            except Exception as e:
                log.error(f"Detection cycle error: {e}", exc_info=True)
            
            # Sleep for remainder of interval
            elapsed = time.monotonic() - cycle_start
            sleep_time = max(0, DETECTION_INTERVAL - elapsed)
            time.sleep(sleep_time)
```

---

## 9. INFRASTRUCTURE: BCC LOADER AND DOCKER EVENT LISTENER

### 9.1 BCC Loader (loader.py)

The loader is responsible for:
1. Compiling all BPF C programs using BCC
2. Attaching them to the correct hook points
3. Setting up the tail-call dispatch table
4. Populating the `host_ns` map with the current host namespace inode
5. Starting the Tier 3 daemon

```python
# loader.py
"""
CausalTrace BCC Loader
Compiles and loads all eBPF programs, sets up maps, starts daemon.
Must run as root (sudo).

Usage:
  sudo python3 loader.py --mode monitor    # observe only
  sudo python3 loader.py --mode enforce    # kill on detection
  sudo python3 loader.py --calibrate       # calibration mode
"""
import os, sys, ctypes, argparse, subprocess, time, threading
from pathlib import Path
from bcc import BPF

# ─── BPF Source Files ─────────────────────────────────────────────────
# Loaded in dependency order: common header first, then maps, then programs
TIER1_DIR = Path("tier1")
TIER2_DIR = Path("tier2")

# ─── Syscall numbers that get tail-call handlers ───────────────────────
# Maps syscall_nr → handler name in prog_array
TAIL_CALL_MAP = {
    56:  "handle_fork",     # clone
    435: "handle_fork",     # clone3
    59:  "handle_execve",   # execve
    257: "handle_file",     # openat
    105: "handle_privesc",  # setuid
    308: "handle_privesc",  # setns
    272: "handle_privesc",  # unshare
    101: "handle_privesc",  # ptrace
    33:  "handle_dup2",     # dup2
    292: "handle_dup2",     # dup3
}


def get_host_mount_ns_inum() -> int:
    """Read the host mount namespace inode number from /proc/self/ns/mnt."""
    ns_path = "/proc/self/ns/mnt"
    stat = os.stat(ns_path)
    return stat.st_ino


def load_bpf_programs() -> BPF:
    """
    Compile and load all BPF programs using BCC.
    Returns the BPF object with all programs attached.
    """
    # Concatenate all source files in order
    # BCC compiles a single C file; we include headers via include paths
    bpf_sources = []
    
    for src_file in [
        TIER1_DIR / "dispatcher.bpf.c",
        TIER1_DIR / "handler_fork.bpf.c",
        TIER1_DIR / "handler_execve.bpf.c",
        TIER1_DIR / "handler_file.bpf.c",
        TIER1_DIR / "handler_privesc.bpf.c",
        TIER1_DIR / "handler_dup2.bpf.c",
    ]:
        bpf_sources.append(src_file.read_text())
    
    # BCC compiles the combined source
    # Include path for headers
    cflags = [f"-I{TIER1_DIR}"]
    
    print("Compiling eBPF programs...")
    b = BPF(text="\n".join(bpf_sources), cflags=cflags)
    print("  ✓ Compilation successful")
    
    return b


def setup_tail_calls(b: BPF):
    """
    Attach handler programs to the prog_array for tail-call dispatch.
    The dispatcher uses bpf_tail_call(ctx, &prog_array, syscall_nr)
    to call the correct handler.
    """
    prog_array = b.get_table("prog_array")
    
    for syscall_nr, handler_name in TAIL_CALL_MAP.items():
        try:
            prog_fd = b[handler_name].fd
            prog_array[ctypes.c_uint32(syscall_nr)] = ctypes.c_int(prog_fd)
            print(f"  ✓ syscall {syscall_nr:3d} → {handler_name}")
        except Exception as e:
            print(f"  ✗ Failed to attach handler for syscall {syscall_nr}: {e}")


def attach_probes(b: BPF):
    """Attach Probe B (network tracker) and Probe C (process lineage)."""
    
    # Probe B: TCP connection tracker
    # Entry probe: stash sock pointer
    b.attach_kprobe(
        event="tcp_v4_connect",
        fn_name="trace_connect_entry"
    )
    # Return probe: connection established, read socket fields
    b.attach_kretprobe(
        event="tcp_v4_connect",
        fn_name="trace_connect_return"
    )
    print("  ✓ Probe B: tcp_v4_connect kprobe/kretprobe attached")
    
    # Probe C: Process exec tracker
    b.attach_tracepoint(
        tp="sched:sched_process_exec",
        fn_name="trace_exec"
    )
    print("  ✓ Probe C: sched_process_exec tracepoint attached")


def populate_host_ns(b: BPF):
    """Write host mount namespace inode to host_ns BPF array."""
    host_ns_inum = get_host_mount_ns_inum()
    host_ns_map = b.get_table("host_ns")
    host_ns_map[ctypes.c_uint32(0)] = ctypes.c_uint32(host_ns_inum)
    print(f"  ✓ Host NS inode: {host_ns_inum}")


def setup_alerts_callback(b: BPF):
    """Setup callback for high-priority alerts ring buffer."""
    def handle_alert(ctx, data, size):
        import ctypes
        class AlertT(ctypes.Structure):
            _fields_ = [
                ('type', ctypes.c_uint32),
                ('pid', ctypes.c_uint32),
                ('cgroup_id', ctypes.c_uint64),
                ('timestamp', ctypes.c_uint64),
                ('flags', ctypes.c_uint64),
                ('extra', ctypes.c_uint64),
            ]
        evt = ctypes.cast(data, ctypes.POINTER(AlertT)).contents
        
        ALERT_NAMES = {
            1: "FORK_BOMB", 2: "REVERSE_SHELL", 3: "SENSITIVE_FILE",
            4: "PRIVESC", 5: "FD_REDIRECT", 6: "FORK_ACCEL",
            7: "TWO_HOP", 8: "NS_ESCAPE"
        }
        name = ALERT_NAMES.get(evt.type, f"UNKNOWN({evt.type})")
        ts_ms = evt.timestamp / 1e6
        print(f"[ALERT] {name} | cgroup={evt.cgroup_id} | pid={evt.pid} | "
              f"ts={ts_ms:.3f}ms | flags=0x{evt.flags:016x}")
    
    b["alerts_rb"].open_ring_buffer(handle_alert)


def main():
    parser = argparse.ArgumentParser(description="CausalTrace Loader")
    parser.add_argument("--mode", choices=["monitor", "enforce"],
                        default="monitor", help="Enforcement mode")
    parser.add_argument("--calibrate", action="store_true",
                        help="Run in calibration mode (Tier 3 collects data, no enforcement)")
    args = parser.parse_args()
    
    if os.geteuid() != 0:
        print("ERROR: Must run as root (sudo)")
        sys.exit(1)
    
    print("="*60)
    print("  CausalTrace — eBPF Loader")
    print("="*60)
    
    # Load and compile all BPF programs
    b = load_bpf_programs()
    
    print("\nSetting up BPF infrastructure...")
    populate_host_ns(b)
    setup_tail_calls(b)
    attach_probes(b)
    setup_alerts_callback(b)
    
    print(f"\nMode: {args.mode.upper()}")
    print("Monitoring container syscalls... (Ctrl+C to stop)\n")
    
    # Start Docker event listener in background thread
    from infra.docker_event_listener import DockerEventListener
    listener = DockerEventListener(b)
    listener_thread = threading.Thread(target=listener.run, daemon=True)
    listener_thread.start()
    
    # Main loop: poll ring buffers + run detection
    if args.calibrate:
        # Calibration mode: collect data, write to disk
        from tier3.calibrate_runner import run_calibration
        run_calibration(b)
    else:
        # Detection mode: run sheaf daemon
        from tier3.daemon_main import CausalTraceDaemon
        daemon = CausalTraceDaemon(b, mode=args.mode)
        
        while True:
            try:
                b.ring_buffer_poll(timeout=100)  # poll all ring buffers
                daemon.run_detection_cycle()
                time.sleep(4.9)  # roughly 5s cycles
            except KeyboardInterrupt:
                print("\nShutting down CausalTrace...")
                break


if __name__ == "__main__":
    main()
```

### 9.2 Docker Event Listener (docker_event_listener.py)

Maintains the `ip_to_cgroup` BPF map as containers start/stop. Also pre-populates `bigram_sketch_map` with zeroed entries to avoid the cold-path stack overflow problem.

```python
# infra/docker_event_listener.py
"""
Docker Event Listener
Maintains ip_to_cgroup BPF map as containers start and stop.
Also pre-populates bigram_sketch_map with zeroed entries.

CRITICAL: The bigram CMS struct is 2072 bytes. Pre-populating from userspace
avoids the need to stack-allocate this struct in the BPF cold path
(which would exceed the 512-byte stack limit and get rejected by the verifier).

Runs as a daemon thread inside the loader process.
"""
import docker, subprocess, ctypes, json, time, logging
from pathlib import Path

log = logging.getLogger("causaltrace.docker")


class DockerEventListener:
    def __init__(self, bpf_obj):
        self.bpf = bpf_obj
        self.docker_client = docker.from_env()
        self.ip_to_cgroup = bpf_obj.get_table("ip_to_cgroup")
        self.bigram_sketch_map = bpf_obj.get_table("bigram_sketch_map")
        self.known_containers = {}  # container_id → {ip, cgroup_id}
    
    def get_container_cgroup_id(self, container_id: str) -> int:
        """
        Get the cgroup_id for a running container.
        Method: inspect the container's init PID and read its cgroup id
        via /proc/<pid>/cgroup, then resolve via bpf_get_current_cgroup_id
        semantics (uses cgroupv2 inode number).
        """
        try:
            inspect = self.docker_client.api.inspect_container(container_id)
            pid = inspect['State']['Pid']
            if pid == 0:
                return None
            
            # Read cgroup id from /proc/<pid>/cgroup
            # For cgroupv2: single hierarchy, path in /sys/fs/cgroup
            cgroup_path_file = f"/proc/{pid}/cgroup"
            with open(cgroup_path_file) as f:
                for line in f:
                    parts = line.strip().split(':')
                    if len(parts) >= 3 and parts[0] == '0':  # cgroupv2
                        cgroup_rel = parts[2].lstrip('/')
                        full_path = f"/sys/fs/cgroup/{cgroup_rel}"
                        # Get inode number (this is what bpf_get_current_cgroup_id returns)
                        stat = Path(full_path).stat()
                        return stat.st_ino
            return None
        except Exception as e:
            log.error(f"Failed to get cgroup_id for {container_id}: {e}")
            return None
    
    def get_container_ip(self, container_id: str) -> str:
        """Get the bridge network IP address of a container."""
        try:
            inspect = self.docker_client.api.inspect_container(container_id)
            networks = inspect['NetworkSettings']['Networks']
            for net_name, net_info in networks.items():
                ip = net_info.get('IPAddress', '')
                if ip:
                    return ip
            return None
        except Exception as e:
            log.error(f"Failed to get IP for {container_id}: {e}")
            return None
    
    def ip_to_int(self, ip_str: str) -> int:
        """Convert 'a.b.c.d' to 32-bit integer in network byte order."""
        parts = ip_str.split('.')
        val = (int(parts[0]) << 24 | int(parts[1]) << 16 |
               int(parts[2]) << 8 | int(parts[3]))
        # Network byte order (big-endian): swap bytes
        return (((val & 0xFF) << 24) | (((val >> 8) & 0xFF) << 16) |
                (((val >> 16) & 0xFF) << 8) | ((val >> 24) & 0xFF))
    
    def register_container(self, container_id: str):
        """Register a new container: update ip_to_cgroup + pre-populate bigram map."""
        ip = self.get_container_ip(container_id)
        cgroup_id = self.get_container_cgroup_id(container_id)
        
        if not ip or not cgroup_id:
            log.warning(f"Could not register container {container_id[:12]}: "
                       f"ip={ip}, cgroup_id={cgroup_id}")
            return
        
        # Update ip_to_cgroup map: ip_int → cgroup_id
        ip_int = self.ip_to_int(ip)
        self.ip_to_cgroup[ctypes.c_uint32(ip_int)] = ctypes.c_uint64(cgroup_id)
        
        # Pre-populate bigram_sketch_map with zeroed entry for this cgroup
        # This avoids the cold-path stack overflow in the dispatcher
        # The BPF struct must match struct bigram_sketch in causaltrace_common.h exactly
        # Using BCC's Python API to create a zeroed entry
        try:
            # Create a zeroed entry by accessing the map (BCC creates zero-value entry)
            leaf = self.bigram_sketch_map.Leaf()  # zero-initialized struct
            self.bigram_sketch_map[ctypes.c_uint64(cgroup_id)] = leaf
        except Exception as e:
            log.error(f"Failed to pre-populate bigram map for cgroup {cgroup_id}: {e}")
        
        self.known_containers[container_id] = {
            'ip': ip,
            'cgroup_id': cgroup_id,
            'ip_int': ip_int
        }
        
        log.info(f"Registered container {container_id[:12]}: "
                f"ip={ip}, cgroup_id={cgroup_id}")
    
    def unregister_container(self, container_id: str):
        """Remove a stopped container's entries from BPF maps."""
        info = self.known_containers.pop(container_id, None)
        if not info:
            return
        
        try:
            del self.ip_to_cgroup[ctypes.c_uint32(info['ip_int'])]
        except Exception:
            pass
        
        try:
            del self.bigram_sketch_map[ctypes.c_uint64(info['cgroup_id'])]
        except Exception:
            pass
        
        log.info(f"Unregistered container {container_id[:12]}")
    
    def register_existing_containers(self):
        """Register all currently running containers at startup."""
        containers = self.docker_client.containers.list()
        for container in containers:
            self.register_container(container.id)
    
    def run(self):
        """Main event loop. Subscribe to Docker events and keep maps up to date."""
        log.info("Docker event listener starting...")
        self.register_existing_containers()
        
        # Subscribe to container start/stop events
        event_filters = {"type": "container", "event": ["start", "die", "stop"]}
        
        try:
            for event in self.docker_client.events(filters=event_filters, decode=True):
                event_type = event.get('Action', '')
                container_id = event.get('id', '')
                
                if event_type == 'start':
                    time.sleep(0.5)  # Wait for container to initialize PID/network
                    self.register_container(container_id)
                elif event_type in ('die', 'stop'):
                    self.unregister_container(container_id)
        except Exception as e:
            log.error(f"Docker event listener error: {e}")
```

---

## 10. TESTBED AND ATTACK SCENARIOS

### 10.1 Three-Container Topology

```
ct-web  (172.20.0.10) — nginx:latest + python3 + netcat (Dockerfile)
  ↕ TCP port 8080 (HTTP proxy via NGINX proxy_pass)
ct-api  (172.20.0.20) — python:3.12-slim + netcat (Dockerfile)  
  ↕ TCP port 5432 (PostgreSQL startup packet)
ct-db   (172.20.0.30) — postgres:16 + netcat (Dockerfile)
```

**IPv6:** Disabled on the Docker bridge (`enable_ipv6: false`). This prevents the IPv6 lateral bypass (Probe B only hooks `tcp_v4_connect`).

**Security options on all containers:**
- `seccomp:unconfined`: Required so that the eBPF monitoring doesn't interfere with container syscalls
- `CAP_SYS_PTRACE`: Allows `/proc` access for namespace probe scenarios
- `CAP_NET_ADMIN`: Allows network configuration inspection
- `CAP_SYS_ADMIN`: Allows `unshare`/`nsenter` for escape scenarios (eBPF detection fires regardless of whether the attack would succeed)

### 10.2 Calibration Traffic Pattern

Run `scripts/generate_normal_traffic.sh` for 30-60 minutes before enforcement. The script generates:

**Pattern 1 — Web→API:** `curl localhost:8080/api/health` goes through NGINX `proxy_pass`, generating a `tcp_v4_connect(172.20.0.20, 8080)` from the Web container. This is what Probe B records as a calibrated edge.

**Pattern 2 — API→DB:** `curl localhost:8080/api/db/query` causes the API server to call `socket.connect(172.20.0.30, 5432)`. Probe B records this as the API→DB calibrated edge.

**Pattern 3 — Bursts:** Every 30 seconds, 5 concurrent requests simulate realistic traffic spikes. CCA must learn that bursts are normal.

**What NOT to do:** Don't generate direct API connections via `curl localhost:8081/...` during calibration — these bypass NGINX (go host→API directly) and don't create Web→API edges. They are fine for health checks but not for calibration coverage.

### 10.3 Seven Attack Scenarios

| # | Scenario | Detection Layer | What Fires |
|---|----------|----------------|-----------|
| 1 | Normal (60s HTTP traffic) | None | Nothing — verifies zero FP |
| 2 | Reverse shell — Method A: bash | Tier 1 execve handler + dup2 invariant | ALERT_REVERSE_SHELL + ALERT_FD_REDIRECT |
| 2 | Reverse shell — Method B: python | **Tier 1 dup2 invariant ONLY** | ALERT_FD_REDIRECT (key test: only invariant catches python) |
| 3 | Sensitive file `/etc/shadow` | Tier 1 file handler | ALERT_SENSITIVE_FILE |
| 4 | Fork bomb | Tier 1 fork acceleration | ALERT_FORK_ACCEL |
| 5 | Namespace probe + nsenter | Tier 1 file handler + privesc | ALERT_SENSITIVE_FILE + ALERT_NS_ESCAPE |
| 6 | `unshare --user --mount` + `setuid(0)` | Tier 1 privesc | ALERT_PRIVESC |
| 7 | **Cross-container lateral movement** | **Tier 2 two-hop + Tier 3 novel-edge + sheaf** | **The unique CausalTrace detection** |

**Scenario 7 Walkthrough (the key differentiator):**
1. Attacker spawns shell in Web container → bit0 (BIT_SHELL_SPAWN) set, bit_ts[0] = now
2. Attacker connects from Web to API on port 9999 (uncalibrated) → Probe B fires
3. Probe B two-hop check: `(now - bit_ts[0]) < 5s AND (flags & BIT_SHELL_SPAWN)` → SIGKILL + ALERT_TWO_HOP
4. Simultaneously (or if two-hop missed): Tier 3 novel-edge detector sees `(Web, API, 9999)` not in calibrated_edges → HIGH alert
5. Next detection cycle: Web's bigram signal shows shell-like patterns → sheaf edge energy spikes → verdict_map written
6. Semantic label: bit0 + bit1 → "Shell spawn with lateral connection" → T1059 → T1021

---

## 11. EVALUATION PLAN

### 11.1 Six Experiments

**E1: Detection Accuracy**
- Run each of 7 scenarios × 10 repetitions
- Record: TP, FP, TN, FN per scenario
- Compute: Precision = TP/(TP+FP), Recall = TP/(TP+FN), F1, FPR
- Target: 7/7 scenarios, F1 ≥ 0.95, FPR ≤ 0.03

**E2: Enforcement Latency**
- Instrument with `bpf_ktime_get_ns()` at syscall entry and SIGKILL delivery
- Report: per-scenario latency (μs) with mean, min, max
- Target: Tier 1 < 5μs, Tier 3 < 2s

**E3: CPU Overhead**
- Run `redis-benchmark -n 100000 -c 50` with/without CausalTrace
- Measure: throughput (ops/sec), latency p50/p99
- Target: < 5% throughput reduction

**E4: Memory Footprint**
- `sudo bpftool map show` → sum of all BPF map sizes
- `/proc/<daemon_pid>/status` → VmRSS (daemon RSS)
- Target: total < 100MB

**E5: Sheaf Sensitivity (Scenario 7 Focus)**
- Vary: attack intensity (data volume, connection frequency)
- Measure: Rayleigh quotient value and EMA energy at each intensity
- Plot: ROC curve for sheaf detection
- Target: AUC > 0.95, clear separation between normal and attack distributions

**E6: False Positive Rate**
- Run 1 hour of normal workload with all detection layers active
- Count: alerts per layer per hour
- Target: < 1 false alert per hour total

**Bonus E7: Eigenmode Fingerprinting**
- Run each of 7 scenarios, record eigenmode energy distribution
- Plot: fraction of L_F energy per mode, per scenario as a bar chart
- Expected result: distinct fingerprints per attack type

### 11.2 Comparison Table (Expected)

| Metric | Baseline A | Baseline B | CausalTrace |
|--------|-----------|-----------|-------------|
| Scenarios detected | 1/7 | 5/7 | **7/7** |
| Cross-container | No | No | **Yes** |
| Temporal ordering | No | N/A | **Bigram CMS** |
| Enforcement latency | N/A | 0.3–2.5 μs | **0.3–2.5 μs (T1) / <2s (T3)** |
| CPU overhead | 3–6% | 1–3% | **3–5%** |
| Memory | ~1MB | ~2MB | **~50MB daemon + 915KB maps** |
| GPU required | No | No | **No** |
| External training data | No | No | **No** |
| Model size | N/A | N/A | **~50KB restriction maps** |

---

## 12. FILE MANIFEST AND IMPLEMENTATION ORDER

### 12.1 Complete File Structure

```
~/causaltrace/
├── activate.sh                          # environment activation
├── docker-compose.yml                   # 3-container testbed
│
├── kernel/                              # All BPF C code
│   ├── causaltrace_common.h             # Shared constants, structs, helpers
│   ├── causaltrace_maps.h               # BPF map declarations
│   ├── dispatcher.bpf.c                 # Main entry: every container syscall
│   ├── handler_fork.bpf.c               # Fork acceleration invariant
│   ├── handler_execve.bpf.c             # Shell binary name matching
│   ├── handler_file.bpf.c               # Sensitive file path matching
│   ├── handler_privesc.bpf.c            # setuid/unshare/setns/ptrace
│   ├── handler_dup2.bpf.c               # fd-type invariant (THE KEY ONE)
│   ├── probe_b_network.bpf.c            # tcp_v4_connect tracker
│   └── probe_c_lineage.bpf.c            # sched_process_exec tracker
│
├── infra/
│   └── docker_event_listener.py         # Maintains ip_to_cgroup + bigram pre-pop
│
├── tier3/
│   ├── signal_extractor.py              # BigramSketch → 74-dim signal
│   ├── whitener.py                      # FeatureWhitener
│   ├── ema_buffer.py                    # EMASignalBuffer (α=0.2)
│   ├── calibrate.py                     # SheafCalibrator (PCA+CCA+thresholds)
│   ├── sheaf_detector.py                # SheafDetector (runtime detection)
│   ├── eigenmode_analyzer.py            # SheafEigenmodeAnalyzer
│   └── daemon_main.py                   # CausalTraceDaemon (main loop)
│
├── loader.py                            # BCC loader (entry point, run as sudo)
│
├── testbed/
│   ├── web/
│   │   ├── Dockerfile                   # nginx + python3 + netcat
│   │   ├── nginx.conf                   # proxy_pass /api/ → 172.20.0.20:8080
│   │   └── html/index.html
│   ├── api/
│   │   ├── Dockerfile                   # python:3.12-slim + netcat
│   │   └── server.py                    # HTTP server on :8080
│   └── db/
│       ├── Dockerfile                   # postgres:16 + netcat
│       └── init.sql                     # test schema with sensitive data
│
├── attacks/
│   ├── scenario_1_normal.sh
│   ├── scenario_2_reverse_shell.sh
│   ├── scenario_3_sensitive_file.sh
│   ├── scenario_4_fork_bomb.sh
│   ├── scenario_5_ns_escape.sh
│   ├── scenario_6_privesc.sh
│   ├── scenario_7_cross_container.sh    # THE key scenario
│   └── run_all.sh
│
├── scripts/
│   ├── generate_normal_traffic.sh       # 30-60min calibration traffic
│   └── test_connectivity.sh             # verify testbed before experiments
│
├── calibration/
│   ├── pca.pkl                          # PCA model (625→50)
│   ├── whiteners.pkl                    # per-container whiteners
│   ├── restriction_maps.npz             # F_u, F_v per (edge, lag)
│   ├── edge_thresholds.json             # 4-sigma per-edge thresholds
│   ├── global_threshold.json            # 4-sigma global Rayleigh threshold
│   └── calibrated_edges.json            # set of (src_cg, dst_cg, port)
│
├── results/
│   ├── baseline-a/
│   ├── baseline-b/
│   └── causaltrace/
│       └── verdicts.jsonl               # detection log (JSON lines)
│
└── baselines/
    ├── bertinatto_bosc.py               # Baseline A (already built)
    └── patrol_kernelnative.py           # Baseline B (already built)
```

### 12.2 Implementation Order (Saturday–Sunday)

**Saturday Morning (4h) — Kernel Code:**
1. `causaltrace_common.h` — all constants, structs, `syscall_to_idx()`, `is_noise_syscall()`
2. `causaltrace_maps.h` — all map declarations (copy exactly from Section 6.2)
3. `dispatcher.bpf.c` — core dispatcher with all v5 fixes
4. `handler_dup2.bpf.c` — fd-type invariant (highest priority — enables python reverse shell detection)
5. `handler_fork.bpf.c` — acceleration invariant
6. `handler_execve.bpf.c`, `handler_file.bpf.c`, `handler_privesc.bpf.c` — from Baseline B
7. **Test:** Load dispatcher, verify bigram CMS updates under normal traffic

**Saturday Afternoon (3h) — Infrastructure + Calibration:**
8. `probe_b_network.bpf.c` — LRU stash, split telemetry RB, per-bit timestamps
9. `probe_c_lineage.bpf.c` — exec tracepoint
10. `infra/docker_event_listener.py` — ip_to_cgroup + bigram pre-population
11. `loader.py` — BCC loader tying everything together
12. **Test:** `sudo python3 loader.py --mode monitor` with normal traffic, verify alerts fire

**Sunday Morning (3h) — Tier 3 Detection:**
13. `signal_extractor.py` — `extract_signal_74()` and CMS reconstruction
14. `whitener.py` — `FeatureWhitener`
15. `ema_buffer.py` — `EMASignalBuffer`
16. `calibrate.py` — `SheafCalibrator`
17. **Run calibration:** `bash scripts/generate_normal_traffic.sh 1800` (30 min)
18. `sheaf_detector.py` — `SheafDetector` (novel-edge + dual-path + multi-lag + Mahalanobis)
19. `eigenmode_analyzer.py` — `SheafEigenmodeAnalyzer`
20. `daemon_main.py` — main loop with staleness TTL

**Sunday Afternoon (2h) — Evaluation:**
21. Run `bash attacks/run_all.sh` with CausalTrace in enforce mode
22. Collect metrics for E1–E6 + bonus E7
23. Generate comparison tables

---

## 13. MATHEMATICAL REFERENCE

### 13.1 Cellular Sheaf on Container Graph

Let G = (V, E) be the container communication graph.
- V = {Web, API, DB} (vertices = containers)
- E = {(Web,API), (API,DB)} (edges = TCP communication channels)

A cellular sheaf F on G assigns:
- F(v) = ℝ^74 to each vertex v (container behavioral signal space)
- F(e) = ℝ^50 to each edge e (shared coupling space, k=50 CCA components)
- Restriction maps F_{v◁e}: ℝ^74 → ℝ^50 for each vertex-edge incidence

### 13.2 Sheaf Laplacian

The sheaf Laplacian L_F is the (n·d) × (n·d) block matrix:

```
(L_F)_{vv} = Σ_{e: v◁e} F_{v◁e}^T F_{v◁e}    (diagonal blocks)
(L_F)_{uv} = −F_{u◁e}^T F_{v◁e}               (off-diagonal, if e=(u,v)∈E)
```

For the global signal x = (x_Web, x_API, x_DB) ∈ ℝ^{222}:
```
x^T L_F x = Σ_{e=(u,v)∈E} ‖F_{u◁e}·x_u − F_{v◁e}·x_v‖²
```

This quadratic form measures **total inter-container behavioral inconsistency**.

### 13.3 Anomaly Detection Criterion

**Rayleigh quotient:** E(x) = x^T L_F x / ‖x‖²

E(x) > τ = μ_cal + 4σ_cal implies inter-container behavioral inconsistency.

**Mahalanobis edge energy:** For edge e=(u,v) at lag ℓ:
D_M^2(e,ℓ) = d(t)^T Σ_e^{-1} d(t)
where d(t) = F_u^ℓ · x_u(t) − F_v^ℓ · x_v(t-ℓ) and Σ_e is the covariance of normal residuals.

**Dual-path detection:**
- Fire if D_M^2(e, ℓ*) > τ_e^raw for any lag ℓ* (catches sudden attacks)
- Fire if D_M^2_EMA(e) > τ_e^ema (catches slow-drip attacks)

### 13.4 Key Propositions

**Proposition 1 (Temporal Ordering):** 
Bigram signals distinguish sequences with identical syscall multisets:
∀σ, σ': if syscall_multiset(σ) = syscall_multiset(σ') and ∃(a,b): count(a→b|σ) ≠ count(a→b|σ'), then x_v(σ) ≠ x_v(σ').

**Proposition 2 (Invariant Unevadability):**
For attack class A with physical invariant I(A): ∀ execution traces t ∈ A: I(A) fires on t. The attacker cannot execute A without triggering I(A) regardless of language, binary name, or evasion technique.

**Proposition 3 (Bigram Obfuscation Closure):**
Let S_noise = {getpid, getuid, gettid, getppid, time, clock_gettime}. Any obfuscation using S_noise is transparent to the bigram CMS (prev_idx unchanged). Any obfuscation using S\S_noise inflates non-trivial bigram frequencies, detectable by the sheaf Laplacian. Therefore, bigram obfuscation at the signal level results in detection at either the pattern level or the distribution level.

### 13.5 Computational Complexity Per Detection Cycle

| Operation | Complexity | For n=3, d=74, k=50, m=2, lags=3 |
|-----------|-----------|----------------------------------|
| Signal extraction | O(n·MAX_BIGRAMS) | ~1,875 ops |
| PCA projection | O(n·k·MAX_BIGRAMS) | ~93,750 ops |
| Per-edge energy (3 lags) | O(3·m·k·d) | ~22,200 ops |
| Mahalanobis (k×k matrix-vector) | O(3·m·k²) | ~15,000 ops |
| EMA update | O(n·d) | ~222 ops |
| Eigenmode projection | O((n·d)²) | ~49,284 ops |
| **Total per cycle** | — | **~182,000 ops ≈ <1ms** |

---

## APPENDIX A: KNOWN LIMITATIONS

| Limitation | Status | Mitigation |
|-----------|--------|-----------|
| Calibration poisoning | Acknowledged | Clean-room assumption (no attacks during calibration). All unsupervised detection has this property. |
| TOCTOU in dup2 handler | Acknowledged | Theoretical (requires sub-μs thread coordination under kernel spinlock). Mentioned in paper limitations. |
| IPv6 lateral bypass | Mitigated | IPv6 disabled on Docker bridge. Future: hook `tcp_v6_connect` + extend ip_to_cgroup to 128-bit keys. |
| NAT/overlay networks (Kubernetes) | Acknowledged | Docker bridge only. Kubernetes ClusterIPs break ip_to_cgroup resolution. Future: conntrack hooks. |
| Bigram temporal range | Acknowledged | Bigrams capture 1-step transitions only. Future: trigrams (20× memory cost). Noise filtering closes the practical evasion gap. |
| GIL scaling (>20 containers) | Not relevant | 3-container demo: <1ms per cycle. Future: multiprocessing.Pool for per-edge CCA. |
| Multi-node deployment | Designed, not implemented | Sheaf Laplacian is natively distributed. Future: gRPC edge projection transport. |

---

## APPENDIX B: COMMON IMPLEMENTATION PITFALLS

**BPF Verifier Pitfalls:**
1. Any array index from user-controlled input needs explicit bounds checking before use. The verifier does NOT trust implicit bounds.
2. `#pragma unroll` required for all fixed-count loops. Variable-count loops are rejected.
3. NULL checks required after EVERY `bpf_map_lookup_elem()`. No exceptions.
4. BPF_CORE_READ for all kernel struct access — bare pointer dereference fails on non-matching kernel versions.
5. Stack allocation of large structs (>256 bytes in tail-called programs) will be rejected. Use map values for large data.
6. `bpf_send_signal(9)` requires kernel ≥ 5.3. Check with `uname -r`.

**Python Daemon Pitfalls:**
1. `np.linalg.inv()` on a nearly-singular covariance matrix → garbage or LinAlgError. Always add `1e-6 * np.eye(k)` regularization before inverting.
2. EMA threshold must be calibrated separately from raw threshold — EMA has lower variance than raw signals (low-pass filter).
3. BCC's `BPF.get_table()` returns a map object that is read live from kernel at each access — not a snapshot. Cache if you need consistent reads.
4. Docker SDK's `docker.events()` blocks — must run in a separate thread.
5. cgroup IDs are NOT stable across host reboots — recalibrate after reboot.

**BCC Compilation Issues on Ubuntu 25.04/Kernel 6.14:**
- If BCC fails to compile: `bpftool btf dump file /sys/kernel/btf/vmlinux` to verify BTF is available
- If struct offsets are wrong: use `BPF_CORE_READ` (not raw pointer arithmetic)
- If kernel headers not found: `sudo apt-get install linux-headers-$(uname -r)`
- For verbose BCC error output: `b = BPF(text=src, debug=0x4)`

---

## APPENDIX C: CALIBRATION RUNNER (calibrate_runner.py)

This is the module called by `loader.py --calibrate`. It reads from live BPF maps during a normal-traffic window and produces the calibration artifacts consumed by `SheafCalibrator`.

```python
# tier3/calibrate_runner.py
"""
Calibration Runner — collects live BPF data during normal operation
and produces the restriction maps, thresholds, and PCA model.

Invoked by: sudo python3 loader.py --calibrate
Duration: 30-60 minutes (controlled by CALIBRATION_DURATION_S)

What it does:
  1. Every SAMPLE_INTERVAL seconds, reads bigram_sketch_map from BPF
  2. Reads connection events from telemetry_rb
  3. After duration completes, calls SheafCalibrator.calibrate()
  4. Saves all calibration artifacts to CALIBRATION_DIR

Pre-requisites:
  - docker compose up -d (containers running)
  - bash scripts/generate_normal_traffic.sh (running in another terminal)
  - loader.py is already running with probes attached (BPF maps are live)
"""
import time, ctypes, logging, json
from collections import defaultdict
from pathlib import Path
from bcc import BPF

from signal_extractor import BigramSketch
import numpy as np

CALIBRATION_DIR = "calibration"
CALIBRATION_DURATION_S = 1800   # 30 minutes default; use 3600 for 60 min
SAMPLE_INTERVAL = 5.0            # read BPF maps every 5 seconds (one CMS window)

log = logging.getLogger("causaltrace.calibrate")


# ─── BPF Struct mirrors ───────────────────────────────────────────────
# These must EXACTLY match the C structs in causaltrace_common.h.
# Field order, sizes, and padding must be identical.
# Use ctypes to read raw BPF map values.

import ctypes

class CBigramSketch(ctypes.Structure):
    """Mirror of struct bigram_sketch from causaltrace_common.h."""
    _fields_ = [
        ("counters", (ctypes.c_uint32 * 128) * 4),   # [CMS_ROWS][CMS_COLS]
        ("prev_idx", ctypes.c_uint32),
        ("_pad", ctypes.c_uint32),
        ("total_count", ctypes.c_uint64),
        ("window_start", ctypes.c_uint64),
    ]
    # sizeof = 2048 + 4 + 4 + 8 + 8 = 2072 bytes

class CBehaviorState(ctypes.Structure):
    """Mirror of struct behavior_state from causaltrace_common.h."""
    _fields_ = [
        ("flags", ctypes.c_uint64),
        ("bit_ts", ctypes.c_uint64 * 8),
        ("conn_dst_cg", ctypes.c_uint64),
        ("conn_port", ctypes.c_uint16),
        ("_pad", ctypes.c_uint16 * 3),
    ]
    # sizeof = 8 + 64 + 8 + 2 + 6 = 88 bytes

class CAlertT(ctypes.Structure):
    """Mirror of struct alert_t from causaltrace_common.h."""
    _fields_ = [
        ("type", ctypes.c_uint32),
        ("pid", ctypes.c_uint32),
        ("cgroup_id", ctypes.c_uint64),
        ("timestamp", ctypes.c_uint64),
        ("flags", ctypes.c_uint64),
        ("extra", ctypes.c_uint64),
    ]
    # sizeof = 40 bytes


def read_bigram_sketches(bpf_obj: BPF) -> dict:
    """
    Read all bigram sketches from BPF map.
    Returns: {cgroup_id (int): BigramSketch}
    """
    sketches = {}
    bigram_map = bpf_obj.get_table("bigram_sketch_map")

    for key, value in bigram_map.items():
        cg_id = key.value

        # Reconstruct numpy counters array from BCC map value
        # BCC returns a ctypes-compatible object
        counters = np.zeros((4, 128), dtype=np.uint32)
        for r in range(4):
            for c in range(128):
                counters[r, c] = value.counters[r][c]

        sketches[cg_id] = BigramSketch(
            counters=counters,
            prev_idx=int(value.prev_idx),
            total_count=int(value.total_count),
            window_start=int(value.window_start),
        )

    return sketches


def drain_connection_events(bpf_obj: BPF, event_buffer: list):
    """
    Poll telemetry ring buffer and collect CONNECTION_EVENT records.
    Appends to event_buffer in-place.
    """
    EVENT_CONNECTION = 100

    def handle_event(ctx, data, size):
        evt = ctypes.cast(data, ctypes.POINTER(CAlertT)).contents
        if evt.type == EVENT_CONNECTION:
            dst_ip   = (evt.extra >> 32) & 0xFFFFFFFF
            dst_port = evt.extra & 0xFFFF
            event_buffer.append({
                'src_cg':   int(evt.cgroup_id),
                'dst_cg':   int(evt.flags),     # flags field reused for dst_cg
                'dst_port': int(dst_port),
                'timestamp': int(evt.timestamp),
            })

    bpf_obj["telemetry_rb"].open_ring_buffer(handle_event)
    bpf_obj.ring_buffer_poll(timeout=200)


def run_calibration(bpf_obj: BPF,
                    duration_s: int = CALIBRATION_DURATION_S,
                    sample_interval: float = SAMPLE_INTERVAL):
    """
    Main calibration entry point. Called from loader.py --calibrate.

    Algorithm:
      Every SAMPLE_INTERVAL seconds:
        - Read current bigram_sketch_map snapshot
        - Collect connection events from telemetry_rb
        - Store both in growing lists

      After duration_s:
        - Run SheafCalibrator.calibrate() on collected data
        - Save artifacts to CALIBRATION_DIR
    """
    log.info(f"Starting calibration ({duration_s // 60} minutes).")
    log.info("Ensure normal traffic is running: bash scripts/generate_normal_traffic.sh")
    log.info("")

    # Collected data
    bigram_traces  = defaultdict(list)   # cg_id → [BigramSketch, ...]
    connection_events = []               # list of connection event dicts

    start = time.monotonic()
    samples_collected = 0
    last_report = start

    while True:
        elapsed = time.monotonic() - start
        if elapsed >= duration_s:
            break

        # Progress report every 60 seconds
        if time.monotonic() - last_report >= 60:
            mins = int(elapsed // 60)
            total_mins = duration_s // 60
            log.info(f"  [{mins}/{total_mins} min] "
                     f"{samples_collected} samples, "
                     f"{len(connection_events)} connections")
            last_report = time.monotonic()

        # Read BPF maps
        sketches = read_bigram_sketches(bpf_obj)
        drain_connection_events(bpf_obj, connection_events)

        for cg_id, sketch in sketches.items():
            if sketch.total_count > 0:   # skip empty windows
                bigram_traces[cg_id].append(sketch)

        samples_collected += 1
        time.sleep(sample_interval)

    # ── Calibration ───────────────────────────────────────────────────
    log.info("")
    log.info(f"Calibration data collection complete.")
    log.info(f"  Containers observed: {list(bigram_traces.keys())}")
    log.info(f"  Samples per container: "
             f"{[len(v) for v in bigram_traces.values()]}")
    log.info(f"  Connection events: {len(connection_events)}")

    if not bigram_traces:
        log.error("No bigram data collected. Is normal traffic running?")
        return

    if len(bigram_traces) < 2:
        log.error("Only 1 container observed. Need ≥2 for sheaf edges.")
        return

    min_samples = min(len(v) for v in bigram_traces.values())
    if min_samples < 60:
        log.warning(f"Only {min_samples} samples for some containers. "
                    f"Need ≥60 (5 minutes) for stable CCA. "
                    f"Consider running longer.")

    # Run the full calibration pipeline
    from calibrate import SheafCalibrator
    cal = SheafCalibrator(d=74, k=50)
    cal.calibrate(
        bigram_traces=dict(bigram_traces),
        connection_events=connection_events,
        duration_minutes=duration_s / 60,
    )

    # Save artifacts
    Path(CALIBRATION_DIR).mkdir(parents=True, exist_ok=True)
    cal.save(CALIBRATION_DIR)

    log.info("")
    log.info(f"Calibration complete. Artifacts saved to {CALIBRATION_DIR}/")
    log.info("Restart loader in --mode enforce to enable detection.")
```

---

## APPENDIX D: BCC / PYTHON CTYPES BRIDGE REFERENCE

BCC compiles BPF C code and exposes maps as Python objects. This appendix documents the exact patterns for reading each map type used in CausalTrace.

### D.1 Reading Hash Map Values

BCC map items are accessed as ctypes-compatible objects. The Python-side struct must exactly mirror the C struct layout including padding.

```python
from bcc import BPF
import ctypes, numpy as np

b = BPF(src_file="dispatcher.bpf.c")

# ── Reading bigram_sketch_map ─────────────────────────────────────────
bigram_map = b.get_table("bigram_sketch_map")

for key, value in bigram_map.items():
    cg_id = key.value   # u64 cgroup_id

    # Access nested array: value.counters[row][col]
    counters = np.array([[value.counters[r][c]
                          for c in range(128)]
                         for r in range(4)], dtype=np.uint32)

    prev_idx    = int(value.prev_idx)
    total_count = int(value.total_count)

# ── Reading container_behavior map ───────────────────────────────────
behavior_map = b.get_table("container_behavior")

for key, value in behavior_map.items():
    cg_id = key.value
    flags = int(value.flags)
    bit_ts = [int(value.bit_ts[i]) for i in range(8)]
    conn_port = int(value.conn_port)

# ── Writing to verdict_map ────────────────────────────────────────────
verdict_map = b.get_table("verdict_map")

VERDICT_KILL = 1
cg_key = ctypes.c_uint64(cgroup_id)
verdict_val = ctypes.c_uint32(VERDICT_KILL)
verdict_map[cg_key] = verdict_val

# To clear a verdict (allow again):
del verdict_map[cg_key]
```

### D.2 Ring Buffer Polling Pattern

```python
# Pattern for polling BOTH ring buffers in the main loop

def make_alert_handler(alert_log: list):
    def handle_alert(ctx, data, size):
        evt = ctypes.cast(data, ctypes.POINTER(CAlertT)).contents
        alert_log.append({
            'type': int(evt.type),
            'pid': int(evt.pid),
            'cgroup_id': int(evt.cgroup_id),
            'timestamp': int(evt.timestamp),
            'flags': int(evt.flags),
            'extra': int(evt.extra),
        })
    return handle_alert

def make_telemetry_handler(conn_buffer: list):
    def handle_telemetry(ctx, data, size):
        evt = ctypes.cast(data, ctypes.POINTER(CAlertT)).contents
        if evt.type == 100:  # EVENT_CONNECTION
            conn_buffer.append({
                'src_cg':    int(evt.cgroup_id),
                'dst_cg':    int(evt.flags),         # reused field
                'dst_port':  int(evt.extra & 0xFFFF),
                'dst_ip':    int((evt.extra >> 32) & 0xFFFFFFFF),
                'timestamp': int(evt.timestamp),
            })
    return handle_telemetry

# Setup (called once):
alert_log = []
conn_buffer = []
b["alerts_rb"].open_ring_buffer(make_alert_handler(alert_log))
b["telemetry_rb"].open_ring_buffer(make_telemetry_handler(conn_buffer))

# In main loop (called every ~5 seconds):
b.ring_buffer_poll(timeout=100)   # 100ms timeout, then return
# After this call: alert_log and conn_buffer have new entries
```

### D.3 BPF Program Attachment Reference

```python
# raw_tracepoint (dispatcher + handlers via tail-call):
b.attach_raw_tracepoint(tp="sys_enter", fn_name="dispatcher")
# Note: handlers are NOT directly attached — they're called via prog_array tail-calls

# kprobe/kretprobe (Probe B):
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_return")

# tracepoint (Probe C):
b.attach_tracepoint(tp="sched:sched_process_exec", fn_name="trace_exec")

# Verify attachments:
print(b.num_open_kprobes())          # should be 2 (entry + return)
print(b.num_open_tracepoints())      # should be ≥1
```

### D.4 Reading Prog_Array for Tail Calls (BCC Pattern)

```python
# BCC-specific: load programs from separate source files and register in prog_array

# Method 1: compile all programs in one BPF() call (simpler)
combined_src = open("dispatcher.bpf.c").read() + open("handler_fork.bpf.c").read() + ...
b = BPF(text=combined_src, cflags=["-I./kernel"])
prog_array = b.get_table("prog_array")

# Register each handler at its syscall number(s)
# b.load_func() returns the BPF function object
HANDLERS = {
    "handle_fork":    [56, 435],  # clone, clone3
    "handle_execve":  [59],
    "handle_file":    [257],
    "handle_privesc": [101, 105, 272, 308],
    "handle_dup2":    [33, 292],
}
for fn_name, syscall_nrs in HANDLERS.items():
    fn = b.load_func(fn_name, BPF.RAW_TRACEPOINT)
    for nr in syscall_nrs:
        prog_array[ctypes.c_uint32(nr)] = ctypes.c_int(fn.fd)

# Method 2: BCC's BPF_MAP_TYPE_PROG_ARRAY with fn_name lookup
# (alternative syntax — same result)
prog_array = b["prog_array"]
prog_array[56] = b["handle_fork"]
```

### D.5 Struct Size Verification

Always verify Python ctypes struct sizes match BPF C struct sizes before running.

```python
# Run this before starting the daemon to catch struct mismatch bugs

def verify_struct_sizes(b: BPF):
    """
    Verify that Python ctypes struct sizes match BPF C struct sizes.
    Mismatch causes silent read corruption (wrong field values).
    """
    checks = [
        (CBigramSketch, 2072, "bigram_sketch"),
        (CBehaviorState, 88,   "behavior_state"),
        (CAlertT,        40,   "alert_t"),
    ]
    all_ok = True
    for cls, expected, name in checks:
        actual = ctypes.sizeof(cls)
        ok = actual == expected
        status = "✓" if ok else "✗"
        print(f"  {status} sizeof({name}): {actual} (expected {expected})")
        if not ok:
            all_ok = False
    if not all_ok:
        raise RuntimeError("Struct size mismatch — update ctypes definitions to match C")

verify_struct_sizes(b)
```

---

## APPENDIX E: VERDICT WRITER (verdict_writer.py)

Standalone module for writing detection verdicts to the BPF `verdict_map` and the structured log.

```python
# tier3/verdict_writer.py
"""
Verdict Writer — writes sheaf daemon verdicts to BPF verdict_map
and to the structured results log.

The verdict_map is the ONLY path by which Tier 3 decisions become
kernel enforcement. The dispatcher reads this map on every container
syscall and calls bpf_send_signal(9) if the cgroup is flagged.

Design constraint: verdicts are persistent until explicitly cleared.
Once a cgroup is flagged KILL, it will be killed on every subsequent
syscall until the map entry is removed. This is intentional — an
attacker cannot escape by quickly spawning a new process.

Clearing verdicts: done on container restart (Docker event listener
calls unregister_container() which clears the map entry).
"""
import ctypes, json, time, logging
from pathlib import Path
from dataclasses import asdict

log = logging.getLogger("causaltrace.verdict")

VERDICT_ALLOW = 0
VERDICT_KILL  = 1


class VerdictWriter:
    def __init__(self, bpf_obj, results_dir: str = "results/causaltrace",
                 mode: str = "monitor"):
        """
        bpf_obj: BPF object from BCC (already loaded)
        results_dir: directory for JSON log output
        mode: "monitor" (log only) or "enforce" (write verdict_map)
        """
        self.verdict_map = bpf_obj.get_table("verdict_map")
        self.mode = mode

        Path(results_dir).mkdir(parents=True, exist_ok=True)
        log_path = Path(results_dir) / "verdicts.jsonl"
        self.log_file = open(log_path, 'a', buffering=1)  # line-buffered

        log.info(f"VerdictWriter: mode={mode}, log={log_path}")

    def write(self, verdict) -> None:
        """
        Process a verdict from SheafDetector.detect_cycle().
        - If KILL and mode=enforce: writes to verdict_map
        - Always: writes structured log entry
        """
        ts = time.time()

        log_entry = {
            "timestamp":       ts,
            "action":          "KILL" if verdict.action == VERDICT_KILL else "ALLOW",
            "mode":            self.mode,
            "rayleigh":        round(verdict.rayleigh, 6),
            "global_tau":      round(verdict.global_threshold, 6),
            "novel_edges":     len(verdict.novel_edges),
            "edge_anomalies":  len(verdict.edge_anomalies),
            "affected_cgroups": verdict.affected_cgroups,
            "label":           verdict.label.name if verdict.label else None,
            "severity":        verdict.label.severity if verdict.label else "NONE",
            "mitre":           verdict.label.mitre_ids if verdict.label else [],
            "reason":          verdict.reason,
        }

        # Add edge anomaly details
        if verdict.edge_anomalies:
            log_entry["edge_details"] = [
                {
                    "src": a.src, "dst": a.dst, "lag": a.lag,
                    "energy": round(a.energy, 4),
                    "threshold": round(a.threshold, 4),
                    "ratio": round(a.ratio, 3),
                }
                for a in verdict.edge_anomalies
            ]

        # Add novel edge details
        if verdict.novel_edges:
            log_entry["novel_edge_details"] = [
                {"src": n.src, "dst": n.dst, "port": n.port}
                for n in verdict.novel_edges
            ]

        # Add eigenmode fingerprint if available
        if verdict.eigenmodes:
            log_entry["eigenmodes"] = {
                "total_energy":   round(verdict.eigenmodes.total_energy, 4),
                "dominant_modes": verdict.eigenmodes.dominant_modes,
                "mode_energies":  [round(e, 4) for e in verdict.eigenmodes.mode_energies],
            }

        # Write to log
        self.log_file.write(json.dumps(log_entry) + "\n")

        if verdict.action == VERDICT_KILL:
            label_str = verdict.label.name if verdict.label else "Unknown"
            log.warning(
                f"ATTACK: {label_str} | "
                f"cgroups={verdict.affected_cgroups} | "
                f"rayleigh={verdict.rayleigh:.3f} | "
                f"{verdict.reason}"
            )

            if self.mode == "enforce":
                for cg_id in verdict.affected_cgroups:
                    self._kill_cgroup(cg_id)
            else:
                log.info("  (monitor mode — verdict not enforced)")

    def _kill_cgroup(self, cgroup_id: int) -> None:
        """Write VERDICT_KILL for a cgroup to the BPF verdict_map."""
        try:
            key = ctypes.c_uint64(cgroup_id)
            val = ctypes.c_uint32(VERDICT_KILL)
            self.verdict_map[key] = val
            log.info(f"  verdict_map[{cgroup_id}] = KILL (kernel will enforce on next syscall)")
        except Exception as e:
            log.error(f"  Failed to write verdict for cgroup {cgroup_id}: {e}")

    def clear_verdict(self, cgroup_id: int) -> None:
        """
        Clear a KILL verdict for a cgroup (e.g., after container restart).
        Called by DockerEventListener on container stop/die.
        """
        try:
            key = ctypes.c_uint64(cgroup_id)
            del self.verdict_map[key]
            log.info(f"  verdict_map[{cgroup_id}] cleared")
        except Exception:
            pass   # Entry may not exist — that's fine

    def close(self):
        self.log_file.close()
```

---

## APPENDIX F: RESULTS ANALYSIS (results_analysis.py)

Reads the `verdicts.jsonl` log and generates the comparison tables and graphs needed for the final paper.

```python
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
```

### F.1 Adding Scenario Tagging to run_all.sh

Modify `attacks/run_all.sh` to pass the scenario number as an environment variable so the daemon can tag log entries:

```bash
# In run_all.sh, replace the scenario loop with:
for i in 1 2 3 4 5 6 7; do
    # Signal daemon to tag next verdicts with scenario number
    echo "$i" > /tmp/causaltrace_current_scenario
    bash ~/causaltrace/attacks/scenario_${i}_*.sh 2>&1 | tee "$RESULTS_DIR/scenario_${i}.log"
    sleep 5
    echo "0" > /tmp/causaltrace_current_scenario
done
```

In `daemon_main.py`, read the scenario tag in each detection cycle:

```python
# In run_detection_cycle(), add before writing log:
import os
scenario_tag = None
try:
    with open("/tmp/causaltrace_current_scenario") as f:
        sc = int(f.read().strip())
        if sc > 0:
            scenario_tag = sc
except Exception:
    pass

log_entry["scenario"] = scenario_tag
```

---

## APPENDIX G: PROMPTING GUIDE FOR A NEW CLAUDE OPUS SESSION

This appendix explains how to use this document with a fresh Claude Opus session to implement CausalTrace from scratch. It is the operational guide for the coding phase.

### G.1 Session Setup

Start every new coding session with this system prompt:

```
You are implementing CausalTrace, an eBPF-based container security system.
I have a complete design document that specifies every component in detail.
Follow the document exactly — every design decision is there for a specific
reason documented alongside the problem it solves.

Key constraints to never violate:
1. BPF verifier rules: always bounds-check array indices from user input,
   always NULL-check map lookups, always use #pragma unroll on fixed loops,
   always use BPF_CORE_READ_INTO for kernel struct access.
2. Invariant bits (behavior_state.flags) go ONLY to the Semantic Label Engine.
   They must NOT be included in the d=74 sheaf signal vector.
3. Use two separate ring buffers: alerts_rb (64KB, Tier 1 only) and
   telemetry_rb (256KB, Probe B only). Never mix them.
4. connect_sk_stash must be BPF_MAP_TYPE_LRU_HASH, not BPF_MAP_TYPE_HASH.
5. behavior_state has bit_ts[8] (per-bit timestamps), NOT a single ts field.

When I ask you to implement a file, reference the pseudocode in the design
document and produce complete, working code. Ask if anything is ambiguous
before guessing.
```

### G.2 File-by-File Implementation Prompts

Use these prompts in order. Each builds on the previous.

**Prompt 1 — Common header:**
```
Implement causaltrace_common.h from Section 6.1 of the design document.
This is a C header file shared by all BPF programs.
Include: all #define constants, all struct definitions (behavior_state with
bit_ts[8], rate_state, bigram_sketch, alert_t), CMS_PRIMES/CMS_SEEDS arrays,
syscall_to_idx() function (top-24 list from Section 6.1), and
is_noise_syscall() function.
Write the complete file, nothing omitted.
```

**Prompt 2 — BPF map declarations:**
```
Implement causaltrace_maps.h from Section 6.2. This declares all BPF maps
used across the system. Use the exact map types specified — particularly:
- connect_sk_stash must be BPF_MAP_TYPE_LRU_HASH with max_entries=4096
- alerts_rb is 64*1024 bytes (alerts only)
- telemetry_rb is 256*1024 bytes (connection events only)
Write the complete file.
```

**Prompt 3 — Dispatcher:**
```
Implement dispatcher.bpf.c from Section 6.3. This is the most critical file.
It runs on every container syscall. Implement all 6 steps exactly as specified:
1. Read syscall number
2. Container filter (BPF_CORE_READ_INTO for mnt namespace)
3. verdict_map check → bpf_send_signal(9) if VERDICT_KILL
4. Cgroup inheritance check (pending_cgroup_inherit map)
5. Bigram CMS update — with noise filter (don't advance prev_idx for noise
   syscalls, but still tail-call), with cold-path continue (don't return 0
   when sketch is NULL), with window reset
6. bpf_tail_call dispatch

Every verifier constraint must be explicitly satisfied with a comment explaining
which verifier rule it addresses.
```

**Prompt 4 — dup2 invariant handler:**
```
Implement handler_dup2.bpf.c from Section 6.4. This is the fd-type invariant —
the most important new detection in CausalTrace. It detects ALL reverse shells
regardless of language by checking if a socket fd is being redirected to
stdin/stdout/stderr.

Key verifier requirements:
- Bound check oldfd: if (oldfd < 0 || oldfd >= MAX_FD) return 0
- Bound check newfd: if (newfd < 0 || newfd > 2) return 0
- Use bpf_probe_read_kernel for fd_array[oldfd] access
- All struct traversal via BPF_CORE_READ_INTO
- NULL check every pointer

Write to alerts_rb (not telemetry_rb). Set bit_ts[6] (not the old single ts).
```

**Prompt 5 — Fork acceleration handler:**
```
Implement handler_fork.bpf.c from Section 6.5. Detects fork bombs using the
second discrete derivative of fork rate. Three consecutive 1-second windows.
Alarm condition: d2 > 0 AND rate > prev AND prev > prev_prev AND rate > 50.
Hard ceiling: rate > 500 always kills. Set bit_ts[7].
```

**Prompt 6 — Remaining handlers:**
```
Implement handler_execve.bpf.c, handler_file.bpf.c, and handler_privesc.bpf.c
from Sections 6.6, 6.7, and 6.8.

For handler_privesc.bpf.c: the unshare handler must register the current
cgroup_id in pending_cgroup_inherit keyed by pid_tgid when CLONE_NEWCGROUP
flag is detected. This enables cgroup inheritance in the dispatcher.
Set per-bit timestamps throughout (bit_ts[i], not a single ts).
```

**Prompt 7 — Probe B:**
```
Implement probe_b_network.bpf.c from Section 7.1.
Two functions: trace_connect_entry (kprobe) and trace_connect_return (kretprobe).

Key details:
- Entry: stash sock* in connect_sk_stash (LRU_HASH) keyed by pid_tgid
- Return: only process if ret==0 (successful connect), retrieve stashed sk,
  resolve dst_ip via ip_to_cgroup, check two-hop invariant with per-bit timestamps
- Two-hop check: use bit_ts[0] and bit_ts[6] independently (not the old single ts)
  Include lazy expiry loop (clear stale bits)
- Connection events go to telemetry_rb (NOT alerts_rb)
- Two-hop alerts go to alerts_rb
```

**Prompt 8 — BCC Loader:**
```
Implement loader.py from Section 9.1. This is the entry point (run as sudo).
It must:
1. Compile all BPF C source files using BCC (combined src or per-file)
2. Attach dispatcher to raw_tracepoint/sys_enter
3. Set up prog_array tail calls for all 5 handler types × their syscall numbers
4. Attach kprobe/kretprobe for tcp_v4_connect (Probe B)
5. Attach tracepoint sched:sched_process_exec (Probe C)
6. Read host mount namespace inode from /proc/self/ns/mnt → write to host_ns map
7. Start DockerEventListener in a background thread
8. Start CausalTraceDaemon in main thread

Include the CTLRs HANDLERS dict mapping handler names → syscall number lists.
Use argparse for --mode (monitor/enforce) and --calibrate flags.
```

**Prompt 9 — Docker Event Listener:**
```
Implement infra/docker_event_listener.py from Section 9.2.
Must handle:
- Startup: register all already-running containers
- docker events start: register new container (with 0.5s delay for init)
- docker events die/stop: unregister container

For each container registration:
- Get container IP via docker inspect → Networks → IPAddress
- Get cgroup_id via /proc/<pid>/cgroup → find line starting with "0:" →
  extract cgroup path → stat /sys/fs/cgroup/<path> → st_ino
- Write ip_to_cgroup[ip_int] = cgroup_id
- Pre-populate bigram_sketch_map[cgroup_id] with zeroed entry (prevents
  cold-path stack overflow in dispatcher)
```

**Prompt 10 — Signal Extractor:**
```
Implement tier3/signal_extractor.py from Section 8.1.
The key function is extract_signal_74(sketch, cal_stats) → np.ndarray shape (74,).

Components:
- [0:3] Rényi entropy H_α for α ∈ {0.5, 1.0, 2.0}
- [3:53] PCA projection of bigram frequencies (625→50)
- [53:73] Transition probability marginals (top 24 rows, take max → 20 values)
  Wait — the code in Section 8.1 takes the first 20 rows; ensure dim = 20
- [73] Total syscall rate / WINDOW_SECONDS

Also implement: BigramSketch dataclass, CalibrationStats dataclass,
reconstruct_bigrams(), renyi_entropy().

IMPORTANT: Do NOT include any invariant bits in this function's output.
The d=74 vector has NO behavior flags.
```

**Prompt 11 — Whitener, EMA, Calibrator:**
```
Implement tier3/whitener.py (Section 8.2), tier3/ema_buffer.py (Section 8.3),
and tier3/calibrate.py (Section 8.4) as three separate files.

For calibrate.py, the SheafCalibrator.calibrate() method:
- PCA: pool all bigram vectors, fit sklearn PCA(n_components=50)
- Whitening: per container, fit FeatureWhitener on extracted signals
- CCA: for each observed edge × 3 lags, fit sklearn CCA(n_components=50)
  on aligned (X_u, X_v) pairs, extract x_rotations_ and y_rotations_ as
  F_u and F_v, compute Mahalanobis covariance of normal residuals,
  set threshold = mean + 4*std of Mahalanobis distances
- Global threshold: mean + 4*std of Rayleigh quotients over calibration windows

The save() method must write: pca.pkl, whiteners.pkl, restriction_maps.npz,
edge_thresholds.json, global_threshold.json, calibrated_edges.json
```

**Prompt 12 — Sheaf Detector:**
```
Implement tier3/sheaf_detector.py from Section 8.5.

The detect_cycle() method runs 6 stages:
1. Novel-edge detection (hash lookup on calibrated_edges set)
2. Signal extraction + whitening + EMA update + signal history deque append
3. Sheaf spectral test: for each calibrated (u,v) pair, try lags 0,1,2,
   compute Mahalanobis edge energy for both raw and EMA paths,
   take max across lags, compare to per-edge threshold
4. Global Rayleigh quotient (total_raw_energy / ||x_global||^2)
5. Eigenmode analysis (if analyzer available)
6. Semantic label from behavior bitfields (Section 8.5 _compute_semantic_label)
   — reads container_behavior map flags, applies priority-ordered rules

The _compute_semantic_label() reads behavior bits from kernel (not from x_v).
This is the ONLY place behavior bits are used in Tier 3.
```

**Prompt 13 — Eigenmode Analyzer:**
```
Implement tier3/eigenmode_analyzer.py from Section 8.6.
SheafEigenmodeAnalyzer.__init__() builds L_F from lag=0 restriction maps
(use _build_laplacian() from sheaf_detector) and calls np.linalg.eigh().
Keep only modes with eigenvalue > 1e-8.
analyze() projects x_global onto eigenvectors, computes mode_energies = coeffs^2 * eigenvalues,
returns top-5 dominant modes and their energy fractions.
```

**Prompt 14 — Main Daemon + Verdict Writer:**
```
Implement tier3/daemon_main.py (Section 8.7) and tier3/verdict_writer.py
(Appendix E) as two separate files.

For daemon_main.py:
- CausalTraceDaemon class with run_detection_cycle() method
- Staleness TTL: check if latest ring buffer event is >10s old → drain and skip
- Poll telemetry_rb for connections, read bigram_sketch_map and
  container_behavior in each cycle
- Call SheafDetector.detect_cycle() → pass result to VerdictWriter.write()

For verdict_writer.py:
- VerdictWriter.write() logs to JSONL with all verdict fields
- _kill_cgroup() writes ctypes.c_uint64 key + ctypes.c_uint32 value to verdict_map
- In "monitor" mode: log only, no verdict_map writes
```

**Prompt 15 — Calibration Runner:**
```
Implement tier3/calibrate_runner.py from Appendix C.
run_calibration(bpf_obj, duration_s, sample_interval) collects live BPF data:
- Every SAMPLE_INTERVAL seconds: read bigram_sketch_map, drain telemetry_rb
- Append sketches to bigram_traces[cg_id] if total_count > 0
- After duration: call SheafCalibrator.calibrate() then cal.save()

Also include the CBigramSketch, CBehaviorState, CAlertT ctypes struct definitions
from Appendix D.4, with the verify_struct_sizes() check.
```

**Prompt 16 — Results Analysis:**
```
Implement scripts/results_analysis.py from Appendix F.
Include: load_verdicts(), compute_metrics(), print_comparison_table()
with hardcoded BASELINE_A_RESULTS and BASELINE_B_RESULTS from the mid-review,
plot_rayleigh_distribution(), plot_eigenmode_fingerprints(), and main().
```

### G.3 Testing Checkpoints

After each major implementation step, verify before moving on:

```bash
# After Prompts 1-6 (kernel code):
sudo python3 -c "
from bcc import BPF
import os
src = open('kernel/dispatcher.bpf.c').read()
# Add other handler files
b = BPF(text=src, cflags=['-I./kernel'], debug=0x4)
print('BPF compilation: OK')
"

# After Prompt 8 (loader):
sudo python3 loader.py --mode monitor &
sleep 5
curl -s http://localhost:8080/api/health > /dev/null
# Should see no alerts in console for normal traffic

# After Prompts 10-11 (signal + calibration):
python3 -c "
import numpy as np
from tier3.signal_extractor import BigramSketch, CalibrationStats, extract_signal_74
from sklearn.decomposition import PCA
# Create a dummy sketch and verify output shape
sk = BigramSketch(
    counters=np.random.randint(0, 100, (4, 128), dtype=np.uint32),
    prev_idx=5, total_count=1000, window_start=0
)
pca = PCA(n_components=50).fit(np.random.rand(100, 625))
cal_stats = CalibrationStats(pca_components=pca.components_, pca_mean=pca.mean_)
x = extract_signal_74(sk, cal_stats)
assert x.shape == (74,), f'Expected (74,), got {x.shape}'
print('signal_extractor: OK, shape =', x.shape)
"

# After Prompt 12 (sheaf detector):
# Run calibration then test detection on a saved trace:
sudo python3 loader.py --calibrate   # run for 5 min with traffic in other terminal
# Then:
sudo python3 loader.py --mode monitor
bash attacks/scenario_7_cross_container.sh
# Should see ATTACK log entry within 5 seconds
```

### G.4 What to Tell the Opus Session When It Gets Stuck

**"The BPF verifier is rejecting my program":**
> Check the specific verifier error message from `bpftool prog load`. Common fixes:
> - Add `if (prev_idx > 24) prev_idx = 24;` before using prev_idx as array index
> - Add `& CMS_COL_MASK` after hash computation
> - Add NULL check after every `bpf_map_lookup_elem()`
> - Replace any raw struct dereferences with `BPF_CORE_READ_INTO`
> - If a struct is too large for stack: pre-populate from userspace, never zero-initialize in BPF

**"CCA is failing / singular matrix error":**
> - Verify that T >= k + 10 (at least 60 samples for k=50 CCA)
> - Verify that invariant bits (bit_ts[i] flags) are NOT in the signal vector
> - Add `+ 1e-6 * np.eye(k)` regularization to covariance before inverting
> - Increase calibration duration if T is too small

**"Novel-edge detector firing on normal traffic":**
> - The calibrated_edges set was not populated during calibration
> - Check that generate_normal_traffic.sh produces curl via localhost:8080/api/* (not :8081/*)
> - Verify ip_to_cgroup map is populated (docker event listener running)
> - Print calibrated_edges after loading to verify it contains the expected tuples

**"Two-hop invariant not firing on Scenario 7":**
> - Verify bigram_sketch_map is pre-populated (cold path fix from Prompt 3)
> - Check that bit_ts[0] and bit_ts[6] are being set by their handlers
> - Verify the timestamp comparison uses per-bit ts (bit_ts[0]) not the old single ts
> - Print container_behavior flags in the daemon to see what bits are set

**"Sheaf detector always fires (false positives)":**
> - Calibration data is insufficient — run longer
> - Verify signal vector is d=74 (no behavior bits) — print shape
> - Lower the threshold multiplier from 4 to 3 sigma temporarily for debugging
> - Check if normal traffic generates shell-like bigrams (legitimate shell spawns during calibration)

---

## APPENDIX H: PAPER FRAMING GUIDE

This appendix gives exact language to use in the final report for each design evolution, so the paper reads as a coherent narrative rather than a changelog.

### H.1 The Tier 3 Evolution Narrative

Use this framing in the Introduction or Background section:

> "During implementation, we discovered that the DistilGPT-2 + GCN pipeline proposed at mid-review had three fundamental constraints that made it incompatible with CausalTrace's design goals: (1) a circular training data dependency — the GCN required 500+ labelled cross-container attack chain graphs, which could only be generated by the very pipeline we were building; (2) a resource contradiction — a 330MB GPU-dependent model running alongside kernel-space eBPF probes requires either a dedicated GPU container or significant CPU fallback overhead incompatible with our <5% overhead target; and (3) a latency gap — DistilGPT-2 inference takes 50–200ms per sequence, far from the microsecond enforcement of Tiers 1–2.
>
> We replaced both models with a sheaf Laplacian spectral detector from algebraic topology, which addresses all seven research gaps with closed-form solutions, zero GPU dependency, zero external training data, and sub-millisecond detection cycles. This represents a deeper contribution: a provably sound anomaly detector based on mathematical consistency of container behavioral signals, rather than an iterative training approach with uncertain convergence."

### H.2 Framing the Two-Surface Principle

> "We identify two orthogonal detectability surfaces for container attacks. The first surface — physical invariants — consists of operations the attacker must perform regardless of implementation language, evasion technique, or obfuscation level. These are checked by kernel-space eBPF handlers at syscall granularity with zero false negatives for the covered attack classes. The second surface — behavioral consistency — applies when no known invariant matches the attack pattern. Unknown attacks or novel variants necessarily change a container's syscall transition distribution, producing measurable inconsistency between that container's behavioral signal and its neighbors' calibrated coupling structure. The sheaf Laplacian quantifies this inconsistency as a Rayleigh quotient, providing statistical coverage for the space of attacks that deterministic invariants cannot reach."

### H.3 Framing Proposition 3 (Bigram Obfuscation Closure)

> "The noise-syscall filtering mechanism creates a provable adversarial closure property. An attacker attempting to obfuscate their syscall signature by injecting side-effect-free syscalls (getpid, getuid, gettid, getppid, time, clock_gettime) between each malicious call finds that the filtering mechanism makes such syscalls transparent to the bigram CMS — the transition counter prev_idx is not advanced for noise calls, so the malicious bigrams are still recorded. Conversely, an attacker who injects non-trivial syscalls (those with observable side effects) to break bigrams instead inflates the frequency of those non-trivial syscalls far beyond their normal distribution, producing a distributional shift detectable by the sheaf Laplacian. The attacker faces a forced trade-off: either preserve the malicious bigram signature (detected by pattern analysis) or destroy it by injecting observable syscalls (detected by statistical analysis). This property, which we term bigram obfuscation closure, makes CausalTrace's bigram representation adversarially robust without requiring any additional computation."

### H.4 Framing the Eigenmode Result

> "Beyond binary anomaly detection, the sheaf Laplacian provides spectral fingerprinting of attack types. The eigendecomposition of L_F yields basis vectors representing different 'modes of inconsistency' between containers. We observe empirically that different attack types excite distinct eigenmodes: a single-container reverse shell concentrates energy in the mode corresponding to the compromised container's deviation, while a full lateral movement chain distributes energy across modes corresponding to multiple containers. This suggests a path toward automated attack type classification from spectral features alone — without any trained classifier — which we identify as a direction for future work."

### H.5 Framing Detected Scenarios for the Paper

The key claim requires careful phrasing. "CausalTrace detects 7/7 scenarios while Baseline B detects 5/7" is true but needs qualification:

> "CausalTrace detects all seven attack scenarios: five via Tier 1 deterministic invariant handlers (shared capability with Baseline B), and two via Tier 2 cross-container pattern detection combined with Tier 3 sheaf Laplacian analysis (unique capability). Baseline A detects one scenario (namespace escape via path-based anomaly detection). Baseline B detects five scenarios but cannot correlate events across containers and therefore misses both cross-container scenarios. CausalTrace is the only system among the three that detects Scenario 7 — multi-stage lateral movement from the web container through the API container to the database — which constitutes the primary novel detection claim of this work."

---

## APPENDIX I: QUICK REFERENCE — ALL CONSTANTS

These constants must be consistent across BPF C headers and Python code. Any mismatch causes incorrect behavior (wrong CMS indices, wrong struct offsets, wrong threshold computations).

| Constant | C Value | Python Value | Used In |
|----------|---------|-------------|---------|
| `MAX_CONTAINERS` | 256 | 256 | All map max_entries |
| `CMS_ROWS` | 4 | `CMS_ROWS = 4` | bigram_sketch counters |
| `CMS_COLS` | 128 | `CMS_COLS = 128` | bigram_sketch counters |
| `CMS_COL_MASK` | 0x7F | `CMS_COL_MASK = 127` | hash masking |
| `TOP_SYSCALLS` | 25 | `TOP_SYSCALLS = 25` | bigram key computation |
| `MAX_BIGRAMS` | 625 | `MAX_BIGRAMS = 625` | bigram frequency arrays |
| `WINDOW_NS` | 5,000,000,000 | `WINDOW_SECONDS = 5.0` | CMS window |
| `TWOHOP_WINDOW_NS` | 5,000,000,000 | `TWOHOP_WINDOW_S = 5.0` | two-hop check |
| `MAX_FD` | 1024 | — | dup2 bounds check |
| `CMS_PRIMES` | [2654435761, 2246822519, 3266489917, 668265263] | same list | CMS hashing |
| `CMS_SEEDS` | [1, 7, 13, 31] | same list | CMS hashing |
| `sizeof(bigram_sketch)` | 2072 | `ctypes.sizeof(CBigramSketch) == 2072` | struct verification |
| `sizeof(behavior_state)` | 88 | `ctypes.sizeof(CBehaviorState) == 88` | struct verification |
| `sizeof(alert_t)` | 40 | `ctypes.sizeof(CAlertT) == 40` | struct verification |
| `d` (signal dims) | — | `d = 74` | CCA, whitening |
| `k` (CCA components) | — | `k = 50` | restriction maps |
| `alpha` (EMA) | — | `alpha = 0.2` | EMA buffer |
| threshold sigma | — | `4.0` | Mahalanobis 4-sigma |

**Syscall index mapping must be identical in both C (`syscall_to_idx()`) and Python (if used for analysis):**

| Index | Syscall | Number |
|-------|---------|--------|
| 0 | read | 0 |
| 1 | write | 1 |
| 2 | open | 2 |
| 3 | close | 3 |
| 4 | stat | 4 |
| 5 | fstat | 5 |
| 6 | mmap | 9 |
| 7 | mprotect | 10 |
| 8 | brk | 12 |
| 9 | ioctl | 16 |
| 10 | access | 21 |
| 11 | pipe | 22 |
| 12 | socket | 41 |
| 13 | connect | 42 |
| 14 | accept | 43 |
| 15 | sendto | 44 |
| 16 | ptrace | 101 |
| 17 | mount | 165 |
| 18 | unshare | 272 |
| 19 | setns | 308 |
| 20 | memfd_create | 319 |
| 21 | bpf | 321 |
| 22 | io_uring_enter | 426 |
| 23 | execve | 59 |
| 24 | (other) | — |

**Behavior bit assignments (must match between C `#define` and Python Semantic Label Engine):**

| Bit | Name | C Define | Python check |
|-----|------|----------|-------------|
| 0 | Shell spawn | `BIT_SHELL_SPAWN` | `flags & (1<<0)` |
| 1 | Lateral connect | `BIT_LATERAL_CONNECT` | `flags & (1<<1)` |
| 2 | Sensitive file | `BIT_SENSITIVE_FILE` | `flags & (1<<2)` |
| 3 | NS probe | `BIT_NS_PROBE` | `flags & (1<<3)` |
| 4 | Privesc | `BIT_PRIVESC` | `flags & (1<<4)` |
| 5 | Large transfer | `BIT_LARGE_TRANSFER` | `flags & (1<<5)` |
| 6 | fd redirect | `BIT_FD_REDIRECT` | `flags & (1<<6)` |
| 7 | Fork accel | `BIT_FORK_ACCEL` | `flags & (1<<7)` |

---

*End of CausalTrace Complete Design and Implementation Document.*
*Version: Final (April 2026). Total length: ~15,000 lines of specification.*
