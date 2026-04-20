# CausalTrace — Claude Code Session Context

## START HERE (every session)

1. Read `CausalTrace_Complete_Design_Document_1_.md` — this is the authoritative spec
2. Run the state check below to see what's actually on disk
3. Ask what needs to be worked on

```bash
# Run this at session start to see current state
find ~/causaltrace -name "*.py" -o -name "*.c" -o -name "*.h" \
  | grep -v venv | grep -v __pycache__ | sort

# Check line counts to see which files are stubs vs real
find ~/causaltrace -name "*.py" -o -name "*.c" -o -name "*.h" \
  | grep -v venv | grep -v __pycache__ \
  | xargs wc -l 2>/dev/null | sort -rn | head -30
```

## Project in one paragraph

eBPF-based container security system. Three tiers:
- **Tier 1** (kernel, eBPF C): stateless enforcement via bpf_send_signal. 5 handlers: fork
  acceleration, execve, file, privesc, dup2 fd-type invariant. Tail-call dispatcher with bigram
  CMS update. All in `kernel/` or `tier1/`.
- **Tier 2** (kernel + infra): Probe B (tcp_v4_connect kprobe), Probe C (fork/execve tracepoints),
  Docker event listener for ip_to_cgroup map. In `tier2/` and `infra/`.
- **Tier 3** (user-space Python): Sheaf Laplacian daemon. Signal extraction (d=74), CCA
  calibration, EMA dual-path detection, eigenmode analysis, semantic labels. In `tier3/`.

## Where everything is specified

| What you need | Where in the design doc |
|---------------|------------------------|
| All eBPF C code (exact) | Sections 6.1–6.9 |
| BPF map declarations | Section 6.2 |
| Dispatcher logic | Section 6.3 |
| All handlers | Sections 6.4–6.9 |
| Probe B (network) | Section 7 |
| Probe C (lineage) | Section 8 |
| Loader.py | Section 9 |
| Signal extractor (d=74) | Section (Tier 3 signal) |
| Calibration (CCA) | Section (Tier 3 calibration) |
| Sheaf detector | Section (Tier 3 detection) |
| ctypes struct layout | Appendix D |
| Verdict writer | Appendix E |
| Results analysis | Appendix F |
| BCC attachment patterns | Appendix D.3–D.4 |
| Struct size verification | Appendix D.5 — RUN THIS when debugging |
| Common pitfalls | Appendix B — read when something breaks |

## Hard rules — never violate these

- `behavior_state` has `bit_ts[8]` (per-bit timestamps), NOT a single `ts` field
- Signal vector is d=74. Invariant bits are NOT inside sheaf signal math
- `connect_sk_stash` is `BPF_MAP_TYPE_LRU_HASH`, not `BPF_MAP_TYPE_HASH`
- Two ring buffers: `alerts_rb` (64KB) and `telemetry_rb` (256KB) — separate
- Dispatcher cold path (sketch == NULL): do NOT return 0, still tail-call to handlers
- Noise syscalls (getpid/getuid/gettid/getppid/time/clock_gettime): skip bigram update
  but do NOT skip tail-call dispatch
- Top-24 syscall list includes: io_uring_enter(426), ptrace(101), memfd_create(319),
  bpf(321), unshare(272), mount(165), setns(308) — see Section 6.1 for full switch statement
- `pending_cgroup_inherit` map must exist for unshare(CLONE_NEWCGROUP) fix

## Sudo and environment

```bash
# Always activate venv before running Python
source ~/causaltrace/venv/bin/activate

# eBPF loading always needs sudo
sudo python3 tier1/loader.py   # or wherever loader is

# Check BPF verifier errors
sudo python3 tier1/loader.py 2>&1 | head -50

# See what's loaded
sudo bpftool prog list
sudo bpftool map list

# Live alerts
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## Debugging workflow

When something breaks:
1. Check Appendix B (common pitfalls) first
2. Run struct size verification from Appendix D.5
3. For BCC errors: look for `invalid mem access` → bounds check missing,
   `R_ unbounded` → loop needs #pragma unroll, `invalid indirect read` → need BPF_CORE_READ
4. For Python daemon errors: check ctypes struct layout matches C exactly (Appendix D)

## Testbed

```bash
docker compose up -d          # start containers
bash scripts/test_connectivity.sh   # verify all green

# Calibration (30 min normal traffic)
bash scripts/generate_normal_traffic.sh

# Run attacks
bash attacks/scenario_7_cross_container.sh   # the key one
bash attacks/run_all.sh
```

## What "done" looks like

The project is complete when:
- [ ] `sudo python3 tier1/loader.py` loads without BCC errors
- [ ] Scenarios 1–6 all produce KILL within 5μs (Tier 1)
- [ ] Scenario 7 produces an alert (novel-edge or sheaf) — this is the main contribution
- [ ] Calibration runs cleanly and produces `calibration/restriction_maps.npz`
- [ ] All 6 evaluation experiments have logged results in `results/causaltrace/`
- [ ] Struct size verification (Appendix D.5) passes with no mismatches
