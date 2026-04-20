# Architecture

Short overview. For the full specification see
`CausalTrace_Complete_Design_Document(1).md` and
`CausalTrace_Definitive_Architecture_vFinal.md` at the repo root.

## Three tiers

**Tier 1 — strict invariants (eBPF).** A tail-call dispatcher in
`kernel/causaltrace_bcc.c` routes each syscall into one of five
handlers (dup2 fd-type, execve path, fork acceleration, sensitive
write, rare-syscall Top-24). A handler that observes a physical
invariant violation calls `maybe_kill(cg, case_id)` which chooses
between four enforcement cases:

| Case | When                                            | Action |
|------|-------------------------------------------------|--------|
| A    | strict invariant fired (e.g. dup2 socket→stdio) | SIGKILL + BURN trust + TC drop attacker IP |
| B    | soft anomaly, client IP is `TRUST_CALIBRATED`   | alert only (grace) |
| C    | soft anomaly, client IP is untrusted            | SIGKILL + TC drop |
| D    | the attacker is us (self-inflicted)             | SIGKILL |

Case B is the "trusted workload's first free mistake" rule. Any strict
invariant (Case A) burns the client IP to `TRUST_BURNED`, which is
sticky — subsequent events from that IP downgrade from B to C.

**Tier 2 — network + lineage (eBPF).**

* `tcp_v4_connect` kprobe → novel-edge detection against the calibrated
  `(src_cg, dst_cg, dst_port)` set.
* `inet_csk_accept` kretprobe → populates `cgroup_current_client` and
  per-TID `tid_client_ip` so syscalls can be attributed to the client.
* `sched_process_fork` / `sched_process_exec` tracepoints → lineage +
  inherited-sin behavior-bit propagation.
* `tcp_sendmsg` / `tcp_recvmsg` probes → L4 byte accumulation on a
  per-socket `connection_context`, read by the L4-stability trust
  promoter.
* TC classifier (`clsact` direct-action) on the container's veth →
  `drop_ip_list` lookup; matches get `TC_ACT_SHOT`. Flows from burned
  IPs are severed at the veth before they reach the container.

**Tier 3 — sheaf Laplacian (Python).**

* `signal_extractor.extract_signal_74` produces a 74-dim per-container
  vector per 5 s window: 3 entropy metrics + 50 PCA components of the
  bigram CMS + 20 top-marginal bigrams + 1 syscall rate.
* `SheafCalibrator` learns per-container whitening, per-edge CCA
  restriction maps at three temporal lags (k=15), per-edge Mahalanobis
  covariance inverse, and a global Rayleigh-quotient threshold — all
  at 4σ.
* `SheafDetector` at runtime: extracts signals, looks up calibrated
  edges, computes raw and EMA edge energies, emits alerts that the
  `EnforcementEngine` translates into BPF map updates.
* `TrustPromoter` walks `connection_context` each cycle and advances
  `client_trust` per the L4-stability policy (≥5120 B AND ≥1 s flow).
* `RingBufferMonitor` reads `ringbuf_stats` each cycle and surfaces
  backpressure / lost alerts.
* `CalibrationDriver.validate_calibration` gatekeeps the move from
  calibration to enforcement.

## Why a sheaf?

A sheaf over a graph assigns a signal space to each vertex and a
restriction map to each edge; the global section space is the kernel of
the resulting Laplacian. We learn restriction maps from normal traffic
and then, at runtime, measure **how far current signals are from being
a global section**. Cross-container lateral movement produces edge
residuals even when no single container's signal looks anomalous in
isolation — that is the core paper claim.

## Data flow

```
container syscalls
       │
       ▼
  ┌──────────────────┐ kill decisions  ┌──────────────────┐
  │ Tier 1 handlers  │◀────────────────│ Compound Gate    │
  └──────────────────┘                 └──────────────────┘
       │ bigram CMS                      ▲
       ▼                                 │ client_trust (IP→u8)
  ┌──────────────────┐                   │ drop_ip_list
  │ bigram_sketch_map│                   │
  └──────────────────┘                   │
       │                                 │
       ▼                                 │
  ┌──────────────────┐  verdict          │
  │ Tier 3 daemon    │──────────────────▶│
  └──────────────────┘                   │
       ▲                                 │
       │ connection_context              │
       │ (bytes_in, bytes_out, age)      │
  ┌──────────────────┐                   │
  │ tcp_sendmsg /    │                   │
  │ tcp_recvmsg      │───────────────────┘
  └──────────────────┘
```

## What lives where

* Hot path stays in the kernel. Tier 3's only enforcement surface is
  BPF-map updates; it never issues signals directly.
* Calibration state is on disk under `calibration/`; only well-formed
  artifacts (validated by `calibration_driver`) are loaded at startup.
* Supervisor + preflight + cgroup-snapshot keep the daemon
  restart-stable and observable.
