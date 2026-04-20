# Threat model

This document states what CausalTrace is designed to detect and stop,
and what it explicitly **does not** defend against. Operators deploying
outside a lab should read this in full.

## Who we defend

1. **Workloads** running inside monitored containers (ct-web, ct-api,
   ct-db in the testbed, or equivalents in a real deployment).
2. **The host kernel**, against lateral movement and privilege escalation
   that originates from a compromised container.
3. **The sheaf of calibrated communications** — i.e. we assume the
   operator ran calibration on representative normal traffic; anomalies
   are defined against that baseline.

## Actor models we cover

| Actor                                  | Primary detection path |
|----------------------------------------|-----------------------|
| External attacker, arbitrary IP        | `tid_client_ip` → `TRUST_UNKNOWN` → Case C on any soft anomaly; Tier 1 invariants fire independently; TC drop severs the flow |
| External attacker, CALIBRATED IP       | One grace event (Case B), then strict invariant burns the IP to `TRUST_BURNED` (sticky) → Case C thereafter |
| Container→container lateral movement   | Novel-edge (Tier 2) if the `(src_cg, dst_cg, port)` isn't calibrated; sheaf anomaly (Tier 3) if it is; Tier 1 invariants on any payload |
| Node-local attacker without root       | No client IP; `tid_client_ip` empty → UNKNOWN → Case C; Tier 1 invariants still fire |
| Slow-drip exfiltration                 | Guarded EMA (α=0.02, 30 s pristine streak) accumulates the shift without being poisoned by the attack |
| OOD / zero-day (e.g. memfd_create)     | Strict invariant on the rare syscall + sheaf geometric deviation |

## Out of scope

1. **Root on the host.** Any kernel-resident defense can be unloaded or
   rewritten by root. CausalTrace is no exception. In a multi-tenant
   deployment, host root must be treated as out-of-scope by definition.
2. **BPF verifier bugs in the host kernel.** We trust the kernel to
   reject verifier-rejected programs; downstream CVEs in the verifier
   are upstream's problem.
3. **NAT-shared IP.** The trust model is per-IPv4. Attackers sharing an
   egress IP with a legitimate calibrated client inherit the Case B
   grace. This is a noted limitation.
4. **Subtle coincidences.** An attacker who (a) uses only a calibrated
   network edge, (b) triggers zero invariants, (c) never exceeds the
   4σ Mahalanobis threshold and (d) stays quiet long enough for guarded
   EMA to integrate them can evade detection. The compound gate + EMA
   guard make this hard; no system rules it out completely.
5. **Denial of service on the daemon itself.** If the Tier 3 consumer
   is deliberately slowed (OOM, CPU starvation), `ringbuf_stats` will
   surface lost alerts but the alerts themselves will be gone. The
   `alerts_rb` is intentionally never proactively shed so the
   observability signal is preserved until the consumer recovers.

## Trust boundaries

* **Container → daemon.** One-way: the container emits syscalls; the
  kernel enforces. The container never writes into Tier 3 state.
* **Daemon → kernel.** The daemon mutates BPF maps (`verdict_map`,
  `client_trust`, `drop_ip_list`). These mutations are idempotent and
  TTL-bounded: false positives heal without manual intervention.
* **Calibration directory.** Treated as part of the daemon's TCB.
  Operators should gate calibration artifacts through
  `calibration_driver.validate_calibration` and pin the directory
  permissions to `root:root 0600`.

## Disclosure

If you find a false-negative against a realistic threat that this
document does not explicitly list as out-of-scope, that is a bug —
open an issue with the trace + the calibration artifacts and we will
investigate.
