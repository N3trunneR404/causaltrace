# trust_promoter.py
"""
Phase 3 — L4-stability trust promotion.

Runs in the Tier 3 daemon loop. On each scan:
  1. Walks `connection_context` (keyed by sock pointer) and groups bytes
     and duration by client IP.
  2. For each client IP, advances `client_trust` state:
       UNKNOWN    -> OBSERVED    (any connection observed)
       OBSERVED   -> CALIBRATED  (a single flow >= TRUST_BYTES_MIN bytes AND
                                  >= TRUST_DURATION_NS)
       BURNED     -> BURNED      (terminal; never demote or re-promote)

The kernel side updates byte counters inline on the hot TCP path; Tier 3
owns the promotion policy so it stays auditable and reconfigurable.

Only CALIBRATED clients get Case B (alert-only) treatment in maybe_kill.
UNKNOWN / OBSERVED / BURNED get Case C (kill) on soft anomalies.
"""

import ctypes
import time
from dataclasses import dataclass
from typing import Dict, Tuple

# Trust levels — must match kernel constants in causaltrace_bcc.c
TRUST_UNKNOWN = 0
TRUST_OBSERVED = 1
TRUST_CALIBRATED = 2
TRUST_BURNED = 255

# Thresholds — override via config in Phase 9
TRUST_BYTES_MIN = 5120           # 5 KiB in a single flow
TRUST_DURATION_NS = 1_000_000_000  # 1 second


@dataclass
class PromotionMetrics:
    """Returned by scan_and_promote(). Logged by the daemon each cycle."""
    scanned: int = 0          # connection_context entries walked
    observed_new: int = 0     # UNKNOWN -> OBSERVED transitions this cycle
    calibrated_new: int = 0   # OBSERVED -> CALIBRATED transitions this cycle
    burned_seen: int = 0      # entries whose IP is already TRUST_BURNED (skipped)
    ips_with_flows: int = 0   # distinct client IPs touched this cycle


class TrustPromoter:
    """
    Holds references to the BPF maps needed for trust promotion.
    Instantiated once by the daemon; scan_and_promote() is called every cycle.
    """

    def __init__(self, bpf_obj,
                 bytes_min: int = TRUST_BYTES_MIN,
                 duration_ns: int = TRUST_DURATION_NS):
        self.bpf = bpf_obj
        self.bytes_min = bytes_min
        self.duration_ns = duration_ns

    def _read_trust(self, ip_u32_net: int) -> int:
        """Return current trust for an IP (u32 network-byte-order), or UNKNOWN."""
        try:
            val = self.bpf["client_trust"][ctypes.c_uint32(ip_u32_net)]
            return int(val.value)
        except KeyError:
            return TRUST_UNKNOWN

    def _write_trust(self, ip_u32_net: int, level: int) -> None:
        self.bpf["client_trust"][ctypes.c_uint32(ip_u32_net)] = ctypes.c_uint8(level)

    def scan_and_promote(self) -> PromotionMetrics:
        """
        Walk connection_context and advance client_trust per the L4 policy.
        Returns a PromotionMetrics snapshot.
        """
        m = PromotionMetrics()
        now_ns = time.monotonic_ns()

        # Aggregate per-IP across all their flows. A single IP may have many
        # concurrent connections; the policy triggers if ANY flow exceeds the
        # minima (not the sum across flows), because an attacker might spray
        # many tiny probes that sum >5 KB but no individual flow is stable.
        per_ip_best: Dict[int, Tuple[int, int]] = {}  # ip -> (max_bytes, max_duration_ns)

        try:
            ctx_table = self.bpf["connection_context"]
        except Exception:
            return m  # map missing (e.g., during shutdown); nothing to do

        for _sk_ptr, cc in ctx_table.items():
            m.scanned += 1
            ip = int(cc.client_ip)
            if ip == 0:
                continue
            bytes_total = int(cc.bytes_in) + int(cc.bytes_out)
            age_ns = now_ns - int(cc.established_ns)
            if age_ns < 0:
                age_ns = 0
            # Alternative interpretation: use last_active - established as "duration".
            # We want the flow to have BEEN ALIVE for >=1s, which established→now
            # captures even if the client stopped sending halfway. Paper: we err
            # on the side of slightly easier promotion; the byte threshold is the
            # real gate against brief scanners.
            prev_bytes, prev_dur = per_ip_best.get(ip, (0, 0))
            per_ip_best[ip] = (max(prev_bytes, bytes_total),
                               max(prev_dur, age_ns))

        m.ips_with_flows = len(per_ip_best)

        for ip, (best_bytes, best_dur) in per_ip_best.items():
            current = self._read_trust(ip)

            if current == TRUST_BURNED:
                m.burned_seen += 1
                continue

            if current == TRUST_CALIBRATED:
                continue  # already at terminal positive state

            if current == TRUST_UNKNOWN:
                # Promote to OBSERVED as soon as we see any flow for this IP.
                self._write_trust(ip, TRUST_OBSERVED)
                m.observed_new += 1
                current = TRUST_OBSERVED

            # current == TRUST_OBSERVED: check L4 stability
            if (current == TRUST_OBSERVED
                    and best_bytes >= self.bytes_min
                    and best_dur >= self.duration_ns):
                self._write_trust(ip, TRUST_CALIBRATED)
                m.calibrated_new += 1

        return m
