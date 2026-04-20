# ringbuf_monitor.py
"""
Phase 4 — Ring buffer backpressure monitor.

The kernel owns two ring buffers:
  * alerts_rb    (64 KiB)   — critical kill/detection alerts
  * telemetry_rb (256 KiB)  — connection events, exec lineage

Kernel emit paths funnel through emit_alert / emit_telemetry. Telemetry
is proactively shed at >=90% fill (via bpf_ringbuf_query); alerts are
never shed but their failures are counted. All bumps land in the
`ringbuf_stats` BPF_ARRAY (u64 x 8) at fixed indices:

    [0] telemetry_shed     (proactively dropped)
    [1] telemetry_fail     (ringbuf_output returned < 0)
    [2] telemetry_ok       (successfully emitted)
    [3] alerts_fail        (ringbuf_output returned < 0 — LOST ALERT)
    [4] alerts_ok          (successfully emitted)
    [5] alerts_near_full   (>=80% at emit time)

The daemon reads this map each detection cycle and logs non-zero deltas.
Any non-zero alerts_fail is treated as a critical observability event.
"""

import ctypes
import logging
from dataclasses import dataclass, field
from typing import Dict

log = logging.getLogger("causaltrace.ringbuf")

# Must match kernel layout in causaltrace_bcc.c
RB_IDX = {
    'telemetry_shed':    0,
    'telemetry_fail':    1,
    'telemetry_ok':      2,
    'alerts_fail':       3,
    'alerts_ok':         4,
    'alerts_near_full':  5,
}


@dataclass
class RingBufDelta:
    """Difference between two consecutive scans. Values are non-negative ints."""
    telemetry_shed:    int = 0
    telemetry_fail:    int = 0
    telemetry_ok:      int = 0
    alerts_fail:       int = 0
    alerts_ok:         int = 0
    alerts_near_full:  int = 0

    def has_concern(self) -> bool:
        """True when any anomalous signal is present (a drop, a near-full)."""
        return (self.telemetry_shed
                or self.telemetry_fail
                or self.alerts_fail
                or self.alerts_near_full) > 0

    def has_alert_loss(self) -> bool:
        """True iff we lost at least one alert — this must never be silent."""
        return self.alerts_fail > 0


class RingBufferMonitor:
    """Snapshots `ringbuf_stats` each cycle and reports per-cycle deltas."""

    def __init__(self, bpf_obj):
        self.bpf = bpf_obj
        self._prev: Dict[str, int] = {name: 0 for name in RB_IDX}
        self._totals: Dict[str, int] = {name: 0 for name in RB_IDX}

    def _read_snapshot(self) -> Dict[str, int]:
        snap = {name: 0 for name in RB_IDX}
        try:
            tbl = self.bpf["ringbuf_stats"]
        except Exception:
            return snap  # map missing (e.g., during shutdown)
        for name, idx in RB_IDX.items():
            try:
                val = tbl[ctypes.c_uint32(idx)]
                snap[name] = int(val.value)
            except KeyError:
                snap[name] = 0
        return snap

    def scan(self) -> RingBufDelta:
        """Return delta since last scan; update internal prev+totals."""
        cur = self._read_snapshot()
        delta = RingBufDelta(**{
            name: max(0, cur[name] - self._prev[name])
            for name in RB_IDX
        })
        self._prev = cur
        for name in RB_IDX:
            self._totals[name] = cur[name]
        return delta

    def totals(self) -> Dict[str, int]:
        """Cumulative counters since daemon start (last snapshot)."""
        return dict(self._totals)
