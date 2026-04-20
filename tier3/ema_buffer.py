# ema_buffer.py
import numpy as np
from typing import Dict


class EMASignalBuffer:
    """
    Guarded exponential moving average for slow-drip attack detection.

    Motivation:
      Low-and-slow exfiltration resets the bigram CMS each 5 s window, so
      no individual window exceeds the raw threshold. An EMA with small α
      accumulates drift over many windows, revealing the attack.

    Guard rationale:
      A plain EMA is *poisoned* by an attack in progress — the malicious
      signal feeds into the baseline and the detector goes blind. To prevent
      this, the EMA blend is **gated** on a global pristine-streak counter:

        - Each detection cycle, the detector calls `tick(pristine)` with
          True iff the cycle showed no anomalies of any kind.
        - The baseline is updated (α blend) only when the streak has been
          pristine for ≥ PRISTINE_CYCLES_MIN consecutive cycles.
        - During an attack (or immediately after), the streak resets to 0
          and the baseline is frozen at its last-known-good state. New
          telemetry flows through detection against that frozen baseline,
          so the drip attack cannot hide by drifting the EMA toward itself.

    Parameters:
      alpha = 0.02        →  DC gain 1.0; half-life ≈ 34 cycles (~170 s).
      PRISTINE_CYCLES_MIN = 6  →  30 s at the 5 s detection interval.
    """

    # 30 seconds at a 5 s detection interval. Codified as a class constant
    # so the daemon and tests can reference it without re-deriving.
    PRISTINE_CYCLES_MIN = 6

    def __init__(self, alpha: float = 0.02, d: int = 74):
        self.alpha = alpha
        self.d = d
        self._ema: Dict[int, np.ndarray] = {}
        self._pristine_streak: int = 0

    def is_frozen(self) -> bool:
        """True when streak < MIN, i.e. baseline updates are suspended."""
        return self._pristine_streak < self.PRISTINE_CYCLES_MIN

    def tick(self, pristine_this_cycle: bool) -> None:
        """Record this cycle's pristine flag. Call once per detection cycle."""
        if pristine_this_cycle:
            self._pristine_streak += 1
        else:
            self._pristine_streak = 0

    def update(self, cg_id: int, x_raw: np.ndarray) -> np.ndarray:
        """
        Seed-or-blend the per-container EMA.

        First sight of a container: seed baseline with x_raw (no choice —
        we have nothing else). Subsequent cycles: blend only when the
        global streak qualifies; otherwise freeze and return the last
        known-good baseline.

        Returns: current baseline signal vector, shape (d,).
        """
        if cg_id not in self._ema:
            # First observation: unavoidably seed. Streak is about global
            # system health, not per-container newness.
            self._ema[cg_id] = x_raw.copy()
        elif not self.is_frozen():
            self._ema[cg_id] = (
                self.alpha * x_raw + (1.0 - self.alpha) * self._ema[cg_id]
            )
        # else: frozen — keep the last-known-good baseline so that the
        # detector compares attack-cycle x_raw against pre-attack normals.
        return self._ema[cg_id].copy()

    def get(self, cg_id: int):
        return self._ema.get(cg_id, None)

    def reset(self, cg_id: int) -> None:
        """Drop a container's baseline (e.g., container was restarted)."""
        self._ema.pop(cg_id, None)

    def pristine_streak(self) -> int:
        return self._pristine_streak
