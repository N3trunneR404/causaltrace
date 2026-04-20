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
