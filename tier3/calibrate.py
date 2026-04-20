# calibrate.py
import numpy as np
from sklearn.decomposition import PCA
from sklearn.cross_decomposition import CCA
import json, pickle
from pathlib import Path
from typing import Dict, List, Tuple
from collections import defaultdict

try:
    from signal_extractor import BigramSketch, CalibrationStats, extract_signal_74
    from whitener import FeatureWhitener
except ImportError:
    from .signal_extractor import BigramSketch, CalibrationStats, extract_signal_74
    from .whitener import FeatureWhitener

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
    chi-squared distribution. 4-sigma → ≤0.003% FPR.

    Dimensionality choice (k=15):
      Earlier versions used k=50, but with typical calibration windows
      (T ≈ 60–120) the empirical edge covariance at k=50 is rank-deficient,
      inflating Mahalanobis distances at runtime (false positives). k=15
      keeps the coupling subspace well-conditioned at realistic T, captures
      the dominant coupling modes (explained variance >95% in sanity runs),
      and tightens the chi-squared 4σ threshold — χ²_15 has a sharper tail
      than χ²_50, so the same σ multiplier gates with stricter semantics.
    """

    def __init__(self, d: int = 74, k: int = 15):
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
                try:
                    cca.fit(X_u_l, X_v_l)
                except Exception as e:
                    print(f"  Skipping edge ({u},{v}) lag={lag}: CCA failed ({e})")
                    continue

                F_u = cca.x_rotations_.T  # (k, d) = (15, 74)
                F_v = cca.y_rotations_.T  # (k, d) = (15, 74)
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
