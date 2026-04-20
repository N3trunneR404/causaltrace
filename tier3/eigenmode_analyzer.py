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
