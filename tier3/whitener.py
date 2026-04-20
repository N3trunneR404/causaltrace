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
