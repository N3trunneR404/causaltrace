# calibration_driver.py
"""
Phase 5C — Calibration artifact validator.

A production run depends on the calibration directory containing
consistent, well-conditioned learned parameters. This module is the
gatekeeper between calibration and enforcement: it opens every artifact,
checks shapes and invariants, and returns a pass/fail report. The daemon
refuses to run in enforce mode unless this validator returns CLEAN.

Usage (library):
    from calibration_driver import validate_calibration
    report = validate_calibration("./calibration")
    if not report.clean:
        sys.exit(f"calibration invalid: {report.summary()}")

Usage (CLI):
    python3 -m tier3.calibration_driver ./calibration
    (exit 0 on CLEAN, 1 on FAIL)

Checks performed:
  * Required files exist (pca.pkl, whiteners.pkl, edge_thresholds.json,
    global_threshold.json, calibrated_edges.json, restriction_maps.npz).
  * PCA is fitted and explained variance ≥ PCA_MIN_EXPLAINED (0.90 default).
  * Each per-container whitener has a d=74-shaped mean/std.
  * ≥ 2 calibrated edges (otherwise the sheaf is trivial).
  * CCA restriction maps have the expected (k, d) shape (pulled from
    the SheafCalibrator defaults: k=15, d=74).
  * Every edge threshold is finite and > 0.
  * global_threshold is finite and > 0.
  * Every edge_cov_inv (if present) is symmetric and has all positive
    eigenvalues (i.e. positive-definite), otherwise Mahalanobis is
    meaningless at runtime.

The report is deliberately verbose — when calibration fails, the
operator wants one log line per broken invariant, not an opaque boolean.
"""

import argparse
import json
import pickle
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

import numpy as np

# Make tier3/ importable for unpickling artefacts that were pickled
# with bare module names (e.g. "whitener.FeatureWhitener").
_THIS_DIR = str(Path(__file__).resolve().parent)
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

try:
    from calibrate import SheafCalibrator
except ImportError:
    from .calibrate import SheafCalibrator


PCA_MIN_EXPLAINED = 0.90
REQUIRED_FILES = [
    "pca.pkl",
    "whiteners.pkl",
    "edge_thresholds.json",
    "global_threshold.json",
    "calibrated_edges.json",
    "restriction_maps.npz",
]


@dataclass
class ValidationReport:
    ok:       List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors:   List[str] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not self.errors

    def summary(self) -> str:
        return (f"{len(self.ok)} checks passed, "
                f"{len(self.warnings)} warnings, "
                f"{len(self.errors)} errors")

    def dump(self) -> str:
        lines = ["Calibration validation report", "-" * 40]
        for m in self.ok:       lines.append(f"  [ok]    {m}")
        for m in self.warnings: lines.append(f"  [warn]  {m}")
        for m in self.errors:   lines.append(f"  [FAIL]  {m}")
        lines.append("-" * 40)
        lines.append("RESULT: " + ("CLEAN" if self.clean else "FAIL"))
        lines.append(self.summary())
        return "\n".join(lines)


def _check_required_files(calpath: Path, r: ValidationReport) -> bool:
    all_present = True
    for fname in REQUIRED_FILES:
        fp = calpath / fname
        if fp.exists():
            r.ok.append(f"file present: {fname}")
        else:
            r.errors.append(f"missing required file: {fname}")
            all_present = False
    return all_present


def _check_pca(calpath: Path, r: ValidationReport) -> None:
    try:
        with open(calpath / "pca.pkl", "rb") as f:
            pca = pickle.load(f)
    except Exception as e:
        r.errors.append(f"pca.pkl unreadable: {e}")
        return
    if not hasattr(pca, "explained_variance_ratio_"):
        r.errors.append("pca.pkl is not a fitted PCA object")
        return
    explained = float(pca.explained_variance_ratio_.sum())
    if explained >= PCA_MIN_EXPLAINED:
        r.ok.append(f"PCA explained variance {explained:.3f} ≥ {PCA_MIN_EXPLAINED}")
    else:
        r.errors.append(
            f"PCA explained variance {explained:.3f} < {PCA_MIN_EXPLAINED} "
            "(calibration window too short or bigram signal too sparse)"
        )


def _check_whiteners(calpath: Path, r: ValidationReport, d_expected: int) -> None:
    try:
        with open(calpath / "whiteners.pkl", "rb") as f:
            whiteners = pickle.load(f)
    except Exception as e:
        r.errors.append(f"whiteners.pkl unreadable: {e}")
        return
    if not whiteners:
        r.errors.append("whiteners.pkl contains no containers")
        return
    for cg_id, w in whiteners.items():
        mean = getattr(w, "mean", None)
        std  = getattr(w, "std", None)
        if mean is None or std is None:
            r.errors.append(f"whitener[{cg_id}] missing mean/std (not fitted)")
            continue
        if mean.shape != (d_expected,) or std.shape != (d_expected,):
            r.errors.append(
                f"whitener[{cg_id}] shape mismatch: mean={mean.shape} "
                f"std={std.shape} expected ({d_expected},)"
            )
            continue
        if np.any(std <= 0):
            r.warnings.append(f"whitener[{cg_id}] has non-positive std entries")
    r.ok.append(f"whiteners: {len(whiteners)} container(s) validated")


def _check_edges_and_thresholds(calpath: Path, r: ValidationReport) -> int:
    try:
        with open(calpath / "calibrated_edges.json") as f:
            edges = json.load(f)
        with open(calpath / "edge_thresholds.json") as f:
            thresholds = json.load(f)
    except Exception as e:
        r.errors.append(f"edges/thresholds unreadable: {e}")
        return 0

    if len(edges) < 2:
        r.errors.append(f"only {len(edges)} calibrated edge(s); need ≥ 2 "
                        "for a non-trivial sheaf")
    else:
        r.ok.append(f"calibrated_edges: {len(edges)}")

    bad = [k for k, v in thresholds.items() if not (np.isfinite(v) and v > 0)]
    if bad:
        r.errors.append(f"non-positive or NaN edge thresholds: {bad[:5]}"
                        + (f" (+{len(bad)-5} more)" if len(bad) > 5 else ""))
    else:
        r.ok.append(f"edge_thresholds: {len(thresholds)} all finite and > 0")
    return len(edges)


def _check_global_threshold(calpath: Path, r: ValidationReport) -> None:
    try:
        with open(calpath / "global_threshold.json") as f:
            g = json.load(f).get("global", None)
    except Exception as e:
        r.errors.append(f"global_threshold.json unreadable: {e}")
        return
    if g is None:
        r.errors.append("global_threshold missing 'global' key")
    elif not (np.isfinite(g) and g > 0):
        r.errors.append(f"global_threshold non-positive or NaN: {g}")
    else:
        r.ok.append(f"global_threshold = {g:.4f}")


def _check_restriction_maps(calpath: Path, r: ValidationReport,
                            k_expected: int, d_expected: int) -> None:
    try:
        data = np.load(str(calpath / "restriction_maps.npz"))
    except Exception as e:
        r.errors.append(f"restriction_maps.npz unreadable: {e}")
        return
    if len(data.files) == 0:
        r.errors.append("restriction_maps.npz is empty")
        return
    bad_shape = []
    for name in data.files:
        mat = data[name]
        if mat.shape != (k_expected, d_expected):
            bad_shape.append((name, mat.shape))
    if bad_shape:
        r.errors.append(
            f"restriction matrices with wrong shape "
            f"(expected ({k_expected}, {d_expected})): "
            + ", ".join(f"{n}={s}" for n, s in bad_shape[:5])
        )
    else:
        r.ok.append(f"restriction_maps: {len(data.files)} entries, "
                    f"all shape ({k_expected}, {d_expected})")


def _check_cov_inv_psd(calpath: Path, r: ValidationReport) -> None:
    """edge_cov_inv is optional (written by recalibrate_thresholds.py).
    When present, each matrix must be symmetric and positive-definite."""
    covpath = calpath / "edge_cov_inv.npz"
    if not covpath.exists():
        r.warnings.append("edge_cov_inv.npz absent — runtime Mahalanobis "
                          "will fall back to L2 norms")
        return
    data = np.load(str(covpath))
    failures = []
    for name in data.files:
        m = data[name]
        if m.ndim != 2 or m.shape[0] != m.shape[1]:
            failures.append((name, "not square"))
            continue
        if not np.allclose(m, m.T, atol=1e-6):
            failures.append((name, "not symmetric"))
            continue
        eigs = np.linalg.eigvalsh(m)
        if eigs.min() <= 0:
            failures.append((name, f"min eigenvalue {eigs.min():.3e} ≤ 0"))
    if failures:
        r.errors.append(
            "edge_cov_inv not positive-definite: "
            + ", ".join(f"{n}({reason})" for n, reason in failures[:5])
        )
    else:
        r.ok.append(f"edge_cov_inv: {len(data.files)} matrices all PSD")


def validate_calibration(cal_dir: str,
                         k_expected: int = None,
                         d_expected: int = None) -> ValidationReport:
    """Run all checks. Defaults k=15, d=74 per SheafCalibrator()."""
    r = ValidationReport()
    if k_expected is None or d_expected is None:
        defaults = SheafCalibrator()
        k_expected = k_expected or defaults.k
        d_expected = d_expected or defaults.d

    calpath = Path(cal_dir)
    if not calpath.is_dir():
        r.errors.append(f"calibration dir not found: {cal_dir}")
        return r

    if not _check_required_files(calpath, r):
        return r  # no point running further checks

    _check_pca(calpath, r)
    _check_whiteners(calpath, r, d_expected)
    _check_edges_and_thresholds(calpath, r)
    _check_global_threshold(calpath, r)
    _check_restriction_maps(calpath, r, k_expected, d_expected)
    _check_cov_inv_psd(calpath, r)
    return r


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        description="Validate a CausalTrace calibration directory.")
    p.add_argument("path", help="path to calibration directory")
    p.add_argument("--k", type=int, default=None,
                   help="expected CCA dimension (default: from SheafCalibrator)")
    p.add_argument("--d", type=int, default=None,
                   help="expected signal dimension (default: 74)")
    args = p.parse_args(argv)

    report = validate_calibration(args.path, args.k, args.d)
    print(report.dump())
    return 0 if report.clean else 1


if __name__ == "__main__":
    sys.exit(main())
