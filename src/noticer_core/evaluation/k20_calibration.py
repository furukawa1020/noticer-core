"""Descriptive calibration metrics for held-out multiclass predictions."""

from dataclasses import dataclass

import numpy as np


@dataclass(frozen=True, slots=True)
class CalibrationMetrics:
    brier: float
    log_loss: float
    top_label_ece: float
    bin_counts: tuple[int, ...]


def evaluate_calibration(
    probabilities: np.ndarray, truth_indices: np.ndarray, *, bins: int = 10
) -> CalibrationMetrics:
    """Use the declared probability-column order and fixed-width confidence bins."""
    p = np.asarray(probabilities, dtype=float)
    truth = np.asarray(truth_indices)
    if p.ndim != 2 or not p.shape[0] or p.shape[1] < 2:
        raise ValueError("probabilities must have non-empty rows and at least two classes")
    if truth.shape != (len(p),) or truth.dtype.kind not in "iu":
        raise ValueError("truth must contain one integer class index per row")
    if np.any(truth < 0) or np.any(truth >= p.shape[1]):
        raise ValueError("truth index is outside the class order")
    if not np.isfinite(p).all() or np.any((p < 0) | (p > 1)):
        raise ValueError("probabilities must be finite and inside [0, 1]")
    if not np.allclose(p.sum(axis=1), 1, rtol=0, atol=1e-12):
        raise ValueError("probability rows must sum to one")
    if type(bins) is not int or not 1 <= bins <= 1000:
        raise ValueError("bins must be an integer inside [1, 1000]")
    predicted = p.argmax(axis=1)
    rows = np.arange(len(p))
    confidence = p[rows, predicted]
    actual = p[rows, truth]
    bin_index = np.minimum((confidence * bins).astype(int), bins - 1)
    totals = np.bincount(
        bin_index, weights=confidence - (predicted == truth), minlength=bins
    )
    residuals = p.copy()
    residuals[rows, truth] -= 1
    return CalibrationMetrics(
        brier=float(np.mean(np.sum(residuals**2, axis=1))),
        log_loss=float(-np.log(np.maximum(actual, np.finfo(float).eps)).mean()),
        top_label_ece=float(np.abs(totals).sum() / len(p)),
        bin_counts=tuple(int(count) for count in np.bincount(bin_index, minlength=bins)),
    )
