"""Frozen cross-session linkability metrics for K20."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score, roc_curve


class LinkabilityMetricError(ValueError):
    """Raised when scores cannot support a linkability claim."""


@dataclass(frozen=True, slots=True)
class LinkabilityMetrics:
    roc_auc: float
    average_precision: float
    equal_error_rate: float
    tpr_at_fpr: float
    fpr_limit: float
    advantage: float
    pair_count: int
    positive_count: int


def cross_session_linkability_metrics(
    truth: np.ndarray,
    scores: np.ndarray,
    *,
    fpr_limit: float = 0.01,
) -> LinkabilityMetrics:
    """Evaluate same-subject pair scores without selecting a test threshold."""
    labels = np.asarray(truth, dtype=int)
    values = np.asarray(scores, dtype=float)
    if labels.ndim != 1 or values.shape != labels.shape or not len(labels):
        raise LinkabilityMetricError("truth and scores must be aligned non-empty vectors")
    if set(np.unique(labels)) != {0, 1}:
        raise LinkabilityMetricError("linkability truth must contain zero and one")
    if not np.isfinite(values).all():
        raise LinkabilityMetricError("linkability scores must be finite")
    if not 0 <= fpr_limit <= 1:
        raise LinkabilityMetricError("fpr_limit must be inside [0, 1]")

    fpr, tpr, _ = roc_curve(labels, values)
    false_negative_rate = 1.0 - tpr
    eer_index = int(np.argmin(np.abs(fpr - false_negative_rate)))
    allowed = np.flatnonzero(fpr <= fpr_limit)
    constrained_tpr = float(np.max(tpr[allowed])) if len(allowed) else 0.0
    auc = float(roc_auc_score(labels, values))
    return LinkabilityMetrics(
        roc_auc=auc,
        average_precision=float(average_precision_score(labels, values)),
        equal_error_rate=float((fpr[eer_index] + false_negative_rate[eer_index]) / 2.0),
        tpr_at_fpr=constrained_tpr,
        fpr_limit=fpr_limit,
        advantage=2.0 * abs(auc - 0.5),
        pair_count=len(labels),
        positive_count=int(labels.sum()),
    )

