"""Identity attack metrics."""

from __future__ import annotations

import numpy as np
from sklearn.metrics import accuracy_score, balanced_accuracy_score, f1_score


def identity_metrics(y_true: np.ndarray, y_pred: np.ndarray, n_subjects: int) -> dict[str, float]:
    if n_subjects < 2:
        raise ValueError("normalized advantage requires at least two subjects")
    chance = 1.0 / n_subjects
    accuracy = float(accuracy_score(y_true, y_pred))
    return {
        "accuracy": accuracy,
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "chance_accuracy": chance,
        "normalized_attack_advantage": (accuracy - chance) / (1.0 - chance),
    }
