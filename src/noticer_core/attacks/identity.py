"""Logistic-regression identity attacker and permuted-label control."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import balanced_accuracy_score, confusion_matrix
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from noticer_core.data.contracts import WindowDataset
from noticer_core.evaluation.metrics import identity_metrics
from noticer_core.evaluation.splits import DatasetSplit


@dataclass(frozen=True, slots=True)
class AttackResult:
    metrics: dict[str, float | int]
    predictions: pd.DataFrame
    confusion: np.ndarray
    labels: tuple[str, ...]


def _model(c_value: float, max_iter: int, seed: int) -> Pipeline:
    return Pipeline([("scale", StandardScaler()), ("classifier", LogisticRegression(
        C=c_value, max_iter=max_iter, random_state=seed, solver="lbfgs"))])


def run_identity_attack(
    dataset: WindowDataset,
    split: DatasetSplit,
    *,
    regularization_candidates: list[float],
    max_iter: int,
    seed: int,
    permute_labels: bool = False,
) -> AttackResult:
    """Select C on validation only, then evaluate untouched test windows."""
    if not regularization_candidates or any(value <= 0 for value in regularization_candidates):
        raise ValueError("regularization_candidates must contain positive values")
    y = dataset.subject_ids.astype(str).copy()
    if permute_labels:
        rng = np.random.default_rng(seed)
        for indices in (split.train_indices, split.validation_indices, split.test_indices):
            y[indices] = rng.permutation(y[indices])
    best_c = regularization_candidates[0]
    best_score = -1.0
    for c_value in regularization_candidates:
        candidate = _model(c_value, max_iter, seed)
        candidate.fit(dataset.features[split.train_indices], y[split.train_indices])
        score = balanced_accuracy_score(
            y[split.validation_indices],
            candidate.predict(dataset.features[split.validation_indices]),
        )
        if score > best_score:
            best_c, best_score = c_value, float(score)
    model = _model(best_c, max_iter, seed)
    model.fit(dataset.features[split.train_indices], y[split.train_indices])
    predicted = model.predict(dataset.features[split.test_indices])
    probabilities = model.predict_proba(dataset.features[split.test_indices])
    labels = tuple(sorted(np.unique(dataset.subject_ids.astype(str))))
    truth = y[split.test_indices]
    metrics: dict[str, float | int] = identity_metrics(truth, predicted, len(labels))
    metrics.update({
        "number_of_subjects": len(labels),
        "number_of_train_windows": len(split.train_indices),
        "number_of_validation_windows": len(split.validation_indices),
        "number_of_test_windows": len(split.test_indices),
        "selected_regularization_c": best_c,
    })
    metadata = dataset.metadata_frame().iloc[split.test_indices].reset_index(drop=True)
    predictions = metadata.rename(columns={"subject_id": "subject_id_original"})
    predictions.insert(0, "subject_id_true", truth)
    predictions.insert(1, "subject_id_pred", predicted)
    predictions["correct"] = truth == predicted
    for index, class_name in enumerate(model.named_steps["classifier"].classes_):
        predictions[f"prob_{class_name}"] = probabilities[:, index]
    return AttackResult(
        metrics=metrics,
        predictions=predictions,
        confusion=confusion_matrix(truth, predicted, labels=labels),
        labels=labels,
    )
