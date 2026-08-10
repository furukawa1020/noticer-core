"""Counterfactual distinguishers for Action-Equivalent Trace Privacy."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import balanced_accuracy_score, f1_score, roc_auc_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from noticer_core.data.aetp_synthetic import CounterfactualTraceDataset
from noticer_core.evaluation.splits import DatasetSplit


@dataclass(frozen=True, slots=True)
class AetpAttackResult:
    metrics: dict[str, dict[str, float | int | bool]]
    predictions: pd.DataFrame


def _model(c_value: float, max_iter: int, seed: int) -> Pipeline:
    return Pipeline(
        [
            ("scale", StandardScaler()),
            (
                "classifier",
                LogisticRegression(
                    C=c_value,
                    max_iter=max_iter,
                    random_state=seed,
                    solver="lbfgs",
                ),
            ),
        ]
    )


def _fit_view(
    features: np.ndarray,
    labels: np.ndarray,
    split: DatasetSplit,
    candidates: list[float],
    max_iter: int,
    seed: int,
) -> tuple[np.ndarray, np.ndarray, float]:
    best_c = candidates[0]
    best_auc = -1.0
    for c_value in candidates:
        candidate = _model(c_value, max_iter, seed)
        candidate.fit(features[split.train_indices], labels[split.train_indices])
        validation = candidate.predict_proba(features[split.validation_indices])[:, 1]
        auc = float(roc_auc_score(labels[split.validation_indices], validation))
        if auc > best_auc:
            best_c, best_auc = c_value, auc
    model = _model(best_c, max_iter, seed)
    model.fit(features[split.train_indices], labels[split.train_indices])
    probabilities = model.predict_proba(features[split.test_indices])[:, 1]
    predictions = (probabilities >= 0.5).astype(int)
    return probabilities, predictions, best_c


def _paired_excess_interval(
    labels: np.ndarray,
    pair_ids: np.ndarray,
    claim_scores: np.ndarray,
    full_scores: np.ndarray,
    *,
    samples: int,
    seed: int,
) -> tuple[float, float]:
    rng = np.random.default_rng(seed)
    unique_pairs = np.unique(pair_ids)
    differences = np.empty(samples, dtype=float)
    for sample in range(samples):
        selected = rng.choice(unique_pairs, size=len(unique_pairs), replace=True)
        indices = np.concatenate([np.flatnonzero(pair_ids == pair_id) for pair_id in selected])
        differences[sample] = roc_auc_score(labels[indices], full_scores[indices]) - roc_auc_score(
            labels[indices], claim_scores[indices]
        )
    lower, upper = np.quantile(differences, [0.025, 0.975])
    return float(lower), float(upper)


def run_aetp_attack(
    dataset: CounterfactualTraceDataset,
    split: DatasetSplit,
    *,
    regularization_candidates: list[float],
    max_iter: int,
    bootstrap_samples: int,
    seed: int,
    safe_excess_upper_bound: float,
    negative_control_min_auc: float,
) -> AetpAttackResult:
    """Compare claim-only and full-trace attackers on untouched sessions."""
    if not regularization_candidates or any(value <= 0 for value in regularization_candidates):
        raise ValueError("regularization candidates must be positive")
    if bootstrap_samples < 1:
        raise ValueError("bootstrap_samples must be positive")
    labels = dataset.world_labels
    test = split.test_indices
    claim_scores, claim_predicted, claim_c = _fit_view(
        dataset.claim_features,
        labels,
        split,
        regularization_candidates,
        max_iter,
        seed,
    )
    claim_auc = float(roc_auc_score(labels[test], claim_scores))
    predictions = split.manifest.iloc[test].reset_index(drop=True).copy()
    predictions["claim_only_score"] = claim_scores
    predictions["claim_only_predicted"] = claim_predicted
    metrics: dict[str, dict[str, float | int | bool]] = {
        "claim_only": {
            "roc_auc": claim_auc,
            "balanced_accuracy": float(balanced_accuracy_score(labels[test], claim_predicted)),
            "macro_f1": float(f1_score(labels[test], claim_predicted, average="macro")),
            "selected_regularization_c": claim_c,
        }
    }
    views = ("aetp", "timing_control", "payload_control", "retry_control")
    for offset, name in enumerate(views, start=1):
        scores, predicted, selected_c = _fit_view(
            dataset.view(name),
            labels,
            split,
            regularization_candidates,
            max_iter,
            seed + offset,
        )
        auc = float(roc_auc_score(labels[test], scores))
        lower, upper = _paired_excess_interval(
            labels[test],
            dataset.pair_ids[test],
            claim_scores,
            scores,
            samples=bootstrap_samples,
            seed=seed + 100 + offset,
        )
        is_safe = (
            upper <= safe_excess_upper_bound
            if name == "aetp"
            else auc >= negative_control_min_auc
        )
        metrics[name] = {
            "roc_auc": auc,
            "balanced_accuracy": float(balanced_accuracy_score(labels[test], predicted)),
            "macro_f1": float(f1_score(labels[test], predicted, average="macro")),
            "excess_auc": auc - claim_auc,
            "excess_auc_ci95_lower": lower,
            "excess_auc_ci95_upper": upper,
            "selected_regularization_c": selected_c,
            "criterion_passed": is_safe,
        }
        predictions[f"{name}_score"] = scores
        predictions[f"{name}_predicted"] = predicted
    metrics["protocol"] = {
        "n_test_worlds": len(test),
        "n_test_pairs": len(np.unique(dataset.pair_ids[test])),
        "all_criteria_passed": all(bool(metrics[name]["criterion_passed"]) for name in views),
    }
    return AetpAttackResult(metrics=metrics, predictions=predictions)
