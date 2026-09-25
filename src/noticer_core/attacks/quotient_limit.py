"""Independent empirical attackers for QuotientLimit finite trace distributions."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from sklearn.ensemble import (
    ExtraTreesClassifier,
    HistGradientBoostingClassifier,
    RandomForestClassifier,
)
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import balanced_accuracy_score, roc_auc_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from noticer_core.evaluation.splits import DatasetSplit


@dataclass(frozen=True, slots=True)
class BayesAttackResult:
    total_variation: float
    success_probability: float
    decisions: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class SamplingValidation:
    exact_probabilities: np.ndarray
    empirical_probabilities: np.ndarray
    confidence_intervals: np.ndarray
    pearson_chi_square: float
    degrees_of_freedom: int
    maximum_absolute_error: float


@dataclass(frozen=True, slots=True)
class AttackSuiteResult:
    metrics: dict[str, dict[str, float]]
    formal_bayes: BayesAttackResult
    empirical_total_variation: float
    empirical_bayes_success: float
    formal_empirical_consistent: bool
    privacy_supported_by_formal_bound: bool


def bayes_optimal_binary(
    probability_h0: np.ndarray,
    probability_h1: np.ndarray,
) -> BayesAttackResult:
    """Return the equal-prior Bayes attacker for two finite trace distributions."""
    left = _probability_vector(probability_h0)
    right = _probability_vector(probability_h1)
    if left.shape != right.shape:
        raise ValueError("finite distributions must have identical support")
    total_variation = float(0.5 * np.abs(left - right).sum())
    return BayesAttackResult(
        total_variation=total_variation,
        success_probability=0.5 * (1.0 + total_variation),
        decisions=tuple(int(value) for value in (right > left)),
    )


def validate_sampling(
    exact_probabilities: np.ndarray,
    sampled_outcomes: np.ndarray,
) -> SamplingValidation:
    """Compare samples with an exact distribution using intervals and Pearson GOF."""
    exact = _probability_vector(exact_probabilities)
    samples = np.asarray(sampled_outcomes, dtype=int)
    if samples.ndim != 1 or samples.size == 0:
        raise ValueError("sampled_outcomes must be a non-empty one-dimensional array")
    if np.any(samples < 0) or np.any(samples >= exact.size):
        raise ValueError("sampled outcome lies outside exact support")
    counts = np.bincount(samples, minlength=exact.size).astype(float)
    empirical = counts / samples.size
    expected = exact * samples.size
    active = expected > 0
    chi_square = float(np.sum(((counts[active] - expected[active]) ** 2) / expected[active]))
    standard_error = np.sqrt(empirical * (1.0 - empirical) / samples.size)
    intervals = np.column_stack(
        (
            np.maximum(0.0, empirical - 1.96 * standard_error),
            np.minimum(1.0, empirical + 1.96 * standard_error),
        )
    )
    return SamplingValidation(
        exact_probabilities=exact,
        empirical_probabilities=empirical,
        confidence_intervals=intervals,
        pearson_chi_square=chi_square,
        degrees_of_freedom=max(int(active.sum()) - 1, 0),
        maximum_absolute_error=float(np.max(np.abs(empirical - exact))),
    )


def run_quotient_limit_attack_suite(
    features: np.ndarray,
    labels: np.ndarray,
    session_ids: np.ndarray,
    split: DatasetSplit,
    *,
    exact_h0: np.ndarray,
    exact_h1: np.ndarray,
    sampled_h0: np.ndarray,
    sampled_h1: np.ndarray,
    seed: int,
    consistency_tolerance: float,
    formal_privacy_tv_limit: float,
) -> AttackSuiteResult:
    """Run ML baselines while keeping the finite Bayes attacker authoritative."""
    x = np.asarray(features, dtype=float)
    y = np.asarray(labels, dtype=int)
    sessions = np.asarray(session_ids)
    if x.ndim != 2 or y.shape != (x.shape[0],) or sessions.shape != y.shape:
        raise ValueError("features, labels, and sessions have incompatible shapes")
    if set(np.unique(y)) != {0, 1}:
        raise ValueError("binary labels 0 and 1 are required")
    if consistency_tolerance < 0 or not 0 <= formal_privacy_tv_limit <= 1:
        raise ValueError("invalid validation threshold")
    _require_session_disjoint(sessions, split)

    models = {
        "logistic_regression": Pipeline(
            [
                ("scale", StandardScaler()),
                ("classifier", LogisticRegression(max_iter=500, random_state=seed)),
            ]
        ),
        "random_forest": RandomForestClassifier(n_estimators=64, random_state=seed, n_jobs=1),
        "extra_trees": ExtraTreesClassifier(n_estimators=64, random_state=seed, n_jobs=1),
        "hist_gradient_boosting": HistGradientBoostingClassifier(max_iter=100, random_state=seed),
    }
    train = split.train_indices
    test = split.test_indices
    metrics: dict[str, dict[str, float]] = {}
    for name, model in models.items():
        model.fit(x[train], y[train])
        probabilities = model.predict_proba(x[test])[:, 1]
        predictions = (probabilities >= 0.5).astype(int)
        metrics[name] = {
            "roc_auc": float(roc_auc_score(y[test], probabilities)),
            "balanced_accuracy": float(balanced_accuracy_score(y[test], predictions)),
        }

    formal = bayes_optimal_binary(exact_h0, exact_h1)
    empirical_h0 = validate_sampling(exact_h0, sampled_h0).empirical_probabilities
    empirical_h1 = validate_sampling(exact_h1, sampled_h1).empirical_probabilities
    empirical_tv = float(0.5 * np.abs(empirical_h0 - empirical_h1).sum())
    return AttackSuiteResult(
        metrics=metrics,
        formal_bayes=formal,
        empirical_total_variation=empirical_tv,
        empirical_bayes_success=0.5 * (1.0 + empirical_tv),
        formal_empirical_consistent=abs(empirical_tv - formal.total_variation)
        <= consistency_tolerance,
        privacy_supported_by_formal_bound=formal.total_variation <= formal_privacy_tv_limit,
    )


def _probability_vector(values: np.ndarray) -> np.ndarray:
    probabilities = np.asarray(values, dtype=float)
    if probabilities.ndim != 1 or probabilities.size == 0:
        raise ValueError("probabilities must be a non-empty vector")
    if not np.all(np.isfinite(probabilities)) or np.any(probabilities < 0):
        raise ValueError("probabilities must be finite and non-negative")
    if not np.isclose(probabilities.sum(), 1.0, rtol=0.0, atol=1e-12):
        raise ValueError("probabilities must sum to one")
    return probabilities


def _require_session_disjoint(session_ids: np.ndarray, split: DatasetSplit) -> None:
    partitions = [
        set(session_ids[split.train_indices]),
        set(session_ids[split.validation_indices]),
        set(session_ids[split.test_indices]),
    ]
    if (
        partitions[0] & partitions[1]
        or partitions[0] & partitions[2]
        or partitions[1] & partitions[2]
    ):
        raise ValueError("attack split must be session-disjoint")
