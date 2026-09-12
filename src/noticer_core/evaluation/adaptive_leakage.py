"""Statistical evaluation for implementation-derived adaptive attacks."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from sklearn.metrics import brier_score_loss, roc_auc_score

from noticer_core.attacks.adaptive import (
    AdaptiveAttackPrediction,
    ModelFamily,
    ObserverFamily,
)


class LeakageEvaluationError(ValueError):
    """Raised when predictions cannot support the frozen evaluation."""


@dataclass(frozen=True)
class AttackLeakageMetrics:
    observer: ObserverFamily
    model: ModelFamily
    roc_auc: float
    roc_auc_ci95: tuple[float, float]
    advantage: float
    advantage_ci95: tuple[float, float]
    brier_score: float
    expected_calibration_error: float


@dataclass(frozen=True)
class ExcessLeakage:
    model: ModelFamily
    estimate: float
    ci95: tuple[float, float]


@dataclass(frozen=True)
class AdaptiveLeakageReport:
    attacks: tuple[AttackLeakageMetrics, ...]
    full_trace_excess: tuple[ExcessLeakage, ...]
    pointwise_trace_equal: bool
    implementation_claim_eligible: bool
    security_proof: bool = False


def evaluate_adaptive_leakage(
    predictions: tuple[AdaptiveAttackPrediction, ...],
    pair_ids: np.ndarray,
    *,
    bootstrap_samples: int,
    calibration_bins: int,
    seed: int,
    pointwise_trace_equal: bool,
) -> AdaptiveLeakageReport:
    """Evaluate attack scores without treating chance performance as proof."""
    if bootstrap_samples < 100:
        raise LeakageEvaluationError("at least 100 bootstrap samples are required")
    if calibration_bins < 2:
        raise LeakageEvaluationError("at least two calibration bins are required")
    indexed = {(item.observer, item.model): item for item in predictions}
    expected = {
        (observer, model) for observer in ObserverFamily for model in ModelFamily
    }
    if set(indexed) != expected:
        raise LeakageEvaluationError("the complete 5-by-4 attack matrix is required")

    reference = predictions[0]
    test_pairs = pair_ids[reference.test_indices]
    if len(test_pairs) != len(reference.truth):
        raise LeakageEvaluationError("pair ID length mismatch")
    for item in predictions:
        if not np.array_equal(item.test_indices, reference.test_indices):
            raise LeakageEvaluationError("attack test indices differ")
        if not np.array_equal(item.truth, reference.truth):
            raise LeakageEvaluationError("attack test labels differ")
        if len(item.scores) != len(item.truth) or np.any(
            (item.scores < 0.0) | (item.scores > 1.0)
        ):
            raise LeakageEvaluationError("attack scores must be probabilities")

    attacks = []
    bootstrap_auc: dict[tuple[ObserverFamily, ModelFamily], np.ndarray] = {}
    for key in sorted(expected, key=lambda value: (value[0].value, value[1].value)):
        item = indexed[key]
        samples = _paired_bootstrap_auc(
            item.truth,
            item.scores,
            test_pairs,
            bootstrap_samples,
            seed + list(ModelFamily).index(item.model),
        )
        bootstrap_auc[key] = samples
        auc = float(roc_auc_score(item.truth, item.scores))
        advantages = 2.0 * np.abs(samples - 0.5)
        attacks.append(
            AttackLeakageMetrics(
                observer=item.observer,
                model=item.model,
                roc_auc=auc,
                roc_auc_ci95=_interval(samples),
                advantage=2.0 * abs(auc - 0.5),
                advantage_ci95=_interval(advantages),
                brier_score=float(brier_score_loss(item.truth, item.scores)),
                expected_calibration_error=_ece(
                    item.truth,
                    item.scores,
                    calibration_bins,
                ),
            )
        )

    excess = []
    for model in ModelFamily:
        claim = indexed[(ObserverFamily.CLAIM_ONLY, model)]
        full = indexed[(ObserverFamily.FULL_TRACE, model)]
        estimate = float(
            roc_auc_score(full.truth, full.scores)
            - roc_auc_score(claim.truth, claim.scores)
        )
        paired_samples = (
            bootstrap_auc[(ObserverFamily.FULL_TRACE, model)]
            - bootstrap_auc[(ObserverFamily.CLAIM_ONLY, model)]
        )
        excess.append(
            ExcessLeakage(model=model, estimate=estimate, ci95=_interval(paired_samples))
        )

    return AdaptiveLeakageReport(
        attacks=tuple(attacks),
        full_trace_excess=tuple(excess),
        pointwise_trace_equal=pointwise_trace_equal,
        implementation_claim_eligible=pointwise_trace_equal,
    )


def _paired_bootstrap_auc(
    truth: np.ndarray,
    scores: np.ndarray,
    pair_ids: np.ndarray,
    samples: int,
    seed: int,
) -> np.ndarray:
    unique_pairs = np.unique(pair_ids)
    if len(unique_pairs) < 2:
        raise LeakageEvaluationError("at least two test pairs are required")
    by_pair = {pair: np.flatnonzero(pair_ids == pair) for pair in unique_pairs}
    rng = np.random.default_rng(seed)
    output = np.empty(samples, dtype=float)
    for index in range(samples):
        selected = rng.choice(unique_pairs, size=len(unique_pairs), replace=True)
        rows = np.concatenate([by_pair[pair] for pair in selected])
        if len(np.unique(truth[rows])) != 2:
            raise LeakageEvaluationError("a resampled pair lacks both private sides")
        output[index] = _binary_auc(truth[rows], scores[rows])
    return output


def _binary_auc(truth: np.ndarray, scores: np.ndarray) -> float:
    positive = scores[truth == 1]
    negative = scores[truth == 0]
    comparisons = positive[:, np.newaxis] - negative[np.newaxis, :]
    return float(np.mean(comparisons > 0) + 0.5 * np.mean(comparisons == 0))

def _ece(truth: np.ndarray, scores: np.ndarray, bins: int) -> float:
    edges = np.linspace(0.0, 1.0, bins + 1)
    total = len(scores)
    error = 0.0
    for index in range(bins):
        upper_inclusive = index == bins - 1
        selected = (scores >= edges[index]) & (
            (scores <= edges[index + 1])
            if upper_inclusive
            else (scores < edges[index + 1])
        )
        if np.any(selected):
            error += (
                float(np.mean(selected))
                * abs(float(np.mean(truth[selected])) - float(np.mean(scores[selected])))
            )
    if total == 0:
        raise LeakageEvaluationError("test predictions are empty")
    return error


def _interval(values: np.ndarray) -> tuple[float, float]:
    lower, upper = np.quantile(values, [0.025, 0.975])
    return float(lower), float(upper)


