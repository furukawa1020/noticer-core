from __future__ import annotations

import numpy as np
import pytest

from noticer_core.attacks.adaptive import (
    AdaptiveAttackPrediction,
    ModelFamily,
    ObserverFamily,
)
from noticer_core.evaluation.adaptive_leakage import (
    LeakageEvaluationError,
    evaluate_adaptive_leakage,
)


def predictions() -> tuple[AdaptiveAttackPrediction, ...]:
    pair_count = 20
    truth = np.tile(np.array([0, 1], dtype=np.int8), pair_count)
    indices = np.arange(pair_count * 2)
    output = []
    for observer in ObserverFamily:
        for model in ModelFamily:
            if observer is ObserverFamily.FULL_TRACE:
                scores = np.where(truth == 1, 0.9, 0.1)
            else:
                scores = np.full(len(truth), 0.5)
            output.append(
                AdaptiveAttackPrediction(
                    observer=observer,
                    model=model,
                    truth=truth.copy(),
                    scores=scores,
                    predicted=(scores >= 0.5).astype(np.int8),
                    test_indices=indices.copy(),
                )
            )
    return tuple(output)


def test_metrics_and_paired_excess_are_reproducible() -> None:
    pair_ids = np.repeat([f"pair-{index}" for index in range(20)], 2)
    kwargs = {
        "bootstrap_samples": 200,
        "calibration_bins": 10,
        "seed": 1729,
        "pointwise_trace_equal": True,
    }

    first = evaluate_adaptive_leakage(predictions(), pair_ids, **kwargs)
    second = evaluate_adaptive_leakage(predictions(), pair_ids, **kwargs)

    assert first == second
    assert len(first.attacks) == 20
    assert len(first.full_trace_excess) == 4
    assert all(item.estimate == pytest.approx(0.5) for item in first.full_trace_excess)
    assert all(item.ci95 == pytest.approx((0.5, 0.5)) for item in first.full_trace_excess)
    assert not first.security_proof
    assert first.implementation_claim_eligible


def test_pointwise_failure_cannot_be_overwritten_by_chance_scores() -> None:
    pair_ids = np.repeat([f"pair-{index}" for index in range(20)], 2)
    report = evaluate_adaptive_leakage(
        predictions(),
        pair_ids,
        bootstrap_samples=100,
        calibration_bins=5,
        seed=7,
        pointwise_trace_equal=False,
    )

    assert not report.pointwise_trace_equal
    assert not report.implementation_claim_eligible
    assert not report.security_proof


def test_incomplete_attack_matrix_is_rejected() -> None:
    pair_ids = np.repeat([f"pair-{index}" for index in range(20)], 2)
    with pytest.raises(LeakageEvaluationError, match="complete"):
        evaluate_adaptive_leakage(
            predictions()[:-1],
            pair_ids,
            bootstrap_samples=100,
            calibration_bins=5,
            seed=7,
            pointwise_trace_equal=True,
        )
