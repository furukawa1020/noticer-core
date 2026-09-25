from __future__ import annotations

import numpy as np

from noticer_core.attacks.quotient_limit import (
    bayes_optimal_binary,
    run_quotient_limit_attack_suite,
    validate_sampling,
)
from noticer_core.evaluation.splits import DatasetSplit


def test_bayes_attacker_matches_half_one_plus_tv() -> None:
    result = bayes_optimal_binary(np.array([0.75, 0.25]), np.array([0.25, 0.75]))
    assert result.total_variation == 0.5
    assert result.success_probability == 0.75
    assert result.decisions == (0, 1)


def test_sampling_validation_reports_frequency_interval_and_gof() -> None:
    result = validate_sampling(np.array([0.5, 0.5]), np.array([0, 1] * 100))
    np.testing.assert_allclose(result.empirical_probabilities, [0.5, 0.5])
    assert result.pearson_chi_square == 0.0
    assert result.degrees_of_freedom == 1
    assert result.maximum_absolute_error == 0.0
    assert np.all(result.confidence_intervals[:, 0] <= 0.5)
    assert np.all(result.confidence_intervals[:, 1] >= 0.5)


def test_suite_runs_all_models_and_keeps_formal_bayes_authoritative() -> None:
    rng = np.random.default_rng(91)
    features = []
    labels = []
    sessions = []
    for session in range(12):
        label = session % 2
        for _ in range(8):
            features.append(rng.normal(label * 1.5, 0.4, size=3))
            labels.append(label)
            sessions.append(f"session-{session}")
    split = DatasetSplit(
        train_indices=np.arange(0, 64),
        validation_indices=np.arange(64, 80),
        test_indices=np.arange(80, 96),
        manifest=None,
    )
    result = run_quotient_limit_attack_suite(
        np.asarray(features),
        np.asarray(labels),
        np.asarray(sessions),
        split,
        exact_h0=np.array([0.5, 0.5]),
        exact_h1=np.array([0.5, 0.5]),
        sampled_h0=np.array([0, 1] * 200),
        sampled_h1=np.array([1, 0] * 200),
        seed=7,
        consistency_tolerance=0.02,
        formal_privacy_tv_limit=0.0,
    )
    assert set(result.metrics) == {
        "logistic_regression",
        "random_forest",
        "extra_trees",
        "hist_gradient_boosting",
    }
    assert result.formal_bayes.success_probability == 0.5
    assert result.formal_empirical_consistent
    assert result.privacy_supported_by_formal_bound


def test_suite_rejects_session_overlap() -> None:
    features = np.arange(24, dtype=float).reshape(8, 3)
    labels = np.array([0, 1] * 4)
    sessions = np.array(["shared", "shared", "a", "b", "c", "d", "e", "f"])
    split = DatasetSplit(
        train_indices=np.array([0, 2, 3, 4]),
        validation_indices=np.array([1, 5]),
        test_indices=np.array([6, 7]),
        manifest=None,
    )
    try:
        run_quotient_limit_attack_suite(
            features,
            labels,
            sessions,
            split,
            exact_h0=np.array([1.0]),
            exact_h1=np.array([1.0]),
            sampled_h0=np.array([0]),
            sampled_h1=np.array([0]),
            seed=1,
            consistency_tolerance=0.1,
            formal_privacy_tv_limit=0.0,
        )
    except ValueError as error:
        assert "session-disjoint" in str(error)
    else:
        raise AssertionError("overlapping sessions must be rejected")
