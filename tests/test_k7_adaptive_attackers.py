from __future__ import annotations

import numpy as np
import pytest

from noticer_core.attacks.adaptive import (
    AdaptiveAttackDataset,
    AdaptiveAttackError,
    AdaptiveAttackProtocol,
    AdaptiveAttackSplit,
    ModelFamily,
    ObserverFamily,
    run_adaptive_attack_suite,
)


def fixture() -> tuple[AdaptiveAttackDataset, AdaptiveAttackSplit]:
    rng = np.random.default_rng(7)
    pair_count = 45
    labels = np.tile(np.array([0, 1], dtype=np.int8), pair_count)
    signal = labels[:, np.newaxis] * 2.0 - 1.0
    matrix = signal + rng.normal(0.0, 0.15, size=(pair_count * 2, 20))
    longitudinal = signal[:, :, np.newaxis] + rng.normal(
        0.0, 0.15, size=(pair_count * 2, 20, 2)
    )
    pair_ids = np.repeat([f"pair-{index}" for index in range(pair_count)], 2)
    family_ids = np.repeat(
        ["family-train"] * 15 + ["family-development"] * 15 + ["family-test"] * 15,
        2,
    )
    session_ids = np.array(
        [f"session-{pair}-{side}" for pair in range(pair_count) for side in ("left", "right")]
    )
    split = AdaptiveAttackSplit(
        train=np.arange(0, 30),
        development=np.arange(30, 60),
        test=np.arange(60, 90),
    )
    dataset = AdaptiveAttackDataset(
        labels=labels,
        pair_ids=pair_ids,
        family_ids=family_ids,
        session_ids=session_ids,
        views={
            ObserverFamily.CLAIM_ONLY: matrix,
            ObserverFamily.FULL_TRACE: matrix,
            ObserverFamily.SIDE_CHANNEL: matrix,
            ObserverFamily.SERVICE_COLLUSION: matrix,
            ObserverFamily.LONGITUDINAL: longitudinal,
        },
    )
    return dataset, split


def test_frozen_matrix_runs_all_twenty_attackers_reproducibly() -> None:
    dataset, split = fixture()
    protocol = AdaptiveAttackProtocol(query_budget=40, longitudinal_t=16, seed=1729)

    first = run_adaptive_attack_suite(dataset, split, protocol)
    second = run_adaptive_attack_suite(dataset, split, protocol)

    assert len(first) == len(ObserverFamily) * len(ModelFamily) == 20
    assert {(item.observer, item.model) for item in first} == {
        (observer, model) for observer in ObserverFamily for model in ModelFamily
    }
    paired = zip(first, second, strict=True)
    assert all(np.array_equal(left.scores, right.scores) for left, right in paired)
    assert all(len(item.scores) == len(split.test) for item in first)


def test_split_overlap_is_rejected_before_training() -> None:
    dataset, split = fixture()
    overlapping = AdaptiveAttackSplit(
        train=split.train,
        development=split.development,
        test=np.concatenate((split.test, np.array([0]))),
    )
    with pytest.raises(AdaptiveAttackError, match="overlap"):
        run_adaptive_attack_suite(
            dataset,
            overlapping,
            AdaptiveAttackProtocol(query_budget=40, longitudinal_t=16, seed=1729),
        )


def test_missing_observer_and_short_sequence_fail_closed() -> None:
    dataset, split = fixture()
    views = dict(dataset.views)
    del views[ObserverFamily.SERVICE_COLLUSION]
    missing = AdaptiveAttackDataset(
        labels=dataset.labels,
        pair_ids=dataset.pair_ids,
        family_ids=dataset.family_ids,
        session_ids=dataset.session_ids,
        views=views,
    )
    with pytest.raises(AdaptiveAttackError, match="five"):
        run_adaptive_attack_suite(
            missing,
            split,
            AdaptiveAttackProtocol(query_budget=40, longitudinal_t=16, seed=1729),
        )


