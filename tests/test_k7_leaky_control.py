from __future__ import annotations

from dataclasses import replace

import numpy as np

from noticer_core.attacks.adaptive import (
    AdaptiveAttackDataset,
    AdaptiveAttackProtocol,
    AdaptiveAttackSplit,
    ObserverFamily,
    run_adaptive_attack_suite,
)
from noticer_core.attacks.leaky_control import (
    build_leaky_control,
    evaluate_leaky_control,
)


def fixture() -> tuple[AdaptiveAttackDataset, AdaptiveAttackSplit]:
    rng = np.random.default_rng(9)
    pair_count = 45
    labels = np.tile(np.array([0, 1], dtype=np.int8), pair_count)
    matrix = rng.normal(size=(pair_count * 2, 20))
    longitudinal = rng.normal(size=(pair_count * 2, 20, 2))
    dataset = AdaptiveAttackDataset(
        labels=labels,
        pair_ids=np.repeat([f"pair-{index}" for index in range(pair_count)], 2),
        family_ids=np.repeat(
            ["train-family"] * 15 + ["development-family"] * 15 + ["test-family"] * 15,
            2,
        ),
        session_ids=np.array(
            [
                f"session-{pair}-{side}"
                for pair in range(pair_count)
                for side in ("left", "right")
            ]
        ),
        views={
            ObserverFamily.CLAIM_ONLY: matrix.copy(),
            ObserverFamily.FULL_TRACE: matrix.copy(),
            ObserverFamily.SIDE_CHANNEL: matrix.copy(),
            ObserverFamily.SERVICE_COLLUSION: matrix.copy(),
            ObserverFamily.LONGITUDINAL: longitudinal,
        },
    )
    return dataset, AdaptiveAttackSplit(
        train=np.arange(0, 30),
        development=np.arange(30, 60),
        test=np.arange(60, 90),
    )


def test_all_twenty_attackers_detect_separated_leaky_control() -> None:
    protected, split = fixture()
    control = build_leaky_control(
        protected,
        source_dataset_sha256="a" * 64,
        amplitude=20.0,
    )
    predictions = run_adaptive_attack_suite(
        control.dataset,
        split,
        AdaptiveAttackProtocol(query_budget=40, longitudinal_t=16, seed=1729),
    )
    report = evaluate_leaky_control(predictions, minimum_auc=0.90)

    assert control.is_control
    assert control.artifact_namespace.startswith("controls/")
    assert report.detected
    assert len(report.auc_by_attacker) == 20
    assert not report.failed_attackers
    assert np.array_equal(control.dataset.labels, protected.labels)
    assert np.array_equal(control.dataset.pair_ids, protected.pair_ids)
    assert np.array_equal(control.dataset.family_ids, protected.family_ids)
    assert np.array_equal(control.dataset.session_ids, protected.session_ids)


def test_one_blind_attacker_invalidates_control_detection() -> None:
    protected, split = fixture()
    control = build_leaky_control(
        protected,
        source_dataset_sha256="b" * 64,
        amplitude=20.0,
    )
    predictions = list(
        run_adaptive_attack_suite(
            control.dataset,
            split,
            AdaptiveAttackProtocol(query_budget=40, longitudinal_t=16, seed=1729),
        )
    )
    predictions[0] = replace(
        predictions[0],
        scores=np.full(len(predictions[0].truth), 0.5),
    )

    report = evaluate_leaky_control(tuple(predictions), minimum_auc=0.90)

    assert not report.detected
    assert len(report.failed_attackers) == 1
