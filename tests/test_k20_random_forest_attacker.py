from __future__ import annotations

import numpy as np
import pytest

from noticer_core.attacks.k20_identity import (
    IdentityAttackContractError,
    LabelledAttackPartition,
    UnlabelledAttackPartition,
    execute_identity_attacker,
)
from noticer_core.attacks.k20_random_forest import RandomForestIdentityAttacker


def labelled(prefix: str) -> LabelledAttackPartition:
    features = np.asarray(
        [[-2.0, -1.0], [-1.5, -0.5], [-1.0, -1.5], [1.0, 1.5], [1.5, 0.5], [2.0, 1.0]]
    )
    labels = np.asarray(["person_a001"] * 3 + ["person_b001"] * 3)
    sessions = np.asarray([f"{prefix}_{index}" for index in range(6)])
    return LabelledAttackPartition(features, labels, sessions)


def test_random_forest_runs_through_common_contract() -> None:
    attacker = RandomForestIdentityAttacker(n_estimators=32, seed=5)
    test = UnlabelledAttackPartition(
        np.asarray([[-1.7, -0.8], [1.7, 0.8]]),
        np.asarray(["window_0001", "window_0002"]),
        np.asarray(["test_a", "test_b"]),
    )
    output = execute_identity_attacker(attacker, labelled("train"), labelled("valid"), test)
    assert output.predicted_labels.tolist() == ["person_a001", "person_b001"]
    assert attacker.selected_depth in attacker.depth_candidates


def test_random_forest_is_exactly_reproducible() -> None:
    test = UnlabelledAttackPartition(
        np.asarray([[-1.7, -0.8], [1.7, 0.8]]),
        np.asarray(["window_0001", "window_0002"]),
        np.asarray(["test_a", "test_b"]),
    )
    outputs = [
        execute_identity_attacker(
            RandomForestIdentityAttacker(n_estimators=32, seed=5),
            labelled("train"),
            labelled("valid"),
            test,
        ).probabilities
        for _ in range(2)
    ]
    np.testing.assert_array_equal(outputs[0], outputs[1])


@pytest.mark.parametrize(
    "attacker",
    [
        RandomForestIdentityAttacker(depth_candidates=()),
        RandomForestIdentityAttacker(depth_candidates=(0,)),
        RandomForestIdentityAttacker(n_estimators=0),
    ],
)
def test_invalid_forest_contract_is_rejected(attacker: RandomForestIdentityAttacker) -> None:
    with pytest.raises(IdentityAttackContractError):
        attacker.fit(labelled("train"), labelled("valid"))
