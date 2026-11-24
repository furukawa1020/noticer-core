from __future__ import annotations

import numpy as np
import pytest

from noticer_core.attacks.k20_gradient_boosting import GradientBoostingIdentityAttacker
from noticer_core.attacks.k20_identity import (
    IdentityAttackContractError,
    LabelledAttackPartition,
    UnlabelledAttackPartition,
    execute_identity_attacker,
)


def labelled(prefix: str) -> LabelledAttackPartition:
    rng = np.random.default_rng(3 if prefix == "train" else 4)
    left = rng.normal(loc=-2.0, scale=0.2, size=(20, 2))
    right = rng.normal(loc=2.0, scale=0.2, size=(20, 2))
    return LabelledAttackPartition(
        np.vstack((left, right)),
        np.asarray(["person_a001"] * 20 + ["person_b001"] * 20),
        np.asarray([f"{prefix}_{index:03d}" for index in range(40)]),
    )


def test_boosting_attacker_runs_through_common_contract() -> None:
    attacker = GradientBoostingIdentityAttacker(max_iter=30, min_samples_leaf=2, seed=5)
    test = UnlabelledAttackPartition(
        np.asarray([[-2.0, -2.0], [2.0, 2.0]]),
        np.asarray(["window_0001", "window_0002"]),
        np.asarray(["test_a", "test_b"]),
    )
    output = execute_identity_attacker(attacker, labelled("train"), labelled("valid"), test)
    assert output.predicted_labels.tolist() == ["person_a001", "person_b001"]
    assert attacker.selected_leaves in attacker.leaf_candidates


def test_boosting_is_seed_reproducible() -> None:
    test = UnlabelledAttackPartition(
        np.asarray([[-2.0, -2.0], [2.0, 2.0]]),
        np.asarray(["window_0001", "window_0002"]),
        np.asarray(["test_a", "test_b"]),
    )
    outputs = [
        execute_identity_attacker(
            GradientBoostingIdentityAttacker(max_iter=30, min_samples_leaf=2, seed=5),
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
        GradientBoostingIdentityAttacker(leaf_candidates=()),
        GradientBoostingIdentityAttacker(leaf_candidates=(1,)),
        GradientBoostingIdentityAttacker(max_iter=0),
    ],
)
def test_invalid_boosting_contract_is_rejected(
    attacker: GradientBoostingIdentityAttacker,
) -> None:
    with pytest.raises(IdentityAttackContractError):
        attacker.fit(labelled("train"), labelled("valid"))
