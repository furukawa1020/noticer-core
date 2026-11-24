from __future__ import annotations

import numpy as np
import pytest

from noticer_core.attacks.k20_identity import (
    IdentityAttackContractError,
    LabelledAttackPartition,
    UnlabelledAttackPartition,
    execute_identity_attacker,
)
from noticer_core.attacks.k20_logistic import LogisticIdentityAttacker


def labelled(offset: float, prefix: str) -> LabelledAttackPartition:
    features = np.asarray(
        [[-2.0 + offset, -1.0], [-1.5 + offset, -0.8], [1.5 + offset, 0.8], [2.0 + offset, 1.0]]
    )
    return LabelledAttackPartition(
        features,
        np.asarray(["person_a001", "person_a001", "person_b001", "person_b001"]),
        np.asarray([f"{prefix}_{index}" for index in range(4)]),
    )


def test_logistic_attacker_runs_through_common_contract() -> None:
    attacker = LogisticIdentityAttacker(seed=7)
    test = UnlabelledAttackPartition(
        np.asarray([[-1.8, -0.9], [1.8, 0.9]]),
        np.asarray(["window_0001", "window_0002"]),
        np.asarray(["test_session_a", "test_session_b"]),
    )
    result = execute_identity_attacker(
        attacker, labelled(0.0, "train"), labelled(0.1, "validation"), test
    )
    assert result.predicted_labels.tolist() == ["person_a001", "person_b001"]
    assert attacker.selected_c in attacker.candidates


def test_logistic_attacker_is_seed_reproducible() -> None:
    test = UnlabelledAttackPartition(
        np.asarray([[-1.8, -0.9], [1.8, 0.9]]),
        np.asarray(["window_0001", "window_0002"]),
        np.asarray(["test_session_a", "test_session_b"]),
    )
    outputs = []
    for _ in range(2):
        outputs.append(
            execute_identity_attacker(
                LogisticIdentityAttacker(seed=7),
                labelled(0.0, "train"),
                labelled(0.1, "validation"),
                test,
            ).probabilities
        )
    np.testing.assert_array_equal(outputs[0], outputs[1])


@pytest.mark.parametrize("candidates", [(), (0.0,), (float("nan"),)])
def test_invalid_regularization_candidates_fail_closed(candidates: tuple[float, ...]) -> None:
    attacker = LogisticIdentityAttacker(candidates=candidates)
    with pytest.raises(IdentityAttackContractError, match="finite and positive"):
        attacker.fit(labelled(0.0, "train"), labelled(0.1, "validation"))


def test_prediction_before_fit_is_rejected() -> None:
    test = UnlabelledAttackPartition(
        np.ones((2, 2)),
        np.asarray(["window_0001", "window_0002"]),
        np.asarray(["test_a", "test_b"]),
    )
    with pytest.raises(IdentityAttackContractError, match="fitted"):
        LogisticIdentityAttacker().predict(test)
