from __future__ import annotations

import numpy as np
import pytest

from noticer_core.attacks.k20_identity import (
    AttackFamily,
    IdentityAttackContractError,
    IdentityAttackPrediction,
    LabelledAttackPartition,
    UnlabelledAttackPartition,
    execute_identity_attacker,
)


class FakeAttacker:
    attacker_id = "fake-v1"
    family = AttackFamily.LOGISTIC_REGRESSION

    def fit(self, training: LabelledAttackPartition, validation: LabelledAttackPartition) -> None:
        self.classes = tuple(sorted(np.unique(training.labels.astype(str))))

    def predict(self, test: UnlabelledAttackPartition) -> IdentityAttackPrediction:
        probabilities = np.tile([0.75, 0.25], (len(test.features), 1))
        return IdentityAttackPrediction(
            self.attacker_id,
            self.family,
            self.classes,
            probabilities,
            np.repeat(self.classes[0], len(test.features)),
            test.row_ids.copy(),
        )


def labelled(prefix: str) -> LabelledAttackPartition:
    return LabelledAttackPartition(
        features=np.asarray([[0.0, 1.0], [1.0, 0.0]]),
        labels=np.asarray(["person_a001", "person_b001"]),
        session_ids=np.asarray([f"{prefix}_session_a", f"{prefix}_session_b"]),
    )


def test_common_interface_hides_test_truth_and_preserves_row_order() -> None:
    test = UnlabelledAttackPartition(
        features=np.asarray([[0.2, 0.8], [0.8, 0.2]]),
        row_ids=np.asarray(["window_0001", "window_0002"]),
        session_ids=np.asarray(["test_session_a", "test_session_b"]),
    )
    prediction = execute_identity_attacker(
        FakeAttacker(), labelled("train"), labelled("validation"), test
    )
    assert prediction.probabilities.shape == (2, 2)
    np.testing.assert_array_equal(prediction.row_ids, test.row_ids)


def test_session_overlap_is_rejected_before_model_fit() -> None:
    training = labelled("shared")
    validation = labelled("shared")
    test = UnlabelledAttackPartition(
        np.ones((2, 2)),
        np.asarray(["window_0001", "window_0002"]),
        np.asarray(["test_a", "test_b"]),
    )
    with pytest.raises(IdentityAttackContractError, match="session overlap"):
        execute_identity_attacker(FakeAttacker(), training, validation, test)


def test_malformed_probabilities_are_rejected() -> None:
    prediction = IdentityAttackPrediction(
        "fake-v1",
        AttackFamily.LOGISTIC_REGRESSION,
        ("person_a001", "person_b001"),
        np.asarray([[0.8, 0.8]]),
        np.asarray(["person_a001"]),
        np.asarray(["window_0001"]),
    )
    with pytest.raises(IdentityAttackContractError, match="sum to one"):
        prediction.validate()


def test_duplicate_test_row_ids_are_rejected() -> None:
    test = UnlabelledAttackPartition(
        np.ones((2, 2)),
        np.asarray(["window_0001", "window_0001"]),
        np.asarray(["test_a", "test_b"]),
    )
    with pytest.raises(IdentityAttackContractError, match="unique"):
        test.validate()
