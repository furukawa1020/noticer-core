from __future__ import annotations

import numpy as np
import pytest

from noticer_core.attacks.k20_membership import (
    MembershipAttackDataset,
    MembershipAttackError,
    run_membership_smoke_attack,
)


def dataset(prefix: str) -> MembershipAttackDataset:
    member = np.tile([0.99, 0.01], (20, 1))
    nonmember = np.tile([0.55, 0.45], (20, 1))
    probabilities = np.vstack((member, nonmember))
    return MembershipAttackDataset(
        probabilities,
        np.zeros(40, dtype=int),
        np.asarray([1] * 20 + [0] * 20),
        np.asarray([f"{prefix}_{index:03d}" for index in range(40)]),
    )


def test_membership_smoke_attack_detects_deliberate_confidence_leak() -> None:
    result = run_membership_smoke_attack(dataset("train"), dataset("test"), seed=7)
    assert result.roc_auc == 1.0
    assert result.advantage == 1.0


def test_membership_smoke_attack_is_reproducible() -> None:
    first = run_membership_smoke_attack(dataset("train"), dataset("test"), seed=7)
    second = run_membership_smoke_attack(dataset("train"), dataset("test"), seed=7)
    np.testing.assert_array_equal(first.scores, second.scores)


def test_session_overlap_is_rejected() -> None:
    values = dataset("shared")
    with pytest.raises(MembershipAttackError, match="disjoint"):
        run_membership_smoke_attack(values, values, seed=7)


def test_non_normalized_probabilities_are_rejected() -> None:
    values = dataset("train")
    broken = MembershipAttackDataset(
        values.probabilities * 2,
        values.true_class_indices,
        values.membership,
        values.session_ids,
    )
    with pytest.raises(MembershipAttackError, match="sum to one"):
        broken.validate()
