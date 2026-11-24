from __future__ import annotations

import numpy as np
import pytest

from noticer_core.data.contracts import WindowDataset
from noticer_core.data.k20_permutation_control import (
    PermutationControlError,
    break_identity_correspondence,
)
from noticer_core.data.k20_positive_control import (
    PositiveControlConfig,
    generate_positive_control,
)


def source() -> WindowDataset:
    return generate_positive_control(
        PositiveControlConfig(subjects=6, sessions_per_subject=3), seed=10
    )


def test_control_preserves_features_sessions_and_class_balance() -> None:
    original = source()
    broken = break_identity_correspondence(original, seed=20)
    np.testing.assert_array_equal(broken.features, original.features)
    np.testing.assert_array_equal(broken.session_ids, original.session_ids)
    original_counts = np.unique(original.subject_ids, return_counts=True)[1]
    broken_counts = np.unique(broken.subject_ids, return_counts=True)[1]
    np.testing.assert_array_equal(np.sort(broken_counts), np.sort(original_counts))


def test_each_original_subject_changes_label_across_sessions() -> None:
    original = source()
    broken = break_identity_correspondence(original, seed=20)
    for subject in np.unique(original.subject_ids):
        labels = np.unique(broken.subject_ids[original.subject_ids == subject])
        assert len(labels) == 3


def test_permutation_is_seeded_and_deterministic() -> None:
    original = source()
    first = break_identity_correspondence(original, seed=20)
    second = break_identity_correspondence(original, seed=20)
    third = break_identity_correspondence(original, seed=21)
    np.testing.assert_array_equal(first.subject_ids, second.subject_ids)
    assert not np.array_equal(first.subject_ids, third.subject_ids)


def test_too_few_subjects_are_rejected() -> None:
    original = generate_positive_control(PositiveControlConfig(subjects=3), seed=1)
    mask = original.subject_ids != "person_0002"
    reduced = WindowDataset(
        features=original.features[mask],
        subject_ids=original.subject_ids[mask],
        session_ids=original.session_ids[mask],
        condition_ids=original.condition_ids[mask],
        time_indices=original.time_indices[mask],
        feature_names=original.feature_names,
    )
    with pytest.raises(PermutationControlError, match="at least three"):
        break_identity_correspondence(reduced, seed=1)
