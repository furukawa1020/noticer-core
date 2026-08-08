import pytest

from noticer_core.data.synthetic import SyntheticConfig, generate_identity_dataset
from noticer_core.evaluation.splits import session_disjoint_split


def test_three_way_split_is_disjoint_complete_and_deterministic() -> None:
    dataset = generate_identity_dataset(SyntheticConfig(5, 3, 10, 6, 3, 2.5, .4, .5, 1), seed=4)
    first = session_disjoint_split(dataset, seed=8)
    second = session_disjoint_split(dataset, seed=8)
    groups = [
        set(first.manifest.loc[first.manifest.split == name, "session_id"])
        for name in ("train", "validation", "test")
    ]
    assert groups[0].isdisjoint(groups[1])
    assert groups[0].isdisjoint(groups[2])
    assert groups[1].isdisjoint(groups[2])
    assert first.manifest.equals(second.manifest)
    all_indices = (first.train_indices, first.validation_indices, first.test_indices)
    assert sum(map(len, all_indices)) == dataset.n_windows
    expected_subjects = set(dataset.subject_ids)
    assert all(
        set(dataset.subject_ids[index]) == expected_subjects
        for index in (first.train_indices, first.test_indices)
    )


def test_insufficient_sessions_fails() -> None:
    dataset = generate_identity_dataset(SyntheticConfig(3, 3, 2, 2, 3, 1, 0, 0, 1), seed=1)
    dataset.session_ids[:] = [
        value.rsplit("_", 1)[0] + "_00" for value in dataset.session_ids
    ]
    with pytest.raises(ValueError, match="at least 3"):
        session_disjoint_split(dataset, seed=1)
