"""Session-level identity correspondence breaking control for K20."""

from __future__ import annotations

from collections import defaultdict

import numpy as np

from noticer_core.data.contracts import WindowDataset


class PermutationControlError(ValueError):
    """Raised when identity correspondence cannot be broken safely."""


def break_identity_correspondence(dataset: WindowDataset, *, seed: int) -> WindowDataset:
    """Replace session owners with balanced, session-varying pseudolabels."""
    subjects = tuple(sorted(str(value) for value in np.unique(dataset.subject_ids)))
    if len(subjects) < 3:
        raise PermutationControlError("permutation control requires at least three subjects")

    sessions_by_subject: dict[str, list[str]] = defaultdict(list)
    for session in np.unique(dataset.session_ids):
        indices = np.flatnonzero(dataset.session_ids == session)
        owners = np.unique(dataset.subject_ids[indices])
        if len(owners) != 1:
            raise PermutationControlError("each session must have one original owner")
        sessions_by_subject[str(owners[0])].append(str(session))
    session_counts = {len(values) for values in sessions_by_subject.values()}
    if len(session_counts) != 1 or next(iter(session_counts)) < 2:
        raise PermutationControlError("balanced subjects with at least two sessions are required")

    rng = np.random.default_rng(seed)
    pseudolabels = np.asarray(subjects)[rng.permutation(len(subjects))]
    replacement: dict[str, str] = {}
    for subject_rank, subject in enumerate(subjects):
        for session_rank, session in enumerate(sorted(sessions_by_subject[subject])):
            label_index = (subject_rank + session_rank) % len(subjects)
            replacement[session] = str(pseudolabels[label_index])

    broken_labels = np.asarray([replacement[str(session)] for session in dataset.session_ids])
    return WindowDataset(
        features=dataset.features.copy(),
        subject_ids=broken_labels,
        session_ids=dataset.session_ids.copy(),
        condition_ids=dataset.condition_ids.copy(),
        time_indices=dataset.time_indices.copy(),
        feature_names=dataset.feature_names,
    )

