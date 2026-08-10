"""Deterministic three-way session-disjoint splits."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

from noticer_core.data.aetp_synthetic import CounterfactualTraceDataset
from noticer_core.data.contracts import WindowDataset


@dataclass(frozen=True, slots=True)
class DatasetSplit:
    train_indices: np.ndarray
    validation_indices: np.ndarray
    test_indices: np.ndarray
    manifest: pd.DataFrame


def session_disjoint_split(dataset: WindowDataset, *, seed: int) -> DatasetSplit:
    """Assign complete sessions to train, validation, and test within each subject."""
    dataset.require_sessions_per_subject(3)
    rng = np.random.default_rng(seed)
    metadata = dataset.metadata_frame()
    assignments: dict[str, str] = {}
    for _, group in metadata.groupby("subject_id", sort=True):
        sessions = rng.permutation(sorted(group["session_id"].unique()))
        assignments[str(sessions[0])] = "validation"
        assignments[str(sessions[1])] = "test"
        for session in sessions[2:]:
            assignments[str(session)] = "train"
    manifest = metadata.copy()
    manifest.insert(0, "split", manifest["session_id"].map(assignments))
    index_sets = {
        name: np.flatnonzero(manifest["split"].to_numpy() == name)
        for name in ("train", "validation", "test")
    }
    combined = np.concatenate(list(index_sets.values()))
    complete = set(combined) == set(range(dataset.n_windows))
    if len(np.unique(combined)) != dataset.n_windows or not complete:
        raise RuntimeError("split indices must be disjoint and exhaustive")
    expected = set(dataset.subject_ids.astype(str))
    for name, indices in index_sets.items():
        if set(dataset.subject_ids[indices].astype(str)) != expected:
            raise RuntimeError(f"{name} split changed the identity classes")
    return DatasetSplit(
        train_indices=index_sets["train"],
        validation_indices=index_sets["validation"],
        test_indices=index_sets["test"],
        manifest=manifest,
    )


def aetp_session_disjoint_split(
    dataset: CounterfactualTraceDataset, *, seed: int
) -> DatasetSplit:
    """Split complete counterfactual sessions within each action semantic class."""
    rng = np.random.default_rng(seed)
    assignments: dict[str, str] = {}
    for action_id in sorted(np.unique(dataset.action_ids)):
        action_sessions = sorted(np.unique(dataset.session_ids[dataset.action_ids == action_id]))
        if len(action_sessions) < 3:
            raise ValueError("each action semantic class must have at least 3 sessions")
        shuffled = rng.permutation(action_sessions)
        assignments[str(shuffled[0])] = "validation"
        assignments[str(shuffled[1])] = "test"
        for session_id in shuffled[2:]:
            assignments[str(session_id)] = "train"
    manifest = pd.DataFrame(
        {
            "pair_id": dataset.pair_ids,
            "session_id": dataset.session_ids,
            "action_id": dataset.action_ids,
            "world_label": dataset.world_labels,
        }
    )
    manifest.insert(0, "split", manifest["session_id"].map(assignments))
    index_sets = {
        name: np.flatnonzero(manifest["split"].to_numpy() == name)
        for name in ("train", "validation", "test")
    }
    session_sets = [
        set(manifest.loc[manifest["split"] == name, "session_id"])
        for name in ("train", "validation", "test")
    ]
    if any(
        not session_sets[left].isdisjoint(session_sets[right])
        for left, right in ((0, 1), (0, 2), (1, 2))
    ):
        raise RuntimeError("AETP split must be session-disjoint")
    return DatasetSplit(
        train_indices=index_sets["train"],
        validation_indices=index_sets["validation"],
        test_indices=index_sets["test"],
        manifest=manifest,
    )
