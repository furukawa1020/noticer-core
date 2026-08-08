"""Dataset-independent window contract for privacy attacks."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd


@dataclass(frozen=True, slots=True)
class WindowDataset:
    """Validated features and metadata for window-level attack evaluation."""

    features: np.ndarray
    subject_ids: np.ndarray
    session_ids: np.ndarray
    condition_ids: np.ndarray
    time_indices: np.ndarray
    feature_names: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.features.ndim != 2:
            raise ValueError("features must be a two-dimensional array")
        if self.features.shape[0] == 0:
            raise ValueError("dataset must contain at least one window")
        if self.features.shape[1] != len(self.feature_names):
            raise ValueError("feature count must match feature_names")
        if not np.isfinite(self.features).all():
            raise ValueError("features must not contain NaN or Inf")
        metadata = {
            "subject_ids": self.subject_ids,
            "session_ids": self.session_ids,
            "condition_ids": self.condition_ids,
            "time_indices": self.time_indices,
        }
        for name, values in metadata.items():
            if values.ndim != 1 or len(values) != self.n_windows:
                raise ValueError(f"{name} must be one-dimensional with one value per window")
        for name, values in (("subject_ids", self.subject_ids), ("session_ids", self.session_ids)):
            if any(not str(value).strip() for value in values):
                raise ValueError(f"{name} must not contain empty values")
        session_owners = self.metadata_frame().groupby("session_id")["subject_id"].nunique()
        if (session_owners != 1).any():
            raise ValueError("each session_id must belong to exactly one subject")

    @property
    def n_windows(self) -> int:
        return int(self.features.shape[0])

    @property
    def n_features(self) -> int:
        return int(self.features.shape[1])

    @property
    def n_subjects(self) -> int:
        return int(np.unique(self.subject_ids).size)

    @property
    def n_sessions(self) -> int:
        return int(np.unique(self.session_ids).size)

    def metadata_frame(self) -> pd.DataFrame:
        """Return metadata in stable per-window order."""
        return pd.DataFrame(
            {
                "subject_id": self.subject_ids.astype(str),
                "session_id": self.session_ids.astype(str),
                "condition_id": self.condition_ids.astype(str),
                "time_index": self.time_indices,
            }
        )

    def require_sessions_per_subject(self, minimum: int) -> None:
        counts = self.metadata_frame().groupby("subject_id")["session_id"].nunique()
        if (counts < minimum).any():
            raise ValueError(f"each subject must have at least {minimum} sessions")
