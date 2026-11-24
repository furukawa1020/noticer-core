"""Deterministic identity-positive control for K20 harness validation."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from noticer_core.data.contracts import WindowDataset


@dataclass(frozen=True, slots=True)
class PositiveControlConfig:
    subjects: int = 6
    sessions_per_subject: int = 3
    windows_per_session: int = 24
    features: int = 8
    conditions: int = 3
    identity_strength: float = 4.0
    session_drift: float = 0.35
    condition_strength: float = 0.5
    noise: float = 0.4

    def validate(self) -> None:
        if self.subjects < 3 or self.sessions_per_subject < 3:
            raise ValueError("positive control requires >=3 subjects and >=3 sessions")
        if min(self.windows_per_session, self.features, self.conditions) < 1:
            raise ValueError("positive control dimensions must be positive")
        if self.identity_strength <= 0:
            raise ValueError("positive control must contain identity signal")
        if min(self.session_drift, self.condition_strength, self.noise) < 0:
            raise ValueError("positive control strengths must be non-negative")


def generate_positive_control(
    config: PositiveControlConfig | None = None, *, seed: int
) -> WindowDataset:
    """Generate identity-bearing windows without sharing noise across sessions."""
    if config is None:
        config = PositiveControlConfig()
    config.validate()
    rng = np.random.default_rng(seed)
    signatures = rng.normal(size=(config.subjects, config.features)) * config.identity_strength
    condition_effects = (
        rng.normal(size=(config.conditions, config.features)) * config.condition_strength
    )
    feature_rows: list[np.ndarray] = []
    subject_ids: list[str] = []
    session_ids: list[str] = []
    condition_ids: list[str] = []
    time_indices: list[int] = []
    for subject_index in range(config.subjects):
        subject_id = f"person_{subject_index:04d}"
        for session_index in range(config.sessions_per_subject):
            session_id = f"p{subject_index:04d}_session_{session_index:03d}"
            drift = rng.normal(size=config.features) * config.session_drift
            for time_index in range(config.windows_per_session):
                condition_index = time_index % config.conditions
                noise = rng.normal(size=config.features) * config.noise
                feature_rows.append(
                    signatures[subject_index]
                    + drift
                    + condition_effects[condition_index]
                    + noise
                )
                subject_ids.append(subject_id)
                session_ids.append(session_id)
                condition_ids.append(f"condition_{condition_index:03d}")
                time_indices.append(time_index)
    return WindowDataset(
        features=np.asarray(feature_rows),
        subject_ids=np.asarray(subject_ids),
        session_ids=np.asarray(session_ids),
        condition_ids=np.asarray(condition_ids),
        time_indices=np.asarray(time_indices),
        feature_names=tuple(f"feature_{index:03d}" for index in range(config.features)),
    )


def centroid_separation_ratio(dataset: WindowDataset) -> float:
    """Return between-subject centroid distance over within-subject RMS distance."""
    subjects = np.unique(dataset.subject_ids)
    centroids = np.asarray(
        [dataset.features[dataset.subject_ids == subject].mean(axis=0) for subject in subjects]
    )
    between = np.mean(
        [
            np.linalg.norm(centroids[left] - centroids[right])
            for left in range(len(centroids))
            for right in range(left + 1, len(centroids))
        ]
    )
    residuals = np.vstack(
        [
            dataset.features[dataset.subject_ids == subject] - centroids[index]
            for index, subject in enumerate(subjects)
        ]
    )
    within = float(np.sqrt(np.mean(np.sum(residuals * residuals, axis=1))))
    return float(between / within) if within > 0 else float("inf")

