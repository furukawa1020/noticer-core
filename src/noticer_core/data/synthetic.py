"""Deterministic synthetic identity-leakage generator."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from noticer_core.data.contracts import WindowDataset


@dataclass(frozen=True, slots=True)
class SyntheticConfig:
    n_subjects: int
    sessions_per_subject: int
    windows_per_session: int
    n_features: int
    n_conditions: int
    identity_signal_strength: float
    session_drift_strength: float
    condition_effect_strength: float
    noise_strength: float

    def validate(self) -> None:
        if self.n_subjects < 2 or self.sessions_per_subject < 3:
            raise ValueError("synthetic data requires >=2 subjects and >=3 sessions per subject")
        if min(self.windows_per_session, self.n_features) < 1 or self.n_conditions < 3:
            raise ValueError("windows/features must be positive and n_conditions must be >=3")
        strengths = (
            self.identity_signal_strength,
            self.session_drift_strength,
            self.condition_effect_strength,
            self.noise_strength,
        )
        if min(strengths) < 0:
            raise ValueError("signal strengths must be non-negative")


def generate_identity_dataset(config: SyntheticConfig, *, seed: int) -> WindowDataset:
    """Generate subject signature + session drift + condition effect + noise."""
    config.validate()
    rng = np.random.default_rng(seed)
    signatures = rng.normal(size=(config.n_subjects, config.n_features))
    conditions = rng.normal(size=(config.n_conditions, config.n_features))
    features: list[np.ndarray] = []
    subjects: list[str] = []
    sessions: list[str] = []
    condition_ids: list[str] = []
    times: list[int] = []
    for subject in range(config.n_subjects):
        subject_id = f"subject_{subject:02d}"
        signature = signatures[subject] * config.identity_signal_strength
        for session in range(config.sessions_per_subject):
            session_id = f"{subject_id}_session_{session:02d}"
            drift = rng.normal(size=config.n_features) * config.session_drift_strength
            for time_index in range(config.windows_per_session):
                condition = (time_index + session) % config.n_conditions
                noise = rng.normal(size=config.n_features) * config.noise_strength
                features.append(
                    signature
                    + drift
                    + conditions[condition] * config.condition_effect_strength
                    + noise
                )
                subjects.append(subject_id)
                sessions.append(session_id)
                condition_ids.append(f"condition_{condition:02d}")
                times.append(time_index)
    return WindowDataset(
        features=np.asarray(features, dtype=float),
        subject_ids=np.asarray(subjects),
        session_ids=np.asarray(sessions),
        condition_ids=np.asarray(condition_ids),
        time_indices=np.asarray(times, dtype=int),
        feature_names=tuple(f"feature_{index:03d}" for index in range(config.n_features)),
    )
