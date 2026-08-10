"""Counterfactual synthetic traces for Action-Equivalent Trace Privacy tests."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np


@dataclass(frozen=True, slots=True)
class AetpSyntheticConfig:
    n_action_semantics: int
    sessions_per_action: int
    pairs_per_session: int
    nonce_features: int
    packet_count: int
    packet_size: int
    interval_slots: int

    def validate(self) -> None:
        if self.n_action_semantics < 2 or self.sessions_per_action < 3:
            raise ValueError("AETP data requires >=2 actions and >=3 sessions per action")
        if min(
            self.pairs_per_session,
            self.nonce_features,
            self.packet_count,
            self.packet_size,
            self.interval_slots,
        ) < 1:
            raise ValueError("AETP synthetic dimensions must be positive")


@dataclass(frozen=True, slots=True)
class CounterfactualTraceDataset:
    claim_features: np.ndarray
    safe_trace_features: np.ndarray
    timing_control_features: np.ndarray
    payload_control_features: np.ndarray
    retry_control_features: np.ndarray
    world_labels: np.ndarray
    pair_ids: np.ndarray
    session_ids: np.ndarray
    action_ids: np.ndarray
    claim_feature_names: tuple[str, ...]
    trace_feature_names: tuple[str, ...]

    def __post_init__(self) -> None:
        matrices = (
            self.claim_features,
            self.safe_trace_features,
            self.timing_control_features,
            self.payload_control_features,
            self.retry_control_features,
        )
        rows = len(self.world_labels)
        if rows == 0 or any(matrix.ndim != 2 or len(matrix) != rows for matrix in matrices):
            raise ValueError("all AETP feature matrices must have one row per world")
        if any(not np.isfinite(matrix).all() for matrix in matrices):
            raise ValueError("AETP features must be finite")
        if set(np.unique(self.world_labels)) != {0, 1}:
            raise ValueError("counterfactual worlds must use labels 0 and 1")
        for pair_id in np.unique(self.pair_ids):
            indices = np.flatnonzero(self.pair_ids == pair_id)
            if len(indices) != 2 or set(self.world_labels[indices]) != {0, 1}:
                raise ValueError("each pair must contain exactly one world of each secret class")
            if not np.array_equal(
                self.claim_features[indices[0]], self.claim_features[indices[1]]
            ):
                raise ValueError("counterfactual pairs must be action-equivalent")

    @property
    def n_worlds(self) -> int:
        return len(self.world_labels)

    @property
    def n_pairs(self) -> int:
        return len(np.unique(self.pair_ids))

    def view(self, name: str) -> np.ndarray:
        views = {
            "claim_only": self.claim_features,
            "aetp": self.safe_trace_features,
            "timing_control": self.timing_control_features,
            "payload_control": self.payload_control_features,
            "retry_control": self.retry_control_features,
        }
        try:
            return views[name]
        except KeyError as error:
            raise ValueError(f"unknown AETP view: {name}") from error


def generate_aetp_dataset(
    config: AetpSyntheticConfig, *, seed: int
) -> CounterfactualTraceDataset:
    """Generate matched private worlds and deliberate trace-leakage controls."""
    config.validate()
    rng = np.random.default_rng(seed)
    claim_rows: list[np.ndarray] = []
    safe_rows: list[np.ndarray] = []
    timing_rows: list[np.ndarray] = []
    payload_rows: list[np.ndarray] = []
    retry_rows: list[np.ndarray] = []
    labels: list[int] = []
    pairs: list[str] = []
    sessions: list[str] = []
    actions: list[str] = []

    claim_names = tuple(f"action_{index:02d}" for index in range(config.n_action_semantics))
    trace_names = claim_names + (
        "packet_count",
        "wire_size_mean",
        "wire_size_std",
        "interarrival_mean",
        "interarrival_std",
        "retry_count",
        "failure_count",
        *(f"nonce_{index:02d}" for index in range(config.nonce_features)),
        "payload_probe",
    )
    for action in range(config.n_action_semantics):
        claim = np.zeros(config.n_action_semantics, dtype=float)
        claim[action] = 1.0
        action_id = f"action_{action:02d}"
        for session in range(config.sessions_per_action):
            session_id = f"{action_id}_session_{session:02d}"
            for pair in range(config.pairs_per_session):
                pair_id = f"{session_id}_pair_{pair:04d}"
                public_nonce = rng.uniform(0.0, 1.0, size=config.nonce_features)
                public_payload_probe = float(rng.normal())
                public_trace = np.concatenate(
                    [
                        claim,
                        np.asarray(
                            [
                                config.packet_count,
                                config.packet_size,
                                0.0,
                                config.interval_slots,
                                0.0,
                                0.0,
                                0.0,
                            ],
                            dtype=float,
                        ),
                        public_nonce,
                        np.asarray([public_payload_probe]),
                    ]
                )
                for world in (0, 1):
                    safe = public_trace.copy()
                    timing = safe.copy()
                    payload = safe.copy()
                    retry = safe.copy()
                    base = config.n_action_semantics
                    timing[base + 3] += 3.0 * world
                    timing[base + 4] += 1.5 * world
                    payload[-1] += 8.0 * world
                    retry[base + 5] += 3.0 * world
                    retry[base + 6] += float(world)
                    claim_rows.append(claim.copy())
                    safe_rows.append(safe)
                    timing_rows.append(timing)
                    payload_rows.append(payload)
                    retry_rows.append(retry)
                    labels.append(world)
                    pairs.append(pair_id)
                    sessions.append(session_id)
                    actions.append(action_id)
    return CounterfactualTraceDataset(
        claim_features=np.asarray(claim_rows),
        safe_trace_features=np.asarray(safe_rows),
        timing_control_features=np.asarray(timing_rows),
        payload_control_features=np.asarray(payload_rows),
        retry_control_features=np.asarray(retry_rows),
        world_labels=np.asarray(labels, dtype=int),
        pair_ids=np.asarray(pairs),
        session_ids=np.asarray(sessions),
        action_ids=np.asarray(actions),
        claim_feature_names=claim_names,
        trace_feature_names=trace_names,
    )
