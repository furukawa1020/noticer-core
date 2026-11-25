"""Payload-blind release cadence traffic-analysis attacker for K20."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from noticer_core.attacks.k20_identity import (
    IdentityAttackPrediction,
    LabelledAttackPartition,
    UnlabelledAttackPartition,
    execute_identity_attacker,
)
from noticer_core.attacks.k20_logistic import LogisticIdentityAttacker

TRAFFIC_FEATURES = (
    "packet_count",
    "duration",
    "interarrival_mean",
    "interarrival_std",
    "interarrival_min",
    "interarrival_max",
    "size_mean",
    "size_std",
    "outbound_fraction",
    "retry_fraction",
)


class TrafficAttackError(ValueError):
    """Raised when observable traffic metadata violates the attack contract."""


@dataclass(frozen=True, slots=True)
class TrafficSessionTrace:
    session_id: str
    timestamps: np.ndarray
    wire_sizes: np.ndarray
    outbound: np.ndarray
    retries: np.ndarray

    def features(self) -> np.ndarray:
        count = len(self.timestamps)
        arrays = (self.wire_sizes, self.outbound, self.retries)
        if count < 2 or any(values.shape != (count,) for values in arrays):
            raise TrafficAttackError("traffic trace requires aligned metadata and two packets")
        if not np.isfinite(self.timestamps).all() or not np.isfinite(self.wire_sizes).all():
            raise TrafficAttackError("traffic timestamps and sizes must be finite")
        if np.any(self.wire_sizes < 0) or np.any(np.diff(self.timestamps) <= 0):
            raise TrafficAttackError("traffic timestamps must increase and sizes be non-negative")
        if self.outbound.dtype != np.bool_ or self.retries.dtype != np.bool_:
            raise TrafficAttackError("direction and retry metadata must be boolean")
        intervals = np.diff(self.timestamps)
        return np.asarray(
            [
                count,
                self.timestamps[-1] - self.timestamps[0],
                intervals.mean(),
                intervals.std(),
                intervals.min(),
                intervals.max(),
                self.wire_sizes.mean(),
                self.wire_sizes.std(),
                self.outbound.mean(),
                self.retries.mean(),
            ],
            dtype=float,
        )


@dataclass(frozen=True, slots=True)
class LabelledTrafficTrace:
    trace: TrafficSessionTrace
    subject_id: str


def run_traffic_analysis_attack(
    training: tuple[LabelledTrafficTrace, ...],
    validation: tuple[LabelledTrafficTrace, ...],
    test: tuple[TrafficSessionTrace, ...],
    *,
    regularization_candidates: tuple[float, ...],
    seed: int,
) -> IdentityAttackPrediction:
    """Infer identity from release metadata without payload access."""
    train_partition = _labelled_partition(training)
    validation_partition = _labelled_partition(validation)
    if not test:
        raise TrafficAttackError("test traffic traces must not be empty")
    test_partition = UnlabelledAttackPartition(
        np.vstack([trace.features() for trace in test]),
        np.asarray([f"traffic_{trace.session_id}" for trace in test]),
        np.asarray([trace.session_id for trace in test]),
    )
    attacker = LogisticIdentityAttacker(
        candidates=regularization_candidates,
        seed=seed,
        attacker_id="k20-traffic-logistic-v1",
    )
    return execute_identity_attacker(
        attacker,
        train_partition,
        validation_partition,
        test_partition,
    )


def _labelled_partition(values: tuple[LabelledTrafficTrace, ...]) -> LabelledAttackPartition:
    if not values:
        raise TrafficAttackError("labelled traffic partition must not be empty")
    return LabelledAttackPartition(
        np.vstack([value.trace.features() for value in values]),
        np.asarray([value.subject_id for value in values]),
        np.asarray([value.trace.session_id for value in values]),
    )

