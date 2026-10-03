"""Adversarial audit for K7 transport cost claims."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from noticer_core.evaluation.logical_transport_cost import (
    LogicalCostVector,
    artifact_digest,
)
from noticer_core.evaluation.transport_cost_profile import (
    CostCalibrationArtifact,
    canonical_calibration_json,
)
from noticer_core.evaluation.transport_cost_simulator import TransportSimulationArtifact

CANONICAL_UNITS = {
    "bytes": "bytes",
    "dummy_frames": "frames",
    "mean_latency_scaled": "scaled_slots",
    "radio_on_slots": "proxy_slots",
    "reconnects": "count",
    "retries": "count",
    "state_count": "states",
    "total_frames": "frames",
    "worst_latency": "slots",
}
RESIDUAL_LIMITS = ("measurement_source_collusion", "simulator_model_mismatch")


class CostAuditError(ValueError):
    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


@dataclass(frozen=True)
class CostAuditCommitment:
    platform_profile_sha256: str
    calibration_sha256: str
    required_axes: tuple[str, ...]


@dataclass(frozen=True)
class CostAuditReport:
    status: str
    checked_axes: tuple[str, ...]
    residual_limits: tuple[str, ...]
    security_proof: bool = False


def calibration_digest(artifact: CostCalibrationArtifact) -> str:
    payload = canonical_calibration_json(artifact).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def audit_cost_claim(
    simulation: TransportSimulationArtifact,
    calibration: CostCalibrationArtifact,
    claimed_cost: LogicalCostVector,
    commitment: CostAuditCommitment,
) -> CostAuditReport:
    """Reject cost/provenance substitutions against frozen public commitments."""

    if claimed_cost != simulation.logical_cost.cost:
        raise CostAuditError("cost_understatement_or_substitution")
    if calibration.logical_cost_sha256 != artifact_digest(simulation.logical_cost):
        raise CostAuditError("logical_cost_binding_mismatch")
    if (
        calibration.platform_profile_sha256 != commitment.platform_profile_sha256
        or simulation.platform_profile_sha256 != commitment.platform_profile_sha256
    ):
        raise CostAuditError("profile_substitution")
    axes = tuple(interval.axis for interval in calibration.intervals)
    if axes != commitment.required_axes:
        raise CostAuditError("missing_or_reordered_measurement")
    if any(
        CANONICAL_UNITS.get(interval.axis) != interval.unit
        for interval in calibration.intervals
    ):
        raise CostAuditError("unit_confusion")
    if calibration_digest(calibration) != commitment.calibration_sha256:
        raise CostAuditError("interval_or_artifact_tampering")
    return CostAuditReport("PASS", axes, RESIDUAL_LIMITS)
