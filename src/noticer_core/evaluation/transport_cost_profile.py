"""Digest-bound platform profiles and uncertainty intervals for K7 cost calibration."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import asdict, dataclass

from noticer_core.evaluation.logical_transport_cost import (
    LogicalCostArtifact,
    artifact_digest,
)

FORMAT_VERSION = "noticer.k7.transport-cost-profile.v1"
CALIBRATION_VERSION = "noticer.k7.transport-cost-calibration.v1"
ALLOWED_AXES = (
    "bytes",
    "dummy_frames",
    "mean_latency_scaled",
    "radio_on_slots",
    "reconnects",
    "retries",
    "state_count",
    "total_frames",
    "worst_latency",
)
HARDWARE_ENERGY_UNITS = {"j", "joule", "joules", "mah", "mwh", "wh"}


class TransportProfileError(ValueError):
    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


@dataclass(frozen=True)
class PlatformProfile:
    format_version: str
    profile_id: str
    source_ref: str
    source_version: str
    source_sha256: str
    measurement_environment: str
    evidence_kind: str = "SOFTWARE_PROXY"


@dataclass(frozen=True)
class MeasurementInterval:
    axis: str
    unit: str
    lower: float
    estimate: float
    upper: float


@dataclass(frozen=True)
class CostCalibrationArtifact:
    format_version: str
    security_contract_sha256: str
    logical_cost_sha256: str
    platform_profile_sha256: str
    evidence_kind: str
    intervals: tuple[MeasurementInterval, ...]
    hardware_energy_claim: bool = False


def build_calibration_artifact(
    security_contract_sha256: str,
    logical_cost: LogicalCostArtifact,
    profile: PlatformProfile,
    intervals: tuple[MeasurementInterval, ...],
) -> CostCalibrationArtifact:
    """Bind measurements without folding platform data into the security identity."""

    _digest(security_contract_sha256)
    validate_profile(profile)
    if not intervals:
        raise TransportProfileError("missing_intervals")
    axes = tuple(interval.axis for interval in intervals)
    if axes != tuple(sorted(set(axes))):
        raise TransportProfileError("noncanonical_interval_axes")
    for interval in intervals:
        _validate_interval(interval, profile.evidence_kind)
    return CostCalibrationArtifact(
        CALIBRATION_VERSION,
        security_contract_sha256,
        artifact_digest(logical_cost),
        profile_digest(profile),
        profile.evidence_kind,
        intervals,
    )


def validate_profile(profile: PlatformProfile) -> None:
    if profile.format_version != FORMAT_VERSION:
        raise TransportProfileError("unsupported_profile")
    if (
        not profile.profile_id
        or not profile.source_ref
        or not profile.source_version
        or not profile.measurement_environment
    ):
        raise TransportProfileError("missing_provenance")
    _digest(profile.source_sha256)
    if profile.evidence_kind != "SOFTWARE_PROXY":
        raise TransportProfileError("unsupported_evidence_kind")


def canonical_profile_json(profile: PlatformProfile) -> str:
    validate_profile(profile)
    return json.dumps(asdict(profile), sort_keys=True, separators=(",", ":"))


def profile_digest(profile: PlatformProfile) -> str:
    return hashlib.sha256(canonical_profile_json(profile).encode("utf-8")).hexdigest()


def canonical_calibration_json(artifact: CostCalibrationArtifact) -> str:
    if artifact.format_version != CALIBRATION_VERSION or artifact.hardware_energy_claim:
        raise TransportProfileError("invalid_calibration_header")
    for value in (
        artifact.security_contract_sha256,
        artifact.logical_cost_sha256,
        artifact.platform_profile_sha256,
    ):
        _digest(value)
    return json.dumps(asdict(artifact), sort_keys=True, separators=(",", ":"))


def _validate_interval(interval: MeasurementInterval, evidence_kind: str) -> None:
    values = (interval.lower, interval.estimate, interval.upper)
    if (
        interval.axis not in ALLOWED_AXES
        or not interval.unit
        or any(isinstance(value, bool) or not math.isfinite(value) for value in values)
        or interval.lower < 0
        or not interval.lower <= interval.estimate <= interval.upper
    ):
        raise TransportProfileError("invalid_interval")
    if evidence_kind == "SOFTWARE_PROXY" and interval.unit.lower() in HARDWARE_ENERGY_UNITS:
        raise TransportProfileError("hardware_energy_overclaim")


def _digest(value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise TransportProfileError("invalid_digest")
