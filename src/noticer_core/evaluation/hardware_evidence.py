"""Public evidence contract for K5 physical verification tiers.

This module validates bounded, non-identifying summaries.  It never performs a
hardware measurement and it deliberately prevents CI evidence from promoting a
physical tier to ``VERIFIED``.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

SCHEMA_NAME = "noticer-k5-hardware-public-v1"
PROTOCOL_VERSION = "K5-HW-1.0"


class HardwareTier(StrEnum):
    """Physical verification tiers tracked by K5."""

    B = "B"
    C = "C"
    D = "D"
    S3 = "S3"


class EvidenceStatus(StrEnum):
    """Verification state recorded in a public artifact."""

    NOT_VERIFIED = "NOT_VERIFIED"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"


class EvidenceOrigin(StrEnum):
    """Origin of evidence used for a state transition."""

    NONE = "NONE"
    CI = "CI"
    PHYSICAL_MEASUREMENT = "PHYSICAL_MEASUREMENT"


@dataclass(frozen=True)
class ValidationResult:
    """Result of validating one public hardware-evidence artifact."""

    errors: tuple[str, ...]

    @property
    def valid(self) -> bool:
        """Return true when the artifact satisfies the public contract."""

        return not self.errors


PREFLIGHT_FIELDS = frozenset(
    {
        "equipment_available",
        "toolchain_ready",
        "consent_recorded",
        "safety_protocol_approved",
        "private_storage_ready",
        "stop_conditions_recorded",
    }
)

ROOT_FIELDS = frozenset(
    {
        "schema",
        "protocol_version",
        "tier",
        "status",
        "evidence_origin",
        "public_run_id",
        "private_field_count",
        "preflight",
        "measurements",
        "measurement_bundle_sha256",
        "status_reason",
    }
)

FORBIDDEN_PUBLIC_KEYS = frozenset(
    {
        "raw_ppg",
        "ppg_samples",
        "raw_acc",
        "acc_samples",
        "baseline_values",
        "private_history",
        "device_id",
        "participant_id",
        "attestation_chain",
        "certificate_chain",
        "permit_signature",
        "lease_bytes",
        "token_bytes",
        "key_material",
        "consent_document",
    }
)

TIER_MEASUREMENT_FIELDS: dict[HardwareTier, frozenset[str]] = {
    HardwareTier.B: frozenset(
        {
            "duration_seconds",
            "ppg_rate_hz",
            "acc_rate_hz",
            "polar_sdk_version",
            "firmware_recorded",
            "gap_count",
            "rollback_count",
            "window_count",
            "quality_pass_rate",
            "latency_ms_p95",
            "peak_memory_mb",
            "mean_cpu_percent",
            "battery_drop_percent",
            "k1_decision_count",
            "k1_live_input_confirmed",
        }
    ),
    HardwareTier.C: frozenset(
        {
            "fresh_challenge_used",
            "attestation_chain_validated",
            "security_level",
            "verified_boot",
            "device_locked",
            "app_identity_validated",
            "revocation_checked",
            "production_lease_issued",
            "stale_challenge_rejected",
            "replay_rejected",
            "downgrade_rejected",
            "wrong_app_rejected",
        }
    ),
    HardwareTier.D: frozenset(
        {
            "live_ppg_received",
            "evidence_permit_issued",
            "production_lease_validated",
            "atv2_emitted",
            "aplot_verified",
            "menfugu_action_count",
            "replay_rejected",
            "unauthorized_action_count",
            "latency_ms_p95",
        }
    ),
    HardwareTier.S3: frozenset(
        {
            "ethics_approved",
            "safe_fixture_used",
            "stop_conditions_observed",
            "safe_scenario_count",
            "false_permit_count",
            "false_action_count",
            "latency_ms_p95",
        }
    ),
}

_ALLOWED_TRANSITIONS: dict[EvidenceStatus, frozenset[EvidenceStatus]] = {
    EvidenceStatus.NOT_VERIFIED: frozenset(
        {EvidenceStatus.NOT_VERIFIED, EvidenceStatus.VERIFIED, EvidenceStatus.FAILED}
    ),
    EvidenceStatus.VERIFIED: frozenset({EvidenceStatus.VERIFIED}),
    EvidenceStatus.FAILED: frozenset({EvidenceStatus.FAILED}),
}
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def new_public_artifact(
    tier: HardwareTier,
    *,
    public_run_id: str = "unassigned",
) -> dict[str, Any]:
    """Create a bounded artifact in the safe default state."""

    return {
        "schema": SCHEMA_NAME,
        "protocol_version": PROTOCOL_VERSION,
        "tier": tier.value,
        "status": EvidenceStatus.NOT_VERIFIED.value,
        "evidence_origin": EvidenceOrigin.NONE.value,
        "public_run_id": public_run_id,
        "private_field_count": 0,
        "preflight": {field: False for field in sorted(PREFLIGHT_FIELDS)},
        "measurements": {},
        "measurement_bundle_sha256": None,
        "status_reason": "physical measurement has not been performed",
    }


def validate_public_artifact(artifact: Mapping[str, Any]) -> ValidationResult:
    """Validate structure, privacy boundary, state, and tier measurements."""

    errors: list[str] = []
    root_keys = set(artifact)
    errors.extend(_field_set_errors("root", root_keys, ROOT_FIELDS))
    errors.extend(_find_forbidden_keys(artifact))

    if artifact.get("schema") != SCHEMA_NAME:
        errors.append(f"schema must be {SCHEMA_NAME}")
    if artifact.get("protocol_version") != PROTOCOL_VERSION:
        errors.append(f"protocol_version must be {PROTOCOL_VERSION}")
    if artifact.get("private_field_count") != 0:
        errors.append("private_field_count must be exactly 0")

    public_run_id = artifact.get("public_run_id")
    if not isinstance(public_run_id, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", public_run_id
    ):
        errors.append("public_run_id must be a bounded non-identifying label")

    tier = _parse_enum(HardwareTier, artifact.get("tier"), "tier", errors)
    status = _parse_enum(EvidenceStatus, artifact.get("status"), "status", errors)
    origin = _parse_enum(
        EvidenceOrigin, artifact.get("evidence_origin"), "evidence_origin", errors
    )

    preflight = artifact.get("preflight")
    if not isinstance(preflight, Mapping):
        errors.append("preflight must be an object")
        preflight = {}
    else:
        errors.extend(_field_set_errors("preflight", set(preflight), PREFLIGHT_FIELDS))
        for field in PREFLIGHT_FIELDS:
            if field in preflight and not isinstance(preflight[field], bool):
                errors.append(f"preflight.{field} must be boolean")

    measurements = artifact.get("measurements")
    if not isinstance(measurements, Mapping):
        errors.append("measurements must be an object")
        measurements = {}
    elif tier is not None:
        allowed = TIER_MEASUREMENT_FIELDS[tier]
        unknown = set(measurements) - allowed
        if unknown:
            errors.append(f"measurements has unknown fields: {sorted(unknown)}")

    digest = artifact.get("measurement_bundle_sha256")
    if digest is not None and (
        not isinstance(digest, str) or _SHA256_PATTERN.fullmatch(digest) is None
    ):
        errors.append("measurement_bundle_sha256 must be null or lowercase SHA-256")

    reason = artifact.get("status_reason")
    if status in {EvidenceStatus.NOT_VERIFIED, EvidenceStatus.FAILED}:
        if not isinstance(reason, str) or not reason.strip():
            errors.append("non-verified states require a non-empty status_reason")

    if status is EvidenceStatus.VERIFIED:
        if origin is not EvidenceOrigin.PHYSICAL_MEASUREMENT:
            errors.append("VERIFIED requires PHYSICAL_MEASUREMENT evidence")
        if any(preflight.get(field) is not True for field in PREFLIGHT_FIELDS):
            errors.append("VERIFIED requires every preflight gate")
        if not isinstance(digest, str) or _SHA256_PATTERN.fullmatch(digest) is None:
            errors.append("VERIFIED requires a private measurement bundle commitment")
        if reason is not None:
            errors.append("VERIFIED requires status_reason to be null")
        if tier is not None:
            errors.extend(_validate_verified_measurements(tier, measurements))

    if status is EvidenceStatus.FAILED and origin is not EvidenceOrigin.PHYSICAL_MEASUREMENT:
        errors.append("FAILED requires a physical measurement attempt")

    return ValidationResult(tuple(errors))


def transition_status(
    artifact: Mapping[str, Any],
    *,
    target: EvidenceStatus,
    origin: EvidenceOrigin,
) -> dict[str, Any]:
    """Apply a one-way state transition and return a validated copy."""

    errors: list[str] = []
    current = _parse_enum(EvidenceStatus, artifact.get("status"), "status", errors)
    if current is None:
        raise ValueError("; ".join(errors))
    if target not in _ALLOWED_TRANSITIONS[current]:
        raise ValueError(f"transition {current.value} -> {target.value} is not allowed")
    if target is EvidenceStatus.VERIFIED and origin is not EvidenceOrigin.PHYSICAL_MEASUREMENT:
        raise ValueError("CI and synthetic evidence cannot promote a tier to VERIFIED")

    updated = deepcopy(dict(artifact))
    updated["status"] = target.value
    updated["evidence_origin"] = origin.value
    result = validate_public_artifact(updated)
    if not result.valid:
        raise ValueError("; ".join(result.errors))
    return updated


def _field_set_errors(
    location: str,
    actual: set[str],
    expected: frozenset[str],
) -> list[str]:
    errors: list[str] = []
    missing = expected - actual
    unknown = actual - expected
    if missing:
        errors.append(f"{location} is missing fields: {sorted(missing)}")
    if unknown:
        errors.append(f"{location} has unknown fields: {sorted(unknown)}")
    return errors


def _normalise_key(key: object) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(key).strip().lower()).strip("_")


def _find_forbidden_keys(value: object, path: str = "root") -> list[str]:
    errors: list[str] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_name = str(key)
            child_path = f"{path}.{key_name}"
            if _normalise_key(key) in FORBIDDEN_PUBLIC_KEYS:
                errors.append(f"forbidden public field: {child_path}")
            errors.extend(_find_forbidden_keys(child, child_path))
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            errors.extend(_find_forbidden_keys(child, f"{path}[{index}]"))
    return errors


def _parse_enum(
    enum_type: type[HardwareTier] | type[EvidenceStatus] | type[EvidenceOrigin],
    value: object,
    field: str,
    errors: list[str],
) -> HardwareTier | EvidenceStatus | EvidenceOrigin | None:
    try:
        return enum_type(value)
    except (TypeError, ValueError):
        choices = [entry.value for entry in enum_type]
        errors.append(f"{field} must be one of {choices}")
        return None


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _require_true(
    measurements: Mapping[str, Any], fields: tuple[str, ...], errors: list[str]
) -> None:
    for field in fields:
        if measurements.get(field) is not True:
            errors.append(f"measurements.{field} must be true")


def _require_zero(
    measurements: Mapping[str, Any], fields: tuple[str, ...], errors: list[str]
) -> None:
    for field in fields:
        if measurements.get(field) != 0:
            errors.append(f"measurements.{field} must be exactly 0")


def _require_positive(
    measurements: Mapping[str, Any], fields: tuple[str, ...], errors: list[str]
) -> None:
    for field in fields:
        value = measurements.get(field)
        if not _is_number(value) or value <= 0:
            errors.append(f"measurements.{field} must be positive")


def _validate_verified_measurements(
    tier: HardwareTier, measurements: Mapping[str, Any]
) -> list[str]:
    errors: list[str] = []
    required = TIER_MEASUREMENT_FIELDS[tier]
    missing = required - set(measurements)
    if missing:
        errors.append(f"VERIFIED tier {tier.value} is missing measurements: {sorted(missing)}")
        return errors

    if tier is HardwareTier.B:
        duration = measurements.get("duration_seconds")
        if not _is_number(duration) or duration < 1800:
            errors.append("measurements.duration_seconds must be at least 1800")
        if measurements.get("ppg_rate_hz") != 55:
            errors.append("measurements.ppg_rate_hz must be 55")
        if measurements.get("acc_rate_hz") != 52:
            errors.append("measurements.acc_rate_hz must be 52")
        if measurements.get("polar_sdk_version") != "8.1.0":
            errors.append("measurements.polar_sdk_version must be 8.1.0")
        _require_true(
            measurements,
            ("firmware_recorded", "k1_live_input_confirmed"),
            errors,
        )
        _require_zero(measurements, ("rollback_count",), errors)
        _require_positive(measurements, ("window_count", "k1_decision_count"), errors)
        gap_count = measurements.get("gap_count")
        if not _is_number(gap_count) or gap_count < 0:
            errors.append("measurements.gap_count must be non-negative")
        quality = measurements.get("quality_pass_rate")
        if not _is_number(quality) or not 0 <= quality <= 1:
            errors.append("measurements.quality_pass_rate must be between 0 and 1")
        for field in (
            "latency_ms_p95",
            "peak_memory_mb",
            "mean_cpu_percent",
            "battery_drop_percent",
        ):
            value = measurements.get(field)
            if not _is_number(value) or value < 0:
                errors.append(f"measurements.{field} must be non-negative")
        for field in ("mean_cpu_percent", "battery_drop_percent"):
            value = measurements.get(field)
            if _is_number(value) and value > 100:
                errors.append(f"measurements.{field} must not exceed 100")

    elif tier is HardwareTier.C:
        _require_true(
            measurements,
            (
                "fresh_challenge_used",
                "attestation_chain_validated",
                "verified_boot",
                "device_locked",
                "app_identity_validated",
                "revocation_checked",
                "production_lease_issued",
                "stale_challenge_rejected",
                "replay_rejected",
                "downgrade_rejected",
                "wrong_app_rejected",
            ),
            errors,
        )
        if measurements.get("security_level") not in {"TEE", "STRONGBOX"}:
            errors.append("measurements.security_level must be TEE or STRONGBOX")

    elif tier is HardwareTier.D:
        _require_true(
            measurements,
            (
                "live_ppg_received",
                "evidence_permit_issued",
                "production_lease_validated",
                "atv2_emitted",
                "aplot_verified",
                "replay_rejected",
            ),
            errors,
        )
        if measurements.get("menfugu_action_count") != 1:
            errors.append("measurements.menfugu_action_count must be exactly 1")
        _require_zero(measurements, ("unauthorized_action_count",), errors)
        _require_positive(measurements, ("latency_ms_p95",), errors)

    else:
        _require_true(
            measurements,
            ("ethics_approved", "safe_fixture_used", "stop_conditions_observed"),
            errors,
        )
        _require_positive(
            measurements, ("safe_scenario_count", "latency_ms_p95"), errors
        )
        _require_zero(
            measurements, ("false_permit_count", "false_action_count"), errors
        )

    return errors
