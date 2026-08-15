from __future__ import annotations

from typing import Any

import pytest

from noticer_core.evaluation.hardware_evidence import (
    EvidenceOrigin,
    EvidenceStatus,
    HardwareTier,
    new_public_artifact,
    transition_status,
    validate_public_artifact,
)


def _verified_candidate(tier: HardwareTier) -> dict[str, Any]:
    artifact = new_public_artifact(tier, public_run_id=f"contract-{tier.value}")
    artifact["status"] = EvidenceStatus.VERIFIED.value
    artifact["evidence_origin"] = EvidenceOrigin.PHYSICAL_MEASUREMENT.value
    artifact["preflight"] = {key: True for key in artifact["preflight"]}
    artifact["measurement_bundle_sha256"] = "a" * 64
    artifact["status_reason"] = None
    artifact["measurements"] = {
        HardwareTier.B: {
            "duration_seconds": 1800,
            "ppg_rate_hz": 55,
            "acc_rate_hz": 52,
            "polar_sdk_version": "8.1.0",
            "firmware_recorded": True,
            "gap_count": 0,
            "rollback_count": 0,
            "window_count": 100,
            "quality_pass_rate": 0.99,
            "latency_ms_p95": 25.0,
            "peak_memory_mb": 64.0,
            "mean_cpu_percent": 12.0,
            "battery_drop_percent": 3.0,
            "k1_decision_count": 20,
            "k1_live_input_confirmed": True,
        },
        HardwareTier.C: {
            "fresh_challenge_used": True,
            "attestation_chain_validated": True,
            "security_level": "STRONGBOX",
            "verified_boot": True,
            "device_locked": True,
            "app_identity_validated": True,
            "revocation_checked": True,
            "production_lease_issued": True,
            "stale_challenge_rejected": True,
            "replay_rejected": True,
            "downgrade_rejected": True,
            "wrong_app_rejected": True,
        },
        HardwareTier.D: {
            "live_ppg_received": True,
            "evidence_permit_issued": True,
            "production_lease_validated": True,
            "atv2_emitted": True,
            "aplot_verified": True,
            "menfugu_action_count": 1,
            "replay_rejected": True,
            "unauthorized_action_count": 0,
            "latency_ms_p95": 80.0,
        },
        HardwareTier.S3: {
            "ethics_approved": True,
            "safe_fixture_used": True,
            "stop_conditions_observed": True,
            "safe_scenario_count": 3,
            "false_permit_count": 0,
            "false_action_count": 0,
            "latency_ms_p95": 90.0,
        },
    }[tier]
    return artifact


def test_default_artifacts_are_not_verified() -> None:
    for tier in HardwareTier:
        artifact = new_public_artifact(tier)
        assert artifact["status"] == "NOT_VERIFIED"
        assert artifact["private_field_count"] == 0
        assert validate_public_artifact(artifact).valid


def test_ci_cannot_promote_hardware_tier() -> None:
    artifact = _verified_candidate(HardwareTier.B)
    artifact["status"] = EvidenceStatus.NOT_VERIFIED.value
    artifact["status_reason"] = "CI contract exercise only"

    with pytest.raises(ValueError, match="cannot promote"):
        transition_status(
            artifact,
            target=EvidenceStatus.VERIFIED,
            origin=EvidenceOrigin.CI,
        )


def test_forbidden_nested_public_field_is_rejected() -> None:
    artifact = new_public_artifact(HardwareTier.B)
    artifact["measurements"]["device-id"] = "must-not-appear"

    result = validate_public_artifact(artifact)

    assert not result.valid
    assert any("forbidden public field" in error for error in result.errors)


@pytest.mark.parametrize("tier", list(HardwareTier))
def test_complete_physical_contract_can_be_verified(tier: HardwareTier) -> None:
    artifact = _verified_candidate(tier)

    result = validate_public_artifact(artifact)

    assert result.valid, result.errors


def test_missing_tier_measurement_is_rejected() -> None:
    artifact = _verified_candidate(HardwareTier.B)
    del artifact["measurements"]["battery_drop_percent"]

    result = validate_public_artifact(artifact)

    assert not result.valid
    assert any("battery_drop_percent" in error for error in result.errors)


def test_tier_d_requires_exactly_one_menfugu_action() -> None:
    artifact = _verified_candidate(HardwareTier.D)
    artifact["measurements"]["menfugu_action_count"] = 2

    result = validate_public_artifact(artifact)

    assert not result.valid
    assert any("exactly 1" in error for error in result.errors)


def test_s3_requires_ethics_approval() -> None:
    artifact = _verified_candidate(HardwareTier.S3)
    artifact["measurements"]["ethics_approved"] = False

    result = validate_public_artifact(artifact)

    assert not result.valid
    assert any("ethics_approved" in error for error in result.errors)
