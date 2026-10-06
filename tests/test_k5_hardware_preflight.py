from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from noticer_core.evaluation.hardware_preflight import (
    PreflightError,
    protocol_sha256,
    seal_preflight,
    verify_preflight,
)

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "configs" / "k5" / "hardware_protocol.yaml"


def _payload(tier: str = "B") -> dict[str, Any]:
    return {
        "schema": "noticer.k5.hardware_preflight.v1",
        "protocol_version": "K5-HW-1.0",
        "tier": tier,
        "public_run_id": f"preflight-{tier}",
        "status": "NOT_VERIFIED",
        "evidence_origin": "NONE",
        "protocol_sha256": protocol_sha256(PROTOCOL.read_bytes()),
        "toolchain_sha256": "1" * 64,
        "salted_consent_commitment_sha256": "2" * 64,
        "salted_safety_commitment_sha256": "3" * 64,
        "salted_stop_conditions_commitment_sha256": "4" * 64,
        "private_storage_profile_sha256": "5" * 64,
        "operator_approval_sha256": "6" * 64,
        "safety_reviewer_approval_sha256": "7" * 64,
        "ceremony_nonce_commitment_sha256": "8" * 64,
    }


@pytest.mark.parametrize("tier", ["B", "C", "D", "S3"])
def test_all_tiers_seal_deterministically_without_promotion(tier: str) -> None:
    payload = _payload(tier)
    first = seal_preflight(payload)
    second = seal_preflight(dict(reversed(list(payload.items()))))

    assert first == second
    assert first["payload"]["status"] == "NOT_VERIFIED"
    verified = verify_preflight(
        first,
        expected_protocol_sha256=protocol_sha256(PROTOCOL.read_bytes()),
    )
    assert verified == payload


def test_payload_and_protocol_tamper_fail_closed() -> None:
    envelope = seal_preflight(_payload())
    altered = deepcopy(envelope)
    altered["payload"]["tier"] = "C"
    with pytest.raises(PreflightError, match="digest mismatch"):
        verify_preflight(
            altered,
            expected_protocol_sha256=protocol_sha256(PROTOCOL.read_bytes()),
        )
    with pytest.raises(PreflightError, match="protocol commitment"):
        verify_preflight(envelope, expected_protocol_sha256="f" * 64)


def test_preflight_cannot_claim_verified_or_physical_origin() -> None:
    payload = _payload()
    payload["status"] = "VERIFIED"
    payload["evidence_origin"] = "PHYSICAL_MEASUREMENT"
    with pytest.raises(PreflightError, match="cannot claim physical"):
        seal_preflight(payload)


def test_role_separation_and_private_fields_are_enforced() -> None:
    payload = _payload()
    payload["safety_reviewer_approval_sha256"] = payload["operator_approval_sha256"]
    with pytest.raises(PreflightError, match="role-separated"):
        seal_preflight(payload)

    payload = _payload()
    payload["participant_id"] = "forbidden"
    with pytest.raises(PreflightError, match="preflight fields differ"):
        seal_preflight(payload)
