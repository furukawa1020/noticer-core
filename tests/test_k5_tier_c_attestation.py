from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

from noticer_core.evaluation.tier_c_attestation import (
    TierCAttestationError,
    build_tier_c_receipt,
)


def _verdict(provenance: str = "PHYSICAL_MEASUREMENT") -> dict[str, Any]:
    return {
        "schema": "noticer.k5.tier_c_private_attestation_verdict.v1",
        "provenance": provenance,
        "preflight_digest": "a" * 64,
        "private_bundle_sha256": "b" * 64,
        "challenge_sha256": "c" * 64,
        "expected_challenge_sha256": "c" * 64,
        "chain_validated": True,
        "trusted_hardware_root": True,
        "security_level": "STRONGBOX",
        "verified_boot_state": "VERIFIED",
        "device_locked": True,
        "app_package_match": True,
        "app_signing_digest_match": True,
        "app_version_match": True,
        "revocation_status": "NORMAL",
        "revocation_snapshot_sha256": "d" * 64,
        "lease_key_binding_valid": True,
        "lease_profile_binding_valid": True,
        "production_lease_issued": True,
        "stale_challenge_rejected": True,
        "replay_rejected": True,
        "downgrade_rejected": True,
        "wrong_app_rejected": True,
    }


def test_valid_private_verdict_emits_bounded_receipt_without_chain() -> None:
    receipt = build_tier_c_receipt(_verdict())

    assert receipt["hardware_status"] == "NOT_VERIFIED"
    assert receipt["review_status"] == "READY_FOR_PHYSICAL_REVIEW"
    assert receipt["measurements"]["security_level"] == "STRONGBOX"
    assert receipt["measurements"]["production_lease_issued"] is True
    encoded = str(receipt)
    assert "challenge_sha256" not in encoded
    assert "revocation_snapshot" not in encoded
    assert "certificate" not in encoded


def test_software_fixture_never_becomes_physical_evidence() -> None:
    receipt = build_tier_c_receipt(_verdict("SOFTWARE_FIXTURE"))

    assert receipt["hardware_status"] == "NOT_VERIFIED"
    assert receipt["review_status"] == "SOFTWARE_FIXTURE_ONLY"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("security_level", "SOFTWARE"),
        ("verified_boot_state", "SELF_SIGNED"),
        ("device_locked", False),
        ("revocation_status", "REVOKED"),
        ("wrong_app_rejected", False),
    ],
)
def test_failed_security_condition_requires_zero_lease(field: str, value: Any) -> None:
    verdict = _verdict()
    verdict[field] = value
    verdict["production_lease_issued"] = False

    receipt = build_tier_c_receipt(verdict)
    assert receipt["review_status"] == "REJECTED_BY_PRIVATE_APPRAISER"
    assert receipt["measurements"]["production_lease_issued"] is False


def test_lease_issuance_disagreement_and_private_field_fail_closed() -> None:
    verdict = _verdict()
    verdict["expected_challenge_sha256"] = "e" * 64
    with pytest.raises(TierCAttestationError, match="lease issuance disagrees"):
        build_tier_c_receipt(verdict)

    verdict = deepcopy(_verdict())
    verdict["certificate_chain"] = ["private"]
    with pytest.raises(TierCAttestationError, match="fields differ"):
        build_tier_c_receipt(verdict)
