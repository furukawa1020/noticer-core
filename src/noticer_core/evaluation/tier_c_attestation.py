"""Private-to-public verdict bridge for Android hardware key attestation."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from typing import Any

SCHEMA = "noticer.k5.tier_c_private_attestation_verdict.v1"
RECEIPT_SCHEMA = "noticer.k5.tier_c_public_receipt.v1"
DOMAIN = b"NOTICER-K5-TIER-C-RECEIPT-V1\x00"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FIELDS = frozenset(
    {
        "schema",
        "provenance",
        "preflight_digest",
        "private_bundle_sha256",
        "challenge_sha256",
        "expected_challenge_sha256",
        "chain_validated",
        "trusted_hardware_root",
        "security_level",
        "verified_boot_state",
        "device_locked",
        "app_package_match",
        "app_signing_digest_match",
        "app_version_match",
        "revocation_status",
        "revocation_snapshot_sha256",
        "lease_key_binding_valid",
        "lease_profile_binding_valid",
        "production_lease_issued",
        "stale_challenge_rejected",
        "replay_rejected",
        "downgrade_rejected",
        "wrong_app_rejected",
    }
)
_BOOLEAN_FIELDS = frozenset(
    {
        "chain_validated",
        "trusted_hardware_root",
        "device_locked",
        "app_package_match",
        "app_signing_digest_match",
        "app_version_match",
        "lease_key_binding_valid",
        "lease_profile_binding_valid",
        "production_lease_issued",
        "stale_challenge_rejected",
        "replay_rejected",
        "downgrade_rejected",
        "wrong_app_rejected",
    }
)


class TierCAttestationError(ValueError):
    """A fail-closed Tier C attestation bridge error."""


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()


def _require_hash(value: object, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise TierCAttestationError(f"{field} must be lowercase SHA-256")
    return value


def build_tier_c_receipt(private_verdict: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a private appraiser verdict and emit only bounded public facts."""

    if set(private_verdict) != _FIELDS:
        raise TierCAttestationError("private attestation verdict fields differ from contract")
    if private_verdict["schema"] != SCHEMA:
        raise TierCAttestationError("unexpected private attestation verdict schema")
    provenance = private_verdict["provenance"]
    if provenance not in {"PHYSICAL_MEASUREMENT", "SOFTWARE_FIXTURE"}:
        raise TierCAttestationError("unsupported attestation provenance")
    preflight_digest = _require_hash(private_verdict["preflight_digest"], "preflight_digest")
    private_bundle = _require_hash(
        private_verdict["private_bundle_sha256"], "private_bundle_sha256"
    )
    challenge = _require_hash(private_verdict["challenge_sha256"], "challenge_sha256")
    expected_challenge = _require_hash(
        private_verdict["expected_challenge_sha256"], "expected_challenge_sha256"
    )
    _require_hash(
        private_verdict["revocation_snapshot_sha256"], "revocation_snapshot_sha256"
    )
    for field in _BOOLEAN_FIELDS:
        if not isinstance(private_verdict[field], bool):
            raise TierCAttestationError(f"{field} must be boolean")
    security_level = private_verdict["security_level"]
    if security_level not in {"TEE", "STRONGBOX", "SOFTWARE"}:
        raise TierCAttestationError("security_level is invalid")
    boot_state = private_verdict["verified_boot_state"]
    if boot_state not in {"VERIFIED", "SELF_SIGNED", "UNVERIFIED", "FAILED"}:
        raise TierCAttestationError("verified_boot_state is invalid")
    revocation_status = private_verdict["revocation_status"]
    if revocation_status not in {"NORMAL", "REVOKED", "SUSPENDED", "NOT_CHECKED"}:
        raise TierCAttestationError("revocation_status is invalid")

    fresh_challenge = hmac.compare_digest(challenge, expected_challenge)
    eligible = all(
        (
            fresh_challenge,
            private_verdict["chain_validated"],
            private_verdict["trusted_hardware_root"],
            security_level in {"TEE", "STRONGBOX"},
            boot_state == "VERIFIED",
            private_verdict["device_locked"],
            private_verdict["app_package_match"],
            private_verdict["app_signing_digest_match"],
            private_verdict["app_version_match"],
            revocation_status == "NORMAL",
            private_verdict["lease_key_binding_valid"],
            private_verdict["lease_profile_binding_valid"],
            private_verdict["stale_challenge_rejected"],
            private_verdict["replay_rejected"],
            private_verdict["downgrade_rejected"],
            private_verdict["wrong_app_rejected"],
        )
    )
    if private_verdict["production_lease_issued"] is not eligible:
        raise TierCAttestationError(
            "production lease issuance disagrees with the appraiser verdict"
        )

    measurements = {
        "fresh_challenge_used": fresh_challenge,
        "attestation_chain_validated": bool(
            private_verdict["chain_validated"] and private_verdict["trusted_hardware_root"]
        ),
        "security_level": security_level,
        "verified_boot": boot_state == "VERIFIED",
        "device_locked": private_verdict["device_locked"],
        "app_identity_validated": bool(
            private_verdict["app_package_match"]
            and private_verdict["app_signing_digest_match"]
            and private_verdict["app_version_match"]
        ),
        "revocation_checked": revocation_status == "NORMAL",
        "production_lease_issued": private_verdict["production_lease_issued"],
        "stale_challenge_rejected": private_verdict["stale_challenge_rejected"],
        "replay_rejected": private_verdict["replay_rejected"],
        "downgrade_rejected": private_verdict["downgrade_rejected"],
        "wrong_app_rejected": private_verdict["wrong_app_rejected"],
    }
    body = {
        "schema": RECEIPT_SCHEMA,
        "tier": "C",
        "hardware_status": "NOT_VERIFIED",
        "review_status": (
            "READY_FOR_PHYSICAL_REVIEW"
            if provenance == "PHYSICAL_MEASUREMENT" and eligible
            else "SOFTWARE_FIXTURE_ONLY"
            if provenance == "SOFTWARE_FIXTURE"
            else "REJECTED_BY_PRIVATE_APPRAISER"
        ),
        "provenance": provenance,
        "preflight_digest": preflight_digest,
        "private_bundle_sha256": private_bundle,
        "measurements": measurements,
    }
    return {**body, "receipt_digest": hashlib.sha256(DOMAIN + _canonical_json(body)).hexdigest()}
