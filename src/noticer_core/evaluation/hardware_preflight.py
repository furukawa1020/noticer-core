"""Tamper-evident preflight plans for K5 physical measurement ceremonies."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from typing import Any

SCHEMA = "noticer.k5.hardware_preflight.v1"
DOMAIN = b"NOTICER-K5-HW-PREFLIGHT-V1\x00"
TIERS = frozenset({"B", "C", "D", "S3"})
PAYLOAD_FIELDS = frozenset(
    {
        "schema",
        "protocol_version",
        "tier",
        "public_run_id",
        "status",
        "evidence_origin",
        "protocol_sha256",
        "toolchain_sha256",
        "salted_consent_commitment_sha256",
        "salted_safety_commitment_sha256",
        "salted_stop_conditions_commitment_sha256",
        "private_storage_profile_sha256",
        "operator_approval_sha256",
        "safety_reviewer_approval_sha256",
        "ceremony_nonce_commitment_sha256",
    }
)
ENVELOPE_FIELDS = frozenset({"schema", "domain", "payload", "digest"})
HASH_FIELDS = frozenset(field for field in PAYLOAD_FIELDS if field.endswith("_sha256"))
FORBIDDEN_KEYS = frozenset(
    {
        "participant_id",
        "device_id",
        "consent_document",
        "operator_name",
        "reviewer_name",
        "raw_ppg",
        "raw_acc",
        "key_material",
        "ceremony_nonce",
    }
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class PreflightError(ValueError):
    """A fail-closed K5 preflight validation error."""


def canonical_json(value: Any) -> bytes:
    """Encode canonical UTF-8 JSON without platform-dependent whitespace."""

    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()


def protocol_sha256(protocol_bytes: bytes) -> str:
    """Commit to the exact protocol bytes used by a measurement ceremony."""

    return hashlib.sha256(protocol_bytes).hexdigest()


def _normalise_key(key: object) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(key).strip().lower()).strip("_")


def _reject_forbidden_keys(value: object, path: str = "payload") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if _normalise_key(key) in FORBIDDEN_KEYS:
                raise PreflightError(f"forbidden public preflight field: {child_path}")
            _reject_forbidden_keys(child, child_path)
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _reject_forbidden_keys(child, f"{path}[{index}]")


def validate_payload(payload: Mapping[str, Any]) -> None:
    """Validate a public preflight payload without claiming physical execution."""

    if set(payload) != PAYLOAD_FIELDS:
        missing = sorted(PAYLOAD_FIELDS - set(payload))
        unknown = sorted(set(payload) - PAYLOAD_FIELDS)
        raise PreflightError(f"preflight fields differ: missing={missing}, unknown={unknown}")
    _reject_forbidden_keys(payload)
    if payload["schema"] != SCHEMA:
        raise PreflightError("unexpected preflight schema")
    if payload["protocol_version"] != "K5-HW-1.0":
        raise PreflightError("unexpected hardware protocol version")
    if payload["tier"] not in TIERS:
        raise PreflightError("tier must be B, C, D, or S3")
    if not isinstance(payload["public_run_id"], str) or not _RUN_ID.fullmatch(
        payload["public_run_id"]
    ):
        raise PreflightError("public_run_id must be a bounded non-identifying label")
    if payload["status"] != "NOT_VERIFIED" or payload["evidence_origin"] != "NONE":
        raise PreflightError("preflight cannot claim physical verification")
    for field in HASH_FIELDS:
        value = payload[field]
        if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
            raise PreflightError(f"{field} must be lowercase SHA-256")
    if hmac.compare_digest(
        payload["operator_approval_sha256"],
        payload["safety_reviewer_approval_sha256"],
    ):
        raise PreflightError("operator and safety reviewer approvals must be role-separated")


def seal_preflight(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Return a domain-separated, tamper-evident envelope for a validated plan."""

    normalized = dict(payload)
    validate_payload(normalized)
    digest = hashlib.sha256(DOMAIN + canonical_json(normalized)).hexdigest()
    return {
        "schema": SCHEMA,
        "domain": DOMAIN[:-1].decode("ascii"),
        "payload": normalized,
        "digest": digest,
    }


def verify_preflight(
    envelope: Mapping[str, Any],
    *,
    expected_protocol_sha256: str,
) -> dict[str, Any]:
    """Verify an envelope and bind it to the caller's exact protocol bytes."""

    if set(envelope) != ENVELOPE_FIELDS:
        raise PreflightError("preflight envelope has unexpected fields")
    if envelope["schema"] != SCHEMA or envelope["domain"] != DOMAIN[:-1].decode("ascii"):
        raise PreflightError("preflight envelope identity mismatch")
    payload = envelope["payload"]
    if not isinstance(payload, Mapping):
        raise PreflightError("preflight payload must be an object")
    validate_payload(payload)
    if not isinstance(envelope["digest"], str) or _SHA256.fullmatch(envelope["digest"]) is None:
        raise PreflightError("preflight digest must be lowercase SHA-256")
    actual = hashlib.sha256(DOMAIN + canonical_json(payload)).hexdigest()
    if not hmac.compare_digest(actual, envelope["digest"]):
        raise PreflightError("preflight digest mismatch")
    if not hmac.compare_digest(payload["protocol_sha256"], expected_protocol_sha256):
        raise PreflightError("preflight protocol commitment mismatch")
    return dict(payload)
