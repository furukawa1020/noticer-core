"""Strict validation for a public K20 review capsule and its declared digest."""

import hmac
import json
from dataclasses import dataclass

from noticer_core.evaluation.k20_capsule import (
    PublicEndpoint,
    PublicSummary,
    encode_public_capsule,
    public_capsule_digest,
)
from noticer_core.evaluation.k20_dataset_manifest import EvidenceClass

_SCHEMA = "noticer.k20.public-capsule.v1"
_ROOT_KEYS = {"schema", "evidence_class", "public_protocol_sha256", "summaries"}
_ROW_KEYS = {"endpoint", "estimate", "lower", "upper", "independent_units"}


@dataclass(frozen=True, slots=True)
class ValidatedPublicCapsule:
    digest: str
    evidence_class: EvidenceClass
    public_protocol_sha256: str
    summaries: tuple[PublicSummary, ...]


def validate_public_package(data: bytes, *, expected_digest: str) -> ValidatedPublicCapsule:
    """Reject tampered, extended or noncanonical capsules before using them in figures."""
    if type(data) is not bytes or not 1 <= len(data) <= 65_536:
        raise ValueError("public capsule must be a bounded byte string")
    if not isinstance(expected_digest, str) or len(expected_digest) != 64 or not all(
        ch in "0123456789abcdef" for ch in expected_digest
    ):
        raise ValueError("expected digest must be canonical lowercase SHA-256")
    digest = public_capsule_digest(data)
    if not hmac.compare_digest(digest, expected_digest):
        raise ValueError("public capsule digest mismatch")
    try:
        parsed = json.loads(data)
    except (ValueError, RecursionError) as error:
        raise ValueError("invalid public capsule JSON") from error
    if not isinstance(parsed, dict) or set(parsed) != _ROOT_KEYS or parsed["schema"] != _SCHEMA:
        raise ValueError("public capsule root does not match the allowlist")
    rows = parsed["summaries"]
    if not isinstance(rows, list) or not all(
        isinstance(row, dict) and set(row) == _ROW_KEYS for row in rows
    ):
        raise ValueError("public capsule rows do not match the allowlist")
    protocol = parsed["public_protocol_sha256"]
    if not isinstance(protocol, str):
        raise ValueError("public protocol digest must be a string")
    try:
        evidence = EvidenceClass(parsed["evidence_class"])
        summaries = tuple(
            PublicSummary(
                PublicEndpoint(row["endpoint"]),
                row["estimate"],
                row["lower"],
                row["upper"],
                row["independent_units"],
            )
            for row in rows
        )
        canonical = encode_public_capsule(
            evidence_class=evidence, public_protocol_sha256=protocol, summaries=summaries
        )
    except (TypeError, ValueError, OverflowError) as error:
        raise ValueError("public capsule contains invalid field values") from error
    if data != canonical:
        raise ValueError("public capsule is not canonical")
    return ValidatedPublicCapsule(digest, evidence, protocol, summaries)
