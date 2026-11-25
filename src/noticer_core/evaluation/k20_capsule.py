"""Allowlisted aggregate capsule for K20. This is not claim authorization."""

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from math import isfinite

from noticer_core.evaluation.k20_dataset_manifest import EvidenceClass


class PublicEndpoint(StrEnum):
    IDENTITY_ADVANTAGE = "identity-advantage"
    LINKABILITY_AUC = "linkability-auc"
    DEADLINE_RATE = "deadline-rate"
    LATENCY_NS = "latency-ns"
    WIRE_BYTES = "wire-bytes"


@dataclass(frozen=True, slots=True)
class PublicSummary:
    endpoint: PublicEndpoint
    estimate: float
    lower: float
    upper: float
    independent_units: int


def encode_public_capsule(
    *,
    evidence_class: EvidenceClass,
    public_protocol_sha256: str,
    summaries: tuple[PublicSummary, ...],
) -> bytes:
    """Encode fixed aggregate fields; do not pass private dataset or row digests.

    The caller must enforce consent, disclosure minimums and release approval.
    This encoding alone does not establish anonymity or validate a claim.
    """
    if not isinstance(evidence_class, EvidenceClass):
        raise ValueError("evidence class must use the registered vocabulary")
    if len(public_protocol_sha256) != 64 or any(
        digit not in "0123456789abcdef" for digit in public_protocol_sha256
    ):
        raise ValueError("expected a canonical digest of the public protocol")
    seen: set[PublicEndpoint] = set()
    rows = []
    for entry in summaries:
        endpoint = entry.endpoint
        if not isinstance(endpoint, PublicEndpoint) or endpoint in seen:
            raise ValueError("summary endpoint must be allowed and unique")
        seen.add(endpoint)
        values = (entry.estimate, entry.lower, entry.upper)
        if not all(type(value) in (int, float) and isfinite(value) for value in values):
            raise ValueError("summary statistics must be finite numeric values")
        if not entry.lower <= entry.estimate <= entry.upper:
            raise ValueError("summary estimate must be enclosed by its interval")
        if type(entry.independent_units) is not int or entry.independent_units < 1:
            raise ValueError("summary requires a positive number of independent units")
        rows.append({
            "endpoint": endpoint.value,
            "estimate": entry.estimate,
            "lower": entry.lower,
            "upper": entry.upper,
            "independent_units": entry.independent_units,
        })
    if not rows:
        raise ValueError("at least one aggregate summary is required")
    metadata = {
        "schema": "noticer.k20.public-capsule.v1",
        "evidence_class": evidence_class.value,
        "public_protocol_sha256": public_protocol_sha256,
        "summaries": sorted(rows, key=lambda row: row["endpoint"]),
    }
    canonical = json.dumps(metadata, allow_nan=False, sort_keys=True, separators=(",", ":"))
    return canonical.encode("ascii")


def public_capsule_digest(canonical: bytes) -> str:
    """Identify the released bytes, not private inputs or identities."""
    return hashlib.sha256(b"NOTICER_K20_PUBLIC_CAPSULE_V1\0" + canonical).hexdigest()
