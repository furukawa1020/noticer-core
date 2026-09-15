"""Bounded sequential composition for two compatible AQNI buckets."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from enum import StrEnum

from noticer_core.evaluation.certificate_compatibility import (
    CompatibilityDecision,
    check_compatibility,
    witness_digest,
)
from noticer_core.evaluation.public_handoff import (
    PublicHandoffContract,
    ResourceBounds,
    contract_digest,
)

FORMAT_VERSION = "noticer.k7.two-component-composition.v1"


class SourceVerdict(StrEnum):
    VERIFIED = "VERIFIED"
    COUNTEREXAMPLE = "COUNTEREXAMPLE"
    INCONCLUSIVE = "INCONCLUSIVE"
    INVALID = "INVALID"


class CompositionError(ValueError):
    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


@dataclass(frozen=True)
class CertifiedBucket:
    contract: PublicHandoffContract
    aqni_verdict: SourceVerdict
    utility_verdict: SourceVerdict


@dataclass(frozen=True)
class TwoComponentCertificate:
    format_version: str
    left_contract_sha256: str
    right_contract_sha256: str
    compatibility_witness_sha256: str
    composed_bounds: ResourceBounds
    derivation: str
    proof_status: str
    security_proof: bool = False


def compose_two(
    left: CertifiedBucket, right: CertifiedBucket
) -> TwoComponentCertificate:
    """Derive a bounded candidate only from two verified compatible sources."""
    for side, bucket in (("left", left), ("right", right)):
        if bucket.aqni_verdict is not SourceVerdict.VERIFIED:
            raise CompositionError(f"{side}_aqni_not_verified")
        if bucket.utility_verdict is not SourceVerdict.VERIFIED:
            raise CompositionError(f"{side}_utility_not_verified")
    witness = check_compatibility(left.contract, right.contract)
    if witness.decision is not CompatibilityDecision.COMPATIBLE:
        reason = witness.mismatch_reasons[0]
        raise CompositionError(f"incompatible_handoff:{reason}")
    a, b = left.contract.bounds, right.contract.bounds
    return TwoComponentCertificate(
        format_version=FORMAT_VERSION,
        left_contract_sha256=contract_digest(left.contract),
        right_contract_sha256=contract_digest(right.contract),
        compatibility_witness_sha256=witness_digest(witness),
        composed_bounds=ResourceBounds(
            a.horizon_slots + b.horizon_slots,
            a.max_queries + b.max_queries,
            a.max_retries + b.max_retries,
            a.max_failures + b.max_failures,
        ),
        derivation="bounded-sequential-public-handoff-v1",
        proof_status="DERIVED_CANDIDATE",
    )


def independently_check_bounds(
    certificate: TwoComponentCertificate,
    left: PublicHandoffContract,
    right: PublicHandoffContract,
) -> bool:
    """Recompute all additive bounds without trusting the derivation output."""
    a, b = left.bounds, right.bounds
    expected = ResourceBounds(
        a.horizon_slots + b.horizon_slots,
        a.max_queries + b.max_queries,
        a.max_retries + b.max_retries,
        a.max_failures + b.max_failures,
    )
    return (
        certificate.left_contract_sha256 == contract_digest(left)
        and certificate.right_contract_sha256 == contract_digest(right)
        and certificate.composed_bounds == expected
    )


def canonical_composition_json(certificate: TwoComponentCertificate) -> bytes:
    return (json.dumps(asdict(certificate), sort_keys=True, separators=(",", ":"))
            + "\n").encode("utf-8")


def composition_digest(certificate: TwoComponentCertificate) -> str:
    return hashlib.sha256(canonical_composition_json(certificate)).hexdigest()
