"""Independent N-bucket bounded longitudinal composition oracle."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass

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
from noticer_core.evaluation.two_component_composition import (
    CompositionError,
    SourceVerdict,
)

FORMAT_VERSION = "noticer.k7.n-bucket-composition.v1"


@dataclass(frozen=True)
class LongitudinalBucket:
    bucket_id: str
    source_certificate_sha256: str
    bounds: ResourceBounds
    aqni_verdict: SourceVerdict
    utility_verdict: SourceVerdict
    incoming: PublicHandoffContract | None
    outgoing: PublicHandoffContract | None


@dataclass(frozen=True)
class NBucketCertificate:
    format_version: str
    bucket_ids: tuple[str, ...]
    source_certificate_sha256: tuple[str, ...]
    boundary_witness_sha256: tuple[str, ...]
    composed_bounds: ResourceBounds
    induction_steps: int
    proof_status: str
    security_proof: bool = False


def compose_n(buckets: tuple[LongitudinalBucket, ...]) -> NBucketCertificate:
    """Induct over an ordered non-empty bucket sequence."""
    if not buckets:
        raise CompositionError("empty_bucket_sequence")
    if len({bucket.bucket_id for bucket in buckets}) != len(buckets):
        raise CompositionError("duplicate_bucket")
    for index, bucket in enumerate(buckets):
        _validate_bucket(bucket, index, len(buckets))
    witnesses: list[str] = []
    for index, (left, right) in enumerate(zip(buckets, buckets[1:], strict=False)):
        assert left.outgoing is not None and right.incoming is not None
        witness = check_compatibility(left.outgoing, right.incoming)
        if witness.decision is not CompatibilityDecision.COMPATIBLE:
            raise CompositionError(
                f"boundary_{index}_incompatible:{witness.mismatch_reasons[0]}"
            )
        witnesses.append(witness_digest(witness))
    return NBucketCertificate(
        format_version=FORMAT_VERSION,
        bucket_ids=tuple(bucket.bucket_id for bucket in buckets),
        source_certificate_sha256=tuple(
            bucket.source_certificate_sha256 for bucket in buckets
        ),
        boundary_witness_sha256=tuple(witnesses),
        composed_bounds=_sum_bounds(buckets),
        induction_steps=len(buckets) - 1,
        proof_status="INDEPENDENT_ORACLE_ACCEPTED",
    )


def independently_check_n(
    certificate: NBucketCertificate,
    buckets: tuple[LongitudinalBucket, ...],
) -> bool:
    """Recompute order, bindings, every boundary, and resource accumulation."""
    try:
        expected = compose_n(buckets)
    except (CompositionError, ValueError):
        return False
    return certificate == expected


def canonical_n_certificate_json(certificate: NBucketCertificate) -> bytes:
    return (
        json.dumps(asdict(certificate), sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def n_certificate_digest(certificate: NBucketCertificate) -> str:
    return hashlib.sha256(canonical_n_certificate_json(certificate)).hexdigest()


def _validate_bucket(bucket: LongitudinalBucket, index: int, count: int) -> None:
    if not bucket.bucket_id:
        raise CompositionError("empty_bucket_id")
    if bucket.aqni_verdict is not SourceVerdict.VERIFIED:
        raise CompositionError(f"bucket_{index}_aqni_not_verified")
    if bucket.utility_verdict is not SourceVerdict.VERIFIED:
        raise CompositionError(f"bucket_{index}_utility_not_verified")
    if index > 0 and bucket.incoming is None:
        raise CompositionError(f"bucket_{index}_missing_incoming")
    if index + 1 < count and bucket.outgoing is None:
        raise CompositionError(f"bucket_{index}_missing_outgoing")
    for side, contract in (("incoming", bucket.incoming), ("outgoing", bucket.outgoing)):
        if contract is None:
            continue
        if contract.source_certificate_sha256 != bucket.source_certificate_sha256:
            raise CompositionError(f"bucket_{index}_{side}_source_mismatch")
        if contract.bounds != bucket.bounds:
            raise CompositionError(f"bucket_{index}_{side}_bounds_mismatch")
        contract_digest(contract)


def _sum_bounds(buckets: tuple[LongitudinalBucket, ...]) -> ResourceBounds:
    return ResourceBounds(
        sum(bucket.bounds.horizon_slots for bucket in buckets),
        sum(bucket.bounds.max_queries for bucket in buckets),
        sum(bucket.bounds.max_retries for bucket in buckets),
        sum(bucket.bounds.max_failures for bucket in buckets),
    )
