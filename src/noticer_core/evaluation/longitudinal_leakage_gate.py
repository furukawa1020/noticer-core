"""Repeated-claim leakage accounting and longitudinal claim-stop gate."""
from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import asdict, dataclass

from noticer_core.evaluation.claim_stop_gate import ClaimStopDecision

FORMAT_VERSION = "noticer.k7.longitudinal-leakage-gate.v1"
_SHA256 = re.compile(r"[0-9a-f]{64}")
_REQUIRED_INPUTS = frozenset(
    {"composition", "counterexamples", "attack", "control", "corpus"}
)


class LongitudinalGateError(ValueError):
    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


@dataclass(frozen=True)
class BucketLeakage:
    bucket_id: str
    allowed_claim_bits: float
    observed_full_trace_bits: float


@dataclass(frozen=True)
class LongitudinalLeakageArtifact:
    format_version: str
    decision: ClaimStopDecision
    bucket_ids: tuple[str, ...]
    allowed_claim_bits_total: float
    observed_full_trace_bits_total: float
    excess_leakage_bits: float
    paired_excess_ci_low: float
    paired_excess_ci_high: float
    excess_threshold: float
    reasons: tuple[str, ...]
    input_sha256: tuple[tuple[str, str], ...]
    implementation_claim_allowed: bool
    security_proof: bool = False


def evaluate_longitudinal_gate(
    buckets: tuple[BucketLeakage, ...],
    *,
    paired_excess_ci: tuple[float, float],
    composition_oracle_accepted: bool,
    counterexamples_rejected: bool,
    attack_complete: bool,
    leaky_control_detected: bool,
    input_sha256: dict[str, str],
    excess_threshold: float = 0.0,
) -> LongitudinalLeakageArtifact:
    """Separate allowed repeated claims from excess trace leakage and gate claims."""
    _validate_inputs(buckets, paired_excess_ci, input_sha256, excess_threshold)
    allowed = sum(bucket.allowed_claim_bits for bucket in buckets)
    observed = sum(bucket.observed_full_trace_bits for bucket in buckets)
    low, high = paired_excess_ci
    reasons: list[str] = []
    if not attack_complete:
        reasons.append("attack_incomplete")
    if not leaky_control_detected:
        reasons.append("leaky_control_failed")
    if reasons:
        decision = ClaimStopDecision.INVALID_EVALUATION
    else:
        if not composition_oracle_accepted:
            reasons.append("composition_oracle_rejected")
        if not counterexamples_rejected:
            reasons.append("counterexample_not_rejected")
        if low > excess_threshold:
            reasons.append("stable_excess_leakage")
        decision = (
            ClaimStopDecision.BLOCKED
            if reasons
            else ClaimStopDecision.GO_CANDIDATE
        )
    return LongitudinalLeakageArtifact(
        format_version=FORMAT_VERSION,
        decision=decision,
        bucket_ids=tuple(bucket.bucket_id for bucket in buckets),
        allowed_claim_bits_total=allowed,
        observed_full_trace_bits_total=observed,
        excess_leakage_bits=observed - allowed,
        paired_excess_ci_low=low,
        paired_excess_ci_high=high,
        excess_threshold=excess_threshold,
        reasons=tuple(sorted(reasons)),
        input_sha256=tuple(sorted(input_sha256.items())),
        implementation_claim_allowed=decision is ClaimStopDecision.GO_CANDIDATE,
    )


def canonical_longitudinal_gate_json(
    artifact: LongitudinalLeakageArtifact,
) -> bytes:
    payload = asdict(artifact)
    payload["decision"] = artifact.decision.value
    return (
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def longitudinal_gate_digest(artifact: LongitudinalLeakageArtifact) -> str:
    return hashlib.sha256(canonical_longitudinal_gate_json(artifact)).hexdigest()


def _validate_inputs(
    buckets: tuple[BucketLeakage, ...],
    paired_ci: tuple[float, float],
    digests: dict[str, str],
    threshold: float,
) -> None:
    if not buckets:
        raise LongitudinalGateError("empty_sequence")
    ids = tuple(bucket.bucket_id for bucket in buckets)
    if any(not value for value in ids) or len(set(ids)) != len(ids):
        raise LongitudinalGateError("invalid_bucket_ids")
    leakage_values = tuple(
        value
        for bucket in buckets
        for value in (bucket.allowed_claim_bits, bucket.observed_full_trace_bits)
    )
    if any(not math.isfinite(value) for value in (*leakage_values, *paired_ci, threshold)):
        raise LongitudinalGateError("nonfinite_value")
    if any(value < 0 for value in leakage_values):
        raise LongitudinalGateError("negative_leakage")
    if paired_ci[0] > paired_ci[1]:
        raise LongitudinalGateError("invalid_confidence_interval")
    if threshold < 0:
        raise LongitudinalGateError("negative_threshold")
    if set(digests) != _REQUIRED_INPUTS:
        raise LongitudinalGateError("incomplete_input_binding")
    if any(_SHA256.fullmatch(value) is None for value in digests.values()):
        raise LongitudinalGateError("invalid_digest")
