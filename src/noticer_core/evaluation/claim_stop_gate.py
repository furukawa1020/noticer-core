"""Machine-readable claim-stop gate for K7 adaptive leakage evaluation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from enum import StrEnum

from noticer_core.attacks.leaky_control import LeakyControlReport
from noticer_core.evaluation.adaptive_leakage import AdaptiveLeakageReport


class ClaimStopDecision(StrEnum):
    GO_CANDIDATE = "GO_CANDIDATE"
    BLOCKED = "BLOCKED"
    INVALID_EVALUATION = "INVALID_EVALUATION"


class ClaimStopGateError(ValueError):
    """Raised when gate inputs are not content-addressed."""


@dataclass(frozen=True)
class ClaimStopGateArtifact:
    schema: str
    decision: ClaimStopDecision
    reasons: tuple[str, ...]
    maximum_excess_ci95_lower: float
    implementation_claim_allowed: bool
    security_proof: bool
    input_sha256: dict[str, str]
    artifact_sha256: str


def evaluate_claim_stop_gate(
    leakage: AdaptiveLeakageReport,
    control: LeakyControlReport,
    *,
    evaluation_complete: bool,
    stable_excess_lower_bound: float,
    input_sha256: dict[str, str],
) -> ClaimStopGateArtifact:
    """Apply fail-closed claim rules in a fixed order."""
    _validate_digests(input_sha256)
    if stable_excess_lower_bound < 0:
        raise ClaimStopGateError("stable excess threshold must be non-negative")
    maximum_lower = max(item.ci95[0] for item in leakage.full_trace_excess)
    reasons: list[str] = []

    if not evaluation_complete:
        decision = ClaimStopDecision.INVALID_EVALUATION
        reasons.append("EVALUATION_INCOMPLETE")
    elif not control.detected:
        decision = ClaimStopDecision.INVALID_EVALUATION
        reasons.append("LEAKY_CONTROL_NOT_DETECTED")
    elif not leakage.pointwise_trace_equal:
        decision = ClaimStopDecision.BLOCKED
        reasons.append("POINTWISE_TRACE_EQUALITY_FAILED")
    elif maximum_lower > stable_excess_lower_bound:
        decision = ClaimStopDecision.BLOCKED
        reasons.append("FULL_TRACE_EXCESS_STABLY_POSITIVE")
    else:
        decision = ClaimStopDecision.GO_CANDIDATE
        reasons.append("NO_REGISTERED_REFUTATION")

    payload = {
        "schema": "noticer.k7.claim-stop-gate.v1",
        "decision": decision.value,
        "reasons": reasons,
        "maximum_excess_ci95_lower": maximum_lower,
        "implementation_claim_allowed": decision is ClaimStopDecision.GO_CANDIDATE,
        "security_proof": False,
        "input_sha256": dict(sorted(input_sha256.items())),
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return ClaimStopGateArtifact(
        schema=str(payload["schema"]),
        decision=decision,
        reasons=tuple(reasons),
        maximum_excess_ci95_lower=maximum_lower,
        implementation_claim_allowed=decision is ClaimStopDecision.GO_CANDIDATE,
        security_proof=False,
        input_sha256=dict(sorted(input_sha256.items())),
        artifact_sha256=digest,
    )


def canonical_gate_json(artifact: ClaimStopGateArtifact) -> bytes:
    """Serialize a gate artifact canonically for generated evidence."""
    payload = asdict(artifact)
    payload["decision"] = artifact.decision.value
    return (
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _validate_digests(values: dict[str, str]) -> None:
    required = {
        "runtime_capture",
        "corpus",
        "attack_protocol",
        "leakage_report",
        "control_report",
    }
    if set(values) != required:
        raise ClaimStopGateError("all five input digests are required")
    if any(
        len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
        for value in values.values()
    ):
        raise ClaimStopGateError("input digest is not lowercase SHA-256")


