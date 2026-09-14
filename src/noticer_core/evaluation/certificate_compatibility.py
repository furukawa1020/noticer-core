"""Compatibility relation for adjacent bounded-AQNI handoff contracts."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from enum import StrEnum

from noticer_core.evaluation.public_handoff import (
    PublicHandoffContract,
    contract_digest,
    validate_contract,
)

FORMAT_VERSION = "noticer.k7.certificate-compatibility.v1"


class CompatibilityDecision(StrEnum):
    COMPATIBLE = "COMPATIBLE"
    INCOMPATIBLE = "INCOMPATIBLE"


@dataclass(frozen=True)
class CompatibilityWitness:
    format_version: str
    decision: CompatibilityDecision
    left_contract_sha256: str
    right_contract_sha256: str
    matched_dimensions: tuple[str, ...]
    mismatch_reasons: tuple[str, ...]
    security_proof: bool = False


def check_compatibility(
    left: PublicHandoffContract,
    right: PublicHandoffContract,
) -> CompatibilityWitness:
    """Accept only adjacent contracts with an identical public boundary."""
    validate_contract(left)
    validate_contract(right)
    comparisons = (
        ("action_semantics", left.action_semantics_sha256, right.action_semantics_sha256),
        ("observer_contract", left.observer_contract_sha256, right.observer_contract_sha256),
        ("observer_state", left.state.observer_state_sha256, right.state.observer_state_sha256),
        ("service_collusion", left.state.colluding_services, right.state.colluding_services),
        ("epoch", left.state.epoch_id, right.state.epoch_id),
        ("key_epoch", left.state.key_epoch_id, right.state.key_epoch_id),
    )
    matched = tuple(name for name, a, b in comparisons if a == b)
    mismatches = [name for name, a, b in comparisons if a != b]
    if left.state.epoch_event_slot != left.bounds.horizon_slots:
        mismatches.append("left_boundary_slot")
    else:
        matched += ("left_boundary_slot",)
    if right.state.epoch_event_slot != 0:
        mismatches.append("right_boundary_slot")
    else:
        matched += ("right_boundary_slot",)
    reasons = tuple(sorted(mismatches))
    return CompatibilityWitness(
        format_version=FORMAT_VERSION,
        decision=(
            CompatibilityDecision.COMPATIBLE
            if not reasons
            else CompatibilityDecision.INCOMPATIBLE
        ),
        left_contract_sha256=contract_digest(left),
        right_contract_sha256=contract_digest(right),
        matched_dimensions=tuple(sorted(matched)),
        mismatch_reasons=reasons,
    )


def canonical_witness_json(witness: CompatibilityWitness) -> bytes:
    payload = asdict(witness)
    payload["decision"] = witness.decision.value
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()


def witness_digest(witness: CompatibilityWitness) -> str:
    return hashlib.sha256(canonical_witness_json(witness)).hexdigest()
