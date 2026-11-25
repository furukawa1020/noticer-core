"""Mechanical decision over scoped evidence verdicts, not a security proof."""

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

from noticer_core.evaluation.k20_dataset_manifest import DatasetManifest, DatasetManifestError


class ClaimGate(StrEnum):
    INPUT_PROVENANCE = "input-provenance"
    ACTION_EQUIVALENCE = "action-equivalence"
    ATTACK_COVERAGE = "attack-coverage"
    VALID_CONTROLS = "valid-controls"
    MEANINGFUL_PRIVACY_EFFECT = "meaningful-privacy-effect"
    MULTIPLICITY = "multiplicity"
    UTILITY_NONINFERIORITY = "utility-noninferiority"
    DEADLINE_LIVENESS_SAFETY = "deadline-liveness-safety"
    REPRODUCIBILITY = "reproducibility"


class CheckState(StrEnum):
    PASS = "pass"
    FAILED = "failed"
    INVALID = "invalid"
    INCONCLUSIVE = "inconclusive"


class ClaimVerdict(StrEnum):
    VERIFIED = "verified"
    FAILED = "failed"
    INVALID = "invalid"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True, slots=True)
class ClaimDecision:
    verdict: ClaimVerdict
    missing: tuple[ClaimGate, ...] = ()
    blockers: tuple[tuple[ClaimGate, CheckState], ...] = ()
    reason: str | None = None


def decide_claim(
    manifest: DatasetManifest, observations: Mapping[ClaimGate, CheckState]
) -> ClaimDecision:
    """Combine precomputed independent checks and retain every blocking reason.

    The caller is responsible for binding checks to the same preregistered run
    and evaluating them from trusted artifacts. This function does not prove
    privacy, authenticate the dataset, or replace publication approval.
    """
    try:
        manifest.validate()
    except (DatasetManifestError, AttributeError, TypeError):
        return ClaimDecision(ClaimVerdict.INVALID, reason="invalid dataset manifest")
    if any(not isinstance(gate, ClaimGate) or not isinstance(state, CheckState)
           for gate, state in observations.items()):
        return ClaimDecision(ClaimVerdict.INVALID, reason="unknown check or state")
    missing = tuple(gate for gate in ClaimGate if gate not in observations)
    blockers = tuple(
        (gate, observations[gate])
        for gate in ClaimGate
        if gate in observations and observations[gate] is not CheckState.PASS
    )
    states = {state for _, state in blockers}
    verdict = ClaimVerdict.INCONCLUSIVE
    reason = None
    if CheckState.INVALID in states:
        verdict = ClaimVerdict.INVALID
    elif not manifest.permits_scientific_claim:
        reason = "evidence class is not eligible for confirmatory claims"
    elif CheckState.FAILED in states:
        verdict = ClaimVerdict.FAILED
    elif not missing and not blockers:
        verdict = ClaimVerdict.VERIFIED
    return ClaimDecision(verdict, missing, blockers, reason)
