
import pytest

from noticer_core.evaluation.claim_stop_gate import ClaimStopDecision
from noticer_core.evaluation.longitudinal_leakage_gate import (
    BucketLeakage,
    LongitudinalGateError,
    evaluate_longitudinal_gate,
    longitudinal_gate_digest,
)


def _buckets() -> tuple[BucketLeakage, ...]:
    return (
        BucketLeakage("b0", 1.0, 1.05),
        BucketLeakage("b1", 1.0, 1.04),
        BucketLeakage("b2", 1.0, 1.03),
    )


def _digests() -> dict[str, str]:
    return {
        "composition": "a" * 64,
        "counterexamples": "b" * 64,
        "attack": "c" * 64,
        "control": "d" * 64,
        "corpus": "e" * 64,
    }


def _evaluate(**changes: object):
    arguments = {
        "paired_excess_ci": (-0.02, 0.08),
        "composition_oracle_accepted": True,
        "counterexamples_rejected": True,
        "attack_complete": True,
        "leaky_control_detected": True,
        "input_sha256": _digests(),
    }
    arguments.update(changes)
    return evaluate_longitudinal_gate(_buckets(), **arguments)


def test_allowed_and_excess_leakage_are_separate_and_deterministic() -> None:
    first, second = _evaluate(), _evaluate()
    assert first == second
    assert first.allowed_claim_bits_total == 3.0
    assert first.observed_full_trace_bits_total == pytest.approx(3.12)
    assert first.excess_leakage_bits == pytest.approx(0.12)
    assert first.decision is ClaimStopDecision.GO_CANDIDATE
    assert first.implementation_claim_allowed
    assert not first.security_proof
    assert longitudinal_gate_digest(first) == longitudinal_gate_digest(second)


def test_stable_excess_or_longitudinal_failure_blocks_claim() -> None:
    stable = _evaluate(paired_excess_ci=(0.01, 0.09))
    assert stable.decision is ClaimStopDecision.BLOCKED
    assert "stable_excess_leakage" in stable.reasons
    failed = _evaluate(
        composition_oracle_accepted=False, counterexamples_rejected=False
    )
    assert failed.decision is ClaimStopDecision.BLOCKED
    assert failed.reasons == (
        "composition_oracle_rejected",
        "counterexample_not_rejected",
    )


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"attack_complete": False}, "attack_incomplete"),
        ({"leaky_control_detected": False}, "leaky_control_failed"),
    ],
)
def test_incomplete_evaluation_is_invalid_not_blocked(
    change: dict[str, bool], reason: str
) -> None:
    artifact = _evaluate(**change)
    assert artifact.decision is ClaimStopDecision.INVALID_EVALUATION
    assert reason in artifact.reasons
    assert not artifact.implementation_claim_allowed


def test_missing_digest_and_bad_ci_are_rejected() -> None:
    digests = _digests()
    digests.pop("corpus")
    with pytest.raises(LongitudinalGateError) as caught:
        _evaluate(input_sha256=digests)
    assert caught.value.category == "incomplete_input_binding"
    with pytest.raises(LongitudinalGateError) as caught:
        _evaluate(paired_excess_ci=(0.2, 0.1))
    assert caught.value.category == "invalid_confidence_interval"


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_nonfinite_values_cannot_produce_go_candidate(value: float) -> None:
    with pytest.raises(LongitudinalGateError) as caught:
        _evaluate(paired_excess_ci=(value, 0.1))
    assert caught.value.category == "nonfinite_value"
    with pytest.raises(LongitudinalGateError) as caught:
        _evaluate(excess_threshold=value)
    assert caught.value.category == "nonfinite_value"
    with pytest.raises(LongitudinalGateError) as caught:
        evaluate_longitudinal_gate(
            (BucketLeakage("b0", value, 0.1),),
            paired_excess_ci=(0.0, 0.1),
            composition_oracle_accepted=True,
            counterexamples_rejected=True,
            attack_complete=True,
            leaky_control_detected=True,
            input_sha256=_digests(),
        )
    assert caught.value.category == "nonfinite_value"
