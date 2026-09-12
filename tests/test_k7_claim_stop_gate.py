from __future__ import annotations

from dataclasses import replace

from noticer_core.attacks.adaptive import ModelFamily
from noticer_core.attacks.leaky_control import LeakyControlReport
from noticer_core.evaluation.adaptive_leakage import (
    AdaptiveLeakageReport,
    ExcessLeakage,
)
from noticer_core.evaluation.claim_stop_gate import (
    ClaimStopDecision,
    canonical_gate_json,
    evaluate_claim_stop_gate,
)


def leakage(lower: float = -0.01, pointwise: bool = True) -> AdaptiveLeakageReport:
    return AdaptiveLeakageReport(
        attacks=(),
        full_trace_excess=tuple(
            ExcessLeakage(model=model, estimate=0.0, ci95=(lower, 0.03))
            for model in ModelFamily
        ),
        pointwise_trace_equal=pointwise,
        implementation_claim_eligible=pointwise,
    )


def control(detected: bool = True) -> LeakyControlReport:
    return LeakyControlReport(
        detected=detected,
        minimum_auc=0.9,
        auc_by_attacker={},
        failed_attackers=() if detected else ("claim_only/linear",),
    )


def digests() -> dict[str, str]:
    return {
        "runtime_capture": "1" * 64,
        "corpus": "2" * 64,
        "attack_protocol": "3" * 64,
        "leakage_report": "4" * 64,
        "control_report": "5" * 64,
    }


def test_go_candidate_is_reproducible_but_never_a_security_proof() -> None:
    first = evaluate_claim_stop_gate(
        leakage(),
        control(),
        evaluation_complete=True,
        stable_excess_lower_bound=0.02,
        input_sha256=digests(),
    )
    second = evaluate_claim_stop_gate(
        leakage(),
        control(),
        evaluation_complete=True,
        stable_excess_lower_bound=0.02,
        input_sha256=digests(),
    )

    assert first == second
    assert first.decision is ClaimStopDecision.GO_CANDIDATE
    assert first.implementation_claim_allowed
    assert not first.security_proof
    assert canonical_gate_json(first).endswith(b"\n")


def test_pointwise_failure_blocks_regardless_of_classifier_result() -> None:
    artifact = evaluate_claim_stop_gate(
        leakage(pointwise=False),
        control(),
        evaluation_complete=True,
        stable_excess_lower_bound=0.02,
        input_sha256=digests(),
    )

    assert artifact.decision is ClaimStopDecision.BLOCKED
    assert artifact.reasons == ("POINTWISE_TRACE_EQUALITY_FAILED",)
    assert not artifact.implementation_claim_allowed


def test_stably_positive_full_trace_excess_blocks_claim() -> None:
    artifact = evaluate_claim_stop_gate(
        leakage(lower=0.03),
        control(),
        evaluation_complete=True,
        stable_excess_lower_bound=0.02,
        input_sha256=digests(),
    )

    assert artifact.decision is ClaimStopDecision.BLOCKED
    assert artifact.reasons == ("FULL_TRACE_EXCESS_STABLY_POSITIVE",)


def test_incomplete_or_failed_control_is_invalid_not_pass() -> None:
    incomplete = evaluate_claim_stop_gate(
        leakage(),
        control(),
        evaluation_complete=False,
        stable_excess_lower_bound=0.02,
        input_sha256=digests(),
    )
    failed_control = evaluate_claim_stop_gate(
        leakage(),
        replace(control(), detected=False, failed_attackers=("full_trace/tree",)),
        evaluation_complete=True,
        stable_excess_lower_bound=0.02,
        input_sha256=digests(),
    )

    assert incomplete.decision is ClaimStopDecision.INVALID_EVALUATION
    assert failed_control.decision is ClaimStopDecision.INVALID_EVALUATION
    assert not incomplete.implementation_claim_allowed
    assert not failed_control.implementation_claim_allowed


