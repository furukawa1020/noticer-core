from dataclasses import replace

import pytest

from noticer_core.evaluation.baseline_comparison_contract import (
    AXES,
    MECHANISMS,
    ComparisonManifest,
    Mechanism,
    SharedContract,
)
from noticer_core.evaluation.handwritten_controls import (
    HandwrittenConfig,
    HandwrittenControlError,
    MatchedAction,
    action_semantics_digest,
    compare_matched_actions,
    config_digest,
)
from noticer_core.evaluation.pacer_like import fault_trace_digest


def _fixture(
    left: MatchedAction,
    availability: tuple[bool, ...],
) -> tuple[ComparisonManifest, HandwrittenConfig]:
    config = HandwrittenConfig(len(availability), 64, 1)
    mechanisms = tuple(
        Mechanism(
            name,
            "approximation" if name in {"automata", "pacer_like", "netshaper_like"}
            else "local",
            "notion-" + name, "source-" + name, "v1",
            (config_digest(config),), config_digest(config),
        )
        for name in sorted(MECHANISMS)
    )
    return (
        ComparisonManifest(
            "noticer.k7.baseline-comparison.v1",
            SharedContract(
                "a" * 64, "b" * 64, action_semantics_digest(left),
                fault_trace_digest(availability), "c" * 64, "d" * 64,
                "held_out", "development",
            ),
            mechanisms, AXES, True,
        ),
        config,
    )


def test_matched_pair_preserves_aets_trace_and_detects_both_controls() -> None:
    left = MatchedAction("notify", "service-a", 4, 1, 0)
    right = MatchedAction("notify", "service-a", 4, 3, 1)
    availability = (True,) * 6
    manifest, config = _fixture(left, availability)
    result = compare_matched_actions(manifest, config, left, right, availability)
    assert result.status == "VALID"
    assert result.aets_trace_equal
    assert result.immediate_control_detected
    assert result.leaky_control_detected
    assert result.left[0].observer_frames == result.right[0].observer_frames
    assert result.left[1].observer_frames != result.right[1].observer_frames
    assert result.left[2].observer_frames != result.right[2].observer_frames
    assert not result.security_proof


def test_blind_control_invalidates_comparison() -> None:
    left = MatchedAction("notify", "service-a", 4, 1, 0)
    right = replace(left, private_bit=1)
    availability = (True,) * 6
    manifest, config = _fixture(left, availability)
    result = compare_matched_actions(manifest, config, left, right, availability)
    assert result.status == "INVALID_EVALUATION"
    assert not result.immediate_control_detected
    assert result.leaky_control_detected


def test_public_fault_recovery_is_shared_and_deadline_miss_is_reported() -> None:
    left = MatchedAction("notify", "service-a", 4, 1, 0)
    right = MatchedAction("notify", "service-a", 4, 3, 1)
    availability = (True, True, True, True, False, True)
    manifest, config = _fixture(left, availability)
    result = compare_matched_actions(manifest, config, left, right, availability)
    assert result.left[0].delivered_slot == result.right[0].delivered_slot == 5
    assert not result.left[0].deadline_met
    assert result.left[0].public_fault_slots == 1


def test_unmatched_action_and_input_substitution_are_rejected() -> None:
    left = MatchedAction("notify", "service-a", 4, 1, 0)
    right = replace(left, private_ready_slot=3, private_bit=1)
    availability = (True,) * 6
    manifest, config = _fixture(left, availability)
    with pytest.raises(HandwrittenControlError) as caught:
        compare_matched_actions(manifest, config, left,
                                replace(right, service_id="service-b"), availability)
    assert caught.value.category == "not_matched_action"
    with pytest.raises(HandwrittenControlError) as caught:
        compare_matched_actions(manifest, replace(config, frame_bytes=65),
                                left, right, availability)
    assert caught.value.category == "config_binding_mismatch"
    with pytest.raises(HandwrittenControlError) as caught:
        compare_matched_actions(manifest, config, left, right,
                                (True, True, False, True, True, True))
    assert caught.value.category == "fault_binding_mismatch"
