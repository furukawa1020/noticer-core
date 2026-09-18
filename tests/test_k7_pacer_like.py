from dataclasses import replace

import pytest

from noticer_core.evaluation.baseline_comparison_contract import (
    AXES,
    MECHANISMS,
    ComparisonManifest,
    Mechanism,
    SharedContract,
)
from noticer_core.evaluation.pacer_like import (
    ActionObligation,
    PacerLikeConfig,
    PacerLikeError,
    config_digest,
    fault_trace_digest,
    run_pacer_like,
    utility_trace_digest,
)


def _fixture(
    actions: tuple[ActionObligation, ...],
    availability: tuple[bool, ...],
) -> tuple[ComparisonManifest, PacerLikeConfig]:
    config = PacerLikeConfig(horizon_slots=len(availability), period_slots=2,
                             frame_bytes=64)
    mechanisms = tuple(
        Mechanism(
            mechanism_id=name,
            implementation_kind=(
                "approximation" if name in {"pacer_like", "netshaper_like", "automata"}
                else "local"
            ),
            privacy_notion="notion-" + name,
            source_ref="source-" + name,
            source_version="v1",
            candidate_config_sha256=(config_digest(config),),
            selected_config_sha256=config_digest(config),
        )
        for name in sorted(MECHANISMS)
    )
    manifest = ComparisonManifest(
        format_version="noticer.k7.baseline-comparison.v1",
        shared=SharedContract(
            "a" * 64, "b" * 64, utility_trace_digest(actions),
            fault_trace_digest(availability), "c" * 64, "d" * 64,
            "held_out", "development",
        ),
        mechanisms=mechanisms,
        report_axes=AXES,
        privacy_notions_are_separate=True,
    )
    return manifest, config


def test_public_trace_is_secret_independent_but_utility_is_separate() -> None:
    availability = (True, True, False, True, True, True)
    empty: tuple[ActionObligation, ...] = ()
    actions = (ActionObligation("notify", 1, 3),)
    empty_manifest, config = _fixture(empty, availability)
    action_manifest, _ = _fixture(actions, availability)
    empty_run = run_pacer_like(empty_manifest, config, empty, availability)
    action_run = run_pacer_like(action_manifest, config, actions, availability)
    assert empty_run.public_trace == action_run.public_trace
    assert empty_run.bandwidth_bytes == action_run.bandwidth_bytes == 128
    assert action_run.missed_deadlines == 1
    assert action_run.private_deliveries[0].delivered_slot == 4
    assert not action_run.security_proof


def test_public_fault_pause_and_recovery_preserve_fixed_shape() -> None:
    availability = (True, True, False, True, True, True)
    actions = (ActionObligation("notify", 1, 5),)
    manifest, config = _fixture(actions, availability)
    result = run_pacer_like(manifest, config, actions, availability)
    assert [(f.slot, f.transmitted) for f in result.public_trace] == [
        (0, True), (2, False), (4, True)
    ]
    assert result.private_deliveries[0].latency_slots == 3
    assert result.missed_deadlines == 0
    assert result.public_fault_slots == 1


def test_binding_and_invalid_obligations_fail_closed() -> None:
    availability = (True, True, True, True)
    actions = (ActionObligation("notify", 1, 3),)
    manifest, config = _fixture(actions, availability)
    with pytest.raises(PacerLikeError) as caught:
        run_pacer_like(manifest, replace(config, frame_bytes=65), actions, availability)
    assert caught.value.category == "config_binding_mismatch"
    with pytest.raises(PacerLikeError) as caught:
        run_pacer_like(manifest, config, actions, (True, False, True, True))
    assert caught.value.category == "fault_binding_mismatch"
    with pytest.raises(PacerLikeError) as caught:
        run_pacer_like(manifest, config, (ActionObligation("other", 1, 3),),
                       availability)
    assert caught.value.category == "utility_binding_mismatch"


def test_schedule_does_not_depend_on_action_arrival() -> None:
    availability = (True,) * 8
    early = (ActionObligation("notify", 1, 7),)
    late = (ActionObligation("notify", 5, 7),)
    manifest_early, config = _fixture(early, availability)
    manifest_late, _ = _fixture(late, availability)
    first = run_pacer_like(manifest_early, config, early, availability)
    second = run_pacer_like(manifest_late, config, late, availability)
    assert first.public_trace == second.public_trace
    assert first.private_deliveries != second.private_deliveries
