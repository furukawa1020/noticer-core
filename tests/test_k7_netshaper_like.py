from dataclasses import replace

import pytest

from noticer_core.evaluation.baseline_comparison_contract import (
    AXES,
    MECHANISMS,
    ComparisonManifest,
    Mechanism,
    SharedContract,
)
from noticer_core.evaluation.netshaper_like import (
    NetShaperLikeConfig,
    NetShaperLikeError,
    config_digest,
    run_netshaper_like,
)
from noticer_core.evaluation.pacer_like import (
    ActionObligation,
    fault_trace_digest,
    utility_trace_digest,
)


def _fixture(
    actions: tuple[ActionObligation, ...],
    availability: tuple[bool, ...],
    *,
    scale: float = 0.01,
) -> tuple[ComparisonManifest, NetShaperLikeConfig]:
    config = NetShaperLikeConfig(len(availability), 3, 64, 3, scale, 7)
    mechanisms = tuple(
        Mechanism(
            name,
            "approximation" if name in {"pacer_like", "netshaper_like", "automata"}
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
                "a" * 64, "b" * 64, utility_trace_digest(actions),
                fault_trace_digest(availability), "c" * 64, "d" * 64,
                "held_out", "development",
            ),
            mechanisms, AXES, True,
        ),
        config,
    )


def test_windowed_noise_is_deterministic_under_frozen_seed() -> None:
    actions = (ActionObligation("notify", 0, 5),)
    availability = (True,) * 6
    manifest, config = _fixture(actions, availability)
    first = run_netshaper_like(manifest, config, actions, availability)
    second = run_netshaper_like(manifest, config, actions, availability)
    assert first == second
    assert first.implementation_kind == "approximation"
    assert not first.security_proof
    assert first.bandwidth_bytes > 0


def test_observed_shape_may_depend_on_private_queue() -> None:
    availability = (True,) * 6
    empty: tuple[ActionObligation, ...] = ()
    action = (ActionObligation("notify", 0, 5),)
    empty_manifest, config = _fixture(empty, availability)
    action_manifest, _ = _fixture(action, availability)
    empty_run = run_netshaper_like(empty_manifest, config, empty, availability)
    action_run = run_netshaper_like(action_manifest, config, action, availability)
    assert empty_run.public_trace != action_run.public_trace
    assert empty_run.bandwidth_bytes < action_run.bandwidth_bytes


def test_public_fault_and_deadline_are_reported_separately() -> None:
    availability = (False, False, False, True, True, True)
    action = (ActionObligation("notify", 0, 2),)
    manifest, config = _fixture(action, availability)
    result = run_netshaper_like(manifest, config, action, availability)
    assert result.public_fault_slots == 3
    assert result.missed_deadlines == 1
    assert all(not frame.transmitted for frame in result.public_trace[:3])


def test_config_and_trace_bindings_fail_closed() -> None:
    availability = (True,) * 6
    action = (ActionObligation("notify", 0, 5),)
    manifest, config = _fixture(action, availability)
    with pytest.raises(NetShaperLikeError) as caught:
        run_netshaper_like(manifest, replace(config, seed=8), action, availability)
    assert caught.value.category == "config_binding_mismatch"
    with pytest.raises(NetShaperLikeError) as caught:
        run_netshaper_like(manifest, config, action,
                           (True, True, False, True, True, True))
    assert caught.value.category == "fault_binding_mismatch"
    with pytest.raises(NetShaperLikeError) as caught:
        run_netshaper_like(manifest, config,
                           (ActionObligation("other", 0, 5),), availability)
    assert caught.value.category == "utility_binding_mismatch"
