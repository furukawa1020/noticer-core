import pytest

from noticer_core.evaluation.transport_cost_profile import FORMAT_VERSION as PROFILE_VERSION
from noticer_core.evaluation.transport_cost_profile import PlatformProfile
from noticer_core.evaluation.transport_cost_simulator import (
    FORMAT_VERSION,
    PublicRequest,
    TransportSimulationConfig,
    TransportSimulationError,
    canonical_simulation_json,
    simulate_transport_cost,
)


def _profile() -> PlatformProfile:
    return PlatformProfile(
        PROFILE_VERSION, "sim", "simulator", "v1", "a" * 64, "cpu-only"
    )


def _config(**changes) -> TransportSimulationConfig:
    values = {
        "format_version": FORMAT_VERSION,
        "simulator_version": "v1",
        "seed": 17,
        "frame_overhead_bytes": 8,
        "state_count": 2,
        "cover_modulus": 3,
        "max_events": 100,
    }
    values.update(changes)
    return TransportSimulationConfig(**values)


def test_simulation_is_seeded_bound_and_reproducible() -> None:
    requests = (PublicRequest("a", 0, 3, 16), PublicRequest("b", 1, 4, 8))
    availability = (False, True, False, True, True)
    first = simulate_transport_cost(_config(), requests, availability, _profile())
    second = simulate_transport_cost(_config(), requests, availability, _profile())
    assert first == second
    assert canonical_simulation_json(first) == canonical_simulation_json(second)
    assert first.logical_cost.cost.bytes >= 40
    assert first.logical_cost.cost.retries == 2
    assert first.logical_cost.cost.reconnects == 2
    assert first.logical_cost.cost.radio_on_slots >= 3


def test_seed_is_part_of_artifact_and_controls_cover_trace() -> None:
    first = simulate_transport_cost(_config(seed=1), (), (True,) * 12, _profile())
    second = simulate_transport_cost(_config(seed=2), (), (True,) * 12, _profile())
    assert first.config_sha256 != second.config_sha256
    assert first.events != second.events


@pytest.mark.parametrize(
    "config,requests,availability,category",
    [
        (_config(), (PublicRequest("a", 0, 1, 1),), (False, False), "undelivered_request"),
        (
            _config(max_events=1),
            (PublicRequest("a", 0, 0, 1),),
            (True,),
            "event_limit_exceeded",
        ),
        (
            _config(),
            (PublicRequest("b", 0, 0, 1), PublicRequest("a", 0, 0, 1)),
            (True,),
            "noncanonical_requests",
        ),
    ],
)
def test_incomplete_bounded_and_noncanonical_runs_fail_closed(
    config, requests, availability, category
) -> None:
    with pytest.raises(TransportSimulationError) as caught:
        simulate_transport_cost(config, requests, availability, _profile())
    assert caught.value.category == category
