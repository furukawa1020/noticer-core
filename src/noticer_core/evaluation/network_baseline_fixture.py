"""Shared-fixture adapter for Pacer-like and NetShaper-like baselines."""

from __future__ import annotations

from dataclasses import dataclass, replace

from noticer_core.evaluation.baseline_comparison_contract import ComparisonManifest
from noticer_core.evaluation.pacer_like import (
    ActionObligation,
    fault_trace_digest,
    utility_trace_digest,
)
from noticer_core.evaluation.shared_comparison_fixture import (
    SharedComparisonFixture,
    bind_shared_fixture,
)


class NetworkBaselineFixtureError(ValueError):
    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


@dataclass(frozen=True)
class PreparedNetworkBaseline:
    """Identical action and fault inputs prepared for both network baselines."""

    scenario_id: str
    runtime_manifest: ComparisonManifest
    actions: tuple[ActionObligation, ...]
    network_available: tuple[bool, ...]


def prepare_shared_network_baseline(
    manifest: ComparisonManifest,
    fixture: SharedComparisonFixture,
    scenario_id: str,
) -> PreparedNetworkBaseline:
    """Bind the shared contract before deriving legacy runner inputs."""

    bind_shared_fixture(manifest, fixture)
    scenarios = {
        scenario.scenario_id: scenario
        for scenario in fixture.scenarios
    }
    scenario = scenarios.get(scenario_id)
    if scenario is None:
        raise NetworkBaselineFixtureError("unknown_scenario")
    actions = tuple(
        ActionObligation(action.action_id, ready_slot, action.deadline_slot)
        for action, ready_slot in zip(
            fixture.public_actions,
            scenario.private_ready_slots,
            strict=True,
        )
    )
    availability = fixture.network_available
    runtime_shared = replace(
        manifest.shared,
        utility_sha256=utility_trace_digest(actions),
        fault_trace_sha256=fault_trace_digest(availability),
    )
    return PreparedNetworkBaseline(
        scenario.scenario_id,
        replace(manifest, shared=runtime_shared),
        actions,
        availability,
    )
