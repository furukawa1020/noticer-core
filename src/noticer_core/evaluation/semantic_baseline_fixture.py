"""Shared-fixture adapter for automata and handwritten AETS baselines."""

from __future__ import annotations

from dataclasses import dataclass, replace

from noticer_core.evaluation.baseline_comparison_contract import ComparisonManifest
from noticer_core.evaluation.handwritten_controls import (
    HandwrittenConfig,
    MatchedAction,
    action_semantics_digest,
)
from noticer_core.evaluation.observer_automata_baseline import (
    ObserverBaselineConfig,
    SecretScenario,
    case_digest,
    cost_digest,
    observer_digest,
    scenario_digest,
)
from noticer_core.evaluation.pacer_like import (
    ActionObligation,
    fault_trace_digest,
    utility_trace_digest,
)
from noticer_core.evaluation.shared_comparison_fixture import (
    SharedComparisonFixture,
    bind_shared_fixture,
)


class SemanticBaselineFixtureError(ValueError):
    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


@dataclass(frozen=True)
class PreparedSemanticBaselines:
    automata_manifest: ComparisonManifest
    handwritten_manifest: ComparisonManifest
    automata_scenarios: tuple[SecretScenario, ...]
    public_actions: tuple[ActionObligation, ...]
    left: MatchedAction
    right: MatchedAction
    network_available: tuple[bool, ...]


def prepare_shared_semantic_baselines(
    manifest: ComparisonManifest,
    fixture: SharedComparisonFixture,
    automata_config: ObserverBaselineConfig,
    handwritten_config: HandwrittenConfig,
) -> PreparedSemanticBaselines:
    """Derive both semantic baselines only after binding the shared fixture."""

    bind_shared_fixture(manifest, fixture)
    if automata_config.signals != fixture.observer_signals:
        raise SemanticBaselineFixtureError("observer_signal_mismatch")
    if handwritten_config.horizon_slots != len(fixture.network_available):
        raise SemanticBaselineFixtureError("horizon_mismatch")
    if len(fixture.public_actions) != 1:
        raise SemanticBaselineFixtureError("single_action_required")
    false_scenarios = [scenario for scenario in fixture.scenarios if not scenario.secret]
    true_scenarios = [scenario for scenario in fixture.scenarios if scenario.secret]
    if len(false_scenarios) != 1 or len(true_scenarios) != 1:
        raise SemanticBaselineFixtureError("matched_pair_required")

    automata_scenarios = tuple(
        SecretScenario(
            scenario.scenario_id,
            scenario.secret,
            scenario.signal_observations,
        )
        for scenario in fixture.scenarios
    )
    public_actions = tuple(
        ActionObligation(action.action_id, 0, action.deadline_slot)
        for action in fixture.public_actions
    )
    availability = fixture.network_available
    automata_shared = replace(
        manifest.shared,
        case_sha256=case_digest(
            automata_config,
            automata_scenarios,
            public_actions,
            availability,
        ),
        observer_sha256=observer_digest(automata_config),
        utility_sha256=utility_trace_digest(public_actions),
        fault_trace_sha256=fault_trace_digest(availability),
        cost_sha256=cost_digest(automata_config),
        corpus_sha256=scenario_digest(automata_scenarios),
    )

    action = fixture.public_actions[0]
    left_scenario = false_scenarios[0]
    right_scenario = true_scenarios[0]
    left = MatchedAction(
        action.action_id,
        action.service_id,
        action.deadline_slot,
        left_scenario.private_ready_slots[0],
        0,
    )
    right = MatchedAction(
        action.action_id,
        action.service_id,
        action.deadline_slot,
        right_scenario.private_ready_slots[0],
        1,
    )
    handwritten_shared = replace(
        manifest.shared,
        utility_sha256=action_semantics_digest(left),
        fault_trace_sha256=fault_trace_digest(availability),
    )
    return PreparedSemanticBaselines(
        replace(manifest, shared=automata_shared),
        replace(manifest, shared=handwritten_shared),
        automata_scenarios,
        public_actions,
        left,
        right,
        availability,
    )
