from dataclasses import replace

import pytest

from noticer_core.evaluation.baseline_comparison_contract import (
    AXES,
    MECHANISMS,
    ComparisonManifest,
    Mechanism,
    SharedContract,
)
from noticer_core.evaluation.observer_automata_baseline import (
    ObserverBaselineConfig,
    ObserverBaselineError,
    SecretScenario,
    case_digest,
    config_digest,
    cost_digest,
    observer_digest,
    scenario_digest,
    synthesize_hidden_signals,
)
from noticer_core.evaluation.pacer_like import (
    ActionObligation,
    fault_trace_digest,
    utility_trace_digest,
)


def _fixture(
    config: ObserverBaselineConfig,
    scenarios: tuple[SecretScenario, ...],
) -> tuple[ComparisonManifest, tuple[ActionObligation, ...], tuple[bool, ...]]:
    actions = (ActionObligation("notify", 0, 1),)
    faults = (True, True)
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
    shared = SharedContract(
        case_digest(config, scenarios, actions, faults),
        observer_digest(config),
        utility_trace_digest(actions),
        fault_trace_digest(faults),
        cost_digest(config),
        scenario_digest(scenarios),
        "held_out", "development",
    )
    return (
        ComparisonManifest(
            "noticer.k7.baseline-comparison.v1", shared, mechanisms, AXES, True
        ),
        actions,
        faults,
    )


def _scenarios() -> tuple[SecretScenario, ...]:
    return (
        SecretScenario("left", False, ((False, True), (False, True))),
        SecretScenario("right", True, ((True, True), (True, True))),
    )


def test_minimum_cost_hiding_preserves_finite_observer_ambiguity() -> None:
    config = ObserverBaselineConfig(("secret_hint", "tick"), (1, 2), 1)
    scenarios = _scenarios()
    manifest, actions, faults = _fixture(config, scenarios)
    first = synthesize_hidden_signals(manifest, config, scenarios, actions, faults)
    second = synthesize_hidden_signals(manifest, config, scenarios, actions, faults)
    assert first == second
    assert first.status == "FINITE_OPAQUE"
    assert first.hidden_signals == ("secret_hint",)
    assert first.hidden_cost == 1
    assert first.corpus_trie_states == 5
    assert not first.security_proof


def test_budget_zero_is_unrealizable_not_private() -> None:
    config = ObserverBaselineConfig(("secret_hint", "tick"), (1, 2), 0)
    scenarios = _scenarios()
    manifest, actions, faults = _fixture(config, scenarios)
    result = synthesize_hidden_signals(manifest, config, scenarios, actions, faults)
    assert result.status == "UNREALIZABLE_AT_BUDGET"
    assert not result.hidden_signals


def test_all_six_shared_inputs_are_bound() -> None:
    config = ObserverBaselineConfig(("secret_hint", "tick"), (1, 2), 1)
    scenarios = _scenarios()
    manifest, actions, faults = _fixture(config, scenarios)
    tampered = replace(config, hide_budget=2)
    with pytest.raises(ObserverBaselineError) as caught:
        synthesize_hidden_signals(manifest, tampered, scenarios, actions, faults)
    assert caught.value.category == "config_binding_mismatch"
    with pytest.raises(ObserverBaselineError) as caught:
        synthesize_hidden_signals(
            manifest, config, scenarios, actions, (True, False)
        )
    assert caught.value.category == "case_binding_mismatch"
    with pytest.raises(ObserverBaselineError) as caught:
        synthesize_hidden_signals(
            manifest, config, scenarios,
            (ActionObligation("other", 0, 1),), faults
        )
    assert caught.value.category == "case_binding_mismatch"


def test_invalid_corpus_and_unshared_horizon_fail_closed() -> None:
    config = ObserverBaselineConfig(("secret_hint", "tick"), (1, 2), 1)
    scenarios = _scenarios()
    manifest, actions, faults = _fixture(config, scenarios)
    with pytest.raises(ObserverBaselineError) as caught:
        synthesize_hidden_signals(
            manifest, config, (scenarios[0],), actions, faults
        )
    assert caught.value.category == "invalid_corpus"
    with pytest.raises(ObserverBaselineError) as caught:
        synthesize_hidden_signals(
            manifest, config, scenarios, actions, (True,)
        )
    assert caught.value.category == "case_binding_mismatch"
