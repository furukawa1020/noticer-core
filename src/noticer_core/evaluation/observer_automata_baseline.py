"""Finite hidden-signal observer-privacy baseline approximation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from itertools import combinations

from noticer_core.evaluation.baseline_comparison_contract import (
    ComparisonManifest,
    manifest_digest,
    validate_manifest,
)
from noticer_core.evaluation.pacer_like import (
    ActionObligation,
    fault_trace_digest,
    utility_trace_digest,
)


class ObserverBaselineError(ValueError):
    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


@dataclass(frozen=True)
class ObserverBaselineConfig:
    signals: tuple[str, ...]
    hide_costs: tuple[int, ...]
    hide_budget: int


@dataclass(frozen=True)
class SecretScenario:
    scenario_id: str
    secret: bool
    observations: tuple[tuple[bool, ...], ...]


@dataclass(frozen=True)
class ObserverBaselineRun:
    format_version: str
    comparison_manifest_sha256: str
    config_sha256: str
    status: str
    hidden_signals: tuple[str, ...]
    hidden_cost: int
    corpus_trie_states: int
    observed_class_count: int
    checked_scenarios: int
    privacy_notion: str = "finite-trace-observer-ambiguity"
    implementation_kind: str = "approximation"
    security_proof: bool = False


def synthesize_hidden_signals(
    manifest: ComparisonManifest,
    config: ObserverBaselineConfig,
    scenarios: tuple[SecretScenario, ...],
    actions: tuple[ActionObligation, ...],
    network_available: tuple[bool, ...],
) -> ObserverBaselineRun:
    """Find minimum-cost hiding on a declared finite trace corpus."""

    validate_manifest(manifest)
    mechanism = next(
        item for item in manifest.mechanisms if item.mechanism_id == "automata"
    )
    if mechanism.implementation_kind != "approximation":
        raise ObserverBaselineError("not_approximation")
    _validate(config, scenarios)
    if config_digest(config) != mechanism.selected_config_sha256:
        raise ObserverBaselineError("config_binding_mismatch")
    shared = manifest.shared
    if observer_digest(config) != shared.observer_sha256:
        raise ObserverBaselineError("observer_binding_mismatch")
    if cost_digest(config) != shared.cost_sha256:
        raise ObserverBaselineError("cost_binding_mismatch")
    if scenario_digest(scenarios) != shared.corpus_sha256:
        raise ObserverBaselineError("corpus_binding_mismatch")
    if case_digest(config, scenarios, actions, network_available) != shared.case_sha256:
        raise ObserverBaselineError("case_binding_mismatch")
    if utility_trace_digest(actions) != shared.utility_sha256:
        raise ObserverBaselineError("utility_binding_mismatch")
    if fault_trace_digest(network_available) != shared.fault_trace_sha256:
        raise ObserverBaselineError("fault_binding_mismatch")
    if len(network_available) != len(scenarios[0].observations):
        raise ObserverBaselineError("horizon_mismatch")

    choices = [
        subset
        for size in range(len(config.signals) + 1)
        for subset in combinations(range(len(config.signals)), size)
        if sum(config.hide_costs[index] for index in subset) <= config.hide_budget
    ]
    choices.sort(key=lambda subset: (
        sum(config.hide_costs[index] for index in subset),
        tuple(config.signals[index] for index in subset),
    ))
    chosen: tuple[int, ...] | None = None
    class_count = 0
    for subset in choices:
        opaque, count = _observer_ambiguity(config, scenarios, frozenset(subset))
        if opaque:
            chosen, class_count = subset, count
            break
    return ObserverBaselineRun(
        format_version="noticer.k7.observer-automata-baseline.v1",
        comparison_manifest_sha256=manifest_digest(manifest),
        config_sha256=config_digest(config),
        status="FINITE_OPAQUE" if chosen is not None else "UNREALIZABLE_AT_BUDGET",
        hidden_signals=(
            tuple(config.signals[index] for index in chosen)
            if chosen is not None else ()
        ),
        hidden_cost=(
            sum(config.hide_costs[index] for index in chosen)
            if chosen is not None else 0
        ),
        corpus_trie_states=_trie_state_count(scenarios),
        observed_class_count=class_count,
        checked_scenarios=len(scenarios),
    )


def config_digest(config: ObserverBaselineConfig) -> str:
    return _digest(asdict(config))


def observer_digest(config: ObserverBaselineConfig) -> str:
    return _digest({"signals": config.signals})


def cost_digest(config: ObserverBaselineConfig) -> str:
    return _digest({"signals": config.signals, "hide_costs": config.hide_costs})


def scenario_digest(scenarios: tuple[SecretScenario, ...]) -> str:
    return _digest({
        "scenarios": [asdict(item) for item in sorted(
            scenarios, key=lambda item: item.scenario_id
        )]
    })


def case_digest(
    config: ObserverBaselineConfig,
    scenarios: tuple[SecretScenario, ...],
    actions: tuple[ActionObligation, ...],
    network_available: tuple[bool, ...],
) -> str:
    return _digest({
        "observer_sha256": observer_digest(config),
        "corpus_sha256": scenario_digest(scenarios),
        "utility_sha256": utility_trace_digest(actions),
        "fault_sha256": fault_trace_digest(network_available),
    })


def _observer_ambiguity(
    config: ObserverBaselineConfig,
    scenarios: tuple[SecretScenario, ...],
    hidden: frozenset[int],
) -> tuple[bool, int]:
    visible = tuple(index for index in range(len(config.signals)) if index not in hidden)
    classes: dict[tuple[tuple[bool, ...], ...], set[bool]] = {}
    for scenario in scenarios:
        projection = tuple(
            tuple(step[index] for index in visible)
            for step in scenario.observations
        )
        classes.setdefault(projection, set()).add(scenario.secret)
    return all(values == {False, True} for values in classes.values()), len(classes)


def _trie_state_count(scenarios: tuple[SecretScenario, ...]) -> int:
    prefixes: set[tuple[tuple[bool, ...], ...]] = {()}
    for scenario in scenarios:
        for length in range(1, len(scenario.observations) + 1):
            prefixes.add(scenario.observations[:length])
    return len(prefixes)


def _validate(
    config: ObserverBaselineConfig, scenarios: tuple[SecretScenario, ...]
) -> None:
    if (
        not config.signals
        or len(config.signals) > 12
        or config.signals != tuple(sorted(set(config.signals)))
        or any(not signal for signal in config.signals)
        or len(config.signals) != len(config.hide_costs)
        or any(type(cost) is not int or cost <= 0 for cost in config.hide_costs)
        or type(config.hide_budget) is not int
        or config.hide_budget < 0
    ):
        raise ObserverBaselineError("invalid_config")
    if (
        not scenarios
        or {scenario.secret for scenario in scenarios} != {False, True}
        or len({scenario.scenario_id for scenario in scenarios}) != len(scenarios)
    ):
        raise ObserverBaselineError("invalid_corpus")
    horizon = len(scenarios[0].observations)
    if horizon == 0 or any(
        not scenario.scenario_id
        or type(scenario.secret) is not bool
        or len(scenario.observations) != horizon
        or any(
            len(step) != len(config.signals)
            or any(type(value) is not bool for value in step)
            for step in scenario.observations
        )
        for scenario in scenarios
    ):
        raise ObserverBaselineError("invalid_corpus")


def _digest(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
