"""Canonical synthetic fixture for cross-mechanism K7 baseline comparisons."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass

from noticer_core.evaluation.baseline_comparison_contract import (
    ComparisonManifest,
    SharedContract,
    validate_manifest,
)
from noticer_core.evaluation.pacer_like import fault_trace_digest

FORMAT_VERSION = "noticer.k7.shared-comparison-fixture.v1"


class SharedFixtureError(ValueError):
    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


@dataclass(frozen=True)
class PublicAction:
    action_id: str
    service_id: str
    deadline_slot: int


@dataclass(frozen=True)
class SyntheticScenario:
    scenario_id: str
    secret: bool
    private_ready_slots: tuple[int, ...]
    signal_observations: tuple[tuple[bool, ...], ...]


@dataclass(frozen=True)
class SharedComparisonFixture:
    format_version: str
    case_id: str
    observer_signals: tuple[str, ...]
    public_actions: tuple[PublicAction, ...]
    network_available: tuple[bool, ...]
    scenarios: tuple[SyntheticScenario, ...]
    bandwidth_unit: str = "bytes"
    latency_unit: str = "slots"
    state_unit: str = "states"
    failure_unit: str = "count"
    evidence_tier: str = "SYNTHETIC_SMOKE"


def validate_fixture(fixture: SharedComparisonFixture) -> None:
    """Reject non-canonical, non-synthetic, or semantically unmatched inputs."""

    horizon = len(fixture.network_available)
    if (
        fixture.format_version != FORMAT_VERSION
        or fixture.evidence_tier != "SYNTHETIC_SMOKE"
        or not fixture.case_id
        or horizon == 0
        or any(type(value) is not bool for value in fixture.network_available)
    ):
        raise SharedFixtureError("invalid_fixture_header")
    signals = fixture.observer_signals
    if (
        signals != tuple(sorted(set(signals)))
        or any(not signal for signal in signals)
    ):
        raise SharedFixtureError("invalid_observer_signals")
    actions = fixture.public_actions
    if (
        not actions
        or tuple(action.action_id for action in actions)
        != tuple(sorted({action.action_id for action in actions}))
        or any(
            not action.action_id
            or not action.service_id
            or type(action.deadline_slot) is not int
            or action.deadline_slot < 0
            or action.deadline_slot >= horizon
            for action in actions
        )
    ):
        raise SharedFixtureError("invalid_public_actions")
    scenarios = fixture.scenarios
    if (
        len(scenarios) < 2
        or {scenario.secret for scenario in scenarios} != {False, True}
        or tuple(scenario.scenario_id for scenario in scenarios)
        != tuple(sorted({scenario.scenario_id for scenario in scenarios}))
    ):
        raise SharedFixtureError("invalid_scenarios")
    for scenario in scenarios:
        if (
            not scenario.scenario_id
            or type(scenario.secret) is not bool
            or len(scenario.private_ready_slots) != len(actions)
            or len(scenario.signal_observations) != horizon
            or any(
                type(slot) is not int or slot < 0 or slot > action.deadline_slot
                for slot, action in zip(
                    scenario.private_ready_slots, actions, strict=True
                )
            )
            or any(
                len(step) != len(signals)
                or any(type(value) is not bool for value in step)
                for step in scenario.signal_observations
            )
        ):
            raise SharedFixtureError("invalid_scenarios")
    if (
        fixture.bandwidth_unit,
        fixture.latency_unit,
        fixture.state_unit,
        fixture.failure_unit,
    ) != ("bytes", "slots", "states", "count"):
        raise SharedFixtureError("invalid_cost_units")


def shared_contract_for_fixture(fixture: SharedComparisonFixture) -> SharedContract:
    """Derive all six shared digests from one canonical synthetic fixture."""

    validate_fixture(fixture)
    observer_sha = _digest({
        "visible_fields": ("failure", "service", "size", "timing")
        + tuple(f"signal:{signal}" for signal in fixture.observer_signals)
    })
    utility_sha = _digest({
        "public_actions": [asdict(action) for action in fixture.public_actions]
    })
    fault_sha = fault_trace_digest(fixture.network_available)
    cost_sha = _digest({
        "bandwidth_unit": fixture.bandwidth_unit,
        "latency_unit": fixture.latency_unit,
        "state_unit": fixture.state_unit,
        "failure_unit": fixture.failure_unit,
    })
    corpus_sha = _digest({
        "scenarios": [asdict(scenario) for scenario in fixture.scenarios]
    })
    case_sha = _digest({
        "case_id": fixture.case_id,
        "observer_sha256": observer_sha,
        "utility_sha256": utility_sha,
        "fault_trace_sha256": fault_sha,
        "cost_sha256": cost_sha,
        "corpus_sha256": corpus_sha,
    })
    return SharedContract(
        case_sha, observer_sha, utility_sha, fault_sha, cost_sha, corpus_sha,
        "held_out", "development",
    )


def bind_shared_fixture(
    manifest: ComparisonManifest, fixture: SharedComparisonFixture
) -> None:
    """Require one manifest to match every digest of the synthetic fixture."""

    validate_manifest(manifest)
    expected = shared_contract_for_fixture(fixture)
    for field in (
        "case_sha256", "observer_sha256", "utility_sha256",
        "fault_trace_sha256", "cost_sha256", "corpus_sha256",
    ):
        if getattr(manifest.shared, field) != getattr(expected, field):
            raise SharedFixtureError(f"{field}_mismatch")


def _digest(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
