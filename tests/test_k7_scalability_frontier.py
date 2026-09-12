from __future__ import annotations

import json
from pathlib import Path

import pytest

from noticer_core.evaluation.execution_protocol import RunPhase, load_execution_protocol
from noticer_core.evaluation.scalability_contract import OutcomeStatus, load_scalability_contract
from noticer_core.evaluation.scalability_frontier import (
    RunObservation,
    ScalabilityFrontierError,
    build_frontier_report,
)

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "configs" / "quotient_forge" / "k7_scalability_contract_v1.yaml"
PROTOCOL = ROOT / "configs" / "quotient_forge" / "k7_execution_protocol_v1.yaml"


def _inputs() -> tuple[object, object, list[object]]:
    contract = load_scalability_contract(CONTRACT)
    protocol = load_execution_protocol(PROTOCOL, repository_root=ROOT)
    measured = [run for run in protocol.schedule if run.phase is RunPhase.MEASURED]
    return contract, protocol, measured


def _observations(runs: list[object], statuses: dict[str, OutcomeStatus]) -> list[RunObservation]:
    return [
        RunObservation(
            run.run_id,
            run.case_id,
            run.backend_id,
            run.repetition,
            statuses.get(run.case_id, OutcomeStatus.COMPLETED),
        )
        for run in runs
    ]


def test_complete_grid_reports_maximal_completed_target_without_interpolation() -> None:
    contract, protocol, runs = _inputs()
    report = build_frontier_report(contract, protocol, _observations(runs, {}))
    assert report["grid_status"] == "COMPLETE"
    assert report["expected_measured_runs"] == report["observed_measured_runs"] == 460
    assert report["missing_measured_runs"] == 0
    assert report["interpolation_used"] is False
    for backend in report["backends"].values():
        assert len(backend["completed_frontier"]) == 1
        point = backend["completed_frontier"][0]
        assert point["target_gate"] is True


def test_failure_causes_have_separate_minimal_frontiers() -> None:
    contract, protocol, runs = _inputs()
    baseline = {
        case.backend_id: case
        for case in contract.cases
        if case.profile == "baseline"
    }
    statuses = {
        baseline["reference"].case_id: OutcomeStatus.TIMEOUT,
        baseline["cegis"].case_id: OutcomeStatus.MEMORY_LIMIT,
        baseline["smt"].case_id: OutcomeStatus.SOLVER_UNKNOWN,
    }
    report = build_frontier_report(contract, protocol, _observations(runs, statuses))
    assert report["backends"]["reference"]["first_failure"]["TIMEOUT"][0]["profile"] == "baseline"
    assert report["backends"]["cegis"]["first_failure"]["MEMORY_LIMIT"][0]["profile"] == "baseline"
    assert report["backends"]["smt"]["first_failure"]["SOLVER_UNKNOWN"][0]["profile"] == "baseline"


def test_non_monotonic_failure_is_reported_not_hidden() -> None:
    contract, protocol, runs = _inputs()
    baseline = next(
        case
        for case in contract.cases
        if case.backend_id == "qbf" and case.profile == "baseline"
    )
    report = build_frontier_report(
        contract,
        protocol,
        _observations(runs, {baseline.case_id: OutcomeStatus.TIMEOUT}),
    )
    warnings = report["non_monotonic_warnings"]
    assert warnings
    assert all(warning["failed_case_id"] == baseline.case_id for warning in warnings)
    assert report["backends"]["qbf"]["non_monotonic_warning_count"] == len(warnings)


def test_missing_run_keeps_grid_incomplete_and_case_off_completed_frontier() -> None:
    contract, protocol, runs = _inputs()
    missing = runs[0]
    observations = _observations(runs[1:], {})
    report = build_frontier_report(contract, protocol, observations)
    assert report["grid_status"] == "INCOMPLETE"
    assert report["missing_measured_runs"] == 1
    backend = report["backends"][missing.backend_id]
    assert missing.case_id in backend["incomplete_case_ids"]
    assert missing.case_id not in {point["case_id"] for point in backend["completed_frontier"]}


def test_duplicate_or_identity_changed_observation_is_rejected() -> None:
    contract, protocol, runs = _inputs()
    observation = _observations(runs[:1], {})[0]
    with pytest.raises(ScalabilityFrontierError, match="duplicate"):
        build_frontier_report(contract, protocol, [observation, observation])
    changed = RunObservation(
        observation.run_id,
        observation.case_id,
        "wrong",
        observation.repetition,
        observation.status,
    )
    with pytest.raises(ScalabilityFrontierError, match="identity differs"):
        build_frontier_report(contract, protocol, [changed])


def test_report_matches_schema_root_and_is_digest_bound() -> None:
    contract, protocol, runs = _inputs()
    report = build_frontier_report(contract, protocol, _observations(runs, {}))
    schema = json.loads(
        (ROOT / "schemas" / "k7_scalability_frontier_v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    assert set(report) == set(schema["required"]) == set(schema["properties"])
    assert len(report["artifact_sha256"]) == 64
    assert report["hardware_status"] == "NOT_VERIFIED"
