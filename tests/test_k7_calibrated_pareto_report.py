from dataclasses import replace

from noticer_core.evaluation.calibrated_pareto_report import (
    CandidateEvidence,
    DecisionEvidence,
    build_calibrated_pareto_report,
    canonical_report_json,
    report_digest,
)
from noticer_core.evaluation.logical_transport_cost import LogicalCostVector
from noticer_core.evaluation.transport_cost_audit import CostAuditReport
from noticer_core.evaluation.transport_cost_profile import (
    CALIBRATION_VERSION,
    CostCalibrationArtifact,
    MeasurementInterval,
)
from noticer_core.evaluation.transport_cost_selector import CostCandidate


def _candidate(name: str, bytes_: int, latency: int) -> CostCandidate:
    cost = LogicalCostVector(bytes_, 0, 1, latency, latency * 1_000_000, 2, 0, 0, 1)
    return CostCandidate(name, True, True, 0, 0, cost)


def _evidence(name: str, bytes_: int, latency: int) -> CandidateEvidence:
    calibration = CostCalibrationArtifact(
        CALIBRATION_VERSION,
        "a" * 64,
        "b" * 64,
        "c" * 64,
        "SOFTWARE_PROXY",
        (MeasurementInterval("bytes", "bytes", bytes_, bytes_, bytes_),),
    )
    audit = CostAuditReport("PASS", ("bytes",), ("simulator_model_mismatch",))
    return CandidateEvidence(_candidate(name, bytes_, latency), calibration, audit)


def test_report_keeps_logical_and_platform_tables_separate() -> None:
    evidence = (_evidence("bandwidth", 5, 5), _evidence("latency", 10, 1))
    report = build_calibrated_pareto_report(
        evidence, DecisionEvidence(True, True, True)
    )
    assert report.frontier_ids == ("bandwidth", "latency")
    assert report.decision == "GO"
    assert len(report.logical_cost_rows) == len(report.platform_measurement_rows) == 2
    assert not report.missing_measurement_ids
    assert report_digest(report) == report_digest(report)
    assert '"ci_green_is_decision_evidence":false' in canonical_report_json(report)


def test_missing_measurement_is_preserved_and_forces_pivot() -> None:
    complete = _evidence("complete", 5, 5)
    missing = replace(_evidence("missing", 10, 1), calibration=None, audit=None)
    report = build_calibrated_pareto_report(
        (complete, missing), DecisionEvidence(True, False, False)
    )
    assert report.missing_measurement_ids == ("missing",)
    assert report.decision == "PIVOT"
    assert report.decision_reasons == (
        "calibration_incomplete",
        "independent_replication_missing",
    )


def test_core_gate_failure_is_kill_even_when_cost_evidence_exists() -> None:
    report = build_calibrated_pareto_report(
        (_evidence("candidate", 1, 1),), DecisionEvidence(False, True, True)
    )
    assert report.decision == "KILL"
    assert report.decision_reasons == ("core_gate_failed",)
