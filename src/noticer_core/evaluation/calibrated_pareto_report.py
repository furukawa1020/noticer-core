"""Calibrated Pareto report and evidence-based GO/PIVOT/KILL decision."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass

from noticer_core.evaluation.transport_cost_audit import CostAuditReport
from noticer_core.evaluation.transport_cost_profile import CostCalibrationArtifact
from noticer_core.evaluation.transport_cost_selector import (
    AXES,
    CostCandidate,
    SelectionPolicy,
    select_candidates,
)
from noticer_core.evaluation.transport_cost_selector import (
    FORMAT_VERSION as SELECTION_VERSION,
)

FORMAT_VERSION = "noticer.k7.calibrated-pareto-report.v1"


class CalibratedReportError(ValueError):
    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


@dataclass(frozen=True)
class CandidateEvidence:
    candidate: CostCandidate
    calibration: CostCalibrationArtifact | None
    audit: CostAuditReport | None


@dataclass(frozen=True)
class DecisionEvidence:
    core_gate_passed: bool
    measurement_completed: bool
    independent_replication: bool


@dataclass(frozen=True)
class LogicalCostRow:
    candidate_id: str
    values: tuple[tuple[str, int], ...]


@dataclass(frozen=True)
class PlatformMeasurementRow:
    candidate_id: str
    platform_profile_sha256: str
    intervals: tuple[tuple[str, str, float, float, float], ...]


@dataclass(frozen=True)
class CalibratedParetoReport:
    format_version: str
    frontier_ids: tuple[str, ...]
    logical_cost_rows: tuple[LogicalCostRow, ...]
    platform_measurement_rows: tuple[PlatformMeasurementRow, ...]
    missing_measurement_ids: tuple[str, ...]
    decision: str
    decision_reasons: tuple[str, ...]
    ci_green_is_decision_evidence: bool = False
    security_proof: bool = False


def build_calibrated_pareto_report(
    evidence: tuple[CandidateEvidence, ...],
    decision_evidence: DecisionEvidence,
) -> CalibratedParetoReport:
    """Build separate logical/platform tables and a non-CI research decision."""

    ids = tuple(item.candidate.candidate_id for item in evidence)
    if not ids or ids != tuple(sorted(set(ids))):
        raise CalibratedReportError("noncanonical_evidence")
    selection = select_candidates(
        SelectionPolicy(SELECTION_VERSION, "pareto", AXES),
        tuple(item.candidate for item in evidence),
    )
    logical_rows = tuple(
        LogicalCostRow(
            item.candidate.candidate_id,
            tuple((axis, getattr(item.candidate.cost, axis)) for axis in AXES),
        )
        for item in evidence
    )
    platform_rows: list[PlatformMeasurementRow] = []
    missing: list[str] = []
    for item in evidence:
        if item.calibration is None or item.audit is None:
            missing.append(item.candidate.candidate_id)
            continue
        if item.audit.status != "PASS" or item.audit.security_proof:
            raise CalibratedReportError("invalid_audit_evidence")
        platform_rows.append(
            PlatformMeasurementRow(
                item.candidate.candidate_id,
                item.calibration.platform_profile_sha256,
                tuple(
                    (
                        interval.axis,
                        interval.unit,
                        interval.lower,
                        interval.estimate,
                        interval.upper,
                    )
                    for interval in item.calibration.intervals
                ),
            )
        )
    decision, reasons = _decision(decision_evidence, tuple(missing))
    return CalibratedParetoReport(
        FORMAT_VERSION,
        selection.selected_ids,
        logical_rows,
        tuple(platform_rows),
        tuple(missing),
        decision,
        reasons,
    )


def canonical_report_json(report: CalibratedParetoReport) -> str:
    if (
        report.format_version != FORMAT_VERSION
        or report.ci_green_is_decision_evidence
        or report.security_proof
    ):
        raise CalibratedReportError("invalid_report_header")
    return json.dumps(asdict(report), sort_keys=True, separators=(",", ":"))


def report_digest(report: CalibratedParetoReport) -> str:
    return hashlib.sha256(canonical_report_json(report).encode("utf-8")).hexdigest()


def _decision(
    evidence: DecisionEvidence,
    missing: tuple[str, ...],
) -> tuple[str, tuple[str, ...]]:
    if not evidence.core_gate_passed:
        return "KILL", ("core_gate_failed",)
    reasons: list[str] = []
    if missing or not evidence.measurement_completed:
        reasons.append("calibration_incomplete")
    if not evidence.independent_replication:
        reasons.append("independent_replication_missing")
    return ("PIVOT", tuple(reasons)) if reasons else ("GO", ("all_evidence_gates_passed",))
