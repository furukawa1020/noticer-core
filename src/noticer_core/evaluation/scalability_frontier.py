"""Dominance frontiers over complete, failure, and missing K7 observations."""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Final

from noticer_core.evaluation.execution_protocol import (
    ExecutionProtocol,
    RunPhase,
    execution_protocol_sha256,
)
from noticer_core.evaluation.scalability_contract import (
    AXIS_ORDER,
    OutcomeStatus,
    ScalabilityCase,
    ScalabilityContract,
    scalability_contract_sha256,
)

SCHEMA: Final = "noticer.k7.scalability-frontier.v1"
FAILURE_STATUSES: Final = tuple(
    status for status in OutcomeStatus if status is not OutcomeStatus.COMPLETED
)


class ScalabilityFrontierError(ValueError):
    """Observations do not match the frozen schedule or contain ambiguity."""


@dataclass(frozen=True, slots=True)
class RunObservation:
    """One measured run status after checkpoint verification."""

    run_id: str
    case_id: str
    backend_id: str
    repetition: int
    status: OutcomeStatus


def build_frontier_report(
    contract: ScalabilityContract,
    protocol: ExecutionProtocol,
    observations: Iterable[RunObservation],
) -> dict[str, object]:
    """Build exact Pareto frontiers without completing or interpolating missing cells."""

    expected = {
        run.run_id: run for run in protocol.schedule if run.phase is RunPhase.MEASURED
    }
    observed: dict[str, RunObservation] = {}
    for observation in observations:
        if observation.run_id in observed:
            raise ScalabilityFrontierError(f"duplicate observation: {observation.run_id}")
        scheduled = expected.get(observation.run_id)
        if scheduled is None:
            raise ScalabilityFrontierError(
                f"observation is not a measured run: {observation.run_id}"
            )
        if (
            observation.case_id != scheduled.case_id
            or observation.backend_id != scheduled.backend_id
            or observation.repetition != scheduled.repetition
        ):
            raise ScalabilityFrontierError("observation identity differs from schedule")
        observed[observation.run_id] = observation

    by_case: dict[str, list[OutcomeStatus]] = defaultdict(list)
    missing_by_case: Counter[str] = Counter()
    for run_id, run in expected.items():
        observation = observed.get(run_id)
        if observation is None:
            missing_by_case[run.case_id] += 1
        else:
            by_case[run.case_id].append(observation.status)

    backends: dict[str, object] = {}
    warnings: list[dict[str, object]] = []
    for backend_id in sorted({case.backend_id for case in contract.cases}):
        backend_cases = [case for case in contract.cases if case.backend_id == backend_id]
        completed = [
            case
            for case in backend_cases
            if missing_by_case[case.case_id] == 0
            and len(by_case[case.case_id]) == protocol.measured_repetitions
            and all(status is OutcomeStatus.COMPLETED for status in by_case[case.case_id])
        ]
        failure_points = {
            status: [case for case in backend_cases if status in by_case[case.case_id]]
            for status in FAILURE_STATUSES
        }
        backend_warnings = _non_monotonic_warnings(completed, failure_points)
        warnings.extend(backend_warnings)
        incomplete = sorted(
            case.case_id for case in backend_cases if missing_by_case[case.case_id] > 0
        )
        mixed = sorted(
            case.case_id
            for case in backend_cases
            if missing_by_case[case.case_id] == 0
            and len(set(by_case[case.case_id])) > 1
        )
        backends[backend_id] = {
            "completed_frontier": [_point(case) for case in _maximal(completed)],
            "first_failure": {
                status.value: [_point(case) for case in _minimal(points)]
                for status, points in failure_points.items()
            },
            "incomplete_case_ids": incomplete,
            "mixed_status_case_ids": mixed,
            "non_monotonic_warning_count": len(backend_warnings),
        }

    expected_count = len(expected)
    observed_count = len(observed)
    report: dict[str, object] = {
        "schema": SCHEMA,
        "scalability_contract_sha256": scalability_contract_sha256(contract),
        "execution_protocol_sha256": execution_protocol_sha256(protocol),
        "grid_status": "COMPLETE" if observed_count == expected_count else "INCOMPLETE",
        "expected_measured_runs": expected_count,
        "observed_measured_runs": observed_count,
        "missing_measured_runs": expected_count - observed_count,
        "backends": backends,
        "non_monotonic_warnings": sorted(
            warnings,
            key=lambda row: (
                str(row["backend_id"]),
                str(row["failure_status"]),
                str(row["failed_case_id"]),
                str(row["completed_case_id"]),
            ),
        ),
        "interpolation_used": False,
        "hardware_status": "NOT_VERIFIED",
        "security_interpretation": "NOT_A_PERFORMANCE_OR_SECURITY_VERDICT",
    }
    report["artifact_sha256"] = _report_digest(report)
    return report


def observations_from_checkpoints(
    checkpoints: Iterable[Mapping[str, object]],
) -> list[RunObservation]:
    """Extract measured observations from already verified checkpoint mappings."""

    observations = []
    for checkpoint in checkpoints:
        if checkpoint.get("phase") != RunPhase.MEASURED.value:
            continue
        try:
            observations.append(
                RunObservation(
                    run_id=str(checkpoint["run_id"]),
                    case_id=str(checkpoint["case_id"]),
                    backend_id=str(checkpoint["backend_id"]),
                    repetition=int(checkpoint["repetition"]),
                    status=OutcomeStatus(str(checkpoint["status"])),
                )
            )
        except (KeyError, TypeError, ValueError) as error:
            raise ScalabilityFrontierError("checkpoint observation is malformed") from error
    return observations


def _maximal(cases: list[ScalabilityCase]) -> list[ScalabilityCase]:
    return _frontier(cases, maximal=True)


def _minimal(cases: list[ScalabilityCase]) -> list[ScalabilityCase]:
    return _frontier(cases, maximal=False)


def _frontier(cases: list[ScalabilityCase], *, maximal: bool) -> list[ScalabilityCase]:
    unique = {case.case_id: case for case in cases}
    selected = []
    for case in unique.values():
        dominated = any(
            other.case_id != case.case_id
            and (_dominates(case, other) if maximal else _dominates(other, case))
            for other in unique.values()
        )
        if not dominated:
            selected.append(case)
    return sorted(
        selected,
        key=lambda case: tuple(case.dimensions.as_dict()[axis] for axis in AXIS_ORDER),
    )


def _dominates(easier: ScalabilityCase, harder: ScalabilityCase) -> bool:
    left = easier.dimensions.as_dict()
    right = harder.dimensions.as_dict()
    return all(left[axis] <= right[axis] for axis in AXIS_ORDER) and any(
        left[axis] < right[axis] for axis in AXIS_ORDER
    )


def _non_monotonic_warnings(
    completed: list[ScalabilityCase],
    failures: Mapping[OutcomeStatus, list[ScalabilityCase]],
) -> list[dict[str, object]]:
    warnings = []
    for status, failed_cases in failures.items():
        for failed in failed_cases:
            for successful in completed:
                if _dominates(failed, successful):
                    warnings.append(
                        {
                            "backend_id": failed.backend_id,
                            "failure_status": status.value,
                            "failed_case_id": failed.case_id,
                            "completed_case_id": successful.case_id,
                        }
                    )
    return warnings


def _point(case: ScalabilityCase) -> dict[str, object]:
    return {
        "case_id": case.case_id,
        "profile": case.profile,
        "dimensions": case.dimensions.as_dict(),
        "target_gate": case.target_gate,
    }


def _report_digest(report: Mapping[str, object]) -> str:
    unsigned = dict(report)
    unsigned.pop("artifact_sha256", None)
    encoded = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()
