"""Frozen QuotientLimit scalability, ablation, and optimality-gap protocol."""

from __future__ import annotations

import hashlib
import itertools
import json
from dataclasses import asdict, dataclass
from fractions import Fraction
from typing import Final, Literal

AXES: Final = {
    "private_histories": (2, 4, 8, 16, 32, 64),
    "quotient_classes": (1, 2, 4, 8),
    "horizon": (4, 8, 16, 32, 64, 128),
    "services": (1, 2, 4, 8),
    "observer_projections": (1, 2, 4, 8),
    "fault_scenarios": (1, 4, 8, 16),
}
AXIS_ORDER: Final = tuple(AXES)
MEASUREMENT_FIELDS: Final = (
    "variables",
    "equalities",
    "inequalities",
    "nonzeros",
    "solver_time_ms",
    "reconstruction_time_ms",
    "checker_time_ms",
    "peak_memory_bytes",
    "certificate_size_bytes",
)
ABLATION_PAIRS: Final = (
    ("explicit_trace_lp", "sequence_form_lp"),
    ("no_quotient_compression", "quotient_compression"),
    ("no_observer_projection_reduction", "observer_projection_reduction"),
    ("floating_only", "exact_reconstruction"),
    ("no_dual_certificate", "dual_certificate"),
    ("independent_per_service", "joint_collusion"),
    ("per_bucket", "longitudinal_joint"),
    ("deterministic_only", "randomized_mechanism"),
)
ABLATIONS: Final = tuple(value for pair in ABLATION_PAIRS for value in pair)


@dataclass(frozen=True, slots=True)
class ScalabilityPoint:
    private_histories: int
    quotient_classes: int
    horizon: int
    services: int
    observer_projections: int
    fault_scenarios: int


@dataclass(frozen=True, slots=True)
class EvaluationCase:
    case_id: str
    point: ScalabilityPoint
    ablation: str


@dataclass(frozen=True, slots=True)
class EvaluationMeasurement:
    case_id: str
    status: Literal["COMPLETED", "TIMEOUT", "MEMORY_LIMIT", "FAILED"]
    variables: int | None
    equalities: int | None
    inequalities: int | None
    nonzeros: int | None
    solver_time_ms: float | None
    reconstruction_time_ms: float | None
    checker_time_ms: float | None
    peak_memory_bytes: int | None
    certificate_size_bytes: int | None
    maximum_integer_bit_length: int | None
    mutation_rejection_rate: float | None
    cross_platform_bytes_reproducible: bool | None


@dataclass(frozen=True, slots=True)
class OptimalityGap:
    candidate_cost: Fraction
    certified_lower_bound: Fraction
    absolute_gap: Fraction
    relative_gap: Fraction
    scale: Fraction


def iter_scalability_points() -> tuple[ScalabilityPoint, ...]:
    """Return the frozen full Cartesian matrix in canonical axis order."""
    return tuple(
        ScalabilityPoint(*values)
        for values in itertools.product(*(AXES[name] for name in AXIS_ORDER))
    )


def evaluation_cases(ablation: str) -> tuple[EvaluationCase, ...]:
    """Bind every matrix point to one predeclared ablation configuration."""
    if ablation not in ABLATIONS:
        raise ValueError("ablation is not in the frozen protocol")
    cases = []
    for point in iter_scalability_points():
        payload = {"point": asdict(point), "ablation": ablation}
        digest = hashlib.sha256(_canonical_json(payload)).hexdigest()[:16]
        cases.append(EvaluationCase(f"k9e-{digest}", point, ablation))
    return tuple(cases)


def validate_measurement(case: EvaluationCase, measurement: EvaluationMeasurement) -> None:
    """Reject partial success records and impossible resource measurements."""
    if measurement.case_id != case.case_id:
        raise ValueError("measurement case identity mismatch")
    values = [getattr(measurement, field) for field in MEASUREMENT_FIELDS]
    if measurement.status == "COMPLETED":
        if any(value is None for value in values):
            raise ValueError("completed measurement must contain every resource field")
        if measurement.maximum_integer_bit_length is None:
            raise ValueError("completed measurement lacks certificate bit length")
        if measurement.mutation_rejection_rate is None:
            raise ValueError("completed measurement lacks mutation rejection rate")
        if measurement.cross_platform_bytes_reproducible is None:
            raise ValueError("completed measurement lacks byte reproducibility result")
    elif any(value is not None for value in values):
        raise ValueError("failed measurement must not masquerade as partial completion")
    numeric = [value for value in values if value is not None]
    if any(value < 0 for value in numeric):
        raise ValueError("measurement values must be non-negative")
    rate = measurement.mutation_rejection_rate
    if rate is not None and not 0.0 <= rate <= 1.0:
        raise ValueError("mutation rejection rate must be within [0, 1]")


def compute_optimality_gap(
    candidate_cost: Fraction,
    certified_lower_bound: Fraction,
    scale_floor: Fraction,
) -> OptimalityGap:
    """Compute exact absolute and relative gaps without floating-point rounding."""
    if candidate_cost < 0 or certified_lower_bound < 0 or scale_floor <= 0:
        raise ValueError("costs must be non-negative and scale_floor positive")
    if candidate_cost < certified_lower_bound:
        raise ValueError("candidate cannot be below a certified lower bound")
    absolute = candidate_cost - certified_lower_bound
    scale = max(certified_lower_bound, scale_floor)
    return OptimalityGap(
        candidate_cost,
        certified_lower_bound,
        absolute,
        absolute / scale,
        scale,
    )


def build_evaluation_report(
    cases: tuple[EvaluationCase, ...],
    measurements: tuple[EvaluationMeasurement, ...],
) -> dict[str, object]:
    """Build a deterministic report without filling missing matrix cells."""
    expected = {case.case_id: case for case in cases}
    observed: dict[str, EvaluationMeasurement] = {}
    for measurement in measurements:
        if measurement.case_id in observed:
            raise ValueError("duplicate measurement")
        case = expected.get(measurement.case_id)
        if case is None:
            raise ValueError("measurement is outside the frozen matrix")
        validate_measurement(case, measurement)
        observed[measurement.case_id] = measurement
    completed = sum(value.status == "COMPLETED" for value in observed.values())
    report: dict[str, object] = {
        "schema": "noticer.k9.quotient-limit-evaluation.v1",
        "expected_cases": len(cases),
        "observed_cases": len(observed),
        "completed_cases": completed,
        "missing_cases": len(cases) - len(observed),
        "grid_status": "COMPLETE" if len(cases) == len(observed) else "INCOMPLETE",
        "interpolation_used": False,
        "generated_artifacts_committed": False,
        "measurements": [asdict(observed[case_id]) for case_id in sorted(observed)],
    }
    report["artifact_sha256"] = hashlib.sha256(_canonical_json(report)).hexdigest()
    return report


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
