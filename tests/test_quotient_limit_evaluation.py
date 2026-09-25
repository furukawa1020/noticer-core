from __future__ import annotations

from dataclasses import replace
from fractions import Fraction

import pytest

from noticer_core.evaluation.quotient_limit_evaluation import (
    ABLATION_PAIRS,
    ABLATIONS,
    AXES,
    EvaluationMeasurement,
    build_evaluation_report,
    compute_optimality_gap,
    evaluation_cases,
    iter_scalability_points,
    validate_measurement,
)


def test_frozen_matrix_is_full_cartesian_product() -> None:
    points = iter_scalability_points()
    expected = 1
    for values in AXES.values():
        expected *= len(values)
    assert expected == 9216
    assert len(points) == expected
    assert len(set(points)) == expected
    assert max(point.private_histories for point in points) == 64
    assert max(point.horizon for point in points) == 128
    assert max(point.services for point in points) == 8


def test_all_sixteen_ablations_are_paired_and_predeclared() -> None:
    assert len(ABLATIONS) == 16
    assert len(ABLATION_PAIRS) == 8
    assert len(set(ABLATIONS)) == 16
    assert len(evaluation_cases("sequence_form_lp")) == 9216
    with pytest.raises(ValueError, match="frozen protocol"):
        evaluation_cases("result_driven_ablation")


def completed(case_id: str) -> EvaluationMeasurement:
    return EvaluationMeasurement(
        case_id=case_id,
        status="COMPLETED",
        variables=10,
        equalities=2,
        inequalities=3,
        nonzeros=20,
        solver_time_ms=1.5,
        reconstruction_time_ms=0.5,
        checker_time_ms=0.25,
        peak_memory_bytes=4096,
        certificate_size_bytes=512,
        maximum_integer_bit_length=32,
        mutation_rejection_rate=1.0,
        cross_platform_bytes_reproducible=True,
    )


def test_measurement_requires_complete_certificate_and_resource_fields() -> None:
    case = evaluation_cases("dual_certificate")[0]
    validate_measurement(case, completed(case.case_id))
    invalid = completed(case.case_id)
    invalid = replace(completed(case.case_id), checker_time_ms=None)
    with pytest.raises(ValueError, match="every resource field"):
        validate_measurement(case, invalid)


def test_optimality_gap_is_exact() -> None:
    result = compute_optimality_gap(Fraction(7, 2), Fraction(3), Fraction(1, 10))
    assert result.absolute_gap == Fraction(1, 2)
    assert result.relative_gap == Fraction(1, 6)


def test_report_preserves_missing_cells_without_interpolation() -> None:
    cases = evaluation_cases("exact_reconstruction")[:2]
    report = build_evaluation_report(cases, (completed(cases[0].case_id),))
    assert report["grid_status"] == "INCOMPLETE"
    assert report["missing_cases"] == 1
    assert report["interpolation_used"] is False
    assert report["generated_artifacts_committed"] is False
