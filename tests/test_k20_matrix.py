import pytest

from noticer_core.evaluation.k20_matrix import (
    CellEvidence,
    CellState,
    MatrixKey,
    build_evidence_matrix,
)


def test_missing_evidence_is_visible_and_not_a_success() -> None:
    key = MatrixKey("aetp", "metadata", "identity")
    matrix = build_evidence_matrix(
        ["aetp", "fixed"], ["metadata"], ["identity"],
        {key: CellEvidence(CellState.MEASURED, "a" * 64)},
    )
    assert not matrix.complete and not matrix.all_measured
    assert dict(matrix.cells)[MatrixKey("fixed", "metadata", "identity")].state is CellState.MISSING


def test_complete_reporting_is_distinct_from_all_measured() -> None:
    key = MatrixKey("aetp", "metadata", "identity")
    matrix = build_evidence_matrix(
        ["aetp"], ["metadata"], ["identity"],
        {key: CellEvidence(CellState.INCONCLUSIVE, reason="too few clusters")},
    )
    assert matrix.complete and not matrix.all_measured


def test_receipt_required_for_measured_cell() -> None:
    key = MatrixKey("aetp", "metadata", "identity")
    with pytest.raises(ValueError, match="evidence receipt"):
        build_evidence_matrix(
            ["aetp"], ["metadata"], ["identity"], {key: CellEvidence(CellState.MEASURED)}
        )
