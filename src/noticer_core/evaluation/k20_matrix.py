"""Explicit matrix coverage with no implicit promotion of missing evidence."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from itertools import product


class CellState(StrEnum):
    MEASURED = "measured"
    FAILED = "failed"
    INVALID = "invalid"
    INCONCLUSIVE = "inconclusive"
    NOT_APPLICABLE = "not-applicable"
    MISSING = "missing"


@dataclass(frozen=True, order=True, slots=True)
class MatrixKey:
    mechanism: str
    observer: str
    endpoint: str


@dataclass(frozen=True, slots=True)
class CellEvidence:
    state: CellState
    receipt_sha256: str | None = None
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class EvidenceMatrix:
    cells: tuple[tuple[MatrixKey, CellEvidence], ...]

    @property
    def complete(self) -> bool:
        """Whether every expected cell was explicitly accounted for, not validated."""
        return all(cell.state is not CellState.MISSING for _, cell in self.cells)

    @property
    def all_measured(self) -> bool:
        return all(cell.state is CellState.MEASURED for _, cell in self.cells)


def build_evidence_matrix(
    mechanisms: Sequence[str],
    observers: Sequence[str],
    endpoints: Sequence[str],
    observations: Mapping[MatrixKey, CellEvidence],
) -> EvidenceMatrix:
    """Retain partial coverage and reject evidence not in the preregistered axes."""
    for axis in (mechanisms, observers, endpoints):
        if not axis or len(set(axis)) != len(axis) or any(not key.strip() for key in axis):
            raise ValueError("each matrix axis needs distinct nonempty entries")
    if len(mechanisms) * len(observers) * len(endpoints) > 100_000:
        raise ValueError("matrix size exceeds the configured work bound")
    keys = tuple(sorted(MatrixKey(*coords) for coords in product(
        mechanisms, observers, endpoints
    )))
    if not observations.keys() <= set(keys):
        raise ValueError("observed cell is outside the declared matrix")
    for cell in observations.values():
        if not isinstance(cell.state, CellState) or cell.state is CellState.MISSING:
            raise ValueError("missing is a derived state, not an observation")
        if cell.receipt_sha256 is not None and (
            len(cell.receipt_sha256) != 64
            or any(letter not in "0123456789abcdef" for letter in cell.receipt_sha256)
        ):
            raise ValueError("evidence receipt must be a canonical SHA-256 digest")
        if cell.state is CellState.MEASURED and cell.receipt_sha256 is None:
            raise ValueError("measured cells require an evidence receipt")
        if cell.state is not CellState.MEASURED and not (cell.reason or "").strip():
            raise ValueError("non-measured observations require a reason")
    return EvidenceMatrix(tuple(
        (key, observations.get(key, CellEvidence(CellState.MISSING))) for key in keys
    ))
