"""Fail-closed session-disjoint split contract for K20."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from noticer_core.evaluation.k20_identity_contract import WindowIdentity


class SplitContractError(ValueError):
    """Raised when a split can leak session information."""


class SplitName(StrEnum):
    TRAIN = "train"
    VALIDATION = "validation"
    TEST = "test"


@dataclass(frozen=True, slots=True)
class SessionAssignment:
    session_id: str
    split: SplitName


@dataclass(frozen=True, slots=True)
class VerifiedSessionSplit:
    assignments: tuple[SessionAssignment, ...]
    subjects_by_split: tuple[tuple[SplitName, tuple[str, ...]], ...]

    def split_for(self, session_id: str) -> SplitName:
        for assignment in self.assignments:
            if assignment.session_id == session_id:
                return assignment.split
        raise KeyError(session_id)


def verify_session_disjoint_split(
    rows: Iterable[WindowIdentity],
    assignments: Iterable[SessionAssignment],
    *,
    require_every_subject_in_every_split: bool = True,
) -> VerifiedSessionSplit:
    """Verify that complete sessions, never windows, define the split."""
    row_values = tuple(rows)
    assignment_values = tuple(assignments)
    if not row_values or not assignment_values:
        raise SplitContractError("rows and assignments must not be empty")

    session_subject: dict[str, str] = {}
    for row in row_values:
        row.validate()
        owner = session_subject.setdefault(row.session_id, row.subject_id)
        if owner != row.subject_id:
            raise SplitContractError("session ownership is inconsistent")

    split_by_session: dict[str, SplitName] = {}
    for assignment in assignment_values:
        if assignment.session_id in split_by_session:
            raise SplitContractError("each session must have exactly one split assignment")
        if assignment.session_id not in session_subject:
            raise SplitContractError("split contains an unknown session")
        split_by_session[assignment.session_id] = assignment.split

    missing = set(session_subject) - set(split_by_session)
    if missing:
        raise SplitContractError("every session must have a split assignment")

    subjects: dict[SplitName, set[str]] = defaultdict(set)
    for session_id, split in split_by_session.items():
        subjects[split].add(session_subject[session_id])
    missing_splits = set(SplitName) - set(subjects)
    if missing_splits:
        raise SplitContractError("train, validation, and test splits are required")
    if require_every_subject_in_every_split:
        expected = set(session_subject.values())
        if any(subjects[split] != expected for split in SplitName):
            raise SplitContractError(
                "every subject must contribute a complete session to every split"
            )

    canonical = tuple(
        SessionAssignment(session_id, split_by_session[session_id])
        for session_id in sorted(split_by_session)
    )
    coverage = tuple((split, tuple(sorted(subjects[split]))) for split in SplitName)
    return VerifiedSessionSplit(canonical, coverage)

