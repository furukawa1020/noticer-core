from __future__ import annotations

import pytest

from noticer_core.evaluation.k20_identity_contract import WindowIdentity
from noticer_core.evaluation.k20_session_split import (
    SessionAssignment,
    SplitContractError,
    SplitName,
    verify_session_disjoint_split,
)


def rows() -> list[WindowIdentity]:
    values: list[WindowIdentity] = []
    for subject in ("person_a001", "person_b001"):
        for index in range(3):
            session = f"{subject}_s{index:02d}"
            for window in range(2):
                values.append(WindowIdentity(subject, session, f"{session}_w{window:02d}", window))
    return values


def assignments() -> list[SessionAssignment]:
    result: list[SessionAssignment] = []
    names = (SplitName.TRAIN, SplitName.VALIDATION, SplitName.TEST)
    for subject in ("person_a001", "person_b001"):
        for index, split in enumerate(names):
            result.append(SessionAssignment(f"{subject}_s{index:02d}", split))
    return result


def test_complete_sessions_form_a_canonical_disjoint_split() -> None:
    verified = verify_session_disjoint_split(rows(), reversed(assignments()))
    assert len(verified.assignments) == 6
    assert verified.split_for("person_a001_s02") is SplitName.TEST
    assert [item.session_id for item in verified.assignments] == sorted(
        item.session_id for item in verified.assignments
    )


def test_duplicate_session_assignment_is_rejected() -> None:
    values = assignments()
    values.append(SessionAssignment(values[0].session_id, SplitName.TEST))
    with pytest.raises(SplitContractError, match="exactly one"):
        verify_session_disjoint_split(rows(), values)


def test_missing_and_unknown_sessions_are_rejected() -> None:
    with pytest.raises(SplitContractError, match="every session"):
        verify_session_disjoint_split(rows(), assignments()[:-1])
    values = assignments()
    values[-1] = SessionAssignment("unknown_session", SplitName.TEST)
    with pytest.raises(SplitContractError, match="unknown session"):
        verify_session_disjoint_split(rows(), values)


def test_window_style_duplicate_assignment_cannot_pass_as_session_split() -> None:
    values = assignments()
    values.insert(1, values[0])
    with pytest.raises(SplitContractError, match="exactly one"):
        verify_session_disjoint_split(rows(), values)


def test_subject_coverage_is_required_for_identity_evaluation() -> None:
    values = assignments()
    values[-1] = SessionAssignment("person_b001_s02", SplitName.TRAIN)
    with pytest.raises(SplitContractError, match="every subject"):
        verify_session_disjoint_split(rows(), values)
