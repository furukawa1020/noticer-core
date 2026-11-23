from __future__ import annotations

import pytest

from noticer_core.evaluation.k20_identity_contract import (
    IdentityContractError,
    WindowIdentity,
    validate_identity_rows,
)


def row(subject: str, session: str, window: str, time_index: int) -> WindowIdentity:
    return WindowIdentity(subject, session, window, time_index)


def test_inventory_counts_opaque_hierarchy() -> None:
    inventory = validate_identity_rows(
        [
            row("person_a001", "session_a001", "window_a0001", 0),
            row("person_a001", "session_a001", "window_a0002", 1),
            row("person_a001", "session_a002", "window_a0003", 0),
            row("person_b001", "session_b001", "window_b0001", 0),
        ]
    )
    assert inventory.subject_count == 2
    assert inventory.session_count == 3
    assert inventory.window_count == 4
    assert inventory.sessions_per_subject == (("person_a001", 2), ("person_b001", 1))


def test_session_cannot_change_subject_owner() -> None:
    with pytest.raises(IdentityContractError, match="exactly one subject"):
        validate_identity_rows(
            [
                row("person_a001", "session_x001", "window_a0001", 0),
                row("person_b001", "session_x001", "window_b0001", 1),
            ]
        )


def test_window_cannot_be_reused_across_sessions() -> None:
    with pytest.raises(IdentityContractError, match="reused"):
        validate_identity_rows(
            [
                row("person_a001", "session_a001", "window_x0001", 0),
                row("person_a001", "session_a002", "window_x0001", 0),
            ]
        )


def test_time_index_is_unique_inside_session() -> None:
    with pytest.raises(IdentityContractError, match="time_index"):
        validate_identity_rows(
            [
                row("person_a001", "session_a001", "window_a0001", 0),
                row("person_a001", "session_a001", "window_a0002", 0),
            ]
        )


@pytest.mark.parametrize("identifier", ["a@b.example", "Name:Alice", "短い識別子", "short"])
def test_direct_or_nonopaque_identifiers_are_rejected(identifier: str) -> None:
    with pytest.raises(IdentityContractError):
        row(identifier, "session_a001", "window_a0001", 0).validate()
