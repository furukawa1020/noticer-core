"""Opaque participant, session, and window identity contract for K20."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

_OPAQUE_ID = re.compile(r"^[a-z][a-z0-9_-]{7,63}$")
_DIRECT_IDENTIFIER_MARKERS = ("@", ".com", "mailto:", "phone:", "name:")


class IdentityContractError(ValueError):
    """Raised when evaluation identifiers violate privacy or ownership rules."""


@dataclass(frozen=True, slots=True)
class WindowIdentity:
    subject_id: str
    session_id: str
    window_id: str
    time_index: int

    def validate(self) -> None:
        _validate_opaque("subject_id", self.subject_id)
        _validate_opaque("session_id", self.session_id)
        _validate_opaque("window_id", self.window_id)
        if self.time_index < 0:
            raise IdentityContractError("time_index must be non-negative")


@dataclass(frozen=True, slots=True)
class IdentityInventory:
    subject_count: int
    session_count: int
    window_count: int
    sessions_per_subject: tuple[tuple[str, int], ...]


def validate_identity_rows(rows: Iterable[WindowIdentity]) -> IdentityInventory:
    """Validate stable ownership without exposing an external identity mapping."""
    materialized = tuple(rows)
    if not materialized:
        raise IdentityContractError("identity inventory must not be empty")

    session_owner: dict[str, str] = {}
    window_owner: dict[str, tuple[str, str]] = {}
    time_keys: set[tuple[str, int]] = set()
    subject_sessions: dict[str, set[str]] = {}
    for row in materialized:
        row.validate()
        previous_subject = session_owner.setdefault(row.session_id, row.subject_id)
        if previous_subject != row.subject_id:
            raise IdentityContractError("each session must belong to exactly one subject")
        owner = (row.subject_id, row.session_id)
        previous_window = window_owner.setdefault(row.window_id, owner)
        if previous_window != owner:
            raise IdentityContractError("window_id cannot be reused across sessions")
        time_key = (row.session_id, row.time_index)
        if time_key in time_keys:
            raise IdentityContractError("time_index must be unique within a session")
        time_keys.add(time_key)
        subject_sessions.setdefault(row.subject_id, set()).add(row.session_id)

    counts = tuple(sorted((subject, len(sessions)) for subject, sessions in subject_sessions.items()))
    return IdentityInventory(
        subject_count=len(subject_sessions),
        session_count=len(session_owner),
        window_count=len(window_owner),
        sessions_per_subject=counts,
    )


def _validate_opaque(name: str, value: str) -> None:
    lowered = value.lower()
    if not value.isascii() or not _OPAQUE_ID.fullmatch(value):
        raise IdentityContractError(f"{name} must be a lowercase opaque ASCII identifier")
    if any(marker in lowered for marker in _DIRECT_IDENTIFIER_MARKERS):
        raise IdentityContractError(f"{name} appears to contain a direct identifier")

