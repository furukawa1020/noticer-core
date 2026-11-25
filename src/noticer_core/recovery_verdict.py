"""Fail closed when either checker disagrees or lacks an explicit verdict."""

from collections.abc import Mapping
from enum import StrEnum


class Resolution(StrEnum):
    VERIFIED = "verified"
    COUNTEREXAMPLE = "counterexample"
    INVALID = "invalid"
    INCONCLUSIVE = "inconclusive"
    UNRESOLVED = "unresolved"


_FIELDS = (
    "status", "category", "slot", "observer", "side", "causal_field",
    "obligation", "action", "reason", "checked_horizon",
)


def resolve_checkers(first: Mapping[str, object], second: Mapping[str, object]) -> Resolution:
    """Matching omissions are not evidence, and agreeing cutoffs stay inconclusive."""
    if any(not set(_FIELDS) <= report.keys() for report in (first, second)):
        return Resolution.UNRESOLVED
    if any(first[field] != second[field] for field in _FIELDS):
        return Resolution.UNRESOLVED
    status = first["status"]
    if status == "verified" and (
        type(first["checked_horizon"]) is not int or first["checked_horizon"] < 1
    ):
        return Resolution.UNRESOLVED
    try:
        return Resolution(status)
    except ValueError:
        return Resolution.UNRESOLVED
