"""Fail-closed comparison of runtime recipient logs with their checked projection."""

from collections import Counter
from collections.abc import Mapping, Sequence
from enum import StrEnum


class LogAudit(StrEnum):
    MATCH = "match"
    INVALID = "invalid"
    MISSING = "missing"
    EXTRA = "extra"
    REORDERED = "reordered"
    DIVERGED = "diverged"


def _projection(events: Sequence[Mapping[str, object]]) -> tuple[tuple, ...]:
    required = {"service", "slot", "action"}
    result = []
    for event in events:
        if not required <= event.keys() <= required | {"receipt"}:
            raise ValueError("unknown or absent recipient log field")
        if type(event["slot"]) is not int or event["slot"] < 0:
            raise ValueError("logical receipt slot must be a nonnegative integer")
        if any(not isinstance(event[key], str) or not event[key] for key in ("service", "action")):
            raise ValueError("service and action must be named")
        if "receipt" in event and (
            not isinstance(event["receipt"], str) or not event["receipt"]
        ):
            raise ValueError("receipt marker must be textual")
        result.append((event["service"], event["slot"], event["action"], event.get("receipt")))
    return tuple(result)


def audit_recipient_log(
    expected: Sequence[Mapping[str, object]], received: Sequence[Mapping[str, object]]
) -> LogAudit:
    try:
        left, right = _projection(expected), _projection(received)
    except ValueError:
        return LogAudit.INVALID
    if left == right:
        return LogAudit.MATCH
    expected_counts, received_counts = Counter(left), Counter(right)
    if expected_counts == received_counts:
        return LogAudit.REORDERED
    if received_counts < expected_counts:
        return LogAudit.MISSING
    if expected_counts < received_counts:
        return LogAudit.EXTRA
    return LogAudit.DIVERGED
