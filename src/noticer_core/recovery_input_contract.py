"""Identify normal, recovered and out-of-contract public availability tapes."""

from dataclasses import dataclass
from enum import StrEnum


class TapeClass(StrEnum):
    NORMAL = "normal"
    RECOVERED = "recovered"
    OUT_OF_SCOPE = "out-of-scope"


@dataclass(frozen=True, slots=True)
class PublicRecoveryTape:
    classification: TapeClass
    deadline: int | None


def classify_two_slot_tape(opportunities: tuple[bool, ...]) -> PublicRecoveryTape:
    """Classify the fixture's first-loss-only contract, before inspecting any history."""
    if len(opportunities) != 2 or any(type(item) is not bool for item in opportunities):
        raise ValueError("expected two public availability booleans")
    first, last = opportunities
    if not last:
        return PublicRecoveryTape(TapeClass.OUT_OF_SCOPE, None)
    if first:
        return PublicRecoveryTape(TapeClass.NORMAL, 0)
    return PublicRecoveryTape(TapeClass.RECOVERED, 1)
