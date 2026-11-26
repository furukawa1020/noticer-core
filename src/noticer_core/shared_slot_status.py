"""Preserve invalid and inconclusive outcomes at the evaluation boundary."""

from dataclasses import dataclass
from typing import Literal

from noticer_core.shared_slot_contract import SharedSlotCase
from noticer_core.shared_slot_first import (
    MAX_CANDIDATES,
    FirstChoiceEvidence,
    verify_public_futures,
)


@dataclass(frozen=True)
class FirstChoiceAudit:
    """Only a completed enumeration can carry verified evidence."""

    status: Literal["verified", "invalid", "inconclusive"]
    evidence: FirstChoiceEvidence | None
    reason: str | None = None


def audit_public_futures(
    left: SharedSlotCase,
    right: SharedSlotCase,
    *,
    max_candidates: int = MAX_CANDIDATES,
) -> FirstChoiceAudit:
    """An invalid prefix or search cutoff is never a verified separation."""
    try:
        evidence = verify_public_futures(left, right, max_candidates=max_candidates)
    except ValueError as error:
        return FirstChoiceAudit("invalid", None, str(error))
    except OverflowError as error:
        return FirstChoiceAudit("inconclusive", None, str(error))
    return FirstChoiceAudit("verified", evidence)
