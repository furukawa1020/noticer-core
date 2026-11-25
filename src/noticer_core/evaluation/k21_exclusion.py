"""Count a preregistered exclusion ledger without exporting recording identifiers."""

from collections.abc import Mapping, Set
from dataclasses import dataclass
from enum import StrEnum


class Exclusion(StrEnum):
    NOT_CONSENTED = "not-consented"
    CONSENT_WITHDRAWN = "consent-withdrawn"
    SIGNAL_QUALITY = "signal-quality"
    MISSING_RECORDING = "missing-recording"
    INDEPENDENCE_UNCONFIRMED = "independence-unconfirmed"


@dataclass(frozen=True, slots=True)
class ExclusionSummary:
    candidates: int
    retained: int
    excluded_by_reason: tuple[tuple[Exclusion, int], ...]


def summarize_exclusions(
    ledger: Mapping[str, Exclusion | None], *, permitted: Set[Exclusion]
) -> ExclusionSummary:
    """A None value means retained; all exclusions must use permitted codes."""
    if not ledger or "" in ledger or any(not isinstance(item, Exclusion) for item in permitted):
        raise ValueError("require a nonempty inventory and typed permitted codes")
    counts = dict.fromkeys(Exclusion, 0)
    retained = 0
    for reason in ledger.values():
        if reason is None:
            retained += 1
        elif not isinstance(reason, Exclusion) or reason not in permitted:
            raise ValueError("exclusion reason was not preregistered")
        else:
            counts[reason] += 1
    return ExclusionSummary(len(ledger), retained, tuple(counts.items()))
