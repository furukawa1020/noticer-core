"""Non-inferiority decision for an action-utility confidence interval."""

from math import isfinite
from typing import Literal

UtilityVerdict = Literal["noninferior", "inferior", "inconclusive", "action-mismatch"]


def assess_utility(
    interval: tuple[float, float] | None, *, margin: float, semantics_match: bool
) -> UtilityVerdict:
    """Use treatment minus baseline with the utility oriented higher-is-better."""
    if not isfinite(margin) or margin <= 0 or type(semantics_match) is not bool:
        raise ValueError("a positive finite margin and explicit semantics verdict are required")
    if interval is not None:
        lower, upper = interval
        if not isfinite(lower) or not isfinite(upper) or lower > upper:
            raise ValueError("invalid utility confidence interval")
    if not semantics_match:
        return "action-mismatch"
    if interval is None:
        return "inconclusive"
    if lower > -margin:
        return "noninferior"
    if upper < -margin:
        return "inferior"
    return "inconclusive"
