"""Read small schedule laws using canonical rational tokens."""

from typing import Any

from noticer_core.receipt_limit_distribution import PlanLaw
from noticer_core.slot_mix_json import exact_members
from noticer_core.slot_mix_rational import decode_probability


def decode_law(raw: Any) -> PlanLaw:
    """Check tuple shape, integers, and bounded support before semantic replay."""
    if type(raw) is not list or not 1 <= len(raw) <= 16:
        raise ValueError("invalid law support")
    law = []
    for entry in raw:
        entry = exact_members(entry, {"plan", "mass"})
        plan = entry["plan"]
        if type(plan) is not list or len(plan) > 5 or any(
            type(item) is not list or len(item) != 2 or type(item[0]) is not str
            or len(item[0]) > 64 or type(item[1]) is not int
            for item in plan
        ):
            raise ValueError("invalid receipt placement")
        law.append((tuple((item[0], item[1]) for item in plan), decode_probability(entry["mass"])))
    return tuple(law)
