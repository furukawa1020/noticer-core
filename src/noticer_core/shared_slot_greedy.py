"""Causal, work-conserving earliest-deadline reference for unit actions."""

from noticer_core.shared_slot_contract import SharedSlotCase
from noticer_core.shared_slot_verify import Placement


def deadline_first(case: SharedSlotCase) -> tuple[Placement, ...]:
    """Use only current eligibility and immutable public deadlines."""
    remaining = {action.name: action for action in case.actions}
    placements: list[Placement] = []
    for slot, capacity in enumerate(case.capacities):
        eligible = sorted(
            (action for action in remaining.values() if slot in action.slots),
            key=lambda action: (action.deadline, action.name),
        )
        for action in eligible[:capacity]:
            placements.append((action.name, slot))
            del remaining[action.name]
    return tuple(sorted(placements))
