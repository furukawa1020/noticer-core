"""Check an allocation without importing the solver."""

from collections import Counter

from noticer_core.shared_slot_contract import SharedSlotCase

Placement = tuple[str, int]


def verify_assignment(
    case: SharedSlotCase,
    placements: tuple[Placement, ...],
    *,
    complete: bool = True,
) -> bool:
    """Reject unknown actions, duplicates, invalid slots, and excess capacity."""
    actions = {action.name: action for action in case.actions}
    assigned: set[str] = set()
    usage: Counter[int] = Counter()
    if type(placements) is not tuple:
        return False
    for placement in placements:
        if type(placement) is not tuple or len(placement) != 2:
            return False
        name, slot = placement
        if type(name) is not str or name not in actions or name in assigned:
            return False
        action = actions[name]
        if type(slot) is not int or slot not in action.slots or slot > action.deadline:
            return False
        assigned.add(name)
        usage[slot] += 1
        if usage[slot] > case.capacities[slot]:
            return False
    return not complete or assigned == actions.keys()
