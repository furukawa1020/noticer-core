"""Independent check for a finite capacitated Hall deficit."""

from dataclasses import dataclass

from noticer_core.shared_slot_contract import SharedSlotCase


@dataclass(frozen=True)
class HallCut:
    """A nonempty action subset and its exact, capacity-deficient neighborhood."""

    actions: tuple[str, ...]
    slots: tuple[int, ...]


def verify_hall_cut(case: SharedSlotCase, cut: HallCut) -> bool:
    """Recompute the union and capacity; trust no solver state."""
    actions = {action.name: action for action in case.actions}
    if (
        type(cut.actions) is not tuple
        or not cut.actions
        or any(type(name) is not str or name not in actions for name in cut.actions)
        or cut.actions != tuple(sorted(set(cut.actions)))
        or type(cut.slots) is not tuple
        or any(type(slot) is not int for slot in cut.slots)
    ):
        return False
    neighborhood = tuple(sorted({slot for name in cut.actions for slot in actions[name].slots}))
    return cut.slots == neighborhood and sum(case.capacities[s] for s in neighborhood) < len(
        cut.actions
    )
