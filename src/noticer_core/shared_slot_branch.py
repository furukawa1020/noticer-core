"""A public prefix with two possible future receiver-availability tapes."""

from noticer_core.shared_slot_contract import SharedSlotCase
from noticer_core.shared_slot_public import PublicDemand, project_public_tape


def public_first_view(case: SharedSlotCase) -> tuple[int, tuple[tuple[str, int, bool], ...]]:
    """Expose only slot zero and common demand/deadline metadata."""
    return case.capacities[0], tuple(
        sorted((action.name, action.deadline, 0 in action.slots) for action in case.actions)
    )


def crossed_public_futures() -> tuple[SharedSlotCase, SharedSlotCase]:
    """Only A or only B will be available later; the first view is identical."""
    both = frozenset({"left", "right"})
    demands = (PublicDemand("a", "left", 1), PublicDemand("b", "right", 1))
    left = project_public_tape((1, 1), (both, frozenset({"left"})), demands)
    right = project_public_tape((1, 1), (both, frozenset({"right"})), demands)
    return left, right
