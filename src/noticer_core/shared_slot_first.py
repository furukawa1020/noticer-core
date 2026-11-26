"""Exhaustive verifier for feasible first decisions on small public tapes."""

from dataclasses import dataclass
from itertools import product
from math import prod

from noticer_core.shared_slot_branch import public_first_view
from noticer_core.shared_slot_contract import SharedSlotCase

FirstChoice = str | None
MAX_CANDIDATES = 50_000


@dataclass(frozen=True)
class FirstChoiceEvidence:
    """Complete feasible decision sets, one per fixed future tape."""

    left: frozenset[FirstChoice]
    right: frozenset[FirstChoice]

    @property
    def have_no_common_choice(self) -> bool:
        """Both tapes individually work, but the first decision must differ."""
        return bool(self.left and self.right and self.left.isdisjoint(self.right))


def candidate_count(case: SharedSlotCase) -> int:
    """Cartesian search bound including candidates rejected for capacity."""
    return prod(len(action.slots) for action in case.actions)


def _feasible_first_choices(case: SharedSlotCase) -> frozenset[FirstChoice]:
    choices: set[FirstChoice] = set()
    for slots in product(*(action.slots for action in case.actions)):
        if all(slots.count(slot) <= capacity for slot, capacity in enumerate(case.capacities)):
            choices.add(case.actions[slots.index(0)].name if 0 in slots else None)
    return frozenset(choices)


def verify_public_futures(
    left: SharedSlotCase,
    right: SharedSlotCase,
    *,
    max_candidates: int = MAX_CANDIDATES,
) -> FirstChoiceEvidence:
    """Independently enumerate all allocations; never treat cutoff as evidence."""
    if public_first_view(left) != public_first_view(right) or left.capacities[0] != 1:
        raise ValueError("expected equal initial views with one immediate opportunity")
    if type(max_candidates) is not int or not 0 < max_candidates <= MAX_CANDIDATES:
        raise ValueError("invalid enumeration budget")
    if candidate_count(left) + candidate_count(right) > max_candidates:
        raise OverflowError("first-choice enumeration budget exceeded")
    return FirstChoiceEvidence(_feasible_first_choices(left), _feasible_first_choices(right))
