from itertools import product

from noticer_core.shared_slot_contract import SharedAction, SharedSlotCase
from noticer_core.shared_slot_hall import verify_hall_cut
from noticer_core.shared_slot_solve import solve_shared_slots
from noticer_core.shared_slot_verify import verify_assignment


def maximum_by_enumeration(case: SharedSlotCase) -> int:
    best = 0
    options = [(-1, *action.slots) for action in case.actions]
    for candidate in product(*options):
        if all(candidate.count(slot) <= limit for slot, limit in enumerate(case.capacities)):
            best = max(best, sum(slot >= 0 for slot in candidate))
    return best


def test_exact_matching_against_every_three_action_three_slot_graph():
    masks = [tuple(slot for slot in range(3) if mask & (1 << slot)) for mask in range(8)]
    for capacities in ((1, 1, 1), (0, 2, 1), (2, 0, 0)):
        for eligibility in product(masks, repeat=3):
            case = SharedSlotCase(
                capacities,
                tuple(
                    SharedAction(name, 2, slots)
                    for name, slots in zip(("a", "b", "c"), eligibility, strict=True)
                ),
            )
            result = solve_shared_slots(case)
            assert len(result.placements) == maximum_by_enumeration(case)
            if result.deficit is None:
                assert verify_assignment(case, result.placements)
            else:
                assert verify_hall_cut(case, result.deficit)
