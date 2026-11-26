from noticer_core.shared_slot_contract import SharedAction, SharedSlotCase
from noticer_core.shared_slot_hall import HallCut
from noticer_core.shared_slot_solve import solve_shared_slots


def test_augmenting_path_reassigns_flexible_action():
    case = SharedSlotCase((1, 1), (SharedAction("a", 1, (0, 1)), SharedAction("b", 1, (0,))))
    reverse = SharedSlotCase(case.capacities, case.actions[::-1])
    solution = solve_shared_slots(case)
    assert solution.placements == (("a", 1), ("b", 0))
    assert solution.deficit is None
    assert solve_shared_slots(reverse) == solution


def test_congested_receivers_create_subset_deficit_not_global_deficit():
    case = SharedSlotCase(
        (1, 0, 3), (SharedAction("a", 1, (0, 1)), SharedAction("b", 1, (0, 1)))
    )
    result = solve_shared_slots(case)
    assert len(result.placements) == 1
    assert result.deficit == HallCut(("a", "b"), (0, 1))
