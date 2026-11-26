from noticer_core.shared_slot_examples import deadline_gap_case, no_contention_case
from noticer_core.shared_slot_greedy import deadline_first
from noticer_core.shared_slot_solve import solve_shared_slots


def test_deadline_gap_requires_no_equal_deadline_tie_at_first_decision():
    case = deadline_gap_case()
    assert case.actions[0].deadline < min(action.deadline for action in case.actions[1:])
    assert deadline_first(case) == (("a", 0), ("b", 2))
    result = solve_shared_slots(case)
    assert result.deficit is None
    assert len(result.placements) == 3


def test_no_contention_is_a_tie():
    case = no_contention_case()
    assert deadline_first(case) == solve_shared_slots(case).placements
