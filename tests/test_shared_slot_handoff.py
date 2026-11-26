from noticer_core.shared_slot_greedy import deadline_first
from noticer_core.shared_slot_handoff import handoff_case
from noticer_core.shared_slot_solve import solve_shared_slots


def test_receiver_handoff_matters_even_with_two_places_in_the_first_slot():
    case = handoff_case()
    assert len(deadline_first(case)) == 3
    result = solve_shared_slots(case)
    assert result.deficit is None
    assert ("early", 1) in result.placements
    assert len(result.placements) == 4
