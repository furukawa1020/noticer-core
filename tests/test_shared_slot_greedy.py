from noticer_core.shared_slot_contract import SharedAction, SharedSlotCase
from noticer_core.shared_slot_greedy import deadline_first
from noticer_core.shared_slot_verify import verify_assignment


def test_greedy_is_work_conserving_and_ignores_unavailable_actions():
    case = SharedSlotCase(
        (0, 2, 1),
        (
            SharedAction("a", 2, (0, 1, 2)),
            SharedAction("b", 1, (1,)),
            SharedAction("c", 1, (1,)),
        ),
    )
    placements = deadline_first(case)
    assert placements == (("a", 2), ("b", 1), ("c", 1))
    assert verify_assignment(case, placements)
