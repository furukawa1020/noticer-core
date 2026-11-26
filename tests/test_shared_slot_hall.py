from noticer_core.shared_slot_contract import SharedAction, SharedSlotCase
from noticer_core.shared_slot_hall import HallCut, verify_hall_cut


def test_deficit_checks_every_neighbor_and_counts_shared_capacity():
    case = SharedSlotCase(
        (1, 0, 2),
        (SharedAction("a", 1, (0, 1)), SharedAction("b", 1, (0,)), SharedAction("c", 2, (2,))),
    )
    assert verify_hall_cut(case, HallCut(("a", "b"), (0, 1)))
    assert not verify_hall_cut(case, HallCut(("a", "b"), (0,)))
    assert not verify_hall_cut(case, HallCut(("a", "b"), (False, 1)))
    assert not verify_hall_cut(case, HallCut(("a", "a"), (0, 1)))
    assert not verify_hall_cut(case, HallCut(("c",), (2,)))


def test_unreachable_receiver_has_empty_neighborhood():
    case = SharedSlotCase((1,), (SharedAction("a", 0, ()),))
    assert verify_hall_cut(case, HallCut(("a",), ()))
