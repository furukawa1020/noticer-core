from noticer_core.shared_slot_contract import SharedAction, SharedSlotCase
from noticer_core.shared_slot_verify import verify_assignment


def test_assignment_checks_capacity_deadline_and_coverage():
    case = SharedSlotCase((1, 1), (SharedAction("a", 0, (0,)), SharedAction("b", 1, (0, 1))))
    assert verify_assignment(case, (("b", 1), ("a", 0)))
    assert not verify_assignment(case, (("b", 0), ("a", 0)))
    assert not verify_assignment(case, (("a", 1), ("b", 0)))
    assert not verify_assignment(case, (("a", True), ("b", 0)))
    assert not verify_assignment(case, (("a", 0), ("a", 0)), complete=False)
    assert not verify_assignment(case, (("c", 0),), complete=False)
    assert not verify_assignment(case, (("a", 0),))
    assert verify_assignment(case, (("a", 0),), complete=False)
