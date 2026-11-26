import pytest

from noticer_core.shared_slot_contract import SharedAction, SharedSlotCase
from noticer_core.shared_slot_receipts import same_joint_receipts


def test_different_valid_allocations_can_disagree_in_joint_receipts():
    case = SharedSlotCase(
        (1, 1), (SharedAction("a", 1, (0, 1)), SharedAction("b", 1, (0, 1)))
    )
    left, right = (("a", 0), ("b", 1)), (("a", 1), ("b", 0))
    receivers = {"a": "left", "b": "right"}
    assert same_joint_receipts(case, left, left[::-1], receivers)
    assert not same_joint_receipts(case, left, right, receivers)
    with pytest.raises(ValueError, match="inconsistent"):
        same_joint_receipts(case, left, right, {"a": "left"})
