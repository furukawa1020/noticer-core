import pytest

from noticer_core.receipt_limit_contract import ReceiptProblem
from noticer_core.shared_slot_contract import SharedAction, SharedSlotCase


def test_exact_action_contract_and_capacity_are_public():
    left = SharedSlotCase((1, 1), (SharedAction("a", 1, (0,)),))
    right = SharedSlotCase((1, 1), (SharedAction("a", 1, (1,)),))
    assert ReceiptProblem((left, right), (("a", "clinic"),)).worlds == (left, right)
    with pytest.raises(ValueError, match="public"):
        ReceiptProblem((left, SharedSlotCase((1, 0), right.actions)), (("a", "clinic"),))
    with pytest.raises(ValueError, match="recipient"):
        ReceiptProblem((left, right), ())
