import pytest

from noticer_core.receipt_limit_enumerate import ReceiptCutoff, enumerate_schedules
from noticer_core.shared_slot_contract import SharedAction, SharedSlotCase


def test_enumeration_keeps_empty_and_partial_but_not_capacity_violations():
    tape = SharedSlotCase((1,), (SharedAction("a", 0, (0,)), SharedAction("b", 0, (0,))))
    assert set(enumerate_schedules(tape)) == {(), (("a", 0),), (("b", 0),)}
    with pytest.raises(ReceiptCutoff):
        tuple(enumerate_schedules(tape, max_steps=1))
