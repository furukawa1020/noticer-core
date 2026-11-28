import pytest

from noticer_core.receipt_limit_schedule import schedule_success
from noticer_core.shared_slot_contract import SharedAction, SharedSlotCase


def test_silence_is_a_valid_failure_but_deadline_violation_is_not_a_plan():
    world = SharedSlotCase((1, 1), (SharedAction("a", 0, (0,)),))
    assert not schedule_success(world, ())
    assert schedule_success(world, (("a", 0),))
    with pytest.raises(ValueError):
        schedule_success(world, (("a", 1),))
