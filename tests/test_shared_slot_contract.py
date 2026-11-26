import pytest

from noticer_core.shared_slot_contract import SharedAction, SharedSlotCase


def test_empty_demand_and_unreachable_receiver_are_valid():
    assert SharedSlotCase((0,), ()).actions == ()
    action = SharedAction("svc-a", 0, ())
    assert SharedSlotCase((1,), (action,)).actions == (action,)


@pytest.mark.parametrize(
    ("capacities", "actions"),
    [
        ((True,), ()),
        ((129,), ()),
        ((), ()),
        ((1,), (SharedAction("private label", 0, (0,)),)),
        ((1,), (SharedAction("a", 0, (False,)),)),
        ((1, 1), (SharedAction("a", 0, (1,)),)),
        ((1,), (SharedAction("a", 0, (0, 0)),)),
        ((1,), (SharedAction("a", 0, ()), SharedAction("a", 0, ()))),
    ],
)
def test_malformed_input_does_not_become_capacity_infeasibility(capacities, actions):
    with pytest.raises(ValueError):
        SharedSlotCase(capacities, actions)
