import pytest

from noticer_core.shared_slot_public import PublicDemand, project_public_tape


def test_projection_keeps_receiver_qualification_and_inclusive_deadline():
    case = project_public_tape(
        (1, 0, 1),
        (frozenset({"one", "two"}), frozenset({"two"}), frozenset({"one"})),
        (PublicDemand("a", "one", 1), PublicDemand("b", "two", 2)),
    )
    assert case.actions[0].slots == (0,)
    assert case.actions[1].slots == (0, 1)
    assert case.capacities[1] == 0


def test_partial_public_tape_is_not_an_infeasibility_result():
    with pytest.raises(ValueError, match="horizon"):
        project_public_tape((1,), (), ())
