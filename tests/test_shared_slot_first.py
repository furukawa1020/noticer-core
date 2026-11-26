import pytest

from noticer_core.shared_slot_branch import crossed_public_futures
from noticer_core.shared_slot_contract import SharedSlotCase
from noticer_core.shared_slot_first import verify_public_futures


def test_foresight_requires_opposite_first_actions():
    left, right = crossed_public_futures()
    evidence = verify_public_futures(left, right)
    assert evidence.left == {"b"}
    assert evidence.right == {"a"}
    assert evidence.have_no_common_choice
    assert not verify_public_futures(left, left).have_no_common_choice


def test_infeasible_tape_is_not_a_foresight_separation():
    left, right = crossed_public_futures()
    evidence = verify_public_futures(left, SharedSlotCase((1, 0), right.actions))
    assert evidence.right == set()
    assert not evidence.have_no_common_choice


def test_incompatible_prefix_and_budget_never_return_evidence():
    left, right = crossed_public_futures()
    with pytest.raises(ValueError, match="initial views"):
        verify_public_futures(left, SharedSlotCase((2, 1), right.actions))
    with pytest.raises(OverflowError, match="budget"):
        verify_public_futures(left, right, max_candidates=3)
