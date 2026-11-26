import pytest

from noticer_core.shared_slot_contract import SharedAction, SharedSlotCase
from noticer_core.shared_slot_reservations import reservation_counts, verify_reservation_shape


def test_reservation_is_checked_against_real_packets_and_public_capacity():
    case = SharedSlotCase((1, 2), (SharedAction("a", 1, (0, 1)),))
    placements = (("a", 1),)
    assert reservation_counts(case, placements) == (0, 1)
    assert verify_reservation_shape(case, placements, (1, 2))
    assert not verify_reservation_shape(case, placements, (2, 2))
    assert not verify_reservation_shape(case, placements, (1, 0))
    assert not verify_reservation_shape(case, placements, (1, True))
    with pytest.raises(ValueError, match="complete"):
        reservation_counts(case, ())
