import pytest

from noticer_core.shared_slot_examples import no_contention_case
from noticer_core.shared_slot_local import replay_local_receipts
from noticer_core.shared_slot_receipts import receipts_for_assignment
from noticer_core.shared_slot_solve import solve_shared_slots
from noticer_core.shared_slot_views import PublicReceipt


def test_local_replay_preserves_both_decoded_receipts():
    case = no_contention_case()
    receipt = receipts_for_assignment(
        case, solve_shared_slots(case).placements, {"a": "first", "b": "second"}
    )
    assert replay_local_receipts(receipt) == receipt
    assert replay_local_receipts(()) == ()


def test_local_replay_refuses_non_demo_payload_size():
    with pytest.raises(ValueError, match="too large"):
        replay_local_receipts((PublicReceipt(0, "a" * 600, "b"),))
