import pytest

from noticer_core.recovery_delivery import DeliveryState
from noticer_core.recovery_receipt_deadline import ReceiptWindow


def test_late_receipt_cannot_commit_an_effect_after_a_retry() -> None:
    record = ReceiptWindow(DeliveryState("notify").send().send(), first_slot=1, deadline=2)
    with pytest.raises(ValueError, match="outside"):
        record.receive(3, "notify")
    updated, committed = record.receive(2, "notify")
    assert committed
    assert updated.receive(2, "notify") == (updated, False)
