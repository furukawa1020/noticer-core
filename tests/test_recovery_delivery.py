import pytest

from noticer_core.recovery_delivery import DeliveryPhase, DeliveryState


def test_retries_do_not_commit_an_effect_until_the_receipt_arrives() -> None:
    active = DeliveryState("notify").send().send()
    assert active.phase is DeliveryPhase.AWAITING_RECEIPT and active.attempts == 2
    done, commit = active.receive("notify")
    assert commit and done.phase is DeliveryPhase.COMMITTED
    assert done.receive("notify") == (done, False)
    with pytest.raises(ValueError, match="already committed"):
        done.send()


def test_spurious_or_premature_receipts_are_rejected() -> None:
    with pytest.raises(ValueError, match="unsent"):
        DeliveryState("notify").receive("notify")
    with pytest.raises(ValueError, match="different"):
        DeliveryState("notify").send().receive("other")
