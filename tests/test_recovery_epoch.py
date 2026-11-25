import pytest

from noticer_core.recovery_delivery import DeliveryPhase, DeliveryState
from noticer_core.recovery_epoch import PublicEpochDelivery


def test_closed_epoch_does_not_contribute_to_the_new_action() -> None:
    pending = PublicEpochDelivery(3, DeliveryState("notify").send())
    done, _ = pending.receive(3, "notify")
    advanced = done.begin_next(4, "notify")
    assert advanced.state.phase is DeliveryPhase.PENDING
    with pytest.raises(ValueError, match="active public epoch"):
        advanced.receive(3, "notify")


def test_unacknowledged_delivery_requires_explicit_recovery() -> None:
    pending = PublicEpochDelivery(3, DeliveryState("notify").send())
    with pytest.raises(ValueError, match="explicit recovery"):
        pending.begin_next(4, "notify")
