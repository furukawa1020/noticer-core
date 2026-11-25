import pytest

from noticer_core.recovery_capacity import (
    CapacityResult,
    PublicDelivery,
    PublicRequest,
    schedule_shared_lane,
)
from noticer_core.recovery_capacity_audit import check_capacity_assignment


def test_capacity_verifier_rejects_hidden_contention_and_hidden_misses() -> None:
    requests = (PublicRequest("a", 0, 0), PublicRequest("b", 0, 0))
    tape = (True,)
    check_capacity_assignment(requests, tape, schedule_shared_lane(requests, tape))
    with pytest.raises(ValueError, match="capacity"):
        invalid = CapacityResult((PublicDelivery("a", 0), PublicDelivery("b", 0)), ())
        check_capacity_assignment(requests, tape, invalid)
    with pytest.raises(ValueError, match="remaining"):
        invalid = CapacityResult((PublicDelivery("a", 0),), ())
        check_capacity_assignment(requests, tape, invalid)
