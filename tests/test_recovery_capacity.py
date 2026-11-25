from noticer_core.recovery_capacity import PublicDelivery, PublicRequest, schedule_shared_lane


def test_shared_capacity_separates_services_with_different_deadlines() -> None:
    later = PublicRequest("a", 0, 2)
    urgent = PublicRequest("b", 0, 0)
    result = schedule_shared_lane([later, urgent], (True, False, True))
    assert result.delivered == (PublicDelivery("b", 0), PublicDelivery("a", 2))
    assert not result.deadline_misses


def test_overlapping_urgent_actions_are_not_both_delivered_on_one_lane() -> None:
    requests = [PublicRequest("a", 0, 0), PublicRequest("b", 0, 0)]
    result = schedule_shared_lane(requests, (True,))
    assert result.delivered == (PublicDelivery("a", 0),)
    assert result.deadline_misses == ("b",)
