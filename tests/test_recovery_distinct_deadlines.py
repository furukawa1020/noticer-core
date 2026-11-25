from noticer_core.recovery_schedule import (
    Receipt,
    ScheduleMode,
    ServiceWindow,
    compile_public_plan,
)


def test_later_service_does_not_relax_the_earlier_service_deadline() -> None:
    plan = compile_public_plan(
        (ServiceWindow("notify", 2, 3, 1), ServiceWindow("light", 3, 5, 1)),
        frame_bytes=256,
    )
    public_input = {"notify": (True, False), "light": (False, True, True)}
    left = {"notify": 0, "light": 1}
    right = {"notify": 1, "light": 2}
    a = plan.replay(left, public_input, mode=ScheduleMode.RECIPIENT_ONLY)
    b = plan.replay(right, public_input, mode=ScheduleMode.RECIPIENT_ONLY)
    assert a == b
    assert a.receipts == (Receipt("notify", 2), Receipt("light", 4))
    late = plan.replay(left, public_input, mode=ScheduleMode.DEADLINE_WAIT)
    assert late.missed == ("notify",)
    assert late.receipts == (Receipt("light", 5),)
