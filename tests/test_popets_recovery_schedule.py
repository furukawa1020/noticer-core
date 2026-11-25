from itertools import product

import pytest

from noticer_core.recovery_schedule import (
    OutOfScopeTape,
    ScheduleMode,
    ServiceWindow,
    compile_public_plan,
)

LANES = ((True, True, True), (False, True, True), (True, False, True), (True, True, False))


def test_joint_receipts_are_readiness_independent_on_every_admissible_tape() -> None:
    plan = compile_public_plan(
        (ServiceWindow("a", 3, 5, 1), ServiceWindow("b", 3, 5, 1)), frame_bytes=256
    )
    for a, b in product(LANES, repeat=2):
        tape = {"a": a, "b": b}
        for mode in ScheduleMode:
            early = plan.replay({"a": 0, "b": 1}, tape, mode=mode)
            late = plan.replay({"a": 2, "b": 2}, tape, mode=mode)
            assert early == late
            if mode is not ScheduleMode.DEADLINE_WAIT:
                assert len(early.receipts) == 2
                assert not early.missed


def test_fixed_envelope_hides_action_presence_only_in_wire_shape() -> None:
    plan = compile_public_plan((ServiceWindow("a", 3, 5, 1),), frame_bytes=256)
    tape = {"a": (False, True, True)}
    for mode in (ScheduleMode.NETWORK_ENVELOPE, ScheduleMode.FIXED_RATE):
        action = plan.replay({"a": 1}, tape, mode=mode)
        idle = plan.replay({}, tape, mode=mode)
        assert action.receipts != idle.receipts and action.frames == idle.frames
    receiver_only = plan.replay({"a": 1}, tape, mode=ScheduleMode.RECIPIENT_ONLY)
    assert receiver_only.cover_frames == 0
    idle = plan.replay({}, tape, mode=ScheduleMode.RECIPIENT_ONLY)
    assert receiver_only.frames != idle.frames


def test_deadline_wait_misses_but_normalized_schedule_has_slack() -> None:
    plan = compile_public_plan((ServiceWindow("a", 3, 5, 1),), frame_bytes=256)
    tape = {"a": (True, True, False)}
    assert plan.replay({"a": 1}, tape, mode=ScheduleMode.DEADLINE_WAIT).missed == ("a",)
    assert not plan.replay({"a": 1}, tape, mode=ScheduleMode.RECIPIENT_ONLY).missed


def test_late_admission_and_faults_outside_the_contract_are_rejected() -> None:
    plan = compile_public_plan((ServiceWindow("a", 3, 5, 1),), frame_bytes=256)
    with pytest.raises(OutOfScopeTape):
        plan.replay({"a": 0}, {"a": (False, False, True)}, mode=ScheduleMode.RECIPIENT_ONLY)
    with pytest.raises(ValueError, match="not admitted"):
        plan.replay({"a": 3}, {"a": (True, True, True)}, mode=ScheduleMode.RECIPIENT_ONLY)
