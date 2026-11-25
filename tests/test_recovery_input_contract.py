import pytest

from noticer_core.recovery_input_contract import TapeClass, classify_two_slot_tape


def test_public_availability_selects_a_deadline_without_private_inputs() -> None:
    assert classify_two_slot_tape((True, True)).deadline == 0
    assert classify_two_slot_tape((False, True)).deadline == 1


@pytest.mark.parametrize("tape", [(True, False), (False, False)])
def test_absent_final_opportunity_is_not_counted_as_a_success(tape: tuple[bool, ...]) -> None:
    result = classify_two_slot_tape(tape)
    assert result.classification is TapeClass.OUT_OF_SCOPE
    assert result.deadline is None
