from fractions import Fraction

import pytest

from noticer_core.shared_slot_cost import measure_shared_slot_cost
from noticer_core.shared_slot_examples import deadline_gap_case


def test_mean_delay_and_bytes_are_not_a_reliability_proxy():
    case = deadline_gap_case()
    sizes = {"a": 5, "b": 7, "c": 11}
    cost = measure_shared_slot_cost(case, (("b", 2), ("a", 0)), sizes)
    assert (cost.delivered, cost.required) == (2, 3)
    assert cost.application_bytes == 12
    assert cost.mean_logical_slots == Fraction(1)
    assert measure_shared_slot_cost(case, (), sizes).mean_logical_slots is None
    with pytest.raises(ValueError, match="byte"):
        measure_shared_slot_cost(case, (), {"a": 5, "b": 7, "c": False})
