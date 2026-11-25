import pytest

from noticer_core.evaluation.k20_chance import assess_chance
from noticer_core.evaluation.k21_sample_size import plan_independent_units


def test_planned_minimum_crosses_the_fixture_precision_boundary() -> None:
    n = plan_independent_units(margin=0.1, expected_distance=0, alpha=0.05)
    assert n == 185
    full = {str(index): 0.5 for index in range(n)}
    assert assess_chance(full, chance=0.5, margin=0.1).verdict == "chance-equivalent"
    full.pop("0")
    assert assess_chance(full, chance=0.5, margin=0.1).verdict == "inconclusive"


def test_no_finite_precision_plan_when_distance_is_the_margin() -> None:
    with pytest.raises(ValueError, match="below"):
        plan_independent_units(margin=0.1, expected_distance=0.1, alpha=0.05)
