from fractions import Fraction

import pytest

from noticer_core.slot_mix_probability import is_distribution, success_profile


def test_profile_preserves_exact_ties_and_checks_arity():
    half = Fraction(1, 2)
    assert success_profile((1, 3), (half, half), 2) == (1, half)
    assert not is_distribution((0.5, 0.5), 2)
    assert not is_distribution((1,), 1)
    with pytest.raises(ValueError):
        success_profile((4,), (Fraction(1),), 2)
