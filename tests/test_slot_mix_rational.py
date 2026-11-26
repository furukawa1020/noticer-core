from fractions import Fraction

import pytest

from noticer_core.slot_mix_rational import decode_probability


@pytest.mark.parametrize("bad", [True, 1, "1.0", "01", "2/4", "1/0", "2", "1/01", "9" * 100])
def test_only_canonical_bounded_fractions_are_accepted(bad):
    with pytest.raises(ValueError):
        decode_probability(bad)


def test_fraction_is_not_treated_as_a_decimal():
    assert decode_probability("2/5") == Fraction(2, 5)
