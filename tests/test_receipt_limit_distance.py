from fractions import Fraction

from noticer_core.receipt_limit_distance import total_variation


def test_variation_includes_silent_and_unmatched_events():
    one = Fraction(1)
    half = Fraction(1, 2)
    trace = ((1, "clinic", "a"),)
    assert total_variation({(): one}, {(): half, trace: half}) == half
