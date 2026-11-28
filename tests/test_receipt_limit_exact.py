from fractions import Fraction

from noticer_core.receipt_limit_exact import exact_pair_law


def test_opposite_partial_successes_make_a_mixed_private_law():
    a = (("a", 0),)
    b = (("a", 1),)
    early, late = ((0, "one", "a"),), ((1, "one", "a"),)
    value, law = exact_pair_law(
        {early: {True: a}, late: {False: b}}, {early: {False: a}, late: {True: b}}
    )
    assert value == Fraction(1, 2)
    assert len(law) == 2
