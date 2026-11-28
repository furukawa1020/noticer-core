from fractions import Fraction

from noticer_core.receipt_limit_relax import construct_laws


def test_relaxation_interpolates_utility():
    a, b = (("a", 0),), (("a", 1),)
    early, late = ((0, "one", "a"),), ((1, "one", "a"),)
    value, laws = construct_laws(
        {early: {True: a}, late: {False: b}},
        {early: {False: a}, late: {True: b}},
        Fraction(1, 4),
    )
    assert value == Fraction(5, 8)
    assert sum(mass for _, mass in laws[0]) == sum(mass for _, mass in laws[1]) == 1
