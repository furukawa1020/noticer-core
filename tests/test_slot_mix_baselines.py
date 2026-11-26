from fractions import Fraction

from noticer_core.slot_mix_baselines import iterative_profile, uniform_success


def test_stronger_iterative_baseline_is_not_uniform_on_asymmetric_incidence():
    masks = (3, 5, 6, 8)
    assert uniform_success(masks, 4) == Fraction(1, 4)
    actual = min(iterative_profile(masks, 4))
    assert Fraction(1, 4) < actual <= Fraction(2, 5)
