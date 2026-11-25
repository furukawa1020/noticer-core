from fractions import Fraction

from noticer_core.recovery_tv import observer_variation


def test_equal_marginals_do_not_imply_equal_joint_distributions() -> None:
    result = observer_variation([(0, 0), (1, 1)], [(0, 1), (1, 0)])
    assert result.marginals == (0, 0)
    assert result.joint == 1


def test_exact_fractions_allow_different_finite_support_sizes() -> None:
    assert observer_variation([(0,), (1,), (1,)], [(0,), (1,)]).joint == Fraction(1, 6)
