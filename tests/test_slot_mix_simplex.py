from fractions import Fraction

import pytest

from noticer_core.slot_mix_frontier import MixLimit
from noticer_core.slot_mix_simplex import pack_fractionally


def test_asymmetric_packing_matches_manual_primal_and_dual():
    result = pack_fractionally((3, 5, 6, 8), 4, 100)
    assert result.objective == Fraction(5, 2)
    assert result.tape_weights == result.policy_weights == (
        Fraction(1, 2), Fraction(1, 2), Fraction(1, 2), Fraction(1)
    )


def test_cutoff_and_unbounded_packing_are_not_optimal():
    with pytest.raises(MixLimit):
        pack_fractionally((1, 2), 2, 1)
    with pytest.raises(ValueError, match="uncovered"):
        pack_fractionally((1,), 2, 100)
