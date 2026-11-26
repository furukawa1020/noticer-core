from fractions import Fraction

from noticer_core.shared_slot_branch import crossed_public_futures
from noticer_core.shared_slot_causal import binary_minimax
from noticer_core.shared_slot_first import FirstChoiceEvidence, verify_public_futures


def test_fair_coin_attains_the_binary_oblivious_upper_bound():
    evidence = verify_public_futures(*crossed_public_futures())
    result = binary_minimax(evidence)
    assert result.deterministic == 0
    assert result.randomized == Fraction(1, 2)
    for winning in (evidence.left, evidence.right):
        assert sum(weight for first, weight in result.policy if first in winning) == Fraction(1, 2)


def test_common_wait_is_valid_and_an_impossible_tape_cannot_succeed():
    common = binary_minimax(FirstChoiceEvidence(frozenset({None}), frozenset({"a", None})))
    assert common.deterministic == common.randomized == 1
    assert common.policy == ((None, Fraction(1)),)
    assert binary_minimax(FirstChoiceEvidence(frozenset({"a"}), frozenset())).randomized == 0
