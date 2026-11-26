from fractions import Fraction

from noticer_core.slot_mix_fixtures import last_slot_game
from noticer_core.slot_mix_solve import solve_mix


def test_three_compatible_in_pairs_but_not_all_yield_two_thirds():
    result = solve_mix(last_slot_game(3, (0b011, 0b101, 0b110)))
    assert len(result.frontier) == 3 and {item.mask.bit_count() for item in result.frontier} == {2}
    assert result.certificate is not None and result.certificate.value == Fraction(2, 3)
