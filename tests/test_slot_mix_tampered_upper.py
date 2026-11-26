from dataclasses import replace
from fractions import Fraction

from noticer_core.slot_mix_certificate import verify_mix
from noticer_core.slot_mix_fixtures import asymmetric_game
from noticer_core.slot_mix_frontier import WorkBudget
from noticer_core.slot_mix_solve import solve_mix


def test_adversarial_mass_can_be_a_distribution_without_certifying_the_claim():
    game = asymmetric_game()
    certificate = solve_mix(game).certificate
    assert certificate is not None and certificate.value == Fraction(2, 5)
    uniform = replace(certificate, tape_weights=(Fraction(1, 4),) * 4)
    assert not verify_mix(game, uniform, WorkBudget(1000))
