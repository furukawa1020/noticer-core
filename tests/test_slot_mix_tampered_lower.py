from dataclasses import replace
from fractions import Fraction

from noticer_core.slot_mix_certificate import verify_mix
from noticer_core.slot_mix_fixtures import asymmetric_game
from noticer_core.slot_mix_frontier import WorkBudget
from noticer_core.slot_mix_solve import solve_mix


def test_mixture_cannot_misreport_mask_or_hide_probability_mass():
    game = asymmetric_game()
    certificate = solve_mix(game).certificate
    assert certificate is not None
    claims = (
        replace(certificate, policy_weights=certificate.policy_weights[1:]),
        replace(certificate, policy_weights=(Fraction(),) * len(certificate.policies)),
        replace(certificate, policies=(
            replace(certificate.policies[0], mask=15), *certificate.policies[1:]
        )),
    )
    assert all(not verify_mix(game, claim, WorkBudget(1000)) for claim in claims)
