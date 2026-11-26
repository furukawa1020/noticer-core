from fractions import Fraction

from noticer_core.shared_slot_branch import crossed_public_futures
from noticer_core.shared_slot_game import PublicSlotGame
from noticer_core.slot_mix_certificate import MixCertificate, verify_mix
from noticer_core.slot_mix_contract import SlotMixGame
from noticer_core.slot_mix_frontier import WorkBudget, build_frontier


def test_exact_value_requires_matching_lower_and_upper_evidence():
    game = SlotMixGame(PublicSlotGame(crossed_public_futures()))
    candidates = build_frontier(game, WorkBudget(1000))
    half = Fraction(1, 2)
    certificate = MixCertificate(candidates, (half, half), (half, half), half)
    assert verify_mix(game, certificate, WorkBudget(1000))
