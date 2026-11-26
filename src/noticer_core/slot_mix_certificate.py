"""Verify a paired feasible mixture and independent upper certificate."""

from dataclasses import dataclass
from fractions import Fraction

from noticer_core.slot_mix_contract import SlotMixGame
from noticer_core.slot_mix_frontier import Candidate, WorkBudget
from noticer_core.slot_mix_probability import is_distribution, success_profile
from noticer_core.slot_mix_replay import replay_mask
from noticer_core.slot_mix_upper import best_weighted_policy


@dataclass(frozen=True)
class MixCertificate:
    """Policy law, tape law, and a claimed exact common value."""

    policies: tuple[Candidate, ...]
    policy_weights: tuple[Fraction, ...]
    tape_weights: tuple[Fraction, ...]
    value: Fraction


def verify_mix(game: SlotMixGame, certificate: MixCertificate, budget: WorkBudget) -> bool:
    """Independently replay all policies and compute a true scalar best response."""
    count = len(game.public.tapes)
    if (
        type(certificate.value) is not Fraction
        or not 0 <= certificate.value <= 1
        or type(certificate.policies) is not tuple
        or len(certificate.policies) > 256
        or not is_distribution(certificate.policy_weights, len(certificate.policies))
        or not is_distribution(certificate.tape_weights, count)
    ):
        return False
    replayed = []
    for candidate in certificate.policies:
        if type(candidate) is not Candidate or type(candidate.mask) is not int:
            return False
        try:
            actual = replay_mask(game, candidate.root)
        except ValueError:
            return False
        if actual != candidate.mask:
            return False
        replayed.append(actual)
    achieved = min(success_profile(tuple(replayed), certificate.policy_weights, count))
    return (
        achieved == certificate.value
        and best_weighted_policy(game, certificate.tape_weights, budget) == certificate.value
    )
