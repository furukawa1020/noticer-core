"""Produce an independently verified exact mixture or an explicit non-result."""

from dataclasses import dataclass
from fractions import Fraction
from typing import Literal

from noticer_core.slot_mix_certificate import MixCertificate, verify_mix
from noticer_core.slot_mix_contract import SlotMixGame
from noticer_core.slot_mix_frontier import MAX_WORK, Candidate, MixLimit, WorkBudget, build_frontier
from noticer_core.slot_mix_simplex import MAX_PIVOTS, pack_fractionally


@dataclass(frozen=True)
class MixResult:
    """The certificate and frontier appear only after strict verification."""

    status: Literal["verified", "invalid", "inconclusive", "rejected"]
    certificate: MixCertificate | None = None
    frontier: tuple[Candidate, ...] = ()
    reason: str | None = None
    work: tuple[int, int] = (0, 0)


def solve_mix(
    game: SlotMixGame,
    *,
    work_limit: int = MAX_WORK,
    verification_limit: int = MAX_WORK,
    pivot_limit: int = MAX_PIVOTS,
) -> MixResult:
    """A cutoff in either construction or independent verification blocks a claim."""
    try:
        search = WorkBudget(work_limit)
        verification = WorkBudget(verification_limit)
        if type(pivot_limit) is not int or not 0 < pivot_limit <= MAX_PIVOTS:
            raise ValueError("invalid pivot limit")
    except ValueError as error:
        return MixResult("invalid", reason=str(error))

    try:
        frontier = build_frontier(game, search)
        masks = tuple(item.mask for item in frontier)
        n = len(game.public.tapes)
        uncovered = next((i for i in range(n) if not any(m & (1 << i) for m in masks)), None)
        if uncovered is not None:
            certificate = MixCertificate(
                frontier[:1], (Fraction(1),),
                tuple(Fraction(i == uncovered) for i in range(n)), Fraction(),
            )
        else:
            packed = pack_fractionally(masks, n, pivot_limit)
            support = tuple(
                (item, mass / packed.objective)
                for item, mass in zip(frontier, packed.policy_weights, strict=True) if mass
            )
            certificate = MixCertificate(
                tuple(item for item, _ in support),
                tuple(mass for _, mass in support),
                tuple(mass / packed.objective for mass in packed.tape_weights),
                1 / packed.objective,
            )
        valid = verify_mix(game, certificate, verification)
    except MixLimit as error:
        return MixResult("inconclusive", reason=str(error), work=(search.used, verification.used))
    work = search.used, verification.used
    if not valid:
        return MixResult("rejected", reason="independent certificate rejection", work=work)
    return MixResult("verified", certificate, frontier, work=work)
