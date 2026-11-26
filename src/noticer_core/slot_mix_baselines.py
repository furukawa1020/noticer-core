"""Causal mixtures with the same solved deterministic success sets."""

from fractions import Fraction

from noticer_core.slot_mix_probability import success_profile


def uniform_success(masks: tuple[int, ...], tapes: int) -> Fraction:
    """Choose uniformly over distinct nondominated deterministic success sets."""
    masks = tuple(sorted(set(masks)))
    mass = Fraction(1, len(masks))
    return min(success_profile(masks, (mass,) * len(masks), tapes))


def iterative_profile(
    masks: tuple[int, ...], tapes: int, *, rounds: int = 64
) -> tuple[Fraction, ...]:
    """Fictitious play over the same frontier, with deterministic ties."""
    if type(rounds) is not int or not 0 < rounds <= 4096 or not masks:
        raise ValueError("invalid iterative baseline")
    masks = tuple(sorted(set(masks)))
    gains = [0] * tapes
    threats = [0] * tapes
    for _ in range(rounds):
        worst = min(range(tapes), key=gains.__getitem__)
        threats[worst] += 1
        chosen = max(masks, key=lambda mask: sum(
            count for i, count in enumerate(threats) if mask & (1 << i)
        ))
        for i in range(tapes):
            gains[i] += bool(chosen & (1 << i))
    return tuple(Fraction(value, rounds) for value in gains)
