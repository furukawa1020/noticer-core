"""Exact arithmetic for probability laws and per-tape success."""

from fractions import Fraction


def is_distribution(weights: tuple[Fraction, ...], count: int) -> bool:
    """Require exactly one rational probability per declared outcome."""
    return (
        type(weights) is tuple
        and len(weights) == count
        and all(type(weight) is Fraction and weight >= 0 for weight in weights)
        and sum(weights) == 1
    )


def success_profile(
    masks: tuple[int, ...], weights: tuple[Fraction, ...], tapes: int
) -> tuple[Fraction, ...]:
    """Mass of each complete-delivery event under one shared initial draw."""
    if (
        type(tapes) is not int
        or not 1 <= tapes <= 8
        or not is_distribution(weights, len(masks))
        or any(type(mask) is not int or not 0 <= mask < (1 << tapes) for mask in masks)
    ):
        raise ValueError("invalid success profile")
    return tuple(
        sum((weight for mask, weight in zip(masks, weights, strict=True) if mask & (1 << i)),
            Fraction())
        for i in range(tapes)
    )
