"""Successful tape IDs are internal bit positions, not policy observations."""

from collections.abc import Iterable


def tape_mask(indices: Iterable[int]) -> int:
    """Encode distinct observed-analysis tape positions as a set."""
    result = 0
    for index in indices:
        if type(index) is not int or not 0 <= index < 8:
            raise ValueError("invalid tape position")
        result |= 1 << index
    return result


def maximal_masks(masks: Iterable[int]) -> tuple[int, ...]:
    """Discard masks that cannot improve any nonnegative success objective."""
    distinct = set(masks)
    if any(type(mask) is not int or not 0 <= mask < 256 for mask in distinct):
        raise ValueError("invalid success mask")
    ordered = sorted(distinct, key=lambda mask: (-mask.bit_count(), mask))
    kept: list[int] = []
    for mask in ordered:
        if not any(mask & better == mask for better in kept):
            kept.append(mask)
    return tuple(sorted(kept))
