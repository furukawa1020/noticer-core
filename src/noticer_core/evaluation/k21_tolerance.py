"""Frozen exact and approximate comparisons for reproducibility replay."""

from collections.abc import Mapping
from dataclasses import dataclass
from math import isclose, isfinite


@dataclass(frozen=True, slots=True)
class FloatTolerance:
    absolute: float
    relative: float


def compare_replay(
    expected: Mapping[str, int | str | float],
    observed: Mapping[str, int | str | float],
    tolerances: Mapping[str, FloatTolerance],
) -> tuple[str, ...]:
    """Return stable names of mismatched fields; require a tolerance per float."""
    if not expected or expected.keys() != observed.keys():
        raise ValueError("replay fields must exactly match the expected inventory")
    float_fields = {name for name, value in expected.items() if type(value) is float}
    if float_fields != tolerances.keys():
        raise ValueError("tolerances must match exactly the expected float fields")
    mismatches = []
    for key in sorted(expected):
        left, right = expected[key], observed[key]
        if type(left) not in (int, str, float):
            raise ValueError("only integer, text and float fields are supported")
        if key in float_fields:
            bounds = tolerances[key]
            if any(not isfinite(value) or value < 0
                   for value in (bounds.absolute, bounds.relative)):
                raise ValueError("tolerances must be finite and nonnegative")
            matches = (
                type(right) is float and isfinite(left) and isfinite(right)
                and isclose(left, right, abs_tol=bounds.absolute, rel_tol=bounds.relative)
            )
        else:
            matches = type(left) is type(right) and left == right
        if not matches:
            mismatches.append(key)
    return tuple(mismatches)
