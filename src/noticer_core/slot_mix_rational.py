"""Decode a small canonical rational in the closed unit interval."""

import re
from fractions import Fraction
from typing import Any

TOKEN = re.compile(r"(?:0|[1-9][0-9]{0,29})(?:/[1-9][0-9]{0,29})?")


def decode_probability(value: Any) -> Fraction:
    """Avoid decimal coercion, redundant fractions, and enormous integers."""
    if type(value) is not str or TOKEN.fullmatch(value) is None or len(value) > 61:
        raise ValueError("invalid probability token")
    result = Fraction(value)
    if result > 1 or str(result) != value:
        raise ValueError("probability must be canonical and in [0, 1]")
    return result
