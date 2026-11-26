"""Worst-case success for a binary oblivious choice of public futures."""

from dataclasses import dataclass
from fractions import Fraction

from noticer_core.shared_slot_first import FirstChoice, FirstChoiceEvidence


@dataclass(frozen=True)
class BinaryCausalResult:
    """Best guaranteed success and a matching first-choice distribution."""

    deterministic: Fraction
    randomized: Fraction
    policy: tuple[tuple[FirstChoice, Fraction], ...]


def binary_minimax(evidence: FirstChoiceEvidence) -> BinaryCausalResult:
    """Assume the adversary fixes either tape before seeing the random choice."""
    common = evidence.left & evidence.right

    def key(choice: FirstChoice) -> tuple[bool, str]:
        return choice is not None, choice or ""

    if not evidence.left or not evidence.right:
        return BinaryCausalResult(Fraction(0), Fraction(0), ())
    if common:
        choice = min(common, key=key)
        return BinaryCausalResult(Fraction(1), Fraction(1), ((choice, Fraction(1)),))
    left = min(evidence.left, key=key)
    right = min(evidence.right, key=key)
    half = Fraction(1, 2)
    return BinaryCausalResult(Fraction(0), half, ((left, half), (right, half)))
