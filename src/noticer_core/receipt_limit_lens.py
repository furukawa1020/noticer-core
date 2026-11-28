"""Re-project an existing law to a smaller receiver coalition."""

from fractions import Fraction

from noticer_core.receipt_limit_projection import Trace


def restrict_law(
    law: dict[Trace, Fraction], receivers: frozenset[str], *, keep_failure: bool
) -> dict[Trace, Fraction]:
    """Aggregate exact probability mass over the requested subprojection."""
    result: dict[Trace, Fraction] = {}
    for trace, mass in law.items():
        visible = tuple(
            item for item in trace if item[1] in receivers or (item[1] == "" and keep_failure)
        )
        result[visible] = result.get(visible, Fraction()) + mass
    return result
