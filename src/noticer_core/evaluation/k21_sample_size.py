"""Precision planning for the K20 bounded cluster-mean chance gate."""

from math import ceil, log


def plan_independent_units(*, margin: float, expected_distance: float, alpha: float) -> int:
    """Count units needed for the planned interval width at a posited estimate.

    This is precision planning at a posited distance from chance, not a power
    guarantee. Clusters must be independent under the analysis contract.
    """
    if not 0 <= expected_distance < margin <= 0.5 or not 0 < alpha < 1:
        raise ValueError("planned distance must be below the margin and alpha in (0, 1)")
    available = margin - expected_distance
    if available < 1e-6:
        raise ValueError("planned precision exceeds the supported bound")
    return max(2, ceil((log(2) - log(alpha)) / (2 * available**2)))
