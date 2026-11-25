"""A conservative chance-equivalence gate for independent cluster scores."""

from collections.abc import Mapping
from dataclasses import dataclass
from math import fsum, isfinite, log, sqrt
from typing import Literal

ChanceVerdict = Literal["chance-equivalent", "outside-chance-band", "inconclusive"]


@dataclass(frozen=True, slots=True)
class ChanceAssessment:
    estimate: float | None
    lower: float | None
    upper: float | None
    clusters: int
    verdict: ChanceVerdict


def assess_chance(
    cluster_scores: Mapping[str, float],
    *,
    chance: float,
    margin: float,
    alpha: float = 0.05,
    min_clusters: int = 2,
) -> ChanceAssessment:
    """Use a two-sided Hoeffding interval on equally weighted independent clusters.

    The chance level, margin and clustering unit must be fixed independently of
    these observations. This estimates the cluster-mean score, not pooled AUC.
    """
    if not 0 < chance < 1 or not 0 < margin <= min(chance, 1 - chance):
        raise ValueError("the equivalence band must be inside [0, 1]")
    if not 0 < alpha < 1 or type(min_clusters) is not int or min_clusters < 2:
        raise ValueError("invalid alpha or minimum cluster count")
    if any(not key or not isfinite(value) or not 0 <= value <= 1
           for key, value in cluster_scores.items()):
        raise ValueError("each cluster needs a finite score in [0, 1] and a nonempty key")
    count = len(cluster_scores)
    if count < min_clusters:
        return ChanceAssessment(None, None, None, count, "inconclusive")
    mean = fsum(cluster_scores.values()) / count
    radius = sqrt((log(2) - log(alpha)) / (2 * count))
    lower, upper = max(0.0, mean - radius), min(1.0, mean + radius)
    verdict: ChanceVerdict = "inconclusive"
    if lower >= chance - margin and upper <= chance + margin:
        verdict = "chance-equivalent"
    elif lower > chance + margin or upper < chance - margin:
        verdict = "outside-chance-band"
    return ChanceAssessment(mean, lower, upper, count, verdict)
