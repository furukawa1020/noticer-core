"""Paired cluster percentile bootstrap for independent experimental units."""

import random
from collections.abc import Mapping
from dataclasses import dataclass
from math import fsum, isfinite


@dataclass(frozen=True, slots=True)
class BootstrapInterval:
    estimate: float
    lower: float
    upper: float
    clusters: int
    repetitions: int


def paired_cluster_interval(
    cluster_differences: Mapping[str, float],
    *,
    seed: int,
    repetitions: int = 2000,
    alpha: float = 0.05,
    min_clusters: int = 10,
) -> BootstrapInterval | None:
    """Resample whole independent cluster differences, never individual windows.

    Each value is a pre-aggregated paired difference for one independent unit.
    This is a percentile interval, not an exact finite-sample coverage claim.
    """
    if type(seed) is not int or not 0 <= seed < 2**64:
        raise ValueError("seed must be an unsigned 64-bit integer")
    if type(repetitions) is not int or not 100 <= repetitions <= 100_000:
        raise ValueError("repetitions must be an integer between 100 and 100000")
    if type(min_clusters) is not int or min_clusters < 2 or not 0 < alpha < 1:
        raise ValueError("invalid alpha or minimum cluster count")
    if "" in cluster_differences or not all(map(isfinite, cluster_differences.values())):
        raise ValueError("cluster differences must be finite and have nonempty identifiers")
    count = len(cluster_differences)
    if count < min_clusters:
        return None
    if count * repetitions > 20_000_000:
        raise ValueError("requested bootstrap exceeds the configured work bound")
    normalized = tuple(cluster_differences[key] / count for key in sorted(cluster_differences))
    rng = random.Random(seed)
    means = sorted(
        fsum(normalized[rng.randrange(count)] for _ in range(count))
        for _ in range(repetitions)
    )
    lower_index = int((repetitions - 1) * (alpha / 2))
    upper_index = repetitions - 1 - lower_index
    return BootstrapInterval(fsum(normalized), means[lower_index], means[upper_index],
                             count, repetitions)
