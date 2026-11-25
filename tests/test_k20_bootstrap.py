import pytest

from noticer_core.evaluation.k20_bootstrap import paired_cluster_interval


def test_clusters_are_reproducible_in_canonical_order() -> None:
    data = {str(index): float(index) for index in range(12)}
    first = paired_cluster_interval(data, seed=5, repetitions=200)
    second = paired_cluster_interval(dict(reversed(tuple(data.items()))), seed=5, repetitions=200)
    assert first == second
    assert first is not None and first.estimate == pytest.approx(5.5)
    assert first.lower < first.estimate < first.upper


def test_constant_and_insufficient_observations_are_distinct() -> None:
    assert paired_cluster_interval({"one": 2}, seed=5) is None
    result = paired_cluster_interval({str(i): 2.0 for i in range(12)}, seed=5)
    assert result is not None
    assert [result.lower, result.upper] == pytest.approx([2, 2])
