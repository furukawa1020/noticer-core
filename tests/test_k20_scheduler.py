import pytest

from noticer_core.evaluation.k20_scheduler import require_paired_coverage, schedule_pairs


def test_scheduling_uses_stable_paired_randomness() -> None:
    first = schedule_pairs(["b", "a"], ["fixed", "aetp"], repetitions=2, root_seed=7)
    second = schedule_pairs(["a", "b"], ["aetp", "fixed"], repetitions=2, root_seed=7)
    assert first == second
    assert len({pair.seed for pair in first}) == 4
    assert all(pair.mechanism_ids == ("aetp", "fixed") for pair in first)


def test_missing_cells_are_not_hidden() -> None:
    schedule = schedule_pairs(["a"], ["fixed", "aetp"], repetitions=1, root_seed=7)
    key = schedule[0].pair_id
    outcomes = {(key, "aetp"): "inconclusive", (key, "fixed"): "completed"}
    require_paired_coverage(schedule, outcomes)
    with pytest.raises(ValueError, match="every scheduled run"):
        require_paired_coverage(schedule, {(key, "fixed"): "completed"})
