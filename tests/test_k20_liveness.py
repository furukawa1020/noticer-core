import pytest

from noticer_core.evaluation.k20_liveness import ActionOutcome, summarize_liveness


def test_liveness_preserves_censoring_and_deadline_misses() -> None:
    result = summarize_liveness(
        [
            ActionOutcome("a", 2, 4, 7, 4),
            ActionOutcome("b", 2, 4, 7, 6),
            ActionOutcome("c", 2, 4, 4),
            ActionOutcome("d", 2, 4, 3),
        ]
    )
    assert (result.on_time, result.late, result.overdue, result.censored) == (1, 1, 1, 1)
    assert result.conservative_deadline_rate == 0.25


def test_liveness_rejects_a_completion_not_observed_by_the_cutoff() -> None:
    with pytest.raises(ValueError, match="observation"):
        summarize_liveness([ActionOutcome("a", 2, 5, 4, 5)])
