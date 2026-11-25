import pytest

from noticer_core.evaluation.k20_latency import ActionTiming, summarize_latency


def test_latency_counts_missing_action_without_distorting_quantiles() -> None:
    result = summarize_latency(
        [ActionTiming("a", 50, 60), ActionTiming("b", 60, 100), ActionTiming("c", 30, None)]
    )
    assert (result.accepted, result.completed, result.unobserved) == (3, 2, 1)
    assert (result.p50_ns, result.p95_ns, result.max_ns) == (10, 40, 40)


def test_no_completions_yield_undefined_quantiles() -> None:
    assert summarize_latency([ActionTiming("a", 0, None)]).p95_ns is None


def test_reversed_clock_tick_is_invalid() -> None:
    with pytest.raises(ValueError, match="after acceptance"):
        summarize_latency([ActionTiming("a", 5, 2)])
