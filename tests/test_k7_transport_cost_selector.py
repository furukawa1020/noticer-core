import pytest

from noticer_core.evaluation.logical_transport_cost import LogicalCostVector
from noticer_core.evaluation.transport_cost_selector import (
    AXES,
    FORMAT_VERSION,
    CostCandidate,
    CostSelectionError,
    SelectionPolicy,
    dominates,
    select_candidates,
)


def _cost(bytes_: int, latency: int) -> LogicalCostVector:
    return LogicalCostVector(bytes_, 0, 1, latency, latency * 1_000_000, 2, 0, 0, 1)


def _candidate(name: str, bytes_: int, latency: int, **changes) -> CostCandidate:
    values = {
        "candidate_id": name,
        "security_pass": True,
        "utility_pass": True,
        "unauthorized_actions": 0,
        "deadline_misses": 0,
        "cost": _cost(bytes_, latency),
    }
    values.update(changes)
    return CostCandidate(**values)


def test_hard_gate_failure_cannot_win_with_lower_cost() -> None:
    candidates = (
        _candidate("invalid", 0, 0, security_pass=False),
        _candidate("valid", 10, 2),
    )
    policy = SelectionPolicy(FORMAT_VERSION, "lexicographic", ("bytes", "worst_latency"))
    result = select_candidates(policy, candidates)
    assert result.selected_ids == ("valid",)
    assert result.rejected_ids == ("invalid",)


def test_modes_preserve_ties_and_incomparable_pareto_points() -> None:
    candidates = (
        _candidate("balanced", 7, 7),
        _candidate("bandwidth", 5, 5),
        _candidate("latency", 10, 1),
    )
    lexicographic = SelectionPolicy(
        FORMAT_VERSION, "lexicographic", ("worst_latency", "bytes")
    )
    assert select_candidates(lexicographic, candidates).selected_ids == ("latency",)
    pareto = SelectionPolicy(FORMAT_VERSION, "pareto", ("bytes", "worst_latency"))
    assert select_candidates(pareto, candidates).selected_ids == ("bandwidth", "latency")
    assert dominates(_cost(5, 5), _cost(7, 7), ("bytes", "worst_latency"))
    assert not dominates(_cost(5, 5), _cost(5, 5), ("bytes", "worst_latency"))


def test_weighted_policy_is_explicit_and_deterministic() -> None:
    weights = tuple((axis, 1) for axis in AXES)
    policy = SelectionPolicy(FORMAT_VERSION, "weighted", AXES, weights)
    result = select_candidates(policy, (_candidate("a", 5, 2), _candidate("b", 8, 8)))
    assert result.selected_ids == ("a",)
    assert result.aggregate_scores[0][1] < result.aggregate_scores[1][1]


@pytest.mark.parametrize(
    "policy,category",
    [
        (SelectionPolicy(FORMAT_VERSION, "weighted", AXES), "invalid_weights"),
        (
            SelectionPolicy(FORMAT_VERSION, "pareto", AXES, (("bytes", 1),)),
            "weights_forbidden_for_mode",
        ),
        (
            SelectionPolicy(FORMAT_VERSION, "lexicographic", ("bytes", "bytes")),
            "invalid_axes",
        ),
    ],
)
def test_ambiguous_or_post_hoc_policy_fails_closed(policy, category) -> None:
    with pytest.raises(CostSelectionError) as caught:
        select_candidates(policy, (_candidate("a", 1, 1),))
    assert caught.value.category == category
