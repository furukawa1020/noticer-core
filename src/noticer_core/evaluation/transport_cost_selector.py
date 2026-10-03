"""Hard-gated lexicographic, weighted, and Pareto cost selection."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass

from noticer_core.evaluation.logical_transport_cost import LogicalCostVector

FORMAT_VERSION = "noticer.k7.transport-cost-selection.v1"
AXES = (
    "bytes",
    "dummy_frames",
    "mean_latency_scaled",
    "radio_on_slots",
    "reconnects",
    "retries",
    "state_count",
    "total_frames",
    "worst_latency",
)
MODES = {"lexicographic", "pareto", "weighted"}


class CostSelectionError(ValueError):
    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


@dataclass(frozen=True)
class CostCandidate:
    candidate_id: str
    security_pass: bool
    utility_pass: bool
    unauthorized_actions: int
    deadline_misses: int
    cost: LogicalCostVector


@dataclass(frozen=True)
class SelectionPolicy:
    format_version: str
    mode: str
    axis_order: tuple[str, ...]
    weights: tuple[tuple[str, int], ...] = ()


@dataclass(frozen=True)
class CostSelectionResult:
    format_version: str
    policy_sha256: str
    mode: str
    selected_ids: tuple[str, ...]
    eligible_ids: tuple[str, ...]
    rejected_ids: tuple[str, ...]
    aggregate_scores: tuple[tuple[str, int], ...] = ()


def select_candidates(
    policy: SelectionPolicy,
    candidates: tuple[CostCandidate, ...],
) -> CostSelectionResult:
    """Apply hard gates before any cost comparison."""

    validate_policy(policy)
    ids = tuple(candidate.candidate_id for candidate in candidates)
    if not ids or ids != tuple(sorted(set(ids))):
        raise CostSelectionError("noncanonical_candidates")
    for candidate in candidates:
        _validate_candidate(candidate)
    eligible = tuple(candidate for candidate in candidates if _passes_hard_gates(candidate))
    rejected = tuple(
        candidate.candidate_id for candidate in candidates if candidate not in eligible
    )
    if not eligible:
        raise CostSelectionError("no_gate_passing_candidate")

    scores: tuple[tuple[str, int], ...] = ()
    if policy.mode == "lexicographic":
        winner = min(eligible, key=lambda item: _cost_key(item, policy.axis_order))
        selected = (winner.candidate_id,)
    elif policy.mode == "weighted":
        weights = dict(policy.weights)
        scores = tuple(
            (
                candidate.candidate_id,
                sum(_axis(candidate.cost, axis) * weights[axis] for axis in AXES),
            )
            for candidate in eligible
        )
        minimum = min(score for _, score in scores)
        selected = tuple(candidate_id for candidate_id, score in scores if score == minimum)
    else:
        selected = tuple(
            candidate.candidate_id
            for candidate in eligible
            if not any(
                other.candidate_id != candidate.candidate_id
                and dominates(other.cost, candidate.cost, policy.axis_order)
                for other in eligible
            )
        )
    return CostSelectionResult(
        FORMAT_VERSION,
        policy_digest(policy),
        policy.mode,
        selected,
        tuple(candidate.candidate_id for candidate in eligible),
        rejected,
        scores,
    )


def dominates(
    left: LogicalCostVector,
    right: LogicalCostVector,
    axes: tuple[str, ...] = AXES,
) -> bool:
    """Return true only for strict Pareto dominance on declared axes."""

    _validate_axes(axes)
    pairs = tuple((_axis(left, axis), _axis(right, axis)) for axis in axes)
    return all(left_value <= right_value for left_value, right_value in pairs) and any(
        left_value < right_value for left_value, right_value in pairs
    )


def validate_policy(policy: SelectionPolicy) -> None:
    if policy.format_version != FORMAT_VERSION or policy.mode not in MODES:
        raise CostSelectionError("invalid_policy_header")
    _validate_axes(policy.axis_order)
    if policy.mode == "weighted":
        if tuple(axis for axis, _ in policy.weights) != AXES or any(
            type(weight) is not int or weight <= 0 for _, weight in policy.weights
        ):
            raise CostSelectionError("invalid_weights")
    elif policy.weights:
        raise CostSelectionError("weights_forbidden_for_mode")


def policy_digest(policy: SelectionPolicy) -> str:
    validate_policy(policy)
    payload = json.dumps(asdict(policy), sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _validate_axes(axes: tuple[str, ...]) -> None:
    if not axes or len(axes) != len(set(axes)) or any(axis not in AXES for axis in axes):
        raise CostSelectionError("invalid_axes")


def _validate_candidate(candidate: CostCandidate) -> None:
    if (
        not candidate.candidate_id
        or type(candidate.security_pass) is not bool
        or type(candidate.utility_pass) is not bool
        or type(candidate.unauthorized_actions) is not int
        or type(candidate.deadline_misses) is not int
        or candidate.unauthorized_actions < 0
        or candidate.deadline_misses < 0
        or any(
            type(_axis(candidate.cost, axis)) is not int
            or _axis(candidate.cost, axis) < 0
            for axis in AXES
        )
    ):
        raise CostSelectionError("invalid_candidate")


def _passes_hard_gates(candidate: CostCandidate) -> bool:
    return (
        candidate.security_pass
        and candidate.utility_pass
        and candidate.unauthorized_actions == 0
        and candidate.deadline_misses == 0
    )


def _axis(cost: LogicalCostVector, axis: str) -> int:
    return getattr(cost, axis)


def _cost_key(candidate: CostCandidate, axes: tuple[str, ...]) -> tuple[int | str, ...]:
    return tuple(_axis(candidate.cost, axis) for axis in axes) + (candidate.candidate_id,)
