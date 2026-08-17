"""Independent finite semantics oracle for AQRS checker models.

This module deliberately shares no executable semantics with the Rust checker.
The only shared boundary is the versioned JSON interchange document.
"""

from __future__ import annotations

import json
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from time import monotonic
from typing import Literal

MODEL_FORMAT = "aqrs-check-model-v1"
REPORT_FORMAT = "aqrs-check-report-v1"


class ModelValidationError(ValueError):
    """A stable validation failure at the JSON or finite-model boundary."""

    def __init__(self, category: str, message: str) -> None:
        super().__init__(message)
        self.category = category


@dataclass(frozen=True, order=True)
class ObligationKey:
    kind: Literal["authorized", "recovery"]
    identifier: str
    triggered_at: int = -1

    def label(self) -> str:
        if self.kind == "authorized":
            return f"authorized:{self.identifier}"
        return f"recovery:{self.identifier}@{self.triggered_at}"


@dataclass(frozen=True)
class ActionEmission:
    obligation: ObligationKey
    action: str


@dataclass(frozen=True)
class Release:
    emitted: bool
    fields: tuple[tuple[str, str], ...]
    actions: tuple[ActionEmission, ...]


@dataclass(frozen=True)
class State:
    id: str
    action_semantics: str
    private_history: str


@dataclass(frozen=True)
class ActionObligation:
    id: str
    action: str
    trigger_slot: int
    deadline_slot: int


@dataclass(frozen=True)
class SemanticContract:
    id: str
    obligations: tuple[ActionObligation, ...]


@dataclass(frozen=True)
class RecoveryRequirement:
    action: str
    deadline_after_slots: int


@dataclass(frozen=True)
class FaultInput:
    id: str
    recovery: RecoveryRequirement | None


@dataclass(frozen=True)
class EnvironmentInput:
    id: str
    public_symbol: str
    fault: str | None


@dataclass(frozen=True)
class Transition:
    source: str
    input_id: str
    target: str
    release: Release


@dataclass(frozen=True)
class Observer:
    id: str
    visible_fields: frozenset[str]
    observes_actions: bool


@dataclass(frozen=True)
class InitialPair:
    left: str
    right: str


@dataclass(frozen=True)
class CheckerModel:
    horizon: int
    states: tuple[State, ...]
    semantics: tuple[SemanticContract, ...]
    faults: tuple[FaultInput, ...]
    inputs: tuple[EnvironmentInput, ...]
    transitions: tuple[Transition, ...]
    observers: tuple[Observer, ...]
    initial_pairs: tuple[InitialPair, ...]


@dataclass(frozen=True)
class CheckLimits:
    max_nodes: int = 100_000
    max_depth: int = 1_024
    time_limit_ms: int = 30_000

    def validate(self) -> None:
        if self.max_nodes < 0 or self.max_depth < 0 or self.time_limit_ms < 0:
            raise ValueError("checker limits must be non-negative")


DEFAULT_LIMITS = CheckLimits()


@dataclass(frozen=True)
class TraceRecord:
    slot: int
    input_id: str
    left_state: str
    right_state: str

    def as_dict(self) -> dict[str, object]:
        return {
            "slot": self.slot,
            "input": self.input_id,
            "left_state": self.left_state,
            "right_state": self.right_state,
        }


@dataclass(frozen=True)
class OracleOutcome:
    status: Literal["verified", "counterexample", "inconclusive", "invalid"]
    category: str
    slot: int | None = None
    observer: str | None = None
    side: Literal["left", "right"] | None = None
    causal_field: str | None = None
    obligation: str | None = None
    action: str | None = None
    reason: str | None = None
    checked_horizon: int | None = None
    trace: tuple[TraceRecord, ...] = ()

    def as_report(self, *, engine: str = "python") -> dict[str, object]:
        return {
            "format_version": REPORT_FORMAT,
            "engine": engine,
            "status": self.status,
            "category": self.category,
            "slot": self.slot,
            "observer": self.observer,
            "side": self.side,
            "causal_field": self.causal_field,
            "obligation": self.obligation,
            "action": self.action,
            "reason": self.reason,
            "checked_horizon": self.checked_horizon,
            "trace": [record.as_dict() for record in self.trace],
        }

    def signature(self) -> tuple[object, ...]:
        return (
            self.status,
            self.category,
            self.slot,
            self.observer,
            self.side,
            self.causal_field,
            self.obligation,
            self.action,
            self.reason,
            self.checked_horizon,
        )


def model_from_document(document: Mapping[str, object]) -> CheckerModel:
    """Parse and validate one canonical JSON interchange document."""

    root = _object(document, "root")
    _exact_keys(
        root,
        {
            "format_version",
            "horizon",
            "states",
            "semantics",
            "faults",
            "inputs",
            "transitions",
            "observers",
            "initial_pairs",
        },
        "root",
    )
    if _text(root["format_version"], "format_version") != MODEL_FORMAT:
        raise ModelValidationError("unsupported_format", "unsupported format_version")

    states = tuple(_parse_state(value) for value in _array(root["states"], "states"))
    semantics = tuple(
        _parse_semantic(value) for value in _array(root["semantics"], "semantics")
    )
    faults = tuple(_parse_fault(value) for value in _array(root["faults"], "faults"))
    inputs = tuple(_parse_input(value) for value in _array(root["inputs"], "inputs"))
    transitions = tuple(
        _parse_transition(value)
        for value in _array(root["transitions"], "transitions")
    )
    observers = tuple(
        _parse_observer(value) for value in _array(root["observers"], "observers")
    )
    initial_pairs = tuple(
        _parse_initial_pair(value)
        for value in _array(root["initial_pairs"], "initial_pairs")
    )
    model = CheckerModel(
        horizon=_integer(root["horizon"], "horizon"),
        states=states,
        semantics=semantics,
        faults=faults,
        inputs=inputs,
        transitions=transitions,
        observers=observers,
        initial_pairs=initial_pairs,
    )
    validate_model(model)
    return model


def load_model(path: Path) -> CheckerModel:
    """Load one UTF-8 JSON model from a pathlib path."""

    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ModelValidationError("json_invalid", "input is not canonical JSON") from error
    return model_from_document(_object(document, "root"))


def check_path(path: Path, limits: CheckLimits = DEFAULT_LIMITS) -> OracleOutcome:
    """Return a four-way outcome without promoting invalid input to success."""

    try:
        model = load_model(path)
    except ModelValidationError as error:
        return OracleOutcome("invalid", error.category)
    return check_model(model, limits)


def check_document(
    document: Mapping[str, object], limits: CheckLimits = DEFAULT_LIMITS
) -> OracleOutcome:
    """Evaluate an in-memory interchange document."""

    try:
        model = model_from_document(document)
    except ModelValidationError as error:
        return OracleOutcome("invalid", error.category)
    return check_model(model, limits)


def validate_model(model: CheckerModel) -> None:
    """Validate totality and all references independently of Rust code."""

    if model.horizon <= 0:
        raise ModelValidationError("empty_domain", "horizon must be positive")
    for domain, values in (
        ("states", model.states),
        ("semantics", model.semantics),
        ("inputs", model.inputs),
        ("observers", model.observers),
        ("initial_pairs", model.initial_pairs),
    ):
        if not values:
            raise ModelValidationError("empty_domain", f"{domain} must not be empty")

    states = _unique(model.states, lambda value: value.id, "states")
    semantics = _unique(model.semantics, lambda value: value.id, "semantics")
    faults = _unique(model.faults, lambda value: value.id, "faults")
    inputs = _unique(model.inputs, lambda value: value.id, "inputs")
    _unique(model.observers, lambda value: value.id, "observers")

    for state in model.states:
        _nonempty(state.id, "states")
        _nonempty(state.private_history, "private_histories")
        if state.action_semantics not in semantics:
            raise ModelValidationError("unknown_reference", "unknown state semantic")

    for semantic in model.semantics:
        _nonempty(semantic.id, "semantics")
        obligation_ids: set[str] = set()
        for obligation in semantic.obligations:
            _nonempty(obligation.id, "obligations")
            _nonempty(obligation.action, "obligations")
            if obligation.id in obligation_ids:
                raise ModelValidationError(
                    "duplicate_identifier", "duplicate obligation identifier"
                )
            obligation_ids.add(obligation.id)
            if obligation.trigger_slot > obligation.deadline_slot:
                raise ModelValidationError("invalid_obligation", "trigger follows deadline")
            if obligation.deadline_slot >= model.horizon:
                raise ModelValidationError(
                    "invalid_obligation", "deadline is outside the horizon"
                )

    for fault in model.faults:
        _nonempty(fault.id, "faults")
        if fault.recovery is not None:
            _nonempty(fault.recovery.action, "recovery action")

    for input_value in model.inputs:
        _nonempty(input_value.id, "inputs")
        _nonempty(input_value.public_symbol, "public_symbols")
        if input_value.fault is not None and input_value.fault not in faults:
            raise ModelValidationError("unknown_reference", "unknown input fault")

    for pair in model.initial_pairs:
        if pair.left not in states or pair.right not in states:
            raise ModelValidationError("unknown_reference", "unknown initial state")
        left = states[pair.left]
        right = states[pair.right]
        if left.action_semantics != right.action_semantics:
            raise ModelValidationError(
                "invalid_initial_pair", "initial pair is not action-equivalent"
            )
        if left.private_history == right.private_history:
            raise ModelValidationError(
                "invalid_initial_pair", "initial pair is not private-distinct"
            )

    transition_index: dict[tuple[str, str], Transition] = {}
    for transition in model.transitions:
        if transition.source not in states or transition.target not in states:
            raise ModelValidationError("unknown_reference", "unknown transition state")
        if transition.input_id not in inputs:
            raise ModelValidationError("unknown_reference", "unknown transition input")
        key = (transition.source, transition.input_id)
        if key in transition_index:
            raise ModelValidationError("duplicate_transition", "duplicate transition")
        transition_index[key] = transition
        if not transition.release.emitted and (
            transition.release.fields or transition.release.actions
        ):
            raise ModelValidationError(
                "invalid_release", "silent release carries observable content"
            )
        for field, _ in transition.release.fields:
            _nonempty(field, "release_fields")

    for state_id in states:
        for input_id in inputs:
            if (state_id, input_id) not in transition_index:
                raise ModelValidationError("missing_transition", "transition is not total")


@dataclass(frozen=True, order=True)
class _RuntimeObligation:
    action: str
    trigger_slot: int
    deadline_slot: int
    emitted: bool


_Utility = tuple[tuple[ObligationKey, _RuntimeObligation], ...]


@dataclass(frozen=True)
class _ProductNode:
    left: str
    right: str
    slot: int
    left_utility: _Utility
    right_utility: _Utility


@dataclass(frozen=True)
class _Observation:
    emitted: bool
    fields: tuple[tuple[str, str], ...]
    actions: tuple[ActionEmission, ...]


@dataclass(frozen=True)
class _UtilityFailure:
    category: str
    action: str
    obligation: ObligationKey


@dataclass(frozen=True)
class _Policy:
    observe_presence: bool = True
    observe_fields: bool = True
    observe_actions: bool = True
    evaluate_left: bool = True
    evaluate_right: bool = True
    reject_unknown_obligation: bool = True
    reject_duplicate_action: bool = True
    enforce_authorized_deadline: bool = True
    activate_recovery: bool = True
    node_limit_is_inconclusive: bool = True


class OracleMutation(StrEnum):
    """Deliberate checker faults used only for mutation adequacy measurement."""

    OMIT_RELEASE_PRESENCE = "omit_release_presence"
    OMIT_VISIBLE_FIELDS = "omit_visible_fields"
    OMIT_OBSERVED_ACTIONS = "omit_observed_actions"
    SUPPRESS_LEFT_UTILITY = "suppress_left_utility"
    SUPPRESS_RIGHT_UTILITY = "suppress_right_utility"
    ACCEPT_UNKNOWN_OBLIGATION = "accept_unknown_obligation"
    ACCEPT_DUPLICATE_ACTION = "accept_duplicate_action"
    SUPPRESS_AUTHORIZED_DEADLINE = "suppress_authorized_deadline"
    SUPPRESS_RECOVERY_ACTIVATION = "suppress_recovery_activation"
    PROMOTE_NODE_LIMIT = "promote_node_limit"


@dataclass(frozen=True)
class MutationCase:
    model: CheckerModel
    limits: CheckLimits = CheckLimits()


@dataclass(frozen=True)
class MutationResult:
    mutation: OracleMutation
    killed: bool
    expected: tuple[object, ...]
    observed: tuple[object, ...]


def run_mutation_campaign(
    cases: Mapping[OracleMutation, MutationCase],
) -> tuple[MutationResult, ...]:
    """Run every declared mutant and report whether its verdict was detected."""

    missing = set(OracleMutation) - set(cases)
    if missing:
        names = ", ".join(sorted(mutation.value for mutation in missing))
        raise ValueError(f"mutation campaign is missing cases: {names}")
    results = []
    for mutation in OracleMutation:
        case = cases[mutation]
        expected = check_model(case.model, case.limits).signature()
        observed = _check_valid_model(
            case.model, case.limits, _policy_for(mutation)
        ).signature()
        results.append(
            MutationResult(
                mutation=mutation,
                killed=expected != observed,
                expected=expected,
                observed=observed,
            )
        )
    return tuple(results)


def check_model(
    model: CheckerModel, limits: CheckLimits = DEFAULT_LIMITS
) -> OracleOutcome:
    """Exhaustively check all bounded product traces in deterministic BFS order."""

    limits.validate()
    try:
        validate_model(model)
    except ModelValidationError as error:
        return OracleOutcome("invalid", error.category)
    return _check_valid_model(model, limits, _Policy())


def _check_valid_model(
    model: CheckerModel, limits: CheckLimits, policy: _Policy
) -> OracleOutcome:
    if limits.max_nodes == 0:
        return _node_limit_outcome(model.horizon, policy)

    started = monotonic()
    states = {state.id: state for state in model.states}
    semantics = {semantic.id: semantic for semantic in model.semantics}
    faults = {fault.id: fault for fault in model.faults}
    transitions = {
        (transition.source, transition.input_id): transition
        for transition in model.transitions
    }
    inputs = sorted(model.inputs, key=lambda value: value.id)
    observers = sorted(model.observers, key=lambda value: value.id)

    queue: deque[_ProductNode] = deque()
    discovered: set[_ProductNode] = set()
    predecessors: dict[_ProductNode, tuple[_ProductNode, TraceRecord]] = {}
    for pair in model.initial_pairs:
        semantic = semantics[states[pair.left].action_semantics]
        utility = _utility_for_semantic(semantic)
        root = _ProductNode(pair.left, pair.right, 0, utility, utility)
        if root not in discovered:
            discovered.add(root)
            if len(discovered) > limits.max_nodes:
                return _node_limit_outcome(model.horizon, policy)
            queue.append(root)

    reached_depth = 0
    depth_truncated = False
    while queue:
        if _timed_out(started, limits.time_limit_ms):
            return OracleOutcome("inconclusive", "resource_limit", reason="time_limit")
        node = queue.popleft()
        reached_depth = max(reached_depth, node.slot)
        if node.slot >= model.horizon:
            continue
        if node.slot >= limits.max_depth:
            depth_truncated = True
            continue

        for input_value in inputs:
            if _timed_out(started, limits.time_limit_ms):
                return OracleOutcome(
                    "inconclusive", "resource_limit", reason="time_limit"
                )
            left_transition = transitions[(node.left, input_value.id)]
            right_transition = transitions[(node.right, input_value.id)]
            step = TraceRecord(
                node.slot, input_value.id, node.left, node.right
            )

            for observer in observers:
                left_observation = _observe(observer, left_transition.release, policy)
                right_observation = _observe(observer, right_transition.release, policy)
                if left_observation != right_observation:
                    return OracleOutcome(
                        "counterexample",
                        "security_divergence",
                        slot=node.slot,
                        observer=observer.id,
                        causal_field=_first_causal_field(
                            left_observation, right_observation
                        ),
                        trace=_reconstruct_trace(node, predecessors) + (step,),
                    )

            left_utility = _activate_recovery(
                node.left_utility, input_value, node.slot, faults, policy
            )
            right_utility = _activate_recovery(
                node.right_utility, input_value, node.slot, faults, policy
            )
            if policy.evaluate_left:
                left_utility, failure = _evaluate_utility(
                    left_utility, left_transition.release, node.slot, policy
                )
                if failure is not None:
                    return _utility_outcome(
                        failure, "left", node, step, predecessors
                    )
            if policy.evaluate_right:
                right_utility, failure = _evaluate_utility(
                    right_utility, right_transition.release, node.slot, policy
                )
                if failure is not None:
                    return _utility_outcome(
                        failure, "right", node, step, predecessors
                    )

            left_next = states[left_transition.target]
            right_next = states[right_transition.target]
            if left_next.action_semantics != right_next.action_semantics:
                continue
            left_utility = _add_semantic_obligations(
                left_utility, semantics[left_next.action_semantics]
            )
            right_utility = _add_semantic_obligations(
                right_utility, semantics[right_next.action_semantics]
            )
            next_node = _ProductNode(
                left_transition.target,
                right_transition.target,
                node.slot + 1,
                left_utility,
                right_utility,
            )
            if next_node in discovered:
                continue
            if len(discovered) >= limits.max_nodes:
                return _node_limit_outcome(model.horizon, policy)
            discovered.add(next_node)
            predecessors[next_node] = (node, step)
            queue.append(next_node)

    if depth_truncated:
        return OracleOutcome("inconclusive", "resource_limit", reason="depth_limit")
    return OracleOutcome(
        "verified", "bounded_verified", checked_horizon=model.horizon
    )


def _policy_for(mutation: OracleMutation) -> _Policy:
    values: dict[str, bool] = {}
    if mutation is OracleMutation.OMIT_RELEASE_PRESENCE:
        values["observe_presence"] = False
    elif mutation is OracleMutation.OMIT_VISIBLE_FIELDS:
        values["observe_fields"] = False
    elif mutation is OracleMutation.OMIT_OBSERVED_ACTIONS:
        values["observe_actions"] = False
    elif mutation is OracleMutation.SUPPRESS_LEFT_UTILITY:
        values["evaluate_left"] = False
    elif mutation is OracleMutation.SUPPRESS_RIGHT_UTILITY:
        values["evaluate_right"] = False
    elif mutation is OracleMutation.ACCEPT_UNKNOWN_OBLIGATION:
        values["reject_unknown_obligation"] = False
    elif mutation is OracleMutation.ACCEPT_DUPLICATE_ACTION:
        values["reject_duplicate_action"] = False
    elif mutation is OracleMutation.SUPPRESS_AUTHORIZED_DEADLINE:
        values["enforce_authorized_deadline"] = False
    elif mutation is OracleMutation.SUPPRESS_RECOVERY_ACTIVATION:
        values["activate_recovery"] = False
    elif mutation is OracleMutation.PROMOTE_NODE_LIMIT:
        values["node_limit_is_inconclusive"] = False
    return _Policy(**values)


def _node_limit_outcome(horizon: int, policy: _Policy) -> OracleOutcome:
    if policy.node_limit_is_inconclusive:
        return OracleOutcome("inconclusive", "resource_limit", reason="node_limit")
    return OracleOutcome("verified", "bounded_verified", checked_horizon=horizon)


def _timed_out(started: float, time_limit_ms: int) -> bool:
    return (monotonic() - started) * 1_000 >= time_limit_ms


def _utility_for_semantic(semantic: SemanticContract) -> _Utility:
    return _add_semantic_obligations((), semantic)


def _add_semantic_obligations(
    utility: _Utility, semantic: SemanticContract
) -> _Utility:
    obligations = dict(utility)
    for obligation in semantic.obligations:
        key = ObligationKey("authorized", obligation.id)
        obligations.setdefault(
            key,
            _RuntimeObligation(
                obligation.action,
                obligation.trigger_slot,
                obligation.deadline_slot,
                False,
            ),
        )
    return tuple(sorted(obligations.items()))


def _activate_recovery(
    utility: _Utility,
    input_value: EnvironmentInput,
    slot: int,
    faults: Mapping[str, FaultInput],
    policy: _Policy,
) -> _Utility:
    if not policy.activate_recovery or input_value.fault is None:
        return utility
    recovery = faults[input_value.fault].recovery
    if recovery is None:
        return utility
    obligations = dict(utility)
    obligations[ObligationKey("recovery", input_value.fault, slot)] = _RuntimeObligation(
        recovery.action,
        slot,
        slot + recovery.deadline_after_slots,
        False,
    )
    return tuple(sorted(obligations.items()))


def _evaluate_utility(
    utility: _Utility, release: Release, slot: int, policy: _Policy
) -> tuple[_Utility, _UtilityFailure | None]:
    obligations = dict(utility)
    for emission in release.actions:
        obligation = obligations.get(emission.obligation)
        if obligation is None:
            if policy.reject_unknown_obligation:
                return utility, _UtilityFailure(
                    "unauthorized_action", emission.action, emission.obligation
                )
            continue
        if obligation.emitted:
            if policy.reject_duplicate_action:
                return utility, _UtilityFailure(
                    "duplicate_action", emission.action, emission.obligation
                )
            continue
        if (
            obligation.action != emission.action
            or slot < obligation.trigger_slot
            or slot > obligation.deadline_slot
        ):
            return utility, _UtilityFailure(
                "unauthorized_action", emission.action, emission.obligation
            )
        obligations[emission.obligation] = _RuntimeObligation(
            obligation.action,
            obligation.trigger_slot,
            obligation.deadline_slot,
            True,
        )

    for key, obligation in sorted(obligations.items()):
        if obligation.emitted or obligation.deadline_slot > slot:
            continue
        if key.kind == "authorized" and not policy.enforce_authorized_deadline:
            continue
        category = (
            "missed_deadline"
            if key.kind == "authorized"
            else "recoverable_fault_violation"
        )
        return tuple(sorted(obligations.items())), _UtilityFailure(
            category, obligation.action, key
        )
    return tuple(sorted(obligations.items())), None


def _observe(observer: Observer, release: Release, policy: _Policy) -> _Observation:
    emitted = release.emitted if policy.observe_presence else True
    fields = ()
    if release.emitted and policy.observe_fields:
        fields = tuple(
            (field, value)
            for field, value in release.fields
            if field in observer.visible_fields
        )
    actions = ()
    if release.emitted and policy.observe_actions and observer.observes_actions:
        actions = release.actions
    return _Observation(emitted, fields, actions)


def _first_causal_field(left: _Observation, right: _Observation) -> str | None:
    if left.emitted != right.emitted:
        return "release_presence"
    left_fields = dict(left.fields)
    right_fields = dict(right.fields)
    for field in sorted(set(left_fields) | set(right_fields)):
        if left_fields.get(field) != right_fields.get(field):
            return f"field:{field}"
    if left.actions != right.actions:
        return "actions"
    return None


def _utility_outcome(
    failure: _UtilityFailure,
    side: Literal["left", "right"],
    node: _ProductNode,
    step: TraceRecord,
    predecessors: Mapping[_ProductNode, tuple[_ProductNode, TraceRecord]],
) -> OracleOutcome:
    return OracleOutcome(
        "counterexample",
        failure.category,
        slot=node.slot,
        side=side,
        obligation=failure.obligation.label(),
        action=failure.action,
        trace=_reconstruct_trace(node, predecessors) + (step,),
    )


def _reconstruct_trace(
    node: _ProductNode,
    predecessors: Mapping[_ProductNode, tuple[_ProductNode, TraceRecord]],
) -> tuple[TraceRecord, ...]:
    cursor = node
    trace: list[TraceRecord] = []
    while cursor in predecessors:
        cursor, step = predecessors[cursor]
        trace.append(step)
    trace.reverse()
    return tuple(trace)


def _parse_state(value: object) -> State:
    item = _object(value, "state")
    _exact_keys(item, {"id", "action_semantics", "private_history"}, "state")
    return State(
        _text(item["id"], "state.id"),
        _text(item["action_semantics"], "state.action_semantics"),
        _text(item["private_history"], "state.private_history"),
    )


def _parse_semantic(value: object) -> SemanticContract:
    item = _object(value, "semantic")
    _exact_keys(item, {"id", "obligations"}, "semantic")
    return SemanticContract(
        _text(item["id"], "semantic.id"),
        tuple(
            _parse_action_obligation(obligation)
            for obligation in _array(item["obligations"], "semantic.obligations")
        ),
    )


def _parse_action_obligation(value: object) -> ActionObligation:
    item = _object(value, "action_obligation")
    _exact_keys(
        item,
        {"id", "action", "trigger_slot", "deadline_slot"},
        "action_obligation",
    )
    return ActionObligation(
        _text(item["id"], "obligation.id"),
        _text(item["action"], "obligation.action"),
        _integer(item["trigger_slot"], "obligation.trigger_slot"),
        _integer(item["deadline_slot"], "obligation.deadline_slot"),
    )


def _parse_fault(value: object) -> FaultInput:
    item = _object(value, "fault")
    _exact_keys(item, {"id", "recovery"}, "fault")
    raw_recovery = item["recovery"]
    recovery = None
    if raw_recovery is not None:
        raw = _object(raw_recovery, "fault.recovery")
        _exact_keys(raw, {"action", "deadline_after_slots"}, "fault.recovery")
        recovery = RecoveryRequirement(
            _text(raw["action"], "recovery.action"),
            _integer(raw["deadline_after_slots"], "recovery.deadline_after_slots"),
        )
    return FaultInput(_text(item["id"], "fault.id"), recovery)


def _parse_input(value: object) -> EnvironmentInput:
    item = _object(value, "input")
    _exact_keys(item, {"id", "public_symbol", "fault"}, "input")
    fault = item["fault"]
    return EnvironmentInput(
        _text(item["id"], "input.id"),
        _text(item["public_symbol"], "input.public_symbol"),
        None if fault is None else _text(fault, "input.fault"),
    )


def _parse_transition(value: object) -> Transition:
    item = _object(value, "transition")
    _exact_keys(item, {"from", "input", "to", "release"}, "transition")
    return Transition(
        _text(item["from"], "transition.from"),
        _text(item["input"], "transition.input"),
        _text(item["to"], "transition.to"),
        _parse_release(item["release"]),
    )


def _parse_release(value: object) -> Release:
    item = _object(value, "release")
    _exact_keys(item, {"emitted", "fields", "actions"}, "release")
    emitted = item["emitted"]
    if not isinstance(emitted, bool):
        raise ModelValidationError("json_invalid", "release.emitted must be boolean")
    fields = _object(item["fields"], "release.fields")
    parsed_fields = tuple(
        sorted(
            (
                _text(field, "release field"),
                _text(field_value, f"release.fields.{field}"),
            )
            for field, field_value in fields.items()
        )
    )
    actions = tuple(
        _parse_action_emission(action)
        for action in _array(item["actions"], "release.actions")
    )
    return Release(emitted, parsed_fields, actions)


def _parse_action_emission(value: object) -> ActionEmission:
    item = _object(value, "action_emission")
    _exact_keys(item, {"obligation", "action"}, "action_emission")
    return ActionEmission(
        _parse_obligation_ref(item["obligation"]),
        _text(item["action"], "action_emission.action"),
    )


def _parse_obligation_ref(value: object) -> ObligationKey:
    item = _object(value, "obligation_ref")
    kind = _text(item.get("kind"), "obligation_ref.kind")
    if kind == "authorized":
        _exact_keys(item, {"kind", "id"}, "authorized obligation_ref")
        return ObligationKey("authorized", _text(item["id"], "obligation_ref.id"))
    if kind == "recovery":
        _exact_keys(
            item, {"kind", "fault", "triggered_at"}, "recovery obligation_ref"
        )
        return ObligationKey(
            "recovery",
            _text(item["fault"], "obligation_ref.fault"),
            _integer(item["triggered_at"], "obligation_ref.triggered_at"),
        )
    raise ModelValidationError("json_invalid", "unknown obligation_ref.kind")


def _parse_observer(value: object) -> Observer:
    item = _object(value, "observer")
    _exact_keys(item, {"id", "visible_fields", "observes_actions"}, "observer")
    observes_actions = item["observes_actions"]
    if not isinstance(observes_actions, bool):
        raise ModelValidationError(
            "json_invalid", "observer.observes_actions must be boolean"
        )
    visible_fields = frozenset(
        _text(field, "observer.visible_fields")
        for field in _array(item["visible_fields"], "observer.visible_fields")
    )
    return Observer(
        _text(item["id"], "observer.id"), visible_fields, observes_actions
    )


def _parse_initial_pair(value: object) -> InitialPair:
    item = _object(value, "initial_pair")
    _exact_keys(item, {"left", "right"}, "initial_pair")
    return InitialPair(
        _text(item["left"], "initial_pair.left"),
        _text(item["right"], "initial_pair.right"),
    )


def _object(value: object, location: str) -> Mapping[str, object]:
    if not isinstance(value, dict) or not all(
        isinstance(key, str) for key in value
    ):
        raise ModelValidationError("json_invalid", f"{location} must be an object")
    return value


def _array(value: object, location: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise ModelValidationError("json_invalid", f"{location} must be an array")
    return value


def _text(value: object, location: str) -> str:
    if not isinstance(value, str):
        raise ModelValidationError("json_invalid", f"{location} must be a string")
    return value


def _integer(value: object, location: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ModelValidationError(
            "json_invalid", f"{location} must be a non-negative integer"
        )
    return value


def _exact_keys(
    value: Mapping[str, object], expected: set[str], location: str
) -> None:
    if set(value) != expected:
        raise ModelValidationError(
            "json_invalid", f"{location} does not match the canonical key set"
        )


def _unique(values: Sequence[object], key_of: object, domain: str) -> dict[str, object]:
    keyed: dict[str, object] = {}
    for value in values:
        key = key_of(value)  # type: ignore[operator]
        if not key:
            raise ModelValidationError("empty_identifier", f"empty {domain} identifier")
        if key in keyed:
            raise ModelValidationError(
                "duplicate_identifier", f"duplicate {domain} identifier"
            )
        keyed[key] = value
    return keyed


def _nonempty(value: str, domain: str) -> None:
    if not value:
        raise ModelValidationError("empty_identifier", f"empty {domain} identifier")
