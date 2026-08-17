from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import cast

import yaml


class SemanticsContractError(ValueError):
    """Raised when the frozen K8 semantics contract is malformed or drifts."""


class TargetEventKind(StrEnum):
    API_CALL = "API_CALL"
    API_RETURN = "API_RETURN"
    ACTION = "ACTION"
    HOST_CALL = "HOST_CALL"
    TRAP = "TRAP"
    CONTROL = "CONTROL"
    INSTRUCTION = "INSTRUCTION"
    MEMORY_ACCESS = "MEMORY_ACCESS"
    MEMORY_GROW = "MEMORY_GROW"
    RESOURCE = "RESOURCE"
    TERMINATION = "TERMINATION"
    UNKNOWN_FAILURE = "UNKNOWN_FAILURE"
    CONTEXT_COMMAND = "CONTEXT_COMMAND"


class SourceEventKind(StrEnum):
    PUBLIC_CALL = "PUBLIC_CALL"
    PUBLIC_RETURN = "PUBLIC_RETURN"
    AUTHORIZED_ACTION = "AUTHORIZED_ACTION"
    PUBLIC_FAULT = "PUBLIC_FAULT"
    TERMINATION = "TERMINATION"


class PublicCommandKind(StrEnum):
    PUBLIC_CALL = "PUBLIC_CALL"
    PUBLIC_FAULT = "PUBLIC_FAULT"
    PUBLIC_RESET = "PUBLIC_RESET"
    PUBLIC_HANDOFF = "PUBLIC_HANDOFF"
    STOP = "STOP"


class ExecutionBoundary(StrEnum):
    NORMAL_RETURN = "NORMAL_RETURN"
    TRAP = "TRAP"
    TERMINATION = "TERMINATION"
    BOUNDED_NONTERMINATION = "BOUNDED_NONTERMINATION"
    FUEL_EXHAUSTED = "FUEL_EXHAUSTED"
    STATE_BOUND_EXHAUSTED = "STATE_BOUND_EXHAUSTED"
    UNSUPPORTED_INSTRUCTION = "UNSUPPORTED_INSTRUCTION"
    UNKNOWN_IMPORT = "UNKNOWN_IMPORT"
    PARSER_DISAGREEMENT = "PARSER_DISAGREEMENT"


class Verdict(StrEnum):
    ACCEPT = "ACCEPT"
    COUNTEREXAMPLE = "COUNTEREXAMPLE"
    INCONCLUSIVE = "INCONCLUSIVE"


class Judgment(StrEnum):
    RAQTR = "RAQTR"
    ROBUST_ACTION_QUOTIENT_NONINTERFERENCE = "ROBUST_ACTION_QUOTIENT_NONINTERFERENCE"
    TRACE_REFINEMENT = "TRACE_REFINEMENT"
    UTILITY_PRESERVATION = "UTILITY_PRESERVATION"
    PRIVATE_INGEST_EQUIVALENCE = "PRIVATE_INGEST_EQUIVALENCE"
    PUBLIC_CALL_RELATIONAL_PRESERVATION = "PUBLIC_CALL_RELATIONAL_PRESERVATION"
    CONTEXT_COUPLING = "CONTEXT_COUPLING"
    FINITE_PRODUCT_INDUCTION = "FINITE_PRODUCT_INDUCTION"


@dataclass(frozen=True)
class ObserverProfile:
    profile_id: str
    name: str
    visible_events: frozenset[TargetEventKind]


@dataclass(frozen=True)
class SemanticsContract:
    schema_version: str
    contract_version: int
    fingerprint: str
    observer_profiles: tuple[ObserverProfile, ...]
    direct_abstraction: tuple[tuple[TargetEventKind, SourceEventKind], ...]
    hidden_events: frozenset[TargetEventKind]
    policy_checked_events: frozenset[TargetEventKind]
    hard_fail_events: frozenset[TargetEventKind]
    context_commands: frozenset[PublicCommandKind]
    deterministic_fuel: int
    state_bound: int

    def profile(self, profile_id: str) -> ObserverProfile:
        for profile in self.observer_profiles:
            if profile.profile_id == profile_id:
                return profile
        raise KeyError(f"unknown observer profile: {profile_id}")

    def direct_source_kind(self, kind: TargetEventKind) -> SourceEventKind | None:
        for target, source in self.direct_abstraction:
            if target is kind:
                return source
        return None


@dataclass(frozen=True)
class PrivateIngest:
    history_digest: str
    action_semantics_id: str

    def __post_init__(self) -> None:
        if not self.history_digest or not self.action_semantics_id:
            raise ValueError("private ingest requires opaque history and action-semantics ids")


@dataclass(frozen=True)
class PublicCommand:
    kind: PublicCommandKind
    label: str
    payload: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.kind, PublicCommandKind):
            raise TypeError("context commands require PublicCommandKind")
        if not self.label:
            raise ValueError("public command label must not be empty")


@dataclass(frozen=True)
class SourceEvent:
    kind: SourceEventKind
    label: str
    slot: int
    value: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.kind, SourceEventKind):
            raise TypeError("source event requires SourceEventKind")
        if not self.label or self.slot < 0:
            raise ValueError("source event requires a label and non-negative slot")


@dataclass(frozen=True)
class TargetEvent:
    kind: TargetEventKind
    label: str
    slot: int
    value: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.kind, TargetEventKind):
            raise TypeError("target event requires TargetEventKind")
        if not self.label or self.slot < 0:
            raise ValueError("target event requires a label and non-negative slot")


@dataclass(frozen=True)
class ObservedEvent:
    kind: TargetEventKind
    label: str
    slot: int
    value: str


@dataclass(frozen=True)
class SourceStateRef:
    caqt_certificate_digest: str
    state_id: str
    action_semantics_id: str


@dataclass(frozen=True)
class PublicTargetState:
    digest: str


@dataclass(frozen=True)
class PrivateStateHandle:
    opaque_index: int

    def __post_init__(self) -> None:
        if self.opaque_index < 0:
            raise ValueError("private state handle must be non-negative")


@dataclass(frozen=True)
class TargetState:
    module_digest: str
    program_counter: int
    public_state: PublicTargetState
    private_state: PrivateStateHandle
    memory_pages: int
    execution_status: str
    action_semantics_id: str

    def __post_init__(self) -> None:
        if self.program_counter < 0 or self.memory_pages < 0:
            raise ValueError("target counters must be non-negative")


@dataclass(frozen=True)
class StateRelationWitness:
    source_state_id: str
    target_program_counter: int
    action_semantics_id: str
    public_state_digest: str


@dataclass(frozen=True)
class AbstractionPolicy:
    allowed_host_calls: frozenset[str] = frozenset()
    declared_traps: tuple[tuple[str, str], ...] = ()

    def source_fault_for(self, target_trap: str) -> str | None:
        for target, source in self.declared_traps:
            if target == target_trap:
                return source
        return None


@dataclass(frozen=True)
class RefinementFailure:
    code: str
    event_index: int | None
    detail: str


@dataclass(frozen=True)
class AbstractionResult:
    events: tuple[SourceEvent, ...]
    failure: RefinementFailure | None = None

    @property
    def accepted(self) -> bool:
        return self.failure is None


@dataclass(frozen=True)
class ContextTransition:
    from_state: str
    observation: tuple[ObservedEvent, ...]
    command: PublicCommand
    to_state: str

    def __post_init__(self) -> None:
        if not isinstance(self.command, PublicCommand):
            raise TypeError("private inputs cannot be context transition outputs")


@dataclass(frozen=True)
class ContextStep:
    next_state: str
    command: PublicCommand


@dataclass(frozen=True)
class ReactiveContext:
    states: frozenset[str]
    initial_state: str
    transitions: tuple[ContextTransition, ...]

    def __post_init__(self) -> None:
        if self.initial_state not in self.states:
            raise ValueError("context initial state is outside the finite state set")
        keys: set[tuple[str, tuple[ObservedEvent, ...]]] = set()
        for transition in self.transitions:
            if transition.from_state not in self.states or transition.to_state not in self.states:
                raise ValueError("context transition references an unknown state")
            key = (transition.from_state, transition.observation)
            if key in keys:
                raise ValueError("context transition relation must be deterministic")
            keys.add(key)

    def step(
        self,
        state: str,
        observation: tuple[ObservedEvent, ...],
    ) -> ContextStep | None:
        for transition in self.transitions:
            if transition.from_state == state and transition.observation == observation:
                return ContextStep(transition.to_state, transition.command)
        return None


@dataclass(frozen=True)
class ActionObligation:
    obligation_id: str
    action: str
    earliest_slot: int
    deadline_slot: int
    recovery: bool = False

    def __post_init__(self) -> None:
        if self.earliest_slot < 0 or self.deadline_slot < self.earliest_slot:
            raise ValueError("utility obligation has an invalid release window")


@dataclass(frozen=True)
class ActionEmission:
    obligation_id: str
    action: str
    slot: int


@dataclass(frozen=True)
class UtilityFailure:
    code: str
    detail: str


@dataclass(frozen=True)
class InductionObligations:
    base_case: bool
    step_closure: bool
    source_determinism: bool
    target_determinism: bool
    context_determinism: bool
    finite_state_space: bool
    resource_progress: bool

    def supports_arbitrary_call_prefix(self) -> bool:
        return all(
            (
                self.base_case,
                self.step_closure,
                self.source_determinism,
                self.target_determinism,
                self.context_determinism,
                self.finite_state_space,
                self.resource_progress,
            )
        )


@dataclass(frozen=True)
class RunEvidence:
    private_ingest: PrivateIngest
    source_trace: tuple[SourceEvent, ...]
    target_trace: tuple[TargetEvent, ...]
    obligations: tuple[ActionObligation, ...] = ()
    emissions: tuple[ActionEmission, ...] = ()
    boundary: ExecutionBoundary = ExecutionBoundary.NORMAL_RETURN


@dataclass(frozen=True)
class EvaluationResult:
    verdict: Verdict
    judgment: Judgment
    code: str
    detail: str
    observer_id: str
    left_observation: tuple[ObservedEvent, ...] = ()
    right_observation: tuple[ObservedEvent, ...] = ()
    context_command: PublicCommand | None = None


def load_semantics_contract(config_path: Path, schema_path: Path) -> SemanticsContract:
    """Load and validate the frozen semantics contract and its local JSON schema."""
    document_raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    schema_raw = json.loads(schema_path.read_text(encoding="utf-8"))
    if not isinstance(document_raw, Mapping) or not isinstance(schema_raw, Mapping):
        raise SemanticsContractError("contract and schema roots must be objects")
    document = cast(Mapping[str, object], document_raw)
    schema = cast(Mapping[str, object], schema_raw)
    schema_errors = _validate_instance(document, schema, "$")
    if schema_errors:
        raise SemanticsContractError("; ".join(schema_errors))
    semantic_errors = validate_semantics_document(document)
    if semantic_errors:
        raise SemanticsContractError("; ".join(semantic_errors))
    return _build_contract(document)


def validate_semantics_document(document: Mapping[str, object]) -> tuple[str, ...]:
    """Check cross-field invariants that JSON Schema cannot express concisely."""
    errors: list[str] = []
    event_values = set(cast(list[str], document["event_kinds"]))
    expected_events = {kind.value for kind in TargetEventKind}
    if event_values != expected_events:
        errors.append("event_kinds must enumerate the complete frozen target event alphabet")

    profiles = cast(list[Mapping[str, object]], document["observer_profiles"])
    profile_events = {
        cast(str, profile["id"]): set(cast(list[str], profile["visible_events"]))
        for profile in profiles
    }
    if set(profile_events) != {f"O{index}" for index in range(7)}:
        errors.append("observer profiles must be exactly O0 through O6")
    if profile_events.get("O6") != expected_events:
        errors.append("O6 must expose the complete declared target event alphabet")
    lower_union = set().union(*(profile_events.get(f"O{index}", set()) for index in range(5)))
    required_o5 = lower_union | {"HOST_CALL", "RESOURCE"}
    if not required_o5.issubset(profile_events.get("O5", set())):
        errors.append("O5 must combine O0-O4 plus host-call and resource events")

    capabilities = cast(Mapping[str, object], document["capabilities"])
    private_only = set(cast(list[str], capabilities["private_only"]))
    context_allowed = set(cast(list[str], capabilities["context_allowed"]))
    context_forbidden = set(cast(list[str], capabilities["context_forbidden"]))
    if private_only != {"PRIVATE_INGEST"}:
        errors.append("PRIVATE_INGEST must be the sole private-only capability")
    if private_only & context_allowed:
        errors.append("private capability cannot be context-allowed")
    if not private_only.issubset(context_forbidden):
        errors.append("private capability must be explicitly forbidden to contexts")
    if context_allowed != {kind.value for kind in PublicCommandKind}:
        errors.append("context_allowed must match the typed public command alphabet")

    abstraction = cast(Mapping[str, object], document["abstraction"])
    direct_items = cast(list[Mapping[str, str]], abstraction["direct"])
    direct = {item["target"] for item in direct_items}
    hidden = set(cast(list[str], abstraction["hidden"]))
    policy_checked = set(cast(list[str], abstraction["policy_checked"]))
    hard_fail = set(cast(list[str], abstraction["hard_fail"]))
    groups = (direct, hidden, policy_checked, hard_fail)
    if set().union(*groups) != expected_events:
        errors.append("abstraction classes must cover every target event")
    if sum(len(group) for group in groups) != len(expected_events):
        errors.append("abstraction classes must be pairwise disjoint")
    if policy_checked != {"HOST_CALL", "TRAP"}:
        errors.append("host calls and traps must remain policy-checked")
    if hard_fail != {"MEMORY_GROW", "UNKNOWN_FAILURE"}:
        errors.append("target-only memory growth and unknown failure must hard-fail")

    outcomes = cast(Mapping[str, object], document["outcomes"])
    success = set(cast(list[str], outcomes["success"]))
    counterexample = set(cast(list[str], outcomes["counterexample"]))
    inconclusive = set(cast(list[str], outcomes["inconclusive"]))
    if success != {"ACCEPT"}:
        errors.append("ACCEPT must be the only security-success outcome")
    if success & counterexample or success & inconclusive or counterexample & inconclusive:
        errors.append("outcome classes must be pairwise disjoint")

    resources = cast(Mapping[str, object], document["resource_semantics"])
    if resources["wall_clock_timing"] != "EMPIRICAL_ONLY":
        errors.append("wall-clock timing cannot be part of deterministic resource semantics")
    if resources["fuel_exhaustion"] != "INCONCLUSIVE":
        errors.append("fuel exhaustion cannot be security success")
    if resources["state_bound_exhaustion"] != "INCONCLUSIVE":
        errors.append("state-bound exhaustion cannot be security success")

    expected_induction = {
        "BASE_CASE",
        "STEP_CLOSURE",
        "SOURCE_DETERMINISM",
        "TARGET_DETERMINISM",
        "CONTEXT_DETERMINISM",
        "FINITE_STATE_SPACE",
        "RESOURCE_PROGRESS",
    }
    induction = cast(Mapping[str, object], document["induction"])
    if set(cast(list[str], induction["obligations"])) != expected_induction:
        errors.append("arbitrary-prefix induction obligations must remain complete")

    k7_boundary = cast(Mapping[str, object], document["k7_boundary"])
    if set(cast(list[int], k7_boundary["required_issues"])) != {76, 77, 88}:
        errors.append("K7 dependency gate must remain #76, #77, and #88")
    if k7_boundary["mode"] != "REFERENCE_ONLY":
        errors.append("K7 artifacts may only be referenced, never copied")
    return tuple(errors)


def semantics_fingerprint(document: Mapping[str, object]) -> str:
    """Return a domain-separated canonical digest for a validated contract document."""
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    payload = b"noticer-core/k8-semantics/v1\x00" + canonical.encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def project_trace(
    trace: Sequence[TargetEvent],
    profile: ObserverProfile,
) -> tuple[ObservedEvent, ...]:
    """Project a target trace onto one frozen observer surface."""
    return tuple(
        ObservedEvent(event.kind, event.label, event.slot, event.value)
        for event in trace
        if event.kind in profile.visible_events
    )


def abstract_target_trace(
    trace: Sequence[TargetEvent],
    contract: SemanticsContract,
    policy: AbstractionPolicy,
) -> AbstractionResult:
    """Apply the partial target-to-source abstraction without treating gaps as success."""
    events: list[SourceEvent] = []
    for index, event in enumerate(trace):
        direct = contract.direct_source_kind(event.kind)
        if direct is not None:
            events.append(SourceEvent(direct, event.label, event.slot, event.value))
            continue
        if event.kind in contract.hidden_events:
            continue
        if event.kind is TargetEventKind.HOST_CALL:
            if event.label in policy.allowed_host_calls:
                continue
            return AbstractionResult(
                tuple(events),
                RefinementFailure("EXTRA_HOST_CALL", index, event.label),
            )
        if event.kind is TargetEventKind.TRAP:
            source_fault = policy.source_fault_for(event.label)
            if source_fault is not None:
                events.append(
                    SourceEvent(SourceEventKind.PUBLIC_FAULT, source_fault, event.slot, event.value)
                )
                continue
            return AbstractionResult(
                tuple(events),
                RefinementFailure("TARGET_ONLY_TRAP", index, event.label),
            )
        if event.kind is TargetEventKind.MEMORY_GROW:
            return AbstractionResult(
                tuple(events),
                RefinementFailure("TARGET_ONLY_MEMORY_GROW", index, event.label),
            )
        if event.kind is TargetEventKind.UNKNOWN_FAILURE:
            return AbstractionResult(
                tuple(events),
                RefinementFailure("UNKNOWN_TARGET_FAILURE", index, event.label),
            )
        return AbstractionResult(
            tuple(events),
            RefinementFailure("UNDECLARED_OBSERVER_EVENT", index, event.kind.value),
        )
    return AbstractionResult(tuple(events))


def check_trace_refinement(
    source_trace: Sequence[SourceEvent],
    target_trace: Sequence[TargetEvent],
    contract: SemanticsContract,
    policy: AbstractionPolicy,
) -> RefinementFailure | None:
    """Require the abstracted target trace to equal the complete source trace."""
    abstraction = abstract_target_trace(target_trace, contract, policy)
    if abstraction.failure is not None:
        return abstraction.failure
    expected = tuple(source_trace)
    if abstraction.events == expected:
        return None
    index = _first_difference(expected, abstraction.events)
    return RefinementFailure(
        "TRACE_MISMATCH",
        index,
        "abstracted target trace differs from the source trace",
    )


def state_relation_holds(
    source: SourceStateRef,
    target: TargetState,
    witness: StateRelationWitness,
) -> bool:
    """Check one explicit source-target relational-state witness."""
    return (
        bool(source.caqt_certificate_digest)
        and source.state_id == witness.source_state_id
        and target.program_counter == witness.target_program_counter
        and source.action_semantics_id == witness.action_semantics_id
        and target.action_semantics_id == witness.action_semantics_id
        and target.public_state.digest == witness.public_state_digest
    )


def private_ingest_equivalent(
    left_ingest: PrivateIngest,
    right_ingest: PrivateIngest,
    left_target: TargetState,
    right_target: TargetState,
) -> bool:
    """Check the private-ingest two-run relation without exposing private handles."""
    return (
        left_ingest.history_digest != right_ingest.history_digest
        and left_ingest.action_semantics_id == right_ingest.action_semantics_id
        and left_target.action_semantics_id == right_target.action_semantics_id
        and left_target.action_semantics_id == left_ingest.action_semantics_id
        and left_target.public_state == right_target.public_state
    )


def public_call_relational_preserved(
    command: PublicCommand,
    left_source: SourceStateRef,
    right_source: SourceStateRef,
    left_target: TargetState,
    right_target: TargetState,
) -> bool:
    """Check preservation of the action quotient after one public call."""
    return (
        command.kind is PublicCommandKind.PUBLIC_CALL
        and left_source.action_semantics_id == right_source.action_semantics_id
        and left_target.action_semantics_id == right_target.action_semantics_id
        and left_source.action_semantics_id == left_target.action_semantics_id
        and left_target.public_state == right_target.public_state
    )


def check_utility(
    obligations: Sequence[ActionObligation],
    emissions: Sequence[ActionEmission],
) -> UtilityFailure | None:
    """Enforce authorization, exactly-once emission, deadlines, and recovery obligations."""
    by_id = {obligation.obligation_id: obligation for obligation in obligations}
    if len(by_id) != len(obligations):
        return UtilityFailure("DUPLICATE_OBLIGATION", "obligation ids must be unique")
    counts = {obligation_id: 0 for obligation_id in by_id}
    for emission in emissions:
        obligation = by_id.get(emission.obligation_id)
        if obligation is None:
            return UtilityFailure("UNAUTHORIZED_ACTION", emission.action)
        if emission.action != obligation.action:
            return UtilityFailure("ACTION_MISMATCH", emission.obligation_id)
        if not obligation.earliest_slot <= emission.slot <= obligation.deadline_slot:
            return UtilityFailure("DEADLINE_VIOLATION", emission.obligation_id)
        counts[emission.obligation_id] += 1
        if counts[emission.obligation_id] > 1:
            return UtilityFailure("DUPLICATE_ACTION", emission.obligation_id)
    for obligation_id, count in counts.items():
        if count == 0:
            obligation = by_id[obligation_id]
            code = "MISSING_RECOVERY" if obligation.recovery else "MISSING_ACTION"
            return UtilityFailure(code, obligation_id)
    return None


def evaluate_raqtr_pair(
    left: RunEvidence,
    right: RunEvidence,
    contract: SemanticsContract,
    observer_id: str,
    policy: AbstractionPolicy,
    context: ReactiveContext | None = None,
    context_state: str | None = None,
    induction: InductionObligations | None = None,
) -> EvaluationResult:
    """Evaluate one private-distinct, action-equivalent two-run RAQTR obligation."""
    profile = contract.profile(observer_id)
    if left.private_ingest.history_digest == right.private_ingest.history_digest:
        return _result(
            Verdict.INCONCLUSIVE,
            Judgment.PRIVATE_INGEST_EQUIVALENCE,
            "PRECONDITION_NOT_MET",
            "the two worlds are not private-distinct",
            observer_id,
        )
    if left.private_ingest.action_semantics_id != right.private_ingest.action_semantics_id:
        return _result(
            Verdict.INCONCLUSIVE,
            Judgment.PRIVATE_INGEST_EQUIVALENCE,
            "PRECONDITION_NOT_MET",
            "the two worlds are not action-equivalent",
            observer_id,
        )

    boundary = _inconclusive_boundary(left.boundary, right.boundary)
    if boundary is not None:
        return _result(
            Verdict.INCONCLUSIVE,
            Judgment.RAQTR,
            boundary.value,
            "execution boundary cannot establish security",
            observer_id,
        )
    if (
        ExecutionBoundary.BOUNDED_NONTERMINATION in {left.boundary, right.boundary}
        and (induction is None or not induction.supports_arbitrary_call_prefix())
    ):
        return _result(
            Verdict.INCONCLUSIVE,
            Judgment.FINITE_PRODUCT_INDUCTION,
            "INDUCTION_NOT_CLOSED",
            "a finite prefix does not establish arbitrary-prefix preservation",
            observer_id,
        )

    if left.source_trace != right.source_trace:
        return _result(
            Verdict.COUNTEREXAMPLE,
            Judgment.ROBUST_ACTION_QUOTIENT_NONINTERFERENCE,
            "SOURCE_AQNI_DIVERGENCE",
            "action-equivalent source traces diverge",
            observer_id,
        )

    for side, run in (("left", left), ("right", right)):
        failure = check_trace_refinement(run.source_trace, run.target_trace, contract, policy)
        if failure is not None:
            return _result(
                Verdict.COUNTEREXAMPLE,
                Judgment.TRACE_REFINEMENT,
                "TRACE_REFINEMENT_FAILURE",
                f"{side}: {failure.code}: {failure.detail}",
                observer_id,
            )
        utility_failure = check_utility(run.obligations, run.emissions)
        if utility_failure is not None:
            return _result(
                Verdict.COUNTEREXAMPLE,
                Judgment.UTILITY_PRESERVATION,
                "UTILITY_FAILURE",
                f"{side}: {utility_failure.code}: {utility_failure.detail}",
                observer_id,
            )

    left_observation = project_trace(left.target_trace, profile)
    right_observation = project_trace(right.target_trace, profile)
    if left_observation != right_observation:
        return EvaluationResult(
            Verdict.COUNTEREXAMPLE,
            Judgment.ROBUST_ACTION_QUOTIENT_NONINTERFERENCE,
            "OBSERVATION_DIVERGENCE",
            "observer projections differ",
            observer_id,
            left_observation,
            right_observation,
        )

    context_command = None
    if context is not None:
        if context_state is None:
            return _result(
                Verdict.INCONCLUSIVE,
                Judgment.CONTEXT_COUPLING,
                "UNKNOWN_CONTEXT_TRANSITION",
                "context state was not supplied",
                observer_id,
            )
        context_step = context.step(context_state, left_observation)
        if context_step is None:
            return _result(
                Verdict.INCONCLUSIVE,
                Judgment.CONTEXT_COUPLING,
                "UNKNOWN_CONTEXT_TRANSITION",
                "the finite context relation is not total for this observation",
                observer_id,
            )
        if context_step.command.kind not in contract.context_commands:
            return _result(
                Verdict.COUNTEREXAMPLE,
                Judgment.CONTEXT_COUPLING,
                "CONTEXT_DECOUPLING",
                "context emitted a command outside the public capability alphabet",
                observer_id,
            )
        context_command = context_step.command

    return EvaluationResult(
        Verdict.ACCEPT,
        Judgment.RAQTR,
        "ACCEPT",
        "all finite semantic obligations hold",
        observer_id,
        left_observation,
        right_observation,
        context_command,
    )


def evaluate_all_observers(
    left: RunEvidence,
    right: RunEvidence,
    contract: SemanticsContract,
    policy: AbstractionPolicy,
    induction: InductionObligations | None = None,
) -> tuple[EvaluationResult, ...]:
    """Evaluate the pair independently for every frozen O0-O6 observer."""
    return tuple(
        evaluate_raqtr_pair(
            left,
            right,
            contract,
            profile.profile_id,
            policy,
            induction=induction,
        )
        for profile in contract.observer_profiles
    )


def _build_contract(document: Mapping[str, object]) -> SemanticsContract:
    profiles_raw = cast(list[Mapping[str, object]], document["observer_profiles"])
    profiles = tuple(
        ObserverProfile(
            cast(str, item["id"]),
            cast(str, item["name"]),
            frozenset(TargetEventKind(value) for value in cast(list[str], item["visible_events"])),
        )
        for item in profiles_raw
    )
    abstraction = cast(Mapping[str, object], document["abstraction"])
    direct_raw = cast(list[Mapping[str, str]], abstraction["direct"])
    resources = cast(Mapping[str, object], document["resource_semantics"])
    capabilities = cast(Mapping[str, object], document["capabilities"])
    return SemanticsContract(
        schema_version=cast(str, document["schema_version"]),
        contract_version=cast(int, document["contract_version"]),
        fingerprint=semantics_fingerprint(document),
        observer_profiles=profiles,
        direct_abstraction=tuple(
            (TargetEventKind(item["target"]), SourceEventKind(item["source"]))
            for item in direct_raw
        ),
        hidden_events=frozenset(
            TargetEventKind(value) for value in cast(list[str], abstraction["hidden"])
        ),
        policy_checked_events=frozenset(
            TargetEventKind(value)
            for value in cast(list[str], abstraction["policy_checked"])
        ),
        hard_fail_events=frozenset(
            TargetEventKind(value) for value in cast(list[str], abstraction["hard_fail"])
        ),
        context_commands=frozenset(
            PublicCommandKind(value)
            for value in cast(list[str], capabilities["context_allowed"])
        ),
        deterministic_fuel=cast(int, resources["deterministic_fuel"]),
        state_bound=cast(int, resources["state_bound"]),
    )


def _result(
    verdict: Verdict,
    judgment: Judgment,
    code: str,
    detail: str,
    observer_id: str,
) -> EvaluationResult:
    return EvaluationResult(verdict, judgment, code, detail, observer_id)


def _inconclusive_boundary(
    left: ExecutionBoundary,
    right: ExecutionBoundary,
) -> ExecutionBoundary | None:
    inconclusive = {
        ExecutionBoundary.FUEL_EXHAUSTED,
        ExecutionBoundary.STATE_BOUND_EXHAUSTED,
        ExecutionBoundary.UNSUPPORTED_INSTRUCTION,
        ExecutionBoundary.UNKNOWN_IMPORT,
        ExecutionBoundary.PARSER_DISAGREEMENT,
    }
    for boundary in (left, right):
        if boundary in inconclusive:
            return boundary
    return None


def _first_difference(
    left: Sequence[SourceEvent],
    right: Sequence[SourceEvent],
) -> int:
    for index, pair in enumerate(zip(left, right, strict=False)):
        if pair[0] != pair[1]:
            return index
    return min(len(left), len(right))


def _validate_instance(
    instance: object,
    schema: Mapping[str, object],
    path: str,
) -> list[str]:
    errors: list[str] = []
    if "const" in schema and instance != schema["const"]:
        errors.append(f"{path}: expected constant {schema['const']!r}")
        return errors
    enum = schema.get("enum")
    if isinstance(enum, list) and instance not in enum:
        errors.append(f"{path}: value is outside the declared enum")
        return errors
    expected_type = schema.get("type")
    if isinstance(expected_type, str) and not _matches_type(instance, expected_type):
        errors.append(f"{path}: expected {expected_type}")
        return errors
    if isinstance(instance, Mapping):
        properties_raw = schema.get("properties", {})
        properties = (
            cast(Mapping[str, Mapping[str, object]], properties_raw)
            if isinstance(properties_raw, Mapping)
            else {}
        )
        required_raw = schema.get("required", [])
        required = set(required_raw) if isinstance(required_raw, list) else set()
        missing = required - set(instance)
        errors.extend(f"{path}: missing required property {name}" for name in sorted(missing))
        if schema.get("additionalProperties") is False:
            unknown = set(instance) - set(properties)
            errors.extend(f"{path}: unknown property {name}" for name in sorted(unknown))
        for name, value in instance.items():
            child_schema = properties.get(str(name))
            if child_schema is not None:
                errors.extend(_validate_instance(value, child_schema, f"{path}.{name}"))
    if isinstance(instance, list):
        minimum = schema.get("minItems")
        if isinstance(minimum, int) and len(instance) < minimum:
            errors.append(f"{path}: requires at least {minimum} items")
        if schema.get("uniqueItems") is True:
            canonical = [json.dumps(item, sort_keys=True) for item in instance]
            if len(canonical) != len(set(canonical)):
                errors.append(f"{path}: items must be unique")
        item_schema = schema.get("items")
        if isinstance(item_schema, Mapping):
            typed_item_schema = cast(Mapping[str, object], item_schema)
            for index, value in enumerate(instance):
                errors.extend(_validate_instance(value, typed_item_schema, f"{path}[{index}]"))
    minimum_value = schema.get("minimum")
    if isinstance(instance, int) and not isinstance(instance, bool):
        if isinstance(minimum_value, int) and instance < minimum_value:
            errors.append(f"{path}: must be at least {minimum_value}")
    return errors


def _matches_type(value: object, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, Mapping)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    return False
