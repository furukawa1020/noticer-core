from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
import yaml

from noticer_core.evaluation.k8_raqtr_semantics import (
    AbstractionPolicy,
    ActionEmission,
    ActionObligation,
    ContextTransition,
    EvaluationResult,
    ExecutionBoundary,
    InductionObligations,
    PrivateIngest,
    PrivateStateHandle,
    PublicCommand,
    PublicCommandKind,
    PublicTargetState,
    ReactiveContext,
    RunEvidence,
    SemanticsContract,
    SemanticsContractError,
    SourceEvent,
    SourceEventKind,
    SourceStateRef,
    StateRelationWitness,
    TargetEvent,
    TargetEventKind,
    TargetState,
    Verdict,
    evaluate_all_observers,
    evaluate_raqtr_pair,
    load_semantics_contract,
    private_ingest_equivalent,
    project_trace,
    public_call_relational_preserved,
    state_relation_holds,
)

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs" / "quotient_seal" / "k8_semantics.yaml"
SCHEMA = ROOT / "schemas" / "k8_raqtr_semantics.schema.json"


@pytest.fixture(scope="module")
def contract() -> SemanticsContract:
    return load_semantics_contract(CONFIG, SCHEMA)


def _source_trace() -> tuple[SourceEvent, ...]:
    return (
        SourceEvent(SourceEventKind.PUBLIC_CALL, "check", 0, "service-a"),
        SourceEvent(SourceEventKind.AUTHORIZED_ACTION, "notify", 2, "permit-1"),
        SourceEvent(SourceEventKind.PUBLIC_RETURN, "ok", 3),
        SourceEvent(SourceEventKind.TERMINATION, "return", 4),
    )


def _target_trace() -> tuple[TargetEvent, ...]:
    return (
        TargetEvent(TargetEventKind.API_CALL, "check", 0, "service-a"),
        TargetEvent(TargetEventKind.CONTROL, "branch.public", 1, "taken"),
        TargetEvent(TargetEventKind.ACTION, "notify", 2, "permit-1"),
        TargetEvent(TargetEventKind.API_RETURN, "ok", 3),
        TargetEvent(TargetEventKind.TERMINATION, "return", 4),
    )


def _run(
    history: str,
    *,
    boundary: ExecutionBoundary = ExecutionBoundary.NORMAL_RETURN,
) -> RunEvidence:
    return RunEvidence(
        private_ingest=PrivateIngest(history, "action-class-7"),
        source_trace=_source_trace(),
        target_trace=_target_trace(),
        obligations=(ActionObligation("permit-1", "notify", 1, 3),),
        emissions=(ActionEmission("permit-1", "notify", 2),),
        boundary=boundary,
    )


def _closed_induction() -> InductionObligations:
    return InductionObligations(True, True, True, True, True, True, True)


def test_frozen_contract_loads_with_complete_observers(contract: SemanticsContract) -> None:
    assert contract.schema_version == "k8-semantics-v1"
    assert len(contract.fingerprint) == 64
    assert [profile.profile_id for profile in contract.observer_profiles] == [
        "O0",
        "O1",
        "O2",
        "O3",
        "O4",
        "O5",
        "O6",
    ]
    assert contract.profile("O6").visible_events == frozenset(TargetEventKind)
    assert "WALL_CLOCK" not in {kind.value for kind in TargetEventKind}


def test_contract_rejects_private_context_capability(tmp_path: Path) -> None:
    document = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    document["capabilities"]["context_allowed"].append("PRIVATE_INGEST")
    mutated = tmp_path / "mutated.yaml"
    mutated.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    with pytest.raises(SemanticsContractError, match="declared enum|private capability"):
        load_semantics_contract(mutated, SCHEMA)


def test_private_ingest_is_not_a_context_command() -> None:
    private = PrivateIngest("private-a", "action-class-7")
    with pytest.raises(TypeError, match="private inputs"):
        ContextTransition("q0", (), cast(PublicCommand, private), "q0")


def test_observer_projection_preserves_only_declared_surface(
    contract: SemanticsContract,
) -> None:
    o0 = project_trace(_target_trace(), contract.profile("O0"))
    o6 = project_trace(_target_trace(), contract.profile("O6"))
    assert [event.kind for event in o0] == [
        TargetEventKind.API_CALL,
        TargetEventKind.ACTION,
        TargetEventKind.API_RETURN,
    ]
    assert TargetEventKind.CONTROL in {event.kind for event in o6}


def test_action_equivalent_private_distinct_pair_accepts_all_observers(
    contract: SemanticsContract,
) -> None:
    results = evaluate_all_observers(
        _run("private-left"),
        _run("private-right"),
        contract,
        AbstractionPolicy(),
    )
    assert len(results) == 7
    assert {result.verdict for result in results} == {Verdict.ACCEPT}


@pytest.mark.parametrize(
    ("extra_event", "failure_code"),
    [
        (TargetEvent(TargetEventKind.HOST_CALL, "host.secret", 2), "EXTRA_HOST_CALL"),
        (TargetEvent(TargetEventKind.TRAP, "unmapped", 2), "TARGET_ONLY_TRAP"),
        (TargetEvent(TargetEventKind.MEMORY_GROW, "grow", 2, "1"), "MEMORY_GROW"),
        (
            TargetEvent(TargetEventKind.UNKNOWN_FAILURE, "unknown", 2),
            "UNKNOWN_TARGET_FAILURE",
        ),
        (TargetEvent(TargetEventKind.ACTION, "extra", 2, "none"), "TRACE_MISMATCH"),
    ],
)
def test_target_only_events_fail_closed(
    contract: SemanticsContract,
    extra_event: TargetEvent,
    failure_code: str,
) -> None:
    right = _run("private-right")
    right = replace(
        right,
        target_trace=right.target_trace[:2] + (extra_event,) + right.target_trace[2:],
    )
    result = evaluate_raqtr_pair(
        _run("private-left"),
        right,
        contract,
        "O6",
        AbstractionPolicy(),
    )
    assert result.verdict is Verdict.COUNTEREXAMPLE
    assert result.code == "TRACE_REFINEMENT_FAILURE"
    assert failure_code in result.detail


@pytest.mark.parametrize(
    "boundary",
    [
        ExecutionBoundary.FUEL_EXHAUSTED,
        ExecutionBoundary.STATE_BOUND_EXHAUSTED,
        ExecutionBoundary.UNSUPPORTED_INSTRUCTION,
        ExecutionBoundary.UNKNOWN_IMPORT,
        ExecutionBoundary.PARSER_DISAGREEMENT,
    ],
)
def test_unresolved_execution_boundaries_are_inconclusive(
    contract: SemanticsContract,
    boundary: ExecutionBoundary,
) -> None:
    result = evaluate_raqtr_pair(
        _run("private-left", boundary=boundary),
        _run("private-right"),
        contract,
        "O0",
        AbstractionPolicy(),
    )
    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.code == boundary.value


def test_suppress_all_is_a_utility_counterexample(contract: SemanticsContract) -> None:
    right = replace(_run("private-right"), emissions=())
    result = evaluate_raqtr_pair(
        _run("private-left"),
        right,
        contract,
        "O0",
        AbstractionPolicy(),
    )
    assert result.verdict is Verdict.COUNTEREXAMPLE
    assert result.code == "UTILITY_FAILURE"
    assert "MISSING_ACTION" in result.detail


def test_equal_observations_couple_one_deterministic_context_step(
    contract: SemanticsContract,
) -> None:
    observation = project_trace(_target_trace(), contract.profile("O6"))
    command = PublicCommand(PublicCommandKind.PUBLIC_CALL, "next", "public")
    context = ReactiveContext(
        frozenset({"q0", "q1"}),
        "q0",
        (ContextTransition("q0", observation, command, "q1"),),
    )
    result = evaluate_raqtr_pair(
        _run("private-left"),
        _run("private-right"),
        contract,
        "O6",
        AbstractionPolicy(),
        context=context,
        context_state="q0",
    )
    assert result.verdict is Verdict.ACCEPT
    assert result.context_command == command


def test_context_automaton_rejects_nondeterminism() -> None:
    first = PublicCommand(PublicCommandKind.PUBLIC_CALL, "first")
    second = PublicCommand(PublicCommandKind.PUBLIC_CALL, "second")
    with pytest.raises(ValueError, match="deterministic"):
        ReactiveContext(
            frozenset({"q0", "q1"}),
            "q0",
            (
                ContextTransition("q0", (), first, "q0"),
                ContextTransition("q0", (), second, "q1"),
            ),
        )


def test_bounded_nontermination_requires_complete_induction(
    contract: SemanticsContract,
) -> None:
    left = _run("private-left", boundary=ExecutionBoundary.BOUNDED_NONTERMINATION)
    right = _run("private-right", boundary=ExecutionBoundary.BOUNDED_NONTERMINATION)
    incomplete = InductionObligations(True, True, True, True, True, True, False)
    inconclusive = evaluate_raqtr_pair(
        left,
        right,
        contract,
        "O0",
        AbstractionPolicy(),
        induction=incomplete,
    )
    accepted = evaluate_raqtr_pair(
        left,
        right,
        contract,
        "O0",
        AbstractionPolicy(),
        induction=_closed_induction(),
    )
    assert inconclusive.verdict is Verdict.INCONCLUSIVE
    assert inconclusive.code == "INDUCTION_NOT_CLOSED"
    assert accepted.verdict is Verdict.ACCEPT


def test_state_and_call_relations_ignore_opaque_private_handle() -> None:
    source_left = SourceStateRef("certificate", "s1", "action-class-7")
    source_right = SourceStateRef("certificate", "s9", "action-class-7")
    public = PublicTargetState("public-equal")
    target_left = TargetState(
        "module", 12, public, PrivateStateHandle(1), 2, "RUNNING", "action-class-7"
    )
    target_right = TargetState(
        "module", 12, public, PrivateStateHandle(9), 2, "RUNNING", "action-class-7"
    )
    witness = StateRelationWitness("s1", 12, "action-class-7", "public-equal")
    command = PublicCommand(PublicCommandKind.PUBLIC_CALL, "check")

    assert state_relation_holds(source_left, target_left, witness)
    assert private_ingest_equivalent(
        PrivateIngest("left", "action-class-7"),
        PrivateIngest("right", "action-class-7"),
        target_left,
        target_right,
    )
    assert public_call_relational_preserved(
        command,
        source_left,
        source_right,
        target_left,
        target_right,
    )


def test_same_private_world_is_not_reported_as_security_success(
    contract: SemanticsContract,
) -> None:
    result: EvaluationResult = evaluate_raqtr_pair(
        _run("same"),
        _run("same"),
        contract,
        "O0",
        AbstractionPolicy(),
    )
    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.code == "PRECONDITION_NOT_MET"
