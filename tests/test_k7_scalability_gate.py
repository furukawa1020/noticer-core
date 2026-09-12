from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from noticer_core.evaluation.execution_protocol import RunPhase, load_execution_protocol
from noticer_core.evaluation.scalability_contract import OutcomeStatus, load_scalability_contract
from noticer_core.evaluation.scalability_frontier import RunObservation, build_frontier_report
from noticer_core.evaluation.scalability_gate import (
    ScalabilityGateError,
    build_gate_manifest,
    load_gate_policy,
)

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "configs" / "quotient_forge" / "k7_scalability_gate_policy_v1.yaml"
BINDINGS = {name: character * 64 for name, character in zip(
    ["corpus_sha256", "split_sha256", "bound_sha256", "backend_sha256", "result_sha256"],
    "abcde",
    strict=True,
)}


def _frontier(*, missing: bool = False) -> dict[str, object]:
    contract = load_scalability_contract(
        ROOT / "configs" / "quotient_forge" / "k7_scalability_contract_v1.yaml"
    )
    protocol = load_execution_protocol(
        ROOT / "configs" / "quotient_forge" / "k7_execution_protocol_v1.yaml",
        repository_root=ROOT,
    )
    runs = [run for run in protocol.schedule if run.phase is RunPhase.MEASURED]
    if missing:
        runs = runs[1:]
    observations = [
        RunObservation(
            run.run_id,
            run.case_id,
            run.backend_id,
            run.repetition,
            OutcomeStatus.COMPLETED,
        )
        for run in runs
    ]
    return build_frontier_report(contract, protocol, observations)


def _outcomes(value: OutcomeStatus) -> dict[str, OutcomeStatus]:
    return {backend: value for backend in ("reference", "cegis", "smt", "qbf")}


def test_one_completed_backend_is_only_a_go_candidate() -> None:
    outcomes = _outcomes(OutcomeStatus.TIMEOUT)
    outcomes["cegis"] = OutcomeStatus.COMPLETED
    manifest = build_gate_manifest(
        _frontier(), outcomes, BINDINGS, policy=load_gate_policy(POLICY)
    )
    assert manifest["decision"] == "GO_CANDIDATE"
    assert manifest["deployment_generalization"] == "FORBIDDEN"
    assert manifest["hardware_status"] == "NOT_VERIFIED"


def test_all_resource_nonpractical_backends_pivot() -> None:
    outcomes = _outcomes(OutcomeStatus.TIMEOUT)
    outcomes["qbf"] = OutcomeStatus.MEMORY_LIMIT
    manifest = build_gate_manifest(
        _frontier(), outcomes, BINDINGS, policy=load_gate_policy(POLICY)
    )
    assert manifest["decision"] == "PIVOT"


@pytest.mark.parametrize(
    "blocked", [OutcomeStatus.SOLVER_UNKNOWN, OutcomeStatus.NOT_RUN, OutcomeStatus.PROCESS_FAILURE]
)
def test_inconclusive_missing_or_process_failure_blocks(blocked: OutcomeStatus) -> None:
    outcomes = _outcomes(OutcomeStatus.TIMEOUT)
    outcomes["smt"] = blocked
    manifest = build_gate_manifest(
        _frontier(), outcomes, BINDINGS, policy=load_gate_policy(POLICY)
    )
    assert manifest["decision"] == "BLOCKED"


def test_incomplete_grid_and_missing_backend_block() -> None:
    incomplete = build_gate_manifest(
        _frontier(missing=True),
        _outcomes(OutcomeStatus.COMPLETED),
        BINDINGS,
        policy=load_gate_policy(POLICY),
    )
    assert incomplete["decision"] == "BLOCKED"
    outcomes = _outcomes(OutcomeStatus.COMPLETED)
    outcomes.pop("qbf")
    missing = build_gate_manifest(
        _frontier(), outcomes, BINDINGS, policy=load_gate_policy(POLICY)
    )
    assert missing["decision"] == "BLOCKED"


def test_tampered_frontier_or_missing_binding_is_rejected() -> None:
    frontier = _frontier()
    frontier["grid_status"] = "INCOMPLETE"
    with pytest.raises(ScalabilityGateError, match="digest mismatch"):
        build_gate_manifest(
            frontier,
            _outcomes(OutcomeStatus.COMPLETED),
            BINDINGS,
            policy=load_gate_policy(POLICY),
        )
    bindings = deepcopy(BINDINGS)
    bindings.pop("split_sha256")
    with pytest.raises(ScalabilityGateError, match="digests are required"):
        build_gate_manifest(
            _frontier(),
            _outcomes(OutcomeStatus.COMPLETED),
            bindings,
            policy=load_gate_policy(POLICY),
        )


def test_manifest_matches_schema_root_and_binds_all_inputs() -> None:
    manifest = build_gate_manifest(
        _frontier(),
        _outcomes(OutcomeStatus.COMPLETED),
        BINDINGS,
        policy=load_gate_policy(POLICY),
    )
    schema = json.loads(
        (ROOT / "schemas" / "k7_scalability_gate_v1.schema.json").read_text(encoding="utf-8")
    )
    assert set(manifest) == set(schema["required"]) == set(schema["properties"])
    assert set(manifest["bindings"]) == set(BINDINGS)
    assert len(manifest["artifact_sha256"]) == 64
