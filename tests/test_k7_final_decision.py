from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from noticer_core.replication.k7_final_decision import (
    K7FinalDecisionError,
    blank_evidence,
    decide,
    load_policy,
)

POLICY = Path("replication/k7_final_decision_policy_v1.json")
CONTRACT = Path("configs/quotient_forge/k7_research.yaml")


def _policy() -> dict[str, object]:
    return load_policy(POLICY, CONTRACT)


def _seal(evidence: dict[str, object]) -> None:
    import hashlib

    from noticer_core.replication.manifest import canonical_json

    unsigned = deepcopy(evidence)
    unsigned.pop("evidence_digest", None)
    domain = b"noticer-core/k7-final-decision/v1\0"
    evidence["evidence_digest"] = hashlib.sha256(domain + canonical_json(unsigned)).hexdigest()


def _go_evidence(policy: dict[str, object]) -> dict[str, object]:
    evidence = blank_evidence(policy)
    digest = "a" * 64
    for criterion in policy["criteria"]["GO"]:
        evidence["criteria"][criterion] = {"artifact_sha256": digest, "observed": True}
    for criterion in policy["criteria"]["PIVOT"] + policy["criteria"]["KILL"]:
        evidence["criteria"][criterion] = {"artifact_sha256": digest, "observed": False}
    for argument in evidence["rejection_arguments"].values():
        argument.update({"artifact_sha256": digest, "status": "ADDRESSED"})
    _seal(evidence)
    return evidence


def test_blank_evidence_is_pivot_and_never_go() -> None:
    policy = _policy()
    report = decide(policy, blank_evidence(policy))

    assert report["decision"] == "PIVOT"
    assert "independent_replication_verified" in report["unmet_go_criteria"]
    assert report["rejection_argument_counts"]["TOTAL"] == 32
    assert len(report["unresolved_rejection_arguments"]) == 32


def test_all_frozen_gates_and_arguments_are_required_for_go() -> None:
    policy = _policy()
    evidence = _go_evidence(policy)

    report = decide(policy, evidence)

    assert report["decision"] == "GO"
    assert report["unmet_go_criteria"] == []
    assert report["rejection_argument_counts"] == {
        "ADDRESSED": 32,
        "OPEN": 0,
        "TRIGGERED": 0,
        "TOTAL": 32,
    }


def test_kill_precedes_pivot_and_complete_go_evidence() -> None:
    policy = _policy()
    evidence = _go_evidence(policy)
    evidence["criteria"]["hardware_cost_not_measured"]["observed"] = True
    evidence["criteria"]["private_artifact_exposure"]["observed"] = True
    evidence["rejection_arguments"]["R10"]["status"] = "TRIGGERED"
    _seal(evidence)

    report = decide(policy, evidence)

    assert report["decision"] == "KILL"
    assert report["kill_criteria_triggered"] == ["private_artifact_exposure"]
    assert report["fatal_rejections_triggered"] == ["R10"]


def test_missing_independent_replication_alone_blocks_go() -> None:
    policy = _policy()
    evidence = _go_evidence(policy)
    evidence["criteria"]["independent_replication_verified"] = {
        "artifact_sha256": None,
        "observed": None,
    }
    _seal(evidence)

    report = decide(policy, evidence)

    assert report["decision"] == "PIVOT"
    assert report["unmet_go_criteria"] == ["independent_replication_verified"]


def test_policy_rejects_gate_drift_short_ledger_and_priority_overclaim(tmp_path: Path) -> None:
    value = json.loads(POLICY.read_text(encoding="utf-8"))
    value["frozen_gate_registry_sha256"] = "0" * 64
    altered = tmp_path / "policy.json"
    altered.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(K7FinalDecisionError, match="gate registry"):
        load_policy(altered, CONTRACT)

    value = json.loads(POLICY.read_text(encoding="utf-8"))
    value["rejection_arguments"] = value["rejection_arguments"][:24]
    altered.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(K7FinalDecisionError, match="at least 25"):
        load_policy(altered, CONTRACT)

    value = json.loads(POLICY.read_text(encoding="utf-8"))
    value["priority_wording"] = "world-first"
    altered.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(K7FinalDecisionError, match="priority wording"):
        load_policy(altered, CONTRACT)


def test_unknown_ci_green_field_cannot_enter_decision_evidence() -> None:
    policy = _policy()
    evidence = _go_evidence(policy)
    evidence["ci_green"] = True
    _seal(evidence)

    with pytest.raises(K7FinalDecisionError, match="fields"):
        decide(policy, evidence)
