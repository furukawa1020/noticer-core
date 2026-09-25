from __future__ import annotations

import copy
from pathlib import Path

import pytest

from noticer_core.evaluation.quotient_limit_replication import (
    CATEGORIES,
    QuotientLimitReplicationError,
    blank_evidence,
    build_manifest,
    evaluate_decision,
    load_policy,
    verify_decision_report,
    verify_manifest,
)

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "configs" / "quotient_limit" / "go_pivot_kill_v1.yaml"


def complete_evidence() -> dict[str, dict[str, object]]:
    policy = load_policy(POLICY)
    return {
        criterion: {
            "observed": category == "GO",
            "evidence_sha256": f"{index + 1:064x}",
        }
        for category in CATEGORIES
        for index, criterion in enumerate(policy["criteria"][category])
    }


def test_policy_freezes_exact_research_criteria() -> None:
    policy = load_policy(POLICY)
    assert [len(policy["criteria"][category]) for category in CATEGORIES] == [13, 10, 13]
    assert policy["decision_precedence"] == ["KILL", "PIVOT", "GO"]
    assert policy["hardware_status"] == "NOT_VERIFIED"


def test_manifest_is_recomputable_and_mutation_is_rejected() -> None:
    manifest = build_manifest(ROOT, POLICY, "a" * 40)
    verify_manifest(ROOT, POLICY, manifest)
    assert manifest == build_manifest(ROOT, POLICY, "a" * 40)
    tampered = copy.deepcopy(manifest)
    tampered["inventory"][0]["bytes"] += 1
    with pytest.raises(QuotientLimitReplicationError, match="recomputed"):
        verify_manifest(ROOT, POLICY, tampered)


def test_all_go_evidence_is_required_for_go() -> None:
    report = evaluate_decision(POLICY, complete_evidence(), "b" * 64)
    assert report["decision"] == "GO"
    assert report["unmet_go"] == []
    verify_decision_report(report)


def test_missing_evidence_and_pivot_signal_produce_pivot() -> None:
    evidence = complete_evidence()
    evidence["LEAN_NO_SORRY"]["observed"] = None
    assert evaluate_decision(POLICY, evidence, "b" * 64)["decision"] == "PIVOT"
    evidence = complete_evidence()
    evidence["SYNTHESIS_SCALABILITY_LIMIT"]["observed"] = True
    assert evaluate_decision(POLICY, evidence, "b" * 64)["decision"] == "PIVOT"


def test_kill_is_noncompensatory_and_has_precedence() -> None:
    evidence = complete_evidence()
    evidence["NO_EXACT_CHECKER"]["observed"] = True
    evidence["STUDIO_REDUCE"]["observed"] = True
    report = evaluate_decision(POLICY, evidence, "b" * 64)
    assert report["decision"] == "KILL"
    assert report["triggered_kill"] == ["NO_EXACT_CHECKER"]


def test_blank_run_is_explicitly_pivot_not_go() -> None:
    report = evaluate_decision(POLICY, blank_evidence(POLICY), "b" * 64)
    assert report["decision"] == "PIVOT"
    assert len(report["unmet_go"]) == 13
    assert len(report["unknown_kill"]) == 13


def test_unknown_or_private_evidence_fails_closed() -> None:
    evidence = complete_evidence()
    evidence["unexpected"] = {"observed": True, "evidence_sha256": "f" * 64}
    with pytest.raises(QuotientLimitReplicationError, match="unknown"):
        evaluate_decision(POLICY, evidence, "b" * 64)
    evidence = complete_evidence()
    evidence["LEAN_NO_SORRY"]["raw_biosignal"] = []
    with pytest.raises(QuotientLimitReplicationError, match="unknown|prohibited"):
        evaluate_decision(POLICY, evidence, "b" * 64)


def test_report_digest_rejects_decision_tampering() -> None:
    report = evaluate_decision(POLICY, complete_evidence(), "b" * 64)
    report["decision"] = "KILL"
    with pytest.raises(QuotientLimitReplicationError, match="SHA-256 mismatch"):
        verify_decision_report(report)
