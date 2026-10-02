from __future__ import annotations

import copy
from pathlib import Path

import pytest

from noticer_core.evaluation.quotient_guard_replication import (
    CATEGORIES,
    GuardReplicationError,
    blank_evidence,
    build_manifest,
    evaluate,
    load_policy,
    verify_manifest,
    verify_report,
)

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "configs" / "quotient_guard" / "go_pivot_kill_v1.yaml"


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


def test_policy_and_manifest_are_frozen_and_recomputable() -> None:
    policy = load_policy(POLICY)
    assert [len(policy["criteria"][category]) for category in CATEGORIES] == [9, 7, 10]
    manifest = build_manifest(ROOT, POLICY, "a" * 40)
    verify_manifest(ROOT, POLICY, manifest)
    changed = copy.deepcopy(manifest)
    changed["inventory"][0]["sha256"] = "0" * 64
    with pytest.raises(GuardReplicationError, match="recomputation"):
        verify_manifest(ROOT, POLICY, changed)


def test_complete_evidence_goes_and_report_verifies() -> None:
    report = evaluate(POLICY, complete_evidence(), "b" * 64)
    assert report["decision"] == "GO"
    verify_report(report)


def test_blank_or_missing_evidence_pivots() -> None:
    assert evaluate(POLICY, blank_evidence(POLICY), "b" * 64)["decision"] == "PIVOT"
    evidence = complete_evidence()
    evidence["CROSS_PLATFORM_REPLAY"]["observed"] = None
    assert evaluate(POLICY, evidence, "b" * 64)["decision"] == "PIVOT"


def test_single_kill_is_noncompensatory_and_precedes_pivot() -> None:
    evidence = complete_evidence()
    evidence["PRIVATE_STATE_EXPOSED"]["observed"] = True
    evidence["RECORDED_ONLY"]["observed"] = True
    report = evaluate(POLICY, evidence, "b" * 64)
    assert report["decision"] == "KILL"
    assert report["triggered_kill"] == ["PRIVATE_STATE_EXPOSED"]


def test_unknown_private_fields_and_report_tampering_fail_closed() -> None:
    evidence = complete_evidence()
    evidence["unknown"] = {"observed": True, "evidence_sha256": "f" * 64}
    with pytest.raises(GuardReplicationError):
        evaluate(POLICY, evidence, "b" * 64)
    report = evaluate(POLICY, complete_evidence(), "b" * 64)
    report["decision"] = "KILL"
    with pytest.raises(GuardReplicationError, match="digest"):
        verify_report(report)
