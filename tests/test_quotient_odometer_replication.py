from __future__ import annotations

import copy
from pathlib import Path

import pytest

from noticer_core.evaluation.quotient_odometer_replication import (
    CATEGORIES,
    OdometerReplicationError,
    blank_evidence,
    build_manifest,
    evaluate,
    load_policy,
    verify_manifest,
    verify_report,
)

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "configs" / "quotient_odometer" / "go_pivot_kill_v1.yaml"


def complete():
    policy = load_policy(POLICY)
    return {
        key: {"observed": category == "GO", "evidence_sha256": f"{index + 1:064x}"}
        for category in CATEGORIES
        for index, key in enumerate(policy["criteria"][category])
    }


def test_policy_and_manifest_are_frozen_and_recomputable():
    policy = load_policy(POLICY)
    assert [len(policy["criteria"][c]) for c in CATEGORIES] == [10, 8, 10]
    manifest = build_manifest(ROOT, POLICY, "a" * 40)
    verify_manifest(ROOT, POLICY, manifest)
    changed = copy.deepcopy(manifest)
    changed["inventory"][0]["bytes"] += 1
    with pytest.raises(OdometerReplicationError, match="recomputation"):
        verify_manifest(ROOT, POLICY, changed)


def test_complete_evidence_goes():
    report = evaluate(POLICY, complete(), "b" * 64)
    assert report["decision"] == "GO"
    verify_report(report)


def test_blank_and_missing_evidence_pivot():
    assert evaluate(POLICY, blank_evidence(POLICY), "b" * 64)["decision"] == "PIVOT"
    evidence = complete()
    evidence["SCALABILITY_10000"]["observed"] = None
    assert evaluate(POLICY, evidence, "b" * 64)["decision"] == "PIVOT"


def test_kill_is_noncompensatory_and_precedes_pivot():
    evidence = complete()
    evidence["ROLLBACK_LOSES_SPEND"]["observed"] = True
    evidence["STUDIO_REDUCE"]["observed"] = True
    report = evaluate(POLICY, evidence, "b" * 64)
    assert report["decision"] == "KILL"
    assert report["triggered_kill"] == ["ROLLBACK_LOSES_SPEND"]


def test_unknown_fields_and_report_tampering_fail_closed():
    evidence = complete()
    evidence["unexpected"] = {"observed": True, "evidence_sha256": "f" * 64}
    with pytest.raises(OdometerReplicationError):
        evaluate(POLICY, evidence, "b" * 64)
    report = evaluate(POLICY, complete(), "b" * 64)
    report["decision"] = "KILL"
    with pytest.raises(OdometerReplicationError, match="digest"):
        verify_report(report)
