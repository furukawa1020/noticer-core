from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from noticer_core.replication.decision import (
    AXES,
    DecisionError,
    evaluate_decision,
    load_decision_input,
    load_decision_policy,
    render_decision_markdown,
    verify_decision_report,
    write_decision_report,
)

POLICY = Path("replication/decision_policy_v1.json")


def _input() -> dict[str, object]:
    digests = {axis: f"{index + 1:064x}" for index, axis in enumerate(AXES)}
    metrics: dict[str, dict[str, int | float]] = {
        axis: {} for axis in AXES
    }
    metrics["security"] = {"invalid_cases": 0}
    metrics["utility"] = {"retention_ratio": 0.97}
    metrics["mutation"] = {"critical_escaped_mutants": 0}
    metrics["engine"] = {"disagreements": 0}
    metrics["attack"] = {"identity_advantage": 0.02}
    metrics["performance"] = {"overhead_ratio": 1.25}
    axes = {
        axis: {
            "status": "PASS",
            "artifact_sha256": digests[axis],
            "reason_codes": [],
            "metrics": metrics[axis],
        }
        for axis in AXES
    }
    return {
        "schema_version": "quotient-seal-decision-input/v1",
        "run_id": "fixed-seed-2026",
        "scope": "QUOTIENTSEAL_SOFTWARE_EVALUATION",
        "source_commit": "a" * 40,
        "hardware_status": "NOT_VERIFIED",
        "artifacts": {
            "manifest_sha256": digests["manifest"],
            "reproduction_sha256": digests["reproduction"],
            "evidence_audit_sha256": digests["evidence_audit"],
        },
        "axes": axes,
    }


def test_policy_and_input_contract_load() -> None:
    policy = load_decision_policy(POLICY)
    decision_input = load_decision_input(_input(), policy)
    assert policy["decision_precedence"] == ["KILL", "PIVOT", "GO"]
    assert decision_input["hardware_status"] == "NOT_VERIFIED"


def test_all_clear_fixture_is_deterministic_go() -> None:
    first = evaluate_decision(_input(), POLICY)
    second = evaluate_decision(_input(), POLICY)
    assert first == second
    assert first["decision"] == "GO"
    assert first["reasons"] == []
    assert first["aggregation"] == "NON_COMPENSATORY"
    verify_decision_report(first)


def test_security_failure_cannot_be_compensated_by_performance_pass() -> None:
    decision_input = _input()
    decision_input["axes"]["security"].update(
        {"status": "FAIL", "reason_codes": ["AQRS_COUNTEREXAMPLE"]}
    )
    decision_input["axes"]["performance"]["metrics"]["overhead_ratio"] = 0.1
    report = evaluate_decision(decision_input, POLICY)
    assert report["decision"] == "KILL"
    assert report["reasons"][0]["code"] == "SECURITY_STATUS_FAIL"


@pytest.mark.parametrize(
    ("axis", "metric", "value", "expected", "code"),
    [
        ("security", "invalid_cases", 1, "KILL", "SECURITY_INVALID_CASES_EXCEEDED"),
        ("utility", "retention_ratio", 0.89, "KILL", "UTILITY_RETENTION_BELOW_FLOOR"),
        ("attack", "identity_advantage", 0.051, "KILL", "IDENTITY_ADVANTAGE_ABOVE_CEILING"),
        ("mutation", "critical_escaped_mutants", 1, "PIVOT", "CRITICAL_MUTANT_ESCAPED"),
        ("engine", "disagreements", 1, "PIVOT", "ENGINE_DISAGREEMENT_OBSERVED"),
        ("performance", "overhead_ratio", 2.01, "PIVOT", "PERFORMANCE_OVERHEAD_ABOVE_BUDGET"),
    ],
)
def test_thresholds_have_predeclared_noncompensatory_effects(
    axis: str,
    metric: str,
    value: float,
    expected: str,
    code: str,
) -> None:
    decision_input = _input()
    decision_input["axes"][axis]["metrics"][metric] = value
    report = evaluate_decision(decision_input, POLICY)
    assert report["decision"] == expected
    assert code in {reason["code"] for reason in report["reasons"]}


@pytest.mark.parametrize("status", ["INCONCLUSIVE", "MISSING", "NOT_RUN", "UNSUPPORTED"])
def test_nonpass_evidence_never_becomes_go(status: str) -> None:
    decision_input = _input()
    decision_input["axes"]["ablation"].update(
        {"status": status, "reason_codes": [f"ABLATION_{status}"]}
    )
    report = evaluate_decision(decision_input, POLICY)
    assert report["decision"] == "PIVOT"


def test_unknown_fields_digest_mismatch_and_unverified_boundary_fail_closed() -> None:
    decision_input = _input()
    decision_input["private_signal"] = [1, 2, 3]
    with pytest.raises(DecisionError, match="unknown"):
        evaluate_decision(decision_input, POLICY)

    decision_input = _input()
    decision_input["artifacts"]["manifest_sha256"] = "f" * 64
    with pytest.raises(DecisionError, match="does not match"):
        evaluate_decision(decision_input, POLICY)

    decision_input = _input()
    decision_input["hardware_status"] = "VERIFIED"
    with pytest.raises(DecisionError, match="NOT_VERIFIED"):
        evaluate_decision(decision_input, POLICY)


def test_nonpass_axis_requires_explicit_reason() -> None:
    decision_input = _input()
    decision_input["axes"]["engine"]["status"] = "INCONCLUSIVE"
    with pytest.raises(DecisionError, match="needs a reason"):
        evaluate_decision(decision_input, POLICY)


def test_report_integrity_detects_tampering() -> None:
    report = evaluate_decision(_input(), POLICY)
    tampered = copy.deepcopy(report)
    tampered["decision"] = "KILL"
    with pytest.raises(DecisionError, match="SHA-256 mismatch"):
        verify_decision_report(tampered)


def test_report_writer_and_markdown_are_deterministic(tmp_path: Path) -> None:
    report = evaluate_decision(_input(), POLICY)
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    write_decision_report(report, first)
    write_decision_report(report, second)
    assert first.read_bytes() == second.read_bytes()
    assert json.loads(first.read_text(encoding="utf-8"))["decision"] == "GO"
    markdown = render_decision_markdown(report)
    assert "**GO**" in markdown
    assert "`NOT_VERIFIED`" in markdown
    assert "`NOT_A_PROOF`" in markdown


def test_sensitivity_and_falsification_conditions_are_explicit() -> None:
    report = evaluate_decision(_input(), POLICY)
    sensitivity = {
        row["condition"]: row["decision"] for row in report["sensitivity"]
    }
    assert sensitivity["security.status=FAIL"] == "KILL"
    assert sensitivity["performance.status=FAIL"] == "PIVOT"
    assert sensitivity["engine.status=INCONCLUSIVE"] == "PIVOT"
    assert "SECURITY_STATUS_FAIL" in report["falsification_conditions"]
    assert "IDENTITY_ADVANTAGE_ABOVE_CEILING" in report[
        "falsification_conditions"
    ]
