from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from noticer_core.evaluation.artifact_fuzz_replication import (
    ArtifactFuzzReplicationError,
    build_report,
    load_spec,
    minimize_case,
    verify_report,
)

SPEC = Path("configs/quotient_forge/artifact_fuzz_replication_v1.json")


def _observations(spec: dict[str, object]) -> list[dict[str, object]]:
    targets = spec["targets"]
    assert isinstance(targets, list)
    return [
        {
            "cases": [{"case_id": "seed", "input_hex": "00", "status": "PASS"}],
            "coverage_proxy": {
                "accepted_mutations": index + 3,
                "executed_cases": index + 10,
                "max_depth": index + 1,
            },
            "target_id": target["id"],
        }
        for index, target in enumerate(targets)
    ]


def test_report_is_deterministic_and_fully_recomputable() -> None:
    spec = load_spec(SPEC)
    forward = _observations(spec)
    report = build_report(spec, forward)
    reverse = build_report(spec, list(reversed(forward)))

    assert report == reverse
    assert len(report["targets"]) == 5
    assert all(target["status"] == "PASS" for target in report["targets"])
    verify_report(spec, report)


def test_statuses_remain_distinct_and_do_not_fail_open() -> None:
    spec = load_spec(SPEC)
    observations = _observations(spec)
    observations[0]["cases"] = [
        {"case_id": "pass", "input_hex": "00", "status": "PASS"},
        {"case_id": "timeout", "input_hex": "01", "status": "TIMEOUT"},
        {"case_id": "difference", "input_hex": "02", "status": "DISAGREEMENT"},
    ]

    report = build_report(spec, observations)

    target = next(item for item in report["targets"] if item["target_id"] == "dsl-import-graph")
    assert target["status"] == "DISAGREEMENT"
    assert {case["status"] for case in target["cases"]} == {
        "PASS",
        "TIMEOUT",
        "DISAGREEMENT",
    }


def test_minimizer_produces_deterministic_one_minimal_input() -> None:
    payload = b"noise!more!"

    minimized = minimize_case(payload, lambda candidate: b"!" in candidate)

    assert minimized == b"!"
    removals = (
        minimized[:index] + minimized[index + 1 :] for index in range(len(minimized))
    )
    assert all(b"!" not in candidate for candidate in removals)


def test_report_rejects_private_markers_and_absolute_paths() -> None:
    spec = load_spec(SPEC)
    observations = _observations(spec)
    observations[0]["secret"] = "not-public"
    with pytest.raises(ArtifactFuzzReplicationError):
        build_report(spec, observations)

    altered = deepcopy(spec)
    altered["targets"][0]["command"] = ["C:\\Users\\researcher\\tool.exe"]
    with pytest.raises(ArtifactFuzzReplicationError):
        build_report(altered, _observations(altered))


def test_modified_report_fails_recomputation() -> None:
    spec = load_spec(SPEC)
    report = build_report(spec, _observations(spec))
    report["targets"][0]["coverage_proxy"]["executed_cases"] += 1

    with pytest.raises(ArtifactFuzzReplicationError, match="recomputation"):
        verify_report(spec, report)
