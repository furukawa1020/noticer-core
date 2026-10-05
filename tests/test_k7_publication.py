from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from noticer_core.replication.k7_publication import build_summary, generate_artifacts
from noticer_core.replication.k7_runner import Execution, K7RunnerError, run_package


def _contract() -> dict[str, object]:
    tasks = []
    for task_id in ("pass-case", "timeout-case", "missing-case"):
        tasks.append(
            {
                "category": "TEST",
                "command": ["unused"],
                "cwd": ".",
                "depends_on": [],
                "id": task_id,
                "inputs": [f"fixtures/{task_id}.txt"],
                "limits": {"max_output_bytes": 1024, "timeout_seconds": 1},
                "outputs": [f"artifacts/k7_replication/{task_id}/result.json"],
            }
        )
    return {
        "schema": "noticer-core.k7-package-contract.v1",
        "evidence_origin": "REPOSITORY_CONTRACT",
        "hardware_status": "NOT_VERIFIED",
        "security_interpretation": "NOT_A_SECURITY_VERDICT",
        "tasks": tasks,
    }


def _log(tmp_path: Path) -> dict[str, object]:
    contract = _contract()
    for task in contract["tasks"]:
        path = tmp_path / task["inputs"][0]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(task["id"], encoding="utf-8")

    def execute(task: dict[str, object], root: Path) -> Execution:
        del root
        outcomes = {
            "pass-case": Execution("PASS", "COMPLETED", 0, 1, "a" * 64),
            "timeout-case": Execution("TIMEOUT", "DEADLINE_EXCEEDED", None, 0, "b" * 64),
            "missing-case": Execution("UNAVAILABLE", "COMMAND_NOT_FOUND", None, 0, "c" * 64),
        }
        return outcomes[task["id"]]

    return run_package(tmp_path, contract, environment_status="READY", executor=execute)


def test_summary_keeps_every_non_success_status(tmp_path: Path) -> None:
    summary = build_summary(_log(tmp_path))

    assert summary["total_tasks"] == 3
    assert summary["status_counts"]["PASS"] == 1
    assert summary["status_counts"]["TIMEOUT"] == 1
    assert summary["status_counts"]["UNAVAILABLE"] == 1
    assert summary["status_counts"]["BLOCKED"] == 0


def test_json_csv_and_svg_are_byte_deterministic(tmp_path: Path) -> None:
    log = _log(tmp_path / "run")
    first = tmp_path / "first"
    second = tmp_path / "second"

    first_manifest = generate_artifacts(log, first)
    second_manifest = generate_artifacts(log, second)

    assert first_manifest == second_manifest
    for name in ("summary.json", "task-status.csv", "task-status.svg", "manifest.json"):
        assert (first / name).read_bytes() == (second / name).read_bytes()
    assert b"TIMEOUT" in (first / "task-status.csv").read_bytes()
    assert b"UNAVAILABLE" in (first / "task-status.svg").read_bytes()


def test_tampered_task_or_run_digest_is_rejected(tmp_path: Path) -> None:
    log = _log(tmp_path)
    tampered = deepcopy(log)
    tampered["tasks"][0]["result"]["status"] = "FAILED"
    with pytest.raises(K7RunnerError, match="task result digest"):
        build_summary(tampered)

    tampered = deepcopy(log)
    tampered["run_digest"] = "0" * 64
    with pytest.raises(K7RunnerError, match="run log digest"):
        build_summary(tampered)
