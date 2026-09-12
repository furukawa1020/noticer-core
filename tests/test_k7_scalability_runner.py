from __future__ import annotations

import json
from pathlib import Path

import pytest

from noticer_core.evaluation.scalability_runner import (
    ScalabilityRunnerError,
    run_scalability,
)

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "configs" / "quotient_forge" / "k7_execution_protocol_v1.yaml"
BINDING = "b" * 64


def _artifact(run: object) -> dict[str, object]:
    return {
        "schema": "noticer.k7.backend-run.v1",
        "case_id": run.case_id,
        "backend_id": run.backend_id,
        "status": "COMPLETED",
        "mock_result_allowed": False,
        "evidence": "public-test-evidence",
    }


def test_runner_checkpoints_a_prefix_and_resumes_without_reexecution(tmp_path: Path) -> None:
    output = tmp_path / "artifacts" / "scalability"
    first = run_scalability(
        PROTOCOL,
        output,
        backend_binding_sha256=BINDING,
        executor=_artifact,
        repository_root=ROOT,
        max_runs=3,
    )
    assert (first.checkpointed, first.executed, first.recovered, first.complete) == (3, 3, 0, False)

    calls = 0

    def counted(run: object) -> dict[str, object]:
        nonlocal calls
        calls += 1
        return _artifact(run)

    second = run_scalability(
        PROTOCOL,
        output,
        backend_binding_sha256=BINDING,
        executor=counted,
        repository_root=ROOT,
        resume=True,
        max_runs=2,
    )
    assert (second.checkpointed, second.executed, second.remaining) == (5, 2, 639)
    assert calls == 2


def test_orphan_backend_artifact_is_recovered_after_interruption(tmp_path: Path) -> None:
    output = tmp_path / "run"
    run_scalability(
        PROTOCOL,
        output,
        backend_binding_sha256=BINDING,
        executor=_artifact,
        repository_root=ROOT,
        max_runs=1,
    )
    first_checkpoint = next((output / "checkpoints").glob("*.json"))
    first_checkpoint.unlink()

    def forbidden(run: object) -> dict[str, object]:
        raise AssertionError("recovery re-executed an existing backend artifact")

    resumed = run_scalability(
        PROTOCOL,
        output,
        backend_binding_sha256=BINDING,
        executor=forbidden,
        repository_root=ROOT,
        resume=True,
        max_runs=1,
    )
    assert resumed.recovered == 1
    assert resumed.executed == 0


def test_backend_artifact_tampering_blocks_resume(tmp_path: Path) -> None:
    output = tmp_path / "run"
    run_scalability(
        PROTOCOL,
        output,
        backend_binding_sha256=BINDING,
        executor=_artifact,
        repository_root=ROOT,
        max_runs=1,
    )
    artifact = next((output / "runs").glob("*/backend.json"))
    artifact.write_text("{}\n", encoding="utf-8")
    with pytest.raises(ScalabilityRunnerError, match="digest mismatch"):
        run_scalability(
            PROTOCOL,
            output,
            backend_binding_sha256=BINDING,
            executor=_artifact,
            repository_root=ROOT,
            resume=True,
            max_runs=1,
        )


def test_binding_change_and_checkpoint_gap_are_rejected(tmp_path: Path) -> None:
    output = tmp_path / "run"
    run_scalability(
        PROTOCOL,
        output,
        backend_binding_sha256=BINDING,
        executor=_artifact,
        repository_root=ROOT,
        max_runs=2,
    )
    with pytest.raises(ScalabilityRunnerError, match="run lock conflicts"):
        run_scalability(
            PROTOCOL,
            output,
            backend_binding_sha256="c" * 64,
            executor=_artifact,
            repository_root=ROOT,
            resume=True,
            max_runs=1,
        )
    first = sorted((output / "checkpoints").glob("*.json"))[0]
    first.unlink()
    with pytest.raises(ScalabilityRunnerError, match="contiguous schedule prefix"):
        run_scalability(
            PROTOCOL,
            output,
            backend_binding_sha256=BINDING,
            executor=_artifact,
            repository_root=ROOT,
            resume=True,
            max_runs=1,
        )


def test_checkpoint_schema_and_hash_chain_are_explicit(tmp_path: Path) -> None:
    output = tmp_path / "run"
    run_scalability(
        PROTOCOL,
        output,
        backend_binding_sha256=BINDING,
        executor=_artifact,
        repository_root=ROOT,
        max_runs=2,
    )
    paths = sorted((output / "checkpoints").glob("*.json"))
    first, second = [json.loads(path.read_text(encoding="utf-8")) for path in paths]
    schema = json.loads(
        (ROOT / "schemas" / "k7_scalability_checkpoint_v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    assert set(first) == set(schema["required"]) == set(schema["properties"])
    assert first["previous_checkpoint_sha256"] == "0" * 64
    import hashlib

    assert second["previous_checkpoint_sha256"] == hashlib.sha256(paths[0].read_bytes()).hexdigest()

