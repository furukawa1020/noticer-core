from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from noticer_core.evaluation.backend_adapter import (
    BackendInvocation,
    run_backend,
    write_backend_artifact,
)

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "k7_backend_run_v1.schema.json"
CASE_ID = "k7s-cegis-0123456789abcdef"


def _invocation(tmp_path: Path, code: str, *, backend: str = "cegis") -> BackendInvocation:
    return BackendInvocation(
        case_id=CASE_ID,
        backend_id=backend,
        reduction_id="symmetry-dominance-v1",
        executable=Path(sys.executable),
        arguments=("-c", code, "{result}", "{case_id}"),
        version_arguments=("--version",),
        output_root=tmp_path / "run",
        timeout_ms=5_000,
        memory_limit_bytes=512 * 1024 * 1024,
    )


def _writer_code(status: str, checker: str) -> str:
    return (
        "import json,sys;"
        "p=sys.argv[1];c=sys.argv[2];"
        "json.dump({"
        "'schema':'noticer.k7.backend-result.v1','case_id':c,'backend_id':'cegis',"
        f"'status':'{status}','candidate_count':7,'checker_node_count':19,"
        f"'solver_call_count':3,'checker_verdict':'{checker}',"
        "'evidence_sha256':'a'*64},open(p,'w',encoding='utf-8'),sort_keys=True)"
    )


def test_real_subprocess_result_is_digest_bound_and_counted(tmp_path: Path) -> None:
    artifact = run_backend(_invocation(tmp_path, _writer_code("COMPLETED", "VERIFIED")))
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert set(artifact) == set(schema["required"]) == set(schema["properties"])
    assert artifact["status"] == "COMPLETED"
    assert artifact["checker_verdict"] == "VERIFIED"
    assert artifact["counts"] == {"candidates": 7, "checker_nodes": 19, "solver_calls": 3}
    assert len(artifact["binary_sha256"]) == 64
    assert len(artifact["backend_evidence_sha256"]) == 64
    assert artifact["mock_result_allowed"] is False
    assert artifact["command_recorded"] is False


def test_completed_without_verified_checker_is_invalid_case(tmp_path: Path) -> None:
    artifact = run_backend(
        _invocation(tmp_path, _writer_code("COMPLETED", "NOT_APPLICABLE"))
    )
    assert artifact["status"] == "INVALID_CASE"
    assert artifact["diagnostic"] == "RESULT_ARTIFACT_INVALID"
    assert artifact["counts"]["candidates"] == "NOT_AVAILABLE"


def test_nonzero_process_cannot_forge_completed_result(tmp_path: Path) -> None:
    code = _writer_code("COMPLETED", "VERIFIED") + ";sys.exit(7)"
    artifact = run_backend(_invocation(tmp_path, code))
    assert artifact["status"] == "PROCESS_FAILURE"
    assert artifact["diagnostic"] == "NONZERO_EXIT"


def test_artifact_write_is_idempotent_and_conflict_safe(tmp_path: Path) -> None:
    artifact = run_backend(_invocation(tmp_path, _writer_code("SOLVER_UNKNOWN", "NOT_APPLICABLE")))
    output = tmp_path / "normalized.json"
    write_backend_artifact(output, artifact)
    original = output.read_bytes()
    write_backend_artifact(output, artifact)
    assert output.read_bytes() == original
    output.write_text("{}\n", encoding="utf-8")
    with pytest.raises(FileExistsError, match="differs"):
        write_backend_artifact(output, artifact)

