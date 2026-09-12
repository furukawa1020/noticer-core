"""Uniform fail-closed adapter for real K7 solver and checker processes."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from noticer_core.evaluation.resource_accounting import (
    ProcessResourceSampler,
    ResourceMeasurement,
    build_resource_artifact,
)
from noticer_core.evaluation.scalability_contract import OutcomeStatus

SCHEMA: Final = "noticer.k7.backend-run.v1"
BACKEND_RESULT_SCHEMA: Final = "noticer.k7.backend-result.v1"
SUPPORTED_BACKENDS: Final = frozenset({"reference", "cegis", "smt", "qbf"})
_ID = re.compile(r"^[a-z][a-z0-9-]{2,95}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class BackendAdapterError(ValueError):
    """An invocation or generated backend result violated the adapter contract."""


@dataclass(frozen=True, slots=True)
class BackendInvocation:
    """One executable invocation; argv is never copied into the public artifact."""

    case_id: str
    backend_id: str
    reduction_id: str
    executable: Path
    arguments: tuple[str, ...]
    version_arguments: tuple[str, ...]
    output_root: Path
    timeout_ms: int
    memory_limit_bytes: int


def run_backend(
    invocation: BackendInvocation,
    *,
    sampler: ProcessResourceSampler | None = None,
) -> dict[str, object]:
    """Execute a real backend process and normalize only its generated evidence."""

    _validate_invocation(invocation)
    if invocation.output_root.exists():
        raise FileExistsError("backend output root already exists")
    invocation.output_root.mkdir(parents=True)
    result_path = invocation.output_root / "backend-result.json"
    stdout_path = invocation.output_root / "stdout.bin"
    stderr_path = invocation.output_root / "stderr.bin"
    arguments = tuple(
        value.replace("{result}", str(result_path)).replace("{case_id}", invocation.case_id)
        for value in invocation.arguments
    )
    version = _probe_version(invocation.executable, invocation.version_arguments)
    binary_sha256 = _sha256_file(invocation.executable)

    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        process = subprocess.Popen(
            [str(invocation.executable), *arguments],
            cwd=invocation.output_root,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            shell=False,
        )
        measurement = (sampler or ProcessResourceSampler()).measure(
            process,
            timeout_ms=invocation.timeout_ms,
        )

    status, backend_result, diagnostic = _classify(
        invocation, measurement, result_path
    )
    artifact: dict[str, object] = {
        "schema": SCHEMA,
        "case_id": invocation.case_id,
        "backend_id": invocation.backend_id,
        "reduction_id": invocation.reduction_id,
        "backend_version": version,
        "binary_sha256": binary_sha256,
        "status": status.value,
        "diagnostic": diagnostic,
        "counts": _counts(backend_result),
        "checker_verdict": (
            backend_result.get("checker_verdict", "NOT_APPLICABLE")
            if backend_result is not None
            else "NOT_APPLICABLE"
        ),
        "backend_evidence_sha256": (
            _sha256_file(result_path) if result_path.is_file() else "NOT_AVAILABLE"
        ),
        "stdout_sha256": _sha256_file(stdout_path),
        "stderr_sha256": _sha256_file(stderr_path),
        "resources": build_resource_artifact(invocation.case_id, measurement),
        "command_recorded": False,
        "mock_result_allowed": False,
    }
    return artifact


def write_backend_artifact(path: Path, artifact: Mapping[str, object]) -> Path:
    """Write a canonical adapter artifact without replacing conflicting evidence."""

    if artifact.get("schema") != SCHEMA or artifact.get("mock_result_allowed") is not False:
        raise BackendAdapterError("invalid backend artifact")
    payload = json.dumps(artifact, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    if path.exists():
        if path.read_bytes() != payload:
            raise FileExistsError("existing backend artifact differs")
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return path


def _classify(
    invocation: BackendInvocation,
    measurement: ResourceMeasurement,
    result_path: Path,
) -> tuple[OutcomeStatus, dict[str, object] | None, str | None]:
    if measurement.timed_out:
        return OutcomeStatus.TIMEOUT, None, "DIRECT_CHILD_TIMEOUT"
    if (
        measurement.peak_rss_bytes is not None
        and measurement.peak_rss_bytes > invocation.memory_limit_bytes
    ):
        return OutcomeStatus.MEMORY_LIMIT, None, "PEAK_RSS_EXCEEDED"
    if measurement.exit_code != 0:
        return OutcomeStatus.PROCESS_FAILURE, None, "NONZERO_EXIT"
    if not result_path.is_file():
        return OutcomeStatus.PROCESS_FAILURE, None, "RESULT_ARTIFACT_MISSING"
    try:
        value = json.loads(result_path.read_text(encoding="utf-8"))
        result = _validate_backend_result(value, invocation)
    except (BackendAdapterError, OSError, json.JSONDecodeError):
        return OutcomeStatus.INVALID_CASE, None, "RESULT_ARTIFACT_INVALID"
    status = OutcomeStatus(result["status"])
    return status, result, None


def _validate_backend_result(
    value: object, invocation: BackendInvocation
) -> dict[str, object]:
    if type(value) is not dict:
        raise BackendAdapterError("backend result must be a mapping")
    required = {
        "schema",
        "case_id",
        "backend_id",
        "status",
        "candidate_count",
        "checker_node_count",
        "solver_call_count",
        "checker_verdict",
        "evidence_sha256",
    }
    if set(value) != required:
        raise BackendAdapterError("backend result fields differ")
    if value["schema"] != BACKEND_RESULT_SCHEMA:
        raise BackendAdapterError("unsupported backend result schema")
    if value["case_id"] != invocation.case_id or value["backend_id"] != invocation.backend_id:
        raise BackendAdapterError("backend result identity mismatch")
    if value["status"] not in {"COMPLETED", "SOLVER_UNKNOWN", "INVALID_CASE"}:
        raise BackendAdapterError("backend cannot self-report host resource outcomes")
    for field in ("candidate_count", "checker_node_count", "solver_call_count"):
        if type(value[field]) is not int or value[field] < 0:
            raise BackendAdapterError(f"{field} must be a non-negative integer")
    if value["checker_verdict"] not in {"VERIFIED", "REJECTED", "NOT_APPLICABLE"}:
        raise BackendAdapterError("invalid checker verdict")
    if value["status"] == "COMPLETED" and value["checker_verdict"] != "VERIFIED":
        raise BackendAdapterError("COMPLETED requires independent checker verification")
    if type(value["evidence_sha256"]) is not str or _SHA256.fullmatch(
        value["evidence_sha256"]
    ) is None:
        raise BackendAdapterError("evidence_sha256 must be lowercase SHA-256")
    return value


def _counts(result: Mapping[str, object] | None) -> dict[str, int | str]:
    if result is None:
        return {
            "candidates": "NOT_AVAILABLE",
            "checker_nodes": "NOT_AVAILABLE",
            "solver_calls": "NOT_AVAILABLE",
        }
    return {
        "candidates": int(result["candidate_count"]),
        "checker_nodes": int(result["checker_node_count"]),
        "solver_calls": int(result["solver_call_count"]),
    }


def _validate_invocation(invocation: BackendInvocation) -> None:
    if _ID.fullmatch(invocation.case_id) is None:
        raise BackendAdapterError("case_id must be canonical")
    if invocation.backend_id not in SUPPORTED_BACKENDS:
        raise BackendAdapterError("unsupported backend_id")
    if _ID.fullmatch(invocation.reduction_id) is None:
        raise BackendAdapterError("reduction_id must be canonical")
    if not invocation.executable.is_file():
        raise BackendAdapterError("backend executable does not exist")
    if invocation.timeout_ms <= 0 or invocation.memory_limit_bytes <= 0:
        raise BackendAdapterError("resource limits must be positive")
    if any(type(value) is not str or not value for value in invocation.arguments):
        raise BackendAdapterError("arguments must be non-empty strings")


def _probe_version(executable: Path, arguments: Sequence[str]) -> str:
    try:
        completed = subprocess.run(
            [str(executable), *arguments],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=5,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise BackendAdapterError("backend version probe failed") from error
    output = (completed.stdout or completed.stderr).decode("utf-8", errors="replace").strip()
    if completed.returncode != 0 or not output:
        raise BackendAdapterError("backend version probe failed")
    return output.splitlines()[0][:200]


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(64 * 1024):
            digest.update(chunk)
    return digest.hexdigest()
