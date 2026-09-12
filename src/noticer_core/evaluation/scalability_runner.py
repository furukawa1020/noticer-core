"""Append-only, digest-bound, resumable runner for K7 scalability schedules."""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Final

from noticer_core.evaluation.execution_protocol import (
    ExecutionProtocol,
    ScheduledRun,
    execution_protocol_sha256,
    load_execution_protocol,
)
from noticer_core.evaluation.scalability_contract import OutcomeStatus

LOCK_SCHEMA: Final = "noticer.k7.scalability-run-lock.v1"
CHECKPOINT_SCHEMA: Final = "noticer.k7.scalability-checkpoint.v1"
ZERO_DIGEST: Final = "0" * 64
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ScalabilityRunnerError(ValueError):
    """A run ledger, artifact, or resume attempt violated append-only policy."""


BackendExecutor = Callable[[ScheduledRun], Mapping[str, object]]


@dataclass(frozen=True, slots=True)
class RunnerSummary:
    """Progress from one bounded runner invocation."""

    total: int
    checkpointed: int
    executed: int
    recovered: int
    remaining: int
    complete: bool


def run_scalability(
    protocol_path: Path,
    output_root: Path,
    *,
    backend_binding_sha256: str,
    executor: BackendExecutor,
    repository_root: Path | None = None,
    resume: bool = False,
    max_runs: int | None = None,
) -> RunnerSummary:
    """Execute or resume a deterministic prefix of the frozen schedule."""

    if _SHA256.fullmatch(backend_binding_sha256) is None:
        raise ScalabilityRunnerError("backend binding digest must be lowercase SHA-256")
    if max_runs is not None and max_runs <= 0:
        raise ScalabilityRunnerError("max_runs must be positive")
    protocol = load_execution_protocol(protocol_path, repository_root=repository_root)
    protocol_digest = execution_protocol_sha256(protocol)
    lock = _lock_mapping(protocol, protocol_digest, backend_binding_sha256)
    lock_path = output_root / "run-lock.json"
    checkpoint_root = output_root / "checkpoints"
    run_root = output_root / "runs"

    if output_root.exists() and not resume:
        raise FileExistsError("scalability output exists; use resume explicitly")
    output_root.mkdir(parents=True, exist_ok=True)
    checkpoint_root.mkdir(exist_ok=True)
    run_root.mkdir(exist_ok=True)
    _write_or_verify(lock_path, lock, allow_existing=resume)

    checkpoints, previous_digest = _load_prefix(
        protocol,
        output_root,
        checkpoint_root,
        protocol_digest,
        backend_binding_sha256,
    )
    if checkpoints and not resume:
        raise ScalabilityRunnerError("existing checkpoints require explicit resume")

    executed = 0
    recovered = 0
    limit = len(protocol.schedule) if max_runs is None else max_runs
    for scheduled in protocol.schedule[len(checkpoints) :]:
        if executed + recovered >= limit:
            break
        artifact_path = run_root / scheduled.run_id / "backend.json"
        if artifact_path.exists():
            artifact = _load_json(artifact_path, "backend artifact")
            _validate_backend_artifact(artifact, scheduled)
            recovered += 1
        else:
            artifact = dict(executor(scheduled))
            _validate_backend_artifact(artifact, scheduled)
            artifact_path.parent.mkdir(parents=True, exist_ok=False)
            _write_new(artifact_path, artifact)
            executed += 1
        artifact_digest = _sha256_file(artifact_path)
        checkpoint = _checkpoint_mapping(
            scheduled,
            protocol,
            protocol_digest,
            backend_binding_sha256,
            artifact_path.relative_to(output_root),
            artifact_digest,
            str(artifact["status"]),
            previous_digest,
        )
        checkpoint_path = checkpoint_root / f"{scheduled.ordinal:04d}-{scheduled.run_id}.json"
        _write_new(checkpoint_path, checkpoint)
        previous_digest = _sha256_file(checkpoint_path)
        checkpoints.append(checkpoint)

    count = len(checkpoints)
    total = len(protocol.schedule)
    return RunnerSummary(total, count, executed, recovered, total - count, count == total)


def _load_prefix(
    protocol: ExecutionProtocol,
    output_root: Path,
    checkpoint_root: Path,
    protocol_digest: str,
    backend_binding_sha256: str,
) -> tuple[list[dict[str, Any]], str]:
    paths = sorted(checkpoint_root.glob("*.json"))
    checkpoints: list[dict[str, Any]] = []
    previous_digest = ZERO_DIGEST
    if len(paths) > len(protocol.schedule):
        raise ScalabilityRunnerError("checkpoint count exceeds schedule")
    for ordinal, path in enumerate(paths):
        scheduled = protocol.schedule[ordinal]
        expected_name = f"{ordinal:04d}-{scheduled.run_id}.json"
        if path.name != expected_name:
            raise ScalabilityRunnerError("checkpoints must form a contiguous schedule prefix")
        checkpoint = _load_json(path, "checkpoint")
        _validate_checkpoint(
            checkpoint,
            scheduled,
            protocol,
            protocol_digest,
            backend_binding_sha256,
            previous_digest,
        )
        artifact_path = _contained_path(output_root, checkpoint["backend_artifact_path"])
        if not artifact_path.is_file():
            raise ScalabilityRunnerError("checkpoint backend artifact is missing")
        if _sha256_file(artifact_path) != checkpoint["backend_artifact_sha256"]:
            raise ScalabilityRunnerError("checkpoint backend artifact digest mismatch")
        artifact = _load_json(artifact_path, "backend artifact")
        _validate_backend_artifact(artifact, scheduled)
        if artifact["status"] != checkpoint["status"]:
            raise ScalabilityRunnerError("checkpoint status differs from backend artifact")
        checkpoints.append(checkpoint)
        previous_digest = _sha256_file(path)
    return checkpoints, previous_digest


def _lock_mapping(
    protocol: ExecutionProtocol, protocol_digest: str, backend_binding_sha256: str
) -> dict[str, object]:
    return {
        "schema": LOCK_SCHEMA,
        "state": "LOCKED",
        "protocol_sha256": protocol_digest,
        "scalability_contract_sha256": protocol.scalability_contract_sha256,
        "backend_binding_sha256": backend_binding_sha256,
        "schedule_length": len(protocol.schedule),
        "replacement_policy": "REJECT",
        "artifact_policy": "GENERATED_NOT_COMMITTED",
    }


def _checkpoint_mapping(
    run: ScheduledRun,
    protocol: ExecutionProtocol,
    protocol_digest: str,
    backend_binding_sha256: str,
    artifact_path: Path,
    artifact_digest: str,
    status: str,
    previous_digest: str,
) -> dict[str, object]:
    return {
        "schema": CHECKPOINT_SCHEMA,
        "ordinal": run.ordinal,
        "run_id": run.run_id,
        "case_id": run.case_id,
        "backend_id": run.backend_id,
        "phase": run.phase.value,
        "repetition": run.repetition,
        "attempt": run.attempt,
        "seed": run.seed,
        "protocol_sha256": protocol_digest,
        "scalability_contract_sha256": protocol.scalability_contract_sha256,
        "backend_binding_sha256": backend_binding_sha256,
        "backend_artifact_path": PurePosixPath(*artifact_path.parts).as_posix(),
        "backend_artifact_sha256": artifact_digest,
        "status": status,
        "previous_checkpoint_sha256": previous_digest,
    }


def _validate_checkpoint(
    value: Mapping[str, Any],
    run: ScheduledRun,
    protocol: ExecutionProtocol,
    protocol_digest: str,
    backend_binding_sha256: str,
    previous_digest: str,
) -> None:
    expected = {
        "schema",
        "ordinal",
        "run_id",
        "case_id",
        "backend_id",
        "phase",
        "repetition",
        "attempt",
        "seed",
        "protocol_sha256",
        "scalability_contract_sha256",
        "backend_binding_sha256",
        "backend_artifact_path",
        "backend_artifact_sha256",
        "status",
        "previous_checkpoint_sha256",
    }
    if set(value) != expected:
        raise ScalabilityRunnerError("checkpoint fields differ")
    identity = (
        value["ordinal"],
        value["run_id"],
        value["case_id"],
        value["backend_id"],
        value["phase"],
        value["repetition"],
        value["attempt"],
        value["seed"],
    )
    scheduled = (
        run.ordinal,
        run.run_id,
        run.case_id,
        run.backend_id,
        run.phase.value,
        run.repetition,
        run.attempt,
        run.seed,
    )
    if identity != scheduled:
        raise ScalabilityRunnerError("checkpoint differs from frozen schedule")
    bindings = (
        value["protocol_sha256"],
        value["scalability_contract_sha256"],
        value["backend_binding_sha256"],
        value["previous_checkpoint_sha256"],
    )
    expected_bindings = (
        protocol_digest,
        protocol.scalability_contract_sha256,
        backend_binding_sha256,
        previous_digest,
    )
    if bindings != expected_bindings:
        raise ScalabilityRunnerError("checkpoint binding or hash chain mismatch")


def _validate_backend_artifact(value: Mapping[str, Any], run: ScheduledRun) -> None:
    if value.get("schema") != "noticer.k7.backend-run.v1":
        raise ScalabilityRunnerError("unsupported backend artifact schema")
    if value.get("case_id") != run.case_id or value.get("backend_id") != run.backend_id:
        raise ScalabilityRunnerError("backend artifact identity mismatch")
    try:
        OutcomeStatus(str(value.get("status")))
    except ValueError as error:
        raise ScalabilityRunnerError("backend artifact status is unsupported") from error
    if value.get("mock_result_allowed") is not False:
        raise ScalabilityRunnerError("mock backend artifact is forbidden")


def _contained_path(root: Path, relative: object) -> Path:
    if type(relative) is not str or "\\" in relative:
        raise ScalabilityRunnerError("artifact path must be portable and relative")
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts:
        raise ScalabilityRunnerError("artifact path escapes run root")
    candidate = root.joinpath(*pure.parts).resolve()
    resolved_root = root.resolve()
    if candidate != resolved_root and resolved_root not in candidate.parents:
        raise ScalabilityRunnerError("artifact path escapes run root")
    return candidate


def _write_or_verify(path: Path, value: Mapping[str, object], *, allow_existing: bool) -> None:
    payload = _canonical_json(value) + b"\n"
    if path.exists():
        if not allow_existing or path.read_bytes() != payload:
            raise ScalabilityRunnerError("run lock conflicts with current bindings")
        return
    _write_bytes_new(path, payload)


def _write_new(path: Path, value: Mapping[str, object]) -> None:
    _write_bytes_new(path, _canonical_json(value) + b"\n")


def _write_bytes_new(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as destination:
            destination.write(payload)
            destination.flush()
            os.fsync(destination.fileno())
    except FileExistsError as error:
        raise ScalabilityRunnerError(f"append-only artifact already exists: {path.name}") from error


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ScalabilityRunnerError(f"{label} is not valid UTF-8 JSON") from error
    if type(value) is not dict:
        raise ScalabilityRunnerError(f"{label} must be an object")
    return value


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")

