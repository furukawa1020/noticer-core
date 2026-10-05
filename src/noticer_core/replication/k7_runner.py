"""Resumable, fail-closed runner for the K7 public replication DAG."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from noticer_core.replication.k7_bootstrap import inspect_environment, load_toolchain_lock
from noticer_core.replication.k7_package import build_lock, load_contract
from noticer_core.replication.manifest import canonical_json

RESULT_SCHEMA: Final = "noticer-core.k7-task-result.v1"
RUN_SCHEMA: Final = "noticer-core.k7-run-log.v1"
_DIGEST_DOMAIN: Final = b"noticer-core/k7-replication-runner/v1\0"
_SUCCESS: Final = "PASS"
_EMPTY_SHA256: Final = hashlib.sha256().hexdigest()
_RESULT_KEYS: Final = {
    "schema",
    "task_id",
    "task_digest",
    "input_digests",
    "status",
    "reason",
    "returncode",
    "output_bytes",
    "output_sha256",
    "result_digest",
}


class K7RunnerError(ValueError):
    """Raised when a saved K7 run artifact violates its contract."""


@dataclass(frozen=True)
class Execution:
    """Typed bounded process outcome used by production and test executors."""

    status: str
    reason: str
    returncode: int | None
    output_bytes: int
    output_sha256: str


Executor = Callable[[Mapping[str, Any], Path], Execution]


def _digest(value: object) -> str:
    return hashlib.sha256(_DIGEST_DOMAIN + canonical_json(value)).hexdigest()


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _terminate(process: subprocess.Popen[bytes]) -> None:
    process.kill()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.terminate()


def execute_subprocess(task: Mapping[str, Any], root: Path) -> Execution:
    """Execute argv with bounded time and captured output, never through a shell."""

    timeout = task["limits"]["timeout_seconds"]
    max_bytes = task["limits"]["max_output_bytes"]
    cwd = root if task["cwd"] == "." else root / task["cwd"]
    started = time.monotonic()
    with tempfile.NamedTemporaryFile() as output:
        try:
            process = subprocess.Popen(
                task["command"],
                cwd=cwd,
                env=os.environ.copy(),
                shell=False,
                stdout=output,
                stderr=subprocess.STDOUT,
            )
        except FileNotFoundError:
            return Execution("UNAVAILABLE", "COMMAND_NOT_FOUND", None, 0, _EMPTY_SHA256)
        except OSError:
            return Execution("FAILED", "SPAWN_ERROR", None, 0, _EMPTY_SHA256)
        status = "FAILED"
        reason = "NONZERO_EXIT"
        while process.poll() is None:
            output.flush()
            if output.tell() > max_bytes:
                _terminate(process)
                status, reason = "OUTPUT_LIMIT", "MAX_OUTPUT_BYTES_EXCEEDED"
                break
            if time.monotonic() - started > timeout:
                _terminate(process)
                status, reason = "TIMEOUT", "DEADLINE_EXCEEDED"
                break
            time.sleep(0.02)
        output.flush()
        size = output.tell()
        output.seek(0)
        digest = hashlib.sha256()
        remaining = max_bytes
        while remaining > 0 and (chunk := output.read(min(65536, remaining))):
            digest.update(chunk)
            remaining -= len(chunk)
        if status not in {"OUTPUT_LIMIT", "TIMEOUT"} and process.returncode == 0:
            status, reason = "PASS", "COMPLETED"
        return Execution(status, reason, process.returncode, size, digest.hexdigest())


def _inputs(root: Path, task: Mapping[str, Any]) -> tuple[dict[str, str], bool]:
    digests: dict[str, str] = {}
    complete = True
    for relative in task["inputs"]:
        path = root / relative
        if not path.is_file():
            digests[relative] = "MISSING"
            complete = False
        else:
            digests[relative] = _file_digest(path)
    return digests, complete


def _result(
    task_id: str,
    task_digest: str,
    input_digests: Mapping[str, str],
    execution: Execution,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "input_digests": dict(sorted(input_digests.items())),
        "output_bytes": execution.output_bytes,
        "output_sha256": execution.output_sha256,
        "reason": execution.reason,
        "returncode": execution.returncode,
        "schema": RESULT_SCHEMA,
        "status": execution.status,
        "task_digest": task_digest,
        "task_id": task_id,
    }
    result["result_digest"] = _digest(result)
    return result


def _validate_saved(
    path: Path,
    task_id: str,
    task_digest: str,
    input_digests: Mapping[str, str],
) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict) or set(value) != _RESULT_KEYS:
        return None
    stored_digest = value["result_digest"]
    unsigned = dict(value)
    unsigned.pop("result_digest")
    if (
        value["task_id"] != task_id
        or value["task_digest"] != task_digest
        or value["input_digests"] != dict(sorted(input_digests.items()))
        or stored_digest != _digest(unsigned)
    ):
        return None
    return value


def _write_outputs(root: Path, task: Mapping[str, Any], result: Mapping[str, Any]) -> None:
    encoded = canonical_json(result)
    for relative in task["outputs"]:
        output = root / relative
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(encoded)


def run_package(
    root: Path,
    contract: Mapping[str, Any],
    *,
    environment_status: str,
    executor: Executor = execute_subprocess,
    resume: bool = True,
) -> dict[str, Any]:
    """Execute a validated topological contract and preserve every failure state."""

    lock = build_lock(contract)
    task_digests = {item["id"]: item["task_digest"] for item in lock["tasks"]}
    statuses: dict[str, str] = {}
    records = []
    for task in contract["tasks"]:
        input_digests, inputs_complete = _inputs(root, task)
        dependency_failed = any(statuses.get(item) != _SUCCESS for item in task["depends_on"])
        saved = None
        if resume and inputs_complete and not dependency_failed and environment_status == "READY":
            saved = _validate_saved(
                root / task["outputs"][0],
                task["id"],
                task_digests[task["id"]],
                input_digests,
            )
        if saved is not None:
            result = saved
            reused = True
        else:
            reused = False
            if environment_status != "READY":
                execution = Execution("BLOCKED", "ENVIRONMENT_BLOCKED", None, 0, _EMPTY_SHA256)
            elif dependency_failed:
                execution = Execution("BLOCKED", "DEPENDENCY_FAILED", None, 0, _EMPTY_SHA256)
            elif not inputs_complete:
                execution = Execution("UNAVAILABLE", "INPUT_MISSING", None, 0, _EMPTY_SHA256)
            else:
                execution = executor(task, root)
            result = _result(task["id"], task_digests[task["id"]], input_digests, execution)
            _write_outputs(root, task, result)
        statuses[task["id"]] = result["status"]
        records.append({"result": result, "reused": reused})
    overall_status = (
        "PASS" if all(value == _SUCCESS for value in statuses.values()) else "FAILED"
    )
    log: dict[str, Any] = {
        "contract_digest": lock["contract_digest"],
        "environment_status": environment_status,
        "overall_status": overall_status,
        "schema": RUN_SCHEMA,
        "tasks": records,
    }
    log["run_digest"] = _digest(log)
    return log


def verify_run_log(log: Mapping[str, Any]) -> None:
    """Full-recompute a run log and every embedded task result digest."""

    if log.get("schema") != RUN_SCHEMA or not isinstance(log.get("tasks"), list):
        raise K7RunnerError("run log schema is invalid")
    for record in log["tasks"]:
        if not isinstance(record, dict) or set(record) != {"result", "reused"}:
            raise K7RunnerError("run log task record is invalid")
        result = record["result"]
        if not isinstance(result, dict) or set(result) != _RESULT_KEYS:
            raise K7RunnerError("task result schema is invalid")
        unsigned_result = dict(result)
        result_digest = unsigned_result.pop("result_digest")
        if result_digest != _digest(unsigned_result):
            raise K7RunnerError("task result digest mismatch")
    unsigned_log = dict(log)
    run_digest = unsigned_log.pop("run_digest", None)
    if run_digest != _digest(unsigned_log):
        raise K7RunnerError("run log digest mismatch")


def main(argv: Sequence[str] | None = None) -> int:
    """Inspect the environment and execute the K7 DAG with one command."""

    parser = argparse.ArgumentParser(description="K7 independent replication DAGを実行する")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument(
        "--contract", type=Path, default=Path("replication/k7_package_contract_v1.json")
    )
    parser.add_argument(
        "--toolchains", type=Path, default=Path("replication/k7_toolchain_lock_v1.json")
    )
    parser.add_argument(
        "--output", type=Path, default=Path("artifacts/k7_replication/run-log.json")
    )
    parser.add_argument("--no-resume", action="store_true")
    args = parser.parse_args(argv)
    environment = inspect_environment(load_toolchain_lock(args.root, args.toolchains))
    contract = load_contract(args.contract)
    log = run_package(
        args.root,
        contract,
        environment_status=environment["overall_status"],
        resume=not args.no_resume,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(canonical_json(log))
    return 0 if log["overall_status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
