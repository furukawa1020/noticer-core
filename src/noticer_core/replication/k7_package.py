"""Public dependency contract for the K7 independent replication package."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Final

from noticer_core.replication.manifest import canonical_json

CONTRACT_SCHEMA: Final = "noticer-core.k7-package-contract.v1"
LOCK_SCHEMA: Final = "noticer-core.k7-package-lock.v1"
_DIGEST_DOMAIN: Final = b"noticer-core/k7-package/v1\0"
_TASK_ID: Final = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_FORBIDDEN: Final = ("secret", "subject_id", "stable_identifier", "raw_biosignal")
_CONTRACT_KEYS: Final = {
    "schema",
    "evidence_origin",
    "hardware_status",
    "security_interpretation",
    "tasks",
}
_TASK_KEYS: Final = {
    "category",
    "command",
    "cwd",
    "depends_on",
    "id",
    "inputs",
    "limits",
    "outputs",
}


class K7PackageError(ValueError):
    """Raised when the K7 public replication contract fails closed."""


def _exact(value: object, keys: set[str], location: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise K7PackageError(f"{location} fields must be exactly {sorted(keys)}")
    return value


def _public_string(value: object, location: str, *, empty: bool = False) -> str:
    if not isinstance(value, str) or (not value and not empty) or len(value) > 4096:
        raise K7PackageError(f"{location} must be a bounded public string")
    lowered = value.lower()
    if any(marker in lowered for marker in _FORBIDDEN):
        raise K7PackageError(f"{location} contains a forbidden private marker")
    if PurePosixPath(value).is_absolute() or PureWindowsPath(value).is_absolute():
        raise K7PackageError(f"{location} must not contain an absolute host path")
    return value


def _path(value: object, location: str, *, artifact: bool | None = None) -> str:
    path = _public_string(value, location)
    if "\\" in path:
        raise K7PackageError(f"{location} must use POSIX separators")
    pure = PurePosixPath(path)
    if not pure.parts or "." in pure.parts or ".." in pure.parts:
        raise K7PackageError(f"{location} is not canonical")
    is_artifact = pure.parts[0] == "artifacts"
    if artifact is not None and is_artifact is not artifact:
        expected = "artifact" if artifact else "repository"
        raise K7PackageError(f"{location} must be a {expected} path")
    return path


def _positive_int(value: object, location: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise K7PackageError(f"{location} is outside its bound")
    return value


def _digest(value: object) -> str:
    return hashlib.sha256(_DIGEST_DOMAIN + canonical_json(value)).hexdigest()


def _topological_ids(tasks: Sequence[Mapping[str, Any]]) -> list[str]:
    dependencies = {task["id"]: set(task["depends_on"]) for task in tasks}
    order: list[str] = []
    while dependencies:
        ready = sorted(task_id for task_id, deps in dependencies.items() if not deps)
        if not ready:
            raise K7PackageError("task dependency graph contains a cycle")
        order.extend(ready)
        for task_id in ready:
            dependencies.pop(task_id)
        for deps in dependencies.values():
            deps.difference_update(ready)
    return order


def load_contract(path: Path) -> dict[str, Any]:
    """Load and fully validate one bounded public K7 package contract."""

    raw = path.read_bytes()
    if len(raw) > 512_000:
        raise K7PackageError("contract exceeds byte bound")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise K7PackageError("contract is not valid UTF-8 JSON") from error
    contract = _exact(value, _CONTRACT_KEYS, "contract")
    if contract["schema"] != CONTRACT_SCHEMA:
        raise K7PackageError("unsupported contract schema")
    if contract["evidence_origin"] != "REPOSITORY_CONTRACT":
        raise K7PackageError("unexpected evidence origin")
    if contract["hardware_status"] != "NOT_VERIFIED":
        raise K7PackageError("hardware status must remain NOT_VERIFIED")
    if contract["security_interpretation"] != "NOT_A_SECURITY_VERDICT":
        raise K7PackageError("security interpretation must remain non-verdict")
    tasks = contract["tasks"]
    if not isinstance(tasks, list) or not 1 <= len(tasks) <= 64:
        raise K7PackageError("tasks must be a bounded non-empty list")
    ids: set[str] = set()
    outputs: dict[str, str] = {}
    normalized: list[dict[str, Any]] = []
    for index, raw_task in enumerate(tasks):
        task = _exact(raw_task, _TASK_KEYS, f"tasks[{index}]")
        task_id = task["id"]
        if not isinstance(task_id, str) or _TASK_ID.fullmatch(task_id) is None:
            raise K7PackageError("task id is not canonical")
        if task_id in ids:
            raise K7PackageError(f"duplicate task id: {task_id}")
        ids.add(task_id)
        _public_string(task["category"], f"{task_id}.category")
        cwd = task["cwd"]
        if cwd != ".":
            _path(cwd, f"{task_id}.cwd", artifact=False)
        command = task["command"]
        if not isinstance(command, list) or not 1 <= len(command) <= 64:
            raise K7PackageError(f"{task_id}.command must be bounded argv")
        for argument in command:
            _public_string(argument, f"{task_id}.command")
        for field in ("depends_on", "inputs", "outputs"):
            if not isinstance(task[field], list) or len(task[field]) > 128:
                raise K7PackageError(f"{task_id}.{field} must be a bounded list")
        if not task["outputs"]:
            raise K7PackageError(f"{task_id} must declare an output")
        if len(set(task["depends_on"])) != len(task["depends_on"]):
            raise K7PackageError(f"{task_id} has duplicate dependencies")
        input_paths = [_path(item, f"{task_id}.inputs") for item in task["inputs"]]
        output_paths = [
            _path(item, f"{task_id}.outputs", artifact=True) for item in task["outputs"]
        ]
        for output in output_paths:
            if output in outputs:
                raise K7PackageError(f"output has multiple producers: {output}")
            outputs[output] = task_id
        limits = _exact(task["limits"], {"max_output_bytes", "timeout_seconds"}, "limits")
        _positive_int(limits["timeout_seconds"], "timeout_seconds", 86_400)
        _positive_int(limits["max_output_bytes"], "max_output_bytes", 1_073_741_824)
        normalized.append({**task, "inputs": input_paths, "outputs": output_paths})
    by_id = {task["id"]: task for task in normalized}
    for task in normalized:
        dependencies = set(task["depends_on"])
        if task["id"] in dependencies or not dependencies <= ids:
            raise K7PackageError(f"{task['id']} has an invalid dependency")
        for input_path in task["inputs"]:
            if input_path.startswith("artifacts/"):
                producer = outputs.get(input_path)
                if producer is None or producer not in dependencies:
                    raise K7PackageError(
                        f"{task['id']} artifact input lacks a direct producer dependency"
                    )
    order = _topological_ids(normalized)
    contract["tasks"] = [by_id[task_id] for task_id in order]
    return contract


def build_lock(contract: Mapping[str, Any]) -> dict[str, Any]:
    """Build a deterministic digest lock over a validated in-memory contract."""

    contract_copy = copy.deepcopy(dict(contract))
    tasks = []
    for task in contract_copy["tasks"]:
        tasks.append({"id": task["id"], "task_digest": _digest(task)})
    lock: dict[str, Any] = {
        "contract_digest": _digest(contract_copy),
        "hardware_status": "NOT_VERIFIED",
        "schema": LOCK_SCHEMA,
        "security_interpretation": "NOT_A_SECURITY_VERDICT",
        "tasks": tasks,
    }
    lock["lock_digest"] = _digest(lock)
    return lock


def verify_lock(contract: Mapping[str, Any], lock: Mapping[str, Any]) -> None:
    """Reject any contract lock that differs from full recomputation."""

    if build_lock(contract) != lock:
        raise K7PackageError("package lock differs from full recomputation")
