"""Offline, non-installing environment inspection for K7 replication."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import subprocess
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Final, NamedTuple

from noticer_core.replication.manifest import canonical_json

LOCK_SCHEMA: Final = "noticer-core.k7-toolchain-lock.v1"
REPORT_SCHEMA: Final = "noticer-core.k7-environment-report.v1"
_DIGEST_DOMAIN: Final = b"noticer-core/k7-toolchain-inspection/v1\0"
_LOCK_KEYS: Final = {
    "schema",
    "network_policy",
    "toolchains",
    "hardware_status",
    "security_interpretation",
}
_TOOL_KEYS: Final = {
    "argv",
    "id",
    "required_marker",
    "source",
    "version",
    "version_pattern",
}
_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")


class K7BootstrapError(ValueError):
    """Raised when a K7 toolchain lock or environment report is invalid."""


class ProbeResult(NamedTuple):
    """Bounded result returned by a toolchain version probe."""

    returncode: int
    output: str


Probe = Callable[[Sequence[str]], ProbeResult]


def _digest(value: object) -> str:
    return hashlib.sha256(_DIGEST_DOMAIN + canonical_json(value)).hexdigest()


def _exact(value: object, keys: set[str], location: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise K7BootstrapError(f"{location} fields must be exactly {sorted(keys)}")
    return value


def _bounded_string(value: object, location: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise K7BootstrapError(f"{location} must be a bounded string")
    lowered = value.lower()
    if any(marker in lowered for marker in ("secret", "subject_id", "raw_biosignal")):
        raise K7BootstrapError(f"{location} contains a private marker")
    if PurePosixPath(value).is_absolute() or PureWindowsPath(value).is_absolute():
        raise K7BootstrapError(f"{location} must not be an absolute path")
    return value


def _repository_file(root: Path, value: object, location: str) -> Path:
    relative = _bounded_string(value, location)
    if "\\" in relative or ".." in PurePosixPath(relative).parts:
        raise K7BootstrapError(f"{location} is not a canonical repository path")
    root_resolved = root.resolve(strict=True)
    try:
        resolved = (root_resolved / relative).resolve(strict=True)
    except OSError as error:
        raise K7BootstrapError(f"{location} does not exist") from error
    if root_resolved not in resolved.parents or not resolved.is_file():
        raise K7BootstrapError(f"{location} escapes the repository")
    return resolved


def load_toolchain_lock(root: Path, path: Path) -> dict[str, Any]:
    """Load pins and verify every pin against its repository provenance source."""

    raw = path.read_bytes()
    if len(raw) > 256_000:
        raise K7BootstrapError("toolchain lock exceeds byte bound")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise K7BootstrapError("toolchain lock is not valid UTF-8 JSON") from error
    lock = _exact(value, _LOCK_KEYS, "lock")
    if lock["schema"] != LOCK_SCHEMA or lock["network_policy"] != "OFFLINE_INSPECTION_ONLY":
        raise K7BootstrapError("unsupported schema or network policy")
    if lock["hardware_status"] != "NOT_VERIFIED":
        raise K7BootstrapError("hardware status must remain NOT_VERIFIED")
    if lock["security_interpretation"] != "NOT_A_SECURITY_VERDICT":
        raise K7BootstrapError("environment inspection is not a security verdict")
    tools = lock["toolchains"]
    if not isinstance(tools, list) or not 1 <= len(tools) <= 32:
        raise K7BootstrapError("toolchains must be a bounded non-empty list")
    seen: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for index, raw_tool in enumerate(tools):
        tool = _exact(raw_tool, _TOOL_KEYS, f"toolchains[{index}]")
        tool_id = tool["id"]
        if not isinstance(tool_id, str) or _ID.fullmatch(tool_id) is None or tool_id in seen:
            raise K7BootstrapError("toolchain id is invalid or duplicated")
        seen.add(tool_id)
        argv = tool["argv"]
        if not isinstance(argv, list) or not 1 <= len(argv) <= 16:
            raise K7BootstrapError(f"{tool_id}.argv must be a bounded list")
        for argument in argv:
            _bounded_string(argument, f"{tool_id}.argv")
        for field in ("version", "version_pattern", "required_marker"):
            _bounded_string(tool[field], f"{tool_id}.{field}")
        try:
            re.compile(tool["version_pattern"])
        except re.error as error:
            raise K7BootstrapError(f"{tool_id}.version_pattern is invalid") from error
        source = _repository_file(root, tool["source"], f"{tool_id}.source")
        source_bytes = source.read_bytes()
        try:
            source_text = source_bytes.decode("utf-8")
        except UnicodeDecodeError as error:
            raise K7BootstrapError(f"{tool_id}.source is not UTF-8") from error
        if tool["required_marker"] not in source_text:
            raise K7BootstrapError(f"{tool_id} pin marker is missing from source")
        normalized.append(
            {**tool, "source_sha256": hashlib.sha256(source_bytes).hexdigest()}
        )
    lock["toolchains"] = sorted(normalized, key=lambda item: item["id"])
    return lock


def subprocess_probe(argv: Sequence[str]) -> ProbeResult:
    """Run one bounded version command without shell, download, or installation."""

    try:
        completed = subprocess.run(
            list(argv),
            capture_output=True,
            check=False,
            shell=False,
            text=True,
            timeout=10,
        )
    except FileNotFoundError:
        return ProbeResult(127, "")
    except (OSError, subprocess.TimeoutExpired):
        return ProbeResult(126, "")
    output = (completed.stdout + completed.stderr)[:4096].strip()
    return ProbeResult(completed.returncode, output)


def inspect_environment(lock: dict[str, Any], probe: Probe = subprocess_probe) -> dict[str, Any]:
    """Inspect all pinned commands and return a deterministic typed status report."""

    results = []
    for tool in lock["toolchains"]:
        probed = probe(tool["argv"])
        first_line = probed.output.splitlines()[0] if probed.output else ""
        if probed.returncode == 127:
            status = "MISSING"
        elif probed.returncode != 0:
            status = "ERROR"
        elif re.search(tool["version_pattern"], first_line) is None:
            status = "MISMATCH"
        else:
            status = "MATCH"
        results.append(
            {
                "detected_version_line": first_line,
                "expected_version": tool["version"],
                "id": tool["id"],
                "source_sha256": tool["source_sha256"],
                "status": status,
            }
        )
    overall_status = (
        "READY" if all(item["status"] == "MATCH" for item in results) else "BLOCKED"
    )
    report: dict[str, Any] = {
        "hardware_status": "NOT_VERIFIED",
        "network_actions": "NONE",
        "overall_status": overall_status,
        "platform": platform.system().lower(),
        "schema": REPORT_SCHEMA,
        "security_interpretation": "NOT_A_SECURITY_VERDICT",
        "toolchain_lock_digest": _digest(lock),
        "toolchains": results,
    }
    report["report_digest"] = _digest(report)
    return report


def verify_environment_report(lock: Mapping[str, Any], report: Mapping[str, Any]) -> None:
    """Reject modified, incomplete, or lock-detached environment reports."""

    expected_keys = {
        "hardware_status",
        "network_actions",
        "overall_status",
        "platform",
        "report_digest",
        "schema",
        "security_interpretation",
        "toolchain_lock_digest",
        "toolchains",
    }
    if set(report) != expected_keys or report.get("schema") != REPORT_SCHEMA:
        raise K7BootstrapError("environment report schema is invalid")
    if report.get("toolchain_lock_digest") != _digest(lock):
        raise K7BootstrapError("environment report lock digest mismatch")
    tool_ids = [tool["id"] for tool in lock["toolchains"]]
    records = report.get("toolchains")
    if not isinstance(records, list) or [record.get("id") for record in records] != tool_ids:
        raise K7BootstrapError("environment report toolchain inventory mismatch")
    known_statuses = {"MATCH", "MISSING", "MISMATCH", "ERROR"}
    if any(record.get("status") not in known_statuses for record in records):
        raise K7BootstrapError("environment report contains an unknown status")
    unsigned = dict(report)
    report_digest = unsigned.pop("report_digest")
    if report_digest != _digest(unsigned):
        raise K7BootstrapError("environment report digest mismatch")


def main(argv: Sequence[str] | None = None) -> int:
    """Inspect the local environment and write a generated report under artifacts."""

    parser = argparse.ArgumentParser(description="K7 toolchain環境をoffline検査する")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument(
        "--lock", type=Path, default=Path("replication/k7_toolchain_lock_v1.json")
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/k7_replication/environment.json"),
    )
    args = parser.parse_args(argv)
    report = inspect_environment(load_toolchain_lock(args.root, args.lock))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(canonical_json(report))
    return 0 if report["overall_status"] == "READY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
