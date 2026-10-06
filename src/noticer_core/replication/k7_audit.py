"""Bounded public-artifact and privacy audit for the K7 replication package."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any, Final

from noticer_core.replication.k7_bootstrap import (
    K7BootstrapError,
    load_toolchain_lock,
    verify_environment_report,
)
from noticer_core.replication.k7_publication import build_summary, publication_files
from noticer_core.replication.k7_runner import K7RunnerError, verify_run_log
from noticer_core.replication.manifest import canonical_json

POLICY_SCHEMA: Final = "noticer-core.k7-audit-policy.v1"
AUDIT_SCHEMA: Final = "noticer-core.k7-audit-report.v1"
_DIGEST_DOMAIN: Final = b"noticer-core/k7-public-audit/v1\0"
_POLICY_KEYS: Final = {
    "schema",
    "allowed_files",
    "limits",
    "prohibited_json_keys",
    "prohibited_suffixes",
    "audit_scope",
    "security_interpretation",
    "hardware_status",
}
_CREDENTIAL_PATTERNS: Final = {
    "PEM_PRIVATE_KEY": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.I),
    "GITHUB_TOKEN": re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{32,}\b"),
    "AWS_ACCESS_KEY": re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    "SECRET_ASSIGNMENT": re.compile(
        rb"\b(?:password|api[_-]?key|secret)\s*[:=]\s*[\"']?[A-Za-z0-9/+_.=-]{16,}",
        re.I,
    ),
}
_HOST_PATHS: Final = (
    re.compile(rb"[A-Za-z]:\\(?:Users|Documents and Settings)\\", re.I),
    re.compile(rb"/(?:home|Users)/[A-Za-z0-9._-]+/"),
)


class K7AuditError(ValueError):
    """Raised when a K7 audit policy cannot be interpreted safely."""


def _digest(value: object) -> str:
    return hashlib.sha256(_DIGEST_DOMAIN + canonical_json(value)).hexdigest()


def _json(path: Path, maximum: int, label: str) -> dict[str, Any]:
    if not path.is_file() or path.stat().st_size > maximum:
        raise K7AuditError(f"{label} is missing or exceeds its byte bound")
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise K7AuditError(f"{label} is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise K7AuditError(f"{label} must be an object")
    return value


def load_policy(path: Path) -> dict[str, Any]:
    """Load the exact K7 public package audit policy."""

    policy = _json(path, 256_000, "audit policy")
    if set(policy) != _POLICY_KEYS or policy["schema"] != POLICY_SCHEMA:
        raise K7AuditError("audit policy schema is invalid")
    files = policy["allowed_files"]
    if not isinstance(files, list) or not files or len(files) != len(set(files)):
        raise K7AuditError("allowed file list is invalid")
    for value in files:
        if not isinstance(value, str) or "\\" in value:
            raise K7AuditError("allowed file path is invalid")
        pure = PurePosixPath(value)
        if pure.is_absolute() or ".." in pure.parts or "." in pure.parts:
            raise K7AuditError("allowed file path is not canonical")
    limits = policy["limits"]
    if set(limits) != {"max_file_bytes", "max_total_bytes"} or not all(
        isinstance(value, int) and value > 0 for value in limits.values()
    ):
        raise K7AuditError("audit limits are invalid")
    for field in ("prohibited_json_keys", "prohibited_suffixes"):
        values = policy[field]
        if not isinstance(values, list) or not values or len(values) != len(set(values)):
            raise K7AuditError(f"{field} is invalid")
    if policy["audit_scope"] != "BOUNDED_PUBLIC_PACKAGE_AUDIT":
        raise K7AuditError("audit scope is invalid")
    if policy["security_interpretation"] != "NOT_A_SECURITY_VERDICT":
        raise K7AuditError("audit must not claim a security verdict")
    if policy["hardware_status"] != "NOT_VERIFIED":
        raise K7AuditError("hardware status must remain NOT_VERIFIED")
    return policy


def _json_keys(value: object) -> set[str]:
    found: set[str] = set()
    stack = [value]
    nodes = 0
    while stack:
        current = stack.pop()
        nodes += 1
        if nodes > 100_000:
            raise K7AuditError("JSON node bound exceeded")
        if isinstance(current, dict):
            found.update(str(key).lower() for key in current)
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)
    return found


def _finding(code: str, path: str, detail: str) -> dict[str, str]:
    return {"code": code, "detail": detail, "path": path, "severity": "ERROR"}


def audit_package(
    package_root: Path,
    policy: Mapping[str, Any],
    toolchain_lock: Mapping[str, Any],
) -> dict[str, Any]:
    """Audit exact inventory, digest chains, and bounded private-data patterns."""

    findings: list[dict[str, str]] = []
    actual = sorted(
        path.relative_to(package_root).as_posix()
        for path in package_root.rglob("*")
        if path.is_file()
    )
    allowed = sorted(policy["allowed_files"])
    for path in sorted(set(allowed) - set(actual)):
        findings.append(_finding("REQUIRED_FILE_MISSING", path, "required artifact is absent"))
    for path in sorted(set(actual) - set(allowed)):
        findings.append(_finding("UNLISTED_FILE", path, "file is outside the exact allowlist"))
    total = 0
    prohibited_keys = set(policy["prohibited_json_keys"])
    for relative in actual:
        path = package_root / PurePosixPath(relative)
        size = path.stat().st_size
        total += size
        if size > policy["limits"]["max_file_bytes"]:
            findings.append(_finding("FILE_BOUND_EXCEEDED", relative, str(size)))
            continue
        if any(relative.lower().endswith(suffix) for suffix in policy["prohibited_suffixes"]):
            findings.append(_finding("PROHIBITED_SUFFIX", relative, "credential-like suffix"))
        content = path.read_bytes()
        for pattern_id, pattern in _CREDENTIAL_PATTERNS.items():
            if pattern.search(content):
                findings.append(_finding("CREDENTIAL_PATTERN", relative, pattern_id))
        if any(pattern.search(content) for pattern in _HOST_PATHS):
            findings.append(_finding("ABSOLUTE_HOST_PATH", relative, "host-specific path"))
        if relative.endswith(".json"):
            try:
                value = json.loads(content)
            except (UnicodeDecodeError, json.JSONDecodeError):
                findings.append(_finding("JSON_INVALID", relative, "invalid UTF-8 JSON"))
                continue
            for key in sorted(_json_keys(value) & prohibited_keys):
                findings.append(_finding("PROHIBITED_JSON_KEY", relative, key))
    if total > policy["limits"]["max_total_bytes"]:
        findings.append(_finding("TOTAL_BOUND_EXCEEDED", ".", str(total)))

    if not findings:
        try:
            maximum = policy["limits"]["max_file_bytes"]
            environment = _json(
                package_root / "environment.json", maximum, "environment"
            )
            verify_environment_report(toolchain_lock, environment)
            run_log = _json(package_root / "run-log.json", maximum, "run log")
            verify_run_log(run_log)
            summary = _json(
                package_root / "publication/summary.json", maximum, "summary"
            )
            expected_summary = build_summary(run_log)
            if summary != expected_summary:
                raise K7AuditError("publication summary differs from recomputation")
            expected_files = publication_files(summary)
            manifest = _json(
                package_root / "publication/manifest.json",
                maximum,
                "publication manifest",
            )
            records = {item["path"]: item for item in manifest.get("files", [])}
            for name, expected in expected_files.items():
                record = records.get(name)
                digest = hashlib.sha256(expected).hexdigest()
                if (
                    record is None
                    or record.get("bytes") != len(expected)
                    or record.get("sha256") != digest
                ):
                    raise K7AuditError(f"publication digest mismatch: {name}")
                if (package_root / "publication" / name).read_bytes() != expected:
                    raise K7AuditError(f"publication content mismatch: {name}")
        except (K7AuditError, K7BootstrapError, K7RunnerError) as error:
            findings.append(_finding("DIGEST_CHAIN_INVALID", ".", str(error)))

    report: dict[str, Any] = {
        "audit_scope": "BOUNDED_PUBLIC_PACKAGE_AUDIT",
        "checked_files": len(actual),
        "findings": findings,
        "hardware_status": "NOT_VERIFIED",
        "release_blocker": bool(findings),
        "schema": AUDIT_SCHEMA,
        "security_interpretation": "NOT_A_SECURITY_VERDICT",
        "verdict": "FAIL" if findings else "PASS",
    }
    report["report_digest"] = _digest(report)
    return report


def main(argv: Sequence[str] | None = None) -> int:
    """Run the independent K7 public package audit."""

    parser = argparse.ArgumentParser(description="K7 public replication packageを監査する")
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--policy", type=Path, default=Path("replication/k7_audit_policy_v1.json"))
    parser.add_argument(
        "--toolchains", type=Path, default=Path("replication/k7_toolchain_lock_v1.json")
    )
    parser.add_argument("--output", type=Path, default=Path("artifacts/k7_replication/audit.json"))
    args = parser.parse_args(argv)
    report = audit_package(
        args.package,
        load_policy(args.policy),
        load_toolchain_lock(args.root, args.toolchains),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(canonical_json(report))
    return 0 if report["verdict"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
