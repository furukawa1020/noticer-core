"""Cross-platform, bounded QuotientSeal reproduction runner."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from noticer_core.replication.manifest import (
    ManifestError,
    build_manifest,
    canonical_json,
)

PLAN_SCHEMA = "quotient-seal.reproduction-plan.v1"
REPORT_SCHEMA = "quotient-seal.reproduction-report.v1"
MAX_PLAN_BYTES = 2 * 1024 * 1024
MAX_STEPS = 64
MAX_COMMAND_TOKENS = 64
MAX_TOKEN_CHARS = 1024
MAX_LOG_BYTES = 1024 * 1024
PROFILE_ORDER = ("smoke", "core", "full")
StepStatus = Literal[
    "PASS",
    "FAIL",
    "TIMEOUT",
    "MISSING_TOOL",
    "SKIPPED_DEPENDENCY",
    "NOT_RUN",
]
RunVerdict = Literal["PASS", "FAIL", "INCONCLUSIVE", "NOT_RUN"]

_PLAN_KEYS = {
    "schema",
    "profiles",
    "offline_environment",
    "steps",
    "evidence_origin",
    "security_interpretation",
    "hardware_status",
}
_STEP_KEYS = {
    "id",
    "phase",
    "minimum_profile",
    "command",
    "cwd",
    "timeout_seconds",
    "depends_on",
}
_ALLOWED_PHASES = {
    "MANIFEST",
    "PYTHON",
    "RUST_CONTRACT",
    "FORMAL",
    "ATTACK",
    "PERFORMANCE",
    "STUDIO",
    "WORKSPACE",
}
_ALLOWED_EXECUTABLES = {"${PYTHON}", "cargo", "npm", "lake"}
_FORBIDDEN_COMMAND_WORDS = {
    "curl",
    "wget",
    "invoke-webrequest",
    "pip install",
    "npm install",
    "npm ci",
    "cargo install",
    "git clone",
}
_SAFE_ENVIRONMENT = {
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "TEMP",
    "TMP",
    "HOME",
    "USERPROFILE",
    "LOCALAPPDATA",
    "APPDATA",
    "CARGO_HOME",
    "RUSTUP_HOME",
    "NPM_CONFIG_CACHE",
}
_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_]{1,63}$")


class ReproductionError(ValueError):
    """Raised when a reproduction plan or run fails its contract."""


def _exact_keys(value: dict[str, Any], allowed: set[str], location: str) -> None:
    unknown = set(value) - allowed
    missing = allowed - set(value)
    if unknown or missing:
        raise ReproductionError(
            f"{location} fields mismatch: unknown={sorted(unknown)}, missing={sorted(missing)}"
        )


def _canonical_cwd(value: Any) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ReproductionError("step cwd must be a non-empty POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or "." in path.parts[1:]:
        raise ReproductionError(f"step cwd is not canonical: {value}")
    return value


def _validate_command(value: Any, location: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > MAX_COMMAND_TOKENS
        or not all(isinstance(token, str) and token for token in value)
    ):
        raise ReproductionError(f"{location} must be a bounded string array")
    if value[0] not in _ALLOWED_EXECUTABLES:
        raise ReproductionError(f"{location} executable is not allowlisted")
    if any(len(token) > MAX_TOKEN_CHARS or "\x00" in token or "\n" in token for token in value):
        raise ReproductionError(f"{location} contains an invalid token")
    joined = " ".join(value).lower()
    if any(word in joined for word in _FORBIDDEN_COMMAND_WORDS):
        raise ReproductionError(f"{location} attempts a network or install operation")
    if any(token in {";", "|", "&&", "||", ">", ">>", "<"} for token in value):
        raise ReproductionError(f"{location} contains a shell control token")
    return value


def load_plan(plan_path: Path) -> dict[str, Any]:
    """Load and validate one fixed reproduction command DAG."""

    if plan_path.stat().st_size > MAX_PLAN_BYTES:
        raise ReproductionError("reproduction plan exceeds its byte bound")
    try:
        value = json.loads(plan_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReproductionError("reproduction plan is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise ReproductionError("reproduction plan must be an object")
    _exact_keys(value, _PLAN_KEYS, "plan")
    if value["schema"] != PLAN_SCHEMA or value["profiles"] != list(PROFILE_ORDER):
        raise ReproductionError("reproduction plan schema or profiles are unsupported")
    environment = value["offline_environment"]
    if not isinstance(environment, dict) or not environment:
        raise ReproductionError("offline environment must be a non-empty object")
    for name, setting in environment.items():
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(setting, str)
            or not setting
            or name.upper() != name
        ):
            raise ReproductionError("offline environment entries must be uppercase strings")
    if environment.get("CARGO_NET_OFFLINE") != "true" or environment.get("PIP_NO_INDEX") != "1":
        raise ReproductionError("offline environment must disable Cargo and pip network access")

    steps = value["steps"]
    if not isinstance(steps, list) or not steps or len(steps) > MAX_STEPS:
        raise ReproductionError("reproduction step count is outside its bound")
    seen: dict[str, int] = {}
    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            raise ReproductionError(f"steps[{index}] must be an object")
        _exact_keys(step, _STEP_KEYS, f"steps[{index}]")
        step_id = step["id"]
        if not isinstance(step_id, str) or not _ID_PATTERN.fullmatch(step_id) or step_id in seen:
            raise ReproductionError(f"steps[{index}].id is invalid or duplicated")
        seen[step_id] = index
        if step["phase"] not in _ALLOWED_PHASES:
            raise ReproductionError(f"steps[{index}].phase is unsupported")
        profile = step["minimum_profile"]
        if profile not in PROFILE_ORDER:
            raise ReproductionError(f"steps[{index}].minimum_profile is unsupported")
        _validate_command(step["command"], f"steps[{index}].command")
        _canonical_cwd(step["cwd"])
        timeout = step["timeout_seconds"]
        if not isinstance(timeout, int) or timeout < 1 or timeout > 7200:
            raise ReproductionError(f"steps[{index}].timeout_seconds is outside its bound")
        dependencies = step["depends_on"]
        if (
            not isinstance(dependencies, list)
            or len(dependencies) > 16
            or not all(isinstance(dependency, str) for dependency in dependencies)
            or len(set(dependencies)) != len(dependencies)
        ):
            raise ReproductionError(f"steps[{index}].depends_on is invalid")
        for dependency in dependencies:
            if dependency not in seen:
                raise ReproductionError(
                    f"steps[{index}] dependency must refer to an earlier step: {dependency}"
                )
            dependency_step = steps[seen[dependency]]
            if PROFILE_ORDER.index(
                dependency_step["minimum_profile"]
            ) > PROFILE_ORDER.index(profile):
                raise ReproductionError("step depends on a higher-profile step")

    if value["evidence_origin"] != "SOFTWARE_REPRODUCTION":
        raise ReproductionError("unexpected reproduction evidence origin")
    if value["security_interpretation"] != "NOT_A_SECURITY_VERDICT":
        raise ReproductionError("reproduction must not claim a security verdict")
    if value["hardware_status"] != "NOT_VERIFIED":
        raise ReproductionError("reproduction hardware status must remain NOT_VERIFIED")
    return value


def select_steps(plan: dict[str, Any], profile: str) -> list[dict[str, Any]]:
    """Select a profile's deterministic prefix-closed command graph."""

    if profile not in PROFILE_ORDER:
        raise ReproductionError(f"unknown reproduction profile: {profile}")
    rank = PROFILE_ORDER.index(profile)
    return [
        copy.deepcopy(step)
        for step in plan["steps"]
        if PROFILE_ORDER.index(step["minimum_profile"]) <= rank
    ]


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _plan_sha256(plan: dict[str, Any], profile: str, steps: list[dict[str, Any]]) -> str:
    return _sha256(
        canonical_json(
            {
                "schema": plan["schema"],
                "profile": profile,
                "offline_environment": plan["offline_environment"],
                "steps": steps,
            }
        )
    )


def _report_sha256(report: dict[str, Any]) -> str:
    unsigned = copy.deepcopy(report)
    unsigned["artifact_sha256"] = ""
    return _sha256(canonical_json(unsigned))


def derive_run_verdict(
    statuses: list[StepStatus],
    provenance_relation: str,
    dirty: bool | None,
    *,
    dry_run: bool,
) -> RunVerdict:
    """Derive one fail-closed run verdict without treating it as security evidence."""

    if dry_run:
        return "NOT_RUN"
    if provenance_relation == "NOT_DESCENDANT" or any(
        status in {"FAIL", "TIMEOUT"} for status in statuses
    ):
        return "FAIL"
    if (
        provenance_relation != "DESCENDANT_OF_BASELINE"
        or dirty is not False
        or any(status in {"MISSING_TOOL", "SKIPPED_DEPENDENCY", "NOT_RUN"} for status in statuses)
    ):
        return "INCONCLUSIVE"
    return "PASS" if statuses and all(status == "PASS" for status in statuses) else "INCONCLUSIVE"


def _base_report(
    plan: dict[str, Any],
    profile: str,
    steps: list[dict[str, Any]],
    manifest: dict[str, Any],
    mode: Literal["DRY_RUN", "EXECUTE"],
) -> dict[str, Any]:
    return {
        "schema": REPORT_SCHEMA,
        "profile": profile.upper(),
        "mode": mode,
        "offline": True,
        "plan_sha256": _plan_sha256(plan, profile, steps),
        "manifest_sha256": manifest["artifact_sha256"],
        "source": {
            "baseline_commit": manifest["repository"]["baseline_commit"],
            "revision": None,
            "relation": "NOT_CHECKED",
            "dirty": None,
        },
        "steps": [],
        "summary": {},
        "verdict": "NOT_RUN",
        "evidence_origin": plan["evidence_origin"],
        "security_interpretation": plan["security_interpretation"],
        "hardware_status": plan["hardware_status"],
        "artifact_sha256": "",
    }


def _planned_step(step: dict[str, Any]) -> dict[str, Any]:
    return {
        **step,
        "status": "NOT_RUN",
        "exit_code": None,
        "duration_ms": 0,
        "resumed": False,
        "stdout": None,
        "stderr": None,
    }


def _finalize_report(report: dict[str, Any]) -> dict[str, Any]:
    statuses = [step["status"] for step in report["steps"]]
    report["summary"] = {
        status: statuses.count(status)
        for status in (
            "PASS",
            "FAIL",
            "TIMEOUT",
            "MISSING_TOOL",
            "SKIPPED_DEPENDENCY",
            "NOT_RUN",
        )
    }
    report["artifact_sha256"] = _report_sha256(report)
    return report


def build_dry_run_report(
    root: Path,
    plan_path: Path,
    manifest_spec_path: Path,
    profile: str,
) -> dict[str, Any]:
    """Build the exact command graph without invoking any external process."""

    plan = load_plan(plan_path)
    steps = select_steps(plan, profile)
    manifest = build_manifest(root, manifest_spec_path)
    report = _base_report(plan, profile, steps, manifest, "DRY_RUN")
    report["steps"] = [_planned_step(step) for step in steps]
    report["verdict"] = derive_run_verdict(
        ["NOT_RUN" for _ in steps], "NOT_CHECKED", None, dry_run=True
    )
    return _finalize_report(report)


def _run_git(root: Path, arguments: list[str]) -> subprocess.CompletedProcess[str] | None:
    executable = shutil.which("git")
    if executable is None:
        return None
    try:
        return subprocess.run(
            [executable, *arguments],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            shell=False,
            env=_execution_environment({}),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def _source_provenance(root: Path, baseline: str) -> dict[str, Any]:
    revision = _run_git(root, ["rev-parse", "HEAD"])
    dirty = _run_git(root, ["status", "--porcelain", "--untracked-files=no"])
    ancestry = _run_git(root, ["merge-base", "--is-ancestor", baseline, "HEAD"])
    if revision is None or revision.returncode != 0:
        return {
            "baseline_commit": baseline,
            "revision": None,
            "relation": "UNRESOLVED",
            "dirty": None,
        }
    revision_value = revision.stdout.strip()
    relation = (
        "UNRESOLVED"
        if ancestry is None
        else "DESCENDANT_OF_BASELINE"
        if ancestry.returncode == 0
        else "NOT_DESCENDANT"
    )
    return {
        "baseline_commit": baseline,
        "revision": revision_value if re.fullmatch(r"[0-9a-f]{40}", revision_value) else None,
        "relation": relation,
        "dirty": None if dirty is None or dirty.returncode != 0 else bool(dirty.stdout.strip()),
    }


def _execution_environment(offline_environment: dict[str, str]) -> dict[str, str]:
    environment = {name: value for name, value in os.environ.items() if name in _SAFE_ENVIRONMENT}
    environment.update(offline_environment)
    environment.update(
        {
            "PYTHONHASHSEED": "0",
            "PYTHONUTF8": "1",
            "SOURCE_DATE_EPOCH": "0",
            "TZ": "UTC",
        }
    )
    return environment


def _resolve_executable(command: list[str]) -> list[str] | None:
    if command[0] == "${PYTHON}":
        return [sys.executable, *command[1:]]
    executable = shutil.which(command[0])
    return None if executable is None else [executable, *command[1:]]


def _redact_and_bound(value: str, root: Path) -> tuple[bytes, bool]:
    redacted = value.replace(str(root), "<REPOSITORY_ROOT>")
    redacted = redacted.replace(str(root).replace("\\", "/"), "<REPOSITORY_ROOT>")
    home = str(Path.home())
    redacted = redacted.replace(home, "<HOME>").replace(home.replace("\\", "/"), "<HOME>")
    normalized = redacted.replace("\r\n", "\n").replace("\r", "\n").encode(
        "utf-8", errors="replace"
    )
    truncated = len(normalized) > MAX_LOG_BYTES
    return normalized[:MAX_LOG_BYTES], truncated


def _write_log(
    output_dir: Path,
    step_id: str,
    stream: str,
    value: str,
    root: Path,
) -> dict[str, Any]:
    encoded, truncated = _redact_and_bound(value, root)
    relative = PurePosixPath("logs", f"{step_id}.{stream}.txt")
    path = output_dir.joinpath(*relative.parts)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encoded)
    return {
        "path": relative.as_posix(),
        "bytes": len(encoded),
        "sha256": _sha256(encoded),
        "truncated": truncated,
    }


def _execute_step(
    root: Path,
    output_dir: Path,
    step: dict[str, Any],
    environment: dict[str, str],
) -> dict[str, Any]:
    record = _planned_step(step)
    command = _resolve_executable(step["command"])
    if command is None:
        record["status"] = "MISSING_TOOL"
        return record
    cwd = root.joinpath(*PurePosixPath(step["cwd"]).parts).resolve(strict=True)
    if root.resolve() != cwd and root.resolve() not in cwd.parents:
        raise ReproductionError(f"step cwd escapes repository: {step['id']}")
    started = time.monotonic_ns()
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=step["timeout_seconds"],
            shell=False,
            env=environment,
        )
        record["status"] = "PASS" if completed.returncode == 0 else "FAIL"
        record["exit_code"] = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
    except subprocess.TimeoutExpired as error:
        record["status"] = "TIMEOUT"
        stdout = error.stdout or ""
        stderr = error.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
    except OSError as error:
        record["status"] = "MISSING_TOOL"
        stdout = ""
        stderr = f"tool execution unavailable: {type(error).__name__}\n"
    record["duration_ms"] = max(0, (time.monotonic_ns() - started) // 1_000_000)
    record["stdout"] = _write_log(output_dir, step["id"], "stdout", stdout, root)
    record["stderr"] = _write_log(output_dir, step["id"], "stderr", stderr, root)
    return record


def _resume_records(
    report_path: Path,
    plan_sha256: str,
    manifest_sha256: str,
    output_dir: Path,
) -> dict[str, dict[str, Any]]:
    if not report_path.is_file():
        return {}
    try:
        previous = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    if (
        previous.get("plan_sha256") != plan_sha256
        or previous.get("manifest_sha256") != manifest_sha256
    ):
        return {}
    records: dict[str, dict[str, Any]] = {}
    for record in previous.get("steps", []):
        if not isinstance(record, dict) or record.get("status") != "PASS":
            continue
        valid = True
        for stream in ("stdout", "stderr"):
            log = record.get(stream)
            if not isinstance(log, dict):
                valid = False
                break
            path = output_dir.joinpath(*PurePosixPath(log.get("path", "")).parts)
            if not path.is_file() or _sha256(path.read_bytes()) != log.get("sha256"):
                valid = False
                break
        if valid and isinstance(record.get("id"), str):
            records[record["id"]] = record
    return records


def run_reproduction(
    root: Path,
    plan_path: Path,
    manifest_spec_path: Path,
    output_dir: Path,
    profile: str,
    *,
    resume: bool = False,
) -> dict[str, Any]:
    """Execute a fixed profile and write a digest-linked bounded report."""

    plan = load_plan(plan_path)
    steps = select_steps(plan, profile)
    manifest = build_manifest(root, manifest_spec_path)
    report = _base_report(plan, profile, steps, manifest, "EXECUTE")
    report["source"] = _source_provenance(root, manifest["repository"]["baseline_commit"])
    report_path = output_dir / "report.json"
    resumed = (
        _resume_records(
            report_path,
            report["plan_sha256"],
            report["manifest_sha256"],
            output_dir,
        )
        if resume
        else {}
    )
    records: list[dict[str, Any]] = []
    statuses: dict[str, StepStatus] = {}
    can_execute = report["source"]["relation"] not in {"NOT_DESCENDANT", "UNRESOLVED"}
    environment = _execution_environment(plan["offline_environment"])
    for step in steps:
        dependency_failed = any(
            statuses.get(dependency) != "PASS" for dependency in step["depends_on"]
        )
        if not can_execute or dependency_failed:
            record = _planned_step(step)
            record["status"] = "SKIPPED_DEPENDENCY"
        elif step["id"] in resumed:
            record = copy.deepcopy(resumed[step["id"]])
            record["resumed"] = True
            record["duration_ms"] = 0
        else:
            record = _execute_step(root, output_dir, step, environment)
        records.append(record)
        statuses[step["id"]] = record["status"]
    report["steps"] = records
    report["verdict"] = derive_run_verdict(
        list(statuses.values()),
        report["source"]["relation"],
        report["source"]["dirty"],
        dry_run=False,
    )
    _finalize_report(report)
    write_report(report, report_path)
    return report


def write_report(report: dict[str, Any], output_path: Path) -> None:
    """Atomically write one canonical reproduction report."""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_suffix(f"{output_path.suffix}.tmp")
    temporary.write_bytes(canonical_json(report))
    temporary.replace(output_path)


def _root() -> Path:
    return Path(__file__).resolve().parents[3]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="QuotientSealを固定profileで再現する")
    parser.add_argument("--profile", choices=PROFILE_ORDER, default="smoke")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--root", type=Path, default=_root())
    parser.add_argument("--plan", type=Path, default=Path("replication/reproduction_plan_v1.json"))
    parser.add_argument(
        "--manifest-spec", type=Path, default=Path("replication/manifest_spec_v1.json")
    )
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    plan = args.plan if args.plan.is_absolute() else root / args.plan
    manifest_spec = (
        args.manifest_spec if args.manifest_spec.is_absolute() else root / args.manifest_spec
    )
    output = args.output or Path("artifacts") / "replication" / args.profile
    output = output if output.is_absolute() else root / output
    artifact_root = (root / "artifacts").resolve()
    output_resolved = output.resolve()
    if artifact_root != output_resolved and artifact_root not in output_resolved.parents:
        raise ReproductionError("CLI output must remain below artifacts/")

    if args.dry_run:
        report = build_dry_run_report(root, plan, manifest_spec, args.profile)
        write_report(report, output / "report.json")
    else:
        report = run_reproduction(
            root,
            plan,
            manifest_spec,
            output,
            args.profile,
            resume=args.resume,
        )
    print(f"profile: {report['profile']}")
    print(f"mode: {report['mode']}")
    print(f"verdict: {report['verdict']}")
    print(f"report: {output / 'report.json'}")
    print(f"sha256: {report['artifact_sha256']}")
    return 0 if report["verdict"] in {"PASS", "NOT_RUN"} else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ManifestError, ReproductionError) as error:
        print(f"reproduction error: {error}", file=sys.stderr)
        raise SystemExit(2) from error
