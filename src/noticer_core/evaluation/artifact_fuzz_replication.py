"""Deterministic public replication reports for QuotientForge artifact fuzzing."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Final

SPEC_SCHEMA: Final = "quotient-forge-artifact-fuzz-spec/v1"
REPORT_SCHEMA: Final = "quotient-forge-artifact-fuzz-report/v1"
_DIGEST_DOMAIN: Final = b"noticer-core/quotient-forge/artifact-fuzz-report/v1\0"
_STATUSES: Final = frozenset({"PASS", "CRASH", "TIMEOUT", "DISAGREEMENT"})
_STATUS_PRIORITY: Final = {"PASS": 0, "TIMEOUT": 1, "DISAGREEMENT": 2, "CRASH": 3}
_FORBIDDEN_KEYS: Final = frozenset(
    {"secret", "private", "subject", "subject_id", "biosignal", "raw_biosignal"}
)
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_TARGET_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")


class ArtifactFuzzReplicationError(ValueError):
    """Raised when a public fuzz replication artifact violates its contract."""


def canonical_json(value: object) -> bytes:
    """Encode a JSON value in the repository's deterministic public form."""

    encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return (encoded + "\n").encode()


def _digest(value: object) -> str:
    return hashlib.sha256(_DIGEST_DOMAIN + canonical_json(value)).hexdigest()


def _object(value: object, name: str, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ArtifactFuzzReplicationError(f"{name} must contain exactly {sorted(keys)}")
    return value


def _public_string(value: object, name: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not value and not allow_empty) or len(value) > 4096:
        raise ArtifactFuzzReplicationError(f"{name} must be a bounded string")
    lowered = value.lower()
    if any(part in lowered for part in ("secret", "subject_id", "raw_biosignal")):
        raise ArtifactFuzzReplicationError(f"{name} contains a forbidden private marker")
    if PurePosixPath(value).is_absolute() or PureWindowsPath(value).is_absolute():
        raise ArtifactFuzzReplicationError(f"{name} must not contain an absolute host path")
    return value


def _bounded_int(value: object, name: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise ArtifactFuzzReplicationError(f"{name} is outside its public bound")
    return value


def _validate_public_tree(value: object, name: str = "artifact") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str) or key.lower() in _FORBIDDEN_KEYS:
                raise ArtifactFuzzReplicationError(f"{name} contains a forbidden key")
            _validate_public_tree(child, f"{name}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _validate_public_tree(child, f"{name}[{index}]")
    elif isinstance(value, str):
        _public_string(value, name, allow_empty=True)


def load_spec(path: Path) -> dict[str, Any]:
    """Load and validate the bounded, public fuzz replication specification."""

    raw = path.read_bytes()
    if len(raw) > 256_000:
        raise ArtifactFuzzReplicationError("spec exceeds byte bound")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ArtifactFuzzReplicationError("spec is not valid UTF-8 JSON") from error
    spec = _object(value, "spec", {"schema", "seed", "targets"})
    if spec["schema"] != SPEC_SCHEMA or not isinstance(spec["seed"], str):
        raise ArtifactFuzzReplicationError("unsupported schema or seed")
    if _HEX_64.fullmatch(spec["seed"]) is None:
        raise ArtifactFuzzReplicationError("seed must be 32 lowercase hexadecimal bytes")
    targets = spec["targets"]
    if not isinstance(targets, list) or not 1 <= len(targets) <= 32:
        raise ArtifactFuzzReplicationError("targets must be a bounded non-empty list")
    seen: set[str] = set()
    for index, value in enumerate(targets):
        target = _object(value, f"targets[{index}]", {"command", "corpus", "id", "limits"})
        target_id = target["id"]
        if not isinstance(target_id, str) or _TARGET_ID.fullmatch(target_id) is None:
            raise ArtifactFuzzReplicationError("target id is not canonical")
        if target_id in seen:
            raise ArtifactFuzzReplicationError("target ids must be unique")
        seen.add(target_id)
        command = target["command"]
        if not isinstance(command, list) or not 1 <= len(command) <= 32:
            raise ArtifactFuzzReplicationError("command must be a bounded argv list")
        for argument in command:
            _public_string(argument, "command argument")
        limits = _object(
            target["limits"], "limits", {"max_bytes", "max_cases", "timeout_seconds"}
        )
        _bounded_int(limits["max_bytes"], "max_bytes", 1_048_576)
        _bounded_int(limits["max_cases"], "max_cases", 100_000)
        _bounded_int(limits["timeout_seconds"], "timeout_seconds", 600)
        corpus = target["corpus"]
        if not isinstance(corpus, list) or len(corpus) > limits["max_cases"]:
            raise ArtifactFuzzReplicationError("corpus exceeds case bound")
        for case_value in corpus:
            case = _object(case_value, "corpus case", {"case_id", "expected_status", "input_hex"})
            _public_string(case["case_id"], "case_id")
            if case["expected_status"] not in _STATUSES:
                raise ArtifactFuzzReplicationError("unknown expected status")
            try:
                payload = bytes.fromhex(case["input_hex"])
            except (TypeError, ValueError) as error:
                raise ArtifactFuzzReplicationError("input_hex is not hexadecimal") from error
            if payload.hex() != case["input_hex"] or len(payload) > limits["max_bytes"]:
                raise ArtifactFuzzReplicationError("input_hex is non-canonical or too large")
    _validate_public_tree(spec)
    return spec


def minimize_case(payload: bytes, reproduces: Callable[[bytes], bool]) -> bytes:
    """Return a deterministic byte-deletion 1-minimal reproducer."""

    if not reproduces(payload):
        raise ArtifactFuzzReplicationError("initial payload does not reproduce")
    candidate = payload
    changed = True
    while changed:
        changed = False
        for index in range(len(candidate)):
            reduced = candidate[:index] + candidate[index + 1 :]
            if reproduces(reduced):
                candidate = reduced
                changed = True
                break
    return candidate


def build_report(
    spec: Mapping[str, Any], observations: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    """Build a digest-linked report from already executed bounded fuzz observations."""

    _validate_public_tree(spec, "spec")
    by_id = {target["id"]: target for target in spec["targets"]}
    if len(observations) != len(by_id):
        raise ArtifactFuzzReplicationError("one observation is required for every target")
    reports: list[dict[str, Any]] = []
    observed: set[str] = set()
    for raw in observations:
        observation = _object(
            dict(raw), "observation", {"cases", "coverage_proxy", "target_id"}
        )
        target_id = observation["target_id"]
        if target_id not in by_id or target_id in observed:
            raise ArtifactFuzzReplicationError("observation target is unknown or duplicated")
        observed.add(target_id)
        coverage = _object(
            observation["coverage_proxy"],
            "coverage_proxy",
            {"accepted_mutations", "executed_cases", "max_depth"},
        )
        for key, value in coverage.items():
            _bounded_int(value, key, 100_000_000)
        cases = observation["cases"]
        max_cases = by_id[target_id]["limits"]["max_cases"]
        if not isinstance(cases, list) or not cases or len(cases) > max_cases:
            raise ArtifactFuzzReplicationError(
                "observed cases are empty or exceed the target bound"
            )
        case_reports: list[dict[str, Any]] = []
        for raw_case in cases:
            case = _object(dict(raw_case), "observed case", {"case_id", "input_hex", "status"})
            _public_string(case["case_id"], "case_id")
            if case["status"] not in _STATUSES:
                raise ArtifactFuzzReplicationError("unknown observed status")
            try:
                payload = bytes.fromhex(case["input_hex"])
            except (TypeError, ValueError) as error:
                raise ArtifactFuzzReplicationError("observed input is not hexadecimal") from error
            max_bytes = by_id[target_id]["limits"]["max_bytes"]
            if payload.hex() != case["input_hex"] or len(payload) > max_bytes:
                raise ArtifactFuzzReplicationError("observed input is non-canonical or too large")
            public_case = {
                "case_id": case["case_id"],
                "input_hex": case["input_hex"],
                "input_sha256": hashlib.sha256(payload).hexdigest(),
                "status": case["status"],
            }
            public_case["case_digest"] = _digest(public_case)
            case_reports.append(public_case)
        case_reports.sort(key=lambda item: (item["case_id"], item["input_sha256"]))
        status = max((case["status"] for case in case_reports), key=_STATUS_PRIORITY.__getitem__)
        target_report = {
            "cases": case_reports,
            "command": by_id[target_id]["command"],
            "coverage_proxy": coverage,
            "limits": by_id[target_id]["limits"],
            "status": status,
            "target_id": target_id,
        }
        target_report["target_digest"] = _digest(target_report)
        reports.append(target_report)
    reports.sort(key=lambda item: item["target_id"])
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "seed": spec["seed"],
        "spec_digest": _digest(spec),
        "targets": reports,
    }
    report["report_digest"] = _digest(report)
    _validate_public_tree(report, "report")
    return report


def verify_report(spec: Mapping[str, Any], report: Mapping[str, Any]) -> None:
    """Recompute every report field and reject any modification."""

    report_copy = dict(report)
    if report_copy.get("schema") != REPORT_SCHEMA:
        raise ArtifactFuzzReplicationError("unsupported report schema")
    observations = []
    for target in report_copy.get("targets", []):
        observations.append(
            {
                "cases": [
                    {
                        "case_id": case["case_id"],
                        "input_hex": case["input_hex"],
                        "status": case["status"],
                    }
                    for case in target["cases"]
                ],
                "coverage_proxy": target["coverage_proxy"],
                "target_id": target["target_id"],
            }
        )
    if build_report(spec, observations) != report_copy:
        raise ArtifactFuzzReplicationError("report recomputation differs")


def main(argv: Sequence[str] | None = None) -> int:
    """Generate a public report without executing commands implicitly."""

    parser = argparse.ArgumentParser(description="QuotientForge public fuzz reportを生成する")
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--observations", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    spec = load_spec(args.spec)
    observations = json.loads(args.observations.read_bytes())
    if not isinstance(observations, list):
        raise ArtifactFuzzReplicationError("observations must be a list")
    report = build_report(spec, observations)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(canonical_json(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
