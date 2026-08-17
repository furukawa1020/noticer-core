"""Fail-closed differential runner for the Python oracle and Rust checker."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path

from noticer_core.evaluation.aqrs_oracle import DEFAULT_LIMITS, CheckLimits, check_path

DIFFERENTIAL_FORMAT = "aqrs-differential-report-v1"
_SIGNATURE_FIELDS = (
    "status",
    "category",
    "slot",
    "observer",
    "side",
    "causal_field",
    "obligation",
    "action",
    "reason",
    "checked_horizon",
)


class DifferentialInfrastructureError(RuntimeError):
    """The Rust adapter could not be executed or did not return JSON."""


def report_signature(report: Mapping[str, object]) -> tuple[object, ...]:
    """Project implementation-specific reports onto the frozen verdict surface."""

    return tuple(report.get(field) for field in _SIGNATURE_FIELDS)


def run_rust_checker(
    model_path: Path,
    limits: CheckLimits,
    *,
    repository_root: Path,
) -> dict[str, object]:
    """Execute the real Rust checker through its JSON-only adapter."""

    command = [
        "cargo",
        "run",
        "--quiet",
        "-p",
        "quotient-forge-check",
        "--bin",
        "aqrs-check-json",
        "--",
        "--input",
        str(model_path.resolve()),
        "--max-nodes",
        str(limits.max_nodes),
        "--max-depth",
        str(limits.max_depth),
        "--time-limit-ms",
        str(limits.time_limit_ms),
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=repository_root,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=max(120.0, limits.time_limit_ms / 1_000 + 30.0),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise DifferentialInfrastructureError("Rust adapter execution failed") from error
    if completed.returncode != 0:
        raise DifferentialInfrastructureError(
            f"Rust adapter exited with {completed.returncode}: {completed.stderr.strip()}"
        )
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise DifferentialInfrastructureError(
            "Rust adapter returned non-JSON output"
        ) from error
    if not isinstance(report, dict):
        raise DifferentialInfrastructureError("Rust adapter report must be an object")
    return report


def run_differential(
    model_path: Path,
    limits: CheckLimits = DEFAULT_LIMITS,
    *,
    repository_root: Path,
) -> dict[str, object]:
    """Compare both engines and mark every disagreement as unresolved."""

    limits.validate()
    python_report = check_path(model_path, limits).as_report(engine="python")
    rust_report = run_rust_checker(
        model_path, limits, repository_root=repository_root
    )
    python_signature = report_signature(python_report)
    rust_signature = report_signature(rust_report)
    agreed = python_signature == rust_signature
    return {
        "format_version": DIFFERENTIAL_FORMAT,
        "status": "AGREE" if agreed else "UNRESOLVED",
        "model_sha256": hashlib.sha256(model_path.read_bytes()).hexdigest(),
        "python": python_report,
        "rust": rust_report,
        "signature_fields": list(_SIGNATURE_FIELDS),
    }


def write_report(path: Path, report: Mapping[str, object]) -> None:
    """Write one deterministic artifact atomically on Windows and Linux."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("model", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--repository-root", type=Path)
    parser.add_argument("--max-nodes", type=int, default=100_000)
    parser.add_argument("--max-depth", type=int, default=1_024)
    parser.add_argument("--time-limit-ms", type=int, default=30_000)
    options = parser.parse_args(arguments)
    repository_root = options.repository_root or Path(__file__).resolve().parents[3]
    limits = CheckLimits(
        max_nodes=options.max_nodes,
        max_depth=options.max_depth,
        time_limit_ms=options.time_limit_ms,
    )
    try:
        report = run_differential(
            options.model, limits, repository_root=repository_root
        )
    except DifferentialInfrastructureError as error:
        parser.error(str(error))
    if options.output is not None:
        write_report(options.output, report)
    else:
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["status"] == "AGREE" else 3


if __name__ == "__main__":
    raise SystemExit(main())
