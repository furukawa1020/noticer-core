"""Validate public K4 transport and execution artifacts without token payloads."""

from __future__ import annotations

import csv
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

EXPECTED_TRACE_COLUMNS = {
    "side",
    "ordinal",
    "scheduled_tick",
    "frame_id",
    "fragment_index",
    "delivered",
    "wire_length",
}
FORBIDDEN_ARTIFACT_FIELDS = {
    "biosignal",
    "ciphertext",
    "evidence",
    "nonce",
    "payload",
    "private_history",
    "root_secret",
    "token_bytes",
    "transport_id_key",
}


@dataclass(frozen=True)
class K4Evaluation:
    """Public, reproducible K4 invariant results."""

    schema_version: int
    rows_per_side: int
    observer_trace_equal: bool
    fixed_fragment_count: bool
    fixed_wire_length: bool
    summary_consistent: bool
    forbidden_field_count: int
    passed: bool


def evaluate_k4_artifacts(artifact_dir: Path) -> K4Evaluation:
    """Load and validate one K4 artifact directory."""
    summary_path = artifact_dir / "summary.json"
    trace_path = artifact_dir / "transport_trace.csv"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    rows = _read_trace(trace_path)
    forbidden = _find_forbidden_fields(summary)

    left = [_public_projection(row) for row in rows if row["side"] == "A"]
    right = [_public_projection(row) for row in rows if row["side"] == "B"]
    observer_equal = left == right and bool(left)
    fixed_count = len(left) == 20 and len(right) == 20
    fixed_wire_length = all(int(row["wire_length"]) == 20 for row in rows)
    summary_consistent = (
        summary.get("schema_version") == 1
        and summary.get("fragments_per_frame") == 20
        and summary.get("fragment_bytes") == 20
        and summary.get("observer_trace_equal") is observer_equal
        and summary.get("tier_a") == "VERIFIED"
        and summary.get("tier_b") == "NOT_VERIFIED"
    )
    passed = (
        observer_equal
        and fixed_count
        and fixed_wire_length
        and summary_consistent
        and not forbidden
        and summary.get("both_reassembled") is True
        and summary.get("both_authorized") is True
        and summary.get("execution_trace_equal") is True
        and summary.get("replay_rejected_without_actuation") is True
    )
    return K4Evaluation(
        schema_version=1,
        rows_per_side=len(left),
        observer_trace_equal=observer_equal,
        fixed_fragment_count=fixed_count,
        fixed_wire_length=fixed_wire_length,
        summary_consistent=summary_consistent,
        forbidden_field_count=len(forbidden),
        passed=passed,
    )


def write_evaluation(artifact_dir: Path, evaluation: K4Evaluation) -> Path:
    """Write only aggregate public metrics."""
    output = artifact_dir / "evaluation.json"
    output.write_text(
        json.dumps(asdict(evaluation), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return output


def _read_trace(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if set(reader.fieldnames or []) != EXPECTED_TRACE_COLUMNS:
            raise ValueError("unexpected K4 transport trace schema")
        rows = list(reader)
    if any(row["side"] not in {"A", "B"} for row in rows):
        raise ValueError("unexpected counterfactual side")
    return rows


def _public_projection(row: dict[str, str]) -> tuple[str, ...]:
    return tuple(row[column] for column in sorted(EXPECTED_TRACE_COLUMNS - {"side"}))


def _find_forbidden_fields(value: Any) -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower()
            if normalized in FORBIDDEN_ARTIFACT_FIELDS:
                found.append(normalized)
            found.extend(_find_forbidden_fields(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(_find_forbidden_fields(child))
    return found


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for reproducibility scripts."""
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 1:
        print("usage: python -m noticer_core.evaluation.k4_transport ARTIFACT_DIR")
        return 2
    artifact_dir = Path(arguments[0])
    evaluation = evaluate_k4_artifacts(artifact_dir)
    output = write_evaluation(artifact_dir, evaluation)
    print(json.dumps({"passed": evaluation.passed, "evaluation": str(output)}))
    return 0 if evaluation.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
