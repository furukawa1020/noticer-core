"""Inspect a public QuotientForge counterexample without private evidence fields."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

FORBIDDEN_FIELDS = {
    "raw_ppg",
    "baseline",
    "stable_identifier",
    "subject_id",
    "user_id",
    "device_id",
    "private_history",
}


def find_forbidden_fields(value: Any, path: str = "$") -> list[str]:
    findings: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key).lower()
            child_path = f"{path}.{key}"
            if key_text in FORBIDDEN_FIELDS:
                findings.append(child_path)
            findings.extend(find_forbidden_fields(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            findings.extend(find_forbidden_fields(child, f"{path}[{index}]"))
    return findings


def inspect_counterexample(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("counterexample root must be an object")
    if value.get("schema") != "quotient-forge-counterexample-v1":
        raise ValueError("unsupported counterexample schema")
    findings = find_forbidden_fields(value)
    if findings:
        raise ValueError(f"private fields found: {', '.join(findings)}")
    return {
        "kind": value.get("kind"),
        "plan": value.get("plan"),
        "schema": value["schema"],
        "slot": value.get("slot"),
        "status": value.get("status"),
    }


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("counterexample", type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    summary = inspect_counterexample(args.counterexample)
    print(json.dumps(summary, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
