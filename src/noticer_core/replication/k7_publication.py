"""Deterministic publication tables and figures from a verified K7 run log."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from collections import Counter
from collections.abc import Mapping, Sequence
from html import escape
from pathlib import Path
from typing import Any, Final

from noticer_core.replication.k7_runner import verify_run_log
from noticer_core.replication.manifest import canonical_json

SUMMARY_SCHEMA: Final = "noticer-core.k7-publication-summary.v1"
MANIFEST_SCHEMA: Final = "noticer-core.k7-publication-manifest.v1"
STATUSES: Final = ("PASS", "FAILED", "TIMEOUT", "UNAVAILABLE", "OUTPUT_LIMIT", "BLOCKED")
_DIGEST_DOMAIN: Final = b"noticer-core/k7-publication/v1\0"


class K7PublicationError(ValueError):
    """Raised when publication artifacts cannot be generated safely."""


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _digest(value: object) -> str:
    return hashlib.sha256(_DIGEST_DOMAIN + canonical_json(value)).hexdigest()


def build_summary(log: Mapping[str, Any]) -> dict[str, Any]:
    """Build a fixed-taxonomy summary without dropping non-success outcomes."""

    verify_run_log(log)
    rows = []
    counts: Counter[str] = Counter()
    for record in log["tasks"]:
        result = record["result"]
        status = result["status"]
        if status not in STATUSES:
            raise K7PublicationError(f"unknown task status: {status}")
        counts[status] += 1
        rows.append(
            {
                "reason": result["reason"],
                "reused": record["reused"],
                "status": status,
                "task_id": result["task_id"],
            }
        )
    summary: dict[str, Any] = {
        "run_digest": log["run_digest"],
        "schema": SUMMARY_SCHEMA,
        "status_counts": {status: counts[status] for status in STATUSES},
        "tasks": rows,
        "total_tasks": len(rows),
    }
    summary["summary_digest"] = _digest(summary)
    return summary


def _table_bytes(summary: Mapping[str, Any]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(("task_id", "status", "reason", "reused"))
    for task in summary["tasks"]:
        writer.writerow(
            (
                task["task_id"],
                task["status"],
                task["reason"],
                str(task["reused"]).lower(),
            )
        )
    return stream.getvalue().encode("utf-8")


def _figure_bytes(summary: Mapping[str, Any]) -> bytes:
    colors = {
        "PASS": "#177245",
        "FAILED": "#b42318",
        "TIMEOUT": "#c76b00",
        "UNAVAILABLE": "#6b7280",
        "OUTPUT_LIMIT": "#8f3985",
        "BLOCKED": "#334155",
    }
    maximum = max(1, max(summary["status_counts"].values()))
    rows = []
    for index, status in enumerate(STATUSES):
        count = summary["status_counts"][status]
        y = 54 + index * 42
        width = 420 * count // maximum
        rows.append(
            f'<text x="20" y="{y + 18}" font-size="15">{escape(status)}</text>'
            f'<rect x="145" y="{y}" width="{width}" height="24" fill="{colors[status]}"/>'
            f'<text x="{155 + width}" y="{y + 18}" font-size="15">{count}</text>'
        )
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="640" height="330" '
        'viewBox="0 0 640 330">'
        '<rect width="640" height="330" fill="#f7f3e8"/>'
        '<text x="20" y="30" font-size="20" font-weight="700">K7 replication outcomes</text>'
        + "".join(rows)
        + "</svg>\n"
    )
    return svg.encode("utf-8")


def publication_files(summary: Mapping[str, Any]) -> dict[str, bytes]:
    """Return all deterministic publication payloads before filesystem output."""

    return {
        "summary.json": canonical_json(summary),
        "task-status.csv": _table_bytes(summary),
        "task-status.svg": _figure_bytes(summary),
    }


def generate_artifacts(log: Mapping[str, Any], output_dir: Path) -> dict[str, Any]:
    """Write deterministic JSON, CSV, SVG, and their digest manifest."""

    summary = build_summary(log)
    files = publication_files(summary)
    output_dir.mkdir(parents=True, exist_ok=True)
    records = []
    for name, content in sorted(files.items()):
        (output_dir / name).write_bytes(content)
        records.append({"bytes": len(content), "path": name, "sha256": _sha256(content)})
    manifest: dict[str, Any] = {
        "files": records,
        "run_digest": log["run_digest"],
        "schema": MANIFEST_SCHEMA,
        "security_interpretation": "NOT_A_SECURITY_VERDICT",
    }
    manifest["manifest_digest"] = _digest(manifest)
    (output_dir / "manifest.json").write_bytes(canonical_json(manifest))
    return manifest


def main(argv: Sequence[str] | None = None) -> int:
    """Generate publication artifacts from one verified run log."""

    parser = argparse.ArgumentParser(description="K7 run logから公開figureとtableを生成する")
    parser.add_argument("--run-log", type=Path, required=True)
    parser.add_argument(
        "--output-dir", type=Path, default=Path("artifacts/k7_replication/publication")
    )
    args = parser.parse_args(argv)
    try:
        log = json.loads(args.run_log.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise K7PublicationError("run log is not valid UTF-8 JSON") from error
    generate_artifacts(log, args.output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
