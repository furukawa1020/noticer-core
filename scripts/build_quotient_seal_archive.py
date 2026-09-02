"""Build or verify a deterministic QuotientSeal replication archive."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from noticer_core.replication.archive import (
    ArchiveError,
    build_final_report,
    build_replication_archive,
    verify_final_report,
    verify_replication_archive,
    write_final_report,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument(
        "--policy",
        type=Path,
        default=Path("replication/archive_policy_v1.json"),
    )
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--staging", type=Path)
    parser.add_argument("--verify", action="store_true")
    return parser


def main() -> int:
    """Run the archive builder or verifier without network access."""

    args = _parser().parse_args()
    try:
        if args.verify:
            verify_replication_archive(args.archive, args.policy)
            report = json.loads(args.report.read_text(encoding="utf-8"))
            verify_final_report(report, args.archive, args.policy)
            print("QuotientSeal replication archive: PASS")
            return 0
        if args.staging is None:
            raise ArchiveError("--staging is required when building")
        build_replication_archive(args.staging, args.archive, args.policy)
        report = build_final_report(args.archive, args.policy)
        write_final_report(report, args.report, args.archive, args.policy)
        print(
            "QuotientSeal replication archive built: "
            f"{report['archive_sha256']} ({report['decision']['value']})"
        )
        return 0
    except (ArchiveError, OSError, json.JSONDecodeError) as exc:
        print(f"QuotientSeal replication archive: FAIL: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
