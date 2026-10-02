from __future__ import annotations

import argparse
import json
from pathlib import Path

from noticer_core.evaluation.quotient_odometer_replication import (
    blank_evidence,
    build_manifest,
    evaluate,
    verify_manifest,
    verify_report,
    write_json,
)

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "configs" / "quotient_odometer" / "go_pivot_kill_v1.yaml"


def main() -> int:
    parser = argparse.ArgumentParser(description="QuotientOdometer replication validator")
    sub = parser.add_subparsers(dest="command", required=True)
    manifest = sub.add_parser("manifest")
    manifest.add_argument("--commit", required=True)
    manifest.add_argument("--out", type=Path, required=True)
    blank = sub.add_parser("blank-evidence")
    blank.add_argument("--out", type=Path, required=True)
    decide = sub.add_parser("decide")
    decide.add_argument("--evidence", type=Path, required=True)
    decide.add_argument("--manifest-sha256", required=True)
    decide.add_argument("--out", type=Path, required=True)
    validate = sub.add_parser("validate")
    validate.add_argument("--manifest", type=Path, required=True)
    validate.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "manifest":
        write_json(args.out, build_manifest(ROOT, POLICY, args.commit))
    elif args.command == "blank-evidence":
        write_json(args.out, blank_evidence(POLICY))
    elif args.command == "decide":
        write_json(
            args.out,
            evaluate(
                POLICY, json.loads(args.evidence.read_text(encoding="utf-8")), args.manifest_sha256
            ),
        )
    else:
        verify_manifest(ROOT, POLICY, json.loads(args.manifest.read_text(encoding="utf-8")))
        verify_report(json.loads(args.report.read_text(encoding="utf-8")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
