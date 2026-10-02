from __future__ import annotations

import argparse
import json
from pathlib import Path

from noticer_core.evaluation.quotient_guard_replication import (
    blank_evidence,
    build_manifest,
    evaluate,
    verify_manifest,
    verify_report,
    write_json,
)

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "configs" / "quotient_guard" / "go_pivot_kill_v1.yaml"


def main() -> int:
    parser = argparse.ArgumentParser(description="QuotientGuard replication validator")
    commands = parser.add_subparsers(dest="command", required=True)
    manifest = commands.add_parser("manifest")
    manifest.add_argument("--commit", required=True)
    manifest.add_argument("--out", type=Path, required=True)
    blank = commands.add_parser("blank-evidence")
    blank.add_argument("--out", type=Path, required=True)
    decide = commands.add_parser("decide")
    decide.add_argument("--evidence", type=Path, required=True)
    decide.add_argument("--manifest-sha256", required=True)
    decide.add_argument("--out", type=Path, required=True)
    validate = commands.add_parser("validate")
    validate.add_argument("--manifest", type=Path, required=True)
    validate.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()

    if args.command == "manifest":
        write_json(args.out, build_manifest(ROOT, POLICY, args.commit))
    elif args.command == "blank-evidence":
        write_json(args.out, blank_evidence(POLICY))
    elif args.command == "decide":
        evidence = json.loads(args.evidence.read_text(encoding="utf-8"))
        write_json(args.out, evaluate(POLICY, evidence, args.manifest_sha256))
    else:
        manifest_document = json.loads(args.manifest.read_text(encoding="utf-8"))
        report_document = json.loads(args.report.read_text(encoding="utf-8"))
        verify_manifest(ROOT, POLICY, manifest_document)
        verify_report(report_document)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
