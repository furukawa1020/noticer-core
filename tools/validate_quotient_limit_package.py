from __future__ import annotations

import argparse
import json
from pathlib import Path

from noticer_core.evaluation.quotient_limit_replication import (
    blank_evidence,
    build_manifest,
    evaluate_decision,
    write_json,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = ROOT / "configs" / "quotient_limit" / "go_pivot_kill_v1.yaml"


def main() -> int:
    parser = argparse.ArgumentParser(description="QuotientLimit replication package validator")
    subparsers = parser.add_subparsers(dest="command", required=True)
    manifest = subparsers.add_parser("manifest")
    manifest.add_argument("--commit", required=True)
    manifest.add_argument("--out", type=Path, required=True)
    evidence = subparsers.add_parser("blank-evidence")
    evidence.add_argument("--out", type=Path, required=True)
    decide = subparsers.add_parser("decide")
    decide.add_argument("--evidence", type=Path, required=True)
    decide.add_argument("--manifest-sha256", required=True)
    decide.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    if args.command == "manifest":
        write_json(args.out, build_manifest(ROOT, DEFAULT_POLICY, args.commit))
    elif args.command == "blank-evidence":
        write_json(args.out, blank_evidence(DEFAULT_POLICY))
    else:
        document = json.loads(args.evidence.read_text(encoding="utf-8"))
        write_json(
            args.out,
            evaluate_decision(DEFAULT_POLICY, document, args.manifest_sha256),
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
