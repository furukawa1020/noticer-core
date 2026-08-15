"""Create and validate bounded K5 public hardware-evidence artifacts."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from noticer_core.evaluation.hardware_evidence import (
    HardwareTier,
    new_public_artifact,
    validate_public_artifact,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    initialise = commands.add_parser("init", help="create a NOT_VERIFIED artifact")
    initialise.add_argument("--tier", choices=[tier.value for tier in HardwareTier], required=True)
    initialise.add_argument("--output", type=Path, required=True)
    initialise.add_argument("--public-run-id", default="unassigned")

    validate = commands.add_parser("validate", help="validate a public artifact")
    validate.add_argument("--input", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the artifact initializer or validator."""

    args = _build_parser().parse_args(argv)
    if args.command == "init":
        artifact = new_public_artifact(
            HardwareTier(args.tier), public_run_id=args.public_run_id
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(f"created NOT_VERIFIED artifact: {args.output}")
        return 0

    artifact = json.loads(args.input.read_text(encoding="utf-8"))
    result = validate_public_artifact(artifact)
    if result.valid:
        print(f"valid public artifact: {args.input}")
        return 0
    for error in result.errors:
        print(f"error: {error}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
