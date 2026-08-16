"""Build or validate the frozen K7 public research manifest."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from noticer_core.evaluation.k7_research_contract import (
    load_research_contract,
    validate_public_manifest,
    write_research_manifest,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build", help="build a deterministic public manifest")
    build.add_argument("--config", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    validate = commands.add_parser("validate", help="validate a manifest against the contract")
    validate.add_argument("--config", type=Path, required=True)
    validate.add_argument("--input", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the K7 manifest command-line interface."""

    args = _parser().parse_args(argv)
    if args.command == "build":
        output = write_research_manifest(args.config, args.output)
        print(f"wrote frozen K7 manifest: {output}")
        return 0

    contract = load_research_contract(args.config)
    loaded = json.loads(args.input.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        print("error: public manifest root must be an object")
        return 1
    result = validate_public_manifest(loaded, contract)
    if result.valid:
        print(f"valid frozen K7 manifest: {args.input}")
        return 0
    for error in result.errors:
        print(f"error: {error}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

