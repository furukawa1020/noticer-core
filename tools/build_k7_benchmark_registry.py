"""Build or validate the frozen K7 benchmark-family public manifest."""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping, Sequence
from pathlib import Path

import yaml

from noticer_core.evaluation.benchmark_registry import (
    load_benchmark_registry,
    validate_benchmark_registry_manifest,
    write_benchmark_registry_manifest,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("build", "validate"):
        command = commands.add_parser(name)
        command.add_argument("--registry", type=Path, required=True)
        command.add_argument("--contract", type=Path, required=True)
        command.add_argument(
            "--output" if name == "build" else "--input",
            type=Path,
            required=True,
        )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the family-registry manifest CLI."""

    args = _parser().parse_args(argv)
    if args.command == "build":
        output = write_benchmark_registry_manifest(args.registry, args.contract, args.output)
        print(f"wrote frozen benchmark family manifest: {output}")
        return 0

    contract_loaded = yaml.safe_load(args.contract.read_text(encoding="utf-8"))
    if not isinstance(contract_loaded, Mapping):
        print("error: research contract root must be an object")
        return 1
    contract = dict(contract_loaded)
    registry = load_benchmark_registry(args.registry, contract)
    manifest = json.loads(args.input.read_text(encoding="utf-8"))
    if not isinstance(manifest, Mapping):
        print("error: family manifest root must be an object")
        return 1
    result = validate_benchmark_registry_manifest(manifest, registry, contract)
    if result.valid:
        print(f"valid frozen benchmark family manifest: {args.input}")
        return 0
    for error in result.errors:
        print(f"error: {error}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
