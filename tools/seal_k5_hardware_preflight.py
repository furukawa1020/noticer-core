"""Seal or verify a K5 hardware preflight plan."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from noticer_core.evaluation.hardware_preflight import (
    PreflightError,
    canonical_json,
    protocol_sha256,
    seal_preflight,
    verify_preflight,
)


def _read_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PreflightError(f"could not read JSON object: {error}") from error
    if not isinstance(value, dict):
        raise PreflightError("input must be a JSON object")
    return value


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    seal = subparsers.add_parser("seal")
    seal.add_argument("--input", type=Path, required=True)
    seal.add_argument("--output", type=Path, required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--input", type=Path, required=True)
    verify.add_argument("--protocol", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.command == "seal":
        envelope = seal_preflight(_read_object(args.input))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(canonical_json(envelope) + b"\n")
        print(envelope["digest"])
        return
    envelope = _read_object(args.input)
    expected = protocol_sha256(args.protocol.read_bytes())
    payload = verify_preflight(envelope, expected_protocol_sha256=expected)
    print(f"verified preflight for tier {payload['tier']}: {envelope['digest']}")


if __name__ == "__main__":
    try:
        main()
    except PreflightError as error:
        raise SystemExit(f"hardware preflight failed: {error}") from error
