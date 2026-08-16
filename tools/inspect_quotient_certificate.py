"""Verify a CAQT certificate through the QuotientForge CLI."""

from __future__ import annotations

import argparse
import subprocess
from collections.abc import Sequence
from pathlib import Path


def inspect_certificate(
    repo_root: Path,
    certificate: Path,
    output: Path,
    cargo: str = "cargo",
) -> Path:
    subprocess.run(
        [
            cargo,
            "run",
            "--quiet",
            "-p",
            "quotient-forge-cli",
            "--bin",
            "quotient-forge",
            "--",
            "verify",
            "--certificate",
            str(certificate),
            "--output",
            str(output),
            "--solver",
            "off",
        ],
        cwd=repo_root,
        check=True,
    )
    return output / "manifest.json"


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("certificate", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cargo", default="cargo")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    repo_root = Path(__file__).resolve().parents[1]
    certificate = args.certificate.resolve()
    output = args.output if args.output.is_absolute() else repo_root / args.output
    print(inspect_certificate(repo_root, certificate, output, args.cargo))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
