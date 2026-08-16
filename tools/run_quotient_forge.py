"""Run every QuotientForge smoke command with a reproducible public-only contract."""

from __future__ import annotations

import argparse
import json
import subprocess
import tomllib
from collections.abc import Sequence
from pathlib import Path
from typing import Any

COMMANDS = ("check", "synthesize", "repair", "verify", "frontier", "generate")


def load_config(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        config = tomllib.load(handle)
    if config.get("schema_version") != 1:
        raise ValueError("schema_version must be 1")
    commands = tuple(config.get("commands", ()))
    if not commands or any(command not in COMMANDS for command in commands):
        raise ValueError("commands contains an unsupported QuotientForge command")
    if config.get("solver", "off") not in {"off", "auto", "required"}:
        raise ValueError("solver must be off, auto, or required")
    return config


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"


def run_pipeline(
    repo_root: Path,
    config_path: Path,
    output_root: Path | None = None,
    cargo: str = "cargo",
) -> Path:
    config = load_config(config_path)
    configured_root = Path(config["artifact"]["root"])
    output = output_root or (repo_root / configured_root)
    if output.exists():
        raise FileExistsError(f"output already exists: {output}")

    seed = int(config.get("seed", 0))
    solver = str(config.get("solver", "off"))
    commands = tuple(str(command) for command in config["commands"])
    for command in commands:
        command_output = output / command
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
                command,
                "--output",
                str(command_output),
                "--seed",
                str(seed),
                "--solver",
                solver,
            ],
            cwd=repo_root,
            check=True,
        )

    run_manifest = {
        "commands": list(commands),
        "privacy_contract": "public-only-v1",
        "schema": "quotient-forge-run-v1",
        "seed": seed,
        "solver": solver,
    }
    manifest_path = output / "run-manifest.json"
    manifest_path.write_text(canonical_json(run_manifest), encoding="utf-8", newline="\n")
    return manifest_path


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("configs/quotient_forge/cli_smoke.toml"),
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument("--cargo", default="cargo")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    repo_root = Path(__file__).resolve().parents[1]
    config = args.config if args.config.is_absolute() else repo_root / args.config
    output = args.output
    if output is not None and not output.is_absolute():
        output = repo_root / output
    manifest = run_pipeline(repo_root, config, output, args.cargo)
    print(manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
