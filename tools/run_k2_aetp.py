"""Run the complete Rust simulation and Python AETP attack evaluation."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    rust_command = [
        "cargo",
        "run",
        "-p",
        "noticer-aetp-demo",
        "--",
        "--config",
        str(args.config),
        "--out",
        str(args.out),
    ]
    if sys.platform == "win32":
        developer = Path(
            r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"
            r"\Common7\Tools\VsDevCmd.bat"
        )
        if developer.is_file():
            quoted = subprocess.list2cmdline(rust_command)
            rust_command = [
                "cmd.exe",
                "/d",
                "/s",
                "/c",
                f'"{developer}" -arch=x64 -host_arch=x64 >nul && {quoted}',
            ]
    subprocess.run(rust_command, check=True)
    subprocess.run(
        [
            sys.executable,
            "experiments/aetp/evaluate_attacks.py",
            "--artifact-dir",
            str(args.out),
        ],
        check=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
