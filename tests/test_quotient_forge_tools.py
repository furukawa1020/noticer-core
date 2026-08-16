from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "tool",
    [
        "run_quotient_forge.py",
        "inspect_quotient_certificate.py",
        "inspect_quotient_counterexample.py",
    ],
)
def test_tools_expose_cli_help(tool: str) -> None:
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "tools" / tool), "--help"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    assert "usage:" in result.stdout


def test_counterexample_inspector_accepts_public_schema(tmp_path: Path) -> None:
    counterexample = tmp_path / "counterexample.json"
    counterexample.write_text(
        json.dumps(
            {
                "kind": "SecurityDivergence",
                "plan": "immediate-release",
                "schema": "quotient-forge-counterexample-v1",
                "slot": 0,
                "status": "COUNTEREXAMPLE",
            }
        ),
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "tools" / "inspect_quotient_counterexample.py"),
            str(counterexample),
        ],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(result.stdout)["slot"] == 0


def test_counterexample_inspector_rejects_private_fields(tmp_path: Path) -> None:
    counterexample = tmp_path / "counterexample.json"
    counterexample.write_text(
        json.dumps(
            {
                "schema": "quotient-forge-counterexample-v1",
                "status": "COUNTEREXAMPLE",
                "subject_id": "forbidden",
            }
        ),
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "tools" / "inspect_quotient_counterexample.py"),
            str(counterexample),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "private fields found" in result.stderr
