import json
import shutil
import subprocess
from pathlib import Path

import pytest

from noticer_core.shared_slot_game_report import build_checked_game_report


def test_game_demo_values_match_the_independent_python_results():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for cross-language demo parity")
    root = Path(__file__).resolve().parents[1]
    code = (
        'import {gameScenes} from "./studio/src/scripts/shared-slot-demo-game.mjs";'
        'console.log(JSON.stringify(gameScenes));'
    )
    result = subprocess.run(
        [node, "--input-type=module", "-e", code],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    browser = json.loads(result.stdout)
    python = build_checked_game_report()
    for browser_key, python_key in (("hedge", "robust_hedge"), ("late", "late_conflict")):
        row = python["scenarios"][python_key]
        assert browser[browser_key]["early"] == f"{min(row['offline'])}/{row['required']}"
        assert browser[browser_key]["reference"] == (
            f"{min(row['deadline_first'])}/{row['required']}"
        )
        expected = "None" if "causal" not in row else f"{min(row['causal'])}/{row['required']}"
        assert browser[browser_key]["hedge"] == expected
    assert browser["cutoff"]["evidence"].lower() == python["controls"]["forced_cutoff"]
