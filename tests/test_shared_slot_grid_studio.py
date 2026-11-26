import json
import shutil
import subprocess
from pathlib import Path

import pytest

from noticer_core.shared_slot_comparison import compare_finite_grid


def test_published_results_include_the_strong_baseline_tie():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for cross-language demo parity")
    root = Path(__file__).resolve().parents[1]
    code = (
        'import {grid} from "./studio/src/scripts/shared-slot-demo-grid.mjs";'
        'console.log(JSON.stringify(grid));'
    )
    results = subprocess.check_output([node, "--input-type=module", "-e", code], cwd=root)
    browser = json.loads(results)
    reference = compare_finite_grid()
    for shown, key in zip(browser, ("steady", "outage_then_burst"), strict=True):
        raw = reference[key]
        assert shown["total"] == raw["tape_pairs"]
        assert shown["slack"] == raw["worst_slack_both"]
        assert shown["verified"] == raw["checked_policy"]
        assert shown["deadline"] == raw["deadline_first_both"]
        assert shown["offline"] == raw["offline_both"]
