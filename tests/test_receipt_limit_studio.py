import json
import shutil
import subprocess
from pathlib import Path

import pytest

from noticer_core.receipt_limit_report import build_report


def test_studio_tradeoff_matches_exact_local_evidence():
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is needed for the Studio parity check")
    root = Path(__file__).resolve().parents[1]
    command = (
        'import {budgets, values, costs} from "./studio/src/scripts/receipt-limit-demo.mjs";'
        'console.log(JSON.stringify({budgets, values, costs}));'
    )
    actual = json.loads(subprocess.check_output(
        [node, "--input-type=module", "-e", command], cwd=root
    ))
    source = build_report()["tradeoff"]
    for tag, values in actual["values"].items():
        assert values == [source[tag][cap]["certified"] for cap in actual["budgets"]]
    assert actual["costs"] == [
        source["single"][cap]["common_complete"] for cap in actual["budgets"]
    ]
