import json
import shutil
import subprocess
from pathlib import Path

import pytest

from noticer_core.shared_slot_report import build_shared_slot_report


def test_browser_demo_matches_independent_python_evidence():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for cross-language demo parity")
    root = Path(__file__).resolve().parents[1]
    code = (
        'import { evaluateFirstSend } from "./studio/src/scripts/shared-slot-demo.mjs";'
        'console.log(JSON.stringify(["A", "B", "wait"].map(evaluateFirstSend)));'
    )
    result = subprocess.run(
        [node, "--input-type=module", "-e", code],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    trace = build_shared_slot_report()["causality"]["shortest_trace"][0]
    left = trace["left_state"]["completable_first_choices"]
    right = trace["right_state"]["completable_first_choices"]
    assert json.loads(result.stdout) == [
        {"a": decision in left, "b": decision in right} for decision in ("a", "b", None)
    ]
