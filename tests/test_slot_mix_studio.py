import json
import shutil
import subprocess
from fractions import Fraction
from pathlib import Path

import pytest

from noticer_core.slot_mix_examples_report import build_mix_examples


def test_studio_publishes_the_same_asymmetric_profile():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node required for cross-language validation")
    root = Path(__file__).resolve().parents[1]
    command = (
        'import {moves, viewRows} from "./studio/src/scripts/slot-mix-demo.mjs";'
        'console.log(JSON.stringify({moves, rows: viewRows()}));'
    )
    actual = json.loads(subprocess.check_output(
        [node, "--input-type=module", "-e", command], cwd=root
    ))
    expected = build_mix_examples()["examples"]["asymmetric"]
    assert tuple(move["mask"] for move in actual["moves"]) == expected["policy_masks"]
    assert [Fraction(row["certified"]) for row in actual["rows"]] == [
        Fraction(token) for token in expected["success_profile"]
    ]
    assert min(Fraction(row["uniform"]) for row in actual["rows"]) == Fraction(expected["uniform"])
