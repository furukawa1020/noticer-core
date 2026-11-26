import json
import os
import subprocess
import sys
from pathlib import Path


def test_standalone_checker_requires_a_completed_upper_bound(tmp_path):
    root = Path(__file__).resolve().parents[1]
    env = {**os.environ, "PYTHONPATH": str(root / "src")}
    artifact = tmp_path / "proof.json"
    writer = root / "tools" / "write_slot_mix_certificate.py"
    checker = root / "tools" / "check_slot_mix_certificate.py"
    subprocess.run([sys.executable, str(writer), str(artifact)], env=env, check=True)
    command = [sys.executable, str(checker), str(artifact)]
    good = subprocess.check_output(command, env=env)
    assert json.loads(good)["value"] == "2/5"
    cutoff = subprocess.run([*command, "--max-work", "1"], env=env, capture_output=True)
    assert (cutoff.returncode, json.loads(cutoff.stdout)) == (3, {"status": "inconclusive"})
