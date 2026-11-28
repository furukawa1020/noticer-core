import json
import os
import subprocess
import sys
from pathlib import Path


def test_cli_rejects_forged_value_and_distinguishes_cutoff(tmp_path):
    root = Path(__file__).resolve().parents[1]
    env = {**os.environ, "PYTHONPATH": str(root / "src")}
    file = tmp_path / "proof.json"
    write = [sys.executable, str(root / "tools/write_receipt_limit_certificate.py"), str(file)]
    check = [sys.executable, str(root / "tools/check_receipt_limit_certificate.py"), str(file)]
    subprocess.run(write, env=env, check=True)
    valid = subprocess.run(check, env=env, check=True, capture_output=True)
    data = json.loads(file.read_bytes())
    assert json.loads(valid.stdout)["value"] == "5/8"
    cutoff = subprocess.run([*check, "--max-work", "1"], env=env, capture_output=True)
    assert cutoff.returncode == 3 and json.loads(cutoff.stdout)["status"] == "inconclusive"
    data["value"] = "1"
    file.write_text(json.dumps(data), encoding="utf-8")
    forged = subprocess.run(check, env=env, capture_output=True)
    assert forged.returncode == 2 and json.loads(forged.stdout)["status"] == "rejected"
