from __future__ import annotations

import json
from pathlib import Path

from noticer_core.cli import main


def test_provenance_cli_writes_public_artifacts_and_passes_criteria(
    tmp_path: Path, capsys
) -> None:
    output = tmp_path / "provenance-run"
    code = main(
        [
            "attack",
            "provenance",
            "--config",
            "configs/attacks/provenance_smoke.yaml",
            "--output-dir",
            str(output),
        ]
    )
    expected = {
        "run_config.json",
        "dataset_summary.json",
        "criteria.json",
        "feature_schema.json",
        "split_manifest.csv",
        "attack_results.csv",
        "source_attack_results.csv",
        "attack_summary.svg",
        "run.log",
        "private_artifact_validation.json",
    }
    assert code == 0
    assert {path.name for path in output.iterdir()} == expected
    criteria = json.loads((output / "criteria.json").read_text(encoding="utf-8"))
    validation = json.loads(
        (output / "private_artifact_validation.json").read_text(encoding="utf-8")
    )
    assert criteria["all_criteria_passed"] is True
    assert validation["passed"] is True
    stdout = capsys.readouterr().out
    assert "leaky baselines passing" in stdout
    assert "unauthorized actions: 0" in stdout
