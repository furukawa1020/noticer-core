import json
from pathlib import Path

from noticer_core.cli import main


def test_cli_artifacts_and_stdout(tmp_path: Path, capsys) -> None:
    output = tmp_path / "run"
    code = main(
        [
            "attack", "identity", "--config", "configs/attacks/identity_smoke.yaml",
            "--output-dir", str(output),
        ]
    )
    expected = {
        "run_config.json", "dataset_summary.json", "split_manifest.csv",
        "primary_metrics.json", "control_metrics.json", "primary_predictions.csv",
        "control_predictions.csv", "confusion_matrix.png", "run.log",
    }
    assert code == 0 and {path.name for path in output.iterdir()} == expected
    assert json.loads((output / "primary_metrics.json").read_text(encoding="utf-8"))
    stdout = capsys.readouterr().out
    assert "primary balanced accuracy" in stdout and "artifact directory" in stdout


def test_aetp_cli_artifacts_and_stdout(tmp_path: Path, capsys) -> None:
    output = tmp_path / "aetp-run"
    code = main(
        [
            "attack",
            "aetp",
            "--config",
            "configs/attacks/aetp_smoke.yaml",
            "--output-dir",
            str(output),
        ]
    )
    expected = {
        "run_config.json",
        "dataset_summary.json",
        "aetp_metrics.json",
        "feature_schema.json",
        "split_manifest.csv",
        "predictions.csv",
        "attack_auc.png",
        "run.log",
    }
    assert code == 0 and {path.name for path in output.iterdir()} == expected
    metrics = json.loads((output / "aetp_metrics.json").read_text(encoding="utf-8"))
    assert metrics["protocol"]["all_criteria_passed"] is True
    stdout = capsys.readouterr().out
    assert "AETP excess AUC" in stdout and "artifact directory" in stdout
