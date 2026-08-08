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
