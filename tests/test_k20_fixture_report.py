import json
from pathlib import Path

from noticer_core.evaluation.k20_fixture_report import build_fixture_bundle


def test_two_fixture_bundles_are_identical(tmp_path: Path) -> None:
    left, right = tmp_path / "left", tmp_path / "right"
    build_fixture_bundle(left)
    build_fixture_bundle(right)
    files = {item.name: item.read_bytes() for item in left.iterdir()}
    assert files == {item.name: item.read_bytes() for item in right.iterdir()}
    assert set(files) == {
        "aetp.json", "aetp.svg", "fixed-rate.json", "fixed-rate.svg", "comparison.csv",
        "manifest.json",
    }
    assert json.loads(files["manifest.json"])["evidence_class"] == "fixture"
    assert b"fixture" in files["comparison.csv"]
