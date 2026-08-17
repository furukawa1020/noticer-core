from __future__ import annotations

import json
import shutil
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from test_aqrs_oracle import base_document

from noticer_core.evaluation.aqrs_differential import run_differential
from noticer_core.evaluation.aqrs_oracle import CheckLimits


def _write(path: Path, document: dict[str, Any]) -> Path:
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return path


def test_real_rust_python_differential_matrix(tmp_path: Path) -> None:
    if shutil.which("cargo") is None:
        pytest.skip("cargo is required for the cross-language differential test")

    repository_root = Path(__file__).resolve().parents[1]
    verified = base_document(horizon=2)

    counterexample = deepcopy(verified)
    counterexample["observers"][0]["visible_fields"] = ["bucket"]
    counterexample["transitions"][0]["release"]["fields"] = {"bucket": "a"}
    counterexample["transitions"][1]["release"]["fields"] = {"bucket": "b"}

    invalid = deepcopy(verified)
    invalid["transitions"].pop()

    matrix = [
        ("verified", verified, CheckLimits()),
        ("counterexample", counterexample, CheckLimits()),
        ("invalid", invalid, CheckLimits()),
        ("inconclusive", verified, CheckLimits(max_nodes=0)),
    ]
    for name, document, limits in matrix:
        model_path = _write(tmp_path / f"{name}.json", document)
        report = run_differential(
            model_path, limits, repository_root=repository_root
        )
        assert report["status"] == "AGREE"


def test_disagreement_is_fail_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    model_path = _write(tmp_path / "model.json", base_document())

    def disagreeing_rust(*args: object, **kwargs: object) -> dict[str, object]:
        return {
            "status": "verified",
            "category": "wrong_semantics",
            "slot": None,
            "observer": None,
            "side": None,
            "causal_field": None,
            "obligation": None,
            "action": None,
            "reason": None,
            "checked_horizon": 1,
        }

    monkeypatch.setattr(
        "noticer_core.evaluation.aqrs_differential.run_rust_checker",
        disagreeing_rust,
    )
    report = run_differential(
        model_path,
        repository_root=Path(__file__).resolve().parents[1],
    )
    assert report["status"] == "UNRESOLVED"
