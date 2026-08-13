from __future__ import annotations

import csv
import json
from pathlib import Path

from noticer_core.evaluation.k4_transport import evaluate_k4_artifacts


def _write_fixture(path: Path, *, include_secret: bool = False) -> None:
    path.mkdir()
    summary: dict[str, object] = {
        "schema_version": 1,
        "seed": 4401,
        "fragments_per_frame": 20,
        "fragment_bytes": 20,
        "observer_trace_equal": True,
        "both_reassembled": True,
        "both_authorized": True,
        "execution_trace_equal": True,
        "replay_rejected_without_actuation": True,
        "tier_a": "VERIFIED",
        "tier_b": "NOT_VERIFIED",
    }
    if include_secret:
        summary["token_bytes"] = "forbidden"
    (path / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
    columns = [
        "side",
        "ordinal",
        "scheduled_tick",
        "frame_id",
        "fragment_index",
        "delivered",
        "wire_length",
    ]
    with (path / "transport_trace.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for side in ("A", "B"):
            for ordinal in range(20):
                writer.writerow(
                    {
                        "side": side,
                        "ordinal": ordinal,
                        "scheduled_tick": 1000 + ordinal * 5,
                        "frame_id": "010203",
                        "fragment_index": ordinal,
                        "delivered": ordinal not in {0, 5, 10, 15},
                        "wire_length": 20,
                    }
                )


def test_k4_artifact_pair_is_congruent_and_secret_free(tmp_path: Path) -> None:
    artifact_dir = tmp_path / "valid"
    _write_fixture(artifact_dir)
    evaluation = evaluate_k4_artifacts(artifact_dir)
    assert evaluation.passed
    assert evaluation.rows_per_side == 20
    assert evaluation.forbidden_field_count == 0


def test_k4_artifact_rejects_forbidden_secret_field(tmp_path: Path) -> None:
    artifact_dir = tmp_path / "secret"
    _write_fixture(artifact_dir, include_secret=True)
    evaluation = evaluate_k4_artifacts(artifact_dir)
    assert not evaluation.passed
    assert evaluation.forbidden_field_count == 1
