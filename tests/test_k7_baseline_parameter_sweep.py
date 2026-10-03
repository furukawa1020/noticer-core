import json
from dataclasses import replace

import pytest

from noticer_core.evaluation.baseline_comparison_contract import (
    AXES,
    MECHANISMS,
    manifest_from_document,
)
from noticer_core.evaluation.baseline_parameter_sweep import (
    AxisMetrics,
    CandidateObservation,
    ParameterSweepError,
    build_sweep_report,
    canonical_report_json,
    report_digest,
    write_report,
)


def _manifest():
    return manifest_from_document(
        {
            "format_version": "noticer.k7.baseline-comparison.v1",
            "shared": {
                "case_sha256": "1" * 64,
                "observer_sha256": "2" * 64,
                "utility_sha256": "3" * 64,
                "fault_trace_sha256": "4" * 64,
                "cost_sha256": "5" * 64,
                "corpus_sha256": "6" * 64,
                "evaluation_split": "held_out",
                "selection_split": "development",
            },
            "mechanisms": [
                {
                    "mechanism_id": name,
                    "implementation_kind": (
                        "approximation"
                        if name in {"pacer_like", "netshaper_like", "automata"}
                        else "local"
                    ),
                    "privacy_notion": "notion-" + name,
                    "source_ref": "source-" + name,
                    "source_version": "v1",
                    "candidate_config_sha256": ["a" * 64, "b" * 64],
                    "selected_config_sha256": "a" * 64,
                }
                for name in sorted(MECHANISMS)
            ],
            "report_axes": list(AXES),
            "privacy_notions_are_separate": True,
            "security_proof": False,
        }
    )


def _observations() -> tuple[CandidateObservation, ...]:
    rows = []
    for mechanism in sorted(MECHANISMS):
        for config, failure in (("a" * 64, 0), ("b" * 64, 1)):
            for split in ("development", "held_out"):
                rows.append(
                    CandidateObservation(
                        mechanism,
                        config,
                        split,
                        "notion-" + mechanism,
                        AxisMetrics(0.1, 100, failure, 2.0, 3),
                    )
                )
    return tuple(reversed(rows))


def test_complete_sweep_is_canonical_and_keeps_axes_separate(tmp_path) -> None:
    report = build_sweep_report(_manifest(), _observations())
    payload = canonical_report_json(report)
    assert report.report_axes == AXES
    assert all(item.config_sha256 == "a" * 64 for item in report.selected_candidates)
    assert '"score"' not in payload
    assert report_digest(report) == report_digest(report)
    destination = tmp_path / "nested" / "report.json"
    write_report(report, destination)
    assert destination.read_text(encoding="utf-8") == payload + "\n"
    assert json.loads(payload)["metrics_are_not_aggregated"] is True


def test_held_out_results_cannot_change_selection() -> None:
    original = build_sweep_report(_manifest(), _observations())
    changed = tuple(
        replace(row, metrics=AxisMetrics(0.0, 0, 0, 0.0, 0))
        if row.split == "held_out" and row.config_sha256 == "b" * 64
        else row
        for row in _observations()
    )
    updated = build_sweep_report(_manifest(), changed)
    assert updated.selected_candidates == original.selected_candidates


@pytest.mark.parametrize(
    "mutation,category",
    [
        (lambda rows: rows[:-1], "incomplete_candidate_coverage"),
        (lambda rows: rows + (rows[0],), "duplicate_observation"),
        (
            lambda rows: (replace(rows[0], config_sha256="c" * 64),) + rows[1:],
            "undeclared_candidate",
        ),
        (
            lambda rows: (replace(rows[0], privacy_notion="other"),) + rows[1:],
            "privacy_notion_mismatch",
        ),
    ],
)
def test_cherry_picking_and_contract_drift_fail_closed(mutation, category) -> None:
    with pytest.raises(ParameterSweepError) as caught:
        build_sweep_report(_manifest(), mutation(_observations()))
    assert caught.value.category == category


def test_post_hoc_selected_config_is_rejected() -> None:
    manifest = _manifest()
    mechanisms = tuple(
        replace(item, selected_config_sha256="b" * 64)
        if item.mechanism_id == manifest.mechanisms[0].mechanism_id
        else item
        for item in manifest.mechanisms
    )
    with pytest.raises(ParameterSweepError) as caught:
        build_sweep_report(replace(manifest, mechanisms=mechanisms), _observations())
    assert caught.value.category == "precommitted_selection_mismatch"
