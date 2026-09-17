from copy import deepcopy

import pytest

from noticer_core.evaluation.baseline_comparison_contract import (
    AXES,
    MECHANISMS,
    ComparisonContractError,
    manifest_digest,
    manifest_from_document,
)


def _document() -> dict[str, object]:
    mechanisms = [
        {
            "mechanism_id": name,
            "implementation_kind": (
                "approximation" if name in {"pacer_like", "netshaper_like", "automata"}
                else "local"
            ),
            "privacy_notion": "notion-" + name,
            "source_ref": "source-" + name,
            "source_version": "v1",
            "candidate_config_sha256": ["a" * 64, "b" * 64],
            "selected_config_sha256": "a" * 64,
        }
        for name in sorted(MECHANISMS)
    ]
    return {
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
        "mechanisms": mechanisms,
        "report_axes": list(AXES),
        "privacy_notions_are_separate": True,
        "security_proof": False,
    }


def test_complete_shared_contract_has_stable_digest() -> None:
    first = manifest_from_document(_document())
    second = manifest_from_document(deepcopy(_document()))
    assert first == second
    assert manifest_digest(first) == manifest_digest(second)


@pytest.mark.parametrize(
    "field,value,category",
    [
        ("evaluation_split", "development", "split_misuse"),
        ("selection_split", "held_out", "split_misuse"),
        ("observer_sha256", "wrong", "invalid_digest"),
    ],
)
def test_shared_contract_cannot_be_weakened(
    field: str, value: str, category: str
) -> None:
    document = _document()
    document["shared"][field] = value
    with pytest.raises(ComparisonContractError) as caught:
        manifest_from_document(document)
    assert caught.value.category == category


def test_parameter_cherry_picking_and_missing_provenance_are_rejected() -> None:
    document = _document()
    document["mechanisms"][0]["selected_config_sha256"] = "c" * 64
    with pytest.raises(ComparisonContractError) as caught:
        manifest_from_document(document)
    assert caught.value.category == "selected_config_not_precommitted"
    document = _document()
    document["mechanisms"][0]["source_version"] = ""
    with pytest.raises(ComparisonContractError) as caught:
        manifest_from_document(document)
    assert caught.value.category == "missing_provenance"


def test_privacy_notions_and_metrics_cannot_be_collapsed() -> None:
    document = _document()
    document["report_axes"] = ["score"]
    with pytest.raises(ComparisonContractError) as caught:
        manifest_from_document(document)
    assert caught.value.category == "collapsed_privacy_or_metrics"
    document = _document()
    document["privacy_notions_are_separate"] = False
    with pytest.raises(ComparisonContractError) as caught:
        manifest_from_document(document)
    assert caught.value.category == "collapsed_privacy_or_metrics"


def test_missing_mechanism_and_undeclared_channel_are_rejected() -> None:
    document = _document()
    document["mechanisms"].pop()
    with pytest.raises(ComparisonContractError) as caught:
        manifest_from_document(document)
    assert caught.value.category == "mechanism_set_mismatch"
    document = _document()
    document["shared"]["secret"] = "hidden"
    with pytest.raises(ComparisonContractError) as caught:
        manifest_from_document(document)
    assert caught.value.category == "undeclared_field"
