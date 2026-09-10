from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from noticer_core.evaluation.benchmark_case import load_benchmark_case, verify_aqrs_source_binding

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "configs" / "quotient_forge" / "benchmark_cases" / "negative"
REGISTRY = ROOT / "configs" / "quotient_forge" / "benchmark_family_registry_v1.yaml"
REFUTATIONS = ROOT / "configs" / "quotient_forge" / "negative_refutations_v1.yaml"

EXPECTED = {
    "negative_missing_authorized_output": ("train", "UNREALIZABLE", "UNSAT_AT_BOUND"),
    "negative_secret_dependent_retry": ("train", "INVALID", "INVALID_SPEC"),
    "negative_impossible_deadline": ("development", "INVALID", "INVALID_SPEC"),
    "negative_failure_leak": ("development", "INVALID", "INVALID_SPEC"),
    "negative_quotient_merge": ("development", "INVALID", "INVALID_SPEC"),
    "negative_private_carryover": ("held_out", "INVALID", "INVALID_SPEC"),
    "negative_observer_omission": ("held_out", "INVALID", "INVALID_SPEC"),
    "negative_unauthorized_cover_action": ("held_out", "UNREALIZABLE", "UNSAT_AT_BOUND"),
}


@pytest.mark.parametrize("family_id", EXPECTED)
def test_negative_case_binding_split_and_outcome_class(family_id: str) -> None:
    split, outcome_class, _ = EXPECTED[family_id]
    case = load_benchmark_case(CORPUS / f"{family_id}.yaml")
    verify_aqrs_source_binding(case, (CORPUS / f"{family_id}.qf").read_bytes())
    assert case.family_id == family_id
    assert case.variant_id == "canonical"
    assert case.split == split
    assert case.expected_outcome_class == outcome_class
    assert case.author_template_sha256 is None


def test_negative_splits_match_the_locked_registry() -> None:
    registry = yaml.safe_load(REGISTRY.read_text(encoding="utf-8"))
    locked = {
        family["id"]: family["split"]
        for family in registry["families"]
        if family["category"] == "negative"
    }
    actual = {
        family_id: load_benchmark_case(CORPUS / f"{family_id}.yaml").split for family_id in EXPECTED
    }
    assert actual == locked


def test_refutation_index_is_total_unique_and_status_locked() -> None:
    document = yaml.safe_load(REFUTATIONS.read_text(encoding="utf-8"))
    assert set(document) == {"schema", "cases"}
    assert document["schema"] == "noticer.k7.negative-refutations.v1"
    entries = document["cases"]
    assert len(entries) == 8
    by_id = {entry["family_id"]: entry for entry in entries}
    assert set(by_id) == set(EXPECTED)
    assert len(by_id) == len(entries)
    for family_id, (_, _, expected_status) in EXPECTED.items():
        entry = by_id[family_id]
        assert set(entry) == {
            "family_id",
            "expected_status",
            "reason_code",
            "diagnostic_code",
        }
        assert entry["expected_status"] == expected_status
        assert entry["reason_code"]
        if expected_status == "INVALID_SPEC":
            assert entry["diagnostic_code"].startswith("QF")
        else:
            assert entry["diagnostic_code"] is None


def test_negative_directory_contains_exactly_eight_case_pairs() -> None:
    assert len(list(CORPUS.glob("*.yaml"))) == 8
    assert len(list(CORPUS.glob("*.qf"))) == 8
