from __future__ import annotations

import json
from copy import deepcopy
from hashlib import sha256
from pathlib import Path

import pytest
import yaml

from noticer_core.evaluation.benchmark_case import (
    CASE_SCHEMA,
    BenchmarkCaseError,
    BenchmarkCaseLimits,
    benchmark_case_manifest,
    benchmark_case_sha256,
    canonical_benchmark_case_bytes,
    parse_benchmark_case,
    verify_aqrs_source_binding,
    write_benchmark_case_manifest,
)

AQRS_SOURCE = b"module contract_smoke version 1 {\n  horizon 4;\n}\n"


def case_document() -> dict[str, object]:
    return {
        "schema": CASE_SCHEMA,
        "family_id": "noticer_action_window",
        "variant_id": "base",
        "split": "development",
        "aqrs": {
            "language_version": 1,
            "canonical_source_sha256": sha256(AQRS_SOURCE).hexdigest(),
        },
        "dimensions": {
            "plant_states": 4,
            "plant_transitions": 6,
            "machine_state_bound": 3,
            "machine_symbol_count": 2,
            "horizon": 4,
            "observer_count": 2,
            "observer_dimensions": 3,
        },
        "feature_tags": ["silence", "timing"],
        "obligations": ["action_window", "exactly_once"],
        "expected_outcome_class": "REALIZABLE",
        "difficulty_tier": "D2",
        "author_template_sha256": "1" * 64,
    }


def encoded(document: dict[str, object]) -> bytes:
    return yaml.safe_dump(document, sort_keys=False).encode("utf-8")


def test_reordered_yaml_has_byte_identical_canonical_form_and_digest() -> None:
    document = case_document()
    reversed_document = dict(reversed(list(document.items())))

    first = parse_benchmark_case(encoded(document))
    second = parse_benchmark_case(encoded(reversed_document).replace(b"\n", b"\r\n"))

    assert first.case_id == "noticer_action_window__base"
    assert canonical_benchmark_case_bytes(first) == canonical_benchmark_case_bytes(second)
    assert benchmark_case_sha256(first) == benchmark_case_sha256(second)


def test_source_binding_is_byte_exact() -> None:
    case = parse_benchmark_case(encoded(case_document()))
    verify_aqrs_source_binding(case, AQRS_SOURCE)

    with pytest.raises(BenchmarkCaseError, match="digest mismatch"):
        verify_aqrs_source_binding(case, AQRS_SOURCE.replace(b"4", b"5"))
    with pytest.raises(BenchmarkCaseError, match="BOM-free LF"):
        verify_aqrs_source_binding(case, AQRS_SOURCE.replace(b"\n", b"\r\n"))


def test_unknown_private_or_stable_identifier_fields_are_rejected() -> None:
    document = case_document()
    document["subject_id"] = "person-001"
    with pytest.raises(BenchmarkCaseError, match="unknown fields: subject_id"):
        parse_benchmark_case(encoded(document))

    document = case_document()
    dimensions = document["dimensions"]
    assert isinstance(dimensions, dict)
    dimensions["raw_biosignal"] = [0.1, 0.2]
    with pytest.raises(BenchmarkCaseError, match="unknown fields: raw_biosignal"):
        parse_benchmark_case(encoded(document))


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("family_id", "Noticer-01", "snake_case"),
        ("split", "test", "split must be one of"),
        ("expected_outcome_class", "TIMEOUT", "expected_outcome_class must be one of"),
        ("difficulty_tier", "easy", "difficulty_tier must be one of"),
    ],
)
def test_noncanonical_envelope_values_are_rejected(field: str, value: object, message: str) -> None:
    document = case_document()
    document[field] = value
    with pytest.raises(BenchmarkCaseError, match=message):
        parse_benchmark_case(encoded(document))


def test_bounds_and_sorted_sets_are_strict() -> None:
    document = case_document()
    dimensions = document["dimensions"]
    assert isinstance(dimensions, dict)
    dimensions["horizon"] = 0
    with pytest.raises(BenchmarkCaseError, match="dimensions.horizon"):
        parse_benchmark_case(encoded(document))

    document = case_document()
    document["feature_tags"] = ["timing", "silence"]
    with pytest.raises(BenchmarkCaseError, match="lexicographically sorted"):
        parse_benchmark_case(encoded(document))

    document = case_document()
    document["obligations"] = ["action_window", "action_window"]
    with pytest.raises(BenchmarkCaseError, match="unique"):
        parse_benchmark_case(encoded(document))


def test_held_out_case_cannot_bind_author_template() -> None:
    document = case_document()
    document["split"] = "held_out"
    with pytest.raises(BenchmarkCaseError, match="cannot bind an author template"):
        parse_benchmark_case(encoded(document))

    document["author_template_sha256"] = None
    assert parse_benchmark_case(encoded(document)).author_template_sha256 is None


def test_duplicate_keys_aliases_invalid_utf8_and_size_are_rejected() -> None:
    duplicate = encoded(case_document()) + b"schema: duplicate\n"
    with pytest.raises(BenchmarkCaseError, match="duplicate key"):
        parse_benchmark_case(duplicate)

    alias = encoded(case_document()).replace(
        b"family_id: noticer_action_window", b"family_id: &family noticer_action_window"
    )
    with pytest.raises(BenchmarkCaseError, match="aliases, anchors, and tags"):
        parse_benchmark_case(alias)

    with pytest.raises(BenchmarkCaseError, match="valid UTF-8"):
        parse_benchmark_case(b"\xff")
    with pytest.raises(BenchmarkCaseError, match="max_document_bytes"):
        parse_benchmark_case(encoded(case_document()), BenchmarkCaseLimits(max_document_bytes=8))


def test_public_manifest_is_aggregate_only_and_conflict_safe(tmp_path: Path) -> None:
    case = parse_benchmark_case(encoded(case_document()))
    manifest = benchmark_case_manifest(case)
    serialized = json.dumps(manifest, sort_keys=True)
    assert manifest["case_sha256"] == benchmark_case_sha256(case)
    assert "person-001" not in serialized
    assert "raw_biosignal" not in serialized
    assert manifest["privacy"] == {
        "private_biosignal_field_count": 0,
        "stable_person_identifier_field_count": 0,
        "aqrs_source_embedded": False,
    }

    output = tmp_path / "case-manifest.json"
    write_benchmark_case_manifest(output, case)
    first = output.read_bytes()
    write_benchmark_case_manifest(output, case)
    assert output.read_bytes() == first

    conflicting = deepcopy(case_document())
    conflicting["variant_id"] = "alternate"
    other = parse_benchmark_case(encoded(conflicting))
    with pytest.raises(BenchmarkCaseError, match="refusing to replace"):
        write_benchmark_case_manifest(output, other)
