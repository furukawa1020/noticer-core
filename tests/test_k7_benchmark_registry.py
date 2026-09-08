from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from noticer_core.evaluation.benchmark_registry import (
    PUBLIC_MANIFEST_FIELDS,
    build_benchmark_registry_manifest,
    load_benchmark_registry,
    serialize_benchmark_registry_manifest,
    validate_benchmark_registry,
    validate_benchmark_registry_manifest,
    validate_variant_assignments,
    write_benchmark_registry_manifest,
)
from noticer_core.evaluation.k7_research_contract import (
    build_research_manifest,
    load_research_contract,
)

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "configs" / "quotient_forge" / "benchmark_family_registry_v1.yaml"
CONTRACT = ROOT / "configs" / "quotient_forge" / "k7_research.yaml"
SCHEMA = ROOT / "schemas" / "k7_benchmark_family_manifest_v1.schema.json"


def _inputs() -> tuple[dict[str, object], dict[str, object]]:
    contract = load_research_contract(CONTRACT)
    registry = load_benchmark_registry(REGISTRY, contract)
    return registry, contract


def test_registry_matches_frozen_k7_catalog_and_split_hashes() -> None:
    registry, contract = _inputs()
    manifest = build_benchmark_registry_manifest(registry, contract)
    research = build_research_manifest(contract)

    assert manifest["benchmark_catalog_sha256"] == research["benchmark_catalog_sha256"]
    assert manifest["split_sha256"] == research["split_sha256"]
    assert manifest["family_count"] == 24
    assert manifest["category_counts"] == {"noticer": 8, "generic": 8, "negative": 8}
    assert manifest["split_counts"] == {"train": 8, "development": 8, "held_out": 8}
    assert manifest["private_field_count"] == 0


def test_registry_row_order_does_not_change_canonical_manifest() -> None:
    registry, contract = _inputs()
    reordered = deepcopy(registry)
    reordered["families"].reverse()

    first = build_benchmark_registry_manifest(registry, contract)
    second = build_benchmark_registry_manifest(reordered, contract)
    assert serialize_benchmark_registry_manifest(first) == serialize_benchmark_registry_manifest(
        second
    )


def test_family_tamper_duplicate_and_split_drift_are_rejected() -> None:
    registry, contract = _inputs()
    tampered = deepcopy(registry)
    tampered["families"][0]["id"] = "noticer_replacement_after_results"
    tampered["families"][1]["split_ordinal"] = 0

    result = validate_benchmark_registry(tampered, contract)
    assert not result.valid
    assert any("duplicate split slot" in error for error in result.errors)
    assert any("differ from K7-00" in error for error in result.errors)


def test_variants_inherit_family_split_and_cross_split_leakage_fails() -> None:
    registry, _ = _inputs()
    valid = [
        {
            "variant_id": "aets_fixed_cadence_base",
            "spec_family": "noticer_aets_fixed_cadence",
            "split": "train",
        },
        {
            "variant_id": "collusion_base",
            "spec_family": "noticer_multiservice_collusion",
            "split": "held_out",
        },
    ]
    assert validate_variant_assignments(valid, registry).valid

    leaked = deepcopy(valid)
    leaked[1]["split"] = "development"
    result = validate_variant_assignments(leaked, registry)
    assert not result.valid
    assert any("variant split leakage" in error for error in result.errors)


def test_duplicate_variant_and_private_payload_are_rejected() -> None:
    registry, _ = _inputs()
    assignments = [
        {
            "variant_id": "same_variant",
            "spec_family": "generic_public_retry",
            "split": "train",
        },
        {
            "variant_id": "same_variant",
            "spec_family": "generic_public_retry",
            "split": "train",
            "private_history": "forbidden",
        },
    ]
    result = validate_variant_assignments(assignments, registry)
    assert not result.valid
    assert any("duplicate variant" in error for error in result.errors)
    assert any("forbidden field" in error for error in result.errors)


def test_public_schema_and_runtime_validator_share_exact_allowlist() -> None:
    registry, contract = _inputs()
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == PUBLIC_MANIFEST_FIELDS
    assert set(schema["properties"]) == PUBLIC_MANIFEST_FIELDS

    manifest = build_benchmark_registry_manifest(registry, contract)
    manifest["participant_id"] = "forbidden"
    result = validate_benchmark_registry_manifest(manifest, registry, contract)
    assert not result.valid
    assert any("forbidden field" in error for error in result.errors)


def test_writer_is_idempotent_and_refuses_conflicting_evidence(tmp_path: Path) -> None:
    output = tmp_path / "family-manifest.json"
    write_benchmark_registry_manifest(REGISTRY, CONTRACT, output)
    original = output.read_bytes()
    write_benchmark_registry_manifest(REGISTRY, CONTRACT, output)
    assert output.read_bytes() == original

    output.write_text("{}\n", encoding="utf-8")
    with pytest.raises(FileExistsError, match="differs"):
        write_benchmark_registry_manifest(REGISTRY, CONTRACT, output)
