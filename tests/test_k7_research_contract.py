from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from noticer_core.evaluation.k7_research_contract import (
    PUBLIC_MANIFEST_FIELDS,
    build_research_manifest,
    load_research_contract,
    serialize_manifest,
    validate_public_manifest,
    validate_research_contract,
    write_research_manifest,
)

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs" / "quotient_forge" / "k7_research.yaml"
SCHEMA = ROOT / "schemas" / "k7_research_manifest_public.schema.json"


def _contract() -> dict[str, object]:
    return load_research_contract(CONFIG)


def test_frozen_contract_builds_byte_identical_manifest() -> None:
    contract = _contract()

    first = build_research_manifest(contract)
    reordered = dict(reversed(list(contract.items())))
    second = build_research_manifest(reordered)

    assert serialize_manifest(first) == serialize_manifest(second)
    assert first["family_counts"] == {
        "generic": 8,
        "negative": 8,
        "noticer": 8,
        "total": 24,
    }
    assert first["private_field_count"] == 0


def test_family_splits_are_disjoint_and_row_random_is_disabled() -> None:
    contract = _contract()
    splits = contract["benchmark"]["splits"]
    groups = [set(splits[name]) for name in ("train", "development", "held_out")]

    assert all(len(group) == 8 for group in groups)
    assert sum(len(group) for group in groups) == len(set().union(*groups))
    assert contract["evaluation"]["split_unit"] == "spec_family"
    assert contract["evaluation"]["row_random_split_allowed"] is False


def test_row_random_split_and_gate_drift_are_rejected() -> None:
    contract = _contract()
    contract["evaluation"]["row_random_split_allowed"] = True
    contract["gates"]["scalability"]["min_horizon"] = 32

    result = validate_research_contract(contract)

    assert not result.valid
    assert any("row random" in error for error in result.errors)
    assert any("12x8x64x4" in error for error in result.errors)


def test_timeout_cannot_be_relabelled_as_bounded_negative() -> None:
    contract = _contract()
    outcomes = contract["evaluation"]["outcomes"]
    outcomes["bounded_negative"].append("TIMEOUT")
    outcomes["inconclusive"].remove("TIMEOUT")

    result = validate_research_contract(contract)

    assert not result.valid
    assert any("bounded_negative" in error for error in result.errors)
    assert any("inconclusive" in error for error in result.errors)


def test_public_manifest_rejects_private_and_unknown_fields() -> None:
    contract = _contract()
    manifest = build_research_manifest(contract)
    manifest["nested"] = {"raw-ppg": [1, 2, 3]}

    result = validate_public_manifest(manifest, contract)

    assert not result.valid
    assert any("forbidden public field" in error for error in result.errors)
    assert any("unknown fields" in error for error in result.errors)


def test_schema_and_runtime_validator_share_the_allowlist() -> None:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))

    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == PUBLIC_MANIFEST_FIELDS
    assert set(schema["properties"]) == PUBLIC_MANIFEST_FIELDS


def test_writer_is_idempotent_and_rejects_conflicting_existing_file(
    tmp_path: Path,
) -> None:
    output = tmp_path / "manifest.json"

    write_research_manifest(CONFIG, output)
    original = output.read_bytes()
    write_research_manifest(CONFIG, output)
    assert output.read_bytes() == original

    output.write_text("{}\n", encoding="utf-8")
    with pytest.raises(FileExistsError, match="differs"):
        write_research_manifest(CONFIG, output)


def test_contract_hash_changes_only_through_a_new_contract() -> None:
    contract = _contract()
    original = build_research_manifest(contract)["contract_sha256"]
    changed = deepcopy(contract)
    changed["hypothesis"] = "changed_after_freeze"

    changed_result = validate_research_contract(changed)
    changed_hash = build_research_manifest(changed)["contract_sha256"]

    assert changed_result.valid
    assert changed_hash != original

