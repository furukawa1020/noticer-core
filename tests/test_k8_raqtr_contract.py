from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

from noticer_core.evaluation.k8_raqtr_contract import (
    ADVERSARY_ALLOWED,
    ADVERSARY_FORBIDDEN,
    CONTRACT_SCHEMA,
    FORBIDDEN_ARTIFACT_KEYS,
    OBSERVER_EVENTS,
    ROOT_FIELDS,
    contract_fingerprint,
    load_raqtr_contract,
    validate_raqtr_contract,
)

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs" / "quotient_seal" / "k8_research.yaml"
SCHEMA = ROOT / "schemas" / "k8_raqtr_contract.schema.json"
DOC = ROOT / "docs" / "quotient_seal_research_contract.md"


def _contract() -> dict[str, object]:
    return load_raqtr_contract(CONFIG)


def test_frozen_contract_has_stable_canonical_fingerprint() -> None:
    contract = _contract()
    reordered = dict(reversed(list(contract.items())))

    assert contract_fingerprint(contract) == contract_fingerprint(reordered)
    assert contract["state"] == "FROZEN"
    assert contract["contract_version"] == 1


def test_schema_and_runtime_validator_share_root_contract() -> None:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))

    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == ROOT_FIELDS
    assert set(schema["properties"]) == ROOT_FIELDS
    assert schema["properties"]["schema"]["const"] == CONTRACT_SCHEMA


def test_k7_dependencies_are_references_and_unmerged_types_cannot_be_copied() -> None:
    contract = _contract()
    dependencies = contract["dependencies"]
    reuse = contract["reuse"]

    assert dependencies["k7_02"]["status"] == "MERGED"
    assert dependencies["k7_03"]["status"] == "REQUIRED_UNMERGED"
    assert dependencies["k7_10"]["status"] == "REQUIRED_UNMERGED"
    assert reuse["copy_unmerged_k7_types_allowed"] is False
    assert reuse["redefine_k7_certificate_allowed"] is False

    changed = deepcopy(contract)
    changed["reuse"]["copy_unmerged_k7_types_allowed"] = True
    result = validate_raqtr_contract(changed)
    assert not result.valid
    assert any("copy_unmerged_k7_types_allowed" in error for error in result.errors)


def test_observer_registry_is_complete_and_cannot_drop_memory_trace() -> None:
    contract = _contract()
    profiles = contract["security"]["observer_profiles"]
    actual = {profile["id"]: tuple(profile["events"]) for profile in profiles}

    assert actual == OBSERVER_EVENTS

    changed = deepcopy(contract)
    changed["security"]["observer_profiles"] = [
        profile
        for profile in changed["security"]["observer_profiles"]
        if profile["id"] != "O4_MEMORY"
    ]
    result = validate_raqtr_contract(changed)
    assert not result.valid
    assert any("O0-O6" in error for error in result.errors)


def test_adversary_capabilities_are_explicit_and_disjoint() -> None:
    contract = _contract()
    adversary = contract["security"]["adversary"]

    assert set(adversary["allowed"]) == ADVERSARY_ALLOWED
    assert set(adversary["forbidden"]) == ADVERSARY_FORBIDDEN
    assert not ADVERSARY_ALLOWED & ADVERSARY_FORBIDDEN
    assert "private_capability_acquisition" in ADVERSARY_FORBIDDEN


def test_inconclusive_results_cannot_be_relabelled_as_success() -> None:
    contract = _contract()
    outcomes = contract["evaluation"]["outcomes"]
    assert outcomes["success"] == ["QSM_VALID"]
    assert "RESOURCE_BOUND" in outcomes["inconclusive"]
    assert "PARSER_DISAGREEMENT" in outcomes["inconclusive"]
    assert "UNSUPPORTED_WASM_FEATURE" in outcomes["invalid"]

    changed = deepcopy(contract)
    changed_outcomes = changed["evaluation"]["outcomes"]
    changed_outcomes["inconclusive"].remove("RESOURCE_BOUND")
    changed_outcomes["success"].append("RESOURCE_BOUND")
    result = validate_raqtr_contract(changed)
    assert not result.valid
    assert any("outcomes.success" in error for error in result.errors)


def test_evaluation_gate_and_module_family_split_are_frozen() -> None:
    contract = _contract()
    evaluation = contract["evaluation"]
    gates = evaluation["gates"]

    assert evaluation["split_unit"] == "module_family"
    assert evaluation["row_random_split_allowed"] is False
    assert gates["min_module_families"] == 16
    assert gates["min_compiler_configs"] == 12
    assert gates["min_mutants"] == 30
    assert gates["min_context_families"] == 12
    assert gates["min_engines"] == 2
    assert gates["min_explicit_call_prefix"] == 256

    changed = deepcopy(contract)
    changed["evaluation"]["row_random_split_allowed"] = True
    changed["evaluation"]["gates"]["min_mutants"] = 20
    result = validate_raqtr_contract(changed)
    assert not result.valid
    assert any("row random" in error for error in result.errors)
    assert any("evaluation.gates" in error for error in result.errors)


def test_artifact_boundary_rejects_private_field_drift() -> None:
    contract = _contract()
    artifacts = contract["artifacts"]

    assert artifacts["generated_committed"] is False
    assert artifacts["private_field_count"] == 0
    assert set(artifacts["forbidden_keys"]) == FORBIDDEN_ARTIFACT_KEYS

    changed = deepcopy(contract)
    changed["artifacts"]["forbidden_keys"].remove("raw_ppg")
    result = validate_raqtr_contract(changed)
    assert not result.valid
    assert any("privacy denylist" in error for error in result.errors)


def test_kill_contract_contains_target_and_context_falsifiers() -> None:
    contract = _contract()
    kill = set(contract["decision"]["kill_any"])

    assert "adversarial_context_missing" in kill
    assert "target_only_surface_ignored" in kill
    assert "accepted_mutant_leaks" in kill
    assert "preservation_theorem_contains_sorry" in kill


def test_document_names_machine_contract_and_nonclaims() -> None:
    document = DOC.read_text(encoding="utf-8")
    normalized = " ".join(document.split())

    assert "configs/quotient_seal/k8_research.yaml" in document
    assert "schemas/k8_raqtr_contract.schema.json" in document
    assert "`QSM_VALID` is the only success outcome" in document
    assert "physical hardware verification" in normalized
