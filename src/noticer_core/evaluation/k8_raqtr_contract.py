"""Frozen research contract for K8 Robust Action-Quotient Trace Refinement."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

CONTRACT_SCHEMA = "noticer-k8-raqtr-contract-v1"
ROOT_FIELDS = frozenset(
    {
        "schema",
        "contract_version",
        "state",
        "freeze_date",
        "parent_issue",
        "implementation_issue",
        "amendment_policy",
        "hypothesis",
        "dependencies",
        "reuse",
        "security",
        "evaluation",
        "seeds",
        "limits",
        "artifacts",
        "decision",
        "change_history",
    }
)
EXPECTED_DEPENDENCIES = {
    "k7_02": (76, "bounded_aqni_soundness", "MERGED"),
    "k7_03": (77, "inductive_caqt_certificate", "REQUIRED_UNMERGED"),
    "k7_10": (85, "no_std_wasm_translation_validation", "REQUIRED_UNMERGED"),
}
OBSERVER_EVENTS = {
    "O0_API": (
        "import_call_sequence",
        "export_return_sequence",
        "public_output_bytes",
        "public_error_code",
    ),
    "O1_TRAP": (
        "return_kind",
        "trap_kind",
        "termination",
        "bounded_nontermination",
    ),
    "O2_CONTROL": (
        "branch_outcomes",
        "direct_call_sequence",
        "loop_iterations",
    ),
    "O3_INSTRUCTION": ("opcode_sequence", "opcode_count", "opcode_histogram"),
    "O4_MEMORY": (
        "memory_address",
        "access_width",
        "access_kind",
        "memory_page_count",
    ),
    "O5_SERVICE": (
        "all_declared_profiles",
        "service_alias",
        "public_slot",
        "reset_handoff_order",
    ),
    "O6_COLLUSION": ("combined_module_instance_trace",),
}
ADVERSARY_ALLOWED = frozenset(
    {
        "arbitrary_public_call_order",
        "adaptive_public_input",
        "adaptive_public_fault",
        "reset",
        "handoff",
        "malformed_input_length",
        "unknown_enum",
        "expired_public_slot",
        "repeated_calls",
        "observation_adaptive_calls",
        "public_randomness",
        "multiservice_context",
    }
)
ADVERSARY_FORBIDDEN = frozenset(
    {
        "direct_linear_memory_read",
        "private_capability_acquisition",
        "hidden_private_function_call",
        "runtime_bytecode_mutation",
        "engine_semantics_violation",
        "root_os_process_memory_read",
        "direct_microarchitectural_cache_observation",
    }
)
REQUIRED_GUARANTEES = (
    "robust_action_quotient_noninterference",
    "restricted_context_trace_refinement",
    "utility_preservation",
)
REQUIRED_UTILITY = (
    "authorized_action_exactly_once",
    "public_deadline_preserved",
    "unauthorized_action_zero",
    "duplicate_action_zero",
    "recoverable_fault_preserved",
    "invalid_call_fails_closed",
)
REQUIRED_OUTCOMES = {
    "success": ("QSM_VALID",),
    "counterexample": (
        "RAQTR_COUNTEREXAMPLE",
        "TRACE_REFINEMENT_COUNTEREXAMPLE",
        "UTILITY_COUNTEREXAMPLE",
        "RESOURCE_TRACE_COUNTEREXAMPLE",
    ),
    "inconclusive": (
        "TIMEOUT",
        "RESOURCE_BOUND",
        "PARSER_DISAGREEMENT",
        "ENGINE_DISAGREEMENT",
        "CHECKER_UNAVAILABLE",
        "COMPILER_UNAVAILABLE",
    ),
    "invalid": (
        "INVALID_SOURCE_CERTIFICATE",
        "INVALID_WASM",
        "UNSUPPORTED_WASM_FEATURE",
        "INVALID_ABI",
        "INVALID_RELATION",
        "INVALID_CAPSULE",
        "UNSUPPORTED_VERSION",
        "MALFORMED_ARTIFACT",
    ),
}
FROZEN_GATES = {
    "min_module_families": 16,
    "min_compiler_configs": 12,
    "min_mutants": 30,
    "min_context_families": 12,
    "min_engines": 2,
    "min_explicit_call_prefix": 256,
    "min_noticer_modules": 5,
    "min_generic_families": 8,
    "min_negative_families": 8,
    "max_source_target_mismatches": 0,
    "max_accepted_mutant_leaks": 0,
    "held_out_mutation_detection": 1.0,
}
FROZEN_SEEDS = {
    "compiler_matrix": 48001,
    "mutation": 48002,
    "context": 48003,
    "engine": 48004,
    "attack": 48005,
    "performance": 48006,
    "split": 48007,
    "capsule": 48008,
}
FROZEN_LIMITS = {
    "parser_seconds": 30,
    "validator_seconds": 300,
    "context_checker_seconds": 600,
    "memory_mb": 8192,
    "max_module_bytes": 2097152,
    "max_capsule_bytes": 16777216,
    "max_functions": 1024,
    "max_instructions": 1000000,
    "max_context_states": 4096,
    "max_product_states": 5000000,
    "explicit_call_prefix": 256,
    "fuel_per_call": 1000000,
}
FORBIDDEN_ARTIFACT_KEYS = frozenset(
    {
        "raw_ppg",
        "raw_acc",
        "biosignal",
        "baseline_values",
        "private_history",
        "private_margin",
        "private_ready_time",
        "participant_id",
        "device_id",
        "stable_identifier",
        "key_material",
        "token_bytes",
        "permit_signature",
        "lease_bytes",
    }
)
REQUIRED_OUTPUTS = frozenset(
    {
        "frozen_contract.json",
        "compiler_matrix.csv",
        "mutation_results.csv",
        "cross_engine_results.csv",
        "robust_context_results.csv",
        "resource_results.csv",
        "attack_results.csv",
        "performance_results.csv",
        "ablation_results.csv",
        "invariant_report.json",
        "run.log",
    }
)
FROZEN_DECISIONS = {
    "go_all": frozenset(
        {
            "k7_final_not_kill",
            "lean_theorem_without_sorry",
            "independent_checker_accepts_valid_qsm",
            "required_mutants_rejected",
            "held_out_mutation_detection_100_percent",
            "source_target_refinement_100_percent",
            "vulnerable_baseline_context_counterexample",
            "no_full_qseal_counterexample_within_bound",
            "private_ingress_resource_trace_equal",
            "two_engines_agree",
            "three_compiler_configs_accept",
            "five_noticer_modules_validate",
            "four_generic_families_validate",
            "materially_exceeds_k7_one_step",
            "resource_only_leak_detected",
            "arbitrary_finite_prefix_theorem_checked",
        }
    ),
    "pivot_any": frozenset(
        {
            "sealed_admission_too_hard",
            "exact_opcode_trace_too_strong",
            "memory_trace_too_expensive",
            "general_context_synthesis_too_large",
            "rustc_output_outside_subset",
            "cross_engine_subset_disagreement",
            "quotient_pad_only_bounded",
            "lean_target_semantics_must_reduce",
            "generic_benchmark_too_weak",
        }
    ),
    "kill_any": frozenset(
        {
            "only_repeats_k7_state_output_comparison",
            "adversarial_context_missing",
            "target_only_surface_ignored",
            "private_api_publicly_reachable",
            "accepted_mutant_leaks",
            "checker_trusts_manifest_without_binary_parse",
            "hardcoded_module_relation",
            "capsule_validation_is_test_execution_only",
            "resource_claim_uses_wall_clock_only",
            "unsupported_wasm_silently_accepted",
            "optimizer_breakage_undetected",
            "malicious_context_breaks_utility",
            "preservation_theorem_contains_sorry",
            "no_contribution_beyond_k7",
        }
    ),
}
_SHA256 = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True)
class RaqtrContractValidation:
    """Validation result for the frozen K8 research contract."""

    errors: tuple[str, ...]

    @property
    def valid(self) -> bool:
        """Return true when no frozen-contract violation was found."""

        return not self.errors


def load_raqtr_contract(path: Path) -> dict[str, Any]:
    """Load and strictly validate one UTF-8 K8 YAML contract."""

    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, Mapping):
        raise ValueError("RAQTR contract root must be an object")
    contract = dict(loaded)
    result = validate_raqtr_contract(contract)
    if not result.valid:
        raise ValueError("; ".join(result.errors))
    return contract


def validate_raqtr_contract(contract: Mapping[str, Any]) -> RaqtrContractValidation:
    """Validate K7 reuse, security boundary, gates, and outcome invariants."""

    errors: list[str] = []
    errors.extend(_field_errors("root", set(contract), ROOT_FIELDS))
    if contract.get("schema") != CONTRACT_SCHEMA:
        errors.append(f"schema must be {CONTRACT_SCHEMA}")
    if contract.get("contract_version") != 1:
        errors.append("contract_version must be 1")
    if contract.get("state") != "FROZEN":
        errors.append("state must be FROZEN")
    if contract.get("freeze_date") != "2026-08-17":
        errors.append("freeze_date must identify version 1 freeze")
    if contract.get("parent_issue") != 95 or contract.get("implementation_issue") != 96:
        errors.append("K8-00 issue bindings must remain #95 and #96")
    if contract.get("amendment_policy") != "new_version_required":
        errors.append("amendment_policy must require a new version")
    hypothesis = contract.get("hypothesis")
    if not isinstance(hypothesis, str) or not hypothesis:
        errors.append("hypothesis must be non-empty")

    _validate_dependencies(
        _mapping(contract.get("dependencies"), "dependencies", errors), errors
    )
    _validate_reuse(_mapping(contract.get("reuse"), "reuse", errors), errors)
    _validate_security(
        _mapping(contract.get("security"), "security", errors), errors
    )
    _validate_evaluation(
        _mapping(contract.get("evaluation"), "evaluation", errors), errors
    )
    _validate_exact_mapping(contract.get("seeds"), FROZEN_SEEDS, "seeds", errors)
    _validate_exact_mapping(contract.get("limits"), FROZEN_LIMITS, "limits", errors)
    _validate_artifacts(
        _mapping(contract.get("artifacts"), "artifacts", errors), errors
    )
    _validate_decision(
        _mapping(contract.get("decision"), "decision", errors), errors
    )
    _validate_change_history(contract.get("change_history"), errors)
    return RaqtrContractValidation(tuple(errors))


def contract_fingerprint(contract: Mapping[str, Any]) -> str:
    """Return the domain-separated canonical SHA-256 of a valid contract."""

    result = validate_raqtr_contract(contract)
    if not result.valid:
        raise ValueError("; ".join(result.errors))
    encoded = json.dumps(
        contract,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(b"NOTICER_K8_RAQTR_CONTRACT_V1\x00" + encoded).hexdigest()


def _validate_dependencies(value: Mapping[str, Any], errors: list[str]) -> None:
    errors.extend(
        _field_errors("dependencies", set(value), frozenset(EXPECTED_DEPENDENCIES))
    )
    for name, (issue, requirement, status) in EXPECTED_DEPENDENCIES.items():
        dependency = _mapping(value.get(name), f"dependencies.{name}", errors)
        expected_fields = frozenset({"issue", "requirement", "status", "merge_commit"})
        errors.extend(_field_errors(f"dependencies.{name}", set(dependency), expected_fields))
        if dependency.get("issue") != issue:
            errors.append(f"dependencies.{name}.issue must be {issue}")
        if dependency.get("requirement") != requirement:
            errors.append(f"dependencies.{name}.requirement changed")
        if dependency.get("status") != status:
            errors.append(f"dependencies.{name}.status must be {status}")
        merge_commit = dependency.get("merge_commit")
        if status == "MERGED":
            if not isinstance(merge_commit, str) or _SHA256.fullmatch(merge_commit) is None:
                errors.append(f"dependencies.{name}.merge_commit must be a full Git SHA")
        elif merge_commit is not None:
            errors.append(f"dependencies.{name}.merge_commit must remain null before merge")


def _validate_reuse(value: Mapping[str, Any], errors: list[str]) -> None:
    expected = frozenset(
        {
            "action_equivalence",
            "source_certificate",
            "generated_runtime",
            "copy_unmerged_k7_types_allowed",
            "redefine_k7_manifest_allowed",
            "redefine_k7_certificate_allowed",
        }
    )
    errors.extend(_field_errors("reuse", set(value), expected))
    action = _mapping(value.get("action_equivalence"), "reuse.action_equivalence", errors)
    if action != {
        "source": "docs/aetp_security_definition.md",
        "symbol": "H0 ~=_A,C H1",
    }:
        errors.append("action equivalence must reference the existing AETP definition")
    source = _mapping(value.get("source_certificate"), "reuse.source_certificate", errors)
    if source != {
        "source": "configs/quotient_forge/k7_research.yaml",
        "producer": "K7_CAQT",
    }:
        errors.append("source certificate must reference K7 CAQT")
    runtime = _mapping(value.get("generated_runtime"), "reuse.generated_runtime", errors)
    if runtime != {"issue": 85, "producer": "K7_CODEGEN"}:
        errors.append("generated runtime must reference K7-10")
    for field in (
        "copy_unmerged_k7_types_allowed",
        "redefine_k7_manifest_allowed",
        "redefine_k7_certificate_allowed",
    ):
        if value.get(field) is not False:
            errors.append(f"reuse.{field} must remain false")


def _validate_security(value: Mapping[str, Any], errors: list[str]) -> None:
    expected = frozenset(
        {
            "notion",
            "abbreviation",
            "artifact",
            "artifact_abbreviation",
            "artifact_extension",
            "guarantees",
            "observer_profiles",
            "adversary",
            "utility",
            "tcb",
            "untrusted",
            "nonclaims",
        }
    )
    errors.extend(_field_errors("security", set(value), expected))
    scalar_expected = {
        "notion": "robust_action_quotient_trace_refinement",
        "abbreviation": "RAQTR",
        "artifact": "quotient_sealed_module",
        "artifact_abbreviation": "QSM",
        "artifact_extension": ".qseal",
    }
    for field, expected_value in scalar_expected.items():
        if value.get(field) != expected_value:
            errors.append(f"security.{field} changed from frozen value")
    if tuple(value.get("guarantees", ())) != REQUIRED_GUARANTEES:
        errors.append("security.guarantees changed from frozen values")
    if tuple(value.get("utility", ())) != REQUIRED_UTILITY:
        errors.append("security.utility changed from frozen values")
    _validate_observers(value.get("observer_profiles"), errors)
    adversary = _mapping(value.get("adversary"), "security.adversary", errors)
    if adversary.get("class") != "capability_scoped_language_level":
        errors.append("security.adversary.class changed")
    allowed = _string_set(adversary.get("allowed"), "security.adversary.allowed", errors)
    forbidden = _string_set(
        adversary.get("forbidden"), "security.adversary.forbidden", errors
    )
    if allowed != ADVERSARY_ALLOWED:
        errors.append("security.adversary.allowed changed from frozen values")
    if forbidden != ADVERSARY_FORBIDDEN:
        errors.append("security.adversary.forbidden changed from frozen values")
    if allowed & forbidden:
        errors.append("adversary allowed and forbidden capabilities must be disjoint")
    tcb = _string_set(value.get("tcb"), "security.tcb", errors)
    untrusted = _string_set(value.get("untrusted"), "security.untrusted", errors)
    if not tcb or not untrusted or tcb & untrusted:
        errors.append("security TCB and untrusted registries must be non-empty and disjoint")
    nonclaims = _string_set(value.get("nonclaims"), "security.nonclaims", errors)
    if "native_machine_cycle_equality" not in nonclaims:
        errors.append("microarchitectural timing must remain an explicit non-claim")
    if "physical_hardware_verification" not in nonclaims:
        errors.append("physical hardware must remain an explicit non-claim")


def _validate_observers(value: object, errors: list[str]) -> None:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        errors.append("security.observer_profiles must be an array")
        return
    observed: dict[str, tuple[str, ...]] = {}
    for index, item in enumerate(value):
        profile = _mapping(item, f"security.observer_profiles[{index}]", errors)
        errors.extend(
            _field_errors(
                f"security.observer_profiles[{index}]",
                set(profile),
                frozenset({"id", "events"}),
            )
        )
        identifier = profile.get("id")
        events = profile.get("events")
        if not isinstance(identifier, str) or not _is_unique_string_sequence(events):
            errors.append(f"security.observer_profiles[{index}] is malformed")
            continue
        if identifier in observed:
            errors.append(f"duplicate observer profile: {identifier}")
        observed[identifier] = tuple(events)
    if observed != OBSERVER_EVENTS:
        errors.append("observer profile registry changed from O0-O6 frozen values")


def _validate_evaluation(value: Mapping[str, Any], errors: list[str]) -> None:
    expected = frozenset(
        {
            "split_unit",
            "row_random_split_allowed",
            "splits",
            "warmup_runs",
            "repetitions",
            "gates",
            "outcomes",
            "stop_conditions",
            "metrics",
        }
    )
    errors.extend(_field_errors("evaluation", set(value), expected))
    if value.get("split_unit") != "module_family":
        errors.append("evaluation.split_unit must be module_family")
    if value.get("row_random_split_allowed") is not False:
        errors.append("row random split must remain disabled")
    if tuple(value.get("splits", ())) != ("train", "development", "held_out"):
        errors.append("evaluation.splits changed from frozen values")
    if value.get("warmup_runs") != 1 or value.get("repetitions") != 5:
        errors.append("evaluation repetitions must remain one warmup plus five measured runs")
    gates = _mapping(value.get("gates"), "evaluation.gates", errors)
    if dict(gates) != FROZEN_GATES:
        errors.append("evaluation.gates changed from frozen values")
    outcomes = _mapping(value.get("outcomes"), "evaluation.outcomes", errors)
    if set(outcomes) != set(REQUIRED_OUTCOMES):
        errors.append("evaluation.outcomes has incorrect groups")
    groups: list[set[str]] = []
    for name, expected_outcomes in REQUIRED_OUTCOMES.items():
        actual = outcomes.get(name)
        if not _is_unique_string_sequence(actual) or tuple(actual) != expected_outcomes:
            errors.append(f"evaluation.outcomes.{name} changed from frozen values")
        else:
            groups.append(set(actual))
    if groups and sum(map(len, groups)) != len(set().union(*groups)):
        errors.append("evaluation outcome groups must be disjoint")
    for field in ("stop_conditions", "metrics"):
        if not _is_unique_string_sequence(value.get(field)):
            errors.append(f"evaluation.{field} must be a non-empty unique list")


def _validate_exact_mapping(
    value: object,
    expected: Mapping[str, int],
    location: str,
    errors: list[str],
) -> None:
    mapping = _mapping(value, location, errors)
    if dict(mapping) != dict(expected):
        errors.append(f"{location} changed from frozen values")
    values = tuple(mapping.values())
    if any(not isinstance(item, int) or isinstance(item, bool) or item <= 0 for item in values):
        errors.append(f"{location} values must be positive integers")
    if location == "seeds" and len(values) != len(set(values)):
        errors.append("seed values must be pairwise distinct")


def _validate_artifacts(value: Mapping[str, Any], errors: list[str]) -> None:
    expected = frozenset(
        {
            "root",
            "contract_schema_path",
            "generated_committed",
            "private_field_count",
            "required_outputs",
            "forbidden_keys",
        }
    )
    errors.extend(_field_errors("artifacts", set(value), expected))
    if value.get("root") != "artifacts/k8_quotient_seal":
        errors.append("artifacts.root changed")
    if value.get("contract_schema_path") != "schemas/k8_raqtr_contract.schema.json":
        errors.append("artifacts.contract_schema_path changed")
    if value.get("generated_committed") is not False:
        errors.append("generated K8 artifacts must not be committed")
    if value.get("private_field_count") != 0:
        errors.append("artifacts.private_field_count must be zero")
    outputs = _string_set(value.get("required_outputs"), "artifacts.required_outputs", errors)
    if outputs != REQUIRED_OUTPUTS:
        errors.append("artifacts.required_outputs changed from frozen values")
    forbidden = _string_set(value.get("forbidden_keys"), "artifacts.forbidden_keys", errors)
    if forbidden != FORBIDDEN_ARTIFACT_KEYS:
        errors.append("artifacts.forbidden_keys changed from privacy denylist")


def _validate_decision(value: Mapping[str, Any], errors: list[str]) -> None:
    errors.extend(
        _field_errors("decision", set(value), frozenset(FROZEN_DECISIONS))
    )
    groups: list[frozenset[str]] = []
    for name, expected in FROZEN_DECISIONS.items():
        actual = _string_set(value.get(name), f"decision.{name}", errors)
        if actual != expected:
            errors.append(f"decision.{name} changed from frozen values")
        groups.append(actual)
    if sum(map(len, groups)) != len(set().union(*groups)):
        errors.append("GO, PIVOT, and KILL identifiers must be disjoint")


def _validate_change_history(value: object, errors: list[str]) -> None:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)) or len(value) != 1:
        errors.append("change_history must contain exactly the version 1 entry")
        return
    entry = value[0]
    if not isinstance(entry, Mapping) or set(entry) != {"version", "date", "reason"}:
        errors.append("change_history entry has invalid fields")
        return
    if entry.get("version") != 1 or entry.get("date") != "2026-08-17":
        errors.append("change_history must identify frozen version 1")
    if not isinstance(entry.get("reason"), str) or not entry["reason"]:
        errors.append("change_history reason must be non-empty")


def _mapping(value: object, location: str, errors: list[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        errors.append(f"{location} must be an object")
        return {}
    return value


def _field_errors(
    location: str, actual: set[str], expected: frozenset[str]
) -> list[str]:
    errors: list[str] = []
    missing = expected - actual
    unknown = actual - expected
    if missing:
        errors.append(f"{location} is missing fields: {sorted(missing)}")
    if unknown:
        errors.append(f"{location} has unknown fields: {sorted(unknown)}")
    return errors


def _is_unique_string_sequence(value: object) -> bool:
    return (
        isinstance(value, Sequence)
        and not isinstance(value, (str, bytes))
        and bool(value)
        and all(isinstance(item, str) and item for item in value)
        and len(value) == len(set(value))
    )


def _string_set(value: object, location: str, errors: list[str]) -> frozenset[str]:
    if not _is_unique_string_sequence(value):
        errors.append(f"{location} must be a non-empty unique string list")
        return frozenset()
    return frozenset(value)
