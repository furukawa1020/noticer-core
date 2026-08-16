"""Frozen, public-only research contract for K7 AQRS evaluation."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

CONTRACT_SCHEMA = "noticer-k7-research-contract-v1"
MANIFEST_SCHEMA = "noticer-k7-research-manifest-v1"

ROOT_FIELDS = frozenset(
    {
        "schema",
        "contract_version",
        "state",
        "amendment_policy",
        "hypothesis",
        "evaluation",
        "seeds",
        "limits",
        "gates",
        "benchmark",
        "artifact",
        "change_history",
    }
)
PUBLIC_MANIFEST_FIELDS = frozenset(
    {
        "schema",
        "contract_version",
        "state",
        "contract_sha256",
        "benchmark_catalog_sha256",
        "split_sha256",
        "seed_registry_sha256",
        "limit_registry_sha256",
        "gate_registry_sha256",
        "split_unit",
        "row_random_split_allowed",
        "outcomes",
        "family_counts",
        "private_field_count",
    }
)
FORBIDDEN_PUBLIC_KEYS = frozenset(
    {
        "acc_samples",
        "attestation_chain",
        "baseline_values",
        "certificate_chain",
        "consent_document",
        "device_id",
        "key_material",
        "lease_bytes",
        "participant_id",
        "permit_signature",
        "ppg_samples",
        "private_history",
        "raw_acc",
        "raw_ppg",
        "stable_identifier",
        "token_bytes",
    }
)
REQUIRED_SEEDS = frozenset({"catalog", "synthesis", "attack", "split", "mutation"})
REQUIRED_LIMITS = frozenset(
    {
        "solver_seconds",
        "checker_seconds",
        "memory_mb",
        "max_candidates",
        "max_checker_nodes",
        "max_artifact_bytes",
    }
)
REQUIRED_OUTCOMES = {
    "success": ("CERTIFICATE_VALID",),
    "bounded_negative": ("UNSAT_AT_BOUND", "UNREALIZABLE_WITHIN_BOUNDS"),
    "inconclusive": (
        "TIMEOUT",
        "RESOURCE_LIMIT",
        "SOLVER_UNAVAILABLE",
        "SOLVER_UNKNOWN",
        "CHECKER_INCONCLUSIVE",
    ),
    "invalid": (
        "INVALID_SPEC",
        "INVALID_CANDIDATE",
        "INVALID_CERTIFICATE",
        "MALFORMED_SOLVER_OUTPUT",
    ),
}
REQUIRED_METRICS = frozenset(
    {
        "checker_status",
        "solver_status",
        "wall_time_ms",
        "cpu_time_ms",
        "peak_rss_mb",
        "candidates",
        "checker_nodes",
        "solver_calls",
        "pointwise_divergences",
        "utility_violations",
        "attack_auc",
        "attack_advantage",
        "excess_advantage",
        "cost_vector",
    }
)
SPLIT_NAMES = ("train", "development", "held_out")
HASH_FIELDS = frozenset(
    {
        "contract_sha256",
        "benchmark_catalog_sha256",
        "split_sha256",
        "seed_registry_sha256",
        "limit_registry_sha256",
        "gate_registry_sha256",
    }
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FAMILY_ID = re.compile(r"^(noticer|generic|negative)_[a-z0-9_]{3,63}$")


@dataclass(frozen=True)
class ContractValidation:
    """Validation result for a research contract or public manifest."""

    errors: tuple[str, ...]

    @property
    def valid(self) -> bool:
        """Return true when no contract violation was found."""

        return not self.errors


def load_research_contract(path: Path) -> dict[str, Any]:
    """Load and validate one UTF-8 YAML research contract."""

    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, Mapping):
        raise ValueError("research contract root must be an object")
    contract = dict(loaded)
    result = validate_research_contract(contract)
    if not result.valid:
        raise ValueError("; ".join(result.errors))
    return contract


def validate_research_contract(contract: Mapping[str, Any]) -> ContractValidation:
    """Validate frozen split, seed, limit, gate, and artifact invariants."""

    errors: list[str] = []
    errors.extend(_field_errors("root", set(contract), ROOT_FIELDS))
    if contract.get("schema") != CONTRACT_SCHEMA:
        errors.append(f"schema must be {CONTRACT_SCHEMA}")
    if contract.get("contract_version") != 1:
        errors.append("contract_version must be 1")
    if contract.get("state") != "FROZEN":
        errors.append("state must be FROZEN")
    if contract.get("amendment_policy") != "new_version_required":
        errors.append("amendment_policy must require a new version")
    hypothesis = contract.get("hypothesis")
    if not isinstance(hypothesis, str) or not hypothesis.strip():
        errors.append("hypothesis must be a non-empty string")

    evaluation = _mapping(contract.get("evaluation"), "evaluation", errors)
    _validate_evaluation(evaluation, errors)
    seeds = _mapping(contract.get("seeds"), "seeds", errors)
    _validate_positive_integer_registry(seeds, REQUIRED_SEEDS, "seeds", errors)
    if len(set(seeds.values())) != len(seeds):
        errors.append("seed values must be pairwise distinct")
    limits = _mapping(contract.get("limits"), "limits", errors)
    _validate_positive_integer_registry(limits, REQUIRED_LIMITS, "limits", errors)
    gates = _mapping(contract.get("gates"), "gates", errors)
    _validate_gates(gates, errors)
    benchmark = _mapping(contract.get("benchmark"), "benchmark", errors)
    _validate_benchmark(benchmark, errors)
    artifact = _mapping(contract.get("artifact"), "artifact", errors)
    _validate_artifact_contract(artifact, errors)
    _validate_change_history(contract.get("change_history"), errors)
    return ContractValidation(tuple(errors))


def build_research_manifest(contract: Mapping[str, Any]) -> dict[str, Any]:
    """Build a deterministic public manifest from a valid frozen contract."""

    result = validate_research_contract(contract)
    if not result.valid:
        raise ValueError("; ".join(result.errors))

    benchmark = contract["benchmark"]
    splits = benchmark["splits"]
    catalog = sorted(family for name in SPLIT_NAMES for family in splits[name])
    counts = Counter(family.split("_", 1)[0] for family in catalog)
    evaluation = contract["evaluation"]
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "contract_version": contract["contract_version"],
        "state": contract["state"],
        "contract_sha256": _domain_hash("NOTICER_K7_CONTRACT_V1", contract),
        "benchmark_catalog_sha256": _domain_hash(
            "NOTICER_K7_BENCHMARK_CATALOG_V1", catalog
        ),
        "split_sha256": _domain_hash("NOTICER_K7_SPLIT_V1", splits),
        "seed_registry_sha256": _domain_hash(
            "NOTICER_K7_SEED_REGISTRY_V1", contract["seeds"]
        ),
        "limit_registry_sha256": _domain_hash(
            "NOTICER_K7_LIMIT_REGISTRY_V1", contract["limits"]
        ),
        "gate_registry_sha256": _domain_hash(
            "NOTICER_K7_GATE_REGISTRY_V1", contract["gates"]
        ),
        "split_unit": evaluation["split_unit"],
        "row_random_split_allowed": evaluation["row_random_split_allowed"],
        "outcomes": _json_clone(evaluation["outcomes"]),
        "family_counts": {
            "generic": counts["generic"],
            "negative": counts["negative"],
            "noticer": counts["noticer"],
            "total": len(catalog),
        },
        "private_field_count": 0,
    }
    manifest_result = validate_public_manifest(manifest, contract)
    if not manifest_result.valid:
        raise ValueError("; ".join(manifest_result.errors))
    return manifest


def validate_public_manifest(
    manifest: Mapping[str, Any], contract: Mapping[str, Any]
) -> ContractValidation:
    """Validate a public manifest and bind it to the supplied frozen contract."""

    errors: list[str] = []
    errors.extend(_field_errors("manifest", set(manifest), PUBLIC_MANIFEST_FIELDS))
    errors.extend(_find_forbidden_keys(manifest))
    if manifest.get("schema") != MANIFEST_SCHEMA:
        errors.append(f"manifest schema must be {MANIFEST_SCHEMA}")
    if manifest.get("contract_version") != 1:
        errors.append("manifest contract_version must be 1")
    if manifest.get("state") != "FROZEN":
        errors.append("manifest state must be FROZEN")
    if manifest.get("private_field_count") != 0:
        errors.append("private_field_count must be exactly 0")
    if manifest.get("split_unit") != "spec_family":
        errors.append("manifest split_unit must be spec_family")
    if manifest.get("row_random_split_allowed") is not False:
        errors.append("row random split must remain disabled")
    for field in HASH_FIELDS:
        value = manifest.get(field)
        if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
            errors.append(f"{field} must be lowercase SHA-256")

    contract_result = validate_research_contract(contract)
    if contract_result.valid and set(manifest) == PUBLIC_MANIFEST_FIELDS:
        expected = _build_unchecked_manifest(contract)
        if dict(manifest) != expected:
            errors.append("manifest does not match the frozen research contract")
        max_bytes = contract["limits"]["max_artifact_bytes"]
        if len(serialize_manifest(manifest)) > max_bytes:
            errors.append("manifest exceeds max_artifact_bytes")
    else:
        errors.extend(contract_result.errors)
    return ContractValidation(tuple(errors))


def serialize_manifest(manifest: Mapping[str, Any]) -> bytes:
    """Serialize a public manifest using canonical UTF-8 JSON plus LF."""

    return json.dumps(
        manifest,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8") + b"\n"


def write_research_manifest(config_path: Path, output_path: Path) -> Path:
    """Write a deterministic manifest, refusing a conflicting existing file."""

    contract = load_research_contract(config_path)
    encoded = serialize_manifest(build_research_manifest(contract))
    if output_path.exists():
        if output_path.read_bytes() != encoded:
            raise FileExistsError("existing research manifest differs from frozen contract")
        return output_path
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(encoded)
    return output_path


def _build_unchecked_manifest(contract: Mapping[str, Any]) -> dict[str, Any]:
    benchmark = contract["benchmark"]
    splits = benchmark["splits"]
    catalog = sorted(family for name in SPLIT_NAMES for family in splits[name])
    counts = Counter(family.split("_", 1)[0] for family in catalog)
    evaluation = contract["evaluation"]
    return {
        "schema": MANIFEST_SCHEMA,
        "contract_version": contract["contract_version"],
        "state": contract["state"],
        "contract_sha256": _domain_hash("NOTICER_K7_CONTRACT_V1", contract),
        "benchmark_catalog_sha256": _domain_hash(
            "NOTICER_K7_BENCHMARK_CATALOG_V1", catalog
        ),
        "split_sha256": _domain_hash("NOTICER_K7_SPLIT_V1", splits),
        "seed_registry_sha256": _domain_hash(
            "NOTICER_K7_SEED_REGISTRY_V1", contract["seeds"]
        ),
        "limit_registry_sha256": _domain_hash(
            "NOTICER_K7_LIMIT_REGISTRY_V1", contract["limits"]
        ),
        "gate_registry_sha256": _domain_hash(
            "NOTICER_K7_GATE_REGISTRY_V1", contract["gates"]
        ),
        "split_unit": evaluation["split_unit"],
        "row_random_split_allowed": evaluation["row_random_split_allowed"],
        "outcomes": _json_clone(evaluation["outcomes"]),
        "family_counts": {
            "generic": counts["generic"],
            "negative": counts["negative"],
            "noticer": counts["noticer"],
            "total": len(catalog),
        },
        "private_field_count": 0,
    }


def _validate_evaluation(value: Mapping[str, Any], errors: list[str]) -> None:
    expected = frozenset(
        {
            "split_unit",
            "row_random_split_allowed",
            "warmup_runs",
            "repetitions",
            "metrics",
            "outcomes",
            "stop_conditions",
        }
    )
    errors.extend(_field_errors("evaluation", set(value), expected))
    if value.get("split_unit") != "spec_family":
        errors.append("evaluation.split_unit must be spec_family")
    if value.get("row_random_split_allowed") is not False:
        errors.append("row random split must be disabled")
    if value.get("warmup_runs") != 1:
        errors.append("evaluation.warmup_runs must be 1")
    if value.get("repetitions") != 5:
        errors.append("evaluation.repetitions must be 5")
    metrics = value.get("metrics")
    if not _is_unique_string_sequence(metrics) or set(metrics) != REQUIRED_METRICS:
        errors.append("evaluation.metrics must equal the frozen metric registry")
    outcomes = _mapping(value.get("outcomes"), "evaluation.outcomes", errors)
    if set(outcomes) != set(REQUIRED_OUTCOMES):
        errors.append("evaluation.outcomes has incorrect groups")
    groups: list[set[str]] = []
    for name, required in REQUIRED_OUTCOMES.items():
        entries = outcomes.get(name)
        if not _is_unique_string_sequence(entries) or tuple(entries) != required:
            errors.append(f"evaluation.outcomes.{name} does not match frozen values")
        else:
            groups.append(set(entries))
    if groups and sum(len(group) for group in groups) != len(set().union(*groups)):
        errors.append("evaluation outcome groups must be disjoint")
    stops = value.get("stop_conditions")
    if not _is_unique_string_sequence(stops) or not stops:
        errors.append("evaluation.stop_conditions must be a non-empty unique list")


def _validate_positive_integer_registry(
    value: Mapping[str, Any],
    expected_fields: frozenset[str],
    location: str,
    errors: list[str],
) -> None:
    errors.extend(_field_errors(location, set(value), expected_fields))
    for key, item in value.items():
        if not isinstance(item, int) or isinstance(item, bool) or item <= 0:
            errors.append(f"{location}.{key} must be a positive integer")


def _validate_gates(value: Mapping[str, Any], errors: list[str]) -> None:
    expected = frozenset({"scalability", "discovery", "oracle", "translation", "attack"})
    errors.extend(_field_errors("gates", set(value), expected))
    scalability = _mapping(value.get("scalability"), "gates.scalability", errors)
    if scalability != {
        "min_plant_states": 12,
        "min_machine_states": 8,
        "min_horizon": 64,
        "min_observers": 4,
    }:
        errors.append("gates.scalability must preserve the 12x8x64x4 gate")
    discovery = _mapping(value.get("discovery"), "gates.discovery", errors)
    if discovery != {"min_held_out_valid": 1, "reject_template_equivalence": True}:
        errors.append("gates.discovery does not match frozen values")
    oracle = _mapping(value.get("oracle"), "gates.oracle", errors)
    if oracle != {"min_mutants_detected": 10}:
        errors.append("gates.oracle does not match frozen values")
    translation = _mapping(value.get("translation"), "gates.translation", errors)
    if translation != {"max_cross_target_mismatches": 0}:
        errors.append("gates.translation does not match frozen values")
    attack = _mapping(value.get("attack"), "gates.attack", errors)
    if attack != {
        "confidence_level": 0.95,
        "min_pair_groups": 200,
        "max_excess_advantage": 0.05,
        "min_leaky_control_advantage": 0.30,
    }:
        errors.append("gates.attack does not match frozen values")


def _validate_benchmark(value: Mapping[str, Any], errors: list[str]) -> None:
    errors.extend(
        _field_errors(
            "benchmark", set(value), frozenset({"template_equivalence_check", "splits"})
        )
    )
    if value.get("template_equivalence_check") is not True:
        errors.append("benchmark.template_equivalence_check must be true")
    splits = _mapping(value.get("splits"), "benchmark.splits", errors)
    errors.extend(_field_errors("benchmark.splits", set(splits), frozenset(SPLIT_NAMES)))
    all_families: list[str] = []
    for name in SPLIT_NAMES:
        families = splits.get(name)
        if not _is_unique_string_sequence(families) or len(families) != 8:
            errors.append(f"benchmark.splits.{name} must contain 8 unique families")
            continue
        for family in families:
            if _FAMILY_ID.fullmatch(family) is None:
                errors.append(f"invalid benchmark family ID: {family}")
        all_families.extend(families)
    if len(all_families) != len(set(all_families)):
        errors.append("benchmark families must be disjoint across splits")
    counts = Counter(family.split("_", 1)[0] for family in all_families)
    if counts != Counter({"noticer": 8, "generic": 8, "negative": 8}):
        errors.append("benchmark catalog must contain 8 families per category")


def _validate_artifact_contract(value: Mapping[str, Any], errors: list[str]) -> None:
    expected = frozenset({"schema", "schema_path", "public_allowlist", "forbidden_keys"})
    errors.extend(_field_errors("artifact", set(value), expected))
    if value.get("schema") != MANIFEST_SCHEMA:
        errors.append(f"artifact.schema must be {MANIFEST_SCHEMA}")
    if value.get("schema_path") != "schemas/k7_research_manifest_public.schema.json":
        errors.append("artifact.schema_path must name the versioned public schema")
    allowlist = value.get("public_allowlist")
    if not _is_unique_string_sequence(allowlist) or set(allowlist) != PUBLIC_MANIFEST_FIELDS:
        errors.append("artifact.public_allowlist must equal public manifest fields")
    forbidden = value.get("forbidden_keys")
    if not _is_unique_string_sequence(forbidden) or set(forbidden) != FORBIDDEN_PUBLIC_KEYS:
        errors.append("artifact.forbidden_keys must equal the frozen privacy denylist")


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
    if not isinstance(entry.get("reason"), str) or not entry["reason"].strip():
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
        and all(isinstance(item, str) and item for item in value)
        and len(value) == len(set(value))
    )


def _normalise_key(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value).lower()).strip("_")


def _find_forbidden_keys(value: object, path: str = "manifest") -> list[str]:
    errors: list[str] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if _normalise_key(key) in FORBIDDEN_PUBLIC_KEYS:
                errors.append(f"forbidden public field: {child_path}")
            errors.extend(_find_forbidden_keys(child, child_path))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for index, child in enumerate(value):
            errors.extend(_find_forbidden_keys(child, f"{path}[{index}]"))
    return errors


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _domain_hash(domain: str, value: object) -> str:
    return hashlib.sha256(domain.encode("ascii") + b"\x00" + _canonical_json(value)).hexdigest()


def _json_clone(value: object) -> Any:
    return json.loads(_canonical_json(value))

