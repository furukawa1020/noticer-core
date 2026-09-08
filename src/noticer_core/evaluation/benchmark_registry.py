"""Frozen family registry and split-leakage guard for K7 AQRS benchmarks."""

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

from noticer_core.evaluation.k7_research_contract import (
    SPLIT_NAMES,
    build_research_manifest,
    validate_research_contract,
)

REGISTRY_SCHEMA = "noticer-k7-benchmark-family-registry-v1"
MANIFEST_SCHEMA = "noticer-k7-benchmark-family-manifest-v1"
VARIANT_POLICY = "inherits_spec_family_split"
CATEGORIES = ("noticer", "generic", "negative")
ROOT_FIELDS = frozenset(
    {
        "schema",
        "contract_version",
        "state",
        "contract_path",
        "split_unit",
        "row_random_split_allowed",
        "variant_split_policy",
        "seeds",
        "families",
    }
)
FAMILY_FIELDS = frozenset({"id", "category", "split", "split_ordinal"})
VARIANT_FIELDS = frozenset({"variant_id", "spec_family", "split"})
PUBLIC_MANIFEST_FIELDS = frozenset(
    {
        "schema",
        "contract_version",
        "state",
        "contract_sha256",
        "registry_sha256",
        "benchmark_catalog_sha256",
        "split_sha256",
        "variant_policy_sha256",
        "split_unit",
        "row_random_split_allowed",
        "family_count",
        "category_counts",
        "split_counts",
        "private_field_count",
    }
)
_FAMILY_ID = re.compile(r"^(noticer|generic|negative)_[a-z0-9_]{3,63}$")
_VARIANT_ID = re.compile(r"^[a-z][a-z0-9_]{3,95}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class RegistryValidation:
    """Validation result for a registry, variant assignment, or public manifest."""

    errors: tuple[str, ...]

    @property
    def valid(self) -> bool:
        """Return true only when all frozen invariants hold."""

        return not self.errors


def load_benchmark_registry(path: Path, contract: Mapping[str, Any]) -> dict[str, Any]:
    """Load UTF-8 YAML and require exact agreement with the frozen K7 contract."""

    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, Mapping):
        raise ValueError("benchmark registry root must be an object")
    registry = dict(loaded)
    result = validate_benchmark_registry(registry, contract)
    if not result.valid:
        raise ValueError("; ".join(result.errors))
    return registry


def validate_benchmark_registry(
    registry: Mapping[str, Any], contract: Mapping[str, Any]
) -> RegistryValidation:
    """Validate family identities, ordering, categories, and split lock."""

    errors: list[str] = []
    errors.extend(_field_errors("registry", set(registry), ROOT_FIELDS))
    contract_result = validate_research_contract(contract)
    errors.extend(f"contract: {error}" for error in contract_result.errors)
    if registry.get("schema") != REGISTRY_SCHEMA:
        errors.append(f"schema must be {REGISTRY_SCHEMA}")
    if registry.get("contract_version") != 1 or registry.get("state") != "FROZEN":
        errors.append("registry must bind frozen contract version 1")
    if registry.get("contract_path") != "configs/quotient_forge/k7_research.yaml":
        errors.append("contract_path must identify the frozen K7 contract")
    if registry.get("split_unit") != "spec_family":
        errors.append("split_unit must be spec_family")
    if registry.get("row_random_split_allowed") is not False:
        errors.append("row random split must remain disabled")
    if registry.get("variant_split_policy") != VARIANT_POLICY:
        errors.append(f"variant_split_policy must be {VARIANT_POLICY}")

    seeds = _mapping(registry.get("seeds"), "seeds", errors)
    if seeds != {"catalog": 42001, "split": 42004}:
        errors.append("catalog and split seeds must match K7-00")
    if contract_result.valid and seeds:
        if seeds.get("catalog") != contract["seeds"]["catalog"]:
            errors.append("catalog seed differs from K7-00")
        if seeds.get("split") != contract["seeds"]["split"]:
            errors.append("split seed differs from K7-00")

    rows = registry.get("families")
    if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)):
        errors.append("families must be a sequence")
        rows = []
    if len(rows) != 24:
        errors.append("families must contain exactly 24 rows")
    seen_ids: set[str] = set()
    seen_slots: set[tuple[str, int]] = set()
    normalized: list[dict[str, Any]] = []
    for index, raw in enumerate(rows):
        if not isinstance(raw, Mapping):
            errors.append(f"families[{index}] must be an object")
            continue
        row = dict(raw)
        errors.extend(_field_errors(f"families[{index}]", set(row), FAMILY_FIELDS))
        family_id = row.get("id")
        category = row.get("category")
        split = row.get("split")
        ordinal = row.get("split_ordinal")
        if not isinstance(family_id, str) or _FAMILY_ID.fullmatch(family_id) is None:
            errors.append(f"families[{index}].id is invalid")
            continue
        if family_id in seen_ids:
            errors.append(f"duplicate family ID: {family_id}")
        seen_ids.add(family_id)
        expected_category = family_id.split("_", 1)[0]
        if category != expected_category or category not in CATEGORIES:
            errors.append(f"category does not match family ID: {family_id}")
        if split not in SPLIT_NAMES:
            errors.append(f"invalid split for family: {family_id}")
        if not isinstance(ordinal, int) or isinstance(ordinal, bool) or not 0 <= ordinal < 8:
            errors.append(f"invalid split ordinal for family: {family_id}")
        elif isinstance(split, str):
            slot = (split, ordinal)
            if slot in seen_slots:
                errors.append(f"duplicate split slot: {split}[{ordinal}]")
            seen_slots.add(slot)
        normalized.append(row)

    counts = Counter(row.get("category") for row in normalized)
    if counts != Counter({category: 8 for category in CATEGORIES}):
        errors.append("registry must contain 8 families per category")
    split_counts = Counter(row.get("split") for row in normalized)
    if split_counts != Counter({split: 8 for split in SPLIT_NAMES}):
        errors.append("registry must contain 8 families per split")
    if contract_result.valid and len(normalized) == 24:
        actual_splits = _split_mapping(normalized)
        if actual_splits != contract["benchmark"]["splits"]:
            errors.append("registry family IDs or split order differ from K7-00")
    return RegistryValidation(tuple(errors))


def validate_variant_assignments(
    assignments: Sequence[Mapping[str, Any]], registry: Mapping[str, Any]
) -> RegistryValidation:
    """Reject duplicate variants and any split that differs from its spec family."""

    errors: list[str] = []
    family_splits = {
        row["id"]: row["split"]
        for row in registry.get("families", [])
        if isinstance(row, Mapping) and isinstance(row.get("id"), str)
    }
    seen_variants: set[str] = set()
    for index, raw in enumerate(assignments):
        if not isinstance(raw, Mapping):
            errors.append(f"assignments[{index}] must be an object")
            continue
        assignment = dict(raw)
        errors.extend(_field_errors(f"assignments[{index}]", set(assignment), VARIANT_FIELDS))
        errors.extend(_forbidden_key_errors(assignment, f"assignments[{index}]"))
        variant_id = assignment.get("variant_id")
        family_id = assignment.get("spec_family")
        split = assignment.get("split")
        if not isinstance(variant_id, str) or _VARIANT_ID.fullmatch(variant_id) is None:
            errors.append(f"assignments[{index}].variant_id is invalid")
        elif variant_id in seen_variants:
            errors.append(f"duplicate variant ID: {variant_id}")
        else:
            seen_variants.add(variant_id)
        if family_id not in family_splits:
            errors.append(f"unknown spec family: {family_id}")
        elif split != family_splits[family_id]:
            errors.append(f"variant split leakage: {variant_id}")
    return RegistryValidation(tuple(errors))


def build_benchmark_registry_manifest(
    registry: Mapping[str, Any], contract: Mapping[str, Any]
) -> dict[str, Any]:
    """Build a public aggregate-only manifest bound to K7-00 hashes."""

    result = validate_benchmark_registry(registry, contract)
    if not result.valid:
        raise ValueError("; ".join(result.errors))
    rows = [dict(row) for row in registry["families"]]
    splits = _split_mapping(rows)
    catalog = sorted(row["id"] for row in rows)
    research_manifest = build_research_manifest(contract)
    normalized_rows = sorted(rows, key=lambda row: row["id"])
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "contract_version": 1,
        "state": "FROZEN",
        "contract_sha256": research_manifest["contract_sha256"],
        "registry_sha256": _domain_hash("NOTICER_K7_FAMILY_REGISTRY_V1", normalized_rows),
        "benchmark_catalog_sha256": _domain_hash("NOTICER_K7_BENCHMARK_CATALOG_V1", catalog),
        "split_sha256": _domain_hash("NOTICER_K7_SPLIT_V1", splits),
        "variant_policy_sha256": _domain_hash(
            "NOTICER_K7_VARIANT_SPLIT_POLICY_V1",
            {"policy": VARIANT_POLICY, "split_unit": "spec_family"},
        ),
        "split_unit": "spec_family",
        "row_random_split_allowed": False,
        "family_count": 24,
        "category_counts": {category: 8 for category in CATEGORIES},
        "split_counts": {split: 8 for split in SPLIT_NAMES},
        "private_field_count": 0,
    }
    if manifest["benchmark_catalog_sha256"] != research_manifest["benchmark_catalog_sha256"]:
        raise ValueError("benchmark catalog hash differs from K7-00")
    if manifest["split_sha256"] != research_manifest["split_sha256"]:
        raise ValueError("split hash differs from K7-00")
    validation = validate_benchmark_registry_manifest(manifest, registry, contract)
    if not validation.valid:
        raise ValueError("; ".join(validation.errors))
    return manifest


def validate_benchmark_registry_manifest(
    manifest: Mapping[str, Any],
    registry: Mapping[str, Any],
    contract: Mapping[str, Any],
) -> RegistryValidation:
    """Validate allowlist, privacy boundary, and exact canonical contents."""

    errors = _field_errors("manifest", set(manifest), PUBLIC_MANIFEST_FIELDS)
    errors.extend(_forbidden_key_errors(manifest, "manifest"))
    if manifest.get("schema") != MANIFEST_SCHEMA:
        errors.append(f"manifest schema must be {MANIFEST_SCHEMA}")
    for field in (
        "contract_sha256",
        "registry_sha256",
        "benchmark_catalog_sha256",
        "split_sha256",
        "variant_policy_sha256",
    ):
        value = manifest.get(field)
        if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
            errors.append(f"{field} must be lowercase SHA-256")
    if manifest.get("private_field_count") != 0:
        errors.append("private_field_count must be zero")
    if manifest.get("split_unit") != "spec_family":
        errors.append("manifest split_unit must be spec_family")
    if manifest.get("row_random_split_allowed") is not False:
        errors.append("manifest must prohibit row random split")
    registry_result = validate_benchmark_registry(registry, contract)
    errors.extend(registry_result.errors)
    if registry_result.valid and set(manifest) == PUBLIC_MANIFEST_FIELDS:
        expected = _build_unchecked_manifest(registry, contract)
        if dict(manifest) != expected:
            errors.append("manifest does not match the frozen family registry")
    return RegistryValidation(tuple(errors))


def serialize_benchmark_registry_manifest(manifest: Mapping[str, Any]) -> bytes:
    """Return canonical ASCII JSON followed by one LF."""

    return _canonical_json(manifest) + b"\n"


def write_benchmark_registry_manifest(
    registry_path: Path,
    contract_path: Path,
    output_path: Path,
) -> Path:
    """Write idempotently and refuse replacement of conflicting evidence."""

    contract_loaded = yaml.safe_load(contract_path.read_text(encoding="utf-8"))
    if not isinstance(contract_loaded, Mapping):
        raise ValueError("research contract root must be an object")
    contract = dict(contract_loaded)
    registry = load_benchmark_registry(registry_path, contract)
    encoded = serialize_benchmark_registry_manifest(
        build_benchmark_registry_manifest(registry, contract)
    )
    if output_path.exists():
        if output_path.read_bytes() != encoded:
            raise FileExistsError("existing family manifest differs from frozen registry")
        return output_path
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(encoded)
    return output_path


def _build_unchecked_manifest(
    registry: Mapping[str, Any], contract: Mapping[str, Any]
) -> dict[str, Any]:
    rows = [dict(row) for row in registry["families"]]
    splits = _split_mapping(rows)
    catalog = sorted(row["id"] for row in rows)
    research_manifest = build_research_manifest(contract)
    return {
        "schema": MANIFEST_SCHEMA,
        "contract_version": 1,
        "state": "FROZEN",
        "contract_sha256": research_manifest["contract_sha256"],
        "registry_sha256": _domain_hash(
            "NOTICER_K7_FAMILY_REGISTRY_V1", sorted(rows, key=lambda row: row["id"])
        ),
        "benchmark_catalog_sha256": _domain_hash("NOTICER_K7_BENCHMARK_CATALOG_V1", catalog),
        "split_sha256": _domain_hash("NOTICER_K7_SPLIT_V1", splits),
        "variant_policy_sha256": _domain_hash(
            "NOTICER_K7_VARIANT_SPLIT_POLICY_V1",
            {"policy": VARIANT_POLICY, "split_unit": "spec_family"},
        ),
        "split_unit": "spec_family",
        "row_random_split_allowed": False,
        "family_count": 24,
        "category_counts": {category: 8 for category in CATEGORIES},
        "split_counts": {split: 8 for split in SPLIT_NAMES},
        "private_field_count": 0,
    }


def _split_mapping(rows: Sequence[Mapping[str, Any]]) -> dict[str, list[str]]:
    return {
        split: [
            row["id"]
            for row in sorted(
                (row for row in rows if row.get("split") == split),
                key=lambda row: row["split_ordinal"],
            )
        ]
        for split in SPLIT_NAMES
    }


def _mapping(value: object, location: str, errors: list[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        errors.append(f"{location} must be an object")
        return {}
    return value


def _field_errors(location: str, actual: set[str], expected: frozenset[str]) -> list[str]:
    errors: list[str] = []
    if missing := expected - actual:
        errors.append(f"{location} is missing fields: {sorted(missing)}")
    if unknown := actual - expected:
        errors.append(f"{location} has unknown fields: {sorted(unknown)}")
    return errors


def _forbidden_key_errors(value: object, path: str) -> list[str]:
    forbidden = {
        "private_history",
        "ppg_samples",
        "acc_samples",
        "stable_identifier",
        "participant_id",
        "device_id",
        "token_bytes",
        "key_material",
    }
    errors: list[str] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = re.sub(r"[^a-z0-9]+", "_", str(key).lower()).strip("_")
            child_path = f"{path}.{key}"
            if normalized in forbidden:
                errors.append(f"forbidden field: {child_path}")
            errors.extend(_forbidden_key_errors(child, child_path))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for index, child in enumerate(value):
            errors.extend(_forbidden_key_errors(child, f"{path}[{index}]"))
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
