"""Strict canonical contract for bounded K7 AQRS benchmark cases."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Final

import yaml
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode
from yaml.tokens import AliasToken, AnchorToken, TagToken

CASE_SCHEMA: Final = "noticer.k7.aqrs-benchmark-case.v1"
MANIFEST_SCHEMA: Final = "noticer.k7.aqrs-benchmark-case-manifest.v1"
CASE_HASH_DOMAIN: Final = b"NOTICER_K7_AQRS_BENCHMARK_CASE_V1\0"
AQRS_LANGUAGE_VERSION: Final = 1

SPLITS: Final = frozenset({"train", "development", "held_out"})
FEATURE_TAGS: Final = frozenset(
    {"collusion", "failure", "longitudinal", "retry", "silence", "size", "timing"}
)
OBLIGATIONS: Final = frozenset({"action_window", "bounded_loss", "exactly_once", "reconnect"})
OUTCOME_CLASSES: Final = frozenset({"REALIZABLE", "UNREALIZABLE", "INVALID"})
DIFFICULTY_TIERS: Final = frozenset({"D1", "D2", "D3", "D4", "D5"})

_CANONICAL_ID = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class BenchmarkCaseError(ValueError):
    """Raised when a benchmark case violates the public case contract."""


class _UniqueKeyLoader(yaml.SafeLoader):
    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[object, object]:
        if not isinstance(node, MappingNode):
            raise ConstructorError(None, None, "expected a mapping node", node.start_mark)
        mapping: dict[object, object] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in mapping
            except TypeError as error:
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "found an unhashable key",
                    key_node.start_mark,
                ) from error
            if duplicate:
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"found duplicate key {key!r}",
                    key_node.start_mark,
                )
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


@dataclass(frozen=True)
class BenchmarkCaseLimits:
    """Resource limits applied before a benchmark case is accepted."""

    max_document_bytes: int = 65_536
    max_horizon: int = 256
    max_plant_states: int = 4_096
    max_plant_transitions: int = 16_384
    max_machine_states: int = 256
    max_machine_symbols: int = 256
    max_observers: int = 32
    max_observer_dimensions: int = 128

    def __post_init__(self) -> None:
        for name, value in self.__dict__.items():
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True)
class AqrsSourceBinding:
    """Digest-only binding to canonical AQRS source."""

    language_version: int
    canonical_source_sha256: str


@dataclass(frozen=True)
class BenchmarkDimensions:
    """Public bounded dimensions; no trace or biosignal values are admitted."""

    plant_states: int
    plant_transitions: int
    machine_state_bound: int
    machine_symbol_count: int
    horizon: int
    observer_count: int
    observer_dimensions: int


@dataclass(frozen=True)
class BenchmarkCase:
    """Canonical, privacy-safe envelope shared by every K7 benchmark family."""

    family_id: str
    variant_id: str
    split: str
    aqrs: AqrsSourceBinding
    dimensions: BenchmarkDimensions
    feature_tags: tuple[str, ...]
    obligations: tuple[str, ...]
    expected_outcome_class: str
    difficulty_tier: str
    author_template_sha256: str | None

    @property
    def case_id(self) -> str:
        """Return the derived case identifier without accepting a separate ID field."""

        return f"{self.family_id}__{self.variant_id}"


def parse_benchmark_case(
    payload: bytes, limits: BenchmarkCaseLimits | None = None
) -> BenchmarkCase:
    """Parse one bounded UTF-8 YAML document under an exact field allowlist."""

    active_limits = limits or BenchmarkCaseLimits()
    if len(payload) > active_limits.max_document_bytes:
        raise BenchmarkCaseError("benchmark case exceeds max_document_bytes")
    if payload.startswith(b"\xef\xbb\xbf"):
        raise BenchmarkCaseError("UTF-8 BOM is not canonical")
    try:
        source = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise BenchmarkCaseError("benchmark case is not valid UTF-8") from error

    try:
        for token in yaml.scan(source):
            if isinstance(token, (AliasToken, AnchorToken, TagToken)):
                raise BenchmarkCaseError("YAML aliases, anchors, and tags are forbidden")
        raw = yaml.load(source, Loader=_UniqueKeyLoader)
    except yaml.YAMLError as error:
        raise BenchmarkCaseError(f"invalid benchmark case YAML: {error}") from error

    root = _require_mapping(raw, "case")
    _require_fields(
        root,
        {
            "schema",
            "family_id",
            "variant_id",
            "split",
            "aqrs",
            "dimensions",
            "feature_tags",
            "obligations",
            "expected_outcome_class",
            "difficulty_tier",
            "author_template_sha256",
        },
        "case",
    )
    if root["schema"] != CASE_SCHEMA:
        raise BenchmarkCaseError(f"schema must be {CASE_SCHEMA!r}")

    family_id = _canonical_id(root["family_id"], "family_id")
    variant_id = _canonical_id(root["variant_id"], "variant_id")
    split = _enum(root["split"], SPLITS, "split")
    aqrs = _parse_aqrs(root["aqrs"])
    dimensions = _parse_dimensions(root["dimensions"], active_limits)
    feature_tags = _sorted_enum_list(root["feature_tags"], FEATURE_TAGS, "feature_tags")
    obligations = _sorted_enum_list(root["obligations"], OBLIGATIONS, "obligations")
    expected = _enum(root["expected_outcome_class"], OUTCOME_CLASSES, "expected_outcome_class")
    difficulty = _enum(root["difficulty_tier"], DIFFICULTY_TIERS, "difficulty_tier")
    template = _optional_digest(root["author_template_sha256"], "author_template_sha256")
    if split == "held_out" and template is not None:
        raise BenchmarkCaseError("held_out cases cannot bind an author template")

    return BenchmarkCase(
        family_id=family_id,
        variant_id=variant_id,
        split=split,
        aqrs=aqrs,
        dimensions=dimensions,
        feature_tags=feature_tags,
        obligations=obligations,
        expected_outcome_class=expected,
        difficulty_tier=difficulty,
        author_template_sha256=template,
    )


def load_benchmark_case(path: Path, limits: BenchmarkCaseLimits | None = None) -> BenchmarkCase:
    """Load a benchmark case through pathlib without triggering work at import time."""

    try:
        payload = path.read_bytes()
    except OSError as error:
        raise BenchmarkCaseError(f"cannot read benchmark case {path}: {error}") from error
    return parse_benchmark_case(payload, limits)


def canonical_benchmark_case_bytes(case: BenchmarkCase) -> bytes:
    """Return the one canonical byte representation used by hashing and artifacts."""

    return _canonical_json_bytes(_case_mapping(case))


def benchmark_case_sha256(case: BenchmarkCase) -> str:
    """Return the domain-separated digest of a canonical benchmark case."""

    return sha256(CASE_HASH_DOMAIN + canonical_benchmark_case_bytes(case)).hexdigest()


def verify_aqrs_source_binding(
    case: BenchmarkCase, source: bytes, limits: BenchmarkCaseLimits | None = None
) -> None:
    """Verify byte-exact binding to canonical AQRS source without storing that source."""

    active_limits = limits or BenchmarkCaseLimits()
    if len(source) > active_limits.max_document_bytes:
        raise BenchmarkCaseError("AQRS source exceeds max_document_bytes")
    if source.startswith(b"\xef\xbb\xbf") or b"\r" in source or not source.endswith(b"\n"):
        raise BenchmarkCaseError("AQRS source must be BOM-free LF text ending in a newline")
    try:
        source.decode("utf-8")
    except UnicodeDecodeError as error:
        raise BenchmarkCaseError("AQRS source is not valid UTF-8") from error
    actual = sha256(source).hexdigest()
    if actual != case.aqrs.canonical_source_sha256:
        raise BenchmarkCaseError("AQRS canonical source digest mismatch")


def benchmark_case_manifest(case: BenchmarkCase) -> dict[str, object]:
    """Build an aggregate-only public artifact for one accepted case."""

    return {
        "schema": MANIFEST_SCHEMA,
        "case_id": case.case_id,
        "case_sha256": benchmark_case_sha256(case),
        "case": _case_mapping(case),
        "privacy": {
            "private_biosignal_field_count": 0,
            "stable_person_identifier_field_count": 0,
            "aqrs_source_embedded": False,
        },
    }


def write_benchmark_case_manifest(path: Path, case: BenchmarkCase) -> None:
    """Write a canonical manifest idempotently and refuse conflicting replacement."""

    payload = _canonical_json_bytes(benchmark_case_manifest(case))
    if path.exists():
        try:
            existing = path.read_bytes()
        except OSError as error:
            raise BenchmarkCaseError(f"cannot read existing manifest {path}: {error}") from error
        if existing != payload:
            raise BenchmarkCaseError(f"refusing to replace conflicting manifest {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.write_bytes(payload)
    except OSError as error:
        raise BenchmarkCaseError(f"cannot write manifest {path}: {error}") from error


def _parse_aqrs(value: object) -> AqrsSourceBinding:
    mapping = _require_mapping(value, "aqrs")
    _require_fields(mapping, {"language_version", "canonical_source_sha256"}, "aqrs")
    version = _bounded_integer(
        mapping["language_version"], AQRS_LANGUAGE_VERSION, "aqrs.language_version"
    )
    if version != AQRS_LANGUAGE_VERSION:
        raise BenchmarkCaseError(f"aqrs.language_version must be {AQRS_LANGUAGE_VERSION}")
    return AqrsSourceBinding(
        language_version=version,
        canonical_source_sha256=_digest(
            mapping["canonical_source_sha256"], "aqrs.canonical_source_sha256"
        ),
    )


def _parse_dimensions(value: object, limits: BenchmarkCaseLimits) -> BenchmarkDimensions:
    mapping = _require_mapping(value, "dimensions")
    fields = {
        "plant_states",
        "plant_transitions",
        "machine_state_bound",
        "machine_symbol_count",
        "horizon",
        "observer_count",
        "observer_dimensions",
    }
    _require_fields(mapping, fields, "dimensions")
    dimensions = BenchmarkDimensions(
        plant_states=_bounded_integer(
            mapping["plant_states"], limits.max_plant_states, "dimensions.plant_states"
        ),
        plant_transitions=_bounded_integer(
            mapping["plant_transitions"],
            limits.max_plant_transitions,
            "dimensions.plant_transitions",
        ),
        machine_state_bound=_bounded_integer(
            mapping["machine_state_bound"],
            limits.max_machine_states,
            "dimensions.machine_state_bound",
        ),
        machine_symbol_count=_bounded_integer(
            mapping["machine_symbol_count"],
            limits.max_machine_symbols,
            "dimensions.machine_symbol_count",
        ),
        horizon=_bounded_integer(mapping["horizon"], limits.max_horizon, "dimensions.horizon"),
        observer_count=_bounded_integer(
            mapping["observer_count"], limits.max_observers, "dimensions.observer_count"
        ),
        observer_dimensions=_bounded_integer(
            mapping["observer_dimensions"],
            limits.max_observer_dimensions,
            "dimensions.observer_dimensions",
        ),
    )
    if dimensions.observer_dimensions < dimensions.observer_count:
        raise BenchmarkCaseError("observer_dimensions cannot be smaller than observer_count")
    return dimensions


def _case_mapping(case: BenchmarkCase) -> dict[str, object]:
    return {
        "schema": CASE_SCHEMA,
        "family_id": case.family_id,
        "variant_id": case.variant_id,
        "split": case.split,
        "aqrs": {
            "language_version": case.aqrs.language_version,
            "canonical_source_sha256": case.aqrs.canonical_source_sha256,
        },
        "dimensions": {
            "plant_states": case.dimensions.plant_states,
            "plant_transitions": case.dimensions.plant_transitions,
            "machine_state_bound": case.dimensions.machine_state_bound,
            "machine_symbol_count": case.dimensions.machine_symbol_count,
            "horizon": case.dimensions.horizon,
            "observer_count": case.dimensions.observer_count,
            "observer_dimensions": case.dimensions.observer_dimensions,
        },
        "feature_tags": list(case.feature_tags),
        "obligations": list(case.obligations),
        "expected_outcome_class": case.expected_outcome_class,
        "difficulty_tier": case.difficulty_tier,
        "author_template_sha256": case.author_template_sha256,
    }


def _require_mapping(value: object, context: str) -> dict[str, object]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise BenchmarkCaseError(f"{context} must be a string-keyed mapping")
    return value


def _require_fields(mapping: dict[str, object], expected: set[str], context: str) -> None:
    actual = set(mapping)
    missing = sorted(expected - actual)
    unknown = sorted(actual - expected)
    if missing:
        raise BenchmarkCaseError(f"{context} is missing fields: {', '.join(missing)}")
    if unknown:
        raise BenchmarkCaseError(f"{context} has unknown fields: {', '.join(unknown)}")


def _canonical_id(value: object, field: str) -> str:
    if type(value) is not str or len(value) > 64 or _CANONICAL_ID.fullmatch(value) is None:
        raise BenchmarkCaseError(f"{field} must be a lowercase snake_case identifier")
    return value


def _bounded_integer(value: object, maximum: int, field: str) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise BenchmarkCaseError(f"{field} must be an integer in [1, {maximum}]")
    return value


def _enum(value: object, choices: frozenset[str], field: str) -> str:
    if type(value) is not str or value not in choices:
        raise BenchmarkCaseError(f"{field} must be one of {sorted(choices)!r}")
    return value


def _sorted_enum_list(value: object, choices: frozenset[str], field: str) -> tuple[str, ...]:
    if type(value) is not list or not value or any(type(item) is not str for item in value):
        raise BenchmarkCaseError(f"{field} must be a non-empty string list")
    if any(item not in choices for item in value):
        raise BenchmarkCaseError(f"{field} contains an unsupported value")
    if value != sorted(set(value)):
        raise BenchmarkCaseError(f"{field} must be unique and lexicographically sorted")
    return tuple(value)


def _digest(value: object, field: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise BenchmarkCaseError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _optional_digest(value: object, field: str) -> str | None:
    if value is None:
        return None
    return _digest(value, field)


def _canonical_json_bytes(value: object) -> bytes:
    encoded = json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    )
    return encoded.encode("ascii") + b"\n"
