"""Shared, provenance-aware contract for K7 mechanism comparisons."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Literal

FORMAT_VERSION = "noticer.k7.baseline-comparison.v1"
MECHANISMS = frozenset(
    {"aqrs", "pacer_like", "netshaper_like", "automata",
     "handwritten_aets", "immediate_control", "leaky_control"}
)
AXES = ("attack", "bandwidth", "failure", "latency", "state")
_SHA256 = re.compile(r"[0-9a-f]{64}")


class ComparisonContractError(ValueError):
    """Stable reason for an invalid comparison manifest."""

    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


@dataclass(frozen=True)
class SharedContract:
    case_sha256: str
    observer_sha256: str
    utility_sha256: str
    fault_trace_sha256: str
    cost_sha256: str
    corpus_sha256: str
    evaluation_split: Literal["held_out"]
    selection_split: Literal["development"]


@dataclass(frozen=True)
class Mechanism:
    mechanism_id: str
    implementation_kind: Literal["original", "approximation", "local"]
    privacy_notion: str
    source_ref: str
    source_version: str
    candidate_config_sha256: tuple[str, ...]
    selected_config_sha256: str


@dataclass(frozen=True)
class ComparisonManifest:
    format_version: str
    shared: SharedContract
    mechanisms: tuple[Mechanism, ...]
    report_axes: tuple[str, ...]
    privacy_notions_are_separate: bool
    security_proof: bool = False


def manifest_from_document(document: Mapping[str, object]) -> ComparisonManifest:
    """Parse a closed JSON-like document and validate fair shared inputs."""

    _keys(document, {"format_version", "shared", "mechanisms", "report_axes",
                     "privacy_notions_are_separate", "security_proof"})
    shared_doc = _mapping(document["shared"])
    _keys(shared_doc, {"case_sha256", "observer_sha256", "utility_sha256",
                       "fault_trace_sha256", "cost_sha256", "corpus_sha256",
                       "evaluation_split", "selection_split"})
    shared = SharedContract(**shared_doc)  # type: ignore[arg-type]
    raw_mechanisms = document["mechanisms"]
    if not isinstance(raw_mechanisms, list):
        raise ComparisonContractError("invalid_document")
    mechanisms = []
    for raw in raw_mechanisms:
        item = _mapping(raw)
        _keys(item, {"mechanism_id", "implementation_kind", "privacy_notion",
                     "source_ref", "source_version", "candidate_config_sha256",
                     "selected_config_sha256"})
        candidates = item["candidate_config_sha256"]
        if not isinstance(candidates, list):
            raise ComparisonContractError("invalid_document")
        mechanisms.append(
            Mechanism(
                mechanism_id=_text(item["mechanism_id"]),
                implementation_kind=_text(item["implementation_kind"]),  # type: ignore[arg-type]
                privacy_notion=_text(item["privacy_notion"]),
                source_ref=_text(item["source_ref"]),
                source_version=_text(item["source_version"]),
                candidate_config_sha256=tuple(_text(v) for v in candidates),
                selected_config_sha256=_text(item["selected_config_sha256"]),
            )
        )
    raw_axes = document["report_axes"]
    if not isinstance(raw_axes, list):
        raise ComparisonContractError("invalid_document")
    artifact = ComparisonManifest(
        format_version=_text(document["format_version"]),
        shared=shared,
        mechanisms=tuple(mechanisms),
        report_axes=tuple(_text(v) for v in raw_axes),
        privacy_notions_are_separate=_boolean(document["privacy_notions_are_separate"]),
        security_proof=_boolean(document["security_proof"]),
    )
    validate_manifest(artifact)
    return artifact


def validate_manifest(artifact: ComparisonManifest) -> None:
    """Reject unequal contracts, provenance ambiguity, and cherry-picked configs."""

    if artifact.format_version != FORMAT_VERSION:
        raise ComparisonContractError("unsupported_format")
    for value in (
        artifact.shared.case_sha256,
        artifact.shared.observer_sha256,
        artifact.shared.utility_sha256,
        artifact.shared.fault_trace_sha256,
        artifact.shared.cost_sha256,
        artifact.shared.corpus_sha256,
    ):
        _digest(value)
    if (
        artifact.shared.evaluation_split != "held_out"
        or artifact.shared.selection_split != "development"
    ):
        raise ComparisonContractError("split_misuse")
    if artifact.report_axes != AXES or not artifact.privacy_notions_are_separate:
        raise ComparisonContractError("collapsed_privacy_or_metrics")
    if artifact.security_proof:
        raise ComparisonContractError("comparison_is_not_proof")
    ids = tuple(mechanism.mechanism_id for mechanism in artifact.mechanisms)
    if ids != tuple(sorted(MECHANISMS)):
        raise ComparisonContractError("mechanism_set_mismatch")
    for mechanism in artifact.mechanisms:
        if mechanism.implementation_kind not in {"original", "approximation", "local"}:
            raise ComparisonContractError("invalid_implementation_kind")
        if mechanism.mechanism_id in {"pacer_like", "netshaper_like", "automata"}:
            if mechanism.implementation_kind == "local":
                raise ComparisonContractError("missing_provenance_kind")
        if not all((mechanism.privacy_notion, mechanism.source_ref,
                    mechanism.source_version)):
            raise ComparisonContractError("missing_provenance")
        candidates = mechanism.candidate_config_sha256
        if not candidates or candidates != tuple(sorted(set(candidates))):
            raise ComparisonContractError("invalid_candidate_set")
        for digest in (*candidates, mechanism.selected_config_sha256):
            _digest(digest)
        if mechanism.selected_config_sha256 not in candidates:
            raise ComparisonContractError("selected_config_not_precommitted")


def canonical_manifest_json(artifact: ComparisonManifest) -> bytes:
    validate_manifest(artifact)
    return (
        json.dumps(asdict(artifact), sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def manifest_digest(artifact: ComparisonManifest) -> str:
    return hashlib.sha256(canonical_manifest_json(artifact)).hexdigest()


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, dict) or not all(isinstance(k, str) for k in value):
        raise ComparisonContractError("invalid_document")
    return value


def _keys(value: Mapping[str, object], expected: set[str]) -> None:
    if set(value) != expected:
        raise ComparisonContractError("undeclared_field")


def _text(value: object) -> str:
    if not isinstance(value, str):
        raise ComparisonContractError("invalid_document")
    return value


def _boolean(value: object) -> bool:
    if not isinstance(value, bool):
        raise ComparisonContractError("invalid_document")
    return value


def _digest(value: str) -> None:
    if _SHA256.fullmatch(value) is None:
        raise ComparisonContractError("invalid_digest")
