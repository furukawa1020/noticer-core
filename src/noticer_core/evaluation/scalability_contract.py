"""Frozen K7 scalability axes, case identities, and outcome taxonomy."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any, Final

import yaml

SCHEMA: Final = "noticer.k7.scalability-contract.v1"
HASH_DOMAIN: Final = b"NOTICER_K7_SCALABILITY_CONTRACT_V1\0"
CASE_HASH_DOMAIN: Final = b"NOTICER_K7_SCALABILITY_CASE_V1\0"

AXIS_ORDER: Final = (
    "plant_states",
    "machine_states",
    "horizon",
    "observer_count",
    "fault_state_count",
    "output_alphabet",
    "quotient_class_count",
)
AXIS_VALUES: Final = {
    "plant_states": (3, 6, 9, 12),
    "machine_states": (2, 4, 6, 8),
    "horizon": (8, 16, 32, 64),
    "observer_count": (1, 2, 3, 4),
    "fault_state_count": (0, 1, 2, 3),
    "output_alphabet": (2, 4, 6, 8),
    "quotient_class_count": (2, 4, 6, 8),
}
BASELINE: Final = {name: values[0] for name, values in AXIS_VALUES.items()}
TARGET: Final = {name: values[-1] for name, values in AXIS_VALUES.items()}
BACKENDS: Final = (
    ("reference", "none"),
    ("cegis", "symmetry-dominance-v1"),
    ("smt", "incremental-symmetry-v1"),
    ("qbf", "cone-quantifier-v1"),
)
RESOURCE_LIMITS: Final = {
    "wall_time_ms": 60_000,
    "memory_mib": 4_096,
    "max_candidates": 1_000_000,
    "max_checker_nodes": 2_000_000,
    "max_solver_calls": 1_000_000,
}
ARTIFACT_POLICY: Final = {
    "root": "artifacts/quotient_forge/scalability",
    "commit_generated_artifacts": False,
    "hardware_status": "NOT_VERIFIED",
}

ROOT_FIELDS: Final = frozenset(
    {
        "schema",
        "version",
        "state",
        "study_id",
        "design",
        "axes",
        "baseline",
        "target_gate",
        "backends",
        "resource_limits",
        "outcome_statuses",
        "artifact_policy",
    }
)
_ID = re.compile(r"^[a-z][a-z0-9-]{2,63}$")
_PRIVATE_KEYS: Final = frozenset(
    {"biosignal", "identity", "subject_id", "participant_id", "token", "raw_trace"}
)


class ScalabilityContractError(ValueError):
    """The scalability contract is malformed or differs from the frozen protocol."""


class OutcomeStatus(StrEnum):
    """Mutually exclusive scalability outcomes; only COMPLETED is a completion."""

    COMPLETED = "COMPLETED"
    TIMEOUT = "TIMEOUT"
    MEMORY_LIMIT = "MEMORY_LIMIT"
    SOLVER_UNKNOWN = "SOLVER_UNKNOWN"
    PROCESS_FAILURE = "PROCESS_FAILURE"
    INVALID_CASE = "INVALID_CASE"
    NOT_RUN = "NOT_RUN"


@dataclass(frozen=True, slots=True)
class ScalabilityDimensions:
    """Public finite-model dimensions for one benchmark case."""

    plant_states: int
    machine_states: int
    horizon: int
    observer_count: int
    fault_state_count: int
    output_alphabet: int
    quotient_class_count: int

    def as_dict(self) -> dict[str, int]:
        """Return dimensions in the frozen axis order."""

        return {name: getattr(self, name) for name in AXIS_ORDER}


@dataclass(frozen=True, slots=True)
class ScalabilityCase:
    """A deterministic backend/configuration/dimension tuple."""

    case_id: str
    profile: str
    backend_id: str
    reduction_id: str
    dimensions: ScalabilityDimensions
    target_gate: bool


@dataclass(frozen=True, slots=True)
class ScalabilityContract:
    """Verified immutable contract used by all later K7-09 measurements."""

    study_id: str
    cases: tuple[ScalabilityCase, ...]
    resource_limits: Mapping[str, int]
    artifact_root: str
    hardware_status: str


def load_scalability_contract(path: Path) -> ScalabilityContract:
    """Load a YAML contract and reject any deviation from the frozen v1 design."""

    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    if type(document) is not dict:
        raise ScalabilityContractError("contract must be a mapping")
    _reject_private_fields(document)
    _require_exact_fields(document, ROOT_FIELDS, "contract")
    if document["schema"] != SCHEMA or document["version"] != 1:
        raise ScalabilityContractError("unsupported scalability contract schema")
    if document["state"] != "FROZEN":
        raise ScalabilityContractError("scalability contract must be FROZEN")
    study_id = document["study_id"]
    if type(study_id) is not str or _ID.fullmatch(study_id) is None:
        raise ScalabilityContractError("study_id must be a canonical identifier")
    if document["design"] != "BASELINE_PLUS_ONE_FACTOR_SWEEPS_AND_TARGET":
        raise ScalabilityContractError("design differs from the frozen v1 protocol")

    expected_axes = {name: list(values) for name, values in AXIS_VALUES.items()}
    if document["axes"] != expected_axes:
        raise ScalabilityContractError("axes differ from the frozen v1 protocol")
    if document["baseline"] != BASELINE:
        raise ScalabilityContractError("baseline differs from the frozen v1 protocol")
    if document["target_gate"] != TARGET:
        raise ScalabilityContractError("target_gate must remain exactly 12x8x64 and peers")
    expected_backends = [
        {"backend_id": backend, "reduction_id": reduction}
        for backend, reduction in BACKENDS
    ]
    if document["backends"] != expected_backends:
        raise ScalabilityContractError("backend/reduction configurations differ from v1")
    if document["resource_limits"] != RESOURCE_LIMITS:
        raise ScalabilityContractError("resource limits differ from the frozen v1 bounds")
    if document["outcome_statuses"] != [status.value for status in OutcomeStatus]:
        raise ScalabilityContractError("outcome statuses differ from the frozen taxonomy")
    if document["artifact_policy"] != ARTIFACT_POLICY:
        raise ScalabilityContractError("artifact policy differs from the frozen v1 policy")
    _validate_relative_posix_path(ARTIFACT_POLICY["root"])

    cases = tuple(_build_cases())
    if sum(case.target_gate for case in cases) != len(BACKENDS):
        raise AssertionError("each backend must contain exactly one target gate")
    return ScalabilityContract(
        study_id=study_id,
        cases=cases,
        resource_limits=dict(RESOURCE_LIMITS),
        artifact_root=ARTIFACT_POLICY["root"],
        hardware_status=ARTIFACT_POLICY["hardware_status"],
    )


def scalability_contract_sha256(contract: ScalabilityContract) -> str:
    """Hash all semantics that later run manifests must bind."""

    payload = {
        "study_id": contract.study_id,
        "resource_limits": dict(contract.resource_limits),
        "artifact_root": contract.artifact_root,
        "hardware_status": contract.hardware_status,
        "cases": [_case_mapping(case) for case in contract.cases],
    }
    return hashlib.sha256(HASH_DOMAIN + _canonical_json(payload)).hexdigest()


def _build_cases() -> list[ScalabilityCase]:
    profiles: list[tuple[str, dict[str, int]]] = [("baseline", dict(BASELINE))]
    for axis in AXIS_ORDER:
        for value in AXIS_VALUES[axis][1:]:
            dimensions = dict(BASELINE)
            dimensions[axis] = value
            profiles.append((f"sweep-{axis}-{value}", dimensions))
    profiles.append(("target-12x8x64", dict(TARGET)))

    cases = []
    for backend_id, reduction_id in BACKENDS:
        for profile, values in profiles:
            dimensions = ScalabilityDimensions(**values)
            identity = {
                "profile": profile,
                "backend_id": backend_id,
                "reduction_id": reduction_id,
                "dimensions": dimensions.as_dict(),
            }
            digest = hashlib.sha256(CASE_HASH_DOMAIN + _canonical_json(identity)).hexdigest()[:16]
            cases.append(
                ScalabilityCase(
                    case_id=f"k7s-{backend_id}-{digest}",
                    profile=profile,
                    backend_id=backend_id,
                    reduction_id=reduction_id,
                    dimensions=dimensions,
                    target_gate=values == TARGET,
                )
            )
    return cases


def _case_mapping(case: ScalabilityCase) -> dict[str, Any]:
    return {
        "case_id": case.case_id,
        "profile": case.profile,
        "backend_id": case.backend_id,
        "reduction_id": case.reduction_id,
        "dimensions": case.dimensions.as_dict(),
        "target_gate": case.target_gate,
    }


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _require_exact_fields(value: Mapping[str, Any], expected: frozenset[str], label: str) -> None:
    if set(value) != expected:
        raise ScalabilityContractError(f"{label} fields must be exactly {sorted(expected)}")


def _validate_relative_posix_path(value: object) -> None:
    if type(value) is not str or "\\" in value:
        raise ScalabilityContractError("artifact root must be a portable POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ScalabilityContractError("artifact root must stay repository-relative")


def _reject_private_fields(value: object) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = str(key).lower()
            if normalized in _PRIVATE_KEYS or "private" in normalized:
                raise ScalabilityContractError(f"private field is forbidden: {key}")
            _reject_private_fields(child)
    elif isinstance(value, list):
        for child in value:
            _reject_private_fields(child)

