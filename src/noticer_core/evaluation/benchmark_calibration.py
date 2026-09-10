"""Fail-closed expected-status and difficulty calibration for K7 benchmarks."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Final

import yaml

from noticer_core.evaluation.benchmark_case import (
    BenchmarkCase,
    benchmark_case_sha256,
    load_benchmark_case,
    verify_aqrs_source_binding,
)
from noticer_core.evaluation.benchmark_registry import load_benchmark_registry

LOCK_SCHEMA: Final = "noticer.k7.benchmark-calibration.v1"
OBSERVATION_SCHEMA: Final = "noticer.k7.benchmark-calibration-observations.v1"
REPORT_SCHEMA: Final = "noticer.k7.benchmark-calibration-report.v1"
LOCK_HASH_DOMAIN: Final = b"NOTICER_K7_BENCHMARK_CALIBRATION_V1\0"

ROOT_FIELDS: Final = frozenset(
    {
        "schema",
        "version",
        "state",
        "registry_path",
        "case_root",
        "status_policy",
        "resource_policy",
        "cases",
    }
)
STATUS_POLICY_FIELDS: Final = frozenset(
    {
        "author_label_can_be_overwritten",
        "disagreement_policy",
        "inconclusive_policy",
        "held_out_policy",
    }
)
RESOURCE_POLICY_FIELDS: Final = frozenset(
    {
        "max_candidates",
        "checker_max_nodes",
        "checker_max_depth",
        "time_limit_ms",
        "time_limit_status",
        "candidate_limit_status",
        "checker_node_limit_status",
        "checker_depth_limit_status",
    }
)
CASE_FIELDS: Final = frozenset(
    {
        "family_id",
        "split",
        "case_sha256",
        "aqrs_sha256",
        "expected_status",
        "calibration_scope",
        "difficulty",
    }
)
DIFFICULTY_FIELDS: Final = frozenset(
    {
        "state_lower_bound",
        "state_upper_bound",
        "horizon_lower_bound",
        "horizon_upper_bound",
        "observer_count",
        "observer_dimensions",
        "fault_axis_count",
        "tier",
    }
)
OBSERVATION_FIELDS: Final = frozenset(
    {
        "engine_id",
        "status",
        "evidence_sha256",
        "resource_reason",
        "minimum_machine_states",
        "minimum_horizon",
    }
)

_EXPECTED_STATUS_POLICY: Final = {
    "author_label_can_be_overwritten": False,
    "disagreement_policy": "BLOCK",
    "inconclusive_policy": "PRESERVE",
    "held_out_policy": "SEALED_UNTIL_LEDGER",
}
_EXPECTED_RESOURCE_POLICY: Final = {
    "max_candidates": 100_000,
    "checker_max_nodes": 100_000,
    "checker_max_depth": 1_024,
    "time_limit_ms": 30_000,
    "time_limit_status": "INCONCLUSIVE_TIME_LIMIT",
    "candidate_limit_status": "INCONCLUSIVE_CANDIDATE_LIMIT",
    "checker_node_limit_status": "INCONCLUSIVE_NODE_LIMIT",
    "checker_depth_limit_status": "INCONCLUSIVE_DEPTH_LIMIT",
}
_STATUS_FROM_CASE: Final = {
    "REALIZABLE": "REALIZABLE",
    "UNREALIZABLE": "UNSAT_AT_BOUND",
    "INVALID": "INVALID_SPEC",
}
_ID = re.compile(r"^[a-z][a-z0-9_-]{2,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class CalibrationError(ValueError):
    """A frozen calibration input or observation violated its contract."""


class ExpectedStatus(StrEnum):
    """Research statuses that must never be collapsed into a boolean label."""

    REALIZABLE = "REALIZABLE"
    UNSAT_AT_BOUND = "UNSAT_AT_BOUND"
    INVALID_SPEC = "INVALID_SPEC"


class ObservedStatus(StrEnum):
    """Engine status, including resource-bounded non-results."""

    REALIZABLE = "REALIZABLE"
    UNSAT_AT_BOUND = "UNSAT_AT_BOUND"
    INVALID_SPEC = "INVALID_SPEC"
    INCONCLUSIVE = "INCONCLUSIVE"


class CalibrationScope(StrEnum):
    """Whether a case may be observed before the held-out ledger opens."""

    CALIBRATION = "CALIBRATION"
    SEALED_HELD_OUT = "SEALED_HELD_OUT"


class ResourceReason(StrEnum):
    """Non-interchangeable resource exhaustion causes."""

    TIME_LIMIT = "TIME_LIMIT"
    CANDIDATE_LIMIT = "CANDIDATE_LIMIT"
    CHECKER_NODE_LIMIT = "CHECKER_NODE_LIMIT"
    CHECKER_DEPTH_LIMIT = "CHECKER_DEPTH_LIMIT"


class CalibrationVerdict(StrEnum):
    """Fail-closed relation between frozen expectation and two observations."""

    AGREE = "AGREE"
    DISAGREEMENT = "DISAGREEMENT"
    INCONCLUSIVE = "INCONCLUSIVE"
    SEALED = "SEALED"


@dataclass(frozen=True, slots=True)
class StatusPolicy:
    """Immutable policy for disagreements, limits, and held-out access."""

    author_label_can_be_overwritten: bool
    disagreement_policy: str
    inconclusive_policy: str
    held_out_policy: str


@dataclass(frozen=True, slots=True)
class ResourcePolicy:
    """Bounds frozen before any held-out observation is admitted."""

    max_candidates: int
    checker_max_nodes: int
    checker_max_depth: int
    time_limit_ms: int
    time_limit_status: str
    candidate_limit_status: str
    checker_node_limit_status: str
    checker_depth_limit_status: str


@dataclass(frozen=True, slots=True)
class DifficultyVector:
    """Static search interval plus observer and fault dimensions."""

    state_lower_bound: int
    state_upper_bound: int
    horizon_lower_bound: int
    horizon_upper_bound: int
    observer_count: int
    observer_dimensions: int
    fault_axis_count: int
    tier: str


@dataclass(frozen=True, slots=True)
class CalibrationCase:
    """One case bound to source, split, status, bounds, and difficulty."""

    family_id: str
    split: str
    case_sha256: str
    aqrs_sha256: str
    expected_status: ExpectedStatus
    calibration_scope: CalibrationScope
    difficulty: DifficultyVector


@dataclass(frozen=True, slots=True)
class CalibrationLock:
    """Canonical pre-observation lock for the complete 24-family corpus."""

    registry_path: str
    case_root: str
    status_policy: StatusPolicy
    resource_policy: ResourcePolicy
    cases: tuple[CalibrationCase, ...]


@dataclass(frozen=True, slots=True)
class EngineObservation:
    """One engine's immutable, digest-bound calibration observation."""

    engine_id: str
    status: ObservedStatus
    evidence_sha256: str
    resource_reason: ResourceReason | None = None
    minimum_machine_states: int | None = None
    minimum_horizon: int | None = None

    def __post_init__(self) -> None:
        if _ID.fullmatch(self.engine_id) is None:
            raise CalibrationError("engine_id must be a canonical identifier")
        if _SHA256.fullmatch(self.evidence_sha256) is None:
            raise CalibrationError("evidence_sha256 must be lowercase SHA-256")
        if self.status is ObservedStatus.INCONCLUSIVE:
            if self.resource_reason is None:
                raise CalibrationError("INCONCLUSIVE requires a resource_reason")
            if self.minimum_machine_states is not None or self.minimum_horizon is not None:
                raise CalibrationError("INCONCLUSIVE cannot claim calibrated minima")
        elif self.resource_reason is not None:
            raise CalibrationError("conclusive observations cannot carry resource_reason")
        if self.status is ObservedStatus.REALIZABLE:
            _positive(self.minimum_machine_states, "minimum_machine_states")
            _positive(self.minimum_horizon, "minimum_horizon")
        elif self.minimum_machine_states is not None or self.minimum_horizon is not None:
            raise CalibrationError("only REALIZABLE observations can carry minima")


@dataclass(frozen=True, slots=True)
class CaseCalibration:
    """One fail-closed comparison without any expected-label mutation."""

    family_id: str
    split: str
    expected_status: ExpectedStatus
    verdict: CalibrationVerdict
    reason: str
    primary: EngineObservation | None
    independent: EngineObservation | None


def difficulty_from_case(case: BenchmarkCase) -> DifficultyVector:
    """Derive the pre-run difficulty vector only from public case dimensions."""

    fault_axes = len(set(case.feature_tags) & {"failure", "retry"}) + len(
        set(case.obligations) & {"bounded_loss", "reconnect"}
    )
    return DifficultyVector(
        state_lower_bound=1,
        state_upper_bound=case.dimensions.machine_state_bound,
        horizon_lower_bound=1,
        horizon_upper_bound=case.dimensions.horizon,
        observer_count=case.dimensions.observer_count,
        observer_dimensions=case.dimensions.observer_dimensions,
        fault_axis_count=fault_axes,
        tier=case.difficulty_tier,
    )


def load_calibration_lock(path: Path, *, repository_root: Path | None = None) -> CalibrationLock:
    """Load and verify a lock against the registry and every bound AQRS case."""

    root = repository_root or path.resolve().parents[2]
    document = _load_mapping(path)
    _require_fields(document, ROOT_FIELDS, "lock")
    if document["schema"] != LOCK_SCHEMA or document["version"] != 1:
        raise CalibrationError("unsupported calibration lock schema")
    if document["state"] != "FROZEN":
        raise CalibrationError("calibration lock must be FROZEN")
    registry_path = _fixed_relative_path(
        document["registry_path"], "configs/quotient_forge/benchmark_family_registry_v1.yaml"
    )
    case_root = _fixed_relative_path(
        document["case_root"], "configs/quotient_forge/benchmark_cases"
    )
    status_raw = _mapping(document["status_policy"], "status_policy")
    _require_fields(status_raw, STATUS_POLICY_FIELDS, "status_policy")
    if status_raw != _EXPECTED_STATUS_POLICY:
        raise CalibrationError("status_policy differs from the frozen fail-closed policy")
    resource_raw = _mapping(document["resource_policy"], "resource_policy")
    _require_fields(resource_raw, RESOURCE_POLICY_FIELDS, "resource_policy")
    if resource_raw != _EXPECTED_RESOURCE_POLICY:
        raise CalibrationError("resource_policy differs from the frozen bounds")

    contract_path = root / "configs" / "quotient_forge" / "k7_research.yaml"
    contract = _load_mapping(contract_path)
    registry = load_benchmark_registry(root / registry_path, contract)
    registry_rows = {row["id"]: row for row in registry["families"]}

    rows = document["cases"]
    if type(rows) is not list or len(rows) != 24:
        raise CalibrationError("cases must contain exactly 24 entries")
    family_ids = [row.get("family_id") if type(row) is dict else None for row in rows]
    if family_ids != sorted(registry_rows):
        raise CalibrationError("cases must match the registry in lexical family order")

    cases: list[CalibrationCase] = []
    for index, raw in enumerate(rows):
        row = _mapping(raw, f"cases[{index}]")
        _require_fields(row, CASE_FIELDS, f"cases[{index}]")
        family_id = _text(row["family_id"], f"cases[{index}].family_id")
        registry_row = registry_rows[family_id]
        split = _text(row["split"], f"cases[{index}].split")
        if split != registry_row["split"]:
            raise CalibrationError(f"split differs from registry: {family_id}")
        category = family_id.split("_", 1)[0]
        case_path = root / case_root / category / f"{family_id}.yaml"
        source_path = case_path.with_suffix(".qf")
        benchmark = load_benchmark_case(case_path)
        source = source_path.read_bytes().replace(b"\r\n", b"\n")
        verify_aqrs_source_binding(benchmark, source)
        if benchmark.family_id != family_id or benchmark.split != split:
            raise CalibrationError(f"case identity differs from registry: {family_id}")

        expected = ExpectedStatus(_STATUS_FROM_CASE[benchmark.expected_outcome_class])
        if row["expected_status"] != expected.value:
            raise CalibrationError(f"expected status differs from case contract: {family_id}")
        scope = (
            CalibrationScope.SEALED_HELD_OUT
            if split == "held_out"
            else CalibrationScope.CALIBRATION
        )
        if row["calibration_scope"] != scope.value:
            raise CalibrationError(f"calibration scope differs from split: {family_id}")
        case_digest = benchmark_case_sha256(benchmark)
        if row["case_sha256"] != case_digest:
            raise CalibrationError(f"case digest mismatch: {family_id}")
        if row["aqrs_sha256"] != benchmark.aqrs.canonical_source_sha256:
            raise CalibrationError(f"AQRS digest mismatch: {family_id}")
        difficulty = _parse_difficulty(row["difficulty"], family_id)
        if difficulty != difficulty_from_case(benchmark):
            raise CalibrationError(f"difficulty vector differs from case dimensions: {family_id}")
        cases.append(
            CalibrationCase(
                family_id=family_id,
                split=split,
                case_sha256=case_digest,
                aqrs_sha256=benchmark.aqrs.canonical_source_sha256,
                expected_status=expected,
                calibration_scope=scope,
                difficulty=difficulty,
            )
        )

    return CalibrationLock(
        registry_path=registry_path,
        case_root=case_root,
        status_policy=StatusPolicy(**status_raw),
        resource_policy=ResourcePolicy(**resource_raw),
        cases=tuple(cases),
    )


def evaluate_case(
    case: CalibrationCase,
    primary: EngineObservation | None,
    independent: EngineObservation | None,
) -> CaseCalibration:
    """Compare two engines while preserving disagreement and resource outcomes."""

    if case.calibration_scope is CalibrationScope.SEALED_HELD_OUT:
        if primary is not None or independent is not None:
            raise CalibrationError(f"held-out observation is sealed: {case.family_id}")
        return CaseCalibration(
            case.family_id,
            case.split,
            case.expected_status,
            CalibrationVerdict.SEALED,
            "HELD_OUT_SEALED",
            None,
            None,
        )
    if primary is None or independent is None:
        raise CalibrationError(f"two observations are required: {case.family_id}")
    if primary.engine_id == independent.engine_id:
        raise CalibrationError("primary and independent engines must differ")
    for observation in (primary, independent):
        if observation.status is ObservedStatus.REALIZABLE:
            assert observation.minimum_machine_states is not None
            assert observation.minimum_horizon is not None
            if observation.minimum_machine_states > case.difficulty.state_upper_bound:
                raise CalibrationError("observed state minimum exceeds the frozen bound")
            if observation.minimum_horizon > case.difficulty.horizon_upper_bound:
                raise CalibrationError("observed horizon minimum exceeds the frozen bound")

    if any(
        observation.status is ObservedStatus.INCONCLUSIVE for observation in (primary, independent)
    ):
        return CaseCalibration(
            case.family_id,
            case.split,
            case.expected_status,
            CalibrationVerdict.INCONCLUSIVE,
            "RESOURCE_LIMIT",
            primary,
            independent,
        )
    expected = case.expected_status.value
    if primary.status.value != independent.status.value:
        verdict = CalibrationVerdict.DISAGREEMENT
        reason = "ENGINE_DISAGREEMENT"
    elif primary.status.value != expected:
        verdict = CalibrationVerdict.DISAGREEMENT
        reason = "EXPECTED_STATUS_MISMATCH"
    elif primary.status is ObservedStatus.REALIZABLE and (
        primary.minimum_machine_states != independent.minimum_machine_states
        or primary.minimum_horizon != independent.minimum_horizon
    ):
        verdict = CalibrationVerdict.DISAGREEMENT
        reason = "MINIMUM_DISAGREEMENT"
    else:
        verdict = CalibrationVerdict.AGREE
        reason = "AGREED"
    return CaseCalibration(
        case.family_id,
        case.split,
        case.expected_status,
        verdict,
        reason,
        primary,
        independent,
    )


def load_observations(path: Path) -> dict[str, tuple[EngineObservation, EngineObservation]]:
    """Load exact two-engine observations without accepting held-out metadata."""

    document = _load_mapping(path)
    _require_fields(document, frozenset({"schema", "cases"}), "observations")
    if document["schema"] != OBSERVATION_SCHEMA:
        raise CalibrationError("unsupported observations schema")
    rows = document["cases"]
    if type(rows) is not list:
        raise CalibrationError("observations.cases must be a list")
    observations: dict[str, tuple[EngineObservation, EngineObservation]] = {}
    for index, raw in enumerate(rows):
        row = _mapping(raw, f"observations.cases[{index}]")
        _require_fields(
            row,
            frozenset({"family_id", "primary", "independent"}),
            f"observations.cases[{index}]",
        )
        family_id = _text(row["family_id"], "family_id")
        if family_id in observations:
            raise CalibrationError(f"duplicate observation: {family_id}")
        observations[family_id] = (
            _parse_observation(row["primary"], "primary"),
            _parse_observation(row["independent"], "independent"),
        )
    return observations


def build_calibration_report(
    lock: CalibrationLock,
    observations: Mapping[str, tuple[EngineObservation, EngineObservation]],
) -> dict[str, object]:
    """Build a public pre-open report; held-out entries remain sealed."""

    expected_observed = {
        case.family_id
        for case in lock.cases
        if case.calibration_scope is CalibrationScope.CALIBRATION
    }
    if set(observations) != expected_observed:
        raise CalibrationError("observations must exactly cover calibration-scope cases")
    results = []
    for case in lock.cases:
        pair = observations.get(case.family_id)
        result = evaluate_case(case, *(pair or (None, None)))
        results.append(_result_mapping(result))
    counts = Counter(result["verdict"] for result in results)
    blocked = (
        counts[CalibrationVerdict.DISAGREEMENT.value]
        + counts[CalibrationVerdict.INCONCLUSIVE.value]
    )
    report: dict[str, object] = {
        "schema": REPORT_SCHEMA,
        "lock_sha256": calibration_lock_sha256(lock),
        "status": "PREOPEN_READY" if blocked == 0 else "BLOCKED",
        "summary": {
            "agree": counts[CalibrationVerdict.AGREE.value],
            "disagreement": counts[CalibrationVerdict.DISAGREEMENT.value],
            "inconclusive": counts[CalibrationVerdict.INCONCLUSIVE.value],
            "sealed": counts[CalibrationVerdict.SEALED.value],
        },
        "cases": results,
        "private_field_count": 0,
    }
    _reject_private_fields(report)
    return report


def calibration_lock_sha256(lock: CalibrationLock) -> str:
    """Return a domain-separated hash of the semantic lock contents."""

    return hashlib.sha256(LOCK_HASH_DOMAIN + _canonical_json(_lock_mapping(lock))).hexdigest()


def write_calibration_report(path: Path, report: Mapping[str, object]) -> Path:
    """Write canonical evidence idempotently and reject conflicting replacement."""

    _reject_private_fields(report)
    payload = _canonical_json(report) + b"\n"
    if path.exists():
        if path.read_bytes() != payload:
            raise FileExistsError("existing calibration report differs")
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(payload)
    temporary.replace(path)
    return path


def main(arguments: Sequence[str] | None = None) -> int:
    """Build a pre-open calibration artifact from two-engine observations."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--observations", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args(arguments)
    try:
        lock = load_calibration_lock(options.config)
        observations = load_observations(options.observations)
        report = build_calibration_report(lock, observations)
        write_calibration_report(options.output, report)
    except (CalibrationError, FileExistsError, OSError, ValueError) as error:
        parser.error(str(error))
    return 0 if report["status"] == "PREOPEN_READY" else 3


def _parse_difficulty(value: object, family_id: str) -> DifficultyVector:
    mapping = _mapping(value, f"difficulty:{family_id}")
    _require_fields(mapping, DIFFICULTY_FIELDS, f"difficulty:{family_id}")
    integers = {
        name: _integer(mapping[name], f"difficulty.{name}", allow_zero=name == "fault_axis_count")
        for name in DIFFICULTY_FIELDS - {"tier"}
    }
    tier = _text(mapping["tier"], "difficulty.tier")
    if tier not in {"D1", "D2", "D3", "D4", "D5"}:
        raise CalibrationError("difficulty.tier is invalid")
    return DifficultyVector(**integers, tier=tier)


def _parse_observation(value: object, location: str) -> EngineObservation:
    mapping = _mapping(value, location)
    _require_fields(mapping, OBSERVATION_FIELDS, location)
    try:
        status = ObservedStatus(mapping["status"])
        reason = (
            None
            if mapping["resource_reason"] is None
            else ResourceReason(mapping["resource_reason"])
        )
    except (TypeError, ValueError) as error:
        raise CalibrationError(f"{location} has an invalid enum value") from error
    return EngineObservation(
        engine_id=_text(mapping["engine_id"], f"{location}.engine_id"),
        status=status,
        evidence_sha256=_digest(mapping["evidence_sha256"], f"{location}.evidence_sha256"),
        resource_reason=reason,
        minimum_machine_states=_optional_integer(
            mapping["minimum_machine_states"], f"{location}.minimum_machine_states"
        ),
        minimum_horizon=_optional_integer(
            mapping["minimum_horizon"], f"{location}.minimum_horizon"
        ),
    )


def _result_mapping(result: CaseCalibration) -> dict[str, object]:
    return {
        "family_id": result.family_id,
        "split": result.split,
        "expected_status": result.expected_status.value,
        "verdict": result.verdict.value,
        "reason": result.reason,
        "primary": _observation_mapping(result.primary),
        "independent": _observation_mapping(result.independent),
    }


def _observation_mapping(observation: EngineObservation | None) -> object:
    if observation is None:
        return None
    return {
        "engine_id": observation.engine_id,
        "status": observation.status.value,
        "evidence_sha256": observation.evidence_sha256,
        "resource_reason": (
            None if observation.resource_reason is None else observation.resource_reason.value
        ),
        "minimum_machine_states": observation.minimum_machine_states,
        "minimum_horizon": observation.minimum_horizon,
    }


def _lock_mapping(lock: CalibrationLock) -> dict[str, object]:
    return {
        "schema": LOCK_SCHEMA,
        "version": 1,
        "state": "FROZEN",
        "registry_path": lock.registry_path,
        "case_root": lock.case_root,
        "status_policy": {
            field: getattr(lock.status_policy, field) for field in sorted(STATUS_POLICY_FIELDS)
        },
        "resource_policy": {
            field: getattr(lock.resource_policy, field) for field in sorted(RESOURCE_POLICY_FIELDS)
        },
        "cases": [
            {
                "family_id": case.family_id,
                "split": case.split,
                "case_sha256": case.case_sha256,
                "aqrs_sha256": case.aqrs_sha256,
                "expected_status": case.expected_status.value,
                "calibration_scope": case.calibration_scope.value,
                "difficulty": {
                    field: getattr(case.difficulty, field) for field in sorted(DIFFICULTY_FIELDS)
                },
            }
            for case in lock.cases
        ],
    }


def _load_mapping(path: Path) -> dict[str, Any]:
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as error:
        raise CalibrationError(f"cannot load calibration YAML: {path}") from error
    return _mapping(loaded, str(path))


def _mapping(value: object, location: str) -> dict[str, Any]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise CalibrationError(f"{location} must be a string-keyed mapping")
    return dict(value)


def _require_fields(mapping: Mapping[str, object], expected: frozenset[str], location: str) -> None:
    if set(mapping) != expected:
        raise CalibrationError(f"{location} fields differ from the frozen allowlist")


def _fixed_relative_path(value: object, expected: str) -> str:
    if value != expected or Path(expected).is_absolute() or ".." in Path(expected).parts:
        raise CalibrationError(f"path must be {expected}")
    return expected


def _text(value: object, field: str) -> str:
    if type(value) is not str or not value:
        raise CalibrationError(f"{field} must be non-empty text")
    return value


def _digest(value: object, field: str) -> str:
    text = _text(value, field)
    if _SHA256.fullmatch(text) is None:
        raise CalibrationError(f"{field} must be lowercase SHA-256")
    return text


def _integer(value: object, field: str, *, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    if type(value) is not int or value < minimum:
        raise CalibrationError(f"{field} must be an integer >= {minimum}")
    return value


def _optional_integer(value: object, field: str) -> int | None:
    return None if value is None else _integer(value, field)


def _positive(value: object, field: str) -> None:
    _integer(value, field)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("ascii")


def _reject_private_fields(value: object, path: str = "report") -> None:
    forbidden = {
        "private_history",
        "biosignal",
        "participant_id",
        "subject_id",
        "device_id",
        "token_bytes",
        "key_material",
    }
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = re.sub(r"[^a-z0-9]+", "_", str(key).lower()).strip("_")
            if normalized in forbidden:
                raise CalibrationError(f"forbidden public field: {path}.{key}")
            _reject_private_fields(child, f"{path}.{key}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for index, child in enumerate(value):
            _reject_private_fields(child, f"{path}[{index}]")


if __name__ == "__main__":
    raise SystemExit(main())
