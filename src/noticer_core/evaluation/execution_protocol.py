"""Frozen warmup, repetition, ordering, and retention protocol for K7-09."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any, Final

import yaml

from noticer_core.evaluation.scalability_contract import (
    BACKENDS,
    ScalabilityCase,
    load_scalability_contract,
    scalability_contract_sha256,
)

SCHEMA: Final = "noticer.k7.execution-protocol.v1"
HASH_DOMAIN: Final = b"NOTICER_K7_EXECUTION_PROTOCOL_V1\0"
RUN_SEED_DOMAIN: Final = b"NOTICER_K7_RUN_SEED_V1\0"
EXPECTED_SCALABILITY_DIGEST: Final = (
    "ec8f9879f1ec07c8084d99335f2c62fde3d9cbf400269b6e15c625711848d523"
)
ROOT_FIELDS: Final = frozenset(
    {
        "schema",
        "version",
        "state",
        "study_id",
        "scalability_contract",
        "randomization",
        "retention",
        "held_out_policy",
        "artifact_policy",
    }
)
RANDOMIZATION: Final = {
    "master_seed": 260817,
    "warmup_repetitions": 2,
    "measured_repetitions": 5,
    "profile_order": "SEEDED_SHA256_ASCENDING",
    "backend_order": "BALANCED_LATIN_ROTATION",
    "adaptive_reordering_allowed": False,
}
RETENTION: Final = {
    "max_attempts_per_run": 1,
    "retain_all_attempts": True,
    "retry_replaces_attempt": False,
    "failed_result_policy": "PRESERVE",
    "missing_result_status": "NOT_RUN",
    "warmup_in_primary_statistics": False,
}
HELD_OUT_POLICY: Final = {
    "required_initial_state": "SEALED",
    "protocol_changes_after_open": "REJECT",
    "opening_requires_protocol_digest": True,
}
ARTIFACT_POLICY: Final = {
    "root": "artifacts/quotient_forge/scalability",
    "commit_generated_artifacts": False,
}
_ID = re.compile(r"^[a-z][a-z0-9-]{2,95}$")


class ExecutionProtocolError(ValueError):
    """The execution protocol or a ledger transition violated frozen policy."""


class RunPhase(StrEnum):
    """Warmup is retained but excluded from primary statistics."""

    WARMUP = "WARMUP"
    MEASURED = "MEASURED"


class LedgerState(StrEnum):
    """States relevant to protocol mutability."""

    PRECOMMITTED = "PRECOMMITTED"
    SEALED = "SEALED"
    OPENED = "OPENED"


@dataclass(frozen=True, slots=True)
class ScheduledRun:
    """One immutable case execution in the globally ordered schedule."""

    ordinal: int
    run_id: str
    phase: RunPhase
    repetition: int
    profile: str
    backend_position: int
    case_id: str
    backend_id: str
    seed: int
    attempt: int = 1


@dataclass(frozen=True, slots=True)
class ExecutionProtocol:
    """Verified protocol plus its complete deterministic run schedule."""

    study_id: str
    scalability_contract_sha256: str
    schedule: tuple[ScheduledRun, ...]
    warmup_repetitions: int
    measured_repetitions: int
    artifact_root: str


def load_execution_protocol(
    path: Path, *, repository_root: Path | None = None
) -> ExecutionProtocol:
    """Load, bind, and expand the frozen execution protocol."""

    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    if type(document) is not dict:
        raise ExecutionProtocolError("protocol must be a mapping")
    _require_fields(document, ROOT_FIELDS, "protocol")
    if document["schema"] != SCHEMA or document["version"] != 1:
        raise ExecutionProtocolError("unsupported execution protocol schema")
    if document["state"] != "FROZEN":
        raise ExecutionProtocolError("execution protocol must be FROZEN")
    study_id = document["study_id"]
    if type(study_id) is not str or _ID.fullmatch(study_id) is None:
        raise ExecutionProtocolError("study_id must be canonical")

    binding = document["scalability_contract"]
    expected_binding = {
        "path": "configs/quotient_forge/k7_scalability_contract_v1.yaml",
        "sha256": EXPECTED_SCALABILITY_DIGEST,
    }
    if binding != expected_binding:
        raise ExecutionProtocolError("scalability contract binding differs from v1")
    if document["randomization"] != RANDOMIZATION:
        raise ExecutionProtocolError("randomization protocol differs from v1")
    if document["retention"] != RETENTION:
        raise ExecutionProtocolError("retention protocol differs from v1")
    if document["held_out_policy"] != HELD_OUT_POLICY:
        raise ExecutionProtocolError("held-out policy differs from v1")
    if document["artifact_policy"] != ARTIFACT_POLICY:
        raise ExecutionProtocolError("artifact policy differs from v1")
    _relative_posix_path(binding["path"])
    _relative_posix_path(ARTIFACT_POLICY["root"])

    root = repository_root or path.resolve().parents[2]
    scalability = load_scalability_contract(root / binding["path"])
    actual_digest = scalability_contract_sha256(scalability)
    if actual_digest != binding["sha256"]:
        raise ExecutionProtocolError("bound scalability contract digest mismatch")
    schedule = tuple(_build_schedule(scalability.cases))
    _validate_schedule(schedule)
    return ExecutionProtocol(
        study_id=study_id,
        scalability_contract_sha256=actual_digest,
        schedule=schedule,
        warmup_repetitions=RANDOMIZATION["warmup_repetitions"],
        measured_repetitions=RANDOMIZATION["measured_repetitions"],
        artifact_root=ARTIFACT_POLICY["root"],
    )


def execution_protocol_sha256(protocol: ExecutionProtocol) -> str:
    """Return the digest that a held-out opening record must bind."""

    payload = {
        "study_id": protocol.study_id,
        "scalability_contract_sha256": protocol.scalability_contract_sha256,
        "warmup_repetitions": protocol.warmup_repetitions,
        "measured_repetitions": protocol.measured_repetitions,
        "artifact_root": protocol.artifact_root,
        "schedule": [_run_mapping(run) for run in protocol.schedule],
        "retention": RETENTION,
        "held_out_policy": HELD_OUT_POLICY,
    }
    return hashlib.sha256(HASH_DOMAIN + _canonical_json(payload)).hexdigest()


def assert_protocol_transition(
    previous_digest: str,
    proposed_digest: str,
    *,
    ledger_state: LedgerState,
) -> None:
    """Reject any protocol change after the held-out ledger has opened."""

    for label, digest in (("previous", previous_digest), ("proposed", proposed_digest)):
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ExecutionProtocolError(f"{label} protocol digest must be SHA-256")
    if ledger_state is LedgerState.OPENED and previous_digest != proposed_digest:
        raise ExecutionProtocolError("execution protocol cannot change after held-out opening")


def _build_schedule(cases: tuple[ScalabilityCase, ...]) -> list[ScheduledRun]:
    by_profile: dict[str, dict[str, ScalabilityCase]] = defaultdict(dict)
    for case in cases:
        by_profile[case.profile][case.backend_id] = case
    profiles = sorted(
        by_profile,
        key=lambda profile: hashlib.sha256(
            f"{RANDOMIZATION['master_seed']}:{profile}".encode()
        ).digest(),
    )
    backend_ids = tuple(backend for backend, _reduction in BACKENDS)
    schedule: list[ScheduledRun] = []
    ordinal = 0
    phases = (
        (RunPhase.WARMUP, RANDOMIZATION["warmup_repetitions"]),
        (RunPhase.MEASURED, RANDOMIZATION["measured_repetitions"]),
    )
    for phase, repetitions in phases:
        for repetition in range(repetitions):
            for profile_index, profile in enumerate(profiles):
                rotation = (repetition + profile_index) % len(backend_ids)
                order = backend_ids[rotation:] + backend_ids[:rotation]
                for position, backend_id in enumerate(order):
                    case = by_profile[profile][backend_id]
                    run_id = f"k7r-{phase.value.lower()}-{repetition:02d}-{ordinal:04d}"
                    schedule.append(
                        ScheduledRun(
                            ordinal=ordinal,
                            run_id=run_id,
                            phase=phase,
                            repetition=repetition,
                            profile=profile,
                            backend_position=position,
                            case_id=case.case_id,
                            backend_id=backend_id,
                            seed=_derive_seed(run_id),
                        )
                    )
                    ordinal += 1
    return schedule


def _validate_schedule(schedule: tuple[ScheduledRun, ...]) -> None:
    expected = (RANDOMIZATION["warmup_repetitions"] + RANDOMIZATION["measured_repetitions"]) * 92
    if len(schedule) != expected or len({run.run_id for run in schedule}) != expected:
        raise ExecutionProtocolError("schedule coverage or run identity differs")
    if [run.ordinal for run in schedule] != list(range(expected)):
        raise ExecutionProtocolError("schedule ordinals are not contiguous")
    measured = Counter(run.case_id for run in schedule if run.phase is RunPhase.MEASURED)
    warmup = Counter(run.case_id for run in schedule if run.phase is RunPhase.WARMUP)
    if set(measured.values()) != {RANDOMIZATION["measured_repetitions"]}:
        raise ExecutionProtocolError("measured case coverage differs")
    if set(warmup.values()) != {RANDOMIZATION["warmup_repetitions"]}:
        raise ExecutionProtocolError("warmup case coverage differs")


def _derive_seed(run_id: str) -> int:
    source = f"{RANDOMIZATION['master_seed']}:{run_id}".encode("ascii")
    return int.from_bytes(hashlib.sha256(RUN_SEED_DOMAIN + source).digest()[:8], "big")


def _run_mapping(run: ScheduledRun) -> dict[str, object]:
    return {
        "ordinal": run.ordinal,
        "run_id": run.run_id,
        "phase": run.phase.value,
        "repetition": run.repetition,
        "profile": run.profile,
        "backend_position": run.backend_position,
        "case_id": run.case_id,
        "backend_id": run.backend_id,
        "seed": run.seed,
        "attempt": run.attempt,
    }


def _require_fields(value: Mapping[str, Any], fields: frozenset[str], label: str) -> None:
    if set(value) != fields:
        raise ExecutionProtocolError(f"{label} fields must be exactly {sorted(fields)}")


def _relative_posix_path(value: object) -> None:
    if type(value) is not str or "\\" in value:
        raise ExecutionProtocolError("protocol paths must be portable POSIX paths")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts:
        raise ExecutionProtocolError("protocol paths must remain repository-relative")


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
