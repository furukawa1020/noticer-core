"""Append-only held-out opening ledger bound to frozen K7 calibration inputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Final

import yaml

from noticer_core.evaluation.benchmark_calibration import (
    CalibrationLock,
    CalibrationScope,
    calibration_lock_sha256,
    load_calibration_lock,
)

PRECOMMIT_SCHEMA: Final = "noticer.k7.heldout-precommit.v1"
RECEIPT_SCHEMA: Final = "noticer.k7.heldout-opening-receipt.v1"
CORPUS_HASH_DOMAIN: Final = b"NOTICER_K7_HELDOUT_CORPUS_V1\0"
SPLIT_HASH_DOMAIN: Final = b"NOTICER_K7_HELDOUT_SPLIT_V1\0"
BOUNDS_HASH_DOMAIN: Final = b"NOTICER_K7_HELDOUT_BOUNDS_V1\0"
BACKEND_HASH_DOMAIN: Final = b"NOTICER_K7_HELDOUT_BACKEND_V1\0"
RECEIPT_HASH_DOMAIN: Final = b"NOTICER_K7_HELDOUT_RECEIPT_V1\0"
MAX_RESULT_BYTES: Final = 16 * 1024 * 1024

BACKEND_COMPONENT_PATHS: Final = (
    "Cargo.lock",
    "pyproject.toml",
    "crates/quotient-forge-synth/src/search.rs",
    "crates/quotient-forge-check/src/lib.rs",
    "src/noticer_core/evaluation/aqrs_oracle.py",
)
PRECOMMIT_FIELDS: Final = frozenset(
    {
        "schema",
        "version",
        "revision",
        "state",
        "calibration_lock_path",
        "bindings",
        "backend_components",
        "held_out_families",
        "artifact_namespaces",
        "policies",
    }
)
BINDING_FIELDS: Final = frozenset(
    {
        "calibration_lock_sha256",
        "corpus_sha256",
        "split_sha256",
        "bounds_sha256",
        "backend_sha256",
    }
)
COMPONENT_FIELDS: Final = frozenset({"path", "sha256"})
NAMESPACE_FIELDS: Final = frozenset({"development", "held_out"})
POLICY_FIELDS: Final = frozenset(
    {
        "bounds_mutable_after_precommit",
        "reseal_after_open",
        "append_only",
        "receipt_contains_host_identity",
        "receipt_contains_private_data",
    }
)
RECEIPT_FIELDS: Final = frozenset(
    {
        "schema",
        "ledger_revision",
        "sequence",
        "previous_receipt_sha256",
        "from_state",
        "to_state",
        "bindings",
        "result",
        "private_field_count",
    }
)
RESULT_FIELDS: Final = frozenset({"format", "sha256", "byte_count"})

_EXPECTED_POLICIES: Final = {
    "bounds_mutable_after_precommit": False,
    "reseal_after_open": False,
    "append_only": True,
    "receipt_contains_host_identity": False,
    "receipt_contains_private_data": False,
}
_EXPECTED_NAMESPACES: Final = {
    "development": "artifacts/quotient_forge/development",
    "held_out": "artifacts/quotient_forge/held_out",
}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FORMAT_ID = re.compile(r"^[a-z][a-z0-9._-]{2,95}$")


class HeldOutLedgerError(ValueError):
    """A precommit, receipt, transition, or public result was invalid."""


class LedgerState(StrEnum):
    """Monotonic held-out lifecycle states."""

    PRECOMMITTED = "PRECOMMITTED"
    SEALED = "SEALED"
    OPENED = "OPENED"


@dataclass(frozen=True, slots=True)
class LedgerBindings:
    """Independent digests needed to detect stale or retuned evaluation."""

    calibration_lock_sha256: str
    corpus_sha256: str
    split_sha256: str
    bounds_sha256: str
    backend_sha256: str


@dataclass(frozen=True, slots=True)
class BackendComponent:
    """One repository-relative backend component and normalized digest."""

    path: str
    sha256: str


@dataclass(frozen=True, slots=True)
class ArtifactNamespaces:
    """Disjoint repository-relative namespaces for development and held-out data."""

    development: str
    held_out: str


@dataclass(frozen=True, slots=True)
class LedgerPolicies:
    """Frozen irreversible transition and privacy policies."""

    bounds_mutable_after_precommit: bool
    reseal_after_open: bool
    append_only: bool
    receipt_contains_host_identity: bool
    receipt_contains_private_data: bool


@dataclass(frozen=True, slots=True)
class HeldOutPrecommit:
    """Immutable pre-observation ledger input committed with the repository."""

    revision: int
    calibration_lock_path: str
    bindings: LedgerBindings
    backend_components: tuple[BackendComponent, ...]
    held_out_families: tuple[str, ...]
    artifact_namespaces: ArtifactNamespaces
    policies: LedgerPolicies


@dataclass(frozen=True, slots=True)
class ResultDigest:
    """Content-only held-out result reference with no local path."""

    format: str
    sha256: str
    byte_count: int


@dataclass(frozen=True, slots=True)
class OpeningReceipt:
    """One canonical state transition in the append-only receipt chain."""

    ledger_revision: int
    sequence: int
    previous_receipt_sha256: str | None
    from_state: LedgerState
    to_state: LedgerState
    bindings: LedgerBindings
    result: ResultDigest | None
    private_field_count: int = 0


def derive_bindings(
    lock: CalibrationLock, *, repository_root: Path
) -> tuple[LedgerBindings, tuple[BackendComponent, ...]]:
    """Derive five independent bindings from public frozen inputs."""

    corpus = [
        {
            "family_id": case.family_id,
            "case_sha256": case.case_sha256,
            "aqrs_sha256": case.aqrs_sha256,
        }
        for case in lock.cases
    ]
    splits = {
        split: [case.family_id for case in lock.cases if case.split == split]
        for split in ("train", "development", "held_out")
    }
    bounds = {
        "resource_policy": {
            name: getattr(lock.resource_policy, name)
            for name in lock.resource_policy.__dataclass_fields__
        },
        "case_bounds": [
            {
                "family_id": case.family_id,
                "state_lower_bound": case.difficulty.state_lower_bound,
                "state_upper_bound": case.difficulty.state_upper_bound,
                "horizon_lower_bound": case.difficulty.horizon_lower_bound,
                "horizon_upper_bound": case.difficulty.horizon_upper_bound,
                "observer_count": case.difficulty.observer_count,
                "observer_dimensions": case.difficulty.observer_dimensions,
                "fault_axis_count": case.difficulty.fault_axis_count,
                "tier": case.difficulty.tier,
            }
            for case in lock.cases
        ],
    }
    components = tuple(
        BackendComponent(path, _normalized_file_sha256(repository_root / path))
        for path in BACKEND_COMPONENT_PATHS
    )
    backend_document = [
        {"path": component.path, "sha256": component.sha256} for component in components
    ]
    bindings = LedgerBindings(
        calibration_lock_sha256=calibration_lock_sha256(lock),
        corpus_sha256=_domain_hash(CORPUS_HASH_DOMAIN, corpus),
        split_sha256=_domain_hash(SPLIT_HASH_DOMAIN, splits),
        bounds_sha256=_domain_hash(BOUNDS_HASH_DOMAIN, bounds),
        backend_sha256=_domain_hash(BACKEND_HASH_DOMAIN, backend_document),
    )
    return bindings, components


def load_precommit(path: Path, *, repository_root: Path | None = None) -> HeldOutPrecommit:
    """Load a precommit and reject stale corpus, bounds, backend, or split data."""

    root = repository_root or path.resolve().parents[2]
    document = _load_yaml_mapping(path)
    _require_fields(document, PRECOMMIT_FIELDS, "precommit")
    _reject_private_fields(document, "precommit")
    if document["schema"] != PRECOMMIT_SCHEMA or document["version"] != 1:
        raise HeldOutLedgerError("unsupported held-out precommit schema")
    if document["revision"] != 1 or document["state"] != LedgerState.PRECOMMITTED.value:
        raise HeldOutLedgerError("precommit revision and state must remain frozen")
    calibration_path = _fixed_relative_path(
        document["calibration_lock_path"],
        "configs/quotient_forge/benchmark_calibration_v1.yaml",
    )
    lock = load_calibration_lock(root / calibration_path, repository_root=root)
    expected_bindings, expected_components = derive_bindings(lock, repository_root=root)
    bindings = _parse_bindings(document["bindings"], "bindings")
    if bindings != expected_bindings:
        raise HeldOutLedgerError("precommit binding is stale or was modified after freeze")

    raw_components = document["backend_components"]
    if type(raw_components) is not list:
        raise HeldOutLedgerError("backend_components must be a list")
    components = tuple(_parse_component(value, index) for index, value in enumerate(raw_components))
    if components != expected_components:
        raise HeldOutLedgerError("backend component binding is stale")

    held_out = document["held_out_families"]
    if type(held_out) is not list or any(type(value) is not str for value in held_out):
        raise HeldOutLedgerError("held_out_families must be a string list")
    expected_held_out = tuple(
        case.family_id
        for case in lock.cases
        if case.calibration_scope is CalibrationScope.SEALED_HELD_OUT
    )
    if tuple(held_out) != expected_held_out:
        raise HeldOutLedgerError("held_out_families differ from the frozen split")

    namespaces_raw = _mapping(document["artifact_namespaces"], "artifact_namespaces")
    _require_fields(namespaces_raw, NAMESPACE_FIELDS, "artifact_namespaces")
    if namespaces_raw != _EXPECTED_NAMESPACES:
        raise HeldOutLedgerError("development and held-out namespaces must remain disjoint")
    for value in namespaces_raw.values():
        _safe_relative_path(value, "artifact namespace")

    policies_raw = _mapping(document["policies"], "policies")
    _require_fields(policies_raw, POLICY_FIELDS, "policies")
    if policies_raw != _EXPECTED_POLICIES:
        raise HeldOutLedgerError("ledger policies differ from the irreversible policy")
    return HeldOutPrecommit(
        revision=1,
        calibration_lock_path=calibration_path,
        bindings=bindings,
        backend_components=components,
        held_out_families=expected_held_out,
        artifact_namespaces=ArtifactNamespaces(**namespaces_raw),
        policies=LedgerPolicies(**policies_raw),
    )


def seal_precommit(precommit: HeldOutPrecommit) -> OpeningReceipt:
    """Create the only legal first transition without observing held-out results."""

    return OpeningReceipt(
        ledger_revision=precommit.revision,
        sequence=0,
        previous_receipt_sha256=None,
        from_state=LedgerState.PRECOMMITTED,
        to_state=LedgerState.SEALED,
        bindings=precommit.bindings,
        result=None,
    )


def open_held_out(
    precommit: HeldOutPrecommit,
    sealed: OpeningReceipt,
    result_payload: bytes,
    *,
    result_format: str,
) -> OpeningReceipt:
    """Create an OPENED receipt only after validating the seal and public result."""

    validate_receipt_chain(precommit, (sealed,))
    if not result_payload or len(result_payload) > MAX_RESULT_BYTES:
        raise HeldOutLedgerError("held-out result size is outside the public bound")
    if _FORMAT_ID.fullmatch(result_format) is None:
        raise HeldOutLedgerError("result_format must be a canonical identifier")
    try:
        result_document = json.loads(result_payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HeldOutLedgerError("held-out result must be UTF-8 JSON") from error
    _reject_private_fields(result_document, "held_out_result")
    result = ResultDigest(
        format=result_format,
        sha256=hashlib.sha256(result_payload).hexdigest(),
        byte_count=len(result_payload),
    )
    return OpeningReceipt(
        ledger_revision=precommit.revision,
        sequence=1,
        previous_receipt_sha256=receipt_sha256(sealed),
        from_state=LedgerState.SEALED,
        to_state=LedgerState.OPENED,
        bindings=precommit.bindings,
        result=result,
    )


def validate_receipt_chain(precommit: HeldOutPrecommit, receipts: Sequence[OpeningReceipt]) -> None:
    """Validate the complete two-step monotonic chain against current bindings."""

    if not 1 <= len(receipts) <= 2:
        raise HeldOutLedgerError("receipt chain must contain one seal and at most one opening")
    first = receipts[0]
    _validate_receipt_common(precommit, first)
    if (
        first.sequence != 0
        or first.previous_receipt_sha256 is not None
        or first.from_state is not LedgerState.PRECOMMITTED
        or first.to_state is not LedgerState.SEALED
        or first.result is not None
    ):
        raise HeldOutLedgerError("first receipt must be PRECOMMITTED to SEALED")
    if len(receipts) == 1:
        return
    second = receipts[1]
    _validate_receipt_common(precommit, second)
    if (
        second.sequence != 1
        or second.previous_receipt_sha256 != receipt_sha256(first)
        or second.from_state is not LedgerState.SEALED
        or second.to_state is not LedgerState.OPENED
        or second.result is None
    ):
        raise HeldOutLedgerError("second receipt must append SEALED to OPENED")


def append_receipt(path: Path, precommit: HeldOutPrecommit, receipt: OpeningReceipt) -> Path:
    """Append one canonical receipt without replacing or truncating prior bytes."""

    existing = list(load_receipts(path, precommit=precommit)) if path.exists() else []
    if receipt.sequence < len(existing):
        if existing[receipt.sequence] == receipt:
            return path
        raise HeldOutLedgerError("conflicting receipt already occupies this sequence")
    if receipt.sequence != len(existing):
        raise HeldOutLedgerError("receipt sequence is not append-only")
    candidate = (*existing, receipt)
    validate_receipt_chain(precommit, candidate)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("ab") as handle:
        handle.write(serialize_receipt(receipt))
    return path


def load_receipts(
    path: Path, *, precommit: HeldOutPrecommit | None = None
) -> tuple[OpeningReceipt, ...]:
    """Load canonical JSONL receipts and optionally verify their full chain."""

    payload = path.read_bytes()
    if not payload or b"\r" in payload:
        raise HeldOutLedgerError("receipt ledger must be non-empty LF-only JSONL")
    lines = payload.splitlines(keepends=True)
    if any(not line.endswith(b"\n") for line in lines):
        raise HeldOutLedgerError("every receipt must end in LF")
    receipts = tuple(_parse_receipt(line) for line in lines)
    if any(
        serialize_receipt(receipt) != line for receipt, line in zip(receipts, lines, strict=True)
    ):
        raise HeldOutLedgerError("receipt ledger is not canonical JSONL")
    if precommit is not None:
        validate_receipt_chain(precommit, receipts)
    return receipts


def serialize_receipt(receipt: OpeningReceipt) -> bytes:
    """Return one canonical JSONL record."""

    mapping = _receipt_mapping(receipt)
    _reject_private_fields(mapping, "receipt")
    return _canonical_json(mapping) + b"\n"


def receipt_sha256(receipt: OpeningReceipt) -> str:
    """Return a domain-separated receipt digest used by the next link."""

    return hashlib.sha256(
        RECEIPT_HASH_DOMAIN + serialize_receipt(receipt).removesuffix(b"\n")
    ).hexdigest()


def main(arguments: Sequence[str] | None = None) -> int:
    """Seal or open a held-out receipt ledger without embedding local paths."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("configs/quotient_forge/heldout_precommit_v1.yaml"),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    seal = subparsers.add_parser("seal")
    seal.add_argument("--ledger", type=Path, required=True)
    opening = subparsers.add_parser("open")
    opening.add_argument("--ledger", type=Path, required=True)
    opening.add_argument("--result", type=Path, required=True)
    opening.add_argument("--result-format", required=True)
    options = parser.parse_args(arguments)
    try:
        precommit = load_precommit(options.config)
        if options.command == "seal":
            append_receipt(options.ledger, precommit, seal_precommit(precommit))
        else:
            receipts = load_receipts(options.ledger, precommit=precommit)
            if len(receipts) != 1:
                raise HeldOutLedgerError("ledger is not in SEALED state")
            opened = open_held_out(
                precommit,
                receipts[0],
                options.result.read_bytes(),
                result_format=options.result_format,
            )
            append_receipt(options.ledger, precommit, opened)
    except (HeldOutLedgerError, OSError, ValueError) as error:
        parser.error(str(error))
    return 0


def _validate_receipt_common(precommit: HeldOutPrecommit, receipt: OpeningReceipt) -> None:
    if receipt.ledger_revision != precommit.revision:
        raise HeldOutLedgerError("receipt revision is stale")
    if receipt.bindings != precommit.bindings:
        raise HeldOutLedgerError("receipt binding is stale")
    if receipt.private_field_count != 0:
        raise HeldOutLedgerError("receipt must contain no private fields")


def _receipt_mapping(receipt: OpeningReceipt) -> dict[str, object]:
    return {
        "schema": RECEIPT_SCHEMA,
        "ledger_revision": receipt.ledger_revision,
        "sequence": receipt.sequence,
        "previous_receipt_sha256": receipt.previous_receipt_sha256,
        "from_state": receipt.from_state.value,
        "to_state": receipt.to_state.value,
        "bindings": _bindings_mapping(receipt.bindings),
        "result": (
            None
            if receipt.result is None
            else {
                "format": receipt.result.format,
                "sha256": receipt.result.sha256,
                "byte_count": receipt.result.byte_count,
            }
        ),
        "private_field_count": receipt.private_field_count,
    }


def _parse_receipt(payload: bytes) -> OpeningReceipt:
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HeldOutLedgerError("receipt is not UTF-8 JSON") from error
    mapping = _mapping(document, "receipt")
    _require_fields(mapping, RECEIPT_FIELDS, "receipt")
    if mapping["schema"] != RECEIPT_SCHEMA:
        raise HeldOutLedgerError("unsupported receipt schema")
    result_raw = mapping["result"]
    result = None
    if result_raw is not None:
        result_mapping = _mapping(result_raw, "receipt.result")
        _require_fields(result_mapping, RESULT_FIELDS, "receipt.result")
        result = ResultDigest(
            format=_format_id(result_mapping["format"]),
            sha256=_digest(result_mapping["sha256"], "receipt.result.sha256"),
            byte_count=_positive_integer(result_mapping["byte_count"], "receipt.result.byte_count"),
        )
    try:
        from_state = LedgerState(mapping["from_state"])
        to_state = LedgerState(mapping["to_state"])
    except (TypeError, ValueError) as error:
        raise HeldOutLedgerError("receipt contains an unknown state") from error
    return OpeningReceipt(
        ledger_revision=_positive_integer(mapping["ledger_revision"], "ledger_revision"),
        sequence=_nonnegative_integer(mapping["sequence"], "sequence"),
        previous_receipt_sha256=(
            None
            if mapping["previous_receipt_sha256"] is None
            else _digest(mapping["previous_receipt_sha256"], "previous_receipt_sha256")
        ),
        from_state=from_state,
        to_state=to_state,
        bindings=_parse_bindings(mapping["bindings"], "receipt.bindings"),
        result=result,
        private_field_count=_nonnegative_integer(
            mapping["private_field_count"], "private_field_count"
        ),
    )


def _parse_bindings(value: object, location: str) -> LedgerBindings:
    mapping = _mapping(value, location)
    _require_fields(mapping, BINDING_FIELDS, location)
    return LedgerBindings(
        **{field: _digest(mapping[field], f"{location}.{field}") for field in BINDING_FIELDS}
    )


def _bindings_mapping(bindings: LedgerBindings) -> dict[str, str]:
    return {field: getattr(bindings, field) for field in sorted(BINDING_FIELDS)}


def _parse_component(value: object, index: int) -> BackendComponent:
    mapping = _mapping(value, f"backend_components[{index}]")
    _require_fields(mapping, COMPONENT_FIELDS, f"backend_components[{index}]")
    path = _safe_relative_path(mapping["path"], "backend component path")
    return BackendComponent(path, _digest(mapping["sha256"], "backend component sha256"))


def _normalized_file_sha256(path: Path) -> str:
    try:
        payload = path.read_bytes().replace(b"\r\n", b"\n")
    except OSError as error:
        raise HeldOutLedgerError(f"backend component is unavailable: {path.name}") from error
    if b"\r" in payload:
        raise HeldOutLedgerError("backend component contains non-canonical CR bytes")
    return hashlib.sha256(payload).hexdigest()


def _load_yaml_mapping(path: Path) -> dict[str, Any]:
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as error:
        raise HeldOutLedgerError(f"cannot load held-out precommit: {path}") from error
    return _mapping(document, "precommit")


def _mapping(value: object, location: str) -> dict[str, Any]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise HeldOutLedgerError(f"{location} must be a string-keyed mapping")
    return dict(value)


def _require_fields(mapping: Mapping[str, object], expected: frozenset[str], location: str) -> None:
    if set(mapping) != expected:
        raise HeldOutLedgerError(f"{location} fields differ from the frozen allowlist")


def _fixed_relative_path(value: object, expected: str) -> str:
    if value != expected:
        raise HeldOutLedgerError(f"path must be {expected}")
    return _safe_relative_path(value, "fixed path")


def _safe_relative_path(value: object, field: str) -> str:
    if type(value) is not str or not value:
        raise HeldOutLedgerError(f"{field} must be non-empty text")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or "\\" in value:
        raise HeldOutLedgerError(f"{field} must be repository-relative POSIX text")
    return value


def _digest(value: object, field: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise HeldOutLedgerError(f"{field} must be lowercase SHA-256")
    return value


def _format_id(value: object) -> str:
    if type(value) is not str or _FORMAT_ID.fullmatch(value) is None:
        raise HeldOutLedgerError("result format is invalid")
    return value


def _positive_integer(value: object, field: str) -> int:
    if type(value) is not int or value < 1:
        raise HeldOutLedgerError(f"{field} must be a positive integer")
    return value


def _nonnegative_integer(value: object, field: str) -> int:
    if type(value) is not int or value < 0:
        raise HeldOutLedgerError(f"{field} must be a non-negative integer")
    return value


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("ascii")


def _domain_hash(domain: bytes, value: object) -> str:
    return hashlib.sha256(domain + _canonical_json(value)).hexdigest()


def _reject_private_fields(value: object, path: str) -> None:
    forbidden = {
        "private_history",
        "biosignal",
        "participant_id",
        "subject_id",
        "device_id",
        "token_bytes",
        "key_material",
        "username",
        "host_path",
        "absolute_path",
    }
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = re.sub(r"[^a-z0-9]+", "_", str(key).lower()).strip("_")
            if normalized in forbidden:
                raise HeldOutLedgerError(f"forbidden field: {path}.{key}")
            _reject_private_fields(child, f"{path}.{key}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for index, child in enumerate(value):
            _reject_private_fields(child, f"{path}[{index}]")


if __name__ == "__main__":
    raise SystemExit(main())
