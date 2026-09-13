"""Closed public-only handoff contract for bounded longitudinal AQNI."""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass

FORMAT_VERSION = "noticer.k7.public-handoff.v1"
_SHA256 = re.compile(r"[0-9a-f]{64}")
_FORBIDDEN = frozenset(
    {"identity", "private_cache", "private_history", "raw_biosignal",
     "secret_retry", "secret_retry_state"}
)


class HandoffValidationError(ValueError):
    """Stable validation failure."""

    def __init__(self, category: str, message: str) -> None:
        super().__init__(message)
        self.category = category


@dataclass(frozen=True)
class ResourceBounds:
    horizon_slots: int
    max_queries: int
    max_retries: int
    max_failures: int


@dataclass(frozen=True)
class PublicHandoffState:
    observer_state_sha256: str
    colluding_services: tuple[str, ...]
    epoch_id: str
    key_epoch_id: str
    epoch_event_slot: int


@dataclass(frozen=True)
class PublicHandoffContract:
    format_version: str
    contract_id: str
    action_semantics_sha256: str
    observer_contract_sha256: str
    source_certificate_sha256: str
    state: PublicHandoffState
    bounds: ResourceBounds


def contract_from_document(document: Mapping[str, object]) -> PublicHandoffContract:
    """Parse exact keys and reject private carryover recursively."""
    _reject_forbidden(document)
    _keys(document, {"format_version", "contract_id", "action_semantics_sha256",
                     "observer_contract_sha256", "source_certificate_sha256",
                     "state", "bounds"}, "root")
    state = _mapping(document["state"], "state")
    _keys(state, {"observer_state_sha256", "colluding_services", "epoch_id",
                  "key_epoch_id", "epoch_event_slot"}, "state")
    bounds = _mapping(document["bounds"], "bounds")
    _keys(bounds, {"horizon_slots", "max_queries", "max_retries", "max_failures"},
          "bounds")
    contract = PublicHandoffContract(
        format_version=_text(document["format_version"], "format_version"),
        contract_id=_text(document["contract_id"], "contract_id"),
        action_semantics_sha256=_text(document["action_semantics_sha256"], "action"),
        observer_contract_sha256=_text(document["observer_contract_sha256"], "observer"),
        source_certificate_sha256=_text(document["source_certificate_sha256"], "source"),
        state=PublicHandoffState(
            observer_state_sha256=_text(state["observer_state_sha256"], "observer state"),
            colluding_services=tuple(_text(v, "service") for v in
                                     _sequence(state["colluding_services"], "services")),
            epoch_id=_text(state["epoch_id"], "epoch"),
            key_epoch_id=_text(state["key_epoch_id"], "key epoch"),
            epoch_event_slot=_integer(state["epoch_event_slot"], "event slot"),
        ),
        bounds=ResourceBounds(
            horizon_slots=_integer(bounds["horizon_slots"], "horizon"),
            max_queries=_integer(bounds["max_queries"], "queries"),
            max_retries=_integer(bounds["max_retries"], "retries"),
            max_failures=_integer(bounds["max_failures"], "failures"),
        ),
    )
    validate_contract(contract)
    return contract


def validate_contract(contract: PublicHandoffContract) -> None:
    """Validate digests, canonical public state, and finite scope."""
    if contract.format_version != FORMAT_VERSION:
        raise HandoffValidationError("unsupported_format", "unsupported format")
    if not contract.contract_id or not contract.state.epoch_id or not contract.state.key_epoch_id:
        raise HandoffValidationError("empty_identifier", "identifier is empty")
    for digest in (contract.action_semantics_sha256,
                   contract.observer_contract_sha256,
                   contract.source_certificate_sha256,
                   contract.state.observer_state_sha256):
        if _SHA256.fullmatch(digest) is None:
            raise HandoffValidationError("invalid_digest", "binding is not SHA-256")
    services = contract.state.colluding_services
    if services != tuple(sorted(set(services))):
        raise HandoffValidationError("noncanonical_services", "services must be sorted unique")
    if any(not service for service in services):
        raise HandoffValidationError("empty_identifier", "service is empty")
    if contract.bounds.horizon_slots < 1:
        raise HandoffValidationError("invalid_bound", "horizon must be positive")
    if contract.state.epoch_event_slot > contract.bounds.horizon_slots:
        raise HandoffValidationError("event_out_of_bounds", "epoch event exceeds horizon")


def canonical_contract_json(contract: PublicHandoffContract) -> bytes:
    validate_contract(contract)
    return (json.dumps(asdict(contract), sort_keys=True, separators=(",", ":"))
            + "\n").encode("utf-8")


def contract_digest(contract: PublicHandoffContract) -> str:
    return hashlib.sha256(canonical_contract_json(contract)).hexdigest()


def _reject_forbidden(value: object) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if key in _FORBIDDEN:
                raise HandoffValidationError("forbidden_private_carryover",
                                             f"{key} cannot cross handoff")
            _reject_forbidden(child)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for child in value:
            _reject_forbidden(child)


def _mapping(value: object, location: str) -> Mapping[str, object]:
    if not isinstance(value, dict) or not all(isinstance(k, str) for k in value):
        raise HandoffValidationError("invalid_document", f"{location} must be object")
    return value


def _sequence(value: object, location: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise HandoffValidationError("invalid_document", f"{location} must be array")
    return value


def _text(value: object, location: str) -> str:
    if not isinstance(value, str):
        raise HandoffValidationError("invalid_document", f"{location} must be string")
    return value


def _integer(value: object, location: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise HandoffValidationError("invalid_document", f"{location} must be non-negative")
    return value


def _keys(value: Mapping[str, object], expected: set[str], location: str) -> None:
    if set(value) != expected:
        raise HandoffValidationError("undeclared_field",
                                     f"{location} violates closed handoff schema")
