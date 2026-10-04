"""Bounded differential validation for canonical JSON IR envelopes."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import yaml

SCHEMA = "noticer.k7.canonical-ir.v1"
MAX_BYTES = 65_536
MAX_DEPTH = 64
MAX_ITEMS = 4_096
MAX_INTEGER = (1 << 63) - 1
KINDS = frozenset({"compiled_model", "release_transducer"})


class DifferentialStatus(StrEnum):
    ACCEPT = "accept"
    REJECT = "reject"
    DISAGREEMENT = "disagreement"


@dataclass(frozen=True)
class DifferentialResult:
    status: DifferentialStatus
    category: str
    canonical: bytes | None = None


class _StrictLoader(yaml.SafeLoader):
    pass


def _mapping(loader: _StrictLoader, node: yaml.MappingNode) -> dict[str, Any]:
    pairs = loader.construct_pairs(node, deep=True)
    result: dict[str, Any] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise yaml.YAMLError("duplicate or non-text key")
        result[key] = value
    return result


_StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _mapping,
)


def evaluate_canonical_ir(payload: bytes) -> DifferentialResult:
    """Compare independent parsers and enforce one exact canonical encoding."""

    if not payload or len(payload) > MAX_BYTES:
        return DifferentialResult(DifferentialStatus.REJECT, "byte_limit")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return DifferentialResult(DifferentialStatus.REJECT, "invalid_utf8")

    left_ok, left = _parse_json(text)
    right_ok, right = _parse_yaml(text)
    if left_ok != right_ok or (left_ok and left != right):
        return DifferentialResult(DifferentialStatus.DISAGREEMENT, "parser_disagreement")
    if not left_ok:
        return DifferentialResult(DifferentialStatus.REJECT, "syntax")
    try:
        _validate_value(left, depth=0, items=[0])
        _validate_envelope(left)
        canonical = _canonical(left)
    except (TypeError, ValueError):
        return DifferentialResult(DifferentialStatus.REJECT, "contract")
    if payload != canonical:
        return DifferentialResult(DifferentialStatus.REJECT, "non_canonical")
    if _canonical(json.loads(canonical)) != canonical:
        return DifferentialResult(DifferentialStatus.DISAGREEMENT, "round_trip")
    return DifferentialResult(DifferentialStatus.ACCEPT, "canonical", canonical)


def _parse_json(text: str) -> tuple[bool, Any]:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        return True, json.loads(
            text,
            object_pairs_hook=pairs,
            parse_float=lambda _: (_ for _ in ()).throw(ValueError("float")),
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("constant")),
        )
    except (json.JSONDecodeError, TypeError, ValueError):
        return False, None


def _parse_yaml(text: str) -> tuple[bool, Any]:
    try:
        value = yaml.load(text, Loader=_StrictLoader)
        return True, value
    except (yaml.YAMLError, TypeError, ValueError):
        return False, None


def _validate_envelope(value: Any) -> None:
    if type(value) is not dict or set(value) != {"kind", "payload", "schema", "version"}:
        raise ValueError("fields")
    if value["schema"] != SCHEMA or value["version"] != 1 or value["kind"] not in KINDS:
        raise ValueError("header")
    if type(value["payload"]) is not dict:
        raise ValueError("payload")


def _validate_value(value: Any, *, depth: int, items: list[int]) -> None:
    if depth > MAX_DEPTH:
        raise ValueError("depth")
    if value is None or type(value) in {bool, str}:
        return
    if type(value) is int:
        if not -MAX_INTEGER <= value <= MAX_INTEGER:
            raise ValueError("integer")
        return
    if type(value) is list:
        items[0] += len(value)
        if items[0] > MAX_ITEMS:
            raise ValueError("items")
        for child in value:
            _validate_value(child, depth=depth + 1, items=items)
        return
    if type(value) is dict:
        items[0] += len(value)
        if items[0] > MAX_ITEMS or any(type(key) is not str for key in value):
            raise ValueError("items")
        for child in value.values():
            _validate_value(child, depth=depth + 1, items=items)
        return
    raise TypeError("unsupported value")


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
