"""Bound JSON before any portable certificate is decoded."""

import json
from typing import Any

MAX_BUNDLE_BYTES = 256_000


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def decode_json(raw: bytes) -> Any:
    """No duplicate members, non-UTF8, unbounded files, or nonfinite constants."""
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_BUNDLE_BYTES:
        raise ValueError("invalid bundle byte size")

    def invalid_constant(value: str) -> None:
        raise ValueError(f"forbidden JSON constant: {value}")

    try:
        return json.loads(
            raw.decode("utf-8"), object_pairs_hook=_unique_pairs, parse_constant=invalid_constant
        )
    except (UnicodeDecodeError, RecursionError) as error:
        raise ValueError("invalid UTF-8 or excessive JSON nesting") from error


def exact_members(value: Any, names: set[str]) -> dict[str, Any]:
    """Reject unknown members rather than assuming they do not affect semantics."""
    if type(value) is not dict or value.keys() != names:
        raise ValueError("invalid JSON object shape")
    return value
