"""Decode a bounded public policy tree without following unknown fields."""

from typing import Any

from noticer_core.slot_mix_frontier import Choice
from noticer_core.slot_mix_json import exact_members


def _names(names: Any) -> tuple[str, ...]:
    if type(names) is not list or len(names) > 8 or any(
        type(name) is not str or len(name) > 64 for name in names
    ):
        raise ValueError("invalid action name array")
    return tuple(names)


def decode_tree(value: Any, horizon: int) -> Choice:
    """Reject over-deep trees, repeated views, and malformed decision arrays."""
    remaining = 128

    def visit(node: Any, depth: int) -> Choice:
        nonlocal remaining
        remaining -= 1
        if depth >= horizon or remaining < 0:
            raise ValueError("policy exceeds bundle tree bounds")
        node = exact_members(node, {"view", "send", "children"})
        view, children = node["view"], node["children"]
        if (
            type(view) is not list or len(view) != 2 or type(view[0]) is not int
            or not 0 <= view[0] <= 128 or type(children) is not list or len(children) > 8
        ):
            raise ValueError("invalid policy observation or branches")
        decoded = tuple(visit(child, depth + 1) for child in children)
        if len({child.view for child in decoded}) != len(decoded):
            raise ValueError("ambiguous public policy branches")
        return Choice((view[0], _names(view[1])), _names(node["send"]), decoded)

    return visit(value, 0)
