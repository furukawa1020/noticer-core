"""Conservative inventory preflight for an anonymous draft, not anonymity assurance."""

import re
from collections.abc import Iterable
from pathlib import PurePosixPath

_SEGMENT = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9_.-]*")
_SUFFIX = {".md", ".txt", ".json", ".csv", ".svg", ".py", ".rs", ".toml", ".yaml", ".yml"}
_IDENTIFYING = {"noticer", "menfugu", "furukawa", "author", "participant", "raw"}


def check_release_inventory(paths: Iterable[str]) -> tuple[str, ...]:
    """Reject unsafe or obviously identifying names before rendering any archive."""
    values = tuple(paths)
    if not values:
        raise ValueError("review inventory must not be empty")
    keys = set()
    for value in values:
        parts = value.split("/")
        path = PurePosixPath(value)
        if path.suffix not in _SUFFIX or any(
            not _SEGMENT.fullmatch(part) or part.endswith((".", " ")) for part in parts
        ):
            raise ValueError("unsafe or unapproved archive member")
        components = set(re.split(r"[._/-]+", value.casefold()))
        if _IDENTIFYING & components:
            raise ValueError("identifying archive name requires a second review")
        folded = value.casefold()
        if folded in keys:
            raise ValueError("duplicate or case-colliding archive member")
        keys.add(folded)
    return tuple(sorted(values))
