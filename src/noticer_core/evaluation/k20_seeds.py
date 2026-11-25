"""Order-independent, versioned seeds for comparable K20 runs."""

import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass

_LABEL = re.compile(r"[a-z0-9][a-z0-9._/-]{0,95}", re.ASCII)
_SCHEMA = b"NOTICER_K20_SEED_V1\0"


@dataclass(frozen=True, slots=True)
class SeedLedger:
    root_seed: int
    entries: tuple[tuple[str, int], ...]

    def verify(self, expected: Iterable[str]) -> None:
        """Require the entire expected scope and recompute each derived value."""
        if self != build_seed_ledger(self.root_seed, expected):
            raise ValueError("seed ledger does not match the expected scope and derivations")


def build_seed_ledger(root_seed: int, labels: Iterable[str]) -> SeedLedger:
    """Derive uint32 seeds suitable for NumPy and scikit-learn."""
    if type(root_seed) is not int or not 0 <= root_seed < 2**64:
        raise ValueError("root_seed must be an unsigned 64-bit integer")
    names = tuple(labels)
    if not names or any(not isinstance(name, str) or not _LABEL.fullmatch(name) for name in names):
        raise ValueError("a nonempty set of canonical seed labels is required")
    if len(set(names)) != len(names):
        raise ValueError("duplicate seed labels are not allowed")
    prefix = _SCHEMA + root_seed.to_bytes(8, "big")
    entries = tuple(
        (name, int.from_bytes(hashlib.sha256(prefix + name.encode("ascii")).digest()[:4], "big"))
        for name in sorted(names)
    )
    if len({value for _, value in entries}) != len(entries):
        raise ValueError("derived uint32 seeds collide; choose a different root before execution")
    return SeedLedger(root_seed, entries)
