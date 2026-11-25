"""Trace exact paper figure bytes to public source capsules."""

import hashlib
import re
from dataclasses import dataclass

_FIGURE = re.compile(r"fig-[1-9][0-9]{0,3}[a-z]?", re.ASCII)


@dataclass(frozen=True, slots=True)
class FigureReceipt:
    figure_id: str
    figure_sha256: str
    source_capsule_sha256: str


def bind_figure(figure_id: str, svg: bytes, *, source_capsule_sha256: str) -> FigureReceipt:
    """Record the exact lower-level figure bytes and a public capsule digest."""
    if not _FIGURE.fullmatch(figure_id) or not svg.startswith(b"<svg "):
        raise ValueError("expected a canonical figure identifier and generated SVG")
    if len(source_capsule_sha256) != 64 or any(
        ch not in "0123456789abcdef" for ch in source_capsule_sha256
    ):
        raise ValueError("source capsule digest must be lowercase SHA-256")
    if f"source digest {source_capsule_sha256}.".encode("ascii") not in svg:
        raise ValueError("figure does not name the expected capsule")
    return FigureReceipt(figure_id, hashlib.sha256(svg).hexdigest(), source_capsule_sha256)


def verify_figure(receipt: FigureReceipt, svg: bytes) -> None:
    """Reject a substituted report even if its embedded capsule digest is unchanged."""
    actual = bind_figure(
        receipt.figure_id, svg, source_capsule_sha256=receipt.source_capsule_sha256
    )
    if receipt != actual:
        raise ValueError("figure bytes do not match the receipt")
