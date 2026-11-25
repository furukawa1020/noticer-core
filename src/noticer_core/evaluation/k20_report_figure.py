"""Deterministic SVG interval figure with a caller-declared metric axis."""

from math import isfinite

from noticer_core.evaluation.k20_capsule import PublicEndpoint
from noticer_core.evaluation.k20_package import validate_public_package


def render_interval_figure(
    capsule: bytes,
    *,
    expected_digest: str,
    endpoint: PublicEndpoint,
    axis: tuple[float, float],
) -> bytes:
    """Render one endpoint per figure to avoid putting unlike units on one axis."""
    checked = validate_public_package(capsule, expected_digest=expected_digest)
    row = next((item for item in checked.summaries if item.endpoint is endpoint), None)
    if row is None:
        raise ValueError("endpoint is missing from the public capsule")
    start, end = axis
    width = end - start
    if not all(map(isfinite, (start, end, width))) or width <= 0:
        raise ValueError("plot axis must be finite and increasing")
    if not start <= row.lower <= row.upper <= end:
        raise ValueError("plot axis must include the complete interval")

    def x(value: float) -> str:
        return f"{56 + 528 * ((value - start) / width):.3f}"

    title = f"{row.endpoint.value} | {checked.evidence_class.value}"
    desc = (
        f"Estimate {row.estimate}, interval [{row.lower}, {row.upper}], "
        f"independent units {row.independent_units}, source digest {checked.digest}."
    )
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 176" role="img"'
        ' aria-labelledby="title description">\n'
        f'<title id="title">{title}</title>\n<desc id="description">{desc}</desc>\n'
        '<rect width="640" height="176" fill="#fff"/>\n'
        f'<text x="56" y="33" font-size="18">{title}</text>\n'
        '<line x1="56" x2="584" y1="104" y2="104" stroke="#222"/>\n'
        f'<line x1="{x(row.lower)}" x2="{x(row.upper)}" y1="75" y2="75"'
        ' stroke="#006b63" stroke-width="5"/>\n'
        f'<circle cx="{x(row.estimate)}" cy="75" r="7" fill="#006b63"/>\n'
        f'<text x="56" y="127">{start:.6g}</text>\n'
        f'<text x="584" y="127" text-anchor="end">{end:.6g}</text>\n'
        f'<text x="56" y="155" font-size="13">n = {row.independent_units}'
        f' | {checked.digest[:16]}</text>\n</svg>\n'
    )
    return svg.encode("ascii")
