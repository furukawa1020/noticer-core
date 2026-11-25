import pytest

from noticer_core.evaluation.k21_figure_receipt import bind_figure, verify_figure


def test_figure_replacement_is_detected() -> None:
    digest = "a" * 64
    svg = f'<svg role="img"><desc>source digest {digest}.</desc></svg>'.encode("ascii")
    receipt = bind_figure("fig-1", svg, source_capsule_sha256=digest)
    verify_figure(receipt, svg)
    with pytest.raises(ValueError, match="figure bytes"):
        verify_figure(receipt, svg.replace(b"</svg>", b"<line/></svg>"))
    with pytest.raises(ValueError, match="expected capsule"):
        bind_figure("fig-1", svg, source_capsule_sha256="b" * 64)
