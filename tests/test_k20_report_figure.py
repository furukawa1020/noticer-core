import xml.etree.ElementTree as et

import pytest

from noticer_core.evaluation.k20_capsule import (
    PublicEndpoint,
    PublicSummary,
    encode_public_capsule,
    public_capsule_digest,
)
from noticer_core.evaluation.k20_dataset_manifest import EvidenceClass
from noticer_core.evaluation.k20_report_figure import render_interval_figure


def test_figure_pins_source_and_does_not_clip_uncertainty() -> None:
    endpoint = PublicEndpoint.LINKABILITY_AUC
    capsule = encode_public_capsule(
        evidence_class=EvidenceClass.FIXTURE,
        public_protocol_sha256="a" * 64,
        summaries=(PublicSummary(endpoint, 0.5, 0.4, 0.6, 20),),
    )
    digest = public_capsule_digest(capsule)
    kwargs = {"expected_digest": digest, "endpoint": endpoint}
    figure = render_interval_figure(capsule, axis=(0, 1), **kwargs)
    assert figure == render_interval_figure(capsule, axis=(0, 1), **kwargs)
    assert et.fromstring(figure).tag.endswith("svg")
    assert b"fixture" in figure and digest.encode("ascii") in figure
    with pytest.raises(ValueError, match="complete interval"):
        render_interval_figure(capsule, axis=(0.45, 0.55), **kwargs)
