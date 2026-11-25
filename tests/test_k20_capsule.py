import json

import pytest

from noticer_core.evaluation.k20_capsule import (
    PublicEndpoint,
    PublicSummary,
    encode_public_capsule,
    public_capsule_digest,
)
from noticer_core.evaluation.k20_dataset_manifest import EvidenceClass


def encode(*rows: PublicSummary) -> bytes:
    return encode_public_capsule(
        evidence_class=EvidenceClass.FIXTURE, public_protocol_sha256="a" * 64, summaries=rows
    )


def test_canonical_capsule_exposes_only_whitelisted_aggregate_fields() -> None:
    auc = PublicSummary(PublicEndpoint.LINKABILITY_AUC, 0.5, 0.4, 0.6, 20)
    cost = PublicSummary(PublicEndpoint.WIRE_BYTES, 20, 15, 25, 20)
    capsule = encode(auc, cost)
    assert capsule == encode(cost, auc)
    assert len(public_capsule_digest(capsule)) == 64
    parsed = json.loads(capsule)
    assert parsed["evidence_class"] == "fixture"
    assert set(parsed["summaries"][0]) == {
        "endpoint", "estimate", "lower", "upper", "independent_units"
    }


def test_outside_interval_does_not_become_public_evidence() -> None:
    with pytest.raises(ValueError, match="enclosed"):
        encode(PublicSummary(PublicEndpoint.LINKABILITY_AUC, 0.8, 0.4, 0.6, 20))
