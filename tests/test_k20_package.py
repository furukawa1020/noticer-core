import json

import pytest

from noticer_core.evaluation.k20_capsule import (
    PublicEndpoint,
    PublicSummary,
    encode_public_capsule,
    public_capsule_digest,
)
from noticer_core.evaluation.k20_dataset_manifest import EvidenceClass
from noticer_core.evaluation.k20_package import validate_public_package


def capsule() -> bytes:
    return encode_public_capsule(
        evidence_class=EvidenceClass.FIXTURE,
        public_protocol_sha256="a" * 64,
        summaries=(PublicSummary(PublicEndpoint.LINKABILITY_AUC, 0.5, 0.4, 0.6, 20),),
    )


def test_public_review_capsule_round_trip() -> None:
    data = capsule()
    checked = validate_public_package(data, expected_digest=public_capsule_digest(data))
    assert checked.evidence_class is EvidenceClass.FIXTURE
    assert checked.summaries[0].independent_units == 20


def test_digest_and_unknown_fields_are_independent_gates() -> None:
    data = capsule()
    with pytest.raises(ValueError, match="digest mismatch"):
        validate_public_package(data + b" ", expected_digest=public_capsule_digest(data))
    parsed = json.loads(data)
    parsed["subject_ids"] = ["unapproved"]
    bad = json.dumps(parsed).encode("ascii")
    with pytest.raises(ValueError, match="allowlist"):
        validate_public_package(bad, expected_digest=public_capsule_digest(bad))
