import csv

from noticer_core.evaluation.k20_capsule import (
    PublicEndpoint,
    PublicSummary,
    encode_public_capsule,
    public_capsule_digest,
)
from noticer_core.evaluation.k20_dataset_manifest import EvidenceClass
from noticer_core.evaluation.k20_report_table import render_comparison_table


def test_table_pins_provenance_and_evidence_class() -> None:
    capsule = encode_public_capsule(
        evidence_class=EvidenceClass.SYNTHETIC_CONTROL,
        public_protocol_sha256="a" * 64,
        summaries=(PublicSummary(PublicEndpoint.LINKABILITY_AUC, 0.5, 0.4, 0.6, 20),),
    )
    digest = public_capsule_digest(capsule)
    output = render_comparison_table({"aetp": (capsule, digest)})
    assert output == render_comparison_table({"aetp": (capsule, digest)})
    row, = csv.DictReader(output.decode("ascii").splitlines())
    assert row["evidence_class"] == "synthetic-control"
    assert row["capsule_sha256"] == digest
    assert row["estimate"] == "0.5"


def test_absent_endpoint_remains_missing_in_the_comparison() -> None:
    def encode(endpoint: PublicEndpoint) -> tuple[bytes, str]:
        data = encode_public_capsule(
            evidence_class=EvidenceClass.FIXTURE,
            public_protocol_sha256="a" * 64,
            summaries=(PublicSummary(endpoint, 0.5, 0.4, 0.6, 20),),
        )
        return data, public_capsule_digest(data)

    inputs = {
        "aetp": encode(PublicEndpoint.LINKABILITY_AUC),
        "fixed-rate": encode(PublicEndpoint.DEADLINE_RATE),
    }
    output = render_comparison_table(inputs)
    rows = list(csv.DictReader(output.decode("ascii").splitlines()))
    assert sum(row["state"] == "missing" for row in rows) == 2
    assert output == render_comparison_table(dict(reversed(tuple(inputs.items()))))
