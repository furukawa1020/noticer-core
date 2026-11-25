"""Build an explicitly synthetic K20 paper-format bundle for reproducibility CI."""

import argparse
import hashlib
import json
from pathlib import Path

from noticer_core.evaluation.k20_capsule import (
    PublicEndpoint,
    PublicSummary,
    encode_public_capsule,
    public_capsule_digest,
)
from noticer_core.evaluation.k20_dataset_manifest import EvidenceClass
from noticer_core.evaluation.k20_report_figure import render_interval_figure
from noticer_core.evaluation.k20_report_table import render_comparison_table

_FIXTURE_PROTOCOL = b"noticer.k20.fixture.v1;seed=42;units=16;precomputed-not-measured"
_ENDPOINT = PublicEndpoint.WIRE_BYTES


def build_fixture_bundle(output: Path) -> None:
    """Render fixed synthetic aggregate examples, never results from participant data."""
    protocol = hashlib.sha256(_FIXTURE_PROTOCOL).hexdigest()
    capsules: dict[str, tuple[bytes, str]] = {}
    for name, estimates in {"aetp": (64, 58, 70), "fixed-rate": (82, 76, 88)}.items():
        capsule = encode_public_capsule(
            evidence_class=EvidenceClass.FIXTURE,
            public_protocol_sha256=protocol,
            summaries=(PublicSummary(_ENDPOINT, *estimates, independent_units=16),),
        )
        capsules[name] = capsule, public_capsule_digest(capsule)
    output.mkdir(parents=True, exist_ok=True)
    for name, (capsule, digest) in sorted(capsules.items()):
        (output / f"{name}.json").write_bytes(capsule)
        (output / f"{name}.svg").write_bytes(
            render_interval_figure(
                capsule, expected_digest=digest, endpoint=_ENDPOINT, axis=(0, 100)
            )
        )
    (output / "comparison.csv").write_bytes(render_comparison_table(capsules))
    description = {
        "schema": "noticer.k20.fixture-report.v1",
        "evidence_class": "fixture",
        "statement": "Precomputed synthetic display values. Not measured.",
        "seed": 42,
        "protocol_sha256": protocol,
    }
    (output / "manifest.json").write_bytes(json.dumps(description, sort_keys=True).encode("ascii"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="directory for synthetic output")
    args = parser.parse_args()
    build_fixture_bundle(args.output)


if __name__ == "__main__":
    main()
