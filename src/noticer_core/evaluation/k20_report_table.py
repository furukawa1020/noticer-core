"""Deterministic, evidence-labelled CSV table for paper artifact generation."""

import csv
from collections.abc import Mapping
from io import StringIO

from noticer_core.evaluation.k20_package import validate_public_package

_MECHANISMS = {"immediate", "encryption-only", "padding-only", "fixed-rate", "aetp", "full-stack"}


def render_comparison_table(capsules: Mapping[str, tuple[bytes, str]]) -> bytes:
    """Align aggregate endpoints by mechanism; preserve missing summary cells."""
    if not capsules or not capsules.keys() <= _MECHANISMS:
        raise ValueError("a nonempty mapping of registered mechanisms is required")
    checked = {
        key: validate_public_package(data, expected_digest=digest)
        for key, (data, digest) in sorted(capsules.items())
    }
    if len({(c.evidence_class, c.public_protocol_sha256) for c in checked.values()}) != 1:
        raise ValueError("compared capsules must use the same evidence class and public protocol")
    endpoints = sorted({row.endpoint for capsule in checked.values() for row in capsule.summaries})
    output = StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow((
        "mechanism", "evidence_class", "capsule_sha256", "endpoint", "state",
        "estimate", "lower", "upper",
        "independent_units",
    ))
    for mechanism, capsule in checked.items():
        summaries = {row.endpoint: row for row in capsule.summaries}
        for endpoint in endpoints:
            row = summaries.get(endpoint)
            values = ("missing", "", "", "", "") if row is None else (
                "reported", row.estimate, row.lower, row.upper, row.independent_units,
            )
            writer.writerow((
                mechanism, capsule.evidence_class.value, capsule.digest, endpoint.value, *values
            ))
    return output.getvalue().encode("ascii")
