"""An allowlisted export for reviewing this synthetic fixture out of context."""

from typing import Any

from noticer_core.shared_slot_report import build_shared_slot_report


def build_anonymous_evidence() -> dict[str, Any]:
    """Select only the bounded comparison; omit project and environment metadata."""
    report = build_shared_slot_report()
    causality = report["causality"]
    return {
        "schema": "shared-capacity-synthetic-fixture.v1",
        "empirical": False,
        "schedules": report["schedules"],
        "first_choice": {
            "trace": causality["shortest_trace"],
            "deterministic": causality["deterministic_first_choice"],
            "randomized": causality["randomized_first_choice"],
            "control_status": causality["controls"],
        },
    }
