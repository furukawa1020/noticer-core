"""Versioned, deterministic evidence for the shared-slot research cases."""

from typing import Any

from noticer_core.shared_slot_branch import crossed_public_futures, public_first_view
from noticer_core.shared_slot_causal import binary_minimax
from noticer_core.shared_slot_examples import (
    capacity_deficit_case,
    deadline_gap_case,
    no_contention_case,
)
from noticer_core.shared_slot_greedy import deadline_first
from noticer_core.shared_slot_solve import solve_shared_slots
from noticer_core.shared_slot_status import audit_public_futures
from noticer_core.shared_slot_verify import verify_assignment


def build_shared_slot_report() -> dict[str, Any]:
    """Report negative controls and cutoffs alongside successful allocations."""
    schedules: dict[str, Any] = {}
    for label, case in (
        ("deadline_gap", deadline_gap_case()),
        ("capacity_deficit", capacity_deficit_case()),
        ("no_contention", no_contention_case()),
    ):
        reference = deadline_first(case)
        exact = solve_shared_slots(case)
        if not verify_assignment(case, reference, complete=False):
            raise RuntimeError("reference emitted an invalid partial assignment")
        cut = exact.deficit
        schedules[label] = {
            "demand": len(case.actions),
            "deadline_first": reference,
            "exact_offline": exact.placements,
            "deficit": None if cut is None else {
                "actions": cut.actions,
                "slots": cut.slots,
                "capacity": sum(case.capacities[slot] for slot in cut.slots),
            },
        }

    left, right = crossed_public_futures()
    audit = audit_public_futures(left, right)
    if (
        audit.status != "verified"
        or audit.evidence is None
        or not audit.evidence.have_no_common_choice
    ):
        raise RuntimeError("expected verified synthetic first-choice separation")
    values = binary_minimax(audit.evidence)
    capacity, demand = public_first_view(left)
    return {
        "schema": "noticer.shared-slot-evidence.v1",
        "scope": "synthetic_two_slot_causal_claim_only",
        "schedules": schedules,
        "causality": {
            "status": audit.status,
            "deterministic_first_choice": str(values.deterministic),
            "randomized_first_choice": str(values.randomized),
            "shortest_trace": [{
                "slot": 0,
                "input": {
                    "capacity": capacity,
                    "demand": [
                        {"action": name, "deadline": deadline, "available": available}
                        for name, deadline, available in demand
                    ],
                },
                "left_state": {
                    "completable_first_choices": sorted(audit.evidence.left, key=str)
                },
                "right_state": {
                    "completable_first_choices": sorted(audit.evidence.right, key=str)
                },
            }],
            "controls": {
                "equal_futures": audit_public_futures(left, left).status,
                "forced_cutoff": audit_public_futures(left, right, max_candidates=1).status,
                "invalid_budget": audit_public_futures(left, right, max_candidates=0).status,
            },
        },
    }
