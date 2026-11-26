from noticer_core.shared_slot_scale import scaling_cases
from noticer_core.shared_slot_solve import solve_shared_slots


def test_scaling_cases_preserve_a_deficient_tail():
    counts = {label: len(solve_shared_slots(case).placements) for label, case in scaling_cases()}
    assert len(counts) == 12
    assert counts["actions-48"] == 48
    assert counts["horizon-64"] == 16
    assert counts["outage-0"] == 24
    assert counts["outage-8"] == 16
