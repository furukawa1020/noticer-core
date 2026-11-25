from noticer_core.recovery_pareto import EvidenceStatus, RecoveryCost, recovery_frontier


def test_small_machine_and_early_machine_can_both_be_nondominated() -> None:
    verified = EvidenceStatus.VERIFIED
    result = recovery_frontier([
        RecoveryCost("compact", verified, 0, 1, 4, 100),
        RecoveryCost("fast", verified, 0, 2, 2, 100),
        RecoveryCost("extra-bytes", verified, 0, 2, 2, 110),
        RecoveryCost("cheap-but-missed", verified, 1, 1, 0, 0),
        RecoveryCost("timeout", EvidenceStatus.INCONCLUSIVE, 0, 1, 0, 0),
    ])
    assert result.nondominated == ("compact", "fast")
    assert result.dominated == ("extra-bytes",)
    assert result.ineligible == ("cheap-but-missed", "timeout")
