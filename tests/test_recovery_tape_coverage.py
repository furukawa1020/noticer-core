from noticer_core.recovery_tape_coverage import separate_tape_coverage


def test_outside_or_missing_is_not_an_eligible_success() -> None:
    report = separate_tape_coverage(
        {"normal": (True, True), "loss": (False, True), "total-loss": (False, False)},
        ["normal", "total-loss"],
    )
    assert report.eligible == ("loss", "normal")
    assert report.outside == ("total-loss",)
    assert report.missing_eligible == ("loss",)
