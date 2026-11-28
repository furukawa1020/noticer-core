from noticer_core.receipt_limit_report import build_report


def test_report_keeps_failed_and_inconclusive_controls():
    result = build_report()
    assert result == build_report()
    assert result["empirical"] is False
    assert result["tradeoff"]["single"]["1/4"]["certified"] == "5/8"
    assert result["tradeoff"]["coalition"]["1/4"]["certified"] == "1/4"
    assert result["controls"] == {
        "invalid": "invalid",
        "cutoff": "inconclusive",
        "unreachable": "0",
    }
