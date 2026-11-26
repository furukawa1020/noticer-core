from noticer_core.slot_mix_examples_report import build_mix_examples


def test_published_summary_keeps_certificate_and_non_result_controls():
    report = build_mix_examples()
    assert report == build_mix_examples()
    assert report["empirical"] is False
    asymmetric = report["examples"]["asymmetric"]
    assert (asymmetric["value"], asymmetric["uniform"]) == ("2/5", "1/4")
    assert asymmetric["tape_weights"] == ("1/5", "1/5", "1/5", "2/5")
    assert report["controls"] == {
        "verification_cutoff": "inconclusive",
        "invalid_pivots": "invalid",
    }
