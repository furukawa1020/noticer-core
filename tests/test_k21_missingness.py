from noticer_core.evaluation.k21_missingness import Observation, summarize_missingness


def test_missing_and_censored_stay_distinct_per_arm() -> None:
    complete, missing, censored = Observation
    rows = summarize_missingness({
        ("base", "quiet"): (complete, complete),
        ("aetp", "quiet"): (complete, missing, censored, censored),
    })
    assert (rows[0].total, rows[0].missing, rows[0].censored) == (4, 1, 2)
    assert (rows[1].total, rows[1].missing, rows[1].censored) == (2, 0, 0)
