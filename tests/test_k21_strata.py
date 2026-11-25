from noticer_core.evaluation.k21_strata import assess_stratum_support


def test_missing_or_nonmatching_strata_are_visible() -> None:
    results = assess_stratum_support({"a": {"p"}, "b": {"q"}}, {"a": {"p"}, "c": {"r"}})
    assert [entry.stratum for entry in results] == ["a", "b", "c"]
    assert [entry.comparable for entry in results] == [True, False, False]
    assert results[1].baseline_only == 1
    assert results[2].treatment_only == 1
