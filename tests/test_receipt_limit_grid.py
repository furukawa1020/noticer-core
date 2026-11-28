from noticer_core.receipt_limit_grid import compare_grid


def test_grid_uses_fixed_denominators_and_retains_ties():
    grid = compare_grid()
    for row in grid.values():
        assert row["pairs"] == 136 and row["checks"] == 1632
        assert 0 <= row["advantage"] < row["checks"]
        assert row["visibility_decreases"] > 0
    assert grid["1,1"]["advantage"] == 4
    assert grid["2,1"]["advantage"] == 0
