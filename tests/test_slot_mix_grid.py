from noticer_core.slot_mix_grid import compare_incidence_grid


def test_grid_keeps_its_exhaustive_denominators():
    grid = compare_incidence_grid()
    for size, cases in (("3", 35), ("4", 1365)):
        row = grid[size]
        assert row["cases"] == row["verified"] + row["inconclusive"] == cases
        assert row["ties_uniform"] + row["beats_uniform"] == row["verified"]
        assert row["ties_iterative"] + row["beats_iterative"] == row["verified"]
        assert sum(row["optimum_histogram"].values()) == row["verified"]
