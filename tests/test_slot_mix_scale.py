from noticer_core.slot_mix_scale import measure_work_counts


def test_axes_keep_logical_counts_and_cutoff():
    data = measure_work_counts()
    assert len(data) == 8
    assert {data[f"horizon-{n}"]["value"] for n in (2, 4, 6, 8)} == {"1/2"}
    assert data["horizon-8"]["search_work"] > data["horizon-2"]["search_work"]
    assert data["tapes-8"]["budget16"] == "inconclusive"
