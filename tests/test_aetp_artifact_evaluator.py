from pathlib import Path

import pandas as pd

from experiments.aetp.evaluate_attacks import _group_split


def test_pair_group_split_never_leaks_across_partitions(tmp_path: Path) -> None:
    groups = pd.Series([f"pair_{index:03d}" for index in range(100) for _ in range(2)])
    split = _group_split(groups)
    frame = pd.DataFrame({"group": groups, "split": split})
    assert frame.groupby("group")["split"].nunique().max() == 1
