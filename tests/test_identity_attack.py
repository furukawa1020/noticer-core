import math

from noticer_core.attacks.identity import run_identity_attack
from noticer_core.data.synthetic import SyntheticConfig, generate_identity_dataset
from noticer_core.evaluation.splits import session_disjoint_split


def test_primary_beats_permuted_control() -> None:
    # Engineering smoke thresholds, not publication privacy thresholds.
    dataset = generate_identity_dataset(SyntheticConfig(8, 3, 30, 12, 3, 3, .3, .4, 1), seed=42)
    split = session_disjoint_split(dataset, seed=42)
    kwargs = {"regularization_candidates": [.1, 1, 10], "max_iter": 1000}
    primary = run_identity_attack(dataset, split, seed=42, **kwargs)
    control = run_identity_attack(dataset, split, seed=1042, permute_labels=True, **kwargs)
    assert primary.metrics["balanced_accuracy"] > .70
    assert control.metrics["balanced_accuracy"] < .25
    assert primary.metrics["balanced_accuracy"] - control.metrics["balanced_accuracy"] > .40
    assert len(primary.predictions) == len(split.test_indices)
    assert all(math.isfinite(value) for value in primary.metrics.values())
