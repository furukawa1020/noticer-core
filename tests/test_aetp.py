import numpy as np

from noticer_core.attacks.aetp import run_aetp_attack
from noticer_core.data.aetp_synthetic import AetpSyntheticConfig, generate_aetp_dataset
from noticer_core.evaluation.splits import aetp_session_disjoint_split


def _dataset():
    return generate_aetp_dataset(AetpSyntheticConfig(3, 4, 20, 6, 12, 89, 5), seed=91)


def test_counterfactual_pairs_are_action_equivalent_and_exactly_coupled() -> None:
    dataset = _dataset()
    for pair_id in np.unique(dataset.pair_ids):
        indices = np.flatnonzero(dataset.pair_ids == pair_id)
        assert np.array_equal(
            dataset.claim_features[indices[0]], dataset.claim_features[indices[1]]
        )
        assert np.array_equal(
            dataset.safe_trace_features[indices[0]], dataset.safe_trace_features[indices[1]]
        )


def test_aetp_resists_attacker_while_leaky_controls_are_detected() -> None:
    dataset = _dataset()
    split = aetp_session_disjoint_split(dataset, seed=91)
    result = run_aetp_attack(
        dataset,
        split,
        regularization_candidates=[0.1, 1.0],
        max_iter=500,
        bootstrap_samples=100,
        seed=91,
        safe_excess_upper_bound=0.02,
        negative_control_min_auc=0.95,
    )
    assert result.metrics["aetp"]["roc_auc"] == 0.5
    assert result.metrics["aetp"]["excess_auc_ci95_upper"] == 0.0
    assert result.metrics["protocol"]["all_criteria_passed"] is True
    for control in ("timing_control", "payload_control", "retry_control"):
        assert result.metrics[control]["roc_auc"] >= 0.95


def test_aetp_split_is_session_disjoint() -> None:
    split = aetp_session_disjoint_split(_dataset(), seed=7)
    sessions = [
        set(split.manifest.loc[split.manifest["split"] == name, "session_id"])
        for name in ("train", "validation", "test")
    ]
    assert sessions[0].isdisjoint(sessions[1])
    assert sessions[0].isdisjoint(sessions[2])
    assert sessions[1].isdisjoint(sessions[2])
