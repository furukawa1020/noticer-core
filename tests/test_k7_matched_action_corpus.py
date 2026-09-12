from __future__ import annotations

from dataclasses import replace

import pytest

from noticer_core.evaluation.matched_action_corpus import (
    CorpusContractError,
    MatchedActionTraceRow,
    Split,
    SplitPolicy,
    split_matched_action_corpus,
)

FAMILIES = {
    "early_vs_late_evidence": Split.TRAIN,
    "smooth_vs_spiky_signal": Split.TRAIN,
    "different_baseline": Split.TRAIN,
    "different_noise_path": Split.DEVELOPMENT,
    "different_subject": Split.TEST,
    "different_session": Split.TEST,
}


def policy() -> SplitPolicy:
    return SplitPolicy(
        family_split=FAMILIES,
        heldout_schedule_variants=frozenset({"schedule_unseen_cadence"}),
        heldout_fault_variants=frozenset({"fault_unseen_burst"}),
    )


def corpus() -> list[MatchedActionTraceRow]:
    rows = []
    for index, family in enumerate(FAMILIES):
        is_test = FAMILIES[family] is Split.TEST
        for side in ("left", "right"):
            rows.append(
                MatchedActionTraceRow(
                    pair_id=f"pair-{index}",
                    family_id=family,
                    session_id=f"session-{index}-{side}",
                    side=side,
                    action_semantics_sha256=f"{index + 1:064x}",
                    runtime_capture_sha256=f"{index + (side == 'right') + 20:064x}",
                    schedule_variant=(
                        "schedule_unseen_cadence" if is_test else "schedule_calibration"
                    ),
                    fault_variant=(
                        "fault_unseen_burst" if is_test else "fault_calibration"
                    ),
                )
            )
    return rows


def test_three_disjoint_splits_preserve_matched_pairs() -> None:
    splits = split_matched_action_corpus(corpus(), policy())

    assert all(splits[split] for split in Split)
    for field in ("pair_id", "family_id", "session_id"):
        values = [
            {getattr(row, field) for row in splits[split]}
            for split in Split
        ]
        assert values[0].isdisjoint(values[1])
        assert values[0].isdisjoint(values[2])
        assert values[1].isdisjoint(values[2])


def test_random_row_split_cannot_break_a_pair() -> None:
    rows = corpus()
    rows[1] = replace(rows[1], family_id="different_noise_path")
    with pytest.raises(CorpusContractError, match="pair family mismatch"):
        split_matched_action_corpus(rows, policy())


def test_heldout_variant_cannot_enter_training() -> None:
    rows = corpus()
    rows[0] = replace(rows[0], schedule_variant="schedule_unseen_cadence")
    with pytest.raises(CorpusContractError, match="escaped"):
        split_matched_action_corpus(rows, policy())


def test_non_runtime_source_and_action_mismatch_fail_closed() -> None:
    rows = corpus()
    rows[0] = replace(rows[0], source="copied_synthetic_features")
    with pytest.raises(CorpusContractError, match="source"):
        split_matched_action_corpus(rows, policy())

    rows = corpus()
    rows[1] = replace(rows[1], action_semantics_sha256="f" * 64)
    with pytest.raises(CorpusContractError, match="not action-matched"):
        split_matched_action_corpus(rows, policy())
