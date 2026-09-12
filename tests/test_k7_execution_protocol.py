from __future__ import annotations

import json
from collections import Counter
from copy import deepcopy
from pathlib import Path

import pytest
import yaml

from noticer_core.evaluation.execution_protocol import (
    RETENTION,
    ROOT_FIELDS,
    ExecutionProtocolError,
    LedgerState,
    RunPhase,
    assert_protocol_transition,
    execution_protocol_sha256,
    load_execution_protocol,
)

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_PATH = ROOT / "configs" / "quotient_forge" / "k7_execution_protocol_v1.yaml"
SCHEMA_PATH = ROOT / "schemas" / "k7_execution_protocol_v1.schema.json"


def _write(tmp_path: Path, document: object) -> Path:
    path = tmp_path / "protocol.yaml"
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return path


def test_schedule_is_deterministic_complete_and_single_attempt() -> None:
    first = load_execution_protocol(PROTOCOL_PATH, repository_root=ROOT)
    second = load_execution_protocol(PROTOCOL_PATH, repository_root=ROOT)
    assert first.schedule == second.schedule
    assert execution_protocol_sha256(first) == execution_protocol_sha256(second)
    assert len(first.schedule) == 92 * (2 + 5) == 644
    assert len({run.run_id for run in first.schedule}) == 644
    assert all(run.attempt == 1 for run in first.schedule)
    assert all(0 <= run.seed < 2**64 for run in first.schedule)
    warmup = Counter(run.case_id for run in first.schedule if run.phase is RunPhase.WARMUP)
    measured = Counter(run.case_id for run in first.schedule if run.phase is RunPhase.MEASURED)
    assert set(warmup.values()) == {2}
    assert set(measured.values()) == {5}


def test_backend_positions_are_balanced_without_adaptive_reordering() -> None:
    protocol = load_execution_protocol(PROTOCOL_PATH, repository_root=ROOT)
    positions: dict[tuple[str, str], Counter[int]] = {}
    for run in protocol.schedule:
        if run.phase is not RunPhase.MEASURED:
            continue
        positions.setdefault((run.profile, run.backend_id), Counter())[run.backend_position] += 1
    assert positions
    for counts in positions.values():
        assert set(counts) == {0, 1, 2, 3}
        assert max(counts.values()) - min(counts.values()) <= 1


def test_failures_and_warmups_cannot_be_silently_discarded() -> None:
    assert RETENTION == {
        "max_attempts_per_run": 1,
        "retain_all_attempts": True,
        "retry_replaces_attempt": False,
        "failed_result_policy": "PRESERVE",
        "missing_result_status": "NOT_RUN",
        "warmup_in_primary_statistics": False,
    }


def test_protocol_change_is_rejected_after_heldout_opening() -> None:
    original = "a" * 64
    changed = "b" * 64
    assert_protocol_transition(original, changed, ledger_state=LedgerState.SEALED)
    assert_protocol_transition(original, original, ledger_state=LedgerState.OPENED)
    with pytest.raises(ExecutionProtocolError, match="cannot change"):
        assert_protocol_transition(original, changed, ledger_state=LedgerState.OPENED)


@pytest.mark.parametrize(
    ("section", "field", "replacement", "message"),
    [
        ("randomization", "warmup_repetitions", 0, "randomization protocol differs"),
        ("randomization", "measured_repetitions", 4, "randomization protocol differs"),
        ("randomization", "master_seed", 1, "randomization protocol differs"),
        ("retention", "retry_replaces_attempt", True, "retention protocol differs"),
        ("held_out_policy", "protocol_changes_after_open", "ALLOW", "held-out policy differs"),
    ],
)
def test_post_hoc_protocol_tampering_is_rejected(
    tmp_path: Path, section: str, field: str, replacement: object, message: str
) -> None:
    document = yaml.safe_load(PROTOCOL_PATH.read_text(encoding="utf-8"))
    tampered = deepcopy(document)
    tampered[section][field] = replacement
    with pytest.raises(ExecutionProtocolError, match=message):
        load_execution_protocol(_write(tmp_path, tampered), repository_root=ROOT)


def test_schema_and_runtime_share_the_root_allowlist() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert set(schema["required"]) == ROOT_FIELDS
    assert set(schema["properties"]) == ROOT_FIELDS
    assert schema["additionalProperties"] is False

