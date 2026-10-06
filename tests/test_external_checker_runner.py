from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from scripts.run_pinned_external_checker import (
    EXPECTED_POLICY,
    ExternalCheckerError,
    execute_checker,
    load_lock,
    resolve_pinned_binary,
)

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "formal" / "aqrs" / "external_checker_lock.json"


def _checker(tmp_path: Path, body: str) -> list[str]:
    script = tmp_path / "checker.py"
    script.write_text(body, encoding="utf-8")
    return [sys.executable, str(script)]


def test_lock_pins_lean_exporter_checker_and_fail_closed_policy() -> None:
    lock = load_lock(LOCK)

    assert lock.lean_toolchain == "leanprover/lean4:v4.30.0"
    assert len(lock.exporter.revision) == 40
    assert len(lock.checker.revision) == 40
    assert lock.policy == EXPECTED_POLICY
    assert lock.policy["unpermitted_axiom_hard_error"] is True
    assert lock.policy["unsafe_permit_all_axioms"] is False


def test_policy_or_promotion_tamper_is_rejected(tmp_path: Path) -> None:
    value = json.loads(LOCK.read_text(encoding="utf-8"))
    value["policy"]["unsafe_permit_all_axioms"] = True
    altered = tmp_path / "lock.json"
    altered.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ExternalCheckerError, match="fail-closed policy"):
        load_lock(altered)

    value = json.loads(LOCK.read_text(encoding="utf-8"))
    value["verification_status"] = "VERIFIED"
    altered.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ExternalCheckerError, match="before a green"):
        load_lock(altered)


def test_revision_and_binary_must_match_pin(tmp_path: Path) -> None:
    lock = load_lock(LOCK)
    checkout = tmp_path / "checker"
    binary = checkout.joinpath(*lock.checker.binary.parts)
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"checker")

    with pytest.raises(ExternalCheckerError, match="revision mismatch"):
        resolve_pinned_binary(lock.checker, checkout, lambda _: "0" * 40)
    assert resolve_pinned_binary(
        lock.checker, checkout, lambda _: lock.checker.revision
    ).is_absolute()


def test_checker_accepts_only_zero_exit_and_receives_exact_policy(tmp_path: Path) -> None:
    export = tmp_path / "aqrs.ndjson"
    export.write_text('{"kind":"fixture"}\n', encoding="utf-8")
    command = _checker(
        tmp_path,
        "import json,sys\n"
        "policy=json.load(open(sys.argv[1], encoding='utf-8'))\n"
        "assert policy['unpermitted_axiom_hard_error'] is True\n"
        "assert policy['unsafe_permit_all_axioms'] is False\n"
        "assert sys.stdin.buffer.read()\n",
    )

    result = execute_checker(command, export, EXPECTED_POLICY, 5)
    assert result.status == "VERIFIED"
    assert result.return_code == 0


def test_rejection_timeout_and_excessive_diagnostics_fail_closed(tmp_path: Path) -> None:
    export = tmp_path / "aqrs.ndjson"
    export.write_text("fixture\n", encoding="utf-8")

    with pytest.raises(ExternalCheckerError, match="code 7"):
        execute_checker(_checker(tmp_path, "import sys\nsys.exit(7)\n"), export, EXPECTED_POLICY, 5)
    with pytest.raises(ExternalCheckerError, match="timed out"):
        execute_checker(
            _checker(tmp_path, "import time\ntime.sleep(2)\n"),
            export,
            EXPECTED_POLICY,
            1,
        )
    with pytest.raises(ExternalCheckerError, match="diagnostic output"):
        execute_checker(
            _checker(tmp_path, "print('x' * 1048577)\n"), export, EXPECTED_POLICY, 5
        )
