from __future__ import annotations

import json
from pathlib import Path

import pytest

from noticer_core.replication.k7_bootstrap import (
    K7BootstrapError,
    ProbeResult,
    inspect_environment,
    load_toolchain_lock,
)

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "replication" / "k7_toolchain_lock_v1.json"


def _matching_probe(argv: list[str]) -> ProbeResult:
    outputs = {
        "python": "Python 3.11.14",
        "rustc": "rustc 1.93.0 (254b59607 2026-01-19)",
        "node": "v24.12.0",
        "lean": "Lean (version 4.30.0, x86_64-unknown-linux-gnu)",
        "cvc5": "This is cvc5 version 1.3.4",
        "z3": "Z3 version 4.16.0 - 64 bit",
    }
    return ProbeResult(0, outputs[argv[0]])


def test_repository_pins_and_matching_environment_are_ready() -> None:
    lock = load_toolchain_lock(ROOT, LOCK)
    report = inspect_environment(lock, _matching_probe)

    assert report["overall_status"] == "READY"
    assert report["network_actions"] == "NONE"
    assert len(report["toolchains"]) == 6
    assert all(item["status"] == "MATCH" for item in report["toolchains"])
    assert len(report["report_digest"]) == 64


def test_missing_mismatch_and_error_remain_blocking() -> None:
    lock = load_toolchain_lock(ROOT, LOCK)

    def probe(argv: list[str]) -> ProbeResult:
        if argv[0] == "lean":
            return ProbeResult(127, "")
        if argv[0] == "z3":
            return ProbeResult(0, "Z3 version 4.15.0")
        if argv[0] == "cvc5":
            return ProbeResult(1, "failed")
        return _matching_probe(argv)

    report = inspect_environment(lock, probe)
    statuses = {item["id"]: item["status"] for item in report["toolchains"]}

    assert report["overall_status"] == "BLOCKED"
    assert statuses["lean"] == "MISSING"
    assert statuses["z3"] == "MISMATCH"
    assert statuses["cvc5"] == "ERROR"


def test_missing_repository_marker_fails_before_probing(tmp_path: Path) -> None:
    value = json.loads(LOCK.read_text(encoding="utf-8"))
    value["toolchains"][0]["required_marker"] = "not-present-marker"
    altered = tmp_path / "lock.json"
    altered.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(K7BootstrapError, match="pin marker"):
        load_toolchain_lock(ROOT, altered)


def test_absolute_source_and_private_marker_fail_closed(tmp_path: Path) -> None:
    value = json.loads(LOCK.read_text(encoding="utf-8"))
    value["toolchains"][0]["source"] = "C:\\Users\\researcher\\pyproject.toml"
    altered = tmp_path / "lock.json"
    altered.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(K7BootstrapError, match="absolute"):
        load_toolchain_lock(ROOT, altered)

    value = json.loads(LOCK.read_text(encoding="utf-8"))
    value["toolchains"][0]["version"] = "secret-version"
    altered.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(K7BootstrapError, match="private marker"):
        load_toolchain_lock(ROOT, altered)
