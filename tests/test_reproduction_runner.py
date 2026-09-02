from __future__ import annotations

import json
from pathlib import Path

import pytest

from noticer_core.replication.runner import (
    MAX_LOG_BYTES,
    ReproductionError,
    _redact_and_bound,
    build_dry_run_report,
    derive_run_verdict,
    load_plan,
    select_steps,
)

ROOT = Path(__file__).resolve().parents[1]
PLAN = ROOT / "replication" / "reproduction_plan_v1.json"
MANIFEST_SPEC = ROOT / "replication" / "manifest_spec_v1.json"


def test_profiles_form_a_deterministic_prefix_closed_graph() -> None:
    plan = load_plan(PLAN)
    smoke = select_steps(plan, "smoke")
    core = select_steps(plan, "core")
    full = select_steps(plan, "full")

    assert [step["id"] for step in smoke] == [
        "manifest",
        "python_smoke",
        "rust_contract_smoke",
        "studio_evidence_smoke",
    ]
    assert {step["id"] for step in smoke} < {step["id"] for step in core}
    assert {step["id"] for step in core} < {step["id"] for step in full}
    for steps in (smoke, core, full):
        seen: set[str] = set()
        for step in steps:
            assert set(step["depends_on"]) <= seen
            seen.add(step["id"])


def test_dry_run_invokes_no_external_commands_and_is_deterministic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("dry-run invoked subprocess")

    monkeypatch.setattr("subprocess.run", forbidden)
    first = build_dry_run_report(ROOT, PLAN, MANIFEST_SPEC, "smoke")
    second = build_dry_run_report(ROOT, PLAN, MANIFEST_SPEC, "smoke")

    assert first == second
    assert first["verdict"] == "NOT_RUN"
    assert first["source"]["relation"] == "NOT_CHECKED"
    assert all(step["status"] == "NOT_RUN" for step in first["steps"])
    assert len(first["artifact_sha256"]) == 64


def test_plan_has_no_install_network_or_shell_commands() -> None:
    plan = load_plan(PLAN)
    encoded = json.dumps(plan).lower()

    assert "pip install" not in encoded
    assert "npm install" not in encoded
    assert "cargo install" not in encoded
    assert "curl" not in encoded
    assert "wget" not in encoded
    assert plan["offline_environment"] == {
        "CARGO_NET_OFFLINE": "true",
        "PIP_NO_INDEX": "1",
        "NPM_CONFIG_OFFLINE": "true",
    }


def test_unknown_fields_and_shell_control_tokens_fail_closed(tmp_path: Path) -> None:
    plan = json.loads(PLAN.read_text(encoding="utf-8"))
    plan["unexpected"] = True
    malformed = tmp_path / "unknown.json"
    malformed.write_text(json.dumps(plan), encoding="utf-8")
    with pytest.raises(ReproductionError, match="fields mismatch"):
        load_plan(malformed)

    plan.pop("unexpected")
    plan["steps"][0]["command"] = ["cargo", "test", "&&", "curl"]
    shell = tmp_path / "shell.json"
    shell.write_text(json.dumps(plan), encoding="utf-8")
    with pytest.raises(ReproductionError, match="network or install|shell control"):
        load_plan(shell)


def test_verdict_derivation_never_promotes_missing_or_nonpass_evidence() -> None:
    assert derive_run_verdict(["PASS"], "DESCENDANT_OF_BASELINE", False, dry_run=False) == "PASS"
    assert derive_run_verdict(["FAIL"], "DESCENDANT_OF_BASELINE", False, dry_run=False) == "FAIL"
    assert derive_run_verdict(["TIMEOUT"], "DESCENDANT_OF_BASELINE", False, dry_run=False) == "FAIL"
    assert (
        derive_run_verdict(["MISSING_TOOL"], "DESCENDANT_OF_BASELINE", False, dry_run=False)
        == "INCONCLUSIVE"
    )
    assert derive_run_verdict(["PASS"], "NOT_DESCENDANT", False, dry_run=False) == "FAIL"
    assert (
        derive_run_verdict(["PASS"], "DESCENDANT_OF_BASELINE", True, dry_run=False)
        == "INCONCLUSIVE"
    )
    assert derive_run_verdict(["NOT_RUN"], "NOT_CHECKED", None, dry_run=True) == "NOT_RUN"


def test_logs_redact_local_paths_and_enforce_byte_bound() -> None:
    value = f"root={ROOT}\nhome={Path.home()}\n" + "x" * (MAX_LOG_BYTES + 10)
    encoded, truncated = _redact_and_bound(value, ROOT)

    assert truncated is True
    assert len(encoded) == MAX_LOG_BYTES
    assert str(ROOT).encode() not in encoded
    assert str(Path.home()).encode() not in encoded
    assert b"<REPOSITORY_ROOT>" in encoded
    assert b"<HOME>" in encoded


def test_higher_profile_dependency_and_path_escape_are_rejected(tmp_path: Path) -> None:
    value = json.loads(PLAN.read_text(encoding="utf-8"))
    value["steps"][0]["cwd"] = "../outside"
    escaped = tmp_path / "escaped.json"
    escaped.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ReproductionError, match="not canonical"):
        load_plan(escaped)

    value = json.loads(PLAN.read_text(encoding="utf-8"))
    value["steps"][1]["minimum_profile"] = "smoke"
    value["steps"][1]["depends_on"] = ["manifest", "workspace_full"]
    invalid_dependency = tmp_path / "dependency.json"
    invalid_dependency.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ReproductionError, match="earlier step"):
        load_plan(invalid_dependency)
