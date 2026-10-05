from __future__ import annotations

import json
from pathlib import Path

from noticer_core.replication.k7_package import load_contract
from noticer_core.replication.k7_runner import Execution, run_package

CONTRACT = Path("replication/k7_package_contract_v1.json")


def _root(tmp_path: Path) -> Path:
    value = json.loads(CONTRACT.read_text(encoding="utf-8"))
    root = tmp_path / "repo"
    root.mkdir()
    for task in value["tasks"]:
        for relative in task["inputs"]:
            if not relative.startswith("artifacts/"):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(relative, encoding="utf-8")
    contract_path = root / "contract.json"
    contract_path.write_text(json.dumps(value), encoding="utf-8")
    return root


def _pass(task: dict[str, object], root: Path) -> Execution:
    del root
    payload = str(task["id"]).encode()
    import hashlib

    return Execution("PASS", "COMPLETED", 0, len(payload), hashlib.sha256(payload).hexdigest())


def test_runner_executes_topological_dag_and_writes_typed_results(tmp_path: Path) -> None:
    root = _root(tmp_path)
    contract = load_contract(root / "contract.json")

    log = run_package(root, contract, environment_status="READY", executor=_pass)

    assert log["overall_status"] == "PASS"
    assert [item["result"]["task_id"] for item in log["tasks"]] == [
        task["id"] for task in contract["tasks"]
    ]
    assert all(item["result"]["status"] == "PASS" for item in log["tasks"])
    assert all((root / task["outputs"][0]).is_file() for task in contract["tasks"])


def test_failure_blocks_all_dependent_tasks_without_execution(tmp_path: Path) -> None:
    root = _root(tmp_path)
    contract = load_contract(root / "contract.json")
    called: list[str] = []

    def fail_first(task: dict[str, object], root: Path) -> Execution:
        del root
        called.append(str(task["id"]))
        return Execution("FAILED", "NONZERO_EXIT", 7, 0, "0" * 64)

    log = run_package(root, contract, environment_status="READY", executor=fail_first)

    assert called == ["frozen-contract"]
    assert log["tasks"][0]["result"]["status"] == "FAILED"
    assert all(item["result"]["status"] == "BLOCKED" for item in log["tasks"][1:])
    assert all(
        item["result"]["reason"] == "DEPENDENCY_FAILED" for item in log["tasks"][1:]
    )


def test_blocked_environment_never_invokes_executor(tmp_path: Path) -> None:
    root = _root(tmp_path)
    contract = load_contract(root / "contract.json")

    def forbidden(task: dict[str, object], root: Path) -> Execution:
        raise AssertionError((task, root))

    log = run_package(root, contract, environment_status="BLOCKED", executor=forbidden)

    assert log["overall_status"] == "FAILED"
    assert all(item["result"]["status"] == "BLOCKED" for item in log["tasks"])
    assert log["tasks"][0]["result"]["reason"] == "ENVIRONMENT_BLOCKED"


def test_resume_reuses_only_digest_valid_results(tmp_path: Path) -> None:
    root = _root(tmp_path)
    contract = load_contract(root / "contract.json")
    run_package(root, contract, environment_status="READY", executor=_pass)

    def forbidden(task: dict[str, object], root: Path) -> Execution:
        raise AssertionError((task, root))

    resumed = run_package(root, contract, environment_status="READY", executor=forbidden)
    assert all(item["reused"] for item in resumed["tasks"])

    source = root / contract["tasks"][0]["inputs"][0]
    source.write_text("changed", encoding="utf-8")
    calls: list[str] = []

    def recording(task: dict[str, object], root: Path) -> Execution:
        calls.append(str(task["id"]))
        return _pass(task, root)

    rerun = run_package(root, contract, environment_status="READY", executor=recording)
    assert calls == [task["id"] for task in contract["tasks"]]
    assert not any(item["reused"] for item in rerun["tasks"])


def test_missing_input_is_unavailable_not_pass(tmp_path: Path) -> None:
    root = _root(tmp_path)
    contract = load_contract(root / "contract.json")
    (root / contract["tasks"][0]["inputs"][0]).unlink()

    log = run_package(root, contract, environment_status="READY", executor=_pass)

    assert log["tasks"][0]["result"]["status"] == "UNAVAILABLE"
    assert log["tasks"][0]["result"]["reason"] == "INPUT_MISSING"
    assert log["overall_status"] == "FAILED"
