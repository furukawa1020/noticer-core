from __future__ import annotations

from pathlib import Path

import pytest

from noticer_core.evaluation.production_bindings import (
    BACKEND_IDS,
    ProductionBindingError,
    build_production_run_lock,
    load_production_bindings,
)

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "configs" / "quotient_forge" / "k7_production_bindings_v1.yaml"


def values(tmp_path: Path) -> dict[str, object]:
    return {
        "case_id": "case-001",
        "solver": "z3",
        "solver_root": tmp_path,
        "solver_matrix": ROOT / "configs/quotient_forge/solver_matrix_v1.json",
        "expected_binary_sha256": "0" * 64,
        "solver_manifest": ROOT / "configs/quotient_forge/qbf_solver_manifest_v1.json",
        "install_receipt": tmp_path / "install.json",
        "plant_states": 4,
        "machine_states": 2,
        "horizon": 2,
        "observers": 1,
        "fault_states": 0,
        "output_alphabet": 3,
        "quotient_classes": 1,
        "seed": 1729,
        "candidate_limit": 64,
        "time_limit_ms": 2000,
        "output_path": tmp_path / "result.json",
        "platform": "linux-x86_64",
    }


def executables(tmp_path: Path) -> dict[str, Path]:
    result = {}
    for backend_id in BACKEND_IDS:
        path = tmp_path / f"quotient-forge-{backend_id}"
        path.write_bytes(f"production-{backend_id}".encode())
        result[backend_id] = path
    return result


def test_repository_registry_materializes_four_digest_bound_commands(
    tmp_path: Path,
) -> None:
    registry = load_production_bindings(ROOT, REGISTRY)
    commands = {
        backend_id: registry.command(
            backend_id,
            executable,
            values(tmp_path),
        )
        for backend_id, executable in executables(tmp_path).items()
    }
    lock = build_production_run_lock(registry, commands, "linux-ci")

    assert tuple(registry.bindings) == BACKEND_IDS
    assert set(lock["backends"]) == set(BACKEND_IDS)
    assert len(lock["run_lock_sha256"]) == 64
    assert all("{" not in argument for command in commands.values() for argument in command.argv)


def test_fixture_named_executable_is_rejected(tmp_path: Path) -> None:
    registry = load_production_bindings(ROOT, REGISTRY)
    executable = tmp_path / "reference-fixture-helper"
    executable.write_bytes(b"not production")

    with pytest.raises(ProductionBindingError, match="forbidden"):
        registry.command("reference", executable, values(tmp_path))


def test_run_lock_changes_with_executable_bytes(tmp_path: Path) -> None:
    registry = load_production_bindings(ROOT, REGISTRY)
    paths = executables(tmp_path)

    def lock_digest() -> str:
        commands = {
            backend_id: registry.command(backend_id, path, values(tmp_path))
            for backend_id, path in paths.items()
        }
        return str(build_production_run_lock(registry, commands, "linux-ci")["run_lock_sha256"])

    before = lock_digest()
    paths["cegis"].write_bytes(b"changed-production-cegis")
    assert lock_digest() != before
