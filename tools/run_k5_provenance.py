"""Run the public, synthetic K5 Tier A provenance pipeline."""

from __future__ import annotations

import argparse
import json
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

FORBIDDEN_PUBLIC_KEYS = frozenset(
    {
        "raw_ppg",
        "ppg_samples",
        "raw_acc",
        "acc_samples",
        "baseline_values",
        "private_history",
        "device_id",
        "attestation_chain",
        "permit_signature",
        "lease_bytes",
        "token_bytes",
        "key_material",
    }
)


@dataclass(frozen=True)
class ConfigBundle:
    synthetic: dict[str, Any]
    polar: dict[str, Any]
    policy: dict[str, Any]
    hardware: dict[str, Any]


@dataclass(frozen=True)
class GateResult:
    gate_id: str
    passed: bool


def load_yaml_mapping(path: Path) -> dict[str, Any]:
    """Load one UTF-8 YAML mapping without accepting a scalar root."""
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Config root must be a mapping: {path}")
    return value


def load_config_bundle(config_root: Path) -> ConfigBundle:
    """Load and validate the four committed K5 configuration contracts."""
    bundle = ConfigBundle(
        synthetic=load_yaml_mapping(config_root / "synthetic.yaml"),
        polar=load_yaml_mapping(config_root / "polar.yaml"),
        policy=load_yaml_mapping(config_root / "policy.yaml"),
        hardware=load_yaml_mapping(config_root / "hardware.example.yaml"),
    )
    expected = {
        bundle.synthetic.get("schema"): "noticer-k5-synthetic-v1",
        bundle.polar.get("schema"): "noticer-k5-polar-profile-v1",
        bundle.policy.get("schema"): "noticer-k5-policy-v1",
        bundle.hardware.get("schema"): "noticer-k5-hardware-example-v1",
    }
    if any(actual != required for actual, required in expected.items()):
        raise ValueError("K5 config schema mismatch")
    if bundle.polar.get("sdk_version") != "8.1.0":
        raise ValueError("Polar SDK must remain pinned to 8.1.0")
    if bundle.polar.get("hardware_status") != "NOT_VERIFIED":
        raise ValueError("Committed Polar config cannot claim hardware verification")
    for tier in ("tier_b", "tier_c", "tier_d"):
        if bundle.hardware.get(tier) != "NOT_VERIFIED":
            raise ValueError(f"{tier} must remain NOT_VERIFIED in the example config")
    return bundle


def find_private_fields(value: Any, path: str = "$") -> list[str]:
    """Return exact forbidden-key paths from a proposed public artifact."""
    found: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if key in FORBIDDEN_PUBLIC_KEYS:
                found.append(child_path)
            found.extend(find_private_fields(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(find_private_fields(child, f"{path}[{index}]"))
    return found


def validate_public_artifact(path: Path) -> dict[str, Any]:
    """Validate public schema essentials and reject private fields."""
    artifact = json.loads(path.read_text(encoding="utf-8"))
    if artifact.get("schema") != "noticer-k5-tier-a-public-v1":
        raise ValueError("Unexpected K5 public artifact schema")
    private_paths = find_private_fields(artifact)
    if private_paths or artifact.get("private_field_count") != 0:
        raise ValueError(f"Private fields found in public artifact: {private_paths}")
    if artifact.get("decision") != "GO_TIER_A":
        raise ValueError("Tier A decision is not GO_TIER_A")
    tiers = artifact.get("hardware_tiers", [])
    if len(tiers) != 3 or any(tier.get("status") != "NOT_VERIFIED" for tier in tiers):
        raise ValueError("Hardware tiers B-D must remain NOT_VERIFIED")
    return artifact


def run_command(command: Sequence[str], repo_root: Path) -> None:
    """Run one fixed command and surface its diagnostics without artifact capture."""
    completed = subprocess.run(
        list(command),
        cwd=repo_root,
        check=False,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
    )
    if completed.stdout:
        print(completed.stdout, end="")
    if completed.returncode != 0:
        if completed.stderr:
            print(completed.stderr, end="")
        raise RuntimeError(f"Command failed: {command[0]} gate")


def run_gate(gate_id: str, command: Sequence[str], repo_root: Path) -> GateResult:
    """Run one software gate and return only its public pass/fail state."""
    try:
        run_command(command, repo_root)
    except RuntimeError:
        return GateResult(gate_id=gate_id, passed=False)
    return GateResult(gate_id=gate_id, passed=True)


def write_gate_manifest(results: Sequence[GateResult], path: Path) -> None:
    """Write a deterministic public manifest without commands or test output."""
    payload = {
        "schema": "noticer-k5-software-gates-v1",
        "all_passed": all(result.passed for result in results),
        "gates": [
            {"id": result.gate_id, "status": "PASSED" if result.passed else "FAILED"}
            for result in results
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def run_pipeline(repo_root: Path, config_root: Path, output: Path, seed: int) -> Path:
    """Execute the synthetic Tier A pipeline and return its public summary path."""
    bundle = load_config_bundle(config_root)
    if bundle.synthetic.get("seed") != seed:
        raise ValueError("CLI seed must match committed synthetic config")
    output.mkdir(parents=True, exist_ok=True)
    provenance_output = output / "provenance"
    k4_output = output / "k4"
    gate_manifest = output / "software_gates.json"

    gates = [
        run_gate(
            "synthetic_acquisition",
            ["cargo", "test", "--quiet", "-p", "noticer-acquisition-core"],
            repo_root,
        ),
        run_gate(
            "k1_evidence_bridge",
            ["cargo", "test", "--quiet", "-p", "noticer-evidence-bridge"],
            repo_root,
        ),
        run_gate(
            "npl1_appraiser",
            ["cargo", "test", "--quiet", "-p", "noticer-provenance-verifier"],
            repo_root,
        ),
        run_gate(
            "production_lease_guard",
            [
                "cargo",
                "test",
                "--quiet",
                "-p",
                "noticer-token",
                "--test",
                "production_lease_guard",
            ],
            repo_root,
        ),
    ]
    write_gate_manifest(gates, gate_manifest)
    if not all(gate.passed for gate in gates):
        raise RuntimeError("One or more K5 software gates failed")

    run_command(
        [
            "cargo",
            "run",
            "--quiet",
            "-p",
            "noticer-provenance-sim",
            "--",
            "--seed",
            str(seed),
            "--output",
            str(provenance_output),
        ],
        repo_root,
    )
    run_command(
        [
            "cargo",
            "run",
            "--quiet",
            "-p",
            "noticer-k4-demo",
            "--",
            "--config",
            str(repo_root / "configs" / "k4" / "ble_menfugu.toml"),
            "--output",
            str(k4_output),
        ],
        repo_root,
    )
    run_command(
        [
            "cargo",
            "run",
            "--quiet",
            "-p",
            "noticer-k5-demo",
            "--",
            "--provenance-summary",
            str(provenance_output / "summary.json"),
            "--k4-summary",
            str(k4_output / "summary.json"),
            "--software-gates",
            str(gate_manifest),
            "--output",
            str(output / "public"),
        ],
        repo_root,
    )
    summary = output / "public" / "summary.json"
    validate_public_artifact(summary)
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config-root", type=Path, default=Path("configs/k5"))
    parser.add_argument("--output", type=Path, default=Path("artifacts/k5/tier_a/latest"))
    parser.add_argument("--seed", type=int, default=20260814)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = Path(__file__).resolve().parents[1]
    config_root = (
        args.config_root if args.config_root.is_absolute() else repo_root / args.config_root
    )
    output = args.output if args.output.is_absolute() else repo_root / args.output
    summary = run_pipeline(repo_root, config_root, output, args.seed)
    artifact = validate_public_artifact(summary)
    print(
        "K5 Tier A complete: "
        f"decision={artifact['decision']}, private_field_count=0, "
        "Tier B-D=NOT_VERIFIED"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
