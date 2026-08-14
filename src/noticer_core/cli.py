"""Reproducible privacy attack CLI."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import yaml

from noticer_core.attacks.aetp import AetpAttackResult, run_aetp_attack
from noticer_core.attacks.identity import AttackResult, run_identity_attack
from noticer_core.data.aetp_synthetic import AetpSyntheticConfig, generate_aetp_dataset
from noticer_core.data.synthetic import SyntheticConfig, generate_identity_dataset
from noticer_core.evaluation.provenance_attacks import run_provenance_experiment
from noticer_core.evaluation.splits import aetp_session_disjoint_split, session_disjoint_split


def _load(path: Path, required: set[str]) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError(f"configuration file does not exist: {path}")
    with path.open(encoding="utf-8") as handle:
        value = yaml.safe_load(handle)
    if not isinstance(value, dict):
        raise ValueError("configuration root must be a mapping")
    if missing := required - value.keys():
        raise ValueError(f"configuration is missing sections: {sorted(missing)}")
    if value["attack"].get("model") != "logistic_regression":
        raise ValueError(f"unsupported attack model: {value['attack'].get('model')!r}")
    return value


def _plot(result: AttackResult, path: Path) -> None:
    figure, axis = plt.subplots(figsize=(7, 6), constrained_layout=True)
    image = axis.imshow(result.confusion)
    axis.set_title("Synthetic Identity Attack (raw counts)")
    axis.set_xlabel("Predicted subject ID")
    axis.set_ylabel("True subject ID")
    axis.set_xticks(range(len(result.labels)), result.labels, rotation=90, fontsize=6)
    axis.set_yticks(range(len(result.labels)), result.labels, fontsize=6)
    figure.colorbar(image, ax=axis)
    figure.savefig(path, dpi=150)
    plt.close(figure)


def run_identity_experiment(config_path: Path, output_dir: Path | None = None) -> dict[str, Any]:
    """Execute the identity smoke protocol and persist its complete artifact contract."""
    config = _load(config_path, {"experiment", "synthetic", "attack", "control", "output"})
    canonical = json.dumps(config, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode()).hexdigest()[:8]
    run_id = f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{digest}"
    root = output_dir or Path(config["experiment"]["artifact_root"]) / run_id
    root.mkdir(parents=True, exist_ok=False)
    seed = int(config["experiment"]["seed"])
    dataset = generate_identity_dataset(SyntheticConfig(**config["synthetic"]), seed=seed)
    split = session_disjoint_split(dataset, seed=seed)
    attack = config["attack"]
    common = {
        "regularization_candidates": [
            float(value) for value in attack["regularization_candidates"]
        ],
        "max_iter": int(attack["max_iter"]),
    }
    primary = run_identity_attack(dataset, split, seed=seed, **common)
    control = run_identity_attack(
        dataset,
        split,
        seed=int(config["control"]["permutation_seed"]),
        permute_labels=True,
        **common,
    )
    summary = {
        "dataset": "synthetic_identity",
        "n_windows": dataset.n_windows,
        "n_features": dataset.n_features,
        "n_subjects": dataset.n_subjects,
        "n_sessions": dataset.n_sessions,
    }
    files = {
        "run_config.json": config,
        "dataset_summary.json": summary,
        "primary_metrics.json": primary.metrics,
        "control_metrics.json": control.metrics,
    }
    for name, payload in files.items():
        (root / name).write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    split.manifest.to_csv(root / "split_manifest.csv", index=False)
    primary.predictions.to_csv(root / "primary_predictions.csv", index=False)
    control.predictions.to_csv(root / "control_predictions.csv", index=False)
    _plot(primary, root / "confusion_matrix.png")
    (root / "run.log").write_text(
        "W2 identity smoke; synthetic results are not scientific privacy evidence.\n",
        encoding="utf-8",
    )
    return {
        "directory": root,
        "summary": summary,
        "primary": primary.metrics,
        "control": control.metrics,
    }


def _plot_aetp(result: AetpAttackResult, path: Path) -> None:
    names = ["claim_only", "aetp", "timing_control", "payload_control", "retry_control"]
    values = [float(result.metrics[name]["roc_auc"]) for name in names]
    figure, axis = plt.subplots(figsize=(9, 5), constrained_layout=True)
    axis.bar(names, values, color=["#6b7280", "#0f766e", "#b45309", "#b91c1c", "#1d4ed8"])
    axis.axhline(0.5, color="black", linestyle="--", linewidth=1)
    axis.set_ylim(0.45, 1.02)
    axis.set_ylabel("Counterfactual distinguishing ROC-AUC")
    axis.set_title("AETP smoke and deliberate leakage controls")
    axis.tick_params(axis="x", rotation=18)
    figure.savefig(path, dpi=150)
    plt.close(figure)


def run_aetp_experiment(config_path: Path, output_dir: Path | None = None) -> dict[str, Any]:
    """Execute the AETP counterfactual attack protocol and persist artifacts."""
    config = _load(config_path, {"experiment", "synthetic", "attack", "criteria", "output"})
    canonical = json.dumps(config, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode()).hexdigest()[:8]
    run_id = f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{digest}"
    root = output_dir or Path(config["experiment"]["artifact_root"]) / run_id
    root.mkdir(parents=True, exist_ok=False)
    seed = int(config["experiment"]["seed"])
    dataset = generate_aetp_dataset(AetpSyntheticConfig(**config["synthetic"]), seed=seed)
    split = aetp_session_disjoint_split(dataset, seed=seed)
    attack = config["attack"]
    criteria = config["criteria"]
    result = run_aetp_attack(
        dataset,
        split,
        regularization_candidates=[float(value) for value in attack["regularization_candidates"]],
        max_iter=int(attack["max_iter"]),
        bootstrap_samples=int(attack["bootstrap_samples"]),
        seed=seed,
        safe_excess_upper_bound=float(criteria["safe_excess_upper_bound"]),
        negative_control_min_auc=float(criteria["negative_control_min_auc"]),
    )
    summary = {
        "dataset": "synthetic_action_equivalent_counterfactual_traces",
        "n_worlds": dataset.n_worlds,
        "n_pairs": dataset.n_pairs,
        "n_sessions": len(set(dataset.session_ids)),
        "n_action_semantics": len(set(dataset.action_ids)),
    }
    for name, payload in {
        "run_config.json": config,
        "dataset_summary.json": summary,
        "aetp_metrics.json": result.metrics,
        "feature_schema.json": {
            "claim_only": dataset.claim_feature_names,
            "full_trace": dataset.trace_feature_names,
        },
    }.items():
        (root / name).write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    split.manifest.to_csv(root / "split_manifest.csv", index=False)
    result.predictions.to_csv(root / "predictions.csv", index=False)
    _plot_aetp(result, root / "attack_auc.png")
    (root / "run.log").write_text(
        "AETP counterfactual implementation smoke; not scientific deployment evidence.\n",
        encoding="utf-8",
    )
    return {"directory": root, "summary": summary, "metrics": result.metrics}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="noticer-core")
    commands = parser.add_subparsers(dest="command", required=True)
    attack = commands.add_parser("attack").add_subparsers(dest="attack", required=True)
    identity = attack.add_parser("identity")
    identity.add_argument("--config", type=Path, required=True)
    identity.add_argument("--output-dir", type=Path)
    aetp = attack.add_parser("aetp")
    aetp.add_argument("--config", type=Path, required=True)
    aetp.add_argument("--output-dir", type=Path)
    provenance = attack.add_parser("provenance")
    provenance.add_argument("--config", type=Path, required=True)
    provenance.add_argument("--output-dir", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run CLI with concise errors and non-zero failure status."""
    try:
        args = build_parser().parse_args(argv)
        if args.attack == "identity":
            result = run_identity_experiment(args.config, args.output_dir)
        elif args.attack == "aetp":
            result = run_aetp_experiment(args.config, args.output_dir)
        else:
            result = run_provenance_experiment(args.config, args.output_dir)
    except (KeyError, TypeError, ValueError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(f"dataset: {result['summary']['dataset']}")
    print("split protocol: session-disjoint train/validation/test")
    if args.attack == "identity":
        print(f"number of subjects: {result['summary']['n_subjects']}")
        print(f"primary balanced accuracy: {result['primary']['balanced_accuracy']:.6f}")
        print(f"control balanced accuracy: {result['control']['balanced_accuracy']:.6f}")
        print(f"chance accuracy: {result['primary']['chance_accuracy']:.6f}")
    elif args.attack == "aetp":
        print(f"counterfactual pairs: {result['summary']['n_pairs']}")
        print(f"AETP ROC-AUC: {result['metrics']['aetp']['roc_auc']:.6f}")
        print(f"AETP excess AUC: {result['metrics']['aetp']['excess_auc']:.6f}")
        print(f"all criteria passed: {result['metrics']['protocol']['all_criteria_passed']}")
    else:
        print(f"counterfactual pairs: {result['summary']['n_pairs']}")
        print(f"leaky baselines passing: {result['criteria']['leaky_baselines_passing']}")
        print(f"AEPA maximum upper CI: {result['criteria']['aepa_max_auc_ci_high']:.6f}")
        print(f"unauthorized actions: {result['criteria']['unauthorized_action_count']}")
        print(f"all criteria passed: {result['criteria']['all_criteria_passed']}")
    print(f"artifact directory: {result['directory']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
