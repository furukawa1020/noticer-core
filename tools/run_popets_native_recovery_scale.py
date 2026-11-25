"""Profile native synthesis and independent checks while varying one model axis."""

import argparse
import json
import subprocess
from pathlib import Path
from time import perf_counter_ns

from noticer_core.evaluation.aqrs_oracle import check_path
from noticer_core.recovery_verdict import resolve_checkers

SCOPES = ((2, 2), (4, 2), (8, 2), (2, 4), (2, 8))


def execute(command: list[str]) -> dict:
    result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=45)
    return json.loads(result.stdout)


def profile(
    generator: Path, checker: Path, output: Path, *, repetitions: int = 3
) -> list[dict]:
    rows = []
    for services, horizon in SCOPES:
        for sample in range(repetitions):
            native = execute([
                str(generator.resolve()), "--strict-deadline", "--services", str(services),
                "--horizon", str(horizon), "--timing",
            ])
            if native["scope"] != {"services": services, "horizon": horizon}:
                raise ValueError("native scope differs from the profile request")
            row = {
                "services": services,
                "horizon": horizon,
                "sample": sample,
                "synthesis_status": native["synthesis_status"],
                "synthesis_ns": native["synthesis_ns"],
                "rust_verifier_wall_ns_including_startup": None,
                "python_checker_ns": None,
                "states": None,
                "candidates": native.get("candidates"),
                "independent_resolution": None,
            }
            if row["synthesis_status"] == "realizable":
                synthesized = native["cases"]["synthesized"]
                file = output / f"s{services}-h{horizon}-r{sample}.model.json"
                with file.open("x", encoding="utf-8") as stream:
                    json.dump(synthesized["checker_model"], stream, separators=(",", ":"))
                started = perf_counter_ns()
                python_report = check_path(file).as_report(engine="python")
                row["python_checker_ns"] = perf_counter_ns() - started
                started = perf_counter_ns()
                rust_report = execute([str(checker.resolve()), "--input", str(file.resolve())])
                row["rust_verifier_wall_ns_including_startup"] = perf_counter_ns() - started
                row["states"] = synthesized["state_count"]
                row["candidates"] = native["synthesis"]["candidates"]
                row["independent_resolution"] = resolve_checkers(python_report, rust_report).value
            rows.append(row)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("generator", type=Path)
    parser.add_argument("checker", type=Path)
    parser.add_argument("out", type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    report = {
        "schema": "noticer.k22.native-scope-profile.v1",
        "evidence": "bounded synthetic model; one batch may carry several authorized actions",
        "results": profile(args.generator, args.checker, args.out),
    }
    with (args.out / "summary.json").open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    for services, horizon in SCOPES:
        states = [(row["states"], row["independent_resolution"])
                  for row in report["results"]
                  if (row["services"], row["horizon"]) == (services, horizon)]
        print(f"services={services}, horizon={horizon}: {states}")


if __name__ == "__main__":
    main()
