"""Assert the contract of the dedicated synthetic checked-recovery fixture."""

import argparse
import json
from pathlib import Path


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def check_fixture(strict: dict, cutoff: dict) -> None:
    results = strict["results"]
    require(set(results) == {"synthesized", "handwritten", "always_wait"}, "wrong roster")
    for name in ("synthesized", "handwritten"):
        row = results[name]
        require(row["independent_check"]["resolution"] == "verified", "checker mismatch")
        require(row["authorized_exactly_once_on_time"] == 8, "deadline count mismatch")
        require(row["all_receives_match_checked_model"], "receipt replay diverged")
        for case in row["cases"].values():
            for side in ("early", "late"):
                require(case[side]["log_audit"] == "match", "receipt audit was not clean")
                require(len(case[side]["replay_binding"]["digest"]) == 64, "binding absent")
    waiter = results["always_wait"]["independent_check"]
    require(waiter["resolution"] == "counterexample", "deadline counterexample missing")
    require(waiter["rust"]["slot"] == 0, "counterexample is not the first deadline slot")
    require(cutoff["synthesis_status"] == "inconclusive", "cutoff misclassified")
    require(not cutoff["results"], "unqualified replay results were reported")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("strict", type=Path)
    parser.add_argument("cutoff", type=Path)
    args = parser.parse_args()
    check_fixture(
        json.loads(args.strict.read_text(encoding="utf-8")),
        json.loads(args.cutoff.read_text(encoding="utf-8")),
    )


if __name__ == "__main__":
    main()
