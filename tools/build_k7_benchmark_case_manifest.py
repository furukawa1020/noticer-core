"""Validate one K7 AQRS case and emit its public canonical manifest."""

from __future__ import annotations

import argparse
from pathlib import Path

from noticer_core.evaluation.benchmark_case import (
    benchmark_case_sha256,
    load_benchmark_case,
    verify_aqrs_source_binding,
    write_benchmark_case_manifest,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", type=Path, help="AQRS benchmark case YAML")
    parser.add_argument("--aqrs-source", type=Path, help="canonical AQRS source to bind")
    parser.add_argument("--output", required=True, type=Path, help="generated JSON manifest")
    args = parser.parse_args()

    case = load_benchmark_case(args.case)
    if args.aqrs_source is not None:
        verify_aqrs_source_binding(case, args.aqrs_source.read_bytes())
    write_benchmark_case_manifest(args.output, case)
    print(f"{case.case_id} {benchmark_case_sha256(case)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
