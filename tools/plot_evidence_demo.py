"""Render a dependency-free SVG summary from the K1 scenario CSV."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with args.input.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    labels = "".join(
        f'<text x="20" y="{30 + index * 22}">{row["scenario"]}: '
        f'{row["result"]}</text>'
        for index, row in enumerate(rows)
    )
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="900" '
        f'height="{60 + len(rows) * 22}">{labels}</svg>'
    )
    args.output.write_text(svg, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

