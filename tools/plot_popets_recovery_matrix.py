"""Render the two observer scopes of the bounded recovery matrix as an SVG."""

import argparse
import html
import json
from pathlib import Path

SCOPE = (
    ("Recipient coalition", ("recipient-only", "deadline-wait")),
    ("Coalition + wire-shape protection", ("network-envelope", "fixed-rate")),
)
LABELS = {
    "recipient-only": "Public-window schedule",
    "deadline-wait": "Deadline-only wait",
    "network-envelope": "One-frame envelope",
    "fixed-rate": "Window fixed rate",
}


def render(report: dict) -> str:
    if report.get("schema") != "noticer.popets.synthetic-recovery-matrix.v1":
        raise ValueError("expected the bounded synthetic recovery matrix")
    indexed = {row["mode"]: row for row in report["results"]}
    if len(report["results"]) != len(LABELS) or indexed.keys() != LABELS.keys():
        raise ValueError("wrong comparison inventory")
    maximum = max(row["mean_model_bytes_per_case"] for row in indexed.values())
    if not maximum > 0:
        raise ValueError("the chart needs a positive common byte scale")
    maximum = max(1280, maximum)
    graph = [
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 810 378" role="img"',
        ' aria-labelledby="title description">',
        '<title id="title">Recovery cost by privacy scope</title>',
        '<desc id="description">Two separate comparisons of model bytes and deadline completion.'
        ' Point labels include mean delay for completed actions. All data are synthetic.</desc>',
        '<rect width="810" height="378" rx="14" fill="#f4f7f2"/>',
        '<g font-family="sans-serif" fill="#173539">',
        '<text x="28" y="32" font-size="21" font-weight="700">'
        'Recovery cost by observer scope</text>',
        '<text x="28" y="53" font-size="12">FINITE SYNTHETIC MODEL / 64 ACTION OBLIGATIONS</text>',
    ]
    for panel, (title, modes) in enumerate(SCOPE):
        origin = 62 + panel * 393
        graph.append(f'<text x="{origin}" y="83" font-weight="700">{html.escape(title)}</text>')
        for percentage in (75, 100):
            y = 305 - (percentage - 70) * 6
            graph.append(
                f'<path d="M{origin} {y}h310" stroke="#aabbb4"/>'
                f'<text x="{origin - 4}" y="{y + 3}" font-size="10"'
                f' text-anchor="end">{percentage}%</text>'
            )
        graph.append(f'<path d="M{origin} 110v195h310" fill="none" stroke="#526a64"/>')
        for index, mode in enumerate(modes):
            row = indexed[mode]
            amount = row["mean_model_bytes_per_case"]
            rate = 100 * row["deadline_successes"] / row["promised_actions"]
            delay = row["mean_delay_slots_delivered_only"]
            x = origin + 310 * amount / maximum
            y = 305 - (rate - 70) * 6
            color = "#007166" if index == 0 else "#9b490b"
            anchor = "end" if amount / maximum > 0.6 else "start"
            label_x = x - 8 if anchor == "end" else x + 8
            label_y = y + (26 if panel == 1 and index else -10)
            graph.extend((
                f'<circle cx="{x:.2f}" cy="{y:.2f}" r="5" fill="{color}"/>',
                f'<text x="{label_x:.2f}" y="{label_y:.2f}" text-anchor="{anchor}"'
                f' font-size="11" font-weight="700">{LABELS[mode]}</text>',
                f'<text x="{label_x:.2f}" y="{label_y + 14:.2f}" text-anchor="{anchor}"'
                f' font-size="10">{amount:g} B / {delay:g} slots</text>',
            ))
        graph.append(f'<text x="{origin + 68}" y="328" font-size="11">Model bytes per case</text>')
    graph.append('<text x="28" y="355" font-size="11">Delay is conditional on completion.'
                 ' Compare points within a panel, not across different privacy scopes.</text>')
    graph.append('</g></svg>')
    return "\n".join(graph) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("matrix", type=Path)
    parser.add_argument("out", type=Path)
    args = parser.parse_args()
    source = json.loads(args.matrix.read_text(encoding="utf-8"))
    with args.out.open("x", encoding="utf-8") as stream:
        stream.write(render(source))


if __name__ == "__main__":
    main()
