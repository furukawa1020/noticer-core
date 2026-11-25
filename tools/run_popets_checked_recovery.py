"""Check and execute both policies on local socket pairs under synthetic public loss."""

from __future__ import annotations

import argparse
import hashlib
import json
import socket
import struct
import subprocess
from dataclasses import asdict
from itertools import product
from pathlib import Path
from statistics import mean

from noticer_core.evaluation.aqrs_oracle import check_path
from noticer_core.recovery_log_audit import LogAudit, audit_recipient_log
from noticer_core.recovery_log_binding import bind_recovery_log
from noticer_core.recovery_verdict import Resolution, resolve_checkers

SERVICES = ("a", "b")
PUBLIC_TAPES = {"no-loss": (0, 0), "lose-first-opportunity": (1, 0)}
SCENARIOS = {"action": (0, 2), "idle": (4, 6)}
Message = dict[str, str | int]


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
            + "\n").encode("ascii")


def receive_exact(channel: socket.socket, size: int) -> bytes:
    buffer = bytearray()
    while len(buffer) < size:
        chunk = channel.recv(size - len(buffer))
        if not chunk:
            raise RuntimeError("local channel closed before the complete receipt")
        buffer.extend(chunk)
    return bytes(buffer)


def transmit(channel: tuple[socket.socket, socket.socket], message: Message) -> tuple[Message, int]:
    sender, receiver = channel
    payload = canonical(message)
    if not 0 < len(payload) <= 512:
        raise ValueError("local receipt exceeds the finite fixture envelope")
    sender.sendall(struct.pack(">I", len(payload)) + payload)
    length = struct.unpack(">I", receive_exact(receiver, 4))[0]
    if not 0 < length <= 512:
        raise ValueError("invalid framed receipt length")
    data = receive_exact(receiver, length)
    return json.loads(data), 4 + length


def projected_receipts(release: dict, slot: int) -> tuple[Message, ...]:
    fields = release["fields"]
    if not fields.keys() <= {"receipt-b"} or (not release["emitted"] and release["actions"]):
        raise ValueError("release outside the declared local recipient projection")
    observed = []
    for emission in release["actions"]:
        service = emission["obligation"]["id"]
        if service not in SERVICES or emission["action"] != f"notify-{service}":
            raise ValueError("unexpected recipient or action")
        notice = {"service": service, "slot": slot, "action": emission["action"]}
        if service == "b" and "receipt-b" in fields:
            notice["receipt"] = fields["receipt-b"]
        observed.append(notice)
    if fields and not any(message["service"] == "b" for message in observed):
        raise ValueError("diagnostic without its declared recipient")
    return tuple(observed)


def execute_world(
    artifact: dict, candidate: dict, world: int, tape: tuple[int, ...]
) -> dict:
    """Drive the exported transition table and compare received messages to the checked model."""
    plant = {(start, token): (end, symbol) for start, token, end, symbol in artifact["plant"]}
    model = candidate["checker_model"]
    checked_transitions = {(x["from"], x["input"]): x for x in model["transitions"]}
    pair_index, side = divmod(world // 2, 2)
    side_name = "left" if side == 0 else "right"
    checked_state = model["initial_pairs"][pair_index][side_name]
    controller = 0
    simulated_plant = world
    delivered: list[Message] = []
    model_projection: list[Message] = []
    transferred = 0
    channels = {service: socket.socketpair() for service in SERVICES}
    try:
        for pair in channels.values():
            for channel in pair:
                channel.settimeout(2)
        for slot, token in enumerate(tape):
            simulated_plant, symbol = plant[(simulated_plant, token)]
            index = controller * candidate["symbols"] + symbol
            controller, output = candidate["cells"][index]
            event = model["inputs"][token]["id"]
            checked = checked_transitions[(checked_state, event)]
            checked_state = checked["to"]
            model_projection.extend(projected_receipts(checked["release"], slot))
            for receipt in projected_receipts(artifact["outputs"][output], slot):
                received, size = transmit(channels[str(receipt["service"])], receipt)
                delivered.append(received)
                transferred += size
    finally:
        for pair in channels.values():
            for channel in pair:
                channel.close()

    audit = audit_recipient_log(model_projection, delivered)
    machine = {key: candidate[key] for key in ("state_count", "symbols", "cells")}
    replay_input = {"world": world, "tape": tape, "plant": artifact["plant"]}
    binding = bind_recovery_log(
        canonical(machine), canonical(model), canonical(replay_input), canonical(delivered)
    )
    return {
        "model_binding": audit is LogAudit.MATCH,
        "log_audit": audit.value,
        "replay_binding": asdict(binding) | {"digest": binding.digest},
        "received": delivered,
        "application_bytes": transferred,
    }


def dual_check(model_file: Path, checker: Path) -> dict:
    local = check_path(model_file).as_report(engine="python")
    native = subprocess.run(
        [str(checker.resolve()), "--input", str(model_file.resolve())],
        check=True, text=True, encoding="utf-8", capture_output=True, timeout=30,
    )
    rust = json.loads(native.stdout)
    resolution = resolve_checkers(local, rust)
    return {
        "status": "unresolved" if resolution is Resolution.UNRESOLVED else "agree",
        "resolution": resolution.value,
        "model_sha256": hashlib.sha256(model_file.read_bytes()).hexdigest(),
        "python": local,
        "rust": rust,
    }


def evaluate(candidate: dict, artifact: dict) -> dict:
    cases = {}
    active_results = []
    unauthorized = 0
    promises_completed = 0
    strict = artifact.get("deadline_contract") == "context-specific"
    for (scenario, worlds), (public_case, tape) in product(SCENARIOS.items(), PUBLIC_TAPES.items()):
        deadline = 0 if strict and public_case == "no-loss" else 1
        if strict:
            tape = (0, 0)
            if scenario == "action" and public_case == "lose-first-opportunity":
                worlds = (8, 10)
        early, late = (execute_world(artifact, candidate, world, tape) for world in worlds)
        cases[f"{scenario}/{public_case}"] = {
            "paired_view_equal": early["received"] == late["received"],
            "early": early,
            "late": late,
        }
        for output in (early, late):
            if scenario == "action":
                active_results.append(output)
                for service in SERVICES:
                    events = [x for x in output["received"] if x["service"] == service]
                    promises_completed += len(events) == 1 and events[0]["slot"] <= deadline
            else:
                unauthorized += len(output["received"])
    slots = [item["slot"] for row in active_results for item in row["received"]]
    return {
        "machine_states": candidate["state_count"],
        "cases": cases,
        "all_receives_match_checked_model": all(
            row[world]["model_binding"] for row in cases.values() for world in ("early", "late")
        ),
        "active_pairs_equal": sum(
            row["paired_view_equal"] for key, row in cases.items() if key.startswith("action/")
        ),
        "active_pairs": len(PUBLIC_TAPES),
        "authorized_exactly_once_on_time": promises_completed,
        "authorized_expected": len(active_results) * len(SERVICES),
        "unauthorized_idle_receipts": unauthorized,
        "mean_active_application_bytes": mean(row["application_bytes"] for row in active_results),
        "mean_active_receipt_slot": mean(slots) if slots else None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("native", type=Path)
    parser.add_argument("checker", type=Path)
    parser.add_argument("out", type=Path)
    args = parser.parse_args()
    native_bytes = args.native.read_bytes()
    artifact = json.loads(native_bytes.decode("utf-8-sig"))
    if artifact["schema"] != "noticer.popets.recovery-synthesis-pilot.v1":
        raise ValueError("wrong native synthesis artifact")
    synthesis_status = artifact.get("synthesis_status", "realizable")
    if synthesis_status != "realizable":
        if synthesis_status not in {"inconclusive", "unrealizable-at-bound"} or artifact["cases"]:
            raise ValueError("non-realizable synthesis may not include replay cases")
        report = {
            "schema": "noticer.popets.checked-recovery-pilot.v1",
            "synthesis_status": synthesis_status,
            "native_sha256": hashlib.sha256(native_bytes).hexdigest(),
            "native_decision": artifact,
            "results": {},
        }
        with (args.out / "summary.json").open("xb") as stream:
            stream.write(canonical(report))
        print(f"Synthesis {synthesis_status}; no qualified receiver runs")
        raise SystemExit(3)
    results = {}
    if artifact.get("scope", {"services": 2, "horizon": 2}) != {"services": 2, "horizon": 2}:
        raise ValueError("the two-recipient socket replay only supports the original fixture")
    for name, candidate in artifact["cases"].items():
        file = args.out / f"{name}.model.json"
        with file.open("xb") as stream:
            stream.write(canonical(candidate["checker_model"]))
        result = evaluate(candidate, artifact)
        result["independent_check"] = dual_check(file, args.checker)
        results[name] = result
    report = {
        "schema": "noticer.popets.checked-recovery-pilot.v1",
        "evidence": "synthetic model plus local application receipt replay",
        "native_sha256": hashlib.sha256(native_bytes).hexdigest(),
        "synthesis": artifact["synthesis"],
        "results": results,
    }
    with (args.out / "summary.json").open("xb") as stream:
        stream.write(canonical(report))
    for name, result in results.items():
        verdict = result["independent_check"]
        native = verdict["rust"]
        print(name, result["machine_states"], verdict["status"], native["status"],
              native.get("slot"), native.get("causal_field"),
              result["active_pairs_equal"], result["authorized_exactly_once_on_time"],
              result["all_receives_match_checked_model"], result["mean_active_application_bytes"],
              result["mean_active_receipt_slot"])
    print("synthesis", artifact["synthesis"])
    unresolved = any(
        result["independent_check"]["status"] != "agree"
        or not result["all_receives_match_checked_model"]
        for result in results.values()
    )
    if unresolved:
        raise SystemExit(3)


if __name__ == "__main__":
    main()
