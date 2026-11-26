"""Replay synthetic application receipts over owned local socket pairs only."""

import json
import socket
from dataclasses import asdict

from noticer_core.shared_slot_views import PublicReceipt

MAX_RECEIPT_BYTES = 512


def replay_local_receipts(
    receipts: tuple[PublicReceipt, ...],
) -> tuple[PublicReceipt, ...]:
    """Audit byte encoding and receipt order; no listening or remote addresses."""
    received = []
    for receipt in receipts:
        packet = (json.dumps(asdict(receipt), sort_keys=True) + "\n").encode("utf-8")
        if len(packet) > MAX_RECEIPT_BYTES:
            raise ValueError("local synthetic receipt is too large")
        sender, receiver = socket.socketpair()
        with sender, receiver, receiver.makefile("rb") as stream:
            receiver.settimeout(2)
            sender.settimeout(2)
            sender.sendall(packet)
            sender.shutdown(socket.SHUT_WR)
            line = stream.readline(MAX_RECEIPT_BYTES + 1)
            if len(line) > MAX_RECEIPT_BYTES or line[-1:] != b"\n" or stream.read(1):
                raise RuntimeError("invalid local receipt framing")
            received.append(PublicReceipt(**json.loads(line)))
    return tuple(received)
