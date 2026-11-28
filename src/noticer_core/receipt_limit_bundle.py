"""Versioned certificate carrying the modeled input and both achieved laws."""

import json
from dataclasses import asdict

from noticer_core.receipt_limit_contract import ReceiptProblem
from noticer_core.receipt_limit_law_codec import decode_law
from noticer_core.receipt_limit_observer import Observer, check_observer
from noticer_core.receipt_limit_tapes import decode_histories
from noticer_core.receipt_limit_verify import ReceiptCertificate
from noticer_core.slot_mix_json import decode_json, exact_members
from noticer_core.slot_mix_rational import decode_probability

SCHEMA = "synthetic-receipt-limit.v1"


def export_certificate(
    problem: ReceiptProblem, observer: Observer, certificate: ReceiptCertificate
) -> bytes:
    """Serialize the public synthetic fixture with a canonical deterministic order."""
    data = {
        "schema": SCHEMA, "empirical": False, "problem": asdict(problem),
        "observer": {"receivers": sorted(observer.receivers), "failure": observer.announce_failure},
        "delta": str(certificate.delta), "value": str(certificate.value),
        "laws": [
            [{"plan": plan, "mass": str(weight)} for plan, weight in law]
            for law in certificate.laws
        ],
    }
    return (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def parse_certificate(raw: bytes) -> tuple[ReceiptProblem, Observer, ReceiptCertificate]:
    """Parse canonical fields; replay remains a separate required step."""
    data = exact_members(decode_json(raw), {
        "schema", "empirical", "problem", "observer", "delta", "value", "laws"
    })
    if data["schema"] != SCHEMA or data["empirical"] is not False:
        raise ValueError("unexpected evidence model")
    constraint = exact_members(data["problem"], {"worlds", "recipients"})
    game = decode_histories(constraint["worlds"], constraint["recipients"])
    view = exact_members(data["observer"], {"receivers", "failure"})
    names = view["receivers"]
    if type(names) is not list or len(names) > 5 or any(
        type(name) is not str or len(name) > 64 for name in names
    ) or names != sorted(set(names)):
        raise ValueError("invalid canonical receiver set")
    observer = Observer(frozenset(names), view["failure"])
    check_observer(game, observer)
    laws = data["laws"]
    if type(laws) is not list or len(laws) != 2:
        raise ValueError("invalid number of laws")
    return game, observer, ReceiptCertificate(
        decode_probability(data["delta"]), decode_probability(data["value"]),
        (decode_law(laws[0]), decode_law(laws[1])),
    )
