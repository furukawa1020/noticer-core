"""Assemble and parse a portable, independently verifiable certificate."""

import json
from dataclasses import asdict

from noticer_core.slot_mix_certificate import MixCertificate
from noticer_core.slot_mix_contract import SlotMixGame
from noticer_core.slot_mix_frontier import Candidate
from noticer_core.slot_mix_json import decode_json, exact_members
from noticer_core.slot_mix_rational import decode_probability
from noticer_core.slot_mix_tape_codec import decode_tapes, encode_tapes
from noticer_core.slot_mix_tree_codec import decode_tree

SCHEMA = "public-slot-mixed-certificate.v1"
MODEL = "fixed-admitted-tape-before-independent-draw"


def export_bundle(game: SlotMixGame, certificate: MixCertificate) -> bytes:
    """Canonical UTF-8 JSON; export is not a substitute for verification."""
    body = {
        "schema": SCHEMA,
        "model": MODEL,
        "tapes": encode_tapes(game),
        "policies": [asdict(policy) for policy in certificate.policies],
        "policy_weights": list(map(str, certificate.policy_weights)),
        "tape_weights": list(map(str, certificate.tape_weights)),
        "value": str(certificate.value),
    }
    return (json.dumps(body, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")


def parse_bundle(raw: bytes) -> tuple[SlotMixGame, MixCertificate]:
    """Read input/certificate without invoking the synthesis engine."""
    data = exact_members(decode_json(raw), {
        "schema", "model", "tapes", "policies", "policy_weights", "tape_weights", "value"
    })
    if data["schema"] != SCHEMA or data["model"] != MODEL:
        raise ValueError("unknown schema or uncertainty model")
    game = decode_tapes(data["tapes"])
    policies = data["policies"]
    if type(policies) is not list or not 1 <= len(policies) <= 8:
        raise ValueError("invalid support size")
    policy_weights = data["policy_weights"]
    tape_weights = data["tape_weights"]
    if (
        type(policy_weights) is not list or len(policy_weights) != len(policies)
        or type(tape_weights) is not list or len(tape_weights) != len(game.public.tapes)
    ):
        raise ValueError("invalid number of probability weights")
    candidates = []
    for item in policies:
        item = exact_members(item, {"mask", "root"})
        if type(item["mask"]) is not int or not 0 <= item["mask"] < 1 << len(game.public.tapes):
            raise ValueError("invalid policy success mask")
        candidates.append(Candidate(item["mask"], decode_tree(item["root"], game.public.horizon)))
    return game, MixCertificate(
        tuple(candidates),
        tuple(map(decode_probability, policy_weights)),
        tuple(map(decode_probability, tape_weights)),
        decode_probability(data["value"]),
    )
