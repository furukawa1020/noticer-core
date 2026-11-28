"""Validate a portable receipt certificate without running its constructor."""

import argparse
import hashlib
import json
from pathlib import Path

from noticer_core.receipt_limit_bundle import parse_certificate
from noticer_core.receipt_limit_enumerate import MAX_STEPS, ReceiptCutoff
from noticer_core.receipt_limit_verify import verify_receipt_certificate
from noticer_core.slot_mix_json import MAX_BUNDLE_BYTES


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("certificate", type=Path)
    parser.add_argument("--max-work", type=int, default=MAX_STEPS)
    args = parser.parse_args()
    try:
        with args.certificate.open("rb") as stream:
            raw = stream.read(MAX_BUNDLE_BYTES + 1)
        game, view, proof = parse_certificate(raw)
        if verify_receipt_certificate(game, view, proof, args.max_work):
            code, result = 0, {"status": "verified", "value": str(proof.value),
                               "sha256": hashlib.sha256(raw).hexdigest()}
        else:
            code, result = 2, {"status": "rejected"}
    except ReceiptCutoff:
        code, result = 3, {"status": "inconclusive"}
    except (ValueError, OSError):
        code, result = 2, {"status": "invalid"}
    print(json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
