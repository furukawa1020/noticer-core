"""Check a standalone K24 artifact without calling the synthesizer."""

import argparse
import hashlib
import json
from pathlib import Path

from noticer_core.slot_mix_bundle import parse_bundle
from noticer_core.slot_mix_certificate import verify_mix
from noticer_core.slot_mix_frontier import MAX_WORK, MixLimit, WorkBudget
from noticer_core.slot_mix_json import MAX_BUNDLE_BYTES


def main() -> int:
    """Print a machine-readable verification result."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--max-work", type=int, default=MAX_WORK)
    args = parser.parse_args()
    try:
        budget = WorkBudget(args.max_work)
        with args.artifact.open("rb") as stream:
            raw = stream.read(MAX_BUNDLE_BYTES + 1)
        game, certificate = parse_bundle(raw)
        if not verify_mix(game, certificate, budget):
            status, result = 2, {"status": "rejected"}
        else:
            status, result = 0, {
                "status": "verified",
                "value": str(certificate.value),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
    except MixLimit:
        status, result = 3, {"status": "inconclusive"}
    except (ValueError, OSError):
        status, result = 2, {"status": "invalid"}
    print(json.dumps(result, sort_keys=True))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
