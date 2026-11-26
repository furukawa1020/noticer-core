"""Small, readable result set that includes negative and inconclusive controls."""

from typing import Any

from noticer_core.slot_mix_baselines import iterative_profile, uniform_success
from noticer_core.slot_mix_fixtures import asymmetric_game, last_slot_game
from noticer_core.slot_mix_probability import success_profile
from noticer_core.slot_mix_solve import solve_mix


def build_mix_examples() -> dict[str, Any]:
    """Keep exact fractions and probability laws in the published evidence."""
    examples: dict[str, Any] = {}
    for name, game in (
        ("crossed", last_slot_game(2, (1, 2))),
        ("triangle", last_slot_game(3, (3, 5, 6))),
        ("asymmetric", asymmetric_game()),
        ("unreachable", last_slot_game(3, (0, 3, 5, 6))),
    ):
        result = solve_mix(game)
        if result.certificate is None:
            raise RuntimeError("example without verified certificate")
        n = len(game.public.tapes)
        cert = result.certificate
        masks = tuple(c.mask for c in result.frontier)
        examples[name] = {
            "status": result.status,
            "value": str(cert.value),
            "uniform": str(uniform_success(masks, n)),
            "iterative64": str(min(iterative_profile(masks, n))),
            "policy_masks": tuple(item.mask for item in cert.policies),
            "policy_weights": tuple(map(str, cert.policy_weights)),
            "tape_weights": tuple(map(str, cert.tape_weights)),
            "success_profile": tuple(map(str, success_profile(
                tuple(c.mask for c in cert.policies), cert.policy_weights, n
            ))),
            "work": result.work,
        }
    return {
        "schema": "shared-slot-mix-examples.v1",
        "empirical": False,
        "examples": examples,
        "controls": {
            "verification_cutoff": solve_mix(asymmetric_game(), verification_limit=1).status,
            "invalid_pivots": solve_mix(asymmetric_game(), pivot_limit=0).status,
        },
    }
