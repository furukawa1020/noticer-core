from dataclasses import replace

import pytest

from noticer_core.evaluation.k20_seeds import build_seed_ledger


def test_derivation_is_order_independent_and_stable_when_extended() -> None:
    first = build_seed_ledger(8, ["bootstrap", "split"])
    assert first == build_seed_ledger(8, ["split", "bootstrap"])
    extended = dict(build_seed_ledger(8, ["bootstrap", "split", "model/linear"]).entries)
    assert all(extended[name] == seed for name, seed in first.entries)
    assert all(0 <= value < 2**32 for _, value in first.entries)


def test_altered_or_incomplete_ledgers_cannot_verify() -> None:
    ledger = build_seed_ledger(8, ["bootstrap", "split"])
    ledger.verify(["split", "bootstrap"])
    with pytest.raises(ValueError, match="does not match"):
        replace(ledger, entries=ledger.entries[:1]).verify(["split", "bootstrap"])
    with pytest.raises(ValueError, match="does not match"):
        replace(ledger, root_seed=9).verify(["split", "bootstrap"])
