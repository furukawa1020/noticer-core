import pytest

from noticer_core.recovery_coalition import RecipientEvent, assemble_coalition


def test_ties_are_stable_across_recipient_collection_order() -> None:
    a = RecipientEvent("a", 2, 0, "notify")
    b = RecipientEvent("b", 2, 0, "notify")
    assert assemble_coalition(("b", "a"), (b, a)) == (a, b)


def test_duplicate_or_missing_receipts_are_not_silently_reordered() -> None:
    event = RecipientEvent("a", 2, 0, "notify")
    with pytest.raises(ValueError, match="repeated"):
        assemble_coalition(("a",), (event, event))
    with pytest.raises(ValueError, match="incomplete"):
        assemble_coalition(("a",), (RecipientEvent("a", 2, 1, "notify"),))
