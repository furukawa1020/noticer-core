import pytest

from noticer_core.recovery_release_inventory import check_release_inventory


def test_portable_names_are_reported_in_canonical_order() -> None:
    assert check_release_inventory(["src/recovery.py", "proof/v1.json"]) == (
        "proof/v1.json", "src/recovery.py"
    )


@pytest.mark.parametrize("paths", [
    ["../private.json"],
    ["archive/.git/config.txt"],
    ["src/Participant-data.json"],
    ["Data.json", "data.json"],
    ["C:/tmp/data.json"],
])
def test_unsafe_or_obviously_identifying_members_block_preflight(paths: list[str]) -> None:
    with pytest.raises(ValueError):
        check_release_inventory(paths)
