import pytest

from noticer_core.slot_mix_tree_codec import decode_tree


def test_policy_cannot_exceed_horizon_or_use_duplicate_branches():
    leaf = {"view": [1, ["a"]], "send": ["a"], "children": []}
    root = {"view": [0, []], "send": [], "children": [leaf, leaf]}
    with pytest.raises(ValueError, match="bounds"):
        decode_tree(root, 1)
    with pytest.raises(ValueError, match="ambiguous"):
        decode_tree(root, 2)
