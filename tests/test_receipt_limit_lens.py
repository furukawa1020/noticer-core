from noticer_core.receipt_limit_correlation import correlation_control
from noticer_core.receipt_limit_distance import total_variation
from noticer_core.receipt_limit_distribution import summarize_law
from noticer_core.receipt_limit_lens import restrict_law
from noticer_core.receipt_limit_observer import Observer


def test_joint_trace_can_be_collapsed_to_each_matching_receiver_marginal():
    game, laws = correlation_control()
    full = Observer(frozenset({"alpha", "bravo"}))
    for name in ("alpha", "bravo"):
        subset = frozenset({name})
        projections = []
        for world, law in enumerate(laws):
            joint, _ = summarize_law(game, full, world, law)
            direct, _ = summarize_law(game, Observer(subset), world, law)
            collapsed = restrict_law(joint, subset, keep_failure=False)
            assert collapsed == direct and sum(collapsed.values()) == 1
            projections.append(collapsed)
        assert total_variation(*projections) == 0
