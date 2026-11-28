from noticer_core.receipt_limit_correlation import correlation_distances


def test_marginal_privacy_does_not_compose_under_joint_readout():
    assert correlation_distances() == {"alpha": 0, "bravo": 0, "coalition": 1}
